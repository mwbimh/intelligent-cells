import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, startNode, peer, waitConnected, stopAll } from '../scripts/process-helper.mjs';
import { REMOTE_TOOL_NAMES } from '../integration/pi/remote-tools.mjs';

const results = response => response.result.messages.filter(x => x.role === 'toolResult');

test('real Pi master -> mock HTTP model -> mTLS servant -> permissions -> Pi final response', { timeout: 30000 }, async t => {
  const dir = await makeWorkspace('pi-encrypted-e2e-');
  const nodes = [];
  const fixture = path.join(dir, 'fixed-exec-fixture.mjs');
  await fs.writeFile(fixture, 'console.log(JSON.stringify({kind:"servant-exec",pid:process.pid,cwd:process.cwd(),args:process.argv.slice(2)}));\n');
  await fs.writeFile(path.join(dir, 'outside.txt'), 'PRIVATE_OUTSIDE_WORKSPACE_MARKER');
  try {
    const servant = await startNode(dir, { id: 'servant-a', host: '127.0.0.1', port: 0,
      policy: { grants: { master: { tools: ['echo', 'wait', 'readFile', 'writeFile', 'editFile', 'exec'], workspace: 'workspace',
        maxTimeoutMs: 2000, execCommands: { fixture: { file: process.execPath, args: [fixture], argsAllowed: true, maxArgs: 1 } },
      } } },
    });
    nodes.push(servant);
    const master = await startNode(dir, { id: 'master', host: '127.0.0.1', port: 0, agent: 'pi-mock',
      peers: [peer(servant)], policy: { grants: {} },
    });
    nodes.push(master);
    await waitConnected(master, servant.id);
    assert.notEqual(master.child.pid, servant.child.pid);

    await t.test('five genuine Pi tool iterations read, write, edit, exec and read back the servant result', async () => {
      const response = await master.command({ command: 'agent', prompt: 'Complete the approved remote coding workflow', scenario: 'workflow' });
      assert.equal(response.ok, true, JSON.stringify(response.error));
      assert.equal(response.result.version, '0.99.2');
      assert.equal(response.result.modelRequests, 6);
      assert.deepEqual(response.result.dispatches.map(x => x.tool), ['readFile', 'writeFile', 'editFile', 'exec', 'readFile']);
      assert.ok(results(response).every(x => x.isError === false), JSON.stringify(results(response)));
      assert.equal(await fs.readFile(path.join(dir, 'workspace', 'pi-result.txt'), 'utf8'), 'Edited by the servant through Pi.\n');
      assert.match(response.result.final, /Edited by the servant through Pi/);
      assert.match(response.result.final, /pi-remote-exec/);
      const exec = JSON.parse(results(response)[3].content[0].text);
      const execution = JSON.parse(exec.stdout);
      assert.equal(execution.cwd, path.join(dir, 'workspace'));
      assert.notEqual(execution.pid, master.child.pid);
      assert.notEqual(execution.pid, servant.child.pid);
      assert.equal(master.events.filter(x => x.event === 'task_started').length, 0);
      assert.equal(servant.events.filter(x => x.event === 'task_started').length, 5);
      assert.ok(servant.events.filter(x => x.event === 'task_started').every(x => x.masterId === 'master'));
      assert.deepEqual(response.result.allTools, [...REMOTE_TOOL_NAMES].sort());
      assert.equal((await servant.command({ command: 'status' })).result.agent, null);
      assert.match((await master.command({ command: 'status' })).result.agent, /^pi-mock\/0\.99\.2$/);
    });

    await t.test('path escape denial originates on servant and is reported by the final mocked model', async () => {
      const before = servant.events.length;
      const response = await master.command({ command: 'agent', prompt: 'Exercise the denied traversal fixture', scenario: 'denial' });
      assert.equal(response.ok, true);
      assert.equal(results(response)[0].isError, true);
      assert.match(response.result.final, /PATH_DENIED/);
      assert.doesNotMatch(response.result.final, /PRIVATE_OUTSIDE_WORKSPACE_MARKER/);
      assert.ok(servant.events.slice(before).some(x => x.event === 'task_denied' && x.error.code === 'PATH_DENIED'));
      assert.equal(servant.events.slice(before).filter(x => x.event === 'task_started').length, 0);
    });

    await t.test('remote arbitrary executable alias is rejected on servant', async () => {
      const response = await master.command({ command: 'agent', prompt: 'Exercise the denied exec fixture', scenario: 'exec-denial' });
      assert.equal(response.ok, true);
      assert.equal(results(response)[0].isError, true);
      assert.match(response.result.final, /COMMAND_DENIED/);
    });

    await t.test('servant can narrow its live grant and Pi cannot re-enable a denied tool', async () => {
      const updated = structuredClone(servant.config);
      updated.policy.grants.master.tools = ['readFile', 'echo'];
      await fs.writeFile(servant.filename, JSON.stringify(updated));
      const reload = await servant.command({ command: 'reloadPolicy' });
      assert.equal(reload.ok, true);
      const response = await master.command({ command: 'agent', prompt: 'Exercise the locally revoked write tool', scenario: 'tool-denial' });
      assert.equal(response.ok, true);
      assert.equal(results(response)[0].isError, true);
      assert.match(response.result.final, /TOOL_DENIED/);
      await assert.rejects(fs.stat(path.join(dir, 'workspace', 'denied.txt')), { code: 'ENOENT' });
    });

    await t.test('pure servant cannot invoke a model or outbound agent', async () => {
      const response = await servant.command({ command: 'agent', prompt: 'Start a model', scenario: 'read' });
      assert.equal(response.ok, false);
      assert.equal(response.error.code, 'AGENT_REQUIRED');
      assert.equal(servant.events.filter(x => x.event === 'pi_event').length, 0);
    });

    await t.test('disconnected servant produces model-visible failure without local fallback', async () => {
      const after = master.events.length;
      await servant.stop();
      await master.wait(x => x.event === 'peer_disconnected', 6000, after);
      const response = await master.command({ command: 'agent', prompt: 'Read from the disconnected servant', scenario: 'read' });
      assert.equal(response.ok, true);
      assert.equal(results(response)[0].isError, true);
      assert.match(response.result.final, /disconnected|PEER_UNAVAILABLE/i);
      assert.equal(master.events.filter(x => x.event === 'task_started').length, 0);
    });
  } finally {
    await stopAll(nodes);
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('master shutdown aborts Pi and cancellation reaches the authenticated servant before transport closes', { timeout: 15000 }, async () => {
  const dir = await makeWorkspace('pi-cancel-e2e-'); const nodes = [];
  try {
    const servant = await startNode(dir, { id: 'servant-a', port: 0, policy: { grants: {
      master: { tools: ['wait'], maxTimeoutMs: 2000, maxWaitMs: 2000 },
    } } }); nodes.push(servant);
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'pi-mock', peers: [peer(servant)], policy: { grants: {} } }); nodes.push(master);
    await waitConnected(master, servant.id);
    const run = master.command({ command: 'agent', prompt: 'Wait on the servant', scenario: 'wait' });
    const started = await servant.wait(x => x.event === 'task_started' && x.tool === 'wait');
    await master.stop();
    const response = await run;
    assert.equal(response.ok, false);
    assert.equal(response.error.code, 'AGENT_ABORTED');
    const cancelled = await servant.wait(x => x.event === 'task_cancelled' && x.taskId === started.taskId);
    assert.equal(cancelled.masterId, 'master');
    const finished = await servant.wait(x => x.event === 'task_finished' && x.taskId === started.taskId);
    assert.equal(finished.error.code, 'CANCELLED');
    assert.equal((await servant.command({ command: 'status' })).result.active, 0);
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});
