import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, startNode, peer, waitConnected, stopAll } from '../../scripts/process-helper.mjs';

// Disposable loopback demonstration: no production identity or model credential.
const dir = await makeWorkspace('intelligent-cells-pi-demo-');
const nodes = [];
try {
  const fixture = path.join(dir, 'fixed-demo-command.mjs');
  await fs.writeFile(fixture, 'console.log(JSON.stringify({pid:process.pid,cwd:process.cwd(),args:process.argv.slice(2)}));\n');
  const servant = await startNode(dir, { id: 'servant-a', host: '127.0.0.1', port: 0,
    policy: { grants: { master: { tools: ['echo', 'readFile', 'writeFile', 'editFile', 'exec'], workspace: 'workspace',
      maxTimeoutMs: 2000, execCommands: { fixture: { file: process.execPath, args: [fixture], argsAllowed: true, maxArgs: 1 } },
    } } },
  }); nodes.push(servant);
  const master = await startNode(dir, { id: 'master', host: '127.0.0.1', port: 0, agent: 'pi-mock',
    peers: [peer(servant)], policy: { grants: {} },
  }); nodes.push(master);
  await waitConnected(master, servant.id);
  const response = await master.command({ command: 'agent', prompt: 'Read, create, edit and verify the approved remote fixture', scenario: 'workflow' });
  assert.equal(response.ok, true, JSON.stringify(response.error));
  const result = response.result;
  assert.ok(result.messages.filter(x => x.role === 'toolResult').every(x => !x.isError));
  assert.match(result.final, /Edited by the servant through Pi/);
  assert.equal(master.events.filter(x => x.event === 'task_started').length, 0);
  console.log(JSON.stringify({
    proof: 'published Pi SDK -> local mock model HTTP/SSE -> Pi remote tool -> mTLS -> servant grant -> result -> Pi final answer',
    pi: `${result.package}@${result.version}`, mockedModel: result.mockedModel,
    masterPid: master.child.pid, servantPid: servant.child.pid,
    servantAgent: (await servant.command({ command: 'status' })).result.agent,
    masterLocalExecutions: 0, modelRequests: result.modelRequests,
    remoteTools: result.activeTools, dispatches: result.dispatches,
    final: result.final,
  }, null, 2));
  const denied = await master.command({ command: 'agent', prompt: 'Verify the denied traversal fixture', scenario: 'denial' });
  assert.equal(denied.ok, true);
  assert.match(denied.result.final, /PATH_DENIED/);
  console.log(JSON.stringify({ denialVerified: true, final: denied.result.final }, null, 2));
} finally {
  await stopAll(nodes);
  await fs.rm(dir, { recursive: true, force: true });
}
