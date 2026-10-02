import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, startNode, stopAll, peer, waitConnected } from '../scripts/process-helper.mjs';

const task = (taskId, tool, args, timeoutMs = 1000) => ({ taskId, tool, args, timeoutMs });

test('independent tools audit: encrypted requests obey write/edit/exec boundaries and cancellation', { timeout: 30000 }, async t => {
  const dir = await makeWorkspace('tools-audit-'), nodes = [];
  try {
    const root = path.join(dir, 'workspace');
    const fixture = path.join(dir, 'trusted-exec.mjs');
    await fs.writeFile(fixture, `const [mode,...args]=process.argv.slice(2); if(mode==='huge') process.stdout.write('x'.repeat(20000)); else if(mode==='wait') { console.log(process.pid); setTimeout(()=>{},10000); } else console.log(JSON.stringify({args, cwd:process.cwd(), inheritedSecret:process.env.AUDIT_PARENT_SECRET ?? null}));`);
    const commands = {
      fixed: { file: process.execPath, args: [fixture, 'echo'], argsAllowed: false },
      argv: { file: process.execPath, args: [fixture, 'echo'], argsAllowed: true, maxArgs: 8 },
      huge: { file: process.execPath, args: [fixture, 'huge'] },
      wait: { file: process.execPath, args: [fixture, 'wait'] },
    };
    const servant = await startNode(dir, { id: 'servant', port: 0, policy: { grants: { master: { tools: ['readFile', 'writeFile', 'editFile', 'exec', 'echo'], workspace: 'workspace', maxReadBytes: 1024, maxWriteBytes: 128, maxOutputBytes: 1024, maxTimeoutMs: 2000, execCommands: commands }, other: { tools: ['readFile'], workspace: 'workspace' } } } }); nodes.push(servant);
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', peers: [peer(servant)], policy: {} }); nodes.push(master);
    const other = await startNode(dir, { id: 'other', port: 0, agent: 'deterministic-demo', peers: [peer(servant)], policy: {} }); nodes.push(other);
    await Promise.all([waitConnected(master, servant.id), waitConnected(other, servant.id)]);
    let seq = 0;
    const dispatch = async (tool, args, { actor = master, timeoutMs = 1000, taskId = `audit_${++seq}` } = {}) => {
      const response = await actor.command({ command: 'dispatch', peerId: servant.id, task: task(taskId, tool, args, timeoutMs) });
      assert.equal(response.ok, true, JSON.stringify(response)); return response.result;
    };
    const denied = async (tool, args, code = 'PATH_DENIED') => assert.equal((await dispatch(tool, args)).error.code, code);

    await t.test('write uses explicit overwrite and edit requires exactly one match', async () => {
      assert.equal((await dispatch('writeFile', { path: 'created.txt', text: 'unique original' })).status, 'ok');
      await denied('writeFile', { path: 'created.txt', text: 'silently clobber' }, 'FILE_EXISTS');
      assert.equal((await dispatch('editFile', { path: 'created.txt', oldText: 'original', newText: 'edited' })).status, 'ok');
      assert.equal(await fs.readFile(path.join(root, 'created.txt'), 'utf8'), 'unique edited');
      assert.equal((await dispatch('writeFile', { path: 'created.txt', text: 'repeat repeat', overwrite: true })).status, 'ok');
      await denied('editFile', { path: 'created.txt', oldText: 'repeat', newText: 'wrong' }, 'EDIT_MATCH_COUNT');
      await denied('editFile', { path: 'created.txt', oldText: 'absent', newText: 'wrong' }, 'EDIT_MATCH_COUNT');
      assert.equal(await fs.readFile(path.join(root, 'created.txt'), 'utf8'), 'repeat repeat');
      await denied('writeFile', { path: 'large.txt', text: 'x'.repeat(129) }, 'FILE_TOO_LARGE');
      assert.equal(await fs.stat(path.join(root, 'large.txt')).then(() => true, () => false), false);
      assert.ok(!(await fs.readdir(root)).some(name => name.startsWith('.intelligent-cells-')));
    });
    await t.test('all mutation tools reject path traversal and platform aliases', async () => {
      for (const target of ['../outside.txt', '/tmp/audit-not-permitted', 'C:/Windows/file', 'nested\\file', 'file:stream', 'a//b', 'a/./b', 'file.', 'file ', 'NUL', 'CON.txt']) {
        await denied('writeFile', { path: target, text: 'blocked', overwrite: true });
        await denied('editFile', { path: target, oldText: 'x', newText: 'blocked' });
      }
    });
    await t.test('symlink parents, symlink files and hardlinked files cannot be read or changed', async t2 => {
      await fs.mkdir(path.join(dir, 'outside')); await fs.writeFile(path.join(dir, 'outside', 'sentinel.txt'), 'OUTSIDE_UNCHANGED');
      try {
        await fs.symlink(path.join(dir, 'outside'), path.join(root, 'linkdir'), 'dir');
        await fs.symlink(path.join(dir, 'outside', 'sentinel.txt'), path.join(root, 'linkfile'));
        await fs.link(path.join(dir, 'outside', 'sentinel.txt'), path.join(root, 'hardfile'));
      } catch (error) {
        if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) { t2.skip('Filesystem links unavailable on this account'); return; }
        throw error;
      }
      for (const target of ['linkdir/sentinel.txt', 'linkfile', 'hardfile']) {
        await denied('readFile', { path: target });
        await denied('writeFile', { path: target, text: 'blocked', overwrite: true });
        await denied('editFile', { path: target, oldText: 'OUTSIDE', newText: 'blocked' });
      }
      await denied('writeFile', { path: 'linkdir/new.txt', text: 'blocked' });
      assert.equal(await fs.readFile(path.join(dir, 'outside', 'sentinel.txt'), 'utf8'), 'OUTSIDE_UNCHANGED');
      assert.equal(await fs.stat(path.join(dir, 'outside', 'new.txt')).then(() => true, () => false), false);
    });
    await t.test('read-only peer cannot write, edit or execute despite forged local permissions', async () => {
      for (const [tool, args] of [['writeFile', { path: 'other.txt', text: 'blocked' }], ['editFile', { path: 'created.txt', oldText: 'repeat', newText: 'blocked' }], ['exec', { command: 'fixed', args: [] }]]) {
        assert.equal((await dispatch(tool, args, { actor: other })).error.code, 'TOOL_DENIED');
      }
    });
    await t.test('shell-looking args remain literal argv; fixed commands forbid appended arguments', async () => {
      const marker = path.join(root, 'shell-escaped');
      const shellText = `; touch ${marker} #`;
      const literal = await dispatch('exec', { command: 'argv', args: [shellText, '$(id)', '`id`', 'a && b'] });
      assert.equal(literal.status, 'ok');
      const output = JSON.parse(literal.result.stdout);
      assert.deepEqual(output.args, [shellText, '$(id)', '`id`', 'a && b']);
      assert.equal(output.cwd, root); assert.equal(output.inheritedSecret, null);
      assert.equal(await fs.stat(marker).then(() => true, () => false), false);
      await denied('exec', { command: 'fixed', args: ['-e', 'process.exit(0)'] }, 'INVALID_ARGS');
      await denied('exec', { command: 'unconfigured', args: [] }, 'COMMAND_DENIED');
      await denied('exec', { command: '/bin/sh', args: ['-c', 'echo denied'] }, 'INVALID_ARGS');
      await denied('exec', { command: 'argv', args: [], shell: true }, 'INVALID_ARGS');
      await denied('shell', { command: 'echo denied' }, 'TOOL_DENIED');
    });
    await t.test('combined process output and timeout are bounded; authenticated cancel settles work', async () => {
      await denied('exec', { command: 'huge', args: [] }, 'OUTPUT_TOO_LARGE');
      const reconcileInspectedFixtures = async () => {
        for (let i=0;i<100;i++) { if((await servant.command({command:'status'})).result.active===0) break; await new Promise(resolve=>setTimeout(resolve,10)); }
        const jobs = await servant.command({command:'listJobs'});
        for (const job of jobs.result.jobs) if(job.state==='unknown'||job.outcomeUnknown) assert.equal((await servant.command({command:'reconcileJob',masterId:job.masterId,jobId:job.jobId,resolution:'not_applied',note:'Audited fixed fixture only writes test output and has no external effects'})).ok,true);
        for (const actor of [servant,master]) {
          const incoming=actor===servant;
          const entries=await actor.command({command:'listTasks',kind:incoming?'incoming':'outgoing',limit:200});
          for(const record of entries.result.records) if(record.state==='unknown') assert.equal((await actor.command({command:'reconcile',...(incoming?{masterId:'master'}:{peerId:servant.id}),taskId:record.taskId,resolution:'not_applied',note:'Audited fixture only writes bounded output; process is reaped'})).ok,true);
        }
      };
      await reconcileInspectedFixtures();
      const timeout = await dispatch('exec', { command: 'wait', args: [] }, { timeoutMs: 100 });
      assert.equal(timeout.error.code, 'TASK_TIMEOUT');
      // The underlying direct child is reaped before the new slot is available.
      let status; for (let i = 0; i < 20; i++) { status = await servant.command({ command: 'status' }); if (status.result.active === 0) break; await new Promise(resolve => setTimeout(resolve, 10)); }
      assert.equal(status.result.active, 0);
      await reconcileInspectedFixtures();
      const pending = dispatch('exec', { command: 'wait', args: [] }, { taskId: 'cancel_exec', timeoutMs: 2000 });
      await servant.wait(e => e.event === 'task_started' && e.taskId === 'cancel_exec');
      assert.equal((await master.command({ command: 'cancel', peerId: servant.id, taskId: 'cancel_exec' })).result.requested, true);
      assert.equal((await pending).error.code, 'CANCELLED');
      assert.equal((await dispatch('echo', { text: 'alive' })).status, 'ok');
    });
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});
