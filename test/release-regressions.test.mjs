import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DurableStore } from '../src/durable.mjs';
import { loadConfig } from '../src/config.mjs';
import { makeWorkspace, startNode, peer, waitConnected, stopAll, testSecurity } from '../scripts/process-helper.mjs';

// Independent release regressions. Processes below only print/wait in disposable
// loopback fixtures; no untrusted executable, network service or account is used.
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const task = (taskId, tool, args, runId = 'release_run') => ({ taskId, tool, args, runId, timeoutMs: 4000 });
async function until(check, timeout = 5000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const found = await check(); if (found) return found; await pause(20); }
  throw new Error('Release regression observation timed out');
}
async function setupJobs(prefix) {
  const dir = await makeWorkspace(prefix), nodes = [];
  const script = path.join(dir, 'approved-wait.mjs');
  await fs.writeFile(script, "console.log('approved fixture ready');setInterval(()=>{},1000);\n");
  const grant = { tools: ['exec', 'jobStatus', 'jobOutput', 'echo'], workspace: 'workspace', maxTimeoutMs: 4000, maxJobTimeoutMs: 4000,
    execCommands: { wait: { file: process.execPath, args: [script] } } };
  const first = await startNode(dir, { id: 'servant-a', port: 0, policy: { grants: { master: grant } } }); nodes.push(first);
  const second = await startNode(dir, { id: 'servant-b', port: 0, policy: { grants: { master: { tools: ['writeFile', 'echo'], workspace: 'workspace' } } } }); nodes.push(second);
  const masterConfig = { id: 'master', port: 0, agent: 'deterministic-demo', peers: [peer(first), peer(second)], policy: {} };
  const master = await startNode(dir, masterConfig); nodes.push(master);
  await Promise.all([waitConnected(master, first.id), waitConnected(master, second.id)]);
  return { dir, nodes, first, second, master, masterConfig };
}

test('release regression: updating a result retires older terminal data but preserves current and unresolved records across reopen', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'release-growth-'));
  try {
    let store = new DurableStore({ directory: dir, maxRecords: 8, maxBytes: 1800 }).open();
    store.put('peer:old-a', { state: 'completed', updatedAt: 1, response: 'a'.repeat(500) });
    store.put('peer:old-b', { state: 'failed', updatedAt: 2, response: 'b'.repeat(500) });
    store.put('peer:uncertain', { state: 'unknown', sideEffect: true, updatedAt: 3 });
    store.put('peer:current', { state: 'running', updatedAt: 4 });
    store.put('peer:current', { state: 'completed', updatedAt: 5, response: 'c'.repeat(1100) });
    assert.equal(store.failed, false);
    assert.equal(store.get('peer:current').response, 'c'.repeat(1100));
    assert.equal(store.get('peer:uncertain').state, 'unknown');
    assert.ok(store.info().bytes <= 1800);
    assert.ok(store.info().retiredCount >= 1);
    const retired = ['peer:old-a', 'peer:old-b'].filter(key => !store.get(key));
    assert.ok(retired.length >= 1);
    store = new DurableStore({ directory: dir, maxRecords: 8, maxBytes: 1800 }).open();
    for (const key of retired) assert.throws(() => store.put(key, { state: 'completed' }), error => error.code === 'TASK_HISTORY_EXPIRED');
    assert.equal(store.get('peer:current').response.length, 1100);
    assert.equal(store.get('peer:uncertain').state, 'unknown');
    assert.equal(store.failed, false);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('release regression: policy-limit rejection is atomic and an accepted reduction stays restartable under subsequent load', { timeout: 20000 }, async () => {
  const dir = await makeWorkspace('release-limits-'), nodes = [];
  try {
    const policy = { maxTaskRecords: 12, grants: { master: { tools: ['echo'] } } };
    let servant = await startNode(dir, { id: 'servant', port: 0, policy }); nodes.push(servant);
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', peers: [peer(servant)], policy: {} }); nodes.push(master);
    await waitConnected(master, servant.id);
    for (let i = 0; i < 4; i++) assert.equal((await master.command({ command: 'dispatch', peerId: servant.id, task: task(`limit_${i}`, 'echo', { text: `${i}` }) })).result.status, 'ok');
    const original = (await servant.command({ command: 'permissions' })).result;
    const rejected = await servant.command({ command: 'setPolicy', policy: { ...policy, maxTaskRecords: 2 }, expectedEpoch: original.epoch });
    assert.equal(rejected.error.code, 'JOURNAL_CAPACITY');
    const unchanged = (await servant.command({ command: 'permissions' })).result;
    assert.equal(unchanged.epoch, original.epoch);
    assert.equal(unchanged.policy.maxTaskRecords, 12);
    const reduced = { ...policy, maxTaskRecords: 5, maxJournalBytes: 1048576 };
    assert.equal((await servant.command({ command: 'setPolicy', policy: reduced, expectedEpoch: original.epoch })).ok, true);
    for (let i = 4; i < 16; i++) assert.equal((await master.command({ command: 'dispatch', peerId: servant.id, task: task(`limit_${i}`, 'echo', { text: `${i}` }) })).result.status, 'ok');
    const before = (await servant.command({ command: 'status' })).result;
    assert.equal(before.storageFailed, false);
    assert.ok(before.incoming.records <= 5);
    assert.ok(before.incoming.retiredCount > 0);
    const port = servant.port;
    await servant.stop(); const after = master.events.length;
    servant = await startNode(dir, { id: 'servant', port, policy }); nodes.push(servant);
    await waitConnected(master, servant.id, after);
    assert.equal((await servant.command({ command: 'permissions' })).result.policy.maxTaskRecords, 5);
    assert.equal((await master.command({ command: 'dispatch', peerId: servant.id, task: task('limit_after_restart', 'echo', { text: 'ok' }) })).result.status, 'ok');
    assert.equal((await servant.command({ command: 'status' })).result.storageFailed, false);
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('release regression: background terminal notification alone establishes cross-peer quarantine and survives master restart', { timeout: 20000 }, async () => {
  const { dir, nodes, first, second, masterConfig, master: initial } = await setupJobs('release-background-');
  let master = initial;
  try {
    const launched = await master.command({ command: 'dispatch', peerId: first.id, task: task('background_origin', 'exec', { command: 'wait', args: [], background: true, durationMs: 150 }) });
    assert.equal(launched.result.status, 'ok');
    const jobId = launched.result.result.jobId;
    await first.wait(event => event.event === 'job_state' && event.jobId === jobId && event.outcomeUnknown === true);
    await until(async () => (await master.command({ command: 'operationStatus', peerId: first.id, taskId: 'background_origin' })).result.state === 'unknown');
    const attempt = async suffix => {
      const id = `blocked_${suffix}`;
      const result = await master.command({ command: 'dispatch', peerId: second.id, task: task(id, 'writeFile', { path: `${id}.txt`, text: 'must remain blocked' }, `fresh_${suffix}`) });
      assert.equal(result.error.code, 'UNCERTAIN_SIDE_EFFECT');
      assert.equal(second.events.some(event => event.event === 'task_started' && event.taskId === id), false);
      await assert.rejects(fs.stat(path.join(dir, 'workspace', `${id}.txt`)), { code: 'ENOENT' });
      assert.equal((await master.command({ command: 'dispatch', peerId: second.id, task: task(`read_${suffix}`, 'echo', { text: 'inspection remains available' }) })).result.status, 'ok');
    };
    await attempt('before');
    await master.stop();
    master = await startNode(dir, masterConfig); nodes.push(master);
    await Promise.all([waitConnected(master, first.id), waitConnected(master, second.id)]);
    await attempt('after');
    assert.equal((await master.command({ command: 'status' })).result.storageFailed, false);
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('release regression: a fresh master learns job uncertainty from status and blocks another peer durably', { timeout: 20000 }, async () => {
  const { dir, nodes, first, second, masterConfig, master: launcher } = await setupJobs('release-job-status-');
  let observer;
  try {
    const launched = await launcher.command({ command: 'dispatch', peerId: first.id, task: task('status_origin', 'exec', { command: 'wait', args: [], background: true, durationMs: 200 }) });
    assert.equal(launched.result.status, 'ok');
    const jobId = launched.result.result.jobId;
    await launcher.stop();
    await first.wait(event => event.event === 'job_state' && event.jobId === jobId && event.outcomeUnknown === true);
    const observerConfig = { ...masterConfig, stateDir: 'observer-state' };
    observer = await startNode(dir, observerConfig); nodes.push(observer);
    await Promise.all([waitConnected(observer, first.id), waitConnected(observer, second.id)]);
    const status = await observer.command({ command: 'dispatch', peerId: first.id, task: task('observe_unknown', 'jobStatus', { jobId }) });
    assert.equal(status.result.result.outcomeUnknown, true);
    assert.equal(status.result.outcomeUnknown, true);
    assert.equal((await observer.command({ command: 'operationStatus', peerId: first.id, taskId: 'observe_unknown' })).result.state, 'unknown');
    for (const phase of ['before', 'after']) {
      const id = `status_block_${phase}`;
      const denied = await observer.command({ command: 'dispatch', peerId: second.id, task: task(id, 'writeFile', { path: `${id}.txt`, text: 'blocked' }, `new_run_${phase}`) });
      assert.equal(denied.error.code, 'UNCERTAIN_SIDE_EFFECT');
      assert.equal(second.events.some(event => event.event === 'task_started' && event.taskId === id), false);
      if (phase === 'before') { await observer.stop(); observer = await startNode(dir, observerConfig); nodes.push(observer); await Promise.all([waitConnected(observer, first.id), waitConnected(observer, second.id)]); }
    }
    assert.equal((await first.command({ command: 'reconcileJob', masterId: 'master', jobId, resolution: 'completed', note: 'Verified trusted print-only fixture timed out and stopped; no external effects' })).ok, true);
    const stillBlocked = await observer.command({ command: 'dispatch', peerId: second.id, task: task('job_only_still_blocked', 'writeFile', { path: 'job-only.txt', text: 'blocked' }) });
    assert.equal(stillBlocked.error.code, 'UNCERTAIN_SIDE_EFFECT');
    assert.equal((await first.command({ command: 'reconcile', masterId: 'master', taskId: 'status_origin', resolution: 'completed', note: 'Verified original approved fixture only printed and stopped' })).ok, true);
    assert.equal((await observer.command({ command: 'query', peerId: first.id, taskId: 'status_origin' })).result.state, 'reconciled');
    assert.notEqual((await observer.command({ command: 'operationStatus', peerId: first.id, taskId: 'observe_unknown' })).result.state, 'unknown');
    const resumed = await observer.command({ command: 'dispatch', peerId: second.id, task: task('after_owner_reconciliation', 'writeFile', { path: 'resumed.txt', text: 'approved after inspection' }) });
    assert.equal(resumed.result.status, 'ok');
    assert.equal(await fs.readFile(path.join(dir, 'workspace', 'resumed.txt'), 'utf8'), 'approved after inspection');
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('release regression: sensitive directory descendants are rejected by configuration validation without executing tools', async () => {
  const dir = await makeWorkspace('release-directory-isolation-');
  try {
    const security = await testSecurity(dir, 'servant', ['master']), filename = path.join(dir, 'node.json');
    const stateDir = path.join(dir, 'state'), ownerDir = path.join(dir, 'owner'), logDir = path.join(dir, 'logs');
    const sensitive = [stateDir, ownerDir, logDir, path.dirname(path.resolve(dir, security.key))];
    for (const root of sensitive) await fs.mkdir(path.join(root, 'nested-data'), { recursive: true });
    const config = { id: 'servant', port: 0, security, stateDir, operator: { enabled: true, sessionDirectory: ownerDir }, logFile: path.join(logDir, 'audit.jsonl') };
    for (const root of sensitive) {
      await fs.writeFile(filename, JSON.stringify({ ...config, policy: { grants: { master: { tools: ['readFile'], workspace: path.join(root, 'nested-data') } } } }));
      await assert.rejects(loadConfig(filename), error => error.code === 'UNSAFE_STATE_POLICY');
    }
    await fs.writeFile(filename, JSON.stringify({ ...config, policy: { grants: { master: { tools: ['readFile'], workspace: 'workspace' } } } }));
    assert.equal((await loadConfig(filename)).policy.grants.get('master').root, path.join(dir, 'workspace'));
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('release regression: normal completed jobs remain owner-readable but remote access is bound to the granting epoch', { timeout: 20000 }, async () => {
  const dir = await makeWorkspace('release-job-epoch-'), nodes = [];
  try {
    const script = path.join(dir, 'approved-output.mjs');
    await fs.writeFile(script, "console.log('approved output');\n");
    const policy = { grants: { master: { tools: ['exec', 'jobStatus', 'jobOutput', 'jobStdin', 'jobCancel'], workspace: 'workspace', maxTimeoutMs: 4000,
      execCommands: { output: { file: process.execPath, args: [script] } } } } };
    let servant = await startNode(dir, { id: 'servant', port: 0, policy }); nodes.push(servant);
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', peers: [peer(servant)], policy: {} }); nodes.push(master);
    await waitConnected(master, servant.id);
    const completed = await master.command({ command: 'dispatch', peerId: servant.id, task: task('old_job', 'exec', { command: 'output', args: [] }) });
    assert.equal(completed.result.status, 'ok');
    const jobId = completed.result.result.jobId;
    assert.match(completed.result.result.stdout, /approved output/);
    assert.equal((await servant.command({ command: 'setPolicy', policy })).ok, true);
    for (const tool of ['jobStatus', 'jobOutput', 'jobStdin', 'jobCancel']) {
      const response = await master.command({ command: 'dispatch', peerId: servant.id, task: task(`old_${tool}`, tool, { jobId, ...(tool === 'jobStdin' ? { text: 'ordinary data' } : {}) }) });
      assert.equal(response.result.error.code, 'TASK_POLICY_CHANGED');
      assert.equal(response.result.outcomeUnknown, undefined);
    }
    assert.match((await servant.command({ command: 'jobOutput', masterId: 'master', jobId })).result.text, /approved output/);
    const newJob = await master.command({ command: 'dispatch', peerId: servant.id, task: task('new_job', 'exec', { command: 'output', args: [] }) });
    assert.equal(newJob.result.status, 'ok');
    assert.equal((await master.command({ command: 'dispatch', peerId: servant.id, task: task('new_job_status', 'jobStatus', { jobId: newJob.result.result.jobId }) })).result.result.state, 'succeeded');
    const port = servant.port;
    await servant.stop(); const after = master.events.length;
    servant = await startNode(dir, { id: 'servant', port, policy }); nodes.push(servant);
    await waitConnected(master, servant.id, after);
    assert.equal((await master.command({ command: 'dispatch', peerId: servant.id, task: task('old_after_restart', 'jobOutput', { jobId }) })).result.error.code, 'TASK_POLICY_CHANGED');
    assert.match((await servant.command({ command: 'jobOutput', masterId: 'master', jobId })).result.text, /approved output/);
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});
