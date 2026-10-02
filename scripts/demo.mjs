import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { makeWorkspace, startNode, baseConfig, peer, waitConnected, stopAll } from './process-helper.mjs';
const dir = await makeWorkspace('intelligent-cells-demo-');
const nodes = [];
const start = async config => { const n = await startNode(dir, config, { verbose: true }); nodes.push(n); return n; };
const task = (taskId, tool, args, timeoutMs = 1000) => ({ taskId, tool, args, timeoutMs });
try {
  const b = await start(baseConfig('servant-b'));
  const a = await start(baseConfig('servant-a', { agent: 'deterministic-demo', peers: [peer(b)] }));
  const master = await start(baseConfig('master', { agent: 'deterministic-demo', peers: [peer(a), peer(b)], policy: { tools: [], allowedMasters: [] } }));
  await Promise.all([waitConnected(master, a.id), waitConnected(master, b.id), waitConnected(a, b.id)]);
  assert.equal(new Set(nodes.map(n => n.child.pid)).size, 3);
  const plan = await master.command({ command: 'plan', goal: 'demo' });
  assert.equal(plan.ok, true); assert.ok(plan.result.every(r => r.status === 'ok'));
  const dual = await a.command({ command: 'plan', goal: 'echo', text: 'servant-a is also master of servant-b' });
  assert.equal(dual.result[0].status, 'ok');
  const denied = await master.command({ command: 'dispatch', peerId: b.id, task: task('deny_shell', 'shell', { command: 'anything' }) });
  assert.equal(denied.result.error.code, 'TOOL_DENIED');
  const timeout = await master.command({ command: 'dispatch', peerId: b.id, task: task('timeout_wait', 'wait', { ms: 500 }, 60) });
  assert.equal(timeout.result.error.code, 'TASK_TIMEOUT');
  await b.command({ command: 'fault', latencyMs: 120 });
  const delayed = await master.command({ command: 'dispatch', peerId: b.id, task: task('delayed_echo', 'echo', { text: 'application-level latency' }) });
  assert.equal(delayed.result.status, 'ok');
  await b.command({ command: 'fault', latencyMs: 0 });
  const interruptedTask = task('connection_cut', 'wait', { ms: 450 });
  const interrupted = master.command({ command: 'dispatch', peerId: b.id, task: interruptedTask });
  await b.wait(e => e.event === 'task_started' && e.taskId === 'connection_cut');
  const mark = master.events.length;
  await b.command({ command: 'fault', cutInbound: true });
  assert.equal((await interrupted).error.code, 'OUTCOME_UNKNOWN');
  await waitConnected(master, b.id, mark);
  await b.wait(e => e.event === 'task_finished' && e.taskId === 'connection_cut');
  // Explicit resubmission is safe only while this same servant process retains its cache.
  const recovered = await master.command({ command: 'dispatch', peerId: b.id, task: interruptedTask });
  assert.equal(recovered.result.status, 'ok');
  assert.equal(b.events.filter(e => e.event === 'task_started' && e.taskId === 'connection_cut').length, 1);
  assert.equal(master.events.filter(e => e.event === 'task_started').length, 0);
  console.log(JSON.stringify({ event: 'demo_summary', passed: true, processes: nodes.map(n => ({ id: n.id, pid: n.child.pid, port: n.port })),
    checks: ['same executable / three separate processes', 'master agent plans remote tasks', 'servant-a executes and orchestrates', 'servant-b has no agent', 'servant policy denial', 'servant timeout', 'application latency', 'disconnect/reconnect', 'explicit duplicate recovers cached result', 'no master fallback'] }));
} catch (error) { console.error(error); process.exitCode = 1; }
finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
