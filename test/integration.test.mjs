import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import tls from 'node:tls';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';
import { makeWorkspace, startNode, baseConfig, peer, waitConnected, stopAll, testTlsOptions, testDirectoriesByPort } from '../scripts/process-helper.mjs';
const entrypoint = fileURLToPath(new URL('../src/main.mjs', import.meta.url));
const task = (taskId, tool, args, timeoutMs = 1000) => ({ taskId, tool, args, timeoutMs });
async function rawClient(port, id = 'master') {
  const socket = tls.connect({ ...await testTlsOptions(testDirectoriesByPort.get(port)), host: '127.0.0.1', port });
  let buffer = ''; const messages = [], bus = new EventEmitter();
  socket.setEncoding('utf8'); socket.on('error', () => {});
  socket.on('data', data => {
    buffer += data;
    while (buffer.includes('\n')) {
      const i = buffer.indexOf('\n'); const msg = JSON.parse(buffer.slice(0, i)); buffer = buffer.slice(i + 1);
      messages.push(msg); bus.emit('message', msg);
    }
  });
  const wait = (predicate, after = 0) => {
    const found = messages.slice(after).find(predicate); if (found) return Promise.resolve(found);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { bus.off('message', listener); reject(new Error('Raw frame timeout')); }, 3000);
      const listener = message => { if (predicate(message)) { clearTimeout(timer); bus.off('message', listener); resolve(message); } };
      bus.on('message', listener);
    });
  };
  const send = msg => socket.write(JSON.stringify({ ...msg, v: 2 }) + '\n');
  await new Promise(resolve => socket.once('secureConnect', resolve)); send({ type: 'hello', nodeId: id });
  return { socket, messages, wait, send };
}

test('real subprocess integration: directed relationships, local authority, failures and lifecycle', { timeout: 30000 }, async t => {
  const dir = await makeWorkspace('intelligent-cells-test-'); const nodes = [];
  const start = async cfg => { const node = await startNode(dir, cfg); nodes.push(node); return node; };
  try {
    const bCfg = baseConfig('servant-b', { logFile: 'servant-b.log' }); bCfg.policy.maxTimeoutMs = 500;
    const b = await start(bCfg);
    const a = await start(baseConfig('servant-a', { agent: 'deterministic-demo', peers: [peer(b)] }));
    const master = await start(baseConfig('master', { agent: 'deterministic-demo', peers: [peer(a), peer(b)], policy: {} }));
    await Promise.all([waitConnected(master, a.id), waitConnected(master, b.id), waitConnected(a, b.id)]);
    const dispatch = value => master.command({ command: 'dispatch', peerId: b.id, task: value });

    await t.test('three distinct PIDs use one executable; remote agent plan returns echo and confined file data', async () => {
      assert.equal(new Set(nodes.map(n => n.child.pid)).size, 3);
      const response = await master.command({ command: 'plan', goal: 'demo' });
      assert.equal(response.ok, true); assert.equal(response.result.length, 2);
      assert.ok(response.result.every(x => x.status === 'ok'));
      assert.match(response.result[1].result.text, /servant-owned/);
      assert.equal(master.events.filter(e => e.event === 'task_started').length, 0);
    });
    await t.test('one node can execute as servant and orchestrate as master; pure servant needs no agent', async () => {
      await a.wait(e => e.event === 'task_started' && e.masterId === 'master');
      const response = await a.command({ command: 'plan', goal: 'echo', text: 'dual role proof' });
      assert.equal(response.result[0].result.text, 'dual role proof');
      await b.wait(e => e.event === 'task_started' && e.masterId === a.id);
      const noAgent = await b.command({ command: 'plan', goal: 'demo' });
      assert.equal(noAgent.error.code, 'AGENT_REQUIRED');
    });
    await t.test('tool allowlist is authoritative and cannot be changed by request data', async () => {
      const response = await dispatch({ ...task('denied_shell', 'shell', { command: 'echo x' }), policy: { tools: ['shell'] } });
      assert.equal(response.result.error.code, 'TOOL_DENIED');
      assert.ok(!b.events.some(e => e.event === 'task_started' && e.taskId === 'denied_shell'));
      const args = await dispatch(task('denied_echo_args', 'echo', { text: 'x', command: 'anything' }));
      assert.equal(args.result.error.code, 'INVALID_ARGS');
    });
    await t.test('path traversal, absolute paths, Windows aliases and symlinks are rejected', async t2 => {
      for (const [i, value] of ['../secret', '/etc/passwd', 'a/../../x', 'C:\\Windows\\x', 'nested\\file', 'hello.txt:stream'].entries()) {
        const response = await dispatch(task(`bad_path_${i}`, 'readFile', { path: value }));
        assert.equal(response.result.error.code, 'PATH_DENIED');
      }
      try { await fs.symlink(path.join(dir, 'workspace', 'hello.txt'), path.join(dir, 'workspace', 'link.txt')); }
      catch (error) { if (['EPERM', 'EACCES'].includes(error.code)) { t2.diagnostic('Symlink test unavailable on this OS/account'); return; } throw error; }
      const response = await dispatch(task('bad_symlink', 'readFile', { path: 'link.txt' }));
      assert.equal(response.result.error.code, 'PATH_DENIED');
      await fs.mkdir(path.join(dir, 'workspace', 'folder'));
      const directory = await dispatch(task('bad_directory', 'readFile', { path: 'folder' }));
      assert.equal(directory.result.error.code, 'PATH_DENIED');
    });
    await t.test('file size and argument bounds are enforced locally', async () => {
      await fs.writeFile(path.join(dir, 'workspace', 'large.txt'), 'x'.repeat(20000));
      const large = await dispatch(task('large_file', 'readFile', { path: 'large.txt' }));
      assert.equal(large.result.error.code, 'FILE_TOO_LARGE');
      const longWait = await dispatch(task('long_wait', 'wait', { ms: 6000 }));
      assert.equal(longWait.result.error.code, 'INVALID_ARGS');
      const hugeEcho = await dispatch(task('huge_echo', 'echo', { text: 'x'.repeat(4097) }));
      assert.equal(hugeEcho.result.error.code, 'INVALID_ARGS');
    });
    await t.test('servant concurrency cap rejects parallel work rather than silently queueing', async () => {
      const pending = dispatch(task('busy_wait', 'wait', { ms: 180 }));
      await b.wait(e => e.event === 'task_started' && e.taskId === 'busy_wait');
      const busy = await dispatch(task('busy_echo', 'echo', { text: 'x' }));
      assert.equal(busy.result.error.code, 'BUSY');
      assert.equal((await pending).result.status, 'ok');
    });
    await t.test('servant clamps requested timeout to its own maximum and releases capacity', async () => {
      const response = await dispatch(task('timeout_local', 'wait', { ms: 900 }, 2000));
      assert.equal(response.result.error.code, 'TASK_TIMEOUT');
      const start = b.events.find(e => e.event === 'task_started' && e.taskId === 'timeout_local');
      assert.equal(start.timeoutMs, 500);
      const next = await dispatch(task('after_timeout', 'echo', { text: 'slot released' }));
      assert.equal(next.result.status, 'ok');
    });
    await t.test('running duplicate subscribes, completed duplicate returns cache, changed ID payload is denied', async () => {
      const value = task('duplicate_wait', 'wait', { ms: 180 });
      const first = dispatch(value);
      await b.wait(e => e.event === 'task_started' && e.taskId === value.taskId);
      const raw = await rawClient(b.port);
      try {
        await raw.wait(m => m.type === 'welcome'); raw.send({ ...value, type: 'task' });
        await raw.wait(m => m.type === 'task_state' && m.state === 'duplicate');
        assert.equal((await raw.wait(m => m.type === 'result')).status, 'ok');
        assert.equal((await first).result.status, 'ok');
        assert.equal((await dispatch(value)).result.status, 'ok');
        const conflict = await dispatch(task(value.taskId, 'echo', { text: 'different' }));
        assert.equal(conflict.result.error.code, 'TASK_ID_CONFLICT');
        assert.equal(b.events.filter(e => e.event === 'task_started' && e.taskId === value.taskId).length, 1);
      } finally { raw.socket.destroy(); }
    });
    await t.test('bounded application latency delays execution without changing networking', async () => {
      await b.command({ command: 'fault', latencyMs: 100 }); const start = performance.now();
      const response = await dispatch(task('latency_echo', 'echo', { text: 'delay' }));
      assert.equal(response.result.status, 'ok'); assert.ok(performance.now() - start >= 80);
      await b.command({ command: 'fault', latencyMs: 0 });
    });
    await t.test('mid-task connection cut gives unknown outcome, reconnects, never retries or falls back', async () => {
      const value = task('cut_wait', 'wait', { ms: 250 }); const pending = dispatch(value);
      await b.wait(e => e.event === 'task_started' && e.taskId === value.taskId);
      const mark = master.events.length;
      await b.command({ command: 'fault', cutInbound: true });
      assert.equal((await pending).error.code, 'OUTCOME_UNKNOWN');
      await waitConnected(master, b.id, mark); await waitConnected(a, b.id, a.events.findIndex(e => e.event === 'peer_disconnected' && e.peerId === b.id));
      await b.wait(e => e.event === 'task_finished' && e.taskId === value.taskId);
      assert.equal(master.events.filter(e => e.event === 'task_dispatched' && e.taskId === value.taskId).length, 1);
      assert.equal(master.events.filter(e => e.event === 'task_started').length, 0);
      const cached = await dispatch(value); assert.equal(cached.result.status, 'ok');
      assert.equal(b.events.filter(e => e.event === 'task_started' && e.taskId === value.taskId).length, 1);
      const reconnects = master.events.slice(mark).filter(e => e.event === 'peer_reconnect_scheduled');
      assert.ok(reconnects.length); assert.ok(reconnects.every(e => e.delayMs >= 100 && e.delayMs <= 1600));
    });
    await t.test('unknown master relationship is denied before task execution', async () => {
      const raw = await rawClient(b.port, 'stranger');
      try { assert.equal((await raw.wait(m => m.type === 'error')).error.code, 'MASTER_DENIED'); }
      finally { raw.socket.destroy(); }
    });
    await t.test('malformed and oversized frames disconnect only the offending connection', async () => {
      for (const payload of ['{bad-json}\n', 'x'.repeat(131073)]) {
        const raw = await rawClient(b.port); await raw.wait(m => m.type === 'welcome');
        const closed = new Promise(resolve => raw.socket.once('close', resolve)); raw.socket.write(payload); await closed;
      }
      assert.equal((await dispatch(task('after_bad_frame', 'echo', { text: 'still alive' }))).result.status, 'ok');
    });
    await t.test('JSONL audit log records task ids, denials, timeout, duplicate and node identities', async () => {
      const rows = (await fs.readFile(path.join(dir, 'servant-b.log'), 'utf8')).trim().split('\n').map(JSON.parse);
      for (const event of ['node_ready', 'task_started', 'task_finished', 'task_denied', 'task_duplicate', 'fault_injected']) assert.ok(rows.some(row => row.event === event), event);
      assert.ok(rows.every(row => row.nodeId === b.id && Number.isInteger(row.pid) && typeof row.timestamp === 'string'));
    });
    await t.test('servant clean shutdown and disconnected target produce explicit error, no master fallback', async () => {
      const mark = master.events.length;
      assert.deepEqual(await b.stop(), { code: 0, signal: null });
      await master.wait(e => e.event === 'peer_disconnected' && e.peerId === b.id, 6000, mark);
      const response = await dispatch(task('offline_echo', 'echo', { text: 'do not run here' }));
      assert.equal(response.error.code, 'PEER_UNAVAILABLE');
      assert.equal(master.events.filter(e => e.event === 'task_started').length, 0);
      assert.deepEqual(await master.stop(), { code: 0, signal: null });
      assert.deepEqual(await a.stop(), { code: 0, signal: null });
    });
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('configuration rejects all non-loopback listeners and peers', async () => {
  const dir = await makeWorkspace('intelligent-cells-config-');
  try {
    for (const [i, cfg] of [
      { ...baseConfig('invalid'), host: '0.0.0.0' },
      { ...baseConfig('invalid'), host: 'localhost' },
      { ...baseConfig('invalid'), agent: 'deterministic-demo', peers: [{ id: 'other', host: '192.168.0.2', port: 7311 }] },
      { ...baseConfig('invalid'), agent: 'deterministic-demo', peers: [{ id: 'other', host: '::1', port: 7311 }] }
    ].entries()) {
      const filename = path.join(dir, `bad-${i}.json`); await fs.writeFile(filename, JSON.stringify(cfg));
      const run = spawnSync(process.execPath, [entrypoint, '--config', filename], { encoding: 'utf8', timeout: 3000 });
      assert.equal(run.status, 1); assert.match(run.stderr, /LOOPBACK_ONLY/); assert.ok(!run.stdout.includes('node_ready'));
    }
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('default-deny policy and bounded retention tombstones fail closed', { timeout: 10000 }, async () => {
  const dir = await makeWorkspace('intelligent-cells-policy-'); const nodes = [];
  try {
    const denied = await startNode(dir, { id: 'default-deny', port: 0 }); nodes.push(denied);
    const rawDenied = await rawClient(denied.port);
    try { assert.equal((await rawDenied.wait(m => m.type === 'error')).error.code, 'MASTER_DENIED'); } finally { rawDenied.socket.destroy(); }
    const cfg = baseConfig('small-store'); cfg.policy.maxTaskRecords = 1;
    const bounded = await startNode(dir, cfg); nodes.push(bounded);
    const raw = await rawClient(bounded.port);
    try {
      await raw.wait(m => m.type === 'welcome');
      raw.send({ ...task('first', 'echo', { text: 'one' }), type: 'task' });
      assert.equal((await raw.wait(m => m.type === 'result' && m.taskId === 'first')).status, 'ok');
      raw.send({ ...task('second', 'echo', { text: 'two' }), type: 'task' });
      assert.equal((await raw.wait(m => m.type === 'result' && m.taskId === 'second')).status, 'ok');
      const mark = raw.messages.length;
      raw.send({ ...task('first', 'echo', { text: 'one' }), type: 'task' });
      assert.equal((await raw.wait(m => m.type === 'result' && m.taskId === 'first', mark)).error.code, 'TASK_HISTORY_EXPIRED');
      assert.equal(bounded.events.filter(e => e.event === 'task_started').length, 2);
    } finally { raw.socket.destroy(); }
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('active cooperative task is cancelled by clean node shutdown', { timeout: 10000 }, async () => {
  const dir = await makeWorkspace('intelligent-cells-stop-'); const nodes = [];
  try {
    const cfg = baseConfig('stoppable'); cfg.policy.maxTimeoutMs = 10000;
    const node = await startNode(dir, cfg); nodes.push(node);
    const raw = await rawClient(node.port);
    try {
      await raw.wait(m => m.type === 'welcome'); raw.send({ ...task('active_stop', 'wait', { ms: 5000 }, 10000), type: 'task' });
      await node.wait(e => e.event === 'task_started' && e.taskId === 'active_stop');
      assert.deepEqual(await node.stop(), { code: 0, signal: null });
      assert.ok(node.events.some(e => e.event === 'task_finished' && e.error?.code === 'SHUTTING_DOWN'));
    } finally { raw.socket.destroy(); }
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('review regressions: hostile framing and encoded response bounds', { timeout: 15000 }, async t => {
  const dir = await makeWorkspace('intelligent-cells-regression-'); const nodes = [];
  try {
    const cfg = baseConfig('regression'); cfg.policy.maxReadBytes = 65536;
    const node = await startNode(dir, cfg); nodes.push(node);
    await node.command({ command: 'fault', latencyMs: 1 });
    await t.test('rejected hello is terminal even with a valid hello and task pipelined behind it', async () => {
      const mark = node.events.length;
      const socket = tls.connect({ ...await testTlsOptions(dir), host: '127.0.0.1', port: node.port });
      socket.on('error', () => {}); socket.resume();
      await new Promise(resolve => socket.once('secureConnect', resolve));
      const closed = new Promise(resolve => socket.once('close', resolve));
      socket.write([
        { v: 2, type: 'hello', nodeId: 'intruder' },
        { v: 2, type: 'hello', nodeId: 'master' },
        { v: 2, type: 'task', ...task('after_refusal', 'echo', { text: 'must not execute' }) }
      ].map(JSON.stringify).join('\n') + '\n');
      await closed;
      await node.command({ command: 'status' });
      assert.ok(node.events.slice(mark).some(e => e.event === 'relationship_denied'));
      assert.ok(!node.events.slice(mark).some(e => e.event === 'relationship_accepted' || e.event === 'task_started'));
    });
    await t.test('deep taskId cannot crash delayed request handling', async () => {
      const raw = await rawClient(node.port);
      try {
        await raw.wait(m => m.type === 'welcome');
        const closed = new Promise(resolve => raw.socket.once('close', resolve));
        raw.socket.write('{"v":2,"type":"task","taskId":' + '['.repeat(15000) + '0' + ']'.repeat(15000) + ',"tool":"echo","args":{"text":"x"},"timeoutMs":1000}\n');
        await closed;
        assert.equal((await node.command({ command: 'status' })).ok, true);
      } finally { raw.socket.destroy(); }
    });
    await t.test('invalid shallow taskId is never reflected in a rejection', async () => {
      const raw = await rawClient(node.port);
      try {
        await raw.wait(m => m.type === 'welcome'); raw.send({ type: 'task', taskId: { attacker: ['data'] }, tool: 'echo', args: { text: 'x' }, timeoutMs: 1000 });
        const response = await raw.wait(m => m.type === 'result');
        assert.equal(response.taskId, null); assert.equal(response.error.code, 'INVALID_TASK');
      } finally { raw.socket.destroy(); }
    });
    await t.test('escaped file contents produce bounded RESULT_TOO_LARGE, preserving the connection', async () => {
      await fs.writeFile(path.join(dir, 'workspace', 'escaped-bytes.txt'), Buffer.alloc(30000));
      const raw = await rawClient(node.port);
      try {
        await raw.wait(m => m.type === 'welcome'); raw.send({ ...task('escaped_file', 'readFile', { path: 'escaped-bytes.txt' }), type: 'task' });
        const response = await raw.wait(m => m.type === 'result');
        assert.equal(response.error.code, 'RESULT_TOO_LARGE');
        raw.send({ ...task('after_large', 'echo', { text: 'alive' }), type: 'task' });
        assert.equal((await raw.wait(m => m.type === 'result' && m.taskId === 'after_large')).status, 'ok');
      } finally { raw.socket.destroy(); }
    });
    await t.test('invalid shallow operator requestId is normalized and node keeps working', async () => {
      const mark = node.events.length;
      node.child.stdin.write('{"command":"status","requestId":{"not":"an id"}}\n');
      const response = await node.wait(e => e.event === 'command_result' && e.error?.code === 'INVALID_COMMAND', 3000, mark);
      assert.equal(response.requestId, null); assert.equal((await node.command({ command: 'status' })).ok, true);
    });
    for (const [name, payload] of [
      ['deep', '{"command":"status","requestId":' + '['.repeat(15000) + '0' + ']'.repeat(15000) + '}\n'],
      ['oversized', 'x'.repeat(131073)]
    ]) await t.test(`${name} operator frame closes the local input and shuts down cleanly`, async () => {
      const inputNode = await startNode(dir, baseConfig(`input-${name}`)); nodes.push(inputNode);
      inputNode.child.stdin.write(payload);
      await inputNode.wait(e => e.event === 'node_stopped');
      assert.deepEqual(await inputNode.exit, { code: 0, signal: null });
      assert.ok(inputNode.events.some(e => e.event === 'command_result' && e.error?.code === 'INVALID_FRAME'));
      assert.ok(!inputNode.stderr.includes('RangeError'));
    });
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});
