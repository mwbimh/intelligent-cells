import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import { spawnSync } from 'node:child_process';
import { makeWorkspace, startNode, baseConfig, peer, waitConnected, stopAll } from '../scripts/process-helper.mjs';
import { createTestIdentity, testSecurity, testTlsOptions } from '../scripts/test-identities.mjs';
import { loadConfig, loadPolicy } from '../src/config.mjs';
import { inspectIdentity } from '../scripts/pairing.mjs';
const task = (taskId, tool, args, timeoutMs = 1000) => ({ taskId, tool, args, timeoutMs });

test('TLS wire capture exposes no task plaintext; nodes terminate direct mTLS', { timeout: 10000 }, async () => {
  const dir = await makeWorkspace('secure-wire-'), nodes = [], captured = [], sockets = new Set();
  let proxy;
  try {
    const b = await startNode(dir, baseConfig('servant-b')); nodes.push(b);
    proxy = net.createServer(client => {
      const upstream = net.connect(b.port, '127.0.0.1');
      for (const socket of [client, upstream]) { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {}); }
      client.on('data', data => captured.push(Buffer.from(data))); upstream.on('data', data => captured.push(Buffer.from(data)));
      client.pipe(upstream); upstream.pipe(client);
      client.on('close', () => upstream.destroy()); upstream.on('close', () => client.destroy());
    });
    await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));
    const m = await startNode(dir, baseConfig('master', { agent: 'deterministic-demo', policy: {}, peers: [{ ...peer(b), port: proxy.address().port }] })); nodes.push(m);
    await waitConnected(m, b.id);
    const marker = 'unique-cleartext-must-never-appear-over-the-wire-938274';
    const result = await m.command({ command: 'dispatch', peerId: b.id, task: task('encrypted_echo', 'echo', { text: marker }) });
    assert.equal(result.result.result.text, marker);
    const wire = Buffer.concat(captured);
    assert.ok(wire.length > 500); assert.equal(wire.includes(Buffer.from(marker)), false); assert.equal(wire.includes(Buffer.from('encrypted_echo')), false);
    assert.ok(b.events.some(e => e.event === 'relationship_accepted' && e.transport === 'TLSv1.3' && e.authenticated));
  } finally { await stopAll(nodes); for (const socket of sockets) socket.destroy(); if (proxy) await new Promise(resolve => proxy.close(resolve)); await fs.rm(dir, { recursive: true, force: true }); }
});

test('cancel, revocation, quota, and policy reload are enforced on existing TLS relationships', { timeout: 15000 }, async t => {
  const dir = await makeWorkspace('secure-lifecycle-'), nodes = [];
  try {
    const b = await startNode(dir, { id: 'servant-b', port: 0, logFile: 'audit.log', policy: { grants: { master: { tools: ['echo', 'wait', 'readFile'], workspace: 'workspace', maxTimeoutMs: 10000, maxWaitMs: 10000 } } } }); nodes.push(b);
    const m = await startNode(dir, baseConfig('master', { agent: 'deterministic-demo', policy: {}, peers: [peer(b)] })); nodes.push(m); await waitConnected(m, b.id);
    const dispatch = value => m.command({ command: 'dispatch', peerId: b.id, task: value });
    await t.test('authenticated cancellation terminates wait and releases slot', async () => {
      const pending = dispatch(task('cancel_wait', 'wait', { ms: 5000 }, 10000)); await b.wait(e => e.event === 'task_started' && e.taskId === 'cancel_wait');
      assert.equal((await m.command({ command: 'cancel', peerId: b.id, taskId: 'cancel_wait' })).result.requested, true);
      assert.equal((await pending).result.error.code, 'CANCELLED');
      assert.equal((await dispatch(task('after_cancel', 'echo', { text: 'available' }))).result.status, 'ok');
    });
    await t.test('revocation aborts active task and denies both new and cached tasks', async () => {
      const cached = task('cached_secret', 'readFile', { path: 'hello.txt' }); assert.equal((await dispatch(cached)).result.status, 'ok');
      const pending = dispatch(task('revoke_wait', 'wait', { ms: 5000 }, 10000)); await b.wait(e => e.event === 'task_started' && e.taskId === 'revoke_wait');
      await b.command({ command: 'revoke', masterId: 'master' });
      assert.equal((await pending).result.error.code, 'POLICY_REVOKED');
      assert.equal((await dispatch(cached)).result.error.code, 'MASTER_DENIED');
      assert.equal((await dispatch(task('after_revoke', 'echo', { text: 'denied' }))).result.error.code, 'MASTER_DENIED');
      assert.equal((await b.command({ command: 'reloadPolicy' })).ok, true);
      assert.equal((await dispatch(cached)).result.error.code, 'TASK_POLICY_CHANGED');
      assert.equal((await dispatch(task('after_reload', 'echo', { text: 'new grant' }))).result.status, 'ok');
    });
    await t.test('per-peer rate quota survives reload and task body never enters file audit log', async () => {
      const cfg = JSON.parse(await fs.readFile(b.filename, 'utf8')); cfg.policy.grants.master.maxTasksPerMinute = 1;
      await fs.writeFile(b.filename, JSON.stringify(cfg)); assert.equal((await b.command({ command: 'reloadPolicy' })).ok, true);
      assert.equal((await dispatch(task('quota_denied', 'echo', { text: 'payload-never-log-9821' }))).result.error.code, 'RATE_LIMITED');
      const audit = await fs.readFile(path.join(dir, 'audit.log'), 'utf8'); assert.ok(!audit.includes('payload-never-log-9821')); assert.ok(!audit.includes('Hello from'));
      for (const event of ['task_cancelled', 'policy_revoked', 'policy_reloaded', 'task_denied']) assert.ok(audit.includes(event));
    });
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('configuration requires mTLS and explicit pins; expired cert cannot start; pairing is read-only', async () => {
  const dir = await makeWorkspace('secure-config-');
  try {
    const filename = path.join(dir, 'config.json');
    await fs.writeFile(filename, JSON.stringify({ id: 'master', port: 0 }));
    await assert.rejects(loadConfig(filename), e => e.code === 'SECURITY_REQUIRED');
    const security = await testSecurity(dir, 'master', []);
    await fs.writeFile(filename, JSON.stringify({ id: 'master', port: 0, security, policy: { grants: { unknown: { tools: ['echo'] } } } }));
    await assert.rejects(loadConfig(filename), e => e.code === 'INVALID_CONFIG');
    const expired = await createTestIdentity(dir, 'expired', { expired: true });
    await fs.writeFile(filename, JSON.stringify({ id: 'expired', port: 0, security: { ...security, cert: expired.cert, key: expired.key } }));
    await assert.rejects(loadConfig(filename), e => e.code === 'CERTIFICATE_EXPIRED');
    const publicInfo = await inspectIdentity(security.cert, 'master'); assert.equal(publicInfo.nodeId, 'master'); assert.match(publicInfo.fingerprint256, /^[A-F0-9]{64}$/); assert.ok(!JSON.stringify(publicInfo).includes('PRIVATE KEY'));
    await assert.rejects(inspectIdentity(security.cert, 'other'), /does not match/);
    await assert.rejects(loadPolicy({ grants: { master: { tools: ['unknown'] } } }), e => e.code === 'INVALID_CONFIG');
    const stdout = spawnSync(process.execPath, ['scripts/pairing.mjs', 'inspect', security.cert, 'master'], { encoding: 'utf8' }); assert.equal(stdout.status, 0); assert.equal(JSON.parse(stdout.stdout).nodeId, 'master');
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});


test('expired client certificate is rejected by real TLS before application authorization', { timeout: 10000 }, async () => {
  const dir = await makeWorkspace('expired-wire-'), nodes = [];
  try {
    const b = await startNode(dir, baseConfig('servant-b')); nodes.push(b);
    const socket = tls.connect({ ...await testTlsOptions(dir, 'master', { expired: true, suffix: '-expired' }), host: '127.0.0.1', port: b.port });
    const messages = []; socket.on('data', chunk => messages.push(chunk)); socket.on('error', () => {});
    socket.on('secureConnect', () => socket.write(JSON.stringify({ v: 2, type: 'hello', nodeId: 'master' }) + '\n'));
    await new Promise((resolve, reject) => { const timer = setTimeout(() => { socket.destroy(); reject(new Error('Expired TLS client did not close')); }, 4000); socket.once('close', () => { clearTimeout(timer); resolve(); }); });
    assert.equal(Buffer.concat(messages).includes(Buffer.from('welcome')), false);
    assert.ok(!b.events.some(e => e.event === 'relationship_accepted'));
    await b.wait(e => e.event === 'tls_denied');
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('result-cache byte pressure keeps task tombstones and does not reexecute', { timeout: 10000 }, async () => {
  const dir = await makeWorkspace('cache-budget-'), nodes = [];
  try {
    const b = await startNode(dir, { id: 'servant-b', port: 0, policy: { maxCacheBytes: 1024, grants: { master: { tools: ['echo'] } } } }); nodes.push(b);
    const m = await startNode(dir, baseConfig('master', { agent: 'deterministic-demo', policy: {}, peers: [peer(b)] })); nodes.push(m); await waitConnected(m, b.id);
    const value = task('cache_too_large', 'echo', { text: 'x'.repeat(2000) });
    const dispatch = () => m.command({ command: 'dispatch', peerId: b.id, task: value });
    assert.equal((await dispatch()).result.error.code, 'RESULT_CACHE_FULL');
    assert.equal((await dispatch()).result.error.code, 'RESULT_CACHE_FULL');
    assert.equal(b.events.filter(e => e.event === 'task_started' && e.taskId === value.taskId).length, 1);
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});


test('authenticated cancel suppresses a recorded task before fault-delayed write starts', { timeout: 10000 }, async () => {
  const dir = await makeWorkspace('cancel-delayed-'), nodes = [];
  try {
    const b = await startNode(dir, { id: 'servant-b', port: 0, faultInjection: true, policy: { grants: { master: { tools: ['writeFile'], workspace: 'workspace' } } } }); nodes.push(b);
    const m = await startNode(dir, baseConfig('master', { agent: 'deterministic-demo', policy: {}, peers: [peer(b)] })); nodes.push(m); await waitConnected(m, b.id);
    await b.command({ command: 'fault', latencyMs: 500 });
    const pending = m.command({ command: 'dispatch', peerId: b.id, task: task('cancel_before_start', 'writeFile', { path: 'must-not-exist.txt', text: 'not committed' }) });
    await b.wait(e => e.event === 'task_started' && e.taskId === 'cancel_before_start');
    await m.command({ command: 'cancel', peerId: b.id, taskId: 'cancel_before_start' });
    assert.equal((await pending).result.error.code, 'CANCELLED');
    await assert.rejects(fs.stat(path.join(dir, 'workspace', 'must-not-exist.txt')), { code: 'ENOENT' });
    const retry = await m.command({ command: 'dispatch', peerId: b.id, task: task('cancel_before_start', 'writeFile', { path: 'must-not-exist.txt', text: 'not committed' }) });
    assert.equal(retry.result.error.code, 'CANCELLED');
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});


test('policy rejects executable or fixed script writable by any peer', async () => {
  const dir = await makeWorkspace('exec-immutable-policy-');
  try {
    await fs.mkdir(path.join(dir, 'read-only'));
    const code = path.join(dir, 'workspace', 'code.mjs'); await fs.writeFile(code, 'console.log("trusted initially")');
    const writer = { tools: ['writeFile', 'editFile'], workspace: 'workspace' };
    const executor = { tools: ['exec'], workspace: 'read-only', execCommands: { fixture: { file: process.execPath, args: [code] } } };
    await assert.rejects(loadPolicy({ grants: { writer, executor } }, dir), e => e.code === 'UNSAFE_EXEC_POLICY');
    executor.execCommands.fixture = { file: code, args: [] };
    await assert.rejects(loadPolicy({ grants: { writer, executor } }, dir), e => e.code === 'UNSAFE_EXEC_POLICY');
    executor.execCommands.fixture = { file: process.execPath, args: ['../workspace/code.mjs'] };
    await assert.rejects(loadPolicy({ grants: { writer, executor } }, dir), e => e.code === 'UNSAFE_EXEC_POLICY');
    executor.execCommands.fixture = { file: process.execPath, args: ['../workspace/new-code.mjs'] };
    await assert.rejects(loadPolicy({ grants: { writer, executor } }, dir), e => e.code === 'UNSAFE_EXEC_POLICY');
    const fixed = path.join(dir, 'trusted-code.mjs'); await fs.writeFile(fixed, 'console.log("trusted")');
    executor.execCommands.fixture = { file: process.execPath, args: [fixed] };
    assert.equal((await loadPolicy({ grants: { writer, executor } }, dir)).grants.size, 2);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
