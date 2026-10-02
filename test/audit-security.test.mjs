import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { createTestIdentity } from '../scripts/test-identities.mjs';
import { makeWorkspace, startNode, stopAll, peer, waitConnected, testTlsOptions, testSecurity } from '../scripts/process-helper.mjs';

const task = (taskId, tool, args, timeoutMs = 1000) => ({ v: 2, type: 'task', taskId, tool, args, timeoutMs });
async function rawClient(dir, port, identity = 'master', claim = identity, options = {}) {
  const socket = tls.connect({ ...await testTlsOptions(dir, identity, options), host: '127.0.0.1', port });
  const messages = [], bus = new EventEmitter(); let buffer = '';
  socket.setEncoding('utf8'); socket.on('error', () => {});
  socket.on('data', data => { buffer += data; while (buffer.includes('\n')) { const i = buffer.indexOf('\n'); const msg = JSON.parse(buffer.slice(0, i)); buffer = buffer.slice(i + 1); messages.push(msg); bus.emit('message', msg); } });
  const wait = (predicate, after = 0) => {
    const found = messages.slice(after).find(predicate); if (found) return Promise.resolve(found);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { bus.off('message', listener); reject(new Error('Audit frame timeout')); }, 3000);
      const listener = msg => { if (predicate(msg)) { clearTimeout(timer); bus.off('message', listener); resolve(msg); } }; bus.on('message', listener);
    });
  };
  await new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', reject); });
  const send = value => socket.write(JSON.stringify({ ...value, v: 2 }) + '\n');
  send({ type: 'hello', nodeId: claim });
  return { socket, messages, wait, send };
}
async function closes(socket) {
  if (socket.destroyed) return;
  await new Promise((resolve, reject) => { const timer = setTimeout(() => { socket.destroy(); reject(new Error('Rejected audit connection did not close')); }, 4000); socket.once('close', () => { clearTimeout(timer); resolve(); }); });
}
const grant = workspace => ({ tools: ['echo', 'wait', 'readFile'], workspace, maxTimeoutMs: 2000, maxConcurrent: 2 });

test('independent security audit: authenticated identity defeats payload impersonation and isolates cache/cancel', { timeout: 20000 }, async () => {
  const dir = await makeWorkspace('identity-audit-'), nodes = [], clients = [];
  try {
    await fs.mkdir(path.join(dir, 'other'));
    await fs.writeFile(path.join(dir, 'workspace', 'private.txt'), 'MASTER_ONLY');
    await fs.writeFile(path.join(dir, 'other', 'private.txt'), 'OTHER_ONLY');
    const servant = await startNode(dir, { id: 'servant', port: 0, policy: { maxConcurrent: 4, grants: { master: grant('workspace'), other: grant('other') } } }); nodes.push(servant);
    const spoof = await rawClient(dir, servant.port, 'other', 'master'); clients.push(spoof);
    assert.equal((await spoof.wait(m => m.type === 'error')).error.code, 'MASTER_DENIED'); await closes(spoof.socket);
    const master = await rawClient(dir, servant.port, 'master'), other = await rawClient(dir, servant.port, 'other'); clients.push(master, other);
    await Promise.all([master.wait(m => m.type === 'welcome'), other.wait(m => m.type === 'welcome')]);
    master.send(task('same_id', 'readFile', { path: 'private.txt' }));
    assert.equal((await master.wait(m => m.type === 'result' && m.taskId === 'same_id')).result.text, 'MASTER_ONLY');
    other.send({ ...task('same_id', 'readFile', { path: 'private.txt' }), nodeId: 'master', masterId: 'master', policy: { workspace: path.join(dir, 'workspace') } });
    assert.equal((await other.wait(m => m.type === 'result' && m.taskId === 'same_id')).result.text, 'OTHER_ONLY');
    master.send(task('cancel_scoped', 'wait', { ms: 350 })); await master.wait(m => m.type === 'task_state' && m.taskId === 'cancel_scoped');
    other.send({ type: 'cancel', taskId: 'cancel_scoped', masterId: 'master' });
    assert.equal((await other.wait(m => m.type === 'cancel_ack')).accepted, false);
    assert.equal((await master.wait(m => m.type === 'result' && m.taskId === 'cancel_scoped')).status, 'ok');
    assert.equal(servant.events.filter(e => e.event === 'task_started' && e.taskId === 'same_id').length, 2);
  } finally { for (const client of clients) client.socket.destroy(); await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('independent security audit: trusted CA alone does not authorize a replacement unpinned certificate', { timeout: 10000 }, async () => {
  const dir = await makeWorkspace('pin-audit-'), nodes = [];
  try {
    const servant = await startNode(dir, { id: 'servant', port: 0, policy: { grants: { master: grant('workspace') } } }); nodes.push(servant);
    const client = await rawClient(dir, servant.port, 'master', 'master', { suffix: '-replacement' });
    try { await closes(client.socket); assert.equal(client.messages.some(m => m.type === 'welcome'), false); await servant.wait(e => e.event === 'identity_denied'); }
    finally { client.socket.destroy(); }
    assert.equal(servant.events.some(e => e.event === 'relationship_accepted'), false);
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('independent security audit: no plaintext or TLS1.2 downgrade and no certificate-free client', { timeout: 15000 }, async () => {
  const dir = await makeWorkspace('downgrade-audit-'), nodes = [];
  try {
    const servant = await startNode(dir, { id: 'servant', port: 0, policy: { grants: { master: grant('workspace') } } }); nodes.push(servant);
    const plain = net.connect({ host: '127.0.0.1', port: servant.port }); plain.on('error', () => {}); plain.resume();
    await new Promise(resolve => plain.once('connect', resolve)); plain.write(JSON.stringify({ v: 2, type: 'hello', nodeId: 'master' }) + '\n'); await closes(plain);
    const noCert = tls.connect({ host: '127.0.0.1', port: servant.port, ca: await fs.readFile(path.join(dir, 'identities', 'ca.pem')), checkServerIdentity: () => undefined, rejectUnauthorized: true }); noCert.on('error', () => {}); noCert.resume(); await closes(noCert);
    const oldTLS = tls.connect({ ...await testTlsOptions(dir), host: '127.0.0.1', port: servant.port, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }); oldTLS.on('error', () => {}); oldTLS.resume(); await closes(oldTLS);
    assert.equal(servant.events.some(e => e.event === 'relationship_accepted' || e.event === 'task_started'), false);
    const valid = await rawClient(dir, servant.port); try { assert.equal((await valid.wait(m => m.type === 'welcome')).nodeId, 'servant'); assert.equal(valid.socket.getProtocol(), 'TLSv1.3'); } finally { valid.socket.destroy(); }
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('independent security audit: passive byte relay sees encrypted task/result traffic only', { timeout: 15000 }, async () => {
  const dir = await makeWorkspace('ciphertext-audit-'), nodes = [], sockets = new Set(), captured = [];
  let relay;
  try {
    const servant = await startNode(dir, { id: 'servant', port: 0, policy: { grants: { master: grant('workspace') } } }); nodes.push(servant);
    relay = net.createServer(client => {
      const upstream = net.connect({ host: '127.0.0.1', port: servant.port });
      for (const sock of [client, upstream]) { sockets.add(sock); sock.on('error', () => {}); sock.on('close', () => sockets.delete(sock)); sock.on('data', data => captured.push(Buffer.from(data))); }
      client.pipe(upstream); upstream.pipe(client); client.on('close', () => upstream.destroy()); upstream.on('close', () => client.destroy());
    });
    await new Promise(resolve => relay.listen(0, '127.0.0.1', resolve));
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', peers: [{ ...peer(servant), port: relay.address().port }], policy: {} }); nodes.push(master);
    await waitConnected(master, servant.id);
    const sentinel = 'AUDIT_CLEAR_TEXT_MUST_NOT_APPEAR_838137742';
    const response = await master.command({ command: 'dispatch', peerId: servant.id, task: task('opaque_task', 'echo', { text: sentinel }) });
    assert.equal(response.result.result.text, sentinel);
    const bytes = Buffer.concat(captured);
    assert.ok(bytes.length > 500);
    assert.equal(bytes.includes(Buffer.from(sentinel)), false);
    assert.equal(bytes.includes(Buffer.from('opaque_task')), false);
    assert.equal(bytes.includes(Buffer.from('"type":"hello"')), false);
    await servant.wait(e => e.event === 'relationship_accepted' && e.transport === 'TLSv1.3' && e.authenticated === true);
  } finally { await stopAll(nodes); for (const socket of sockets) socket.destroy(); if (relay) await new Promise(resolve => relay.close(resolve)); await fs.rm(dir, { recursive: true, force: true }); }
});

test('independent security audit: policy reload cannot return cached data from the old workspace', { timeout: 15000 }, async () => {
  const dir = await makeWorkspace('reload-audit-'), nodes = [];
  let raw;
  try {
    await fs.mkdir(path.join(dir, 'changed')); await fs.writeFile(path.join(dir, 'changed', 'hello.txt'), 'CHANGED_ROOT');
    const servant = await startNode(dir, { id: 'servant', port: 0, policy: { grants: { master: grant('workspace') } } }); nodes.push(servant);
    raw = await rawClient(dir, servant.port); await raw.wait(m => m.type === 'welcome');
    const request = task('cached_read', 'readFile', { path: 'hello.txt' }); raw.send(request);
    assert.match((await raw.wait(m => m.type === 'result' && m.taskId === 'cached_read')).result.text, /servant-owned/);
    const config = JSON.parse(await fs.readFile(servant.filename, 'utf8')); config.policy.grants.master.workspace = 'changed'; await fs.writeFile(servant.filename, JSON.stringify(config));
    assert.equal((await servant.command({ command: 'reloadPolicy' })).ok, true);
    const mark = raw.messages.length; raw.send(request);
    assert.equal((await raw.wait(m => m.type === 'result' && m.taskId === 'cached_read', mark)).error.code, 'TASK_POLICY_CHANGED');
    raw.send(task('new_read', 'readFile', { path: 'hello.txt' })); assert.equal((await raw.wait(m => m.type === 'result' && m.taskId === 'new_read')).result.text, 'CHANGED_ROOT');
    assert.equal((await servant.command({ command: 'revoke', masterId: 'master' })).ok, true);
    raw.send(task('revoked_read', 'readFile', { path: 'hello.txt' })); assert.equal((await raw.wait(m => m.type === 'result' && m.taskId === 'revoked_read')).error.code, 'MASTER_DENIED');
  } finally { raw?.socket.destroy(); await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});


test('independent security audit: master refuses wrong server identity and replacement server pin', { timeout: 15000 }, async t => {
  const dir = await makeWorkspace('server-identity-audit-'), nodes = [];
  try {
    const imposter = await startNode(dir, { id: 'imposter', port: 0, policy: { grants: { master: grant('workspace') } } }); nodes.push(imposter);
    const security = await testSecurity(dir, 'master', ['servant', 'imposter']);
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', security, peers: [{ id: 'servant', host: '127.0.0.1', port: imposter.port }], policy: {} }); nodes.push(master);
    await master.wait(e => e.event === 'peer_error' && e.code === 'IDENTITY_MISMATCH');
    assert.equal(master.events.some(e => e.event === 'peer_connected'), false);
    assert.equal((await master.command({ command: 'dispatch', peerId: 'servant', task: task('wrong_server', 'echo', { text: 'must not disclose' }) })).error.code, 'PEER_UNAVAILABLE');
    await master.stop();
    const replacement = await createTestIdentity(dir, 'servant', { suffix: '-new' });
    const serverSecurity = await testSecurity(dir, 'servant', ['master']);
    serverSecurity.cert = replacement.cert; serverSecurity.key = replacement.key;
    const servant = await startNode(dir, { id: 'servant', port: 0, security: serverSecurity, policy: { grants: { master: grant('workspace') } } }); nodes.push(servant);
    const second = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', security, peers: [peer(servant)], policy: {} }); nodes.push(second);
    await second.wait(e => e.event === 'peer_error' && e.code === 'UNTRUSTED_IDENTITY');
    assert.equal(second.events.some(e => e.event === 'peer_connected'), false);
    assert.equal(servant.events.some(e => e.event === 'task_started'), false);
  } finally { await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('independent security audit: tampered encrypted task is refused and not automatically replayed', { timeout: 15000 }, async () => {
  const dir = await makeWorkspace('tamper-audit-'), nodes = [], sockets = new Set();
  let relay, armed = false, changed = false;
  try {
    const servant = await startNode(dir, { id: 'servant', port: 0, policy: { grants: { master: grant('workspace') } } }); nodes.push(servant);
    relay = net.createServer(client => {
      const upstream = net.connect({ host: '127.0.0.1', port: servant.port });
      for (const sock of [client, upstream]) { sockets.add(sock); sock.on('error', () => {}); sock.on('close', () => sockets.delete(sock)); }
      client.on('data', data => { const bytes = Buffer.from(data); if (armed && !changed) { bytes[bytes.length - 1] ^= 1; changed = true; armed = false; } upstream.write(bytes); });
      upstream.pipe(client); client.on('close', () => upstream.destroy()); upstream.on('close', () => client.destroy());
    });
    await new Promise(resolve => relay.listen(0, '127.0.0.1', resolve));
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', peers: [{ ...peer(servant), port: relay.address().port }], policy: {} }); nodes.push(master);
    await waitConnected(master, servant.id);
    const mark = master.events.length; armed = true;
    const request = task('tampered_task', 'echo', { text: 'never execute tampered ciphertext' });
    const response = await master.command({ command: 'dispatch', peerId: servant.id, task: request });
    assert.equal(changed, true); assert.equal(response.error.code, 'OUTCOME_UNKNOWN');
    await waitConnected(master, servant.id, mark);
    assert.equal(servant.events.some(e => e.event === 'task_started' && e.taskId === 'tampered_task'), false);
    assert.equal(master.events.filter(e => e.event === 'task_dispatched' && e.taskId === 'tampered_task').length, 1);
    assert.equal((await master.command({ command: 'dispatch', peerId: servant.id, task: request })).result.status, 'ok');
    assert.equal(servant.events.filter(e => e.event === 'task_started' && e.taskId === 'tampered_task').length, 1);
  } finally { await stopAll(nodes); for (const socket of sockets) socket.destroy(); if (relay) await new Promise(resolve => relay.close(resolve)); await fs.rm(dir, { recursive: true, force: true }); }
});
