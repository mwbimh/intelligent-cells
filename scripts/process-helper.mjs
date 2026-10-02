import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { initTestCA, testSecurity, testTlsOptions } from './test-identities.mjs';
export { testSecurity, testTlsOptions };
export const testDirectoriesByPort = new Map();
const entrypoint = fileURLToPath(new URL('../src/main.mjs', import.meta.url));

export async function makeWorkspace(prefix = 'intelligent-cells-') {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  await fs.writeFile(path.join(dir, '.disposable-test-only'), 'ephemeral identities\n');
  await initTestCA(dir);
  await fs.mkdir(path.join(dir, 'workspace'));
  await fs.writeFile(path.join(dir, 'workspace', 'hello.txt'), 'Hello from the servant-owned approved workspace.\n');
  return dir;
}
export async function startNode(dir, config, { verbose = false } = {}) {
  config = structuredClone(config);
  if (config.policy?.allowedMasters || config.policy?.tools) {
    const legacy = config.policy, grants = {};
    for (const id of legacy.allowedMasters ?? []) if (id !== config.id) grants[id] = { ...legacy, allowedMasters: undefined, maxTaskRecords: undefined };
    config.policy = { grants, maxConcurrent: legacy.maxConcurrent ?? 4, maxTaskRecords: legacy.maxTaskRecords };
  }
  if (!config.security) config.security = await testSecurity(dir, config.id, ['master', 'servant-a', ...Object.keys(config.policy?.grants ?? {}), ...(config.peers ?? []).map(p => p.id)]);
  const filename = path.join(dir, `${config.id}.json`);
  await fs.writeFile(filename, JSON.stringify(config, null, 2));
  const child = spawn(process.execPath, [entrypoint, '--config', filename], { stdio: ['pipe', 'pipe', 'pipe'] });
  const events = [], bus = new EventEmitter();
  let buffer = '', stderr = '', sequence = 0, exited = false;
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', data => {
    buffer += data;
    while (buffer.includes('\n')) {
      const cut = buffer.indexOf('\n'), line = buffer.slice(0, cut); buffer = buffer.slice(cut + 1);
      if (verbose) process.stdout.write(line + '\n');
      try { const event = JSON.parse(line); events.push(event); bus.emit('event', event); } catch { /* stdout protocol checked by tests */ }
    }
  });
  child.stderr.on('data', data => { stderr += data; if (verbose) process.stderr.write(data); });
  child.stdin.on('error', () => {});
  const exit = new Promise(resolve => child.once('exit', (code, signal) => { exited = true; bus.emit('exit'); resolve({ code, signal }); }));
  const wait = (predicate, timeout = 6000, after = 0) => {
    const found = events.slice(after).find(predicate); if (found) return Promise.resolve(found);
    return new Promise((resolve, reject) => {
      const cleanup = () => { clearTimeout(timer); bus.off('event', listener); bus.off('exit', onExit); };
      const listener = event => { if (predicate(event)) { cleanup(); resolve(event); } };
      const onExit = () => { cleanup(); reject(new Error(`${config.id} exited while waiting; stderr=${stderr}`)); };
      const timer = setTimeout(() => { cleanup(); reject(new Error(`${config.id}: event wait timed out; stderr=${stderr}`)); }, timeout);
      bus.on('event', listener); bus.on('exit', onExit);
      if (exited) onExit();
    });
  };
  const command = value => {
    const requestId = `${config.id}-${++sequence}`;
    const response = wait(e => e.event === 'command_result' && e.requestId === requestId, 10000);
    child.stdin.write(JSON.stringify({ ...value, requestId }) + '\n'); return response;
  };
  const stop = async () => {
    if (exited) return exit;
    await command({ command: 'shutdown' });
    return Promise.race([exit, new Promise((_, reject) => { const t = setTimeout(() => reject(new Error(`${config.id} did not exit cleanly`)), 3000); t.unref(); })]);
  };
  try {
    const ready = await wait(e => e.event === 'node_ready');
    testDirectoriesByPort.set(ready.port, dir);
    return { child, config, filename, events, wait, command, stop, exit, port: ready.port, id: config.id, get stderr() { return stderr; } };
  } catch (error) { child.kill(); throw error; }
}
export function baseConfig(id, overrides = {}) {
  return { id, host: '127.0.0.1', port: 0, faultInjection: true,
    policy: { allowedMasters: ['master', 'servant-a'], tools: ['echo', 'wait', 'readFile'], workspace: 'workspace', maxConcurrent: 1, maxTimeoutMs: 1000, maxWaitMs: 5000, maxReadBytes: 16384 }, ...overrides };
}
export const peer = node => ({ id: node.id, host: '127.0.0.1', port: node.port });
export async function waitConnected(node, peerId, after = 0) { return node.wait(e => e.event === 'peer_connected' && e.peerId === peerId, 6000, after); }
export async function stopAll(nodes) {
  for (const node of [...nodes].reverse()) {
    try { await node.stop(); } catch { node.child.kill('SIGTERM'); await node.exit; }
  }
}
