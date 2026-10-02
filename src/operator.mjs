import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { errorData, fail, isObject } from './errors.mjs';
import { applyPairing, identitySummary, removePairingPin, reviewIdentity, revokePairing } from './operator-identity.mjs';

const UI = fileURLToPath(new URL('../ui/', import.meta.url));
const commands = new Set(['listWorkspaceBindings','remoteWorkspaces','bindWorkspace','unbindWorkspace','setWorkspaceAutoProvision','ensureWorkspaceBinding','createWorkspace','reconcileWorkspaceCreation','status', 'permissions', 'listTasks', 'taskStatus', 'taskEvents', 'operationStatus', 'query', 'cancel', 'reconcile', 'revoke', 'reloadPolicy', 'setPolicy', 'shutdown', 'pairPeer', 'reviewPeer', 'revokePeer', 'removePeerPin', 'cancelTask', 'listJobs', 'jobStatus', 'jobCancel', 'reconcileJob', 'jobOutput']);
const readOnly = new Set(['listWorkspaceBindings','remoteWorkspaces','status', 'permissions', 'listTasks', 'taskStatus', 'taskEvents', 'operationStatus', 'query', 'reviewPeer', 'listJobs', 'jobStatus', 'jobOutput']);
const secret = () => randomBytes(32).toString('base64url');
const same = (a, b) => { if (typeof a !== 'string' || typeof b !== 'string') return false; const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };
function safeError(error) { const e = errorData(error); return { code: e.code, message: String(e.message).slice(0, 400) }; }
function cookie(req) { return (req.headers.cookie ?? '').split(';').map(s => s.trim()).find(s => s.startsWith('op_sid='))?.slice(7); }
async function body(req) {
  if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(req.headers['content-type'] ?? '')) fail('CONTENT_TYPE', 'Use application/json');
  let bytes = 0, result = '';
  for await (const chunk of req) { bytes += chunk.length; if (bytes > 65536) fail('BODY_TOO_LARGE', 'Operator request exceeds 64 KiB'); result += chunk; }
  try { const value = JSON.parse(result); if (!isObject(value)) throw new Error(); return value; } catch { fail('INVALID_JSON', 'Expected a JSON object'); }
}
export async function startOperator(node, config = {}) {
  if (config.host !== undefined && config.host !== '127.0.0.1') fail('OPERATOR_LOOPBACK_ONLY', 'Operator HTTP must bind 127.0.0.1');
  const port = config.port ?? 0;
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail('INVALID_CONFIG', 'Invalid operator port');
  const ttl = config.sessionTtlMs ?? 1800000;
  if (!Number.isInteger(ttl) || ttl < 1000 || ttl > 3600000) fail('INVALID_CONFIG', 'Operator session TTL must be 1 second to 1 hour');
  const assets = new Map(await Promise.all([['/', 'index.html', 'text/html; charset=utf-8'], ['/app.js', 'app.js', 'text/javascript; charset=utf-8'], ['/app.css', 'app.css', 'text/css; charset=utf-8']].map(async ([route, file, mime]) => [route, { bytes: await fs.readFile(path.join(UI, file)), mime }])));
  const sessions = new Map(), bootstraps = new Map(); let mutationQueue = Promise.resolve(), origin, server, ipc, ownerFile = null, ownerSecret = null, closed = false, badAttempts = [];
  function mint() { const token = secret(); for (const [key, until] of bootstraps) if (until < Date.now()) bootstraps.delete(key); if (bootstraps.size >= 8) bootstraps.delete(bootstraps.keys().next().value); bootstraps.set(token, Date.now() + 300000); return token; }
  const firstToken = mint();
  function respond(res, status, result, extra = {}) { const payload = JSON.stringify(result); res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(payload), ...extra }); res.end(payload); }
  function authenticated(req) {
    const sid = cookie(req), session = sid ? sessions.get(sid) : null;
    if (!session || session.until <= Date.now()) { if (sid) sessions.delete(sid); fail('UNAUTHENTICATED', 'Local owner sign-in required'); }
    return session;
  }
  async function execute(command) {
    if (!isObject(command) || !commands.has(command.command)) fail('INVALID_COMMAND', 'Command is not available in the operator UI');
    if (['bindWorkspace','unbindWorkspace','setWorkspaceAutoProvision'].includes(command.command) && !Number.isSafeInteger(command.expectedRevision)) fail('WORKSPACE_BINDING_CONFLICT', 'Refresh workspace mappings before saving');
    if (command.command === 'createWorkspace' && command.logicalWorkspaceId !== undefined && !Number.isSafeInteger(command.expectedRevision)) fail('WORKSPACE_BINDING_CONFLICT', 'Refresh workspace mappings before creating and binding');
    if (command.command === 'setPolicy' && !Number.isSafeInteger(command.expectedEpoch)) fail('POLICY_CONFLICT', 'Refresh the policy before saving');
    if (command.command === 'reviewPeer') return reviewIdentity(command.certificatePem, command.peerId, command.expectedFingerprint, node.config.security.ca);
    if (command.command === 'pairPeer') return applyPairing(node, command);
    if (command.command === 'revokePeer') return revokePairing(node, command);
    if (command.command === 'removePeerPin') return removePairingPin(node, command);
    if (command.command === 'shutdown') { setTimeout(() => { void node.command({ command: 'shutdown' }).catch(error => node.log('operator_stop_error', { code: error.code })); }, 100).unref(); return { stopping: true }; }
    return node.command(command);
  }
  async function runCommand(command) {
    if (readOnly.has(command.command)) return execute(command);
    const run = mutationQueue.catch(() => {}).then(() => execute(command));
    mutationQueue = run; return run;
  }
  server = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      if (req.socket.remoteAddress !== '127.0.0.1') fail('LOCAL_ONLY', 'Only local loopback clients are allowed');
      if (req.headers.host !== new URL(origin).host) fail('INVALID_HOST', 'Host does not match this local operator');
      if (req.headers.origin && req.headers.origin !== origin) fail('INVALID_ORIGIN', 'Origin does not match this local operator');
      if (req.headers['sec-fetch-site'] && !['same-origin', 'none'].includes(req.headers['sec-fetch-site'])) fail('INVALID_ORIGIN', 'Cross-site operator requests are forbidden');
      const url = new URL(req.url, origin);
      if (url.origin !== origin || url.search) fail('INVALID_PATH', 'Unexpected operator URL');
      if (req.method === 'GET' && assets.has(url.pathname)) { const asset = assets.get(url.pathname); res.writeHead(200, { 'Content-Type': asset.mime, 'Content-Length': asset.bytes.length }); res.end(asset.bytes); return; }
      if (!url.pathname.startsWith('/api/')) { respond(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'Not found' } }); return; }
      if (!['GET', 'POST'].includes(req.method)) fail('INVALID_METHOD', 'Only GET and POST are supported');
      if (req.method === 'POST' && req.headers.origin !== origin) fail('INVALID_ORIGIN', 'An exact same-origin header is required');
      if (req.method === 'POST' && url.pathname === '/api/ownerSession') {
        const input = await body(req);
        if (!ownerSecret || !same(ownerSecret, input.secret)) fail('UNAUTHENTICATED', 'Current process owner capability required');
        respond(res, 200, { ok: true, url: `${origin}/#token=${mint()}`, expiresInSeconds: 300 }); return;
      }
      if (req.method === 'POST' && url.pathname === '/api/session') {
        const input = await body(req);
        badAttempts = badAttempts.filter(time => Date.now() - time < 60000);
        if (badAttempts.length >= 20) fail('RATE_LIMITED', 'Too many failed owner sign-ins; retry after one minute');
        const token = [...bootstraps.keys()].find(value => same(value, input.token));
        if (!token || bootstraps.get(token) <= Date.now()) { badAttempts.push(Date.now()); fail('UNAUTHENTICATED', 'Owner token is invalid, expired or already used'); }
        bootstraps.delete(token);
        for (const [sid, session] of sessions) if (session.until <= Date.now()) sessions.delete(sid);
        if (sessions.size >= 8) sessions.delete(sessions.keys().next().value);
        const sid = secret(), session = { csrf: secret(), until: Date.now() + ttl }; sessions.set(sid, session);
        respond(res, 200, { ok: true, csrf: session.csrf, expiresAt: new Date(session.until).toISOString() }, { 'Set-Cookie': `op_sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(ttl / 1000)}` }); return;
      }
      const session = authenticated(req);
      if (req.method === 'POST' && !same(session.csrf, req.headers['x-operator-csrf'])) fail('CSRF_DENIED', 'Valid session CSRF token required');
      if (req.method === 'GET' && url.pathname === '/api/session') { respond(res, 200, { ok: true, csrf: session.csrf, expiresAt: new Date(session.until).toISOString() }); return; }
      if (req.method === 'POST' && url.pathname === '/api/logout') { sessions.delete(cookie(req)); respond(res, 200, { ok: true }, { 'Set-Cookie': 'op_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' }); return; }
      if (req.method === 'GET' && url.pathname === '/api/state') {
        const [status, permissions, incoming, outgoing, jobs] = await Promise.all([node.command({ command: 'status' }), node.command({ command: 'permissions' }), node.command({ command: 'listTasks', kind: 'incoming', limit: 100 }), node.command({ command: 'listTasks', kind: 'outgoing', limit: 100 }), node.command({ command: 'listJobs', limit: 100 })]);
        respond(res, 200, { ok: true, status, permissions, incoming, outgoing, jobs, workspaces: node.workspaceRegistry?.snapshot() ?? {revision:0,bindings:[],autoProvision:[],creations:[]}, identity: identitySummary(node) }); return;
      }
      if (req.method === 'GET' && url.pathname === '/api/logs') { respond(res, 200, { ok: true, ...(node.audit?.query({ limit: 100 }) ?? { records: [], unavailable: true, message: '未配置持久审计日志' }) }); return; }
      if (req.method === 'POST' && url.pathname === '/api/command') {
        const command = await body(req);
        const result = await runCommand(command);
        if (!readOnly.has(command.command)) node.log('operator_command', { command: command.command, ok: true });
        respond(res, 200, { ok: true, result }); return;
      }
      respond(res, 404, { ok: false, error: { code: 'NOT_FOUND', message: 'Unknown API' } });
    } catch (error) {
      const denied = ['UNAUTHENTICATED', 'CSRF_DENIED', 'INVALID_ORIGIN', 'INVALID_HOST', 'LOCAL_ONLY'].includes(error.code);
      if (!res.headersSent) respond(res, denied ? 403 : error.code === 'RATE_LIMITED' ? 429 : 400, { ok: false, error: safeError(error) }); else res.destroy();
    }
  });
  server.requestTimeout = 10000; server.headersTimeout = 10000; server.keepAliveTimeout = 1000; server.maxConnections = 32;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  origin = `http://127.0.0.1:${server.address().port}`;
  try {
    if (config.sessionDirectory) {
      if (process.platform === 'win32') fail('OWNER_FILE_UNSUPPORTED', 'Use an interactive terminal; Windows ACL provisioning requires owner review');
      const directory = path.resolve(config.sessionDirectory);
      await fs.mkdir(directory, { recursive: true, mode: 0o700 });
      const stat = await fs.lstat(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) || await fs.realpath(directory) !== directory) fail('UNSAFE_OWNER_DIRECTORY', 'Owner access directory must be canonical, private and owned by this user');
      ownerSecret = secret(); ownerFile = path.join(directory, `operator-${process.pid}-${randomBytes(6).toString('hex')}.json`);
      await fs.writeFile(ownerFile, JSON.stringify({ url: origin, secret: ownerSecret, pid: process.pid, createdAt: new Date().toISOString(), ephemeral: true }) + '\n', { flag: 'wx', mode: 0o600 });
    }
    if (config.socketPath) {
      if (process.platform === 'win32') fail('OPERATOR_IPC_UNSUPPORTED', 'Owner-only Unix IPC is unavailable on Windows; use the explicit interactive operator session');
      const filename = path.resolve(config.socketPath), directory = path.dirname(filename);
      await fs.mkdir(directory, { recursive: true, mode: 0o700 });
      const s = await fs.lstat(directory);
      if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o077) || await fs.realpath(directory) !== directory) fail('UNSAFE_OPERATOR_SOCKET', 'Socket directory must be a canonical owner-only directory (0700)');
      try { await fs.lstat(filename); fail('OPERATOR_SOCKET_EXISTS', 'Operator socket path exists; verify old process is stopped before manually removing it'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      ipc = net.createServer(socket => {
        socket.setTimeout(5000, () => socket.destroy());
        let data = '', done = false;
        socket.on('error', () => {});
        socket.on('data', chunk => {
          if (done) return;
          data += chunk; if (Buffer.byteLength(data) > 1024) { socket.destroy(); return; }
          if (!data.includes('\n')) return; done = true;
          try { const command = JSON.parse(data.slice(0, data.indexOf('\n'))); if (command.command !== 'operatorSession') throw new Error('Only operatorSession is supported'); socket.end(JSON.stringify({ url: `${origin}/#token=${mint()}`, expiresInSeconds: 300 }) + '\n'); }
          catch { socket.end(JSON.stringify({ error: 'Invalid owner IPC command' }) + '\n'); }
        });
      });
      await new Promise((resolve, reject) => { ipc.once('error', reject); ipc.listen(filename, () => { ipc.off('error', reject); resolve(); }); });
      await fs.chmod(filename, 0o600);
    }
  } catch (error) { if (ownerFile) await fs.unlink(ownerFile).catch(() => {}); await new Promise(resolve => server.close(resolve)); throw error; }
  return { url: origin, bootstrapToken: firstToken, ownerFile, socketPath: config.socketPath ?? null,
    async close() { if (closed) return; closed = true; ownerSecret = null; if (ownerFile) await fs.unlink(ownerFile).catch(error => { if (error.code !== 'ENOENT') throw error; }); sessions.clear(); bootstraps.clear(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); if (ipc) await new Promise(resolve => ipc.close(resolve)); } };
}
