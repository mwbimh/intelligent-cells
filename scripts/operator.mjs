// Local owner helper. It only talks to an owner-only Unix socket created by the
// running node; no key or persistent access token is generated or saved.
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
export async function ownerSession(socketPath) {
  const filename = path.resolve(socketPath), stat = await fs.lstat(filename), parent = await fs.lstat(path.dirname(filename));
  if (process.platform === 'win32') throw new Error('Unix owner IPC is not supported on Windows; use an interactive local session');
  if (!stat.isSocket() || stat.isSymbolicLink() || (stat.mode & 0o077) || stat.uid !== process.getuid() || await fs.realpath(path.dirname(filename)) !== path.dirname(filename) || !parent.isDirectory() || (parent.mode & 0o077) || parent.uid !== process.getuid()) throw new Error('Refusing an IPC path without owner-only permissions');
  return new Promise((resolve, reject) => {
    const socket = net.connect(filename), timer = setTimeout(() => { socket.destroy(); reject(new Error('Owner IPC timeout')); }, 5000);
    let buffer = '';
    socket.on('error', error => { clearTimeout(timer); reject(error); });
    socket.on('connect', () => socket.write(JSON.stringify({ command: 'operatorSession' }) + '\n'));
    socket.on('data', chunk => { buffer += chunk; if (buffer.length > 4096) socket.destroy(new Error('Invalid owner IPC response')); });
    socket.on('end', () => { clearTimeout(timer); try { const response = JSON.parse(buffer); if (response.error || !response.url) throw new Error(response.error ?? 'Missing owner URL'); const url = new URL(response.url); if (url.hostname !== '127.0.0.1' || url.protocol !== 'http:' || !url.hash.startsWith('#token=')) throw new Error('Unexpected operator URL'); resolve(response); } catch (error) { reject(error); } });
  });
}
export async function fileOwnerSession(filename) {
  const full = path.resolve(filename), stat = await fs.lstat(full), parent = await fs.lstat(path.dirname(full));
  if (process.platform === 'win32' || !stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) || stat.uid !== process.getuid() || !parent.isDirectory() || (parent.mode & 0o077) || parent.uid !== process.getuid() || await fs.realpath(path.dirname(full)) !== path.dirname(full) || stat.size > 4096) throw new Error('Owner file must be a private regular file inside an owner-only directory');
  const value = JSON.parse(await fs.readFile(full, 'utf8')), parsed = new URL(value.url);
  if (parsed.hostname !== '127.0.0.1' || parsed.protocol !== 'http:' || parsed.pathname !== '/' || parsed.hash || parsed.search) throw new Error('Unexpected owner endpoint');
  const response = await fetch(`${parsed.origin}/api/ownerSession`, { method: 'POST', headers: { Origin: parsed.origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ secret: value.secret }) });
  const data = await response.json(); if (!response.ok || !data.ok) throw new Error(data.error?.message ?? 'Owner capability expired'); return data;
}
export async function connectOperator(accessPath, { sessionFile = false } = {}) {
  const { url } = await (sessionFile ? fileOwnerSession(accessPath) : ownerSession(accessPath)), parsed = new URL(url), token = new URLSearchParams(parsed.hash.slice(1)).get('token'), origin = parsed.origin;
  const response = await fetch(`${origin}/api/session`, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  const data = await response.json(); if (!response.ok || !data.ok) throw new Error(data.error?.message ?? 'Owner session rejected');
  const cookie = response.headers.get('set-cookie')?.split(';')[0];
  if (!cookie || !data.csrf) throw new Error('Missing session credentials');
  return { origin, async request(route, command) {
    if (!['/api/state', '/api/logs', '/api/command', '/api/logout'].includes(route)) throw new Error('Unsupported operator route');
    const response = await fetch(`${origin}${route}`, { headers: { Origin: origin, Cookie: cookie, ...(command ? { 'Content-Type': 'application/json', 'X-Operator-CSRF': data.csrf } : {}) }, ...(command ? { method: 'POST', body: JSON.stringify(command) } : {}) });
    const result = await response.json(); if (!response.ok || !result.ok) throw new Error(`${result.error?.code}: ${result.error?.message}`); return result;
  } };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [action, flag, socketPath, argument] = process.argv.slice(2);
  try {
    if (!['--socket', '--session-file'].includes(flag) || !socketPath || !['open', 'status', 'logs', 'command'].includes(action)) throw new Error('Usage: node scripts/operator.mjs open|status|logs|command --socket|--session-file <owner-access-path> [JSON-command]');
    if (action === 'open') console.log((await (flag === '--session-file' ? fileOwnerSession(socketPath) : ownerSession(socketPath))).url);
    else { const client = await connectOperator(socketPath, { sessionFile: flag === '--session-file' }); try { console.log(JSON.stringify(await client.request(action === 'status' ? '/api/state' : action === 'logs' ? '/api/logs' : '/api/command', action === 'command' ? JSON.parse(argument) : undefined), null, 2)); } finally { await client.request('/api/logout', {}).catch(() => {}); } }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
