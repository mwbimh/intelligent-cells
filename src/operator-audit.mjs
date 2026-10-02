import fs from 'node:fs';
import path from 'node:path';

// Disk audit is metadata-only by construction. Never serialize arbitrary task
// arguments, results, prompts, contents, errors, credentials or environment.
const KEYS = new Set(['timestamp', 'nodeId', 'pid', 'event', 'masterId', 'peerId', 'taskId', 'requestId', 'command', 'ok', 'status', 'state', 'code', 'tool', 'epoch', 'active', 'port', 'transport', 'delayMs', 'timeoutMs', 'count', 'resolution']);
export function redactAudit(value) {
  const out = {};
  for (const [key, item] of Object.entries(value ?? {})) {
    if (KEYS.has(key) && (typeof item === 'boolean' || typeof item === 'number' || item === null)) out[key] = item;
    else if (KEYS.has(key) && typeof item === 'string') out[key] = item.replace(/[\r\n\x00-\x1f]/g, '').slice(0, 160);
  }
  if (typeof value?.error?.code === 'string') out.code = value.error.code.slice(0, 80);
  out.payloadRedacted = true;
  return out;
}
export class AuditLog {
  constructor({ filename, maxBytes = 1048576, retention = 4 } = {}) {
    if (typeof filename !== 'string' || !path.isAbsolute(filename)) throw new Error('Audit filename must be absolute');
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1024 || maxBytes > 67108864 || !Number.isSafeInteger(retention) || retention < 1 || retention > 32) throw new Error('Invalid audit rotation bounds');
    this.filename = filename; this.maxBytes = maxBytes; this.retention = retention;
    const directory = path.dirname(filename);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const directoryStat = fs.lstatSync(directory);
    if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink() || fs.realpathSync(directory) !== path.resolve(directory)) throw new Error('Audit directory must be a real directory');
    if (process.platform !== 'win32' && ((directoryStat.mode & 0o077) || directoryStat.uid !== process.getuid())) throw new Error('Audit directory must be owner-only (0700)');
    for (let i = 0; i <= retention; i++) this.checkFile(i ? `${filename}.${i}` : filename);
  }
  checkFile(filename) {
    try {
      const s = fs.lstatSync(filename);
      if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || (process.platform !== 'win32' && (s.uid !== process.getuid() || (s.mode & 0o077)))) throw new Error('Audit file must be a private regular file');
    } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
  append(fields) {
    const line = JSON.stringify(redactAudit(fields)) + '\n';
    this.checkFile(this.filename);
    const size = (() => { try { return fs.statSync(this.filename).size; } catch (e) { if (e.code === 'ENOENT') return 0; throw e; } })();
    if (size && size + Buffer.byteLength(line) > this.maxBytes) {
      for (let i = this.retention; i >= 1; i--) {
        const target = `${this.filename}.${i}`, source = i === 1 ? this.filename : `${this.filename}.${i - 1}`;
        this.checkFile(source); this.checkFile(target);
        if (i === this.retention) { try { fs.unlinkSync(target); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
        try { fs.renameSync(source, target); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      }
    }
    const fd = fs.openSync(this.filename, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    try { fs.writeSync(fd, line); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
  query({ limit = 100, event, taskId, peerId } = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new Error('Audit limit must be 1..500');
    const records = [];
    for (let i = 0; i <= this.retention && records.length < limit; i++) {
      const filename = i ? `${this.filename}.${i}` : this.filename;
      this.checkFile(filename);
      let lines;
      try { const stat = fs.statSync(filename); if (stat.size > this.maxBytes + 4096) throw new Error('Audit file exceeds configured bounds'); lines = fs.readFileSync(filename, 'utf8').trim().split('\n'); }
      catch (e) { if (e.code === 'ENOENT') continue; throw e; }
      for (const line of lines.reverse()) {
        if (!line) continue;
        let entry; try { entry = JSON.parse(line); } catch { continue; }
        if ((event && entry.event !== event) || (taskId && entry.taskId !== taskId) || (peerId && entry.peerId !== peerId && entry.masterId !== peerId)) continue;
        records.push(redactAudit(entry)); if (records.length === limit) break;
      }
    }
    return { records, limit, newestFirst: true, retentionFiles: this.retention + 1, payloadRedacted: true };
  }
}
