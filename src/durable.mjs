// Fail-closed durable state. A task is committed before any network send/tool call.
// Atomic rename is NOT an exactly-once transaction with an external side effect.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fail } from './errors.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const BLOOM_BYTES = 262144; // 2^21 bits; false positives deny, never cause replay.
const MAX_RETIRED = 200000;
export function privateDirectory(directory) {
  const resolved = path.resolve(directory);
  fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink() || fs.realpathSync(resolved) !== resolved ||
      (process.getuid && stat.uid !== process.getuid()) || (process.platform !== 'win32' && (stat.mode & 0o077))) {
    fail('UNSAFE_STATE_DIRECTORY', 'State directory must be an owner-only real directory');
  }
  return resolved;
}
function syncDirectory(directory) {
  const fd = fs.openSync(directory, 'r');
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
export function atomicWriteJson(filename, value) {
  const encoded = JSON.stringify(value);
  const dir = path.dirname(filename), temporary = path.join(dir, `.${path.basename(filename)}.${randomUUID()}.tmp`);
  let fd;
  try {
    try { const old = fs.lstatSync(filename); if (!old.isFile() || old.isSymbolicLink() || old.nlink !== 1) fail('UNSAFE_STATE_FILE', 'Refusing linked or non-regular state file'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    fd = fs.openSync(temporary, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    fs.writeFileSync(fd, encoded, 'utf8'); fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    fs.renameSync(temporary, filename); syncDirectory(dir);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}
export function writeChecked(filename, payload) {
  const data = JSON.stringify(payload);
  atomicWriteJson(filename, { format: 1, checksum: sha(data), data });
}
export function readChecked(filename, maxBytes = 2 * 1024 * 1024) {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maxBytes ||
      (process.getuid && stat.uid !== process.getuid()) || (process.platform !== 'win32' && (stat.mode & 0o077))) fail('JOURNAL_CORRUPT', 'Unsafe or oversized journal file; manual recovery required');
  try {
    const envelope = JSON.parse(fs.readFileSync(filename, 'utf8'));
    if (envelope.format !== 1 || typeof envelope.data !== 'string' || envelope.checksum !== sha(envelope.data)) throw new Error();
    return JSON.parse(envelope.data);
  } catch { fail('JOURNAL_CORRUPT', 'Journal checksum or JSON is invalid; refusing automatic rollback/re-execution'); }
}
export function acquireStateLock(directory) {
  const dir = privateDirectory(directory), lock = path.join(dir, 'owner.lock');
  const owner = { pid: process.pid, nonce: randomUUID() };
  try {
    const fd = fs.openSync(lock, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0), 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(owner)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    syncDirectory(dir);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    // Serialize stale-owner recovery. Without this separate O_EXCL guard two
    // restart processes could both inspect an old PID then unlink a new lock.
    const recovery = path.join(dir, 'recovery.lock');
    let recoveryFd;
    try { recoveryFd = fs.openSync(recovery, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600); }
    catch (cause) { if(cause.code==='EEXIST') fail('STATE_LOCKED','Another recovery is active, or a crashed recovery needs owner inspection');throw cause; }
    try {
      const stat = fs.lstatSync(lock);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 1024) fail('STATE_LOCKED', 'Unsafe state lock; inspect manually');
      let previous;
      try { previous = JSON.parse(fs.readFileSync(lock, 'utf8')); } catch { fail('STATE_LOCKED', 'Corrupt state lock; inspect manually'); }
      if (!Number.isSafeInteger(previous.pid) || previous.pid < 1) fail('STATE_LOCKED', 'Invalid lock owner; inspect manually');
      try { process.kill(previous.pid, 0); fail('STATE_LOCKED', 'Another process owns this state directory'); }
      catch (cause) { if (cause.code !== 'ESRCH') throw cause; }
      fs.unlinkSync(lock);
      return acquireStateLock(dir);
    } finally { fs.closeSync(recoveryFd);fs.unlinkSync(recovery);syncDirectory(dir); }

  }
  return () => {
    try { const current = JSON.parse(fs.readFileSync(lock, 'utf8')); if (current.nonce === owner.nonce) { fs.unlinkSync(lock); syncDirectory(dir); } }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  };
}

export class DurableStore {
  constructor({ directory, maxRecords = 4096, maxBytes = 64 * 1024 * 1024 }) {
    this.directory = directory; this.maxRecords = maxRecords; this.maxBytes = maxBytes;
    this.records = new Map(); this.sizes = new Map(); this.bytes = 0;
    this.retiredCount = 0; this.bloom = Buffer.alloc(BLOOM_BYTES); this.failed = false;
  }
  open() {
    this.directory = privateDirectory(this.directory); this.metaPath = path.join(this.directory, 'meta.json');
    const entries = fs.readdirSync(this.directory);
    if (entries.includes('meta.json')) {
      const metadata = readChecked(this.metaPath);
      if (metadata.kind !== 'task-store' || metadata.bloomBytes !== BLOOM_BYTES || !Number.isSafeInteger(metadata.retiredCount) || metadata.retiredCount < 0 || metadata.retiredCount > MAX_RETIRED || typeof metadata.bloom !== 'string') fail('JOURNAL_CORRUPT', 'Invalid retention metadata');
      this.bloom = Buffer.from(metadata.bloom, 'base64'); this.retiredCount = metadata.retiredCount;
      if (this.bloom.length !== BLOOM_BYTES) fail('JOURNAL_CORRUPT', 'Invalid tombstone bitmap');
    } else {
      if (entries.some(name => name.endsWith('.json'))) fail('JOURNAL_CORRUPT', 'Missing retention metadata; refusing to forget retired operations');
      this.saveMeta();
    }
    for (const name of entries) {
      if (name === 'meta.json') continue;
      if (/^\.(?:meta|[a-f0-9]{64})\.json\.[a-f0-9-]{36}\.tmp$/.test(name)) {
        const temporary=path.join(this.directory,name), stat=fs.lstatSync(temporary);
        if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||(process.getuid&&stat.uid!==process.getuid()))fail('JOURNAL_CORRUPT','Unsafe interrupted staging file');
        fs.unlinkSync(temporary);syncDirectory(this.directory);continue; // discard, never promote uncommitted state
      }
      if (!/^[a-f0-9]{64}\.json$/.test(name)) fail('JOURNAL_CORRUPT', 'Unexpected file in journal directory');
      const wrapper = readChecked(path.join(this.directory, name));
      if (typeof wrapper.key !== 'string' || sha(wrapper.key) + '.json' !== name || !wrapper.value || typeof wrapper.value !== 'object') fail('JOURNAL_CORRUPT', 'Journal key or record is invalid');
      this.records.set(wrapper.key, wrapper.value); const size = Buffer.byteLength(JSON.stringify(wrapper.value)); this.sizes.set(wrapper.key, size); this.bytes += size;
    }
    if (this.records.size > this.maxRecords || this.bytes > this.maxBytes) fail('JOURNAL_CAPACITY', 'Configured journal limit is below existing retained state');
    return this;
  }
  indexes(key) {
    const digest = createHash('sha256').update(key).digest();
    return Array.from({ length: 7 }, (_, index) => digest.readUInt32BE(index * 4) % (BLOOM_BYTES * 8));
  }
  retired(key) { return this.indexes(key).every(bit => (this.bloom[bit >>> 3] & (1 << (bit & 7))) !== 0); }
  addTombstone(key) { for (const bit of this.indexes(key)) this.bloom[bit >>> 3] |= 1 << (bit & 7); }
  saveMeta() { writeChecked(this.metaPath, { kind: 'task-store', bloomBytes: BLOOM_BYTES, retiredCount: this.retiredCount, bloom: this.bloom.toString('base64') }); }
  get(key) { return this.records.get(key); }
  values() { return this.records.values(); }
  assertLimits({ maxRecords, maxBytes }) {
    if (this.failed) fail('JOURNAL_UNAVAILABLE', 'Storage has failed; restart after manual inspection');
    if (this.records.size > maxRecords || this.bytes > maxBytes) fail('JOURNAL_CAPACITY', 'Proposed journal limits are below retained state; retain the current limits or reconcile/archive state first');
  }
  configure(limits) { this.assertLimits(limits); this.maxRecords = limits.maxRecords; this.maxBytes = limits.maxBytes; }
  compact(neededBytes = 0, { excludeKey = null, additionalRecords = 1 } = {}) {
    const candidates = [...this.records.entries()].filter(([key,record]) => key !== excludeKey && !record.outcomeUnknown && !record.response?.outcomeUnknown && !['unknown','running','dispatching','pending'].includes(record.state)).sort((a,b) => (a[1].updatedAt ?? 0) - (b[1].updatedAt ?? 0));
    const remove = []; let freed = 0;
    const target = Math.max(1, Math.ceil(this.maxRecords / 4));
    for (const [key] of candidates) {
      remove.push(key); freed += this.sizes.get(key) ?? 0;
      if (remove.length >= target && this.records.size - remove.length + additionalRecords <= this.maxRecords && this.bytes - freed + neededBytes <= this.maxBytes) break;
    }
    if (!remove.length || this.records.size - remove.length + additionalRecords > this.maxRecords || this.bytes - freed + neededBytes > this.maxBytes || this.retiredCount + remove.length > MAX_RETIRED) fail('TASK_STORE_FULL', 'Unresolved records or bounded tombstone capacity prevent safe retention; operator reconciliation is required');
    for (const key of remove) this.addTombstone(key);
    this.retiredCount += remove.length;
    this.saveMeta(); // Commit tombstones FIRST. A crash may retain extra result files, never forget old IDs.
    for (const key of remove) {
      fs.unlinkSync(path.join(this.directory, sha(key) + '.json'));
      this.bytes -= this.sizes.get(key) ?? 0; this.records.delete(key); this.sizes.delete(key);
    }
    syncDirectory(this.directory);
  }
  put(key, value) {
    if (this.failed) fail('JOURNAL_UNAVAILABLE', 'Storage has failed; restart after manual inspection');
    const existing = this.records.has(key);
    if (!existing && this.retired(key)) fail('TASK_HISTORY_EXPIRED', 'This operation ID is retired (or conservatively matches a tombstone); never re-execute it');
    const size = Buffer.byteLength(JSON.stringify(value));
    if (size > 1024 * 1024 || size > this.maxBytes) fail('RESULT_TOO_LARGE', 'Record exceeds durable storage limit');
    try {
      const growth = size - (this.sizes.get(key) ?? 0);
      if ((!existing && this.records.size >= this.maxRecords) || this.bytes + growth > this.maxBytes) {
        this.compact(growth, { excludeKey: key, additionalRecords: existing ? 0 : 1 });
      }
      writeChecked(path.join(this.directory, sha(key) + '.json'), { key, value });
      this.bytes += size - (this.sizes.get(key) ?? 0); this.sizes.set(key, size); this.records.set(key, structuredClone(value));
    } catch (error) { if (!['TASK_STORE_FULL','TASK_HISTORY_EXPIRED','RESULT_TOO_LARGE'].includes(error.code)) this.failed = true; throw error; }
  }
  info() { return { records: this.records.size, bytes: this.bytes, maxRecords: this.maxRecords, maxBytes: this.maxBytes, retiredCount: this.retiredCount, maxRetired: MAX_RETIRED, tombstones: 'bounded-bloom-fail-closed' }; }
}
