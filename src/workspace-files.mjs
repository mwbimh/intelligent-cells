import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { fail } from './errors.mjs';
import { validateRelativePath, directoryAccess, assertDirectoryAccess } from './directory-policy.mjs';
export { validateRelativePath } from './directory-policy.mjs';
const mutations = new Map();

export function requireRoot(policy) {
  if (typeof policy.root !== 'string' || !path.isAbsolute(policy.root)) {
    fail('PATH_DENIED', 'This tool requires a locally approved workspace');
  }
  return policy.root;
}

function assertInside(root, target) {
  const relative = path.relative(root, target);
  if (!relative || relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) fail('PATH_DENIED', 'Path is outside the approved workspace');
}

function sameFile(a, b) { return a.dev === b.dev && a.ino === b.ino; }

function assertRegular(stat) {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    fail('PATH_DENIED', 'Only regular, non-linked files are allowed');
  }
}

export async function inspectRoot(root, signal) {
  signal.throwIfAborted();
  const stat = await fs.lstat(root);
  if (!stat.isDirectory() || stat.isSymbolicLink() || await fs.realpath(root) !== root) fail('PATH_DENIED', 'Workspace changed or is an alias');
  signal.throwIfAborted();
  return stat;
}

async function inspectPath(root, name, signal, allowMissing = false) {
  validateRelativePath(name);
  const directories = [{ name: root, stat: await inspectRoot(root, signal) }];
  let target = root;
  const components = name.split('/');
  for (const [index, component] of components.entries()) {
    signal.throwIfAborted();
    target = path.join(target, component);
    assertInside(root, target);
    let stat;
    try { stat = await fs.lstat(target); }
    catch (error) {
      if (allowMissing && index === components.length - 1 && error.code === 'ENOENT') {
        return { target, parent: path.dirname(target), stat: null, directories };
      }
      throw error;
    }
    if (stat.isSymbolicLink() || await fs.realpath(target) !== target) fail('PATH_DENIED', 'Symbolic links and path aliases are not allowed');
    if (index === components.length - 1) {
      assertRegular(stat);
      return { target, parent: path.dirname(target), stat, directories };
    }
    if (!stat.isDirectory()) fail('PATH_DENIED', 'Parent must be a directory');
    directories.push({ name: target, stat });
  }
}

async function verifySnapshot(root, name, original, signal) {
  const current = await inspectPath(root, name, signal, original.stat === null);
  if (current.directories.length !== original.directories.length ||
      current.directories.some((directory, index) => !sameFile(directory.stat, original.directories[index].stat)) ||
      Boolean(current.stat) !== Boolean(original.stat) ||
      (current.stat && (!sameFile(current.stat, original.stat) || current.stat.size !== original.stat.size ||
        current.stat.mtimeMs !== original.stat.mtimeMs || current.stat.ctimeMs !== original.stat.ctimeMs))) {
    fail('PATH_DENIED', 'Workspace or file changed during the operation');
  }
  return current;
}

export async function safeRead(root, name, maxBytes, signal, snapshot, strictUtf8 = false) {
  const inspected = snapshot ?? await inspectPath(root, name, signal);
  const handle = await fs.open(inspected.target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await handle.stat();
    assertRegular(stat);
    if (!sameFile(stat, inspected.stat)) fail('PATH_DENIED', 'File changed while opening');
    if (stat.size > maxBytes) fail('FILE_TOO_LARGE', 'File exceeds local byte limit');
    const buffer = Buffer.alloc(maxBytes + 1);
    let bytes = 0;
    while (bytes < buffer.length) {
      signal.throwIfAborted();
      const { bytesRead } = await handle.read(buffer, bytes, buffer.length - bytes, bytes);
      if (!bytesRead) break;
      bytes += bytesRead;
    }
    signal.throwIfAborted();
    if (bytes > maxBytes) fail('FILE_TOO_LARGE', 'File exceeds local byte limit');
    await verifySnapshot(root, name, inspected, signal);
    let text;
    try {
      // Editing must never silently rewrite invalid byte sequences elsewhere in
      // a file. ignoreBOM keeps an existing UTF-8 BOM in the decoded text.
      text = strictUtf8
        ? new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, bytes))
        : buffer.subarray(0, bytes).toString('utf8');
    } catch { fail('INVALID_ENCODING', 'editFile requires valid UTF-8 text'); }
    return { text, bytes };
  } finally { await handle.close(); }
}

// Serializes this process's mutations. Other writers must not mutate the workspace
// concurrently: Node's path-based APIs are not an OS sandbox or an openat boundary.
async function withMutationLock(key, signal, operation) {
  const previous = mutations.get(key) ?? Promise.resolve();
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const tail = previous.then(() => gate);
  mutations.set(key, tail);
  let abortListener;
  try {
    await Promise.race([previous, new Promise((_, reject) => {
      abortListener = () => reject(signal.reason);
      signal.addEventListener('abort', abortListener, { once: true });
      if (signal.aborted) abortListener();
    })]);
    signal.throwIfAborted();
    return await operation();
  } finally {
    signal.removeEventListener('abort', abortListener);
    release();
    tail.then(() => { if (mutations.get(key) === tail) mutations.delete(key); });
  }
}

async function atomicWrite(root, name, text, snapshot, signal) {
  const temporary = path.join(snapshot.parent, `.intelligent-cells-${randomUUID()}.tmp`);
  let handle;
  let created = false;
  try {
    signal.throwIfAborted();
    await verifySnapshot(root, name, snapshot, signal);
    handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    created = true;
    await handle.writeFile(text, { encoding: 'utf8', signal });
    await handle.sync();
    const stagedStat = await handle.stat();
    assertRegular(stagedStat);
    await handle.close();
    handle = null;
    await verifySnapshot(root, name, snapshot, signal);
    const stagedNow = await fs.lstat(temporary);
    assertRegular(stagedNow);
    if (!sameFile(stagedStat, stagedNow)) fail('PATH_DENIED', 'Staged file changed');
    signal.throwIfAborted();
    // The rename commits the effect atomically. A later cancellation cannot undo it.
    await fs.rename(temporary, snapshot.target);
    created = false;
    return { path: name, bytes: Buffer.byteLength(text) };
  } finally {
    if (handle) await handle.close();
    if (created) await fs.unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
}

export async function mutateFile(task, policy, signal) {
  const root = requireRoot(policy), name = task.args.path;
  return withMutationLock(path.join(root, name), signal, async () => {
    const snapshot = await inspectPath(root, name, signal, task.tool === 'writeFile');
    let text = task.args.text;
    if (task.tool === 'writeFile') {
      if (snapshot.stat && task.args.overwrite !== true) fail('FILE_EXISTS', 'Existing file requires overwrite: true');
    } else {
      const source = await safeRead(root, name, policy.maxReadBytes, signal, snapshot, true);
      const first = source.text.indexOf(task.args.oldText);
      if (first === -1 || source.text.indexOf(task.args.oldText, first + 1) !== -1) {
        fail('EDIT_MATCH_COUNT', 'oldText must occur exactly once');
      }
      text = source.text.slice(0, first) + task.args.newText + source.text.slice(first + task.args.oldText.length);
      if (Buffer.byteLength(text) > policy.maxWriteBytes) fail('FILE_TOO_LARGE', 'Edited file exceeds local byte limit');
    }
    return atomicWrite(root, name, text, snapshot, signal);
  });
}


async function inspectDirectory(root, name, signal) {
  const entries = [{ name: root, stat: await inspectRoot(root, signal) }];
  if (name !== undefined && name !== '') {
    validateRelativePath(name);
    let current = root;
    for (const part of name.split('/')) {
      signal.throwIfAborted(); current = path.join(current, part); assertInside(root, current);
      const stat = await fs.lstat(current);
      if (!stat.isDirectory() || stat.isSymbolicLink() || await fs.realpath(current) !== current) fail('PATH_DENIED', 'Directory links and aliases are not allowed');
      entries.push({ name: current, stat });
    }
  }
  return entries;
}
async function verifyDirectories(snapshot, signal) {
  for (const entry of snapshot) {
    signal.throwIfAborted(); const stat = await fs.lstat(entry.name);
    if (!stat.isDirectory() || stat.isSymbolicLink() || !sameFile(stat, entry.stat) || await fs.realpath(entry.name) !== entry.name) fail('PATH_DENIED', 'Directory changed during operation');
  }
}

export async function readRange(root, args, maxBytes, signal, binary = false) {
  const inspected = await inspectPath(root, args.path, signal);
  const handle = await fs.open(inspected.target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await handle.stat(); assertRegular(stat);
    if (!sameFile(stat, inspected.stat)) fail('PATH_DENIED', 'File changed while opening');
    const offset = args.offset ?? 0, length = args.length ?? maxBytes;
    const buffer = Buffer.alloc(Math.min(length, Math.max(0, stat.size - offset)));
    let bytes = 0;
    while (bytes < buffer.length) {
      signal.throwIfAborted(); const next = await handle.read(buffer, bytes, buffer.length - bytes, offset + bytes);
      if (!next.bytesRead) break; bytes += next.bytesRead;
    }
    await verifySnapshot(root, args.path, inspected, signal);
    const data = buffer.subarray(0, bytes);
    return { path: args.path, ...(binary ? { base64: data.toString('base64'), sha256: createHash('sha256').update(data).digest('hex') } : { text: data.toString('utf8') }),
      offset, bytes, nextOffset: offset + bytes, totalBytes: stat.size, eof: offset + bytes >= stat.size };
  } finally { await handle.close(); }
}

export async function listDirectory(root, args, policy, signal) {
  assertDirectoryAccess(policy, args.path ?? '', 'read', true);
  const snapshot = await inspectDirectory(root, args.path, signal);
  const target = snapshot.at(-1).name;
  const entries = [], max = policy.maxDirectoryEntries ?? 1000;
  let scanned = 0, skippedEntries = 0;
  const directory = await fs.opendir(target);
  // A directory is bounded even when the caller only asks for a small first page.
  for await (const entry of directory) {
    signal.throwIfAborted();
    if (++scanned > max) fail('DIRECTORY_TOO_LARGE', 'Directory exceeds local entry limit');
    try { validateRelativePath(entry.name); } catch { skippedEntries++; continue; }
    const relative = args.path ? `${args.path}/${entry.name}` : entry.name;
    // Check visibility before stat; denied entries never expose names or sizes.
    if (!directoryAccess(policy, relative, 'read', true) && !directoryAccess(policy, relative, 'read')) continue;
    const stat = await fs.lstat(path.join(target, entry.name));
    if (!directoryAccess(policy, relative, 'read', stat.isDirectory())) continue;
    entries.push({ name: entry.name, type: stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1) ? 'blocked-link' : stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : 'blocked-special', ...(stat.isFile() && stat.nlink === 1 ? { bytes: stat.size } : {}) });
  }
  await verifyDirectories(snapshot, signal);
  entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  const offset = args.offset ?? 0, limit = args.limit ?? 100, page = entries.slice(offset, offset + limit);
  return { path: args.path ?? '', entries: page, skippedEntries, offset, nextOffset: offset + page.length, total: entries.length, eof: offset + page.length >= entries.length };
}

export async function makeDirectory(root, args, signal) {
  const parent = args.path.includes('/') ? args.path.slice(0, args.path.lastIndexOf('/')) : '';
  return withMutationLock(path.join(root, args.path), signal, async () => {
    const snapshot = await inspectDirectory(root, parent, signal);
    await verifyDirectories(snapshot, signal); signal.throwIfAborted();
    await fs.mkdir(path.join(root, args.path), { mode: 0o700 });
    return { path: args.path, created: true };
  });
}

export async function searchFiles(root, args, policy, signal) {
  assertDirectoryAccess(policy, args.path ?? '', 'read', true);
  const maxFiles = policy.maxSearchFiles ?? 1000, maxBytes = policy.maxSearchBytes ?? 1048576;
  const maxResults = args.maxResults ?? 50, matches = [];
  let visited = 0, scannedBytes = 0, skippedFiles = 0, truncated = false, reason = null;
  const queue = [args.path ?? ''];
  while (queue.length && !truncated) {
    const directoryName = queue.shift();
    const snapshot = await inspectDirectory(root, directoryName, signal);
    const directory = await fs.opendir(snapshot.at(-1).name);
    for await (const entry of directory) {
      signal.throwIfAborted();
      if (++visited > maxFiles) { truncated = true; reason = 'maxSearchFiles'; break; }
      const name = directoryName ? `${directoryName}/${entry.name}` : entry.name;
      try { validateRelativePath(name); } catch { skippedFiles++; continue; }
      if (!directoryAccess(policy, name, 'read', true) && !directoryAccess(policy, name, 'read')) continue;
      const stat = await fs.lstat(path.join(root, name));
      if (!directoryAccess(policy, name, 'read', stat.isDirectory())) continue;
      if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1))) { skippedFiles++; continue; }
      if (stat.isDirectory()) { queue.push(name); continue; }
      if (stat.size > policy.maxReadBytes) { skippedFiles++; continue; }
      if (scannedBytes + stat.size > maxBytes) { truncated = true; reason = 'maxSearchBytes'; break; }
      const result = await safeRead(root, name, policy.maxReadBytes, signal);
      scannedBytes += result.bytes;
      // Literal text search only: no user regular expression / catastrophic backtracking.
      let start = 0, line = 1;
      for (const content of result.text.split('\n')) {
        const column = content.indexOf(args.query);
        if (column >= 0) {
          matches.push({ path: name, line, column: column + 1, preview: content.slice(Math.max(0, column - 80), column + args.query.length + 120).slice(0, 160) });
          if (matches.length >= maxResults) { truncated = true; reason = 'maxResults'; break; }
        }
        start += content.length + 1; line++;
      }
      if (truncated) break;
    }
    await verifyDirectories(snapshot, signal);
  }
  return { matches, scannedEntries: Math.min(visited, maxFiles), scannedBytes, skippedFiles, truncated, reason };
}

export async function writeChunk(root, args, policy, signal) {
  const data = Buffer.from(args.base64, 'base64'), offset = args.offset ?? 0;
  return withMutationLock(path.join(root, args.path), signal, async () => {
    const snapshot = await inspectPath(root, args.path, signal, true);
    if (offset === 0) {
      if (snapshot.stat && args.overwrite !== true) fail('FILE_EXISTS', 'Existing file requires overwrite: true');
      const result = await atomicWrite(root, args.path, data, snapshot, signal);
      return { ...result, offset: 0, nextOffset: data.length };
    }
    if (!snapshot.stat || snapshot.stat.size !== offset) fail('OFFSET_MISMATCH', 'Append offset must equal current file size');
    if (offset + data.length > (policy.maxTransferBytes ?? 67108864)) fail('FILE_TOO_LARGE', 'Transfer exceeds local total size limit');
    const temporary = path.join(snapshot.parent, `.intelligent-cells-${randomUUID()}.tmp`);
    let source, staged, created = false;
    try {
      source = await fs.open(snapshot.target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const stat = await source.stat(); assertRegular(stat);
      if (!sameFile(stat, snapshot.stat)) fail('PATH_DENIED', 'File changed while opening');
      staged = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600); created = true;
      const buffer = Buffer.alloc(65536);
      let position = 0;
      while (position < offset) {
        signal.throwIfAborted(); const { bytesRead } = await source.read(buffer, 0, Math.min(buffer.length, offset - position), position);
        if (!bytesRead) fail('PATH_DENIED', 'Source shortened during transfer');
        await staged.writeFile(buffer.subarray(0, bytesRead), { signal }); position += bytesRead;
      }
      await staged.writeFile(data, { signal }); await staged.sync();
      const stagedStat = await staged.stat(); assertRegular(stagedStat);
      await source.close(); source = null; await staged.close(); staged = null;
      await verifySnapshot(root, args.path, snapshot, signal);
      const stagedNow = await fs.lstat(temporary); assertRegular(stagedNow);
      if (!sameFile(stagedStat, stagedNow)) fail('PATH_DENIED', 'Staged file changed');
      signal.throwIfAborted(); await fs.rename(temporary, snapshot.target); created = false;
      return { path: args.path, bytes: data.length, offset, nextOffset: offset + data.length };
    } finally {
      if (source) await source.close(); if (staged) await staged.close();
      if (created) await fs.unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
    }
  });
}
