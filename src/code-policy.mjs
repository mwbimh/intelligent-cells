import fs from 'node:fs/promises';
import path from 'node:path';
import { fail } from './errors.mjs';

export function containsPath(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}
export const pathsOverlap = (left, right) => containsPath(left, right) || containsPath(right, left);

const stamp = stat => Object.fromEntries(['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].map(key => [key, String(stat[key])]));
async function inspectCode(filename, code) {
  if (typeof filename !== 'string' || !filename || filename.includes('\0') || !path.isAbsolute(filename)) fail(code, 'Approved code must name an explicit absolute local file');
  try {
    const stat = await fs.lstat(filename, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || await fs.realpath(filename) !== filename) fail(code, 'Approved code must be canonical, regular and non-hardlinked');
    return stamp(stat);
  } catch (error) {
    if (error.code === code) throw error;
    fail(code, `Approved code file is unavailable: ${error.code ?? 'I/O error'}`);
  }
}

/**
 * Deliberately narrow interpreter grammar: Node plus an explicit script file.
 * Native binaries need a separate explicit owner declaration with fixed argv.
 * Do not guess interpreter flags, module lookup, inline code or shebangs.
 * Program arguments, imports, subprocesses and dynamic loading remain trusted
 * host capabilities, not something this entrypoint validator can sandbox.
 */
export async function compileApprovedCode(file, args, code, { launchMode = 'node-script', argsAllowed = false, stdinAllowed = false } = {}) {
  let codeFiles;
  if (launchMode === 'native') {
    if (argsAllowed || stdinAllowed || /^(?:node(?:js)?(?:[0-9]+)?|python(?:[0-9.]+)?|ruby|perl|php|bash|sh|dash|zsh|ksh|csh|pwsh|powershell|cmd|env|npm|npx|bun|deno|java)(?:\.exe)?$/i.test(path.basename(file))) {
      fail(code, 'Native launch mode requires a reviewed native binary with fixed arguments and no caller stdin; interpreter and package-launcher modes are unsupported');
    }
    await inspectCode(file, code);
    const handle = await fs.open(file, 'r');
    try {
      const header = Buffer.alloc(4); const { bytesRead } = await handle.read(header, 0, 4, 0);
      const signature = header.toString('hex');
      if (bytesRead < 4 || !(signature === '7f454c46' || signature.startsWith('4d5a') || ['feedface', 'cefaedfe', 'feedfacf', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca'].includes(signature))) {
        fail(code, 'Native launch mode requires a native executable image; scripts require the supported Node-file adapter');
      }
    } finally { await handle.close(); }
    codeFiles = [file];
  } else if (launchMode === 'node-script') {
    if (!/^(?:node(?:js)?(?:[0-9]+)?)(?:\.exe)?$/i.test(path.basename(file)) ||
        !Array.isArray(args) || !args.length || typeof args[0] !== 'string' || !path.isAbsolute(args[0])) {
      fail(code, 'Node-file mode requires an approved Node executable and an absolute script first; runtime flags are unsupported. Native binaries require explicit launchMode:native');
    }
    codeFiles = [...new Set([file, args[0]])];
  } else {
    fail(code, 'Unsupported launchMode; choose node-script or an explicitly trusted native binary');
  }
  const codeSnapshots = await Promise.all(codeFiles.map(async filename => ({ filename, ...await inspectCode(filename, code) })));
  return { launchMode, codeFiles, codeSnapshots };
}

export function verifyCodeIsolation(command, writableRoots, code) {
  if (command.codeFiles.some(filename => writableRoots.some(root => containsPath(root, filename)))) {
    fail(code, 'Approved executable and script files must be outside every remotely writable workspace');
  }
}

export async function verifyApprovedCode(command, signal, code) {
  const snapshots = new Map((command.codeSnapshots ?? []).map(item => [item.filename, item]));
  for (const filename of command.codeFiles ?? []) {
    signal.throwIfAborted();
    const current = await inspectCode(filename, code), approved = snapshots.get(filename);
    if (approved && Object.keys(current).some(key => current[key] !== approved[key])) fail(code, 'Approved executable or script changed after policy approval; reload an owner-reviewed policy');
  }
  signal.throwIfAborted();
}
