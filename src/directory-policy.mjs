import fs from 'node:fs/promises';
import path from 'node:path';
import { fail, isObject } from './errors.mjs';

export const PROCESS_TOOLS = new Set(['exec', 'mcpList', 'mcpCall']);

export function validateRelativePath(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 500 || !value ||
      /[\\:\x00-\x1f\x7f]/u.test(value) || path.isAbsolute(value) || path.win32.isAbsolute(value) ||
      value.split('/').some(part => !part || part === '.' || part === '..' || /[. ]$/u.test(part) ||
        /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(part))) {
    fail('PATH_DENIED', 'Only a normal relative path inside the approved workspace is allowed');
  }
}

// This is an application-level file API policy, never a process/OS sandbox.
// Undefined preserves an existing workspace grant. An explicit empty list is
// deny-all, and each matching rule replaces both bits rather than merging them.
export async function compileDirectoryPolicy(raw, root, tools) {
  if (raw.allowUnsandboxedProcesses !== undefined && typeof raw.allowUnsandboxedProcesses !== 'boolean') fail('INVALID_CONFIG', 'allowUnsandboxedProcesses must be a boolean');
  if (raw.directories === undefined) return {};
  if (!root || !Array.isArray(raw.directories) || raw.directories.length > 128) fail('INVALID_CONFIG', 'directories needs a workspace and at most 128 explicit directory rules');
  if ([...tools].some(tool => PROCESS_TOOLS.has(tool)) && raw.allowUnsandboxedProcesses !== true) fail('INVALID_CONFIG', 'Directory rules do not sandbox exec or MCP processes; explicitly acknowledge allowUnsandboxedProcesses before granting them together');
  const seen = new Set(), directories = [];
  for (const rule of raw.directories) {
    if (!isObject(rule) || Object.keys(rule).some(key => !['path', 'read', 'write'].includes(key)) ||
        typeof rule.path !== 'string' || typeof rule.read !== 'boolean' || typeof rule.write !== 'boolean') fail('INVALID_CONFIG', 'Each directory rule requires only path, read and write');
    if (rule.path !== '') {
      try { validateRelativePath(rule.path); } catch { fail('INVALID_CONFIG', 'Directory rules require canonical relative paths; use an empty path for the workspace root'); }
    }
    if (seen.has(rule.path)) fail('INVALID_CONFIG', 'Duplicate directory rule');
    seen.add(rule.path);
    // Future directories can be approved before mkdir. Existing components
    // must all be actual directories, never symlinks or aliases.
    let current = root;
    for (const component of rule.path ? rule.path.split('/') : []) {
      current = path.join(current, component);
      let stat;
      try { stat = await fs.lstat(current); } catch (error) { if (error.code === 'ENOENT') break; throw error; }
      if (!stat.isDirectory() || stat.isSymbolicLink() || await fs.realpath(current) !== current) fail('INVALID_CONFIG', 'Directory rules cannot target files, links or path aliases');
    }
    directories.push({ path: rule.path, read: rule.read, write: rule.write });
  }
  return { directories, allowUnsandboxedProcesses: raw.allowUnsandboxedProcesses === true };
}

export function directoryAccess(policy, name, access, directory = false) {
  if (policy.directories === undefined) return true;
  if (!Array.isArray(policy.directories) || !['read', 'write'].includes(access)) return false;
  const target = directory ? (name ?? '') : (name.includes('/') ? name.slice(0, name.lastIndexOf('/')) : '');
  let selected;
  for (const rule of policy.directories) {
    if ((rule.path === '' || target === rule.path || target.startsWith(`${rule.path}/`)) && (!selected || rule.path.length > selected.path.length)) selected = rule;
  }
  return selected?.[access] === true;
}

export function assertDirectoryAccess(policy, name, access, directory = false) {
  if (!directoryAccess(policy, name, access, directory)) fail('DIRECTORY_DENIED', `Directory ${access} access was not granted by the servant owner`);
}

export function directoryPolicySummary(policy) {
  const scoped = policy.directories !== undefined;
  const processTools = [...(policy.tools ?? [])].filter(tool => PROCESS_TOOLS.has(tool));
  return {
    mode: scoped ? 'scoped' : 'workspace', defaultAccess: scoped ? 'deny' : 'tool-allowlist',
    ...(scoped ? { directories: structuredClone(policy.directories), precedence: 'most-specific-directory', rootPath: '' } : {}),
    fileToolsRequireToolGrant: true, editRequiresReadAndWrite: true,
    deniedDirectoryTraversal: 'prune', processTools, processSandboxed: false,
    processAccess: processTools.length ? 'outside-directory-policy' : 'not-granted',
    unsandboxedProcessesAcknowledged: scoped && policy.allowUnsandboxedProcesses === true,
  };
}
