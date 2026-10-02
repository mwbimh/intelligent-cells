import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fail, integer, isObject } from './errors.mjs';
import { assertDirectoryAccess, directoryAccess } from './directory-policy.mjs';

const idOK = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(value);
const kinds = ['instruction', 'skill', 'prompt'];
const objectSchema = properties => ({ type: 'object', properties, additionalProperties: false });
export const resourceToolSchemas = Object.freeze([
  { name: 'resourceList', description: 'List only resources explicitly approved in the current servant grant', inputSchema: objectSchema({}) },
  { name: 'resourceRead', description: 'Read bounded approved project instructions, skills or prompt text by alias', inputSchema: { ...objectSchema({ resource: { type: 'string', minLength: 1, maxLength: 64 } }), required: ['resource'] } },
]);
export const isResourceSideEffecting = () => false;

function relativeName(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 500 || !value || /[\\:\x00-\x1f\x7f]/u.test(value) ||
      path.isAbsolute(value) || value.split('/').some(part => !part || part === '.' || part === '..' || /[. ]$/u.test(part))) {
    fail('INVALID_CONFIG', 'Resource path must be a normal relative workspace path');
  }
  return value;
}

export async function compileResourcePolicy(raw, _base, root) {
  if (!isObject(raw.resources ?? {})) fail('INVALID_CONFIG', 'resources must be an explicit alias map');
  const maxResourceBytes = integer(raw.maxResourceBytes ?? 16384, 1, 65536, 'maxResourceBytes');
  const maxResourceTotalBytes = integer(raw.maxResourceTotalBytes ?? 65536, 1, 131072, 'maxResourceTotalBytes');
  const resources = new Map();
  if (Object.keys(raw.resources ?? {}).length > 32) fail('INVALID_CONFIG', 'At most 32 resources may be approved per grant');
  for (const [id, item] of Object.entries(raw.resources ?? {})) {
    if (!root || !idOK(id) || !isObject(item) || !kinds.includes(item.kind) ||
        Object.keys(item).some(key => !['kind', 'path', 'description', 'maxBytes', 'sha256'].includes(key))) fail('INVALID_CONFIG', 'Malformed approved resource');
    const description = item.description ?? id;
    if (typeof description !== 'string' || Buffer.byteLength(description) > 1024) fail('INVALID_CONFIG', 'Resource description is too long');
    if (item.sha256 !== undefined && !/^[a-f0-9]{64}$/.test(item.sha256)) fail('INVALID_CONFIG', 'Resource sha256 must be a lowercase SHA-256 digest');
    resources.set(id, { id, kind: item.kind, path: relativeName(item.path), description,
      maxBytes: integer(item.maxBytes ?? maxResourceBytes, 1, maxResourceBytes, 'resource.maxBytes'), sha256: item.sha256 });
  }
  return { resources, maxResourceBytes, maxResourceTotalBytes };
}

export function validateResourceTask(task, grant) {
  if (!isObject(task.args)) fail('INVALID_ARGS', 'Resource arguments must be an object');
  if (task.tool === 'resourceList') {
    if (Object.keys(task.args).length) fail('INVALID_ARGS', 'resourceList takes no arguments');
  } else if (task.tool === 'resourceRead') {
    if (Object.keys(task.args).some(key => key !== 'resource') || !idOK(task.args.resource)) fail('INVALID_ARGS', 'resourceRead requires an approved resource alias');
    if (!grant.resources?.has(task.args.resource)) fail('RESOURCE_DENIED', 'Resource is not approved for this master');
    assertDirectoryAccess(grant, grant.resources.get(task.args.resource).path, 'read');
  } else fail('TOOL_DENIED', 'Unknown resource operation');
}

const same = (a,b) => a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
async function snapshot(root, relative, signal) {
  const names = [root];
  for (const part of relative.split('/')) names.push(path.join(names.at(-1), part));
  const states = [];
  for (const [i,name] of names.entries()) {
    signal.throwIfAborted();
    const stat = await fs.lstat(name);
    if (stat.isSymbolicLink() || await fs.realpath(name) !== name ||
      (i < names.length - 1 ? !stat.isDirectory() : (!stat.isFile() || stat.nlink !== 1))) fail('PATH_DENIED', 'Resource paths must be regular and cannot contain links');
    states.push({ name, stat });
  }
  return states;
}

export async function executeResourceTask(task, grant, signal = new AbortController().signal) {
  signal.throwIfAborted();
  if (!grant.tools?.has(task.tool)) fail('TOOL_DENIED', 'Resource tool is not granted');
  validateResourceTask(task, grant);
  if (task.tool === 'resourceList') return { resources: [...(grant.resources?.values() ?? [])].filter(resource => directoryAccess(grant, resource.path, 'read')).map(({ id,kind,description,maxBytes,sha256 }) => ({ id,kind,description,maxBytes,sha256 })), maxTotalBytes: grant.maxResourceTotalBytes ?? 65536 };
  const resource = grant.resources.get(task.args.resource);
  const before = await snapshot(grant.root, resource.path, signal);
  const file = before.at(-1);
  if (file.stat.size > Math.min(resource.maxBytes,grant.maxResourceTotalBytes ?? 65536)) fail('RESOURCE_TOO_LARGE', 'Approved resource exceeds its byte limit');
  const handle = await fs.open(file.name, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let text, bytes, digest;
  try {
    if (!same(await handle.stat(), file.stat)) fail('PATH_DENIED', 'Resource changed while opening');
    const buffer = Buffer.alloc(resource.maxBytes + 1); bytes = 0;
    while (bytes < buffer.length) {
      signal.throwIfAborted();
      const { bytesRead } = await handle.read(buffer, bytes, buffer.length - bytes, bytes);
      if (!bytesRead) break;
      bytes += bytesRead;
    }
    if (bytes > resource.maxBytes) fail('RESOURCE_TOO_LARGE', 'Approved resource exceeds its byte limit');
    const after = await snapshot(grant.root, resource.path, signal);
    if (after.some((entry,i) => !same(entry.stat,before[i].stat)) || !same(await handle.stat(),file.stat)) fail('PATH_DENIED', 'Resource changed during read');
    digest = createHash('sha256').update(buffer.subarray(0,bytes)).digest('hex');
    if (resource.sha256 && resource.sha256 !== digest) fail('RESOURCE_CHANGED', 'Resource content no longer matches the owner-approved digest');
    try { text = new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,bytes)); }
    catch { fail('INVALID_ENCODING', 'Approved resources must be UTF-8 text'); }
  } finally { await handle.close(); }
  signal.throwIfAborted();
  return { id: resource.id, kind: resource.kind, description: resource.description, text, bytes, sha256: digest, maxTotalBytes: grant.maxResourceTotalBytes ?? 65536, trust: 'owner-allowlisted-data-not-executable-code' };
}
