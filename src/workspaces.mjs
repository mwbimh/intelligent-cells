import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { fail, isObject } from './errors.mjs';
import { readChecked, writeChecked } from './durable.mjs';
import { directoryPolicySummary } from './directory-policy.mjs';

export const workspaceIdValid = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(value);
export const creationIdValid = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,100}$/.test(value);
export const workspaceNameValid = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(value) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(value);
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (isObject(value)) return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
export const workspaceHash = value => createHash('sha256').update(canonical(value)).digest('hex');
const sameIdentity = (a, b) => a?.dev === b?.dev && a?.ino === b?.ino;
export function directoryIdentity(filename, privateParent = false) {
  const stat = fs.lstatSync(filename);
  if (!stat.isDirectory() || stat.isSymbolicLink() || fs.realpathSync(filename) !== filename ||
      (privateParent && ((process.getuid && stat.uid !== process.getuid()) || (process.platform !== 'win32' && (stat.mode & 0o022))))) fail('WORKSPACE_DENIED', 'Workspace directory must be canonical and provisioning roots owner-controlled');
  return { dev: stat.dev, ino: stat.ino };
}
function syncDirectory(filename) { const fd = fs.openSync(filename, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function summary(id, name, kind, grant, extra = {}) { return { id, name, kind, state: 'ready', tools: [...grant.tools], filesystem: directoryPolicySummary(grant), ...extra }; }

// Stored under the node's existing exclusive owner lock. Synchronous intent,
// mkdir, identity and commit writes cannot interleave with a local policy change.
// A crash in the mkdir/identity gap remains unknown: never adopt or retry it.
export class WorkspaceRegistry {
  constructor(node) { this.node = node; this.filename = path.join(node.config.stateDir, 'workspaces.json'); }
  open() {
    try { this.state = readChecked(this.filename, 8 * 1024 * 1024); }
    catch (error) { if (error.code !== 'ENOENT') throw error; this.state = { version: 1, nodeId: this.node.config.id, revision: 0, bindings: [], autoProvision: [], creations: [] }; this.save(this.state); }
    const s = this.state;
    if (s.version !== 1 || s.nodeId !== this.node.config.id || !Number.isSafeInteger(s.revision) || s.revision < 0 || !Array.isArray(s.bindings) || !Array.isArray(s.autoProvision) || !Array.isArray(s.creations) || s.bindings.length > 1024 || s.autoProvision.length > 1024 || s.creations.length > 1024) fail('JOURNAL_CORRUPT', 'Invalid workspace registry');
    const keys = new Set();
    for (const binding of [...s.bindings, ...s.autoProvision]) {
      if (!workspaceIdValid(binding.logicalWorkspaceId) || !workspaceIdValid(binding.peerId) || (binding.workspaceId !== undefined && !workspaceIdValid(binding.workspaceId)) || (binding.rootId !== undefined && (!workspaceIdValid(binding.rootId) || typeof binding.enabled !== 'boolean'))) fail('JOURNAL_CORRUPT', 'Invalid workspace binding');
      const key = `${binding.workspaceId === undefined ? 'auto' : 'bind'}:${binding.logicalWorkspaceId}:${binding.peerId}`;
      if (keys.has(key)) fail('JOURNAL_CORRUPT', 'Duplicate workspace binding'); keys.add(key);
    }
    for (const record of s.creations) {
      if (!workspaceIdValid(record.id) || !workspaceIdValid(record.masterId) || !workspaceIdValid(record.rootId) || !creationIdValid(record.requestId) || !workspaceNameValid(record.name) || !['intent','created','ready','unknown','failed'].includes(record.state) || !path.isAbsolute(record.parent) || !/^[a-f0-9]{64}$/.test(record.templateHash)) fail('JOURNAL_CORRUPT', 'Invalid workspace creation record');
      const key = `${record.masterId}:${record.requestId}`; if (keys.has(key) || keys.has(record.id)) fail('JOURNAL_CORRUPT', 'Duplicate workspace creation'); keys.add(key); keys.add(record.id);
      if (record.state === 'intent') { record.state = 'unknown'; record.error = 'Interrupted before directory identity was committed'; }
      else if (record.state === 'created') {
        try { this.assertCreation(record); record.state = 'ready'; }
        catch { record.state = 'unknown'; record.error = 'Interrupted creation requires owner inspection'; }
      }
    }
    this.save(s); return this;
  }
  save(state) {
    try { writeChecked(this.filename, state); } catch (error) { this.node.storageFailed = true; throw error; }
    this.state = state;
  }
  snapshot() {
    return { revision: this.state.revision, bindings: structuredClone(this.state.bindings), autoProvision: structuredClone(this.state.autoProvision), creations: this.state.creations.map(({ parent, parentIdentity, identity, templateHash, ...record }) => structuredClone(record)) };
  }
  assertRevision(expected) { if (expected !== undefined && expected !== this.state.revision) fail('WORKSPACE_BINDING_CONFLICT', 'Workspace mappings changed; refresh before saving'); }
  binding(peerId, logicalWorkspaceId) { return this.state.bindings.find(item => item.peerId === peerId && item.logicalWorkspaceId === logicalWorkspaceId); }
  rule(peerId, logicalWorkspaceId) { return this.state.autoProvision.find(item => item.peerId === peerId && item.logicalWorkspaceId === logicalWorkspaceId); }
  bind(peerId, logicalWorkspaceId, workspaceId, expected) {
    this.assertRevision(expected); this.node.assertStorage();
    const state = structuredClone(this.state), existing = this.binding(peerId, logicalWorkspaceId);
    if (existing?.workspaceId === workspaceId) return structuredClone(existing);
    if (!existing && state.bindings.length >= 1024) fail('WORKSPACE_CAPACITY', 'Workspace binding registry is full');
    const binding = { peerId, logicalWorkspaceId, workspaceId, createdAt: existing?.createdAt ?? Date.now(), updatedAt: Date.now() };
    state.bindings = state.bindings.filter(item => item.peerId !== peerId || item.logicalWorkspaceId !== logicalWorkspaceId); state.bindings.push(binding); state.revision++;
    this.save(state); return structuredClone(binding);
  }
  unbind(peerId, logicalWorkspaceId, expected) {
    this.assertRevision(expected); this.node.assertStorage();
    const state = structuredClone(this.state); state.bindings = state.bindings.filter(item => item.peerId !== peerId || item.logicalWorkspaceId !== logicalWorkspaceId);
    if (state.bindings.length !== this.state.bindings.length) { state.revision++; this.save(state); }
    return this.snapshot();
  }
  setAuto(peerId, logicalWorkspaceId, rootId, enabled, expected) {
    this.assertRevision(expected); this.node.assertStorage();
    const state = structuredClone(this.state);
    if (!this.rule(peerId, logicalWorkspaceId) && state.autoProvision.length >= 1024) fail('WORKSPACE_CAPACITY', 'Workspace automatic provisioning registry is full');
    state.autoProvision = state.autoProvision.filter(item => item.peerId !== peerId || item.logicalWorkspaceId !== logicalWorkspaceId);
    state.autoProvision.push({ peerId, logicalWorkspaceId, rootId, enabled, updatedAt: Date.now() }); state.revision++; this.save(state); return this.snapshot();
  }
  assertCreation(record) {
    if (!sameIdentity(record.parentIdentity, directoryIdentity(record.parent, true)) || !record.identity || !sameIdentity(record.identity, directoryIdentity(path.join(record.parent, record.name)))) fail('WORKSPACE_DENIED', 'Provisioned workspace identity changed');
  }
  rootFor(record) {
    const root = this.node.config.policy.grants.get(record.masterId)?.workspaceProvisioning?.get(record.rootId);
    if (!root || root.path !== record.parent || root.templateHash !== record.templateHash || !sameIdentity(root.identity, record.parentIdentity)) fail('WORKSPACE_DENIED', 'Provisioning approval changed or was revoked');
    return root;
  }
  resolve(masterId, id) {
    const grant = this.node.config.policy.grants.get(masterId);
    if (!grant) fail('MASTER_DENIED', 'Local peer permission was revoked');
    if (id === undefined || id === 'default') return grant;
    if (!workspaceIdValid(id)) fail('INVALID_TASK', 'Invalid workspaceId');
    const configured = grant.workspaces?.get(id);
    if (configured) {
      if (!sameIdentity(configured.workspaceIdentity, directoryIdentity(configured.root))) fail('WORKSPACE_DENIED', 'Configured workspace identity changed');
      return configured;
    }
    const record = this.state.creations.find(item => item.masterId === masterId && item.id === id);
    if (!record || record.state !== 'ready') fail('WORKSPACE_DENIED', 'Workspace is not available to this peer');
    const root = this.rootFor(record); this.assertCreation(record);
    const workspaceRoot = path.join(root.path, record.name);
    return { ...root.grant, root: workspaceRoot, mcpServers: new Map([...(root.grant.mcpServers ?? [])].map(([alias,server])=>[alias,{...server,root:workspaceRoot}])) };
  }
  catalog(masterId, {offset=0,limit=32} = {}) {
    const grant = this.node.config.policy.grants.get(masterId); if (!grant) fail('MASTER_DENIED', 'Peer is not allowed');
    const workspaces = [];
    if (grant.root) workspaces.push(summary('default', 'default', 'default', grant));
    for (const [id, item] of grant.workspaces ?? []) {
      try { this.resolve(masterId, id); workspaces.push(summary(id, id, 'configured', item)); } catch { /* An unavailable path is never advertised as usable. */ }
    }
    for (const record of this.state.creations.filter(item => item.masterId === masterId)) {
      try { const item = this.resolve(masterId, record.id); workspaces.push(summary(record.id, record.name, 'provisioned', item, { rootId: record.rootId, requestId: record.requestId })); }
      catch { workspaces.push({ id: record.id, name: record.name, kind: 'provisioned', state: record.state === 'ready' ? 'unavailable' : record.state, rootId: record.rootId, requestId: record.requestId }); }
    }
    const creationRoots = grant.tools.has('workspaceCreate') ? [...(grant.workspaceProvisioning ?? [])].map(([id, root]) => {
      const used = this.state.creations.filter(item => item.masterId === masterId && item.rootId === id && item.state !== 'failed').length;
      return { id, maxWorkspaces: root.maxWorkspaces, used, remaining: Math.max(0, root.maxWorkspaces - used), tools: [...root.grant.tools], filesystem: directoryPolicySummary(root.grant) };
    }) : [];
    const entries=[...workspaces.map(value=>({kind:'workspace',value})),...creationRoots.map(value=>({kind:'root',value}))];
    const result={workspaces:[],creationRoots:[],offset,total:entries.length,nextOffset:null};
    let index=offset,bytes=256;
    for(;index<entries.length && index<offset+limit;index++){
      const entry=entries[index],size=Buffer.byteLength(JSON.stringify(entry.value));
      if(bytes+size>90000){if(index===offset)fail('RESULT_TOO_LARGE','Workspace summary exceeds bounded catalog size');break;}
      result[entry.kind==='workspace'?'workspaces':'creationRoots'].push(entry.value);bytes+=size;
    }
    result.nextOffset=index<entries.length?index:null;return result;
  }
  completedRequest(masterId, args) {
    const record = this.state.creations.find(item => item.masterId === masterId && item.requestId === args.requestId);
    if (!record || record.rootId !== args.rootId || record.name !== args.name || record.state !== 'ready') return null;
    try { return summary(record.id, record.name, 'provisioned', this.resolve(masterId, record.id), { rootId: record.rootId, requestId: record.requestId }); } catch { return null; }
  }
  create(masterId, args, signal) {
    this.node.assertStorage(); signal.throwIfAborted();
    const parentGrant = this.node.config.policy.grants.get(masterId), root = parentGrant?.workspaceProvisioning?.get(args.rootId);
    if (!parentGrant?.tools.has('workspaceCreate') || !root) fail('WORKSPACE_CREATE_DENIED', 'Workspace creation is not approved for this root and peer');
    const previous = this.state.creations.find(item => item.masterId === masterId && item.requestId === args.requestId);
    if (previous) {
      if (previous.rootId !== args.rootId || previous.name !== args.name) fail('WORKSPACE_REQUEST_CONFLICT', 'Creation requestId already names a different workspace');
      const result = this.completedRequest(masterId, args); if (result) return result;
      fail(previous.state === 'failed' ? 'WORKSPACE_NAME_CONFLICT' : 'WORKSPACE_CREATE_UNKNOWN', 'Creation request is consumed; inspect its state, never replay it');
    }
    if (this.state.creations.length >= 1024) fail('WORKSPACE_CAPACITY', 'Workspace creation history is full; owner maintenance required');
    const used = this.state.creations.filter(item => item.masterId === masterId && item.rootId === args.rootId && item.state !== 'failed').length;
    if (used >= root.maxWorkspaces) fail('WORKSPACE_QUOTA', 'Servant-approved workspace quota is exhausted');
    if (!sameIdentity(root.identity, directoryIdentity(root.path, true))) fail('WORKSPACE_DENIED', 'Provisioning root identity changed');
    const target = path.join(root.path, args.name);
    // Existing paths are never adopted or replaced, even if empty.
    try { fs.lstatSync(target); fail('WORKSPACE_NAME_CONFLICT', 'Workspace name already exists'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const record = { id: `ws_${randomUUID().replaceAll('-', '')}`, masterId, rootId: args.rootId, requestId: args.requestId, name: args.name, parent: root.path, parentIdentity: root.identity, templateHash: root.templateHash, state: 'intent', createdAt: Date.now() };
    const state = structuredClone(this.state); state.creations.push(record); this.save(state);
    try {
      fs.mkdirSync(target, { mode: 0o700 }); syncDirectory(root.path);
      record.identity = directoryIdentity(target); record.state = 'created'; this.save(state);
      this.assertCreation(record); record.state = 'ready'; this.save(state);
    } catch (error) {
      if (error.code === 'EEXIST' && !record.identity) { record.state = 'failed'; record.error = 'Name already exists'; this.save(state); fail('WORKSPACE_NAME_CONFLICT', 'Workspace name already exists'); }
      // No deletion/rollback of possibly-created user data, and no blind replay.
      record.state = 'unknown'; record.error = 'Creation interrupted; owner inspection required'; if (!this.node.storageFailed) this.save(state); throw error;
    }
    return this.completedRequest(masterId, args);
  }
  reconcile(command) {
    const record = this.state.creations.find(item => item.id === command.workspaceId && item.masterId === command.masterId);
    if (!record || record.state !== 'unknown' || !['completed','not_created'].includes(command.resolution) || typeof command.note !== 'string' || command.note.trim().length < 3 || command.note.length > 1000) fail('INVALID_COMMAND', 'Unknown creation requires an owner evidence note and completed/not_created resolution');
    const state = structuredClone(this.state), next = state.creations.find(item => item.id === record.id);
    this.rootFor(record);
    if (command.resolution === 'not_created') {
      try { fs.lstatSync(path.join(record.parent, record.name)); fail('WORKSPACE_DENIED', 'Directory exists; cannot confirm not_created'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      next.state = 'failed';
    } else {
      if (!sameIdentity(record.parentIdentity, directoryIdentity(record.parent, true))) fail('WORKSPACE_DENIED', 'Provisioning parent changed');
      // This explicit local owner action, unlike automatic recovery, may attest
      // the directory created in the intent/identity crash window.
      next.identity = directoryIdentity(path.join(record.parent, record.name)); next.state = 'ready';
    }
    next.reconciledAt = Date.now(); next.resolution = command.resolution; delete next.error; this.save(state);
    return this.snapshot();
  }
}
