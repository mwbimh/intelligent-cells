import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { fail, integer, isObject } from './errors.mjs';
import { loadSecurity } from './identity.mjs';
import { validatePiConfiguration } from './pi-policy.mjs';
export const validId = x => typeof x === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(x);
import { TOOL_NAMES, MAX_TASK_TIMEOUT_MS, capabilitySchema } from './tools.mjs';
import { compileResourcePolicy } from './resources.mjs';
import { compileMcpPolicy, verifyMcpCodePolicy } from './mcp.mjs';
import { compileApprovedCode, verifyCodeIsolation, pathsOverlap } from './code-policy.mjs';
import { compileDirectoryPolicy } from './directory-policy.mjs';
import { directoryIdentity, workspaceHash } from './workspaces.mjs';
const names = [...TOOL_NAMES];
export async function loadPolicy(p = {}, base = process.cwd(), nested = false) {
  if (!isObject(p) || !isObject(p.grants ?? {})) fail('INVALID_CONFIG', 'policy.grants must be a per-peer object');
  if (p.allowedMasters !== undefined || p.tools !== undefined) fail('INVALID_CONFIG', 'Use policy.grants with explicit per-peer permissions');
  const policy = { grants: new Map(), allowedMasters: new Set(), tools: new Set(),
    maxConcurrent: integer(p.maxConcurrent ?? 4, 1, 32, 'maxConcurrent'),
    maxCacheBytes: integer(p.maxCacheBytes ?? 4194304, 1024, 67108864, 'maxCacheBytes'),
    maxTaskRecords: integer(p.maxTaskRecords ?? 4096, 1, 100000, 'maxTaskRecords'),
    maxJournalBytes: integer(p.maxJournalBytes ?? 67108864, 1048576, 1073741824, 'maxJournalBytes') };
  if (Object.keys(p.grants ?? {}).length > 128) fail('INVALID_CONFIG', 'At most 128 incoming peer grants');
  for (const [id, g] of Object.entries(p.grants ?? {})) {
    if (!validId(id) || !isObject(g) || !Array.isArray(g.tools ?? []) || (g.tools ?? []).some(t => !names.includes(t))) fail('INVALID_CONFIG', 'Invalid per-peer grant or tool');
    if (nested && (g.workspaces !== undefined || g.workspaceProvisioning !== undefined || (g.tools ?? []).some(t => ['workspaceList','workspaceCreate'].includes(t)))) fail('INVALID_CONFIG', 'Nested workspace grants cannot provision or contain other workspaces');
    const grant = { allowedMasters: new Set([id]), tools: new Set(g.tools ?? []), root: null,
      maxConcurrent: integer(g.maxConcurrent ?? 1, 1, policy.maxConcurrent, 'grant.maxConcurrent'),
      maxTimeoutMs: integer(g.maxTimeoutMs ?? 2000, 10, MAX_TASK_TIMEOUT_MS, 'maxTimeoutMs'),
      maxWaitMs: integer(g.maxWaitMs ?? 5000, 0, MAX_TASK_TIMEOUT_MS, 'maxWaitMs'),
      maxReadBytes: integer(g.maxReadBytes ?? 16384, 1, 65536, 'maxReadBytes'),
      maxWriteBytes: integer(g.maxWriteBytes ?? 16384, 1, 65536, 'maxWriteBytes'),
      maxOutputBytes: integer(g.maxOutputBytes ?? 16384, 1, 16777216, 'maxOutputBytes'),
      maxJobTimeoutMs: integer(g.maxJobTimeoutMs ?? 3600000, 10, MAX_TASK_TIMEOUT_MS, 'maxJobTimeoutMs'),
      maxJobs: integer(g.maxJobs ?? 32, 1, 256, 'maxJobs'),
      maxOutputPageBytes: integer(g.maxOutputPageBytes ?? 16384, 1, 16384, 'maxOutputPageBytes'),
      maxSearchFiles: integer(g.maxSearchFiles ?? 1000, 1, 100000, 'maxSearchFiles'),
      maxSearchBytes: integer(g.maxSearchBytes ?? 1048576, 1, 67108864, 'maxSearchBytes'),
      maxDirectoryEntries: integer(g.maxDirectoryEntries ?? 1000, 1, 10000, 'maxDirectoryEntries'),
      maxTransferBytes: integer(g.maxTransferBytes ?? 67108864, 1, 268435456, 'maxTransferBytes'),
      maxTasksPerMinute: integer(g.maxTasksPerMinute ?? 120, 1, 10000, 'maxTasksPerMinute'), execCommands: new Map() };
    if (g.workspace !== undefined) {
      if (typeof g.workspace !== 'string' || !g.workspace || g.workspace.includes('\0')) fail('INVALID_CONFIG', 'workspace must be a nonempty path');
      grant.root = await fs.realpath(path.resolve(base, g.workspace));
      if (!(await fs.stat(grant.root)).isDirectory()) fail('INVALID_CONFIG', 'workspace must be a directory');
    }
    if (['readFile', 'writeFile', 'editFile', 'exec', 'listDirectory', 'searchFiles', 'mkdir', 'readChunk', 'writeChunk', 'resourceList', 'resourceRead', 'mcpList', 'mcpCall'].some(t => grant.tools.has(t)) && !grant.root) fail('INVALID_CONFIG', 'Filesystem and exec grants require an explicit workspace');
    Object.assign(grant, await compileDirectoryPolicy(g, grant.root, grant.tools));
    if (!isObject(g.execCommands ?? {})) fail('INVALID_CONFIG', 'execCommands must be an object');
    for (const [alias, cmd] of Object.entries(g.execCommands ?? {})) {
      if (!validId(alias) || !isObject(cmd) || typeof cmd.file !== 'string' || !path.isAbsolute(cmd.file) || cmd.file.includes('\0') || !Array.isArray(cmd.args ?? []) || (cmd.args ?? []).length > 32 || (cmd.args ?? []).some(a => typeof a !== 'string' || a.includes('\0') || Buffer.byteLength(a) > 4096)) fail('INVALID_CONFIG', 'exec command needs a local absolute executable and bounded fixed argument prefix');
      const file = await fs.realpath(cmd.file);
      const executableStat = await fs.stat(file);
      if (!executableStat.isFile() || executableStat.nlink !== 1) fail('INVALID_CONFIG', 'exec command executable must be a regular non-hardlinked file');
      if (!isObject(cmd.env ?? {}) || Object.entries(cmd.env ?? {}).some(([k,v]) => !/^[A-Z_][A-Z0-9_]*$/.test(k) || typeof v !== 'string' || ['NODE_OPTIONS', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES'].includes(k))) fail('INVALID_CONFIG', 'Unsafe or malformed exec environment');
      if (cmd.allowedArgs !== undefined && (!Array.isArray(cmd.allowedArgs) || cmd.allowedArgs.length > 128 || cmd.allowedArgs.some(a => typeof a !== 'string' || Buffer.byteLength(a) > 4096))) fail('INVALID_CONFIG', 'allowedArgs must be a bounded explicit string allowlist');
      const approvedCode = await compileApprovedCode(file, cmd.args ?? [], 'UNSAFE_EXEC_POLICY', cmd);
      grant.execCommands.set(alias, { file, args: [...(cmd.args ?? [])], ...approvedCode, argsAllowed: cmd.argsAllowed === true, maxArgs: integer(cmd.maxArgs ?? 8, 0, 32, 'maxArgs'), env: {...(cmd.env ?? {})}, stdinAllowed: cmd.stdinAllowed === true, maxStdinBytes: integer(cmd.maxStdinBytes ?? 16384, 0, 65536, 'maxStdinBytes'), ...(cmd.allowedArgs !== undefined ? {allowedArgs: [...cmd.allowedArgs]} : {}) });
    }
    Object.assign(grant, await compileResourcePolicy(g, base, grant.root));
    Object.assign(grant, await compileMcpPolicy(g, base, grant.root));
    grant.workspaces = new Map(); grant.workspaceProvisioning = new Map();
    if (!isObject(g.workspaces ?? {}) || Object.keys(g.workspaces ?? {}).length > 32) fail('INVALID_CONFIG', 'workspaces must contain at most 32 named grants');
    for (const [workspaceId, raw] of Object.entries(g.workspaces ?? {})) {
      if (!validId(workspaceId) || workspaceId === 'default' || workspaceId.startsWith('ws_') || !isObject(raw) || !Array.isArray(raw.tools) || typeof raw.workspace !== 'string') fail('INVALID_CONFIG', 'Named workspaces need a stable nonreserved ID, workspace and explicit tools');
      const child = (await loadPolicy({ ...p, grants: { [id]: raw } }, base, true)).grants.get(id);
      child.workspaceIdentity = directoryIdentity(child.root); grant.workspaces.set(workspaceId, child);
    }
    if (g.workspaceProvisioning !== undefined) {
      if (!isObject(g.workspaceProvisioning) || Object.keys(g.workspaceProvisioning).some(key => key !== 'roots') || !isObject(g.workspaceProvisioning.roots) || Object.keys(g.workspaceProvisioning.roots).length > 16) fail('INVALID_CONFIG', 'workspaceProvisioning requires at most 16 owner-declared roots');
      for (const [rootId, item] of Object.entries(g.workspaceProvisioning.roots)) {
        if (!validId(rootId) || !isObject(item) || Object.keys(item).some(key => !['path','maxWorkspaces','grant'].includes(key)) || typeof item.path !== 'string' || !item.path || item.path.includes('\0') || !isObject(item.grant) || !Array.isArray(item.grant.tools) || !Array.isArray(item.grant.directories) || ['workspace','workspaces','workspaceProvisioning'].some(key => item.grant[key] !== undefined)) fail('INVALID_CONFIG', 'Provisioning roots require path, quota and explicit tool/directory grant defaults');
        const rootPath = path.resolve(base, item.path);
        let identity;
        try { identity = directoryIdentity(rootPath, true); } catch { fail('INVALID_CONFIG', 'Provisioning root must exist as a canonical owner-controlled directory'); }
        const child = (await loadPolicy({ ...p, grants: { [id]: { ...item.grant, workspace: rootPath } } }, base, true)).grants.get(id);
        const maxWorkspaces = integer(item.maxWorkspaces, 1, 128, 'workspaceProvisioning.maxWorkspaces');
        grant.workspaceProvisioning.set(rootId, { path: rootPath, identity, maxWorkspaces, grant: child, templateHash: workspaceHash(item.grant) });
      }
    }
    if(Buffer.byteLength(JSON.stringify(capabilitySchema(grant)))>98304)fail('INVALID_CONFIG','Compiled peer capability catalog exceeds bounded transport size');
    policy.allowedMasters.add(id); policy.grants.set(id, grant);
    for (const tool of grant.tools) policy.tools.add(tool);
  }
  // A writable data workspace must not directly contain code that another
  // granted command executes. Inspect all peers, not only the executing peer.
  const allGrants = [...policy.grants.values()].flatMap(g => [g, ...g.workspaces.values(), ...[...g.workspaceProvisioning.values()].map(root => root.grant)]);
  const provisioningRoots = [...policy.grants.values()].flatMap(g => [...g.workspaceProvisioning.values()].map(root => root.path));
  const existingRoots = [...policy.grants.values()].flatMap(g => [g.root, ...[...g.workspaces.values()].map(child => child.root)]).filter(Boolean);
  for (const [index, root] of provisioningRoots.entries()) if (existingRoots.some(other => pathsOverlap(root, other)) || provisioningRoots.slice(index + 1).some(other => pathsOverlap(root, other))) fail('INVALID_CONFIG', 'Provisioning roots must be disjoint from every workspace and other provisioning root');
  const writableRoots = [...new Set([...provisioningRoots, ...allGrants.filter(g => ['writeFile','editFile','mkdir','writeChunk'].some(tool => g.tools.has(tool))).map(g => g.root)])];
  for (const grant of allGrants) for (const command of grant.execCommands.values()) {
    verifyCodeIsolation(command, writableRoots, 'UNSAFE_EXEC_POLICY');
  }
  await verifyMcpCodePolicy({grants:new Map(allGrants.map((grant,index)=>[index,grant]))}, writableRoots);
  policy.workspaceGrants = allGrants;
  return policy;
}

export function validatePolicyIsolation(policy, config) {
  const runtimeRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  const configDirectory=path.dirname(config.filename);
  const files=[config.filename,...(config.securityFiles??[]),...(config.logFile?[config.logFile]:[])];
  // Dedicated TLS/log directories are protected as trees. A config and a log
  // may intentionally live beside a workspace, so their shared config parent
  // is not implicitly promoted into a dedicated secret directory.
  const dedicatedDirectories=[...(config.securityFiles??[]),...(config.logFile?[config.logFile]:[])].map(filename=>path.dirname(filename)).filter(directory=>directory!==configDirectory);
  const protectedPaths=[config.stateDir,...files,...dedicatedDirectories,...(config.operator?.sessionDirectory?[config.operator.sessionDirectory]:[]),...(config.operator?.socketPath?[path.dirname(config.operator.socketPath)]:[])];
  for(const grant of (policy.workspaceGrants ?? policy.grants.values())) if(grant.root) {
    if(protectedPaths.some(target=>pathsOverlap(grant.root,target))) fail('UNSAFE_STATE_POLICY','Remote workspaces must be disjoint from durable state, node config, dedicated TLS/log directories and owner-session paths in both directions');
    if((['writeFile','editFile','mkdir','writeChunk'].some(tool=>grant.tools.has(tool)) || [...policy.grants.values()].some(parent=>[...(parent.workspaceProvisioning?.values() ?? [])].some(root=>root.grant===grant))) && pathsOverlap(grant.root,runtimeRoot)) fail('UNSAFE_STATE_POLICY','Remotely writable workspaces must be separate from runtime code');
  }
}

export function validHost(host) {
  return typeof host === 'string' && (net.isIP(host) !== 0 || (host.length <= 253 && /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(host)));
}
export async function loadConfig(filename) {
  const full = path.resolve(filename), base = path.dirname(full);
  const configStat=await fs.lstat(full);
  if(!configStat.isFile()||configStat.isSymbolicLink()||configStat.nlink!==1||await fs.realpath(full)!==full)fail('INVALID_CONFIG','Config must be a canonical regular non-linked file');
  const raw = JSON.parse(await fs.readFile(full, 'utf8'));
  if (!isObject(raw) || !validId(raw.id)) fail('INVALID_CONFIG', 'id must be 1..64 letters, digits, _ or -');
  const checkPath = (value, label) => { if (typeof value !== 'string' || !value || value.includes('\0')) fail('INVALID_CONFIG', `${label} must be a nonempty path`); };
  if (raw.stateDir !== undefined) checkPath(raw.stateDir, 'stateDir');
  if (raw.logFile !== undefined && raw.logFile !== null) checkPath(raw.logFile, 'logFile');
  if (isObject(raw.operator)) for (const key of ['socketPath', 'sessionDirectory']) if (raw.operator[key] !== undefined) checkPath(raw.operator[key], `operator.${key}`);
  if (isObject(raw.security)) for (const key of ['cert', 'key', 'ca']) if (raw.security[key] !== undefined) checkPath(raw.security[key], `security.${key}`);
  const host = raw.host ?? '127.0.0.1';
  if (!validHost(host) || (host !== '127.0.0.1' && raw.security?.allowExternal !== true)) fail('LOOPBACK_ONLY', 'Non-loopback addresses require explicit security.allowExternal=true and mTLS');
  if (!Array.isArray(raw.peers ?? []) || (raw.peers ?? []).length > 32) fail('INVALID_CONFIG', 'peers must be an array');
  const cfg = { id: raw.id, host, port: integer(raw.port, 0, 65535, 'port'), peers: [], agent: raw.agent ?? null, filename: full,
    // Keep the historical default: changing it would hide existing ledgers after upgrades.
    stateDir: path.resolve(base, raw.stateDir ?? `.unified-node-state/${raw.id}`), operator: raw.operator ?? null,
    faultInjection: raw.faultInjection === true, logFile: raw.logFile ? path.resolve(base, raw.logFile) : null };
  if (![null, 'deterministic-demo', 'pi-mock'].includes(cfg.agent)) fail('INVALID_CONFIG', 'agent must be null, deterministic-demo or pi-mock');
  for (const peer of raw.peers ?? []) {
    if (!isObject(peer) || !validId(peer.id) || peer.id === cfg.id || cfg.peers.some(p => p.id === peer.id)) fail('INVALID_CONFIG', 'Invalid or duplicate peer id');
    if (!validHost(peer.host) || (peer.host !== '127.0.0.1' && raw.security?.allowExternal !== true)) fail('LOOPBACK_ONLY', 'Non-loopback peers require explicit secure external configuration');
    cfg.peers.push({ id: peer.id, host: peer.host, port: integer(peer.port, 1, 65535, 'peer.port') });
  }
  if (cfg.peers.length && !cfg.agent) fail('AGENT_REQUIRED', 'Outgoing execution relationships require an agent');
  if (cfg.operator !== null) {
    if (!isObject(cfg.operator) || (cfg.operator.host !== undefined && cfg.operator.host !== '127.0.0.1')) fail('INVALID_CONFIG', 'Operator HTTP must bind 127.0.0.1');
    cfg.operator = {...cfg.operator, port: integer(cfg.operator.port ?? 0, 0, 65535, 'operator.port')};
    if (cfg.operator.socketPath) cfg.operator.socketPath = path.resolve(base, cfg.operator.socketPath);
    if(cfg.operator.sessionDirectory !== undefined || process.platform !== 'win32') cfg.operator.sessionDirectory = path.resolve(base, cfg.operator.sessionDirectory ?? path.join(cfg.stateDir,'operator-access'));
  }
  cfg.pi = validatePiConfiguration(raw.pi);
  if (cfg.pi.resources.some(resource => !cfg.peers.some(peer => peer.id === resource.peerId))) fail('INVALID_CONFIG', 'Pi resources require a configured outgoing peer');
  cfg.policyRaw = raw.policy ?? {};
  cfg.policy = await loadPolicy(raw.policy, base);
  cfg.security = await loadSecurity(raw.security, base, cfg.id);
  cfg.securityFiles = await Promise.all(['cert','key','ca'].map(name=>fs.realpath(path.resolve(base,raw.security[name]))));
  validatePolicyIsolation(cfg.policy,cfg);
  if (cfg.peers.some(p => !cfg.security.trustedPeers.has(p.id)) || [...cfg.policy.allowedMasters].some(id => !cfg.security.trustedPeers.has(id))) fail('INVALID_CONFIG', 'Every configured relationship needs an explicit certificate pin');
  return cfg;
}
