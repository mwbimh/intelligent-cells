import tls from 'node:tls';
import fs from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { authenticateCertificate, tlsOptions } from './identity.mjs';
import { randomUUID, createHash } from 'node:crypto';
import { DeterministicDemoAgent } from './agent.mjs';
import { errorData, fail, isObject, NodeError } from './errors.mjs';
import { validId, loadPolicy, validatePolicyIsolation } from './config.mjs';
import { encodeFrame, receiveFrames, sendFrame } from './wire.mjs';
import { validateRequest, runTool, isSideEffecting, MAX_TASK_TIMEOUT_MS } from './tools.mjs';
import { JobManager } from './jobs.mjs';
import { DurableStore, acquireStateLock, writeChecked, readChecked } from './durable.mjs';
import { AuditLog } from './operator-audit.mjs';
import { directoryPolicySummary } from './directory-policy.mjs';
import { WorkspaceRegistry, workspaceIdValid, workspaceNameValid, creationIdValid, workspaceHash } from './workspaces.mjs';

const taskIdValid = id => typeof id === 'string' && /^[a-zA-Z0-9_-]{1,100}$/.test(id);
const DEFINITE_PRE_EFFECT = new Set(['WORKSPACE_DENIED','WORKSPACE_CREATE_DENIED','WORKSPACE_QUOTA','WORKSPACE_NAME_CONFLICT','WORKSPACE_REQUEST_CONFLICT','WORKSPACE_CAPACITY','PATH_DENIED','DIRECTORY_DENIED','FILE_EXISTS','EDIT_MATCH_COUNT','FILE_TOO_LARGE','INVALID_ENCODING','INVALID_ARGS','INVALID_TASK','TOOL_DENIED','COMMAND_DENIED','UNSAFE_EXEC_POLICY','UNSAFE_MCP_POLICY','ENOENT','ENOTDIR','EISDIR','RESOURCE_DENIED','MCP_TOOL_DENIED','EXEC_CODE_CHANGED','MCP_CODE_CHANGED']);
const unknownCodes = new Set(['OUTCOME_UNKNOWN', 'UNCERTAIN_SIDE_EFFECT']);
const hasUnknownOutcome = response => response?.outcomeUnknown === true || response?.result?.outcomeUnknown === true || response?.result?.state === 'unknown' || unknownCodes.has(response?.error?.code);
const jobIsActive = state => ['starting', 'running'].includes(state);
const terminal = record => !['unknown', 'running', 'dispatching', 'pending'].includes(record.state);
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (isObject(value)) return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
const fingerprint = task => createHash('sha256').update(canonical({ tool: task.tool, args: task.args, timeoutMs: task.timeoutMs, runId: task.runId ?? 'default', ...(task.workspaceId !== undefined ? {workspaceId:task.workspaceId} : {}) })).digest('hex');
const unknownResponse = (taskId, message) => ({ v: 2, type: 'result', taskId, status: 'error', outcomeUnknown: true, error: { code: 'OUTCOME_UNKNOWN', message } });
function publicRecord(record) {
  if (!record) return null;
  const { key, fingerprint: _hash, ...rest } = record;
  const copy=structuredClone(rest);
  if(copy.reconciliation)delete copy.reconciliation.note;
  return copy;
}

export class IntelligentCell {
  constructor(config) {
    this.config = config;
    this.agent = config.agent === 'deterministic-demo' ? new DeterministicDemoAgent() : null;
    this.peers = new Map(config.peers.map(p => [p.id, { ...p, socket: null, connected: false, delay: 100, retry: null, pending: new Map(), requests: new Map(), lastSeen: 0 }]));
    this.inbound = new Set(); this.rawSockets = new Set(); this.records = new Map(); this.active = 0; this.stopping = false;
    this.cacheBytes = 0; this.activeByMaster = new Map(); this.starts = new Map(); this.policyEpoch = 0;
    this.latencyMs = 0; this.executions = new Set(); this.storageFailed = false;
    this.server = tls.createServer({ ...tlsOptions(config.security), requestCert: true, handshakeTimeout: 2000 }, socket => this.accept(socket));
    this.server.on('connection', socket => { this.rawSockets.add(socket); socket.once('close', () => this.rawSockets.delete(socket)); });
    this.server.on('tlsClientError', error => this.log('tls_denied', { code: error.code || 'TLS_ERROR' }));
    this.server.maxConnections = 32;
    this.server.on('error', error => this.log('server_error', { error: errorData(error) }));
  }
  log(event, fields = {}) {
    const base = { timestamp: new Date().toISOString(), nodeId: this.config.id, pid: process.pid, event };
    let line;
    try { line = JSON.stringify({ ...base, ...fields }); }
    catch { line = JSON.stringify({ ...base, error: { code: 'LOG_SERIALIZATION_ERROR', message: 'Unserializable log details omitted' } }); }
    process.stdout.write(line + '\n');
    try { this.audit?.append({ ...base, ...fields }); }
    catch (error) { if (!this.logFailureReported) { this.logFailureReported = true; process.stderr.write(JSON.stringify({ ...base, event: 'log_write_error', error: { code: error.code || 'LOG_WRITE_FAILED', message: 'File audit logging failed; stdout remains available' } }) + '\n'); } }
  }
  persist(store, key, record) {
    try { store.put(key, record); }
    catch (error) { if (store.failed) { this.storageFailed = true; this.log('journal_failed', { error: errorData(error) }); } throw error; }
  }
  persistControl(control) {
    try { writeChecked(this.controlPath,control); } catch(error) { this.storageFailed=true;throw error; }
  }
  assertStorage() { if (this.storageFailed) fail('JOURNAL_UNAVAILABLE', 'Durable storage failed; no new execution is permitted'); }
  async start() {
    this.releaseStateLock = acquireStateLock(this.config.stateDir);
    this.controlPath = path.join(this.config.stateDir, 'control.json');
    try {
      this.control = readChecked(this.controlPath);
      if (this.control.nodeId !== this.config.id || !Number.isSafeInteger(this.control.policyEpoch) || !Array.isArray(this.control.revoked)) fail('JOURNAL_CORRUPT', 'Invalid control state');
      const effectiveRaw = structuredClone(this.control.policyRaw);
      effectiveRaw.grants = Object.fromEntries(Object.entries(effectiveRaw.grants ?? {}).filter(([id]) => !this.control.revoked.includes(id)));
      this.config.policy = await loadPolicy(effectiveRaw, path.dirname(this.config.filename));

    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      this.control = { nodeId: this.config.id, policyEpoch: 0, policyRaw: this.config.policyRaw ?? {}, revoked: [] };
      writeChecked(this.controlPath, this.control);
    }
    validatePolicyIsolation(this.config.policy,this.config);
    this.policyEpoch = this.control.policyEpoch;
    for (const id of this.control.revoked) { this.config.policy.grants.delete(id); this.config.policy.allowedMasters.delete(id); }
    if ([...this.config.policy.allowedMasters].some(id => !this.config.security.trustedPeers.has(id))) fail('INVALID_CONFIG', 'Persisted policy references an unpinned identity');
    this.recomputeTools();
    this.workspaceRegistry = new WorkspaceRegistry(this).open(); this.workspaceEnsures = new Map();
    const opts = { maxRecords: this.config.policy.maxTaskRecords, maxBytes: this.config.policy.maxJournalBytes };
    this.journal = new DurableStore({ ...opts, directory: path.join(this.config.stateDir, 'incoming') }).open();
    this.ledger = new DurableStore({ ...opts, directory: path.join(this.config.stateDir, 'outgoing') }).open();
    for (const [store, direction] of [[this.journal, 'incoming'], [this.ledger, 'outgoing']]) {
      // Upgrade retained v0.3 records without forgetting IDs: launch acknowledgments
      // and nested job uncertainty were formerly recorded as completed tasks.
      for (const [key, stored] of [...store.records]) {
        const result = stored.response?.result, job = stored.tool === 'exec' && result?.jobId;
        const background = stored.background || (job && result.background === true);
        const uncertain = stored.state !== 'reconciled' && (hasUnknownOutcome(stored.response) || (job && result.signal));
        if ((job && !stored.jobId) || (background && !stored.background) || (uncertain && stored.state !== 'unknown')) {
          const record = { ...stored, ...(job ? {jobId:result.jobId} : {}), ...(background ? {background:true} : {}), updatedAt:Date.now() };
          if (uncertain) { record.state='unknown'; record.uncertainSideEffect=true; record.uncertaintyTaskId=stored.response?.uncertainty?.taskId??result?.taskId??stored.taskId; record.response={...stored.response,outcomeUnknown:true}; }
          else if (background && jobIsActive(result?.state)) record.state='running';
          this.persist(store,key,record);
        }
      }
      for (const [key, stored] of [...store.records]) if (['running','dispatching','pending','unknown'].includes(stored.state) && direction === 'incoming' && stored.tool === 'workspaceCreate' && stored.workspaceRequest && stored.policyEpoch === this.policyEpoch) {
        const workspace = this.workspaceRegistry.completedRequest(stored.masterId, stored.workspaceRequest);
        if (workspace) this.persist(store, key, { ...stored, state: 'completed', uncertainSideEffect: false, executionSettled: true, updatedAt: Date.now(), recovery: 'workspace_identity_verified', response: {v:2,type:'result',taskId:stored.taskId,status:'ok',result:workspace} });
      }
      for (const [key, stored] of [...store.records]) if (['running','dispatching','pending'].includes(stored.state)) {
        const record = { ...stored, state: stored.sideEffect ? 'unknown' : 'interrupted', updatedAt: Date.now(), recovery: 'process_restart', response: stored.sideEffect ? unknownResponse(stored.taskId, 'Process stopped while an effect may have been running; query and manual reconciliation are required') : {v:2,type:'result',taskId:stored.taskId,status:'error',error:{code:'TASK_INTERRUPTED',message:'Read-only task interrupted by process restart; this ID will not be re-executed'}} };
        this.persist(store, key, record); this.log('task_recovered', { direction, taskId: record.taskId, state: record.state });
      }
    }
    this.audit = new AuditLog({ filename: this.config.logFile ?? path.join(this.config.stateDir, 'audit.jsonl'), maxBytes: 1048576, retention: 4 });
    this.jobManager = new JobManager({ stateDir: path.join(this.config.stateDir, 'jobs'), maxConcurrent: this.config.policy.maxConcurrent, onState: event => { this.log('job_state', event); this.recordJobState(event); } });
    await this.jobManager.start();
    if (this.config.agent === 'pi-mock') {
      const { createPiRemoteAgent } = await import('../integration/pi/agent.mjs');
      this.agent = await createPiRemoteAgent({ node: this });
    }
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.config.port, this.config.host, () => { this.server.off('error', reject); resolve(); });
    });
    this.log('node_ready', { host: this.config.host, transport: 'TLSv1.3-mTLS-pinned', port: this.server.address().port, agent: this.agent?.name ?? null,
      durable: true, tools: [...this.config.policy.tools], outgoing: [...this.peers.keys()], allowedMasters: [...this.config.policy.allowedMasters] });
    for (const peer of this.peers.values()) this.connect(peer);
    this.heartbeat = setInterval(() => {
      for (const peer of this.peers.values()) if (peer.connected) {
        if (Date.now() - peer.lastSeen > 6000) { this.log('heartbeat_timeout', { peerId: peer.id }); peer.socket.destroy(); }
        else sendFrame(peer.socket, { v: 2, type: 'ping' });
      }
    }, 500);
  }
  recomputeTools() { this.config.policy.tools = new Set([...this.config.policy.grants.values()].flatMap(grant => [grant,...(grant.workspaces?.values()??[]),...[...(grant.workspaceProvisioning?.values()??[])].map(root=>root.grant)].flatMap(item=>[...item.tools]))); }
  accept(socket) {
    if (this.stopping || !socket.authorized) { socket.destroy(); return; }
    let authenticatedId;
    try { authenticatedId = authenticateCertificate(socket.getPeerCertificate(), this.config.security); }
    catch (error) { this.log('identity_denied', { error: errorData(error) }); socket.destroy(); return; }
    socket.authenticatedId = authenticatedId;
    this.inbound.add(socket); socket.setNoDelay(true); socket.setTimeout(6000, () => socket.destroy());
    let masterId = null, rejected = false;
    receiveFrames(socket, message => {
      if (rejected || socket.destroyed || this.stopping) return;
      if (message.v !== 2) { sendFrame(socket, { v: 2, type: 'error', error: { code: 'PROTOCOL_VERSION', message: 'Version 2 framing required' } }); socket.destroy(); return; }
      if (masterId === null) {
        if (message.type !== 'hello' || !validId(message.nodeId) || message.nodeId !== authenticatedId || !this.config.policy.allowedMasters.has(authenticatedId)) {
          rejected = true; this.log('relationship_denied', { claimedNodeId: typeof message.nodeId === 'string' ? message.nodeId.slice(0, 64) : null });
          sendFrame(socket, { v: 2, type: 'error', error: { code: 'MASTER_DENIED', message: 'Master is not allowed locally' } }); socket.end(); return;
        }
        masterId = authenticatedId;
        this.log('relationship_accepted', { masterId, transport: socket.getProtocol(), authenticated: true });
        sendFrame(socket, { v: 2, type: 'welcome', nodeId: this.config.id, features: ['durable-tasks','status-query','streaming','unknown-gate'] }); return;
      }
      if (message.type === 'ping') { sendFrame(socket, { v: 2, type: 'pong' }); return; }
      if (message.type === 'query') {
        try {
          authenticateCertificate(socket.getPeerCertificate(), this.config.security, masterId);
          if (!taskIdValid(message.taskId) || !taskIdValid(message.requestId)) fail('INVALID_TASK', 'Invalid task query');
          if (!this.config.policy.allowedMasters.has(masterId)) fail('MASTER_DENIED', 'Local permissions were revoked');
          const record = this.journal.get(`${masterId}:${message.taskId}`);
          if (record?.workspaceId) this.workspaceRegistry.resolve(masterId, record.workspaceId);
          if (record && record.policyEpoch !== this.policyEpoch) fail('TASK_POLICY_CHANGED', 'Policy changed; retained output cannot be disclosed');
          const result = record ? publicRecord(record) : { taskId: message.taskId, state: this.journal.retired(`${masterId}:${message.taskId}`) ? 'expired' : 'not_found' };
          sendFrame(socket, { v: 2, type: 'task_status', requestId: message.requestId, result });
        } catch (error) { sendFrame(socket, { v: 2, type: 'task_status', requestId: taskIdValid(message.requestId) ? message.requestId : null, error: errorData(error) }); }
        return;
      }
      if (message.type === 'cancel') {
        try { authenticateCertificate(socket.getPeerCertificate(), this.config.security, masterId); } catch { socket.destroy(); return; }
        const record = this.records.get(`${masterId}:${message.taskId}`);
        const accepted = this.config.policy.allowedMasters.has(masterId) && !!record && !record.response;
        if (accepted) { record.controller.abort(new NodeError('CANCELLED', 'Authenticated caller cancelled the task')); this.log('task_cancelled', { masterId, taskId: message.taskId }); }
        sendFrame(socket, { v: 2, type: 'cancel_ack', taskId: taskIdValid(message.taskId) ? message.taskId : null, accepted }); return;
      }
      if (message.type !== 'task') { socket.destroy(); return; }
      this.acceptTask(masterId, socket, message);
    }, reason => this.log('protocol_error', { reason }));
    socket.on('error', () => {});
    socket.on('close', () => {
      this.inbound.delete(socket);
      for (const record of this.records.values()) record.watchers.delete(socket);
      if (masterId) this.log('incoming_disconnected', { masterId });
    });
  }
  connect(peer) {
    if (this.stopping || this.peers.get(peer.id) !== peer) return;
    this.log('peer_connecting', { peerId: peer.id });
    const socket = tls.connect({ ...tlsOptions(this.config.security), host: peer.host, port: peer.port, servername: peer.id,
      checkServerIdentity: (_host, certificate) => { try { authenticateCertificate(certificate, this.config.security, peer.id); } catch (error) { return error; } } });
    peer.socket = socket; socket.setNoDelay(true);
    const handshakeTimer = setTimeout(() => socket.destroy(), 2000);
    socket.on('secureConnect', () => {
      try { if (!socket.authorized) throw new NodeError('UNTRUSTED_IDENTITY', 'TLS verification failed'); authenticateCertificate(socket.getPeerCertificate(), this.config.security, peer.id); }
      catch (error) { this.log('identity_denied', { peerId: peer.id, error: errorData(error) }); socket.destroy(); return; }
      sendFrame(socket, { v: 2, type: 'hello', nodeId: this.config.id });
    });
    receiveFrames(socket, message => {
      if (message.v !== 2) { socket.destroy(); return; }
      if (!peer.connected) {
        if (message.type !== 'welcome' || message.nodeId !== peer.id) { socket.destroy(); return; }
        clearTimeout(handshakeTimer); peer.connected = true; peer.delay = 100; peer.lastSeen = Date.now();
        this.log('peer_connected', { peerId: peer.id }); return;
      }
      peer.lastSeen = Date.now();
      if (message.type === 'pong' || message.type === 'cancel_ack') return;
      if (message.type === 'task_status') {
        const request = peer.requests.get(message.requestId); if (!request) return;
        peer.requests.delete(message.requestId); clearTimeout(request.timer);
        if (message.error) request.reject(new NodeError(message.error.code, message.error.message)); else request.resolve(message.result);
        return;
      }
      if (message.type === 'task_state' || message.type === 'task_event') {
        this.log(message.type === 'task_state' ? 'remote_task_state' : 'remote_task_event', { peerId: peer.id, taskId: message.taskId, state: message.state });
        const key = `${peer.id}:${message.taskId}`, previous = this.ledger.get(key);
        if (previous && message.type === 'task_event') { try { this.appendEvent(this.ledger, key, this.applyJobState(previous, message.event), message.event); } catch { this.storageFailed = true; socket.destroy(); } }
        return;
      }
      if (message.type !== 'result' || typeof message.taskId !== 'string' || !['ok', 'error'].includes(message.status)) { socket.destroy(); return; }
      const pending = peer.pending.get(message.taskId);
      if (!pending) { this.log('late_result_ignored', { peerId: peer.id, taskId: message.taskId }); return; }
      clearTimeout(pending.timer); peer.pending.delete(message.taskId);
      try {
        const key = `${peer.id}:${message.taskId}`, record = this.ledger.get(key);
        const uncertain = hasUnknownOutcome(message) || record.state === 'unknown';
        const response = { peerId: peer.id, taskId: message.taskId, status: message.status, ...(uncertain ? {outcomeUnknown:true} : {}), ...(message.uncertainty ? { uncertainty: message.uncertainty } : {}), ...(message.status === 'ok' ? { result: message.result } : { error: message.error }) };
        this.persist(this.ledger, key, { ...record, state: uncertain ? 'unknown' : record.background && jobIsActive(message.result?.state) ? 'running' : message.status === 'ok' ? 'completed' : 'failed', ...(uncertain ? { uncertainSideEffect: true, uncertaintyTaskId: message.uncertainty?.taskId ?? message.result?.taskId ?? message.taskId } : {}), ...(message.result?.jobId ? { jobId: message.result.jobId } : {}), updatedAt: Date.now(), response });
        this.log('task_result_received', { peerId: peer.id, taskId: message.taskId, status: message.status }); pending.resolve(response);
      } catch (error) { this.markOutboundUnknown(peer.id, message.taskId); pending.reject(new NodeError('OUTCOME_UNKNOWN', 'Result could not be durably recorded; manual reconciliation required')); socket.destroy(); }
    }, reason => this.log('protocol_error', { peerId: peer.id, reason }));
    socket.on('error', error => this.log('peer_error', { peerId: peer.id, code: error.code || 'NETWORK_ERROR' }));
    socket.on('close', () => {
      clearTimeout(handshakeTimer); const wasConnected = peer.connected; peer.connected = false;
      for (const [taskId, pending] of peer.pending) {
        clearTimeout(pending.timer); this.markOutboundUnknown(peer.id, taskId);
        pending.reject(new NodeError('OUTCOME_UNKNOWN', 'Connection lost after dispatch; query remote status before manual reconciliation. No replay or local fallback.'));
      }
      peer.pending.clear();
      // A detached job can change after the launch response. Losing its event
      // channel cannot leave a previously 'running' background effect unguarded.
      for (const record of this.ledger.values()) if (record.peerId === peer.id && record.background && record.state === 'running') this.markOutboundUnknown(peer.id, record.taskId);
      for (const request of peer.requests.values()) { clearTimeout(request.timer); request.reject(new NodeError('PEER_UNAVAILABLE', 'Connection lost during read-only status query')); } peer.requests.clear();
      if (wasConnected) this.log('peer_disconnected', { peerId: peer.id });
      if (!this.stopping && this.peers.get(peer.id) === peer) {
        const delay = peer.delay; peer.delay = Math.min(peer.delay * 2, 1600);
        this.log('peer_reconnect_scheduled', { peerId: peer.id, delayMs: delay }); peer.retry = setTimeout(() => this.connect(peer), delay);
      }
    });
  }
  markOutboundUnknown(peerId, taskId) {
    const key = `${peerId}:${taskId}`, record = this.ledger.get(key);
    if (record) try { this.persist(this.ledger, key, { ...record, state: 'unknown', updatedAt: Date.now(), response: {peerId, ...unknownResponse(taskId, 'Dispatch was not confirmed; query status or manually reconcile')} }); } catch { this.storageFailed = true; }
  }
  assertUncertainGate(store, owner = null) {
    for (const record of store.values()) if (record.state === 'unknown' && (record.sideEffect || record.uncertainSideEffect) && (owner === null || record.masterId === owner)) {
      const error = new NodeError('UNCERTAIN_SIDE_EFFECT', 'A previous side effect has unknown outcome. New IDs, peers or run IDs cannot bypass it; query/reconcile first');
      error.uncertainty = { taskId: record.uncertaintyTaskId ?? record.taskId, ...(record.jobId ? { jobId: record.jobId } : {}) }; throw error;
    }
  }
  applyJobState(record, event) {
    if (event?.type !== 'state' || !taskIdValid(event.jobId)) return record;
    const data = { ...record, jobId: event.jobId };
    if (event.outcomeUnknown === true || event.state === 'unknown') {
      data.state = 'unknown'; data.uncertainSideEffect = true; data.uncertaintyTaskId = record.taskId;
      data.response = data.response?.result ? { ...data.response, outcomeUnknown: true, result: { ...data.response.result, state: event.state, outcomeUnknown: true } } : unknownResponse(record.taskId, 'Job ended without a confirmed effect outcome; owner job and task reconciliation are required');
    } else if (record.background && record.state !== 'unknown' && !jobIsActive(event.state) && event.state !== 'reconciled') {
      data.state = 'completed';
      if (data.response?.result) data.response = { ...data.response, result: { ...data.response.result, state: event.state, outcomeUnknown: false } };
    }
    return data;
  }
  recordJobState(job) {
    // Global callback survives completion of the launch task and also runs for
    // recovered jobs on restart. Job state remains linked to its durable task.
    const event = { type: 'state', jobId: job.jobId, state: job.state, outcomeUnknown: job.outcomeUnknown === true };
    for (const [key, stored] of this.journal.records) {
      if (stored.masterId !== job.masterId || stored.tool !== 'exec' || (stored.jobId !== job.jobId && stored.response?.result?.jobId !== job.jobId && stored.taskId !== job.taskId)) continue;
      const live = this.records.get(key), data = this.applyJobState(stored, event);
      this.appendEvent(this.journal, key, data, event);
      if (live) { live.data = data; if (live.response) live.response = data.response; }
      if (data.policyEpoch !== this.policyEpoch || !this.config.policy.allowedMasters.has(job.masterId)) continue;
      for (const socket of this.inbound) if (socket.authenticatedId === job.masterId) sendFrame(socket, { v: 2, type: 'task_event', taskId: stored.taskId, event: data.events.at(-1) });
    }
  }
  appendEvent(store, key, record, event) {
    if (!isObject(event)) return;
    const next = (record.nextEvent ?? 0) + 1;
    const safe = { seq: next, at: Date.now(), type: typeof event.type === 'string' ? event.type.slice(0,32) : 'output', ...(typeof event.stream === 'string' ? {stream:event.stream.slice(0,16)} : {}), ...(typeof event.text === 'string' ? {text:event.text.slice(0,4096)} : {}), ...(typeof event.state === 'string' ? {state:event.state.slice(0,32)} : {}), ...(taskIdValid(event.jobId) ? { jobId: event.jobId } : {}), ...(typeof event.outcomeUnknown === 'boolean' ? { outcomeUnknown: event.outcomeUnknown } : {}) };
    const events = [...(record.events ?? []), safe];
    while (events.length > 64 || Buffer.byteLength(JSON.stringify(events)) > 16384) events.shift();
    record.events = events; record.nextEvent = next; record.updatedAt = Date.now(); this.persist(store, key, record);
  }
  acceptTask(masterId, socket, task) {
    const safeTaskId = taskIdValid(task.taskId) ? task.taskId : null;
    const deny = error => {
      this.log('task_denied', { masterId, taskId: safeTaskId, error: errorData(error) });
      sendFrame(socket, { v: 2, type: 'result', taskId: safeTaskId, status: 'error', ...(unknownCodes.has(error.code) ? { outcomeUnknown: true, ...(error.uncertainty ? { uncertainty: error.uncertainty } : {}) } : {}), error: errorData(error) });
    };
    try {
      this.assertStorage();
      if (task.logicalWorkspaceId !== undefined || (task.workspaceId !== undefined && !workspaceIdValid(task.workspaceId))) fail('INVALID_TASK', 'Wire tasks require an approved workspaceId, never a master-local logical selector');
      if (['workspaceList','workspaceCreate'].includes(task.tool) && task.workspaceId !== undefined) fail('INVALID_TASK', 'Workspace management tools cannot select a workspace');
      const grant = this.workspaceRegistry.resolve(masterId, task.workspaceId);
      authenticateCertificate(socket.getPeerCertificate(), this.config.security, masterId);
      if (!grant) fail('MASTER_DENIED', 'Local peer permission was denied or revoked');
      if (task.runId !== undefined && !taskIdValid(task.runId)) fail('INVALID_TASK', 'Invalid runId');
      const timeoutMs = validateRequest(task, masterId, grant), key = `${masterId}:${task.taskId}`, hash = fingerprint(task);
      const previous = this.journal.get(key);
      if (previous) {
        if (previous.policyEpoch !== this.policyEpoch) fail('TASK_POLICY_CHANGED', 'Policy changed since this task; retained results cannot be disclosed or replayed');
        if (previous.fingerprint !== hash) fail('TASK_ID_CONFLICT', 'This taskId already names a different request');
        this.log('task_duplicate', { masterId, taskId: task.taskId, state: previous.state });
        sendFrame(socket, { v: 2, type: 'task_state', taskId: task.taskId, state: 'duplicate' });
        if (previous.response) sendFrame(socket, previous.response); else this.records.get(key)?.watchers.add(socket);
        return;
      }
      if (this.journal.retired(key)) fail('TASK_HISTORY_EXPIRED', 'Retired task IDs can never be re-executed; inspect external state before a new operation');
      const sideEffect = isSideEffecting(task, grant);
      if (sideEffect) { this.assertUncertainGate(this.journal, masterId); this.jobManager.assertCanWrite(masterId, task.runId ?? 'default'); }
      const recent = (this.starts.get(masterId) ?? []).filter(at => Date.now() - at < 60000);
      if (recent.length >= grant.maxTasksPerMinute) fail('RATE_LIMITED', 'Per-peer task rate limit reached');
      if ((this.activeByMaster.get(masterId) ?? 0) >= grant.maxConcurrent || this.active >= this.config.policy.maxConcurrent) fail('BUSY', 'Local or per-peer execution concurrency limit reached');
      const data = { masterId, taskId: task.taskId, ...(task.workspaceId !== undefined ? {workspaceId:task.workspaceId} : {}), ...(task.tool === 'workspaceCreate' ? {workspaceRequest:structuredClone(task.args)} : {}), runId: task.runId ?? 'default', tool: task.tool, fingerprint: hash, sideEffect, background: task.tool === 'exec' && task.args.background === true, policyEpoch: this.policyEpoch, state: 'running', createdAt: Date.now(), updatedAt: Date.now(), response: null, events: [], nextEvent: 0, executionSettled: false };
      this.persist(this.journal, key, data); // MUST complete before execution begins.
      for (const oldKey of this.records.keys()) if (!this.journal.get(oldKey)) this.records.delete(oldKey);
      const record = { data, masterId, grant, watchers: new Set([socket]), response: null, controller: new AbortController() };
      this.records.set(key, record); this.active++;
      this.activeByMaster.set(masterId, (this.activeByMaster.get(masterId) ?? 0) + 1); recent.push(Date.now()); this.starts.set(masterId, recent);
      this.log('task_started', { masterId, taskId: task.taskId, tool: task.tool, timeoutMs, active: this.active });
      sendFrame(socket, { v: 2, type: 'task_state', taskId: task.taskId, state: 'running' });
      const execution = this.executeTask(masterId, task, record, timeoutMs);
      this.executions.add(execution); void execution.finally(() => this.executions.delete(execution)).catch(error => this.log('execution_error', {error:errorData(error)}));
    } catch (error) { deny(error); }
  }
  async executeTask(masterId, task, record, timeoutMs) {
    let timer; const key = `${masterId}:${task.taskId}`;
    const emit = event => {
      if (record.response && record.data.executionSettled) return; // Job state uses the independent global callback; the spool owns later output.
      this.appendEvent(this.journal, key, record.data, event);
      if(record.data.policyEpoch!==this.policyEpoch || !this.config.policy.allowedMasters.has(masterId)) return;
      for (const watcher of record.watchers) sendFrame(watcher, {v:2,type:'task_event',taskId:task.taskId,event:record.data.events.at(-1)});
    };
    let enteredTool = false;
    const tool = (async () => {
      if (this.latencyMs) await sleep(this.latencyMs, undefined, { signal: record.controller.signal });
      if (['jobStatus','jobOutput','jobStdin','jobCancel'].includes(task.tool)) {
        this.jobManager.assertPolicy(masterId, task.args.jobId, this.policyEpoch);
        if ((this.jobManager.get(masterId, task.args.jobId).workspaceId ?? 'default') !== (task.workspaceId ?? 'default')) fail('WORKSPACE_DENIED', 'Job belongs to another workspace');
      }
      enteredTool = true;
      const result = await runTool(task, record.grant, record.controller.signal, { onOutput: emit, jobManager: this.jobManager, workspaceRegistry: this.workspaceRegistry, workspaceId: task.workspaceId, masterId, runId: task.runId ?? 'default', policyEpoch: record.data.policyEpoch });
      record.controller.signal.throwIfAborted();
      if (record.data.policyEpoch !== this.policyEpoch) fail('TASK_POLICY_CHANGED', 'Policy changed while task was running; retained output cannot be disclosed');
      if (['jobStatus','jobOutput','jobStdin','jobCancel'].includes(task.tool) && isObject(result)) { const { reconciliationNote, ...remoteResult } = result; return remoteResult; }
      return result;
    })();
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => { const error = new NodeError('TASK_TIMEOUT', 'Servant-local task deadline exceeded'); record.controller.abort(error); reject(error); }, timeoutMs);
    });
    try {
      let result = await Promise.race([tool, deadline]);
      if (record.data.background && result?.jobId) result = { ...result, ...this.jobManager.status(masterId, result.jobId) };
      record.response = { v: 2, type: 'result', taskId: task.taskId, status: 'ok', ...(hasUnknownOutcome({ result }) || record.data.state === 'unknown' ? { outcomeUnknown: true, uncertainty: { taskId: result.taskId ?? task.taskId, ...(result.jobId ? { jobId: result.jobId } : {}) } } : {}), result };
    } catch (error) {
      if (record.controller.signal.aborted && record.controller.signal.reason instanceof Error) error = record.controller.signal.reason;
      record.response = { v: 2, type: 'result', taskId: task.taskId, status: 'error', ...(unknownCodes.has(error.code) || (record.data.sideEffect && enteredTool && !DEFINITE_PRE_EFFECT.has(error.code)) ? {outcomeUnknown:true, ...(error.uncertainty ? { uncertainty: error.uncertainty } : {})} : {}), error: errorData(error) };
    } finally { clearTimeout(timer); }
    if (encodeFrame(record.response) === null || Buffer.byteLength(encodeFrame(record.response)) > 98304) record.response = { v: 2, type: 'result', taskId: task.taskId, status: 'error', ...(record.data.sideEffect ? {outcomeUnknown:true} : {}), error: { code: 'RESULT_TOO_LARGE', message: 'Encoded result exceeds the transport frame limit; effect may have completed' } };
    this.cacheBytes = [...this.journal.values()].reduce((total,data) => total + (data.response ? Buffer.byteLength(JSON.stringify(data.response)) : 0), 0);
    if (this.cacheBytes + Buffer.byteLength(JSON.stringify(record.response)) > this.config.policy.maxCacheBytes) record.response = {v:2,type:'result',taskId:task.taskId,status:'error',...(record.response.outcomeUnknown || (record.data.sideEffect && record.response.status === 'ok') ? {outcomeUnknown:true} : {}),error:{code:'RESULT_CACHE_FULL',message:'Result retention byte limit reached; inspect external state before a new operation'}};
    // Persist unknown before waiting for cleanup; cleanup is not a proof that effects did not happen.
    record.data.response = record.response; record.data.state = record.response.outcomeUnknown ? 'unknown' : record.data.background && jobIsActive(record.response.result?.state) ? 'running' : record.response.status === 'ok' ? 'completed' : 'failed'; record.data.updatedAt = Date.now();
    if (record.response.outcomeUnknown) { record.data.uncertainSideEffect = true; record.data.uncertaintyTaskId = record.response.uncertainty?.taskId ?? task.taskId; }
    if (record.response.result?.jobId) record.data.jobId = record.response.result.jobId;
    try { this.persist(this.journal, key, record.data); }
    catch (error) {
      // A bounded-capacity refusal is not an I/O failure. Retain a small terminal
      // response (or durable unknown for an effect), preserving the consumed ID.
      record.response = record.data.sideEffect || record.response.outcomeUnknown ? unknownResponse(task.taskId, 'Result could not fit durable retention; manual inspection required') : { v:2,type:'result',taskId:task.taskId,status:'error',error:errorData(error) };
      record.data = { ...record.data, response: record.response, state: record.response.outcomeUnknown ? 'unknown' : 'failed', events: [] };
      try { this.persist(this.journal, key, record.data); } catch { this.storageFailed = true; }
    }
    this.log('task_finished', { masterId, taskId: task.taskId, status: record.response.status, ...(record.response.error ? { error: record.response.error } : {}) });
    for (const watcher of record.watchers) sendFrame(watcher, record.response);
    record.watchers.clear();
    await tool.catch(() => {});
    record.data.executionSettled = true; record.data.updatedAt = Date.now();
    try { this.persist(this.journal, key, record.data); } catch { this.storageFailed = true; }
    this.active--; this.activeByMaster.set(masterId, this.activeByMaster.get(masterId) - 1);
  }
  async dispatch(peerId, task, { signal } = {}) {
    signal?.throwIfAborted();
    if (!this.agent) fail('AGENT_REQUIRED', 'This node has no planner/agent for outbound execution');
    if (this.stopping) fail('SHUTTING_DOWN', 'Node is stopping'); this.assertStorage();
    if (!isObject(task) || !taskIdValid(task.taskId) || (task.runId !== undefined && !taskIdValid(task.runId)) || !Number.isSafeInteger(task.timeoutMs) || task.timeoutMs < 10 || task.timeoutMs > MAX_TASK_TIMEOUT_MS) fail('INVALID_TASK', 'Invalid taskId, runId or timeoutMs');
    if (task.logicalWorkspaceId !== undefined) {
      if (!workspaceIdValid(task.logicalWorkspaceId) || task.workspaceId !== undefined || ['workspaceList','workspaceCreate'].includes(task.tool)) fail('INVALID_TASK', 'Choose one valid workspace selector; workspace management is unscoped');
      const binding = this.workspaceRegistry.binding(peerId, task.logicalWorkspaceId) ?? await this.ensureWorkspaceBinding(peerId, task.logicalWorkspaceId);
      signal?.throwIfAborted(); if (this.stopping) fail('SHUTTING_DOWN', 'Node is stopping');
      const {logicalWorkspaceId, ...routed} = task; task = {...routed,workspaceId:binding.workspaceId};
    }
    if (task.workspaceId !== undefined && (!workspaceIdValid(task.workspaceId) || ['workspaceList','workspaceCreate'].includes(task.tool))) fail('INVALID_TASK', 'Invalid workspace selector');
    const peer = this.peers.get(peerId);
    if (!peer) fail('UNKNOWN_PEER', 'No such outgoing relationship');
    if (!peer.connected) fail('PEER_UNAVAILABLE', 'Target is disconnected. No local execution fallback.');
    authenticateCertificate(peer.socket.getPeerCertificate(), this.config.security, peer.id);
    if (peer.pending.size >= 128) fail('BUSY', 'Outbound pending request limit reached');
    if (peer.pending.has(task.taskId)) fail('ALREADY_PENDING', 'This task is already awaiting a result');
    const key = `${peerId}:${task.taskId}`, previous = this.ledger.get(key), hash = fingerprint(task);
    if (!previous && this.ledger.get(`observation:${key}`)) fail('OUTCOME_UNKNOWN', 'This ID was learned through status only; use query, never redispatch an observed operation');
    if (this.ledger.retired(`observation:${key}`)) fail('TASK_HISTORY_EXPIRED', 'This observed operation ID was retired and can never be replayed');
    if (previous) {
      if (previous.fingerprint !== hash) return {peerId,taskId:task.taskId,status:'error',error:{code:'TASK_ID_CONFLICT',message:'This taskId already names a different request'}};
      let remote;
      try { remote = await this.query(peerId, task.taskId); }
      catch (error) { if (['MASTER_DENIED','TASK_POLICY_CHANGED'].includes(error.code)) return {peerId,taskId:task.taskId,status:'error',error:errorData(error)}; throw error; }
      if (remote.response) return {peerId,taskId:task.taskId,status:remote.response.status,...(remote.response.outcomeUnknown?{outcomeUnknown:true}:{}),...(remote.response.status === 'ok' ? {result:remote.response.result} : {error:remote.response.error})};
      // An explicit repeat of a proven read-only request may be sent after the
      // servant confirms it has no record. Unknown writes are never replayed.
      if (previous.sideEffect || remote.state !== 'not_found') fail('OUTCOME_UNKNOWN', 'Existing operation is unresolved; query/manual reconciliation required, never blind replay');
    }
    if (this.ledger.retired(key)) fail('TASK_HISTORY_EXPIRED', 'This operation ID was retired and can never be replayed');
    const sideEffect = isSideEffecting(task); // Unknown tool/provider permissions are treated conservatively.
    if (sideEffect) this.assertUncertainGate(this.ledger);
    if (encodeFrame({...task,v:2,type:'task'}) === null) fail('INVALID_TASK', 'Task exceeds transport frame size');
    const data = {peerId,taskId:task.taskId,...(task.workspaceId !== undefined ? {workspaceId:task.workspaceId} : {}),runId:task.runId ?? 'default',tool:task.tool,fingerprint:hash,sideEffect,background:task.tool==='exec'&&task.args?.background===true,state:'dispatching',createdAt:Date.now(),updatedAt:Date.now(),response:null,events:[],nextEvent:0};
    signal?.throwIfAborted();
    this.persist(this.ledger, key, data); // MUST complete before the network send.
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { peer.pending.delete(task.taskId); this.markOutboundUnknown(peerId,task.taskId); reject(new NodeError('OUTCOME_UNKNOWN', 'No result within transport deadline; query/reconcile, no automatic replay or fallback')); }, task.timeoutMs + 3500);
      peer.pending.set(task.taskId, { resolve, reject, timer });
      this.log('task_dispatched', { peerId, taskId: task.taskId, tool: task.tool });
      if (!sendFrame(peer.socket, { ...task, v: 2, type: 'task' })) { clearTimeout(timer); peer.pending.delete(task.taskId); this.markOutboundUnknown(peerId,task.taskId); reject(new NodeError('OUTCOME_UNKNOWN', 'Transport closed during dispatch; query/reconcile required')); }
    });
  }
  validateBindingTarget(peerId, logicalWorkspaceId) {
    if (!workspaceIdValid(peerId) || !workspaceIdValid(logicalWorkspaceId)) fail('INVALID_COMMAND', 'Workspace binding needs a valid peer and logical workspace ID');
    if (!this.peers.has(peerId)) fail('UNKNOWN_PEER', 'No such outgoing relationship');
  }
  async remoteWorkspaces(peerId) {
    const catalog={workspaces:[],creationRoots:[]};let offset=0;
    do {
      const response = await this.dispatch(peerId, {taskId:`wsl_${randomUUID().replaceAll('-','')}`,tool:'workspaceList',args:{offset,limit:32},timeoutMs:5000});
      if (response.status !== 'ok') fail(response.error.code,response.error.message);
      if(!Array.isArray(response.result?.workspaces)||!Array.isArray(response.result?.creationRoots))fail('INVALID_RESULT','Invalid remote workspace catalog');
      catalog.workspaces.push(...response.result.workspaces);catalog.creationRoots.push(...response.result.creationRoots);
      const next=response.result.nextOffset;if(next===null||next===undefined)break;
      if(!Number.isSafeInteger(next)||next<=offset||next>2048)fail('INVALID_RESULT','Invalid workspace catalog cursor');offset=next;
    } while(true);
    return catalog;
  }
  async bindWorkspace(command) {
    this.validateBindingTarget(command.peerId,command.logicalWorkspaceId);
    if (!workspaceIdValid(command.workspaceId)) fail('INVALID_COMMAND','Invalid remote workspace ID');
    const revision = command.expectedRevision ?? this.workspaceRegistry.state.revision; this.workspaceRegistry.assertRevision(revision);
    const catalog = await this.remoteWorkspaces(command.peerId);
    if (!catalog.workspaces.some(item=>item.id===command.workspaceId && item.state==='ready')) fail('WORKSPACE_DENIED','Workspace is not currently available to this peer');
    const binding = this.workspaceRegistry.bind(command.peerId,command.logicalWorkspaceId,command.workspaceId,revision);
    this.log('workspace_bound',{...binding}); return {...this.workspaceRegistry.snapshot(),binding};
  }
  async setWorkspaceAutoProvision(command) {
    this.validateBindingTarget(command.peerId,command.logicalWorkspaceId);
    if (!workspaceIdValid(command.rootId) || typeof command.enabled !== 'boolean') fail('INVALID_COMMAND','Choose an approved creation root and explicit enabled flag');
    const revision=command.expectedRevision ?? this.workspaceRegistry.state.revision; this.workspaceRegistry.assertRevision(revision);
    if (command.enabled) {
      const catalog=await this.remoteWorkspaces(command.peerId);
      if(!catalog.creationRoots.some(root=>root.id===command.rootId))fail('WORKSPACE_CREATE_DENIED','Creation root is not currently approved for this peer');
    }
    const result=this.workspaceRegistry.setAuto(command.peerId,command.logicalWorkspaceId,command.rootId,command.enabled,revision);
    this.log('workspace_auto_provision_changed',{peerId:command.peerId,logicalWorkspaceId:command.logicalWorkspaceId,rootId:command.rootId,enabled:command.enabled}); return result;
  }
  async createWorkspace(command) {
    if (!workspaceIdValid(command.peerId) || !this.peers.has(command.peerId)) fail('UNKNOWN_PEER','No such outgoing relationship');
    if (!workspaceIdValid(command.rootId) || !workspaceNameValid(command.name) || !creationIdValid(command.creationRequestId)) fail('INVALID_ARGS','Workspace creation needs approved rootId, safe name and stable creationRequestId');
    const revision=command.expectedRevision ?? this.workspaceRegistry.state.revision;
    if(command.logicalWorkspaceId!==undefined){this.validateBindingTarget(command.peerId,command.logicalWorkspaceId);this.workspaceRegistry.assertRevision(revision);}
    const taskId=`wsc_${workspaceHash({peerId:command.peerId,requestId:command.creationRequestId})}`;
    const response=await this.dispatch(command.peerId,{taskId,tool:'workspaceCreate',args:{rootId:command.rootId,name:command.name,requestId:command.creationRequestId},timeoutMs:5000});
    if(response.status!=='ok')fail(response.error.code,response.error.message);
    const workspace=response.result;
    const binding=command.logicalWorkspaceId===undefined ? undefined : this.workspaceRegistry.bind(command.peerId,command.logicalWorkspaceId,workspace.id,revision);
    this.log('remote_workspace_created',{peerId:command.peerId,workspaceId:workspace.id,rootId:command.rootId,...(binding?{logicalWorkspaceId:command.logicalWorkspaceId}:{})});
    return {workspace,...(binding?{binding}:{}),revision:this.workspaceRegistry.state.revision};
  }
  reconcileWorkspaceCreation(command) {
    const creation=this.workspaceRegistry.state.creations.find(item=>item.id===command.workspaceId && item.masterId===command.masterId);
    const tasks=creation ? [...this.journal.values()].filter(item=>item.masterId===creation.masterId && item.tool==='workspaceCreate' && item.workspaceRequest?.requestId===creation.requestId && item.state==='unknown') : [];
    if(tasks.some(item=>this.records.get(`${item.masterId}:${item.taskId}`)?.data.executionSettled===false))fail('RECONCILE_RUNNING','Wait for the creation task to settle before owner reconciliation');
    const result=this.workspaceRegistry.reconcile(command);
    for(const task of tasks) this.reconcile({masterId:task.masterId,taskId:task.taskId,resolution:command.resolution==='completed'?'completed':'not_applied',note:command.note,...(command.resolution==='completed'?{result:this.workspaceRegistry.completedRequest(task.masterId,task.workspaceRequest)}:{})});
    this.log('workspace_creation_reconciled',{workspaceId:command.workspaceId,masterId:command.masterId,resolution:command.resolution});
    return result;
  }
  async ensureWorkspaceBinding(peerId, logicalWorkspaceId) {
    this.validateBindingTarget(peerId,logicalWorkspaceId);
    const existing=this.workspaceRegistry.binding(peerId,logicalWorkspaceId); if(existing)return structuredClone(existing);
    const key=`${peerId}:${logicalWorkspaceId}`;
    if(this.workspaceEnsures.has(key))return this.workspaceEnsures.get(key);
    const operation=(async()=>{
      const rule=this.workspaceRegistry.rule(peerId,logicalWorkspaceId);
      if(!rule?.enabled)fail('WORKSPACE_BINDING_NOT_FOUND','No binding exists and automatic workspace creation is disabled; no default fallback');
      const ruleSnapshot=structuredClone(rule);
      const commitBinding=workspaceId=>{
        const current=this.workspaceRegistry.binding(peerId,logicalWorkspaceId); if(current)return structuredClone(current);
        if(workspaceHash(this.workspaceRegistry.rule(peerId,logicalWorkspaceId))!==workspaceHash(ruleSnapshot))fail('WORKSPACE_BINDING_CONFLICT','Automatic creation settings changed during provisioning; refresh before retrying');
        return this.workspaceRegistry.bind(peerId,logicalWorkspaceId,workspaceId);
      };
      const digest=workspaceHash({nodeId:this.config.id,peerId,logicalWorkspaceId,rootId:rule.rootId});
      const requestId=`auto_${digest}`, name=`w_${logicalWorkspaceId.slice(0,48)}_${digest.slice(0,10)}`;
      const catalog=await this.remoteWorkspaces(peerId);
      const found=catalog.workspaces.find(item=>item.requestId===requestId && item.rootId===rule.rootId && item.name===name && item.state==='ready');
      if(found){
        const taskId=`wsc_${workspaceHash({peerId,requestId})}`;
        if(this.ledger.get(`${peerId}:${taskId}`)?.state==='unknown')await this.query(peerId,taskId);
        return commitBinding(found.id);
      }
      const result=await this.createWorkspace({peerId,rootId:rule.rootId,name,creationRequestId:requestId});
      return commitBinding(result.workspace.id);
    })();
    this.workspaceEnsures.set(key,operation);
    try{return await operation;}finally{if(this.workspaceEnsures.get(key)===operation)this.workspaceEnsures.delete(key);}
  }
  async query(peerId, taskId) {
    if (!taskIdValid(taskId)) fail('INVALID_TASK','Invalid taskId');
    const peer = this.peers.get(peerId); if (!peer?.connected) fail('PEER_UNAVAILABLE','Target is disconnected');
    authenticateCertificate(peer.socket.getPeerCertificate(), this.config.security, peer.id);
    if (peer.requests.size >= 128) fail('BUSY','Too many status queries');
    const requestId = randomUUID();
    const result = await new Promise((resolve,reject) => {
      const timer = setTimeout(() => {peer.requests.delete(requestId); reject(new NodeError('PEER_UNAVAILABLE','Status query timed out'));},3500);
      peer.requests.set(requestId,{resolve,reject,timer});
      if (!sendFrame(peer.socket,{v:2,type:'query',requestId,taskId})) {clearTimeout(timer);peer.requests.delete(requestId);reject(new NodeError('PEER_UNAVAILABLE','Could not send query'));}
    });
    const key = `${peerId}:${taskId}`, observationKey = `observation:${peerId}:${taskId}`;
    const operationKey = this.ledger.get(key) ? key : observationKey, operation = this.ledger.get(operationKey);
    if (result.response) {
      if (hasUnknownOutcome(result.response) || result.state === 'unknown') {
        // A clean/restarted master can learn uncertainty through a query alone.
        // This separate namespace records evidence, never permission to replay.
        try { this.persist(this.ledger,operationKey,{...(operation??{peerId,taskId,tool:result.tool,sideEffect:false,observationOnly:true,createdAt:Date.now()}),state:'unknown',uncertainSideEffect:true,uncertaintyTaskId:result.uncertaintyTaskId??result.response.uncertainty?.taskId??taskId,updatedAt:Date.now(),response:{peerId,...result.response,outcomeUnknown:true}}); }
        catch (error) { this.storageFailed = true; throw error; } // Never allow new effects after losing uncertainty evidence.
      }
      else if (terminal(result)) {
        if (operation) this.persist(this.ledger,operationKey,{...operation,state:result.state,uncertainSideEffect:false,updatedAt:Date.now(),response:{peerId,...result.response}});
        // One owner-reconciled source can be observed through a denied write or
        // jobStatus task. Clear only observations tied to this exact peer/task.
        for (const [observedKey, observed] of this.ledger.records) if (observedKey !== key && observed.peerId === peerId && observed.state === 'unknown' && observed.uncertaintyTaskId === taskId) {
          const response = { peerId, taskId: observed.taskId, status: 'error', error: { code: 'UNCERTAINTY_RESOLVED', message: 'The referenced operation was resolved; this observation ID remains consumed' } };
          this.persist(this.ledger,observedKey,{...observed,state:'reconciled',uncertainSideEffect:false,updatedAt:Date.now(),response});
        }
      }
    }
    return result;
  }
  cancel(peerId, taskId) {
    if (!this.agent) fail('AGENT_REQUIRED', 'Outbound cancellation requires an agent');
    const peer = this.peers.get(peerId); if (!peer?.connected) fail('PEER_UNAVAILABLE', 'Target is disconnected');
    if (!taskIdValid(taskId)) fail('INVALID_TASK', 'Invalid taskId');
    authenticateCertificate(peer.socket.getPeerCertificate(), this.config.security, peer.id);
    if (!sendFrame(peer.socket, { v: 2, type: 'cancel', taskId })) fail('OUTCOME_UNKNOWN', 'Cancel could not be confirmed');
    return { requested: true, taskId };
  }
  reconcile(command) {
    if (!['completed','not_applied'].includes(command.resolution) || typeof command.note !== 'string' || command.note.trim().length < 3 || command.note.length > 1000) fail('INVALID_COMMAND','Reconciliation requires completed/not_applied plus an operator evidence note (3..1000 characters)');
    if (command.jobId) return this.jobManager.reconcileJob(command);
    const incoming = command.masterId !== undefined, owner = incoming ? command.masterId : command.peerId;
    if (!validId(owner) || !taskIdValid(command.taskId)) fail('INVALID_COMMAND','Invalid reconciliation target');
    const store = incoming ? this.journal : this.ledger, sourceKey = `${owner}:${command.taskId}`;
    const key = !incoming && !store.get(sourceKey) && store.get(`observation:${sourceKey}`) ? `observation:${sourceKey}` : sourceKey, record = store.get(key);
    if (incoming && ((this.records.get(key) && record?.executionSettled === false) || (record?.jobId && jobIsActive(this.jobManager.jobs.get(record.jobId)?.state)))) fail('RECONCILE_RUNNING','Wait for the underlying task and job to settle before reconciliation');
    if (!record || record.state !== 'unknown') fail('RECONCILE_DENIED','Only an existing unknown operation can be reconciled');
    const response = command.resolution === 'completed' ? {v:2,type:'result',taskId:command.taskId,status:'ok',result:command.result ?? {manuallyReconciled:true}} : {v:2,type:'result',taskId:command.taskId,status:'error',error:{code:'RECONCILED_NOT_APPLIED',message:'Operator verified effect was not applied; this ID remains permanently consumed'}};
    if (encodeFrame(response) === null) fail('RESULT_TOO_LARGE','Reconciled result exceeds frame limit');
    this.persist(store,key,{...record,state:'reconciled',uncertainSideEffect:false,response,updatedAt:Date.now(),reconciliation:{resolution:command.resolution,note:command.note,at:Date.now()}});
    if (incoming && this.records.has(key)) { this.records.get(key).data = structuredClone(store.get(key)); this.records.get(key).response = response; }
    for (const [observedKey, observed] of store.records) if (observedKey !== key && observed.state === 'unknown' && observed.uncertaintyTaskId === command.taskId && (incoming ? observed.masterId === owner : observed.peerId === owner)) {
      const resolved = {v:2,type:'result',taskId:observed.taskId,status:'error',error:{code:'UNCERTAINTY_RESOLVED',message:'Owner resolved the referenced operation; this observation ID remains consumed'}};
      this.persist(store,observedKey,{...observed,state:'reconciled',uncertainSideEffect:false,response:resolved,updatedAt:Date.now()});
    }
    this.log('task_reconciled',{taskId:command.taskId,masterId:command.masterId,peerId:command.peerId,resolution:command.resolution});
    return publicRecord(store.get(key));
  }
  mutatePolicy(operation) {
    const next=(this.policyMutation ?? Promise.resolve()).catch(()=>{}).then(operation);this.policyMutation=next;return next;
  }
  async setPolicy(raw, expectedEpoch) {
    return this.mutatePolicy(async()=>{
    if (expectedEpoch !== undefined && expectedEpoch !== this.policyEpoch) fail('POLICY_CONFLICT','Permissions changed; refresh before saving');
    const policy = await loadPolicy(raw, path.dirname(this.config.filename));
    validatePolicyIsolation(policy,this.config);
    if ([...policy.allowedMasters].some(id => !this.config.security.trustedPeers.has(id))) fail('INVALID_CONFIG','New relationship requires an already pinned identity');
    const limits = { maxRecords: policy.maxTaskRecords, maxBytes: policy.maxJournalBytes };
    // Preflight both stores before committing any control/config state. These
    // synchronous checks and assignments cannot interleave with task mutation.
    this.journal.assertLimits(limits); this.ledger.assertLimits(limits);
    const control = {...this.control,policyRaw:raw,policyEpoch:this.policyEpoch+1,revoked:[]};
    this.persistControl(control); this.control=control; this.policyEpoch=control.policyEpoch; this.config.policy=policy;
    this.journal.configure(limits); this.ledger.configure(limits); this.jobManager.maxConcurrent=policy.maxConcurrent;
    for (const record of this.records.values()) if (!record.response) record.controller.abort(new NodeError('POLICY_REVOKED','Local policy was reloaded'));
    await this.jobManager.cancelAll(new NodeError('POLICY_REVOKED','Local policy was reloaded'));
    this.log('policy_reloaded',{epoch:this.policyEpoch,masters:[...policy.allowedMasters]}); return {epoch:this.policyEpoch};
    });
  }
  async command(command) {
    if (!isObject(command)) fail('INVALID_COMMAND', 'Expected a JSON object');
    switch (command.command) {
      case 'listWorkspaceBindings': return this.workspaceRegistry.snapshot();
      case 'remoteWorkspaces': return this.remoteWorkspaces(command.peerId);
      case 'bindWorkspace': return this.bindWorkspace(command);
      case 'unbindWorkspace': this.validateBindingTarget(command.peerId, command.logicalWorkspaceId); return this.workspaceRegistry.unbind(command.peerId, command.logicalWorkspaceId, command.expectedRevision);
      case 'setWorkspaceAutoProvision': return this.setWorkspaceAutoProvision(command);
      case 'ensureWorkspaceBinding': return this.ensureWorkspaceBinding(command.peerId, command.logicalWorkspaceId);
      case 'createWorkspace': return this.createWorkspace(command);
      case 'reconcileWorkspaceCreation': return this.reconcileWorkspaceCreation(command);
      case 'status': return { id:this.config.id,port:this.server.address()?.port,agent:this.agent?.name ?? null,peers:[...this.peers.values()].map(p=>({id:p.id,connected:p.connected})),active:this.active,taskRecords:this.journal?.records.size ?? 0,transport:'TLSv1.3-mTLS-pinned',certificateFingerprint:this.config.security.fingerprint256,policyEpoch:this.policyEpoch,durable:true,cacheBytes:this.cacheBytes,storageFailed:this.storageFailed,incoming:this.journal?.info(),outgoing:this.ledger?.info(),unknownIncoming:[...(this.journal?.values() ?? [])].filter(r=>r.state==='unknown').length,unknownOutgoing:[...(this.ledger?.values() ?? [])].filter(r=>r.state==='unknown').length };
      case 'permissions': { const effectivePolicy=structuredClone(this.control.policyRaw);effectivePolicy.grants=Object.fromEntries(Object.entries(effectivePolicy.grants??{}).filter(([id])=>!this.control.revoked.includes(id)));return {epoch:this.policyEpoch,revoked:[...this.control.revoked],policy:structuredClone(this.control.policyRaw),effectivePolicy,grants:structuredClone(effectivePolicy.grants),directoryPolicies:Object.fromEntries([...this.config.policy.grants].map(([id,grant])=>[id,directoryPolicySummary(grant)]))}; }
      case 'listTasks': {
        const store = command.kind === 'outgoing' ? this.ledger : this.journal;
        const limit = command.limit ?? 100; if (!Number.isInteger(limit)||limit<1||limit>200) fail('INVALID_COMMAND','limit must be 1..200');
        return {records:[...store.values()].sort((a,b)=>b.updatedAt-a.updatedAt).slice(0,limit).map(publicRecord),retiredCount:store.retiredCount};
      }
      case 'taskStatus': { if (!validId(command.masterId)||!taskIdValid(command.taskId)) fail('INVALID_COMMAND','Invalid task target'); return publicRecord(this.journal.get(`${command.masterId}:${command.taskId}`)) ?? {state:this.journal.retired(`${command.masterId}:${command.taskId}`)?'expired':'not_found'}; }
      case 'taskEvents': {
        if (!validId(command.masterId)||!taskIdValid(command.taskId)||!Number.isSafeInteger(command.after??0)||(command.after??0)<0) fail('INVALID_COMMAND','Invalid event target/cursor');
        const record=this.journal.get(`${command.masterId}:${command.taskId}`); if(!record) return {events:[],next:0,state:'not_found'};
        return {events:(record.events??[]).filter(e=>e.seq>(command.after??0)),next:record.nextEvent??0,truncated:(record.events?.[0]?.seq??1)>(command.after??0)+1,state:record.state};
      }
      case 'operationStatus': { if(!validId(command.peerId)||!taskIdValid(command.taskId)) fail('INVALID_COMMAND','Invalid operation target');return publicRecord(this.ledger.get(`${command.peerId}:${command.taskId}`)??this.ledger.get(`observation:${command.peerId}:${command.taskId}`))??{state:this.ledger.retired(`${command.peerId}:${command.taskId}`)||this.ledger.retired(`observation:${command.peerId}:${command.taskId}`)?'expired':'not_found'}; }
      case 'query': return this.query(command.peerId,command.taskId);
      case 'reconcile': return this.reconcile(command);
      case 'setPolicy': return this.setPolicy(command.policy,command.expectedEpoch);
      case 'agent': { if (!this.agent?.run) fail('AGENT_REQUIRED','A Pi agent must be configured'); return this.agent.run({prompt:command.prompt,scenario:command.scenario,runId:command.runId,promptResource:command.promptResource,logicalWorkspaceId:command.logicalWorkspaceId,workspaceId:command.workspaceId}); }
      case 'cancel': return this.cancel(command.peerId,command.taskId);
      case 'cancelTask': {
        if(!validId(command.masterId)||!taskIdValid(command.taskId))fail('INVALID_COMMAND','Invalid incoming task target');
        const record=this.records.get(`${command.masterId}:${command.taskId}`);const accepted=!!record&&!record.response;
        if(accepted)record.controller.abort(new NodeError('CANCELLED','Local owner cancelled the task'));
        return{requested:accepted,taskId:command.taskId};
      }
      case 'listJobs': return {jobs:[...this.jobManager.jobs.values()].map(job=>this.jobManager.status(job.masterId,job.jobId))};
      case 'jobStatus': return this.jobManager.status(command.masterId,command.jobId);
      case 'jobOutput': return this.jobManager.output(command.masterId,command,{maxOutputPageBytes:16384});
      case 'jobCancel': return this.jobManager.cancel(command.masterId,command.jobId);
      case 'reconcileJob': return this.reconcile(command);
      case 'revoke': return this.mutatePolicy(async()=>{
        if(!validId(command.masterId)) fail('INVALID_COMMAND','Invalid masterId');
        const control={...this.control,policyEpoch:this.policyEpoch+1,revoked:[...new Set([...this.control.revoked,command.masterId])]};
        this.persistControl(control);this.control=control;this.policyEpoch=control.policyEpoch;
        this.config.policy.grants.delete(command.masterId);this.config.policy.allowedMasters.delete(command.masterId);this.recomputeTools();
        for(const record of this.records.values()) if(record.masterId===command.masterId&&!record.response)record.controller.abort(new NodeError('POLICY_REVOKED','Local permissions were revoked'));
        await this.jobManager.cancelMaster(command.masterId,new NodeError('POLICY_REVOKED','Local permissions were revoked'));
        this.log('policy_revoked',{masterId:command.masterId});return{revoked:command.masterId,epoch:this.policyEpoch};
      });
      case 'reloadPolicy': { const raw=JSON.parse(await fs.readFile(this.config.filename,'utf8'));return this.setPolicy(raw.policy??{}); }
      case 'dispatch': return this.dispatch(command.peerId,command.task);
      case 'plan': {
        if(!this.agent?.plan)fail('AGENT_REQUIRED','A deterministic planner is not configured; Pi uses the agent command');
        const prefix=randomUUID().replaceAll('-','');const proposals=await this.agent.plan(command,{peers:[...this.peers.keys()],prefix});
        this.log('agent_plan',{agent:this.agent.name,goal:command.goal,tasks:proposals.map(p=>({peerId:p.peerId,taskId:p.task.taskId,tool:p.task.tool}))});
        return Promise.all(proposals.map(async proposal=>{try{return await this.dispatch(proposal.peerId,proposal.task);}catch(error){return{peerId:proposal.peerId,taskId:proposal.task.taskId,status:'error',error:errorData(error)};}}));
      }
      case 'fault': {
        if(!this.config.faultInjection)fail('FAULTS_DISABLED','Fault injection must be enabled locally at startup');
        if(command.latencyMs!==undefined){if(!Number.isSafeInteger(command.latencyMs)||command.latencyMs<0||command.latencyMs>2000)fail('INVALID_COMMAND','latencyMs must be 0..2000');this.latencyMs=command.latencyMs;}
        if(command.cutOutbound===true)for(const peer of this.peers.values())peer.socket?.destroy();if(command.cutInbound===true)for(const socket of this.inbound)socket.destroy();
        this.log('fault_injected',{latencyMs:this.latencyMs,cutOutbound:command.cutOutbound===true,cutInbound:command.cutInbound===true});return{latencyMs:this.latencyMs};
      }
      case 'shutdown': await this.shutdown();return{stopped:true};
      default: fail('INVALID_COMMAND','Unknown local operator command');
    }
  }
  async shutdown() {
    if(this.shutdownPromise)return this.shutdownPromise;
    this.shutdownPromise=(async()=>{
      this.stopping=true;clearInterval(this.heartbeat);
      await this.agent?.dispose?.();
      for(const peer of this.peers.values()){clearTimeout(peer.retry);peer.socket?.destroy();}
      for(const record of this.records.values())if(!record.response)record.controller.abort(new NodeError('SHUTTING_DOWN','Node is stopping'));
      for(const socket of this.inbound)socket.destroy();for(const socket of this.rawSockets)socket.destroy();
      if(this.server.listening)await new Promise(resolve=>this.server.close(resolve));
      await this.jobManager?.shutdown();await Promise.allSettled([...this.executions]);
      await this.operator?.close?.();this.releaseStateLock?.();this.releaseStateLock=null;this.log('node_stopped');
    })();return this.shutdownPromise;
  }
}

// Compatibility export for callers using the pre-rename runtime API.
export { IntelligentCell as UnifiedNode };
