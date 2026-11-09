'use strict';

// Pure helpers are also exercised by Node tests without opening a browser.
export const FILE_TOOLS = ['readFile', 'readChunk', 'listDirectory', 'searchFiles', 'writeFile', 'writeChunk', 'editFile', 'mkdir'];
export const PROCESS_TOOLS = ['exec', 'mcpList', 'mcpCall'];
const MANAGED_FIELDS = ['tools', 'workspace', 'root', 'maxConcurrent', 'maxTimeoutMs', 'execCommands', 'directories', 'allowUnsandboxedProcesses', 'workspaces', 'workspaceProvisioning'];
const ACTIVE_STATES = ['running', 'starting', 'received', 'accepted', 'queued', 'sent', 'dispatching', 'pending'];
export const TOOL_GROUPS = [
  ['Read files', [['readFile', 'Read file'], ['readChunk', 'Read chunk'], ['listDirectory', 'List directory'], ['searchFiles', 'Search files']]],
  ['Modify files', [['writeFile', 'Write file'], ['writeChunk', 'Write chunk'], ['editFile', 'Exact edit'], ['mkdir', 'Create directory']]],
  ['Trusted processes (outside the directory sandbox)', [['exec', 'Run approved command'], ['mcpList', 'List MCP Tool'], ['mcpCall', 'Call MCP Tool']]],
  ['Job management', [['jobStatus', 'Read job status'], ['jobOutput', 'Read job output'], ['jobCancel', 'Cancel job'], ['jobStdin', 'Write process input']]],
  ['Workspace management', [['workspaceList', 'Publish workspaces and creation roots'], ['workspaceCreate', 'Allow workspace creation']]],
  ['Resources and capabilities', [['resourceList', 'List approved resources'], ['resourceRead', 'Read approved resource'], ['capabilities', 'Show granted capabilities'], ['echo', 'Echo test'], ['wait', 'Wait test']]],
];
const TOOL_LABELS = Object.fromEntries(TOOL_GROUPS.flatMap(([, items]) => items));
const STATES = { ready: 'Available', unavailable: 'Unavailable', intent: 'Creation intent pending verification', created: 'Created; verification pending', unknown: 'Needs reconciliation', dispatching: 'Dispatching', pending: 'Pending', running: 'Running', starting: 'Starting', received: 'Received', accepted: 'Accepted', queued: 'Queued', sent: 'Sent', completed: 'Completed', succeeded: 'Succeeded', failed: 'Failed', error: 'Error', cancelled: 'Cancelled', timed_out: 'Timed out', reconciled: 'Reconciled', not_found: 'Not found', expired: 'Record expired', rejected: 'Rejected', not_applied: 'Confirmed not applied' };
export function stateLabel(value) { return STATES[value] ?? value ?? 'Unknown status'; }
export function effectivePolicy(state) {
  const permissions = state?.permissions;
  const result = structuredClone(permissions?.effectivePolicy ?? permissions?.policy ?? { grants: permissions?.grants ?? {} });
  result.grants ??= {};
  for (const id of permissions?.revoked ?? []) delete result.grants[id];
  return result;
}
export function validRelativePath(value, rootAllowed = false) {
  if (value === '') return rootAllowed;
  return typeof value === 'string' && new TextEncoder().encode(value).length <= 500 && !/[\\:\x00-\x1f\x7f]/u.test(value) && !value.startsWith('/') && !value.split('/').some(part => !part || part === '.' || part === '..' || /[. ]$/u.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(part));
}
export function validateDirectories(rules) {
  if (!Array.isArray(rules) || rules.length > 128) throw new Error('At most 128 directory rules are allowed');
  const seen = new Set();
  return rules.map(rule => {
    if (!validRelativePath(rule.path, true)) throw new Error('Use a normalized relative directory; leave blank for the root. Do not use .., backslashes, or absolute paths');
    if (seen.has(rule.path)) throw new Error(`Duplicate directory rule: ${rule.path || 'Workspace root'}`);
    if (typeof rule.read !== 'boolean' || typeof rule.write !== 'boolean') throw new Error('Each directory rule must explicitly specify read and write access');
    seen.add(rule.path); return { path: rule.path, read: rule.read, write: rule.write };
  });
}
export function fileAccess(grant, tool, name) {
  if (!FILE_TOOLS.includes(tool)) return { allowed: false, reason: 'Select a built-in file tool' };
  const directory = ['listDirectory', 'searchFiles', 'mkdir'].includes(tool);
  if (!validRelativePath(name, ['listDirectory', 'searchFiles'].includes(tool))) return { allowed: false, reason: 'Invalid path; use a normalized path relative to the workspace' };
  if (!(grant?.tools ?? []).includes(tool)) return { allowed: false, reason: `Not granted: ${TOOL_LABELS[tool]} (${tool})` };
  if (!grant.workspace && !grant.root) return { allowed: false, reason: 'No controlled workspace configured' };
  const target = directory ? name : (name.includes('/') ? name.slice(0, name.lastIndexOf('/')) : '');
  const rules = grant.directories;
  if (rules === undefined) return { allowed: true, reason: 'Whole workspace; tool granted without directory rules', mode: 'workspace' };
  const rule = [...rules].filter(r => r.path === '' || target === r.path || target.startsWith(`${r.path}/`)).sort((a, b) => b.path.length - a.path.length)[0];
  if (!rule) return { allowed: false, reason: 'No matching directory rule; denied by default', mode: 'scoped' };
  const read = ['readFile', 'readChunk', 'listDirectory', 'searchFiles', 'editFile'].includes(tool);
  const write = ['writeFile', 'writeChunk', 'editFile', 'mkdir'].includes(tool);
  const allowed = (!read || rule.read) && (!write || rule.write);
  return { allowed, reason: `Matched "${rule.path || 'Workspace root'}": ${scopeLabel(rule)}${tool === 'editFile' ? '; exact edits require both read and write access' : ''}`, rule, mode: 'scoped' };
}
export function scopeLabel(rule) { return rule.read ? (rule.write ? 'Read and write' : 'Read only') : (rule.write ? 'Write only' : 'No read or write'); }
export function parseObject(text, label) {
  let value; try { value = JSON.parse(text); } catch { throw new Error(`${label} is not valid JSON`); }
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error(`${label} must be a JSON object`);
  return value;
}
export function buildGrant(existing, fields) {
  const extra = parseObject(fields.extra, 'Additional grant fields');
  if (Object.keys(extra).some(key => MANAGED_FIELDS.includes(key))) throw new Error('Advanced fields cannot redefine tools, workspace, directory rules, basic limits, or process approval; use the form above');
  const grant = { ...structuredClone(existing ?? {}), ...extra, tools: [...fields.tools], maxConcurrent: fields.maxConcurrent, maxTimeoutMs: fields.maxTimeoutMs, execCommands: parseObject(fields.commands, 'Approved command aliases') };
  delete grant.root;
  if (fields.workspace && fields.mode !== 'none') grant.workspace = fields.workspace; else delete grant.workspace;
  if (!Number.isInteger(grant.maxConcurrent) || grant.maxConcurrent < 1 || grant.maxConcurrent > 32) throw new Error('Maximum concurrent tasks must be an integer from 1 to 32');
  if (!Number.isInteger(grant.maxTimeoutMs) || grant.maxTimeoutMs < 10 || grant.maxTimeoutMs > 86400000) throw new Error('Maximum timeout must be an integer from 10 to 86400000 milliseconds');
  if (fields.mode === 'scoped') {
    if (!grant.workspace) throw new Error('Directory restrictions require a local controlled workspace');
    grant.directories = validateDirectories(fields.directories);
    grant.allowUnsandboxedProcesses = fields.allowUnsandboxed === true;
    if (grant.tools.some(tool => PROCESS_TOOLS.includes(tool)) && !grant.allowUnsandboxedProcesses) throw new Error('exec / MCP can access paths outside directory rules; explicitly approve unsandboxed processes first');
  } else {
    delete grant.directories; delete grant.allowUnsandboxedProcesses;
  }
  if (grant.tools.some(tool => FILE_TOOLS.includes(tool) || ['exec', 'mcpList', 'mcpCall', 'resourceRead', 'resourceList'].includes(tool)) && !grant.workspace) throw new Error('The selected file, resource, or execution tools require a controlled workspace');
  return grant;
}
export function filterRecords(items, filter = 'all', search = '') {
  const query = search.trim().toLocaleLowerCase();
  return items.filter(item => (filter === 'all' || (filter === 'unknown' ? item.state === 'unknown' : filter === 'active' ? ACTIVE_STATES.includes(item.state) : !ACTIVE_STATES.includes(item.state) && item.state !== 'unknown')) && [item.taskId, item.id, item.peerId, item.masterId, item.peer, item.tool].some(value => String(value ?? '').toLocaleLowerCase().includes(query)));
}
export function taskCommand({ direction, action, peer, taskId, resolution, note }) {
  const incoming = direction === 'incoming';
  if (!['incoming', 'outgoing'].includes(direction)) throw new Error('Select a valid task direction');
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(peer) || !/^[a-zA-Z0-9_-]{1,100}$/.test(taskId)) throw new Error('Enter valid peer and task ID');
  if (action === 'events' && !incoming) throw new Error('Event queries are only available for incoming tasks');
  if (action === 'query' && incoming) throw new Error('Remote queries are only available for outgoing tasks');
  const command = { status: incoming ? 'taskStatus' : 'operationStatus', events: 'taskEvents', query: 'query', cancel: incoming ? 'cancelTask' : 'cancel', reconcile: 'reconcile' }[action];
  if (!command) throw new Error('Select a valid task action');
  const value = { command, [incoming ? 'masterId' : 'peerId']: peer, taskId };
  if (action === 'reconcile') { if (!note?.trim()) throw new Error('Reconciliation requires independent external evidence'); if (!['completed', 'not_applied'].includes(resolution)) throw new Error('Select a valid reconciliation outcome'); value.resolution = resolution; value.note = note.trim(); }
  return value;
}

const $ = id => document.getElementById(id);
let csrf = null, state = null, busy = false, stopped = false, online = false, expiresAt = null, currentView = 'overview';
let workspaceCatalog = null; const pendingCreations = new Map();
let editor = { peerId: null, epoch: null, dirty: false }, editorInitialized = false, directorySerial = 0, logs = [], jobPage = null;
const headings = { overview: 'Node overview', workspaces: 'Workspace mappings', tasks: 'Tasks and reconciliation', permissions: 'Directories and permissions', identity: 'Identity and pairing', logs: 'Audit log' };
const ERRORS = { UNAUTHENTICATED: 'Session expired or token invalid; authenticate the local owner again', POLICY_CONFLICT: 'Policy version changed; draft preserved. Discard the draft and reload before editing', DIRECTORY_DENIED: 'This directory lacks the required read or write permission', TASK_POLICY_CHANGED: 'Permissions changed; previous task/job results require local owner review', CSRF_DENIED: 'Session verification failed; sign out and authenticate again', RATE_LIMITED: 'Too many attempts; try again later' };
function notice(message, error = false) { $('notice').hidden = false; $('notice').textContent = message; $('notice').className = `notice${error ? ' error' : ''}`; $('notice').setAttribute('role', error ? 'alert' : 'status'); }
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function empty(container, text) { container.replaceChildren(el('div', text, 'empty')); }
function rowContent(id, detail) { const div = el('div'); div.append(el('strong', id), el('small', detail)); return div; }
function statusPill(value) { return el('span', stateLabel(value), `pill ${Object.hasOwn(STATES, value) ? value : 'off'}`); }
function fillDl(root, entries) { root.replaceChildren(); for (const [key, value] of entries) root.append(el('dt', key), el('dd', String(value ?? '—'))); }
function formatTime(value) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('en-GB', { hour12: false }); }
function epoch() { return state?.permissions?.epoch ?? state?.status?.policyEpoch ?? 0; }
function records(kind) { const value = state?.[kind]; return value?.records ?? (Array.isArray(value) ? value : []); }
function policy() { return effectivePolicy(state); }
function selectedTools() { return [...document.querySelectorAll('[name=tool]:checked')].map(input => input.value); }
function syncButtons() {
  document.querySelectorAll('button').forEach(button => { button.disabled = busy; });
  if (busy) return;
  $('refresh').disabled = !csrf || stopped;
  document.querySelectorAll('#workspace button').forEach(button => { if (!csrf || stopped) button.disabled = true; });
  $('save-grant').disabled = !csrf || stopped || !online || (editor.epoch !== null && editor.epoch !== epoch());
  $('revoke-grant').disabled = !csrf || stopped || !online || !editor.peerId || !policy().grants[editor.peerId];
  $('job-next-page').disabled = !csrf || stopped || !jobPage || jobPage.eof || !jobPageMatches();
  for (const id of ['save-auto', 'ensure-workspace', 'bind-workspace', 'create-workspace']) $(id).disabled = !csrf || stopped || !online || !bindingRevisionMatches();
  $('bind-workspace').disabled ||= !$('existing-workspace').value;
  $('create-workspace').disabled ||= !$('create-root').value;
  $('save-auto').disabled ||= !$('auto-root').value;
  $('load-workspaces').disabled = !csrf || stopped || !$('workspace-peer').value;
  $('permission-check').querySelector('button').disabled = !csrf || stopped || !$('check-peer').value;
}
async function api(route, value) {
  let response;
  try { response = await fetch(route, { credentials: 'same-origin', cache: 'no-store', ...(value !== undefined ? { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Operator-CSRF': csrf ?? '' }, body: JSON.stringify(value) } : {}) }); }
  catch { online = false; $('connection').textContent = 'Disconnected · Status may be stale'; $('connection').className = 'pill off'; throw new Error(value !== undefined && route === '/api/command' ? 'Request outcome unconfirmed. Refresh and check status before retrying any operation with side effects' : 'Cannot connect to the local node; check that the process is running'); }
  let data; try { data = await response.json(); } catch { throw new Error('Unreadable node response; refresh to verify status'); }
  if (!response.ok || data.ok === false) { const code = data.error?.code; if (code === 'UNAUTHENTICATED') lock(); throw new Error(`${ERRORS[code] ?? data.error?.message ?? 'Request failed'} (${code ?? response.status})`); }
  return data;
}
async function command(value) { if (!csrf || stopped) throw new Error('Authenticate the running local node first'); return (await api('/api/command', value)).result; }
function lock() {
  csrf = null; state = null; online = false; workspaceCatalog = null; pendingCreations.clear(); logs = []; jobPage = null; editorInitialized = false; editor = { peerId: null, epoch: null, dirty: false };
  $('login').hidden = false; $('workspace').hidden = true; $('logout').hidden = true; $('owner-token').value = '';
  $('connection').textContent = 'Not authenticated'; $('connection').className = 'pill off'; $('node-context').textContent = 'Authenticate the local owner first';
  document.querySelectorAll('#workspace form').forEach(form => form.reset());
  for (const id of ['local-workspace-creations', 'owner-workspaces', 'owner-creation-roots', 'workspace-bindings', 'workspace-auto-rules', 'catalog-summary', 'auto-root-summary', 'workspace-result', 'policy-json', 'grant-list', 'directory-rules', 'grant-preview', 'peers', 'incoming-peers', 'runtime', 'task-rows', 'job-rows', 'task-result', 'job-result', 'task-result-summary', 'job-result-summary', 'job-output-text', 'job-output-meta', 'recovery-list', 'identity-summary', 'trusted-peers', 'pair-result', 'pair-result-summary', 'pairing-requests', 'pairing-listener', 'logs-output', 'log-rows', 'check-result']) $(id).replaceChildren();
  $('workspace-catalog').hidden = true; $('workspace-result').hidden = true; $('check-result').hidden = true; $('job-output-panel').hidden = true; $('notice').hidden = true;
  syncButtons();
}
function unlock(data) { csrf = data.csrf; expiresAt = data.expiresAt; stopped = false; $('login').hidden = true; $('workspace').hidden = false; $('logout').hidden = false; }
async function guarded(fn) {
  if (busy) return;
  busy = true; document.body.setAttribute('aria-busy', 'true'); syncButtons();
  try { await fn(); } catch (error) { notice(error.message, true); }
  finally { busy = false; document.body.setAttribute('aria-busy', 'false'); syncButtons(); }
}
async function refresh() {
  if (!csrf || stopped) return;
  state = await api('/api/state'); online = true;
  $('connection').textContent = 'Local owner authenticated'; $('connection').className = 'pill';
  if (!editorInitialized) resetGrant(false);
  render(); if (currentView === 'identity') await loadPairing(); $('last-updated').textContent = `Last updated ${formatTime(Date.now())}`;
  $('session-expiry').textContent = expiresAt ? `Session expires ${formatTime(expiresAt)}` : '';
}
function changeView(view, focus = true) {
  if (!Object.hasOwn(headings, view)) return;
  currentView = view;
  document.querySelectorAll('[data-view]').forEach(button => { const selected = button.dataset.view === view; button.classList.toggle('selected', selected); if (selected) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current'); });
  document.querySelectorAll('[data-panel]').forEach(panel => { panel.hidden = panel.dataset.panel !== view; });
  $('breadcrumb').textContent = headings[view]; $('view-title').textContent = headings[view];
  if (focus) $('view-title').focus({ preventScroll: true });
}
function render() {
  const status = state.status, p = policy(), trusted = new Set((state.identity?.trustedPeers ?? []).map(peer => peer.id));
  $('node-id').textContent = nodeLabel(status.id, status.name); $('node-agent').textContent = 'Resident node · Peer relationships managed independently';
  $('node-context').textContent = `${status.id} · Local administration · Policy version ${epoch()}`;
  $('peer-count').textContent = `${(status.peers ?? []).filter(peer => peer.connected).length} / ${(status.peers ?? []).length}`;
  $('active-count').textContent = status.active ?? 0;
  const unknown = (status.unknownIncoming ?? records('incoming').filter(r => r.state === 'unknown').length) + (status.unknownOutgoing ?? records('outgoing').filter(r => r.state === 'unknown').length) + (state.jobs?.jobs ?? []).filter(job => job.state === 'unknown').length + (state.workspaces?.creations ?? []).filter(item => item.state === 'unknown').length;
  $('unknown-count').textContent = unknown; $('nav-unknown').textContent = unknown; $('nav-unknown').hidden = !unknown;
  $('health-warning').hidden = !status.storageFailed; $('health-warning').textContent = 'Persistent storage failure: check the local disk and logs. Missing records do not prove that an operation did not run';
  $('peers').replaceChildren();
  for (const peer of status.peers ?? []) { const row = el('div', undefined, 'peer-row'); row.append(rowContent(`${nodeLabel(status.id, status.name)} → ${nodeLabel(peer.id, peer.name)}`, 'Inspect remote directory and tool permissions on the peer console'), el('span', peer.connected ? 'Connected' : 'Disconnected', `pill${peer.connected ? '' : ' off'}`)); $('peers').append(row); }
  if (!status.peers?.length) empty($('peers'), 'No outbound relationships configured; this node can still receive authorized work');
  $('incoming-peers').replaceChildren();
  for (const [id, grant] of Object.entries(p.grants)) { const row = el('div', undefined, 'peer-row'); row.append(rowContent(`${id} → ${status.id}`, `${grant.tools?.length ?? 0} tools · ${grant.directories === undefined ? 'Whole workspace' : `${grant.directories.length} directory rules`}`), el('span', trusted.has(id) ? 'Authorized' : 'No valid identity', `pill${trusted.has(id) ? '' : ' off'}`)); $('incoming-peers').append(row); }
  if (!Object.keys(p.grants).length) empty($('incoming-peers'), 'No caller grants; incoming tool calls are denied by default');
  fillDl($('runtime'), [['Encrypted transport', status.transport], ['Node listen port', status.port], ['Durable ledger', status.durable ? 'Enabled' : 'Disabled'], ['Policy version', epoch()], ['Local task records', status.taskRecords], ['Result cache', `${status.cacheBytes ?? 0} bytes`]]);
  renderGrants(trusted); renderWorkspaces(); renderIdentity(); renderTasks(); renderJobs(); renderRecovery(); renderEditorStatus();
}
function renderScopes(container, grant) {
  if (grant.directories === undefined) { container.append(el('span', 'Whole workspace · No directory restrictions', 'scope-chip')); return; }
  if (!grant.directories.length) { container.append(el('span', 'All file paths denied', 'scope-chip block')); return; }
  for (const rule of grant.directories) container.append(el('span', `${rule.path || '/ (workspace root)'} · ${scopeLabel(rule)}`, `scope-chip${!rule.read && !rule.write ? ' block' : ''}`));
}
function renderGrants(trusted) {
  const p = policy(); $('grant-list').replaceChildren();
  for (const [id, grant] of Object.entries(p.grants)) {
    const card = el('article', undefined, 'grant-card'), heading = el('div', undefined, 'section-heading'), actions = el('div', undefined, 'inline-actions compact');
    heading.append(el('h3', id)); const edit = el('button', 'Edit grant', 'secondary'); edit.addEventListener('click', () => editGrant(id, grant)); actions.append(edit); heading.append(actions); card.append(heading);
    card.append(el('p', `${trusted.has(id) ? 'Identity trusted' : 'Identity inactive; this grant alone does not authorize execution'} · Workspace: ${grant.workspace ?? grant.root ?? 'No file workspace'}`, 'muted'));
    const scopes = el('div', undefined, 'grant-scopes'); renderScopes(scopes, grant); card.append(scopes);
    card.append(el('p', `Tools: ${(grant.tools ?? []).map(tool => TOOL_LABELS[tool] ?? tool).join(' · ') || 'None (all denied)'}`, 'grant-tools'));
    card.append(el('p', `Concurrency ≤ ${grant.maxConcurrent ?? 1} · Timeout ≤ ${grant.maxTimeoutMs ?? 2000} ms`, 'muted'));
    const processTools = (grant.tools ?? []).filter(tool => PROCESS_TOOLS.includes(tool));
    if (processTools.length) card.append(el('p', `${processTools.join(' / ')} are trusted unsandboxed host processes that can access resources outside directory rules`, 'notice warn'));
    if (grant.workspaces) card.append(el('p', `Named workspaces: ${Object.keys(grant.workspaces).join(', ')}`, 'muted'));
    if (grant.workspaceProvisioning) card.append(el('p', `Approved creation roots: ${Object.keys(grant.workspaceProvisioning.roots ?? {}).join(', ')} · ${grant.tools?.includes('workspaceCreate') ? 'Creation allowed' : 'Creation tool disabled'}`, 'muted'));
    $('grant-list').append(card);
  }
  if (!Object.keys(p.grants).length) empty($('grant-list'), 'No active grants. Start new grants with an explicit directory scope.');
  $('policy-version').textContent = `Current policy version ${epoch()} · ${Object.keys(p.grants).length} callers · These permissions are currently active`;
  $('revoked-summary').textContent = state.permissions?.revoked?.length ? `Revoked: ${state.permissions.revoked.join(', ')}. Editing other callers does not restore these grants.` : '';
  $('policy-json').textContent = JSON.stringify({ ...p, revokedPeerIds: state.permissions?.revoked ?? [] }, null, 2);
  const selection = $('check-peer').value; $('check-peer').replaceChildren();
  for (const id of Object.keys(p.grants)) { const option = el('option', id); option.value = id; $('check-peer').append(option); }
  if (p.grants[selection]) $('check-peer').value = selection;
  updateCheckWorkspaces();
  $('known-peers').replaceChildren(); for (const id of trusted) { const option = el('option'); option.value = id; $('known-peers').append(option); }
}
function updateCheckWorkspaces() {
  const selection = $('check-workspace').value, grant = policy().grants[$('check-peer').value]; $('check-workspace').replaceChildren();
  const items = [['default', 'Default workspace'], ...Object.keys(grant?.workspaces ?? {}).map(id => [id, `Named workspace · ${id}`])];
  for (const [id, label] of items) { const option = el('option', label); option.value = id; $('check-workspace').append(option); }
  if (items.some(([id]) => id === selection)) $('check-workspace').value = selection; $('check-result').hidden = true;
}
function checkedGrant() { const grant = policy().grants[$('check-peer').value]; return $('check-workspace').value === 'default' ? grant : grant?.workspaces?.[$('check-workspace').value]; }
export function pairingCommand(action, fields) {
  if (!['request', 'confirm', 'approve', 'reject'].includes(action)) throw new Error('Select a valid pairing action');
  const requestId = fields.requestId?.trim();
  if (action !== 'request' && !/^[a-zA-Z0-9_-]{1,100}$/.test(requestId ?? '')) throw new Error('Enter a valid request ID');
  if (action === 'reject') return { command: 'pairingReject', requestId };
  const fingerprint256 = fields.fingerprint256?.trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(fingerprint256 ?? '')) throw new Error('Enter the independently verified 64-character SHA-256 fingerprint');
  if (action === 'approve') return { command: 'pairingApprove', requestId, expectedFingerprint: fingerprint256 };
  const id = fields.id?.trim(), host = fields.host?.trim(), port = Number(fields.port);
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id ?? '')) throw new Error('Enter the master UUID, not its display name');
  if (!host || /\s/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Enter a master address and pairing port from 1 to 65535');
  const value = { command: action === 'request' ? 'pairingRequest' : 'pairingConfirm', master: { id, host, port, fingerprint256 } };
  if (action === 'confirm') value.requestId = requestId;
  return value;
}
function nodeLabel(id, name) { return name && name !== id ? `${name} · ${id}` : id; }
function renderIdentity() {
  const identity = state.identity ?? {};
  fillDl($('identity-summary'), [['Name', state.status.name], ['Node UUID', identity.nodeId], ['Expires at', formatTime(identity.validTo)], ['Days remaining', identity.expiresInDays], ['SHA-256', identity.fingerprint256]]);
  $('trusted-peers').replaceChildren();
  for (const peer of identity.trustedPeers ?? []) {
    const name = peer.name ?? state.status.peers?.find(item => item.id === peer.id)?.name;
    const row = el('div', undefined, 'trust-row'), info = rowContent(nodeLabel(peer.id, name), 'Paired identity');
    for (const pin of peer.pins) info.append(el('code', pin));
    const button = el('button', 'Unpair', 'danger');
    button.addEventListener('click', () => guarded(async () => {
      if (!confirm(`Unpair ${nodeLabel(peer.id, name)}? This removes the local relationship and its permissions. Existing effects are not rolled back. Remove the relationship on the other node as well.`)) return;
      await command({ command: 'unpair', peerId: peer.id }); notice(`Unpaired ${peer.id}`); await refresh();
    }));
    row.append(info, button); $('trusted-peers').append(row);
  }
  if (!identity.trustedPeers?.length) empty($('trusted-peers'), 'No paired identities');
}
async function loadPairing() {
  const [status, listing] = await Promise.all([command({ command: 'pairingStatus' }), command({ command: 'listPairingRequests' })]);
  $('pairing-listener').textContent = status.enabled ? `Pairing listener: ${status.host}:${status.port}` : 'Pairing listener disabled. Configure a reachable pairing endpoint to receive requests.';
  const draftFingerprints = new Map([...$('pairing-requests').querySelectorAll('[data-pairing-request]')].map(input => [input.dataset.pairingRequest, input.value]));
  $('pairing-requests').replaceChildren();
  for (const request of listing.requests ?? []) {
    const card = el('div', undefined, 'grant-card');
    card.append(el('h3', nodeLabel(request.nodeId, request.name)));
    const details = el('dl');
    fillDl(details, [['Request ID', request.requestId], ['Status', request.status], ['Endpoint', `${request.endpoint?.host}:${request.endpoint?.port}`], ['Expires at', formatTime(request.expiresAt)], ['Claimed SHA-256', request.fingerprint256]]); card.append(details);
    if (request.status === 'pending' && request.expiresAt > Date.now()) {
      const form = el('form', undefined, 'form-grid'), label = el('label', 'Independently verified servant fingerprint'), fingerprint = el('input');
      fingerprint.dataset.pairingRequest = `${request.requestId}:${request.fingerprint256}`; fingerprint.value = draftFingerprints.get(fingerprint.dataset.pairingRequest) ?? '';
      fingerprint.required = true; fingerprint.pattern = '[a-fA-F0-9]{64}'; fingerprint.autocomplete = 'off'; label.append(fingerprint);
      const approve = el('button', 'Approve request'); approve.type = 'submit';
      form.append(label, approve); form.addEventListener('submit', event => { event.preventDefault(); void guarded(async () => {
        const value = pairingCommand('approve', { requestId: request.requestId, fingerprint256: fingerprint.value });
        if (!confirm(`Approve request ${request.requestId} from ${request.nodeId} using the independently verified fingerprint? The servant must still confirm.`)) return;
        await command(value); notice('Request approved; waiting for servant confirmation.'); await loadPairing();
      }); }); card.append(form);
    }
    if (['pending', 'approved'].includes(request.status) && request.expiresAt > Date.now()) {
      const reject = el('button', 'Reject request', 'danger'); reject.type = 'button'; reject.addEventListener('click', () => guarded(async () => {
        if (!confirm(`Reject pairing request ${request.requestId}?`)) return;
        await command(pairingCommand('reject', { requestId: request.requestId })); await loadPairing();
      })); card.append(reject);
    }
    $('pairing-requests').append(card);
  }
  if (!listing.requests?.length) empty($('pairing-requests'), 'No incoming pairing requests');
}
function pairingMasterFields() {
  return { id: $('pair-master-id').value, host: $('pair-master-host').value, port: $('pair-master-port').value, fingerprint256: $('pair-master-pin').value, requestId: $('pair-request-id').value };
}
async function submitPairing(action) {
  const value = pairingCommand(action, pairingMasterFields());
  if (action === 'confirm' && !confirm(`Confirm request ${value.requestId} with master ${value.master.id}? This adds a live relationship without granting tools.`)) return;
  const result = await command(value); showResult('pair', result);
  if (action === 'request') { $('pair-request-id').value = result.requestId; notice(`Joining request sent: ${result.requestId}. Ask the master to approve it, then confirm here.`); }
  else notice('Pairing complete. Configure the master’s permissions separately.');
  await refresh();
}
function tableEmpty(root, message) { const row = el('tr'), cell = el('td', message, 'empty'); cell.colSpan = 5; row.append(cell); root.append(row); }
function renderTasks() {
  const kind = $('task-kind').value, all = records(kind), filtered = filterRecords(all, $('task-filter').value, $('task-search').value); $('task-rows').replaceChildren();
  $('task-count').textContent = `Showing ${filtered.length} / ${all.length} loaded records`;
  for (const record of filtered) {
    const peerId = record.peerId ?? record.masterId ?? record.peer ?? '—', taskId = record.taskId ?? record.id ?? '—', row = el('tr'), idCell = el('td'); idCell.append(rowContent(taskId, formatTime(record.updatedAt ?? record.createdAt))); row.append(idCell, el('td', peerId));
    const status = el('td'); status.append(statusPill(record.state ?? record.status)); row.append(status, el('td', TOOL_LABELS[record.tool] ?? record.tool ?? '—'));
    const cell = el('td'), button = el('button', 'View task', 'secondary'); button.addEventListener('click', () => selectTask(kind, peerId, taskId)); cell.append(button); row.append(cell); $('task-rows').append(row);
  }
  if (!filtered.length) tableEmpty($('task-rows'), all.length ? 'No matching tasks' : 'No task records in this direction');
}
function renderJobs() {
  $('job-rows').replaceChildren();
  for (const job of state.jobs?.jobs ?? []) {
    const row = el('tr'), id = el('td'); id.append(rowContent(job.jobId, job.taskId ? `Original task: ${job.taskId}` : 'No original task recorded: ID')); row.append(id, el('td', job.masterId)); const status = el('td'); status.append(statusPill(job.state)); row.append(status, el('td', job.command)); const cell = el('td'), button = el('button', 'View job', 'secondary'); button.addEventListener('click', () => selectJob(job)); cell.append(button); row.append(cell); $('job-rows').append(row);
  }
  if (!(state.jobs?.jobs ?? []).length) tableEmpty($('job-rows'), 'No background jobs');
}
function renderRecovery() {
  $('recovery-list').replaceChildren(); let count = 0;
  for (const job of state.jobs?.jobs ?? []) if (job.state === 'unknown') { count++; const row = el('div', undefined, 'recovery-row'), button = el('button', 'Inspect job', 'secondary'); row.append(rowContent(job.jobId, `Background job · ${job.masterId} · Original task ${job.taskId ?? 'Not recorded'}`)); button.addEventListener('click', () => selectJob(job)); row.append(button); $('recovery-list').append(row); }
  for (const kind of ['incoming', 'outgoing']) for (const record of records(kind)) if (record.state === 'unknown') { count++; const peer = record.peerId ?? record.masterId ?? record.peer, id = record.taskId ?? record.id, row = el('div', undefined, 'recovery-row'), button = el('button', kind === 'outgoing' ? 'Query remote' : 'Inspect task', 'secondary'); row.append(rowContent(id, `${kind === 'incoming' ? 'Incoming' : 'Outgoing'} · ${peer}`)); button.addEventListener('click', () => selectTask(kind, peer, id, kind === 'outgoing' ? 'query' : 'status')); row.append(button); $('recovery-list').append(row); }
  for (const creation of state.workspaces?.creations ?? []) if (creation.state === 'unknown') { count++; const row = el('div', undefined, 'recovery-row'), button = el('button', 'Reconcile creation', 'secondary'); row.append(rowContent(creation.id, `Workspace creation · ${creation.masterId} · ${creation.rootId}/${creation.name}`)); button.addEventListener('click', () => { changeView('workspaces'); $('creation-master').value = creation.masterId; $('creation-id').value = creation.id; $('creation-note').value = ''; $('creation-recovery').open = true; $('creation-recovery').scrollIntoView({ block: 'start' }); }); row.append(button); $('recovery-list').append(row); }
  $('recovery-count').textContent = `${count} loaded records awaiting reconciliation`;
  if (!count) empty($('recovery-list'), 'No unknown outcomes in loaded records; look up earlier tasks by ID');
}
function selectTask(direction, peer, id, action = 'status') {
  changeView('tasks', false); $('task-direction').value = direction; $('task-peer').value = peer; $('task-id').value = id; $('task-action').value = action; $('reconcile-note').value = ''; updateTaskFields(); $('task-result-summary').replaceChildren(); $('task-result').textContent = 'This task has not been queried'; $('task-detail').scrollIntoView({ block: 'start' }); $('task-id').focus({ preventScroll: true });
}
function selectJob(job) {
  changeView('tasks', false); $('job-master').value = job.masterId; $('job-id').value = job.jobId; $('job-action').value = 'jobStatus'; $('job-offset').value = '0'; $('job-note').value = ''; jobPage = null; updateJobFields(); $('job-result-summary').replaceChildren(); $('job-result').textContent = 'This job has not been queried'; $('job-output-panel').hidden = true; $('job-detail').scrollIntoView({ block: 'start' }); $('job-id').focus({ preventScroll: true }); syncButtons();
}
function renderEditorStatus() {
  const stale = editor.epoch !== null && editor.epoch !== epoch();
  $('policy-conflict').hidden = !stale;
  $('draft-state').textContent = stale ? 'Version conflict · Draft preserved' : editor.dirty ? `Unsaved · Based on version ${editor.epoch}` : editor.peerId ? `Editing · Version ${editor.epoch}` : 'New grant draft';
}
function markDirty() { if (editor.epoch === null) editor.epoch = epoch(); editor.dirty = true; renderEditorStatus(); renderGrantPreview(); syncButtons(); }
function mayDiscard() { return !editor.dirty || confirm('Discard the unsaved grant draft?'); }
function resetGrant(check = true) {
  if (check && !mayDiscard()) return;
  $('grant-form').reset(); $('grant-peer').readOnly = false; $('grant-peer').value = ''; $('grant-workspace').value = ''; $('grant-concurrency').value = '1'; $('grant-timeout').value = '2000'; $('exec-commands').value = '{}'; $('grant-extra').value = '{}'; $('directory-mode').value = 'scoped'; $('allow-unsandboxed').checked = false;
  document.querySelectorAll('[name=tool]').forEach(input => { input.checked = ['capabilities', 'readFile', 'readChunk', 'listDirectory', 'searchFiles'].includes(input.value); });
  $('owner-workspaces').replaceChildren(); $('owner-creation-roots').replaceChildren();
  $('directory-rules').replaceChildren(); editor = { peerId: null, epoch: state ? epoch() : null, dirty: false }; editorInitialized = true; $('grant-title').textContent = 'Add caller grant'; $('advanced-grant').open = false; updateDirectoryMode(); renderEditorStatus(); renderGrantPreview(); syncButtons();
}
function editGrant(id, grant) {
  if (!mayDiscard()) return;
  editor = { peerId: id, epoch: epoch(), dirty: false }; editorInitialized = true; $('grant-peer').value = id; $('grant-peer').readOnly = true; $('grant-workspace').value = grant.workspace ?? grant.root ?? ''; $('grant-concurrency').value = grant.maxConcurrent ?? 1; $('grant-timeout').value = grant.maxTimeoutMs ?? 2000;
  document.querySelectorAll('[name=tool]').forEach(input => { input.checked = (grant.tools ?? []).includes(input.value); });
  $('exec-commands').value = JSON.stringify(grant.execCommands ?? {}, null, 2); const extra = structuredClone(grant); for (const key of MANAGED_FIELDS) delete extra[key]; $('grant-extra').value = JSON.stringify(extra, null, 2);
  $('directory-mode').value = grant.directories === undefined ? (grant.workspace || grant.root ? 'legacy' : 'none') : 'scoped'; $('allow-unsandboxed').checked = grant.allowUnsandboxedProcesses === true; $('directory-rules').replaceChildren(); for (const rule of grant.directories ?? []) addDirectory(rule, false);
  $('owner-workspaces').replaceChildren(); $('owner-creation-roots').replaceChildren();
  for (const [name, workspace] of Object.entries(grant.workspaces ?? {})) addOwnerWorkspace('workspace', name, workspace, false);
  for (const [name, root] of Object.entries(grant.workspaceProvisioning?.roots ?? {})) addOwnerWorkspace('root', name, root, false);
  $('grant-title').textContent = `Edit grant for ${id}`; updateDirectoryMode(); renderEditorStatus(); renderGrantPreview(); syncButtons(); $('grant-editor').scrollIntoView({ block: 'start' }); $('grant-workspace').focus({ preventScroll: true });
}
function addDirectory(rule = { path: '', read: false, write: false }, focus = true) {
  if ($('directory-rules').children.length >= 128) { notice('At most 128 directory rules are allowed', true); return; }
  const row = el('div', undefined, 'directory-row'), pathLabel = el('label', 'Relative directory'), input = el('input'); input.dataset.rulePath = ''; input.value = rule.path; input.placeholder = 'e.g. docs; leave blank for root'; input.autocomplete = 'off'; pathLabel.append(input); row.append(pathLabel);
  for (const [access, label] of [['read', 'Allow read'], ['write', 'Allow write']]) { const wrapper = el('label', undefined, 'checkbox'), check = el('input'); check.type = 'checkbox'; check.dataset[access] = ''; check.checked = rule[access] === true; check.id = `directory-${++directorySerial}-${access}`; wrapper.append(check, el('span', label)); row.append(wrapper); }
  const remove = el('button', 'Remove rule', 'danger'); remove.type = 'button'; remove.title = 'Removal restores inherited parent rules and may allow access again'; remove.addEventListener('click', () => { if (!confirm(`Remove rule "${input.value || 'Workspace root'}"? Removal restores inherited parent rules and may allow access again. To deny access, keep the rule and disable read and write.`)) return; row.remove(); markDirty(); updateDirectoryMode(); }); row.append(remove); $('directory-rules').append(row); if (focus) { markDirty(); input.focus(); } updateDirectoryMode();
}
function readDirectoryRows() { return [...$('directory-rules').children].map(row => ({ path: row.querySelector('[data-rule-path]').value, read: row.querySelector('[data-read]').checked, write: row.querySelector('[data-write]').checked })); }
function updateDirectoryMode() {
  const scoped = $('directory-mode').value === 'scoped', none = $('directory-mode').value === 'none'; $('grant-workspace').disabled = none; $('directory-section').hidden = !scoped; $('legacy-warning').hidden = scoped; $('legacy-warning').textContent = none ? 'Default file workspace disabled; only the named workspaces and creation-root templates below are available. Disable default file and process tools, keeping only the workspace management capabilities you need.' : 'File tools apply to the entire workspace without finer directory restrictions.'; $('no-directories').hidden = $('directory-rules').children.length > 0;
  $('owner-list-enabled').checked = selectedTools().includes('workspaceList'); $('owner-create-enabled').checked = selectedTools().includes('workspaceCreate');
  $('unsandboxed-warning').hidden = !(scoped && selectedTools().some(tool => PROCESS_TOOLS.includes(tool)));
}
function grantFromForm() {
  const grant = buildGrant(editor.peerId ? policy().grants[editor.peerId] : undefined, { workspace: $('grant-workspace').value.trim(), tools: selectedTools(), mode: $('directory-mode').value, directories: readDirectoryRows(), allowUnsandboxed: $('allow-unsandboxed').checked, maxConcurrent: Number($('grant-concurrency').value), maxTimeoutMs: Number($('grant-timeout').value), extra: $('grant-extra').value, commands: $('exec-commands').value });
  const owner = readOwnerWorkspaces();
  if (Object.keys(owner.workspaces).length) grant.workspaces = owner.workspaces; else delete grant.workspaces;
  if (Object.keys(owner.workspaceProvisioning.roots).length) grant.workspaceProvisioning = owner.workspaceProvisioning; else delete grant.workspaceProvisioning;
  return grant;
}
function renderGrantPreview() {
  const root = $('grant-preview'); root.replaceChildren(); updateDirectoryMode();
  try {
    const grant = grantFromForm(); root.append(el('p', `Caller: ${$('grant-peer').value.trim() || 'Not specified'} → ${state?.status?.id ?? 'Local'} · ${grant.tools.length} tools`));
    const scopes = el('div', undefined, 'grant-scopes'); renderScopes(scopes, grant); root.append(scopes);
    root.append(el('p', `Workspace: ${grant.workspace ?? 'None'} · Concurrency ${grant.maxConcurrent} · Timeout ${grant.maxTimeoutMs} ms`));
    if (grant.workspaces) root.append(el('p', `Independent workspaces: ${Object.keys(grant.workspaces).join(', ')}`));
    if (grant.workspaceProvisioning) root.append(el('p', `Allowed creation roots: ${Object.entries(grant.workspaceProvisioning.roots).map(([id, item]) => `${id} (limit ${item.maxWorkspaces})`).join(', ')} · ${grant.tools.includes('workspaceCreate') ? 'Creation tool granted' : 'Creation tool disabled; no automatic creation'}`));
    if (!grant.tools.length) root.append(el('p', 'No tools selected; directory permissions alone do not authorize execution.'));
    if (grant.tools.includes('editFile')) root.append(el('p', 'Exact edits require both read and write access to the target directory.'));
    if (grant.tools.some(tool => PROCESS_TOOLS.includes(tool))) root.append(el('p', 'Includes trusted host processes; file directory rules do not sandbox these processes.'));
  } catch (error) { root.append(el('p', error.message, 'muted')); }
}
async function saveGrant() {
  const id = $('grant-peer').value.trim(); if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) throw new Error('Enter a valid caller ID');
  if (editor.epoch !== epoch()) throw new Error(ERRORS.POLICY_CONFLICT);
  if (!editor.peerId && policy().grants[id]) throw new Error('This caller already has a grant. Select Edit grant above to avoid overwriting it.');
  const grant = grantFromForm(), next = structuredClone(policy()); next.grants[id] = grant;
  const scopes = grant.directories === undefined ? 'Whole workspace, without directory restrictions' : grant.directories.map(rule => `${rule.path || 'Workspace root'}: ${scopeLabel(rule)}`).join('\n') || 'All file paths denied';
  if (!confirm(`Save the persistent grant for ${id} → ${state.status.id}?\nWorkspace: ${grant.workspace ?? 'None'}\nTools: ${grant.tools.join(', ') || 'None'}\nDirectories: \n${scopes}\n${grant.tools.some(tool => PROCESS_TOOLS.includes(tool)) ? 'Note: exec / MCP are trusted host processes that can access paths outside directory rules.\n' : ''}Named workspaces: ${Object.keys(grant.workspaces ?? {}).join(', ') || 'None'}\nApproved creation roots: ${Object.entries(grant.workspaceProvisioning?.roots ?? {}).map(([name, item]) => `${name} → ${item.path} (limit ${item.maxWorkspaces}); tools ${item.grant.tools.join(', ') || 'None'}; directories ${item.grant.directories.map(rule => `${rule.path || 'Root'}:${scopeLabel(rule)}`).join(', ') || 'All denied'}${item.grant.tools.some(tool => PROCESS_TOOLS.includes(tool)) ? '; includes unsandboxed host processes' : ''}`).join('\n') || 'None'}\nRemoving a creation root or changing its template revokes access to workspaces created from it; files remain.\nPolicy changes may stop current tasks and jobs; existing effects are not rolled back.`)) return;
  await command({ command: 'setPolicy', policy: next, expectedEpoch: editor.epoch }); editor.dirty = false; editorInitialized = false; notice(`Validated and saved the grant for ${id}`); await refresh(); const saved = policy().grants[id]; if (saved) editGrant(id, saved);
}
function updateTaskFields() {
  const incoming = $('task-direction').value === 'incoming';
  for (const option of $('task-action').options) option.disabled = (option.value === 'events' && !incoming) || (option.value === 'query' && incoming);
  if ($('task-action').selectedOptions[0]?.disabled) $('task-action').value = 'status';
  const reconcile = $('task-action').value === 'reconcile'; $('task-reconcile-fields').hidden = !reconcile; $('reconcile-note').required = reconcile;
  $('task-submit').textContent = { status: 'Read task record', events: 'Read task events', query: 'Query remote result', cancel: 'Confirm task cancellation', reconcile: 'Review and record reconciliation' }[$('task-action').value];
}
function updateJobFields() {
  const action = $('job-action').value; $('job-output-fields').hidden = action !== 'jobOutput'; $('job-reconcile-fields').hidden = action !== 'reconcileJob'; $('job-note').required = action === 'reconcileJob';
  $('job-submit').textContent = { jobStatus: 'Read job status', jobOutput: 'Read this output page', jobCancel: 'Confirm job cancellation', reconcileJob: 'Review and record reconciliation' }[action];
}
function showResult(prefix, result) {
  $(`${prefix}-result`).textContent = JSON.stringify(result, null, 2);
  const summary = $(`${prefix}-result-summary`); summary.replaceChildren();
  const value = result?.record ?? result?.result ?? result;
  if (value && typeof value === 'object') {
    const stateValue = value.state ?? value.status ?? result.state;
    if (stateValue) summary.append(statusPill(stateValue));
    const entries = [['Task ID', value.taskId], ['Job ID', value.jobId], ['Caller', value.masterId ?? value.peerId], ['Command alias', value.command], ['Tool', value.tool], ['Updated at', value.updatedAt ? formatTime(value.updatedAt) : undefined], ['Exit code', value.exitCode], ['Error code', value.error?.code ?? value.response?.error?.code], ['Reconciliation outcome', value.resolution ? stateLabel(value.resolution) : undefined], ['Node ID', value.nodeId], ['Expires at', value.validTo], ['SHA-256', value.fingerprint256]].filter(([, v]) => v !== undefined && v !== null);
    if (entries.length) { const list = el('dl'); fillDl(list, entries); summary.append(list); }
    if (value.events) { const list = el('ol'); for (const event of value.events) list.append(el('li', `${event.seq ?? ''} · ${event.event ?? event.type ?? 'Event'} · ${stateLabel(event.state ?? event.status)}`)); summary.append(list); if (!value.events.length) summary.append(el('p', 'No events to display')); }
    if (stateValue === 'unknown' || value.outcomeUnknown) summary.append(el('p', 'Outcome unknown: independently verify effects before reconciliation. Cancellation, timeout, and missing records do not prove the operation did not run.', 'notice warn'));
    if (['not_found', 'expired'].includes(stateValue)) summary.append(el('p', 'Missing retained records do not prove non-execution and do not automatically clear unknown-outcome gates.', 'notice warn'));
    if (value.requested !== undefined) summary.append(el('p', value.requested ? 'Cancellation requested; check status to confirm the outcome. Existing effects are not rolled back.' : 'No active task to cancel; read the record to confirm final status.'));
  }
  if (!summary.children.length) summary.append(el('p', 'Operation returned. Expand the full response for details.'));
}
async function runTask() {
  const action = $('task-action').value, value = taskCommand({ direction: $('task-direction').value, action, peer: $('task-peer').value.trim(), taskId: $('task-id').value.trim(), resolution: $('resolution').value, note: $('reconcile-note').value });
  if (action === 'cancel' && !confirm(`Cancel ${value.taskId}? Existing external effects are not rolled back; verify the final status.`)) return;
  if (action === 'reconcile' && !confirm(`Based on independent evidence, mark ${value.taskId} as "${stateLabel(value.resolution)}"? This only records an outcome; it does not execute or replay the task.`)) return;
  showResult('task', await command(value)); if (['reconcile', 'cancel'].includes(action)) notice('Task operation returned; check the status and recovery list below'); await refresh();
}
function jobPageMatches() { return jobPage && jobPage.masterId === $('job-master').value.trim() && jobPage.jobId === $('job-id').value.trim() && jobPage.stream === $('job-stream').value; }
async function runJob(next = false) {
  const input = { command: next ? 'jobOutput' : $('job-action').value, masterId: $('job-master').value.trim(), jobId: $('job-id').value.trim() };
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(input.masterId) || !/^[a-zA-Z0-9_-]{1,100}$/.test(input.jobId)) throw new Error('Enter valid caller and job ID');
  if (input.command === 'jobOutput') { if (next && (!jobPageMatches() || jobPage.eof)) throw new Error('Read the first output page for the current job first'); input.offset = next ? jobPage.nextOffset : Number($('job-offset').value); if (!Number.isSafeInteger(input.offset) || input.offset < 0) throw new Error('Output offset must be a non-negative integer'); input.limit = 16384; input.stream = $('job-stream').value; }
  if (input.command === 'jobCancel' && !confirm(`Stop background job ${input.jobId}? Existing external effects are not rolled back; verify the final status.`)) return;
  if (input.command === 'reconcileJob') { input.resolution = $('job-resolution').value; input.note = $('job-note').value.trim(); if (!input.note) throw new Error('Enter independent reconciliation evidence'); if (!confirm(`Reconcile unknown job ${input.jobId} as "${stateLabel(input.resolution)}"? This does not execute or replay the command. Reconcile the original launch task afterward.`)) return; }
  const result = await command(input); showResult('job', result);
  if (input.command === 'jobOutput') { jobPage = { ...result, masterId: input.masterId, jobId: input.jobId, stream: input.stream }; $('job-output-panel').hidden = false; $('job-output-text').textContent = result.text || '(No output on this page)'; $('job-output-meta').textContent = `${input.stream} · bytes ${result.offset ?? input.offset}–${result.nextOffset} / ${result.totalBytes}${result.eof ? ' · End of current output' : ''}`; $('job-offset').value = result.nextOffset; }
  else { jobPage = null; $('job-output-panel').hidden = true; }
  await refresh();
}
async function showLogs() {
  const data = await api('/api/logs'); logs = data.records ?? []; $('logs-output').textContent = data.unavailable ? data.message : logs.map(record => JSON.stringify(record)).join('\n') || 'No persistent audit records';
  const selected = $('log-event').value; $('log-event').replaceChildren(el('option', 'All events')); $('log-event').firstElementChild.value = '';
  for (const event of [...new Set(logs.map(record => record.event).filter(Boolean))].sort()) { const option = el('option', event); option.value = event; $('log-event').append(option); }
  if (logs.some(record => record.event === selected)) $('log-event').value = selected;
  renderLogs(); if (data.unavailable) $('log-count').textContent = data.message ?? 'Persistent audit log not configured';
}
function renderLogs() {
  const query = $('log-search').value.toLocaleLowerCase(), event = $('log-event').value, filtered = logs.filter(record => (!event || record.event === event) && JSON.stringify(record).toLocaleLowerCase().includes(query)); $('log-rows').replaceChildren(); $('log-count').textContent = `Showing ${filtered.length} / ${logs.length} loaded metadata records`;
  for (const record of filtered) { const row = el('tr'); for (const value of [formatTime(record.timestamp ?? record.time), record.event ?? '—', [record.masterId ?? record.peerId ?? record.nodeId, record.taskId, record.jobId].filter(Boolean).join(' / ') || '—', [record.state ? stateLabel(record.state) : record.status, record.error?.code ?? record.code, record.command].filter(Boolean).join(' · ') || '—']) row.append(el('td', value)); $('log-rows').append(row); }
  if (!filtered.length) { const row = el('tr'), cell = el('td', logs.length ? 'No matching logs' : 'No audit records', 'empty'); cell.colSpan = 4; row.append(cell); $('log-rows').append(row); }
}
function mountTools() {
  for (const [name, tools] of TOOL_GROUPS) { const group = el('div', undefined, 'tool-group'), list = el('div', undefined, 'tool-choices'); group.append(el('h3', name)); for (const [value, label] of tools) { const wrapper = el('label'), input = el('input'), text = el('span', label); input.type = 'checkbox'; input.name = 'tool'; input.value = value; text.append(el('small', value)); wrapper.append(input, text); list.append(wrapper); } group.append(list); $('tool-groups').append(group); }
  for (const tool of FILE_TOOLS) { const option = el('option', `${TOOL_LABELS[tool]} (${tool})`); option.value = tool; $('check-tool').append(option); }
}
const ownerTemplateSources = new WeakMap();
function labeledInput(label, key, value = '', options = {}) {
  const wrapper = el('label', label), input = el(options.textarea ? 'textarea' : 'input'); input.dataset[key] = ''; input.value = value;
  for (const [property, item] of Object.entries(options)) if (property !== 'textarea') input[property] = item;
  wrapper.append(input); return { wrapper, input };
}
function addTemplateDirectory(container, rule = { path: '', read: false, write: false }, focus = true) {
  const row = el('div', undefined, 'template-directory-row'); row.dataset.templateRule = '';
  const field = labeledInput('Template relative directory (blank for root)', 'templatePath', rule.path); row.append(field.wrapper);
  for (const access of ['read', 'write']) { const label = el('label', undefined, 'checkbox'), input = el('input'); input.type = 'checkbox'; input.dataset[access] = ''; input.checked = rule[access] === true; label.append(input, el('span', access === 'read' ? 'Allow read' : 'Allow write')); row.append(label); }
  const remove = el('button', 'Remove rule', 'danger'); remove.type = 'button'; remove.addEventListener('click', () => { if (!confirm('Removing a template directory rule restores parent inheritance and may allow access again. Remove it? To deny access, keep the rule and disable read and write.')) return; row.remove(); markDirty(); }); row.append(remove); container.append(row); if (focus) { markDirty(); field.input.focus(); }
}
function addOwnerWorkspace(kind, id = '', source = null, focus = true) {
  if ($(kind === 'root' ? 'owner-creation-roots' : 'owner-workspaces').children.length >= (kind === 'root' ? 16 : 32)) { notice(kind === 'root' ? 'Each caller supports at most 16 creation roots' : 'Each caller supports at most 32 named workspaces', true); return; }
  const root = kind === 'root', template = structuredClone(root ? source?.grant ?? {} : source ?? {}), card = el('div', undefined, 'owner-workspace-card'); card.dataset.ownerKind = kind; ownerTemplateSources.set(card, { template, source: structuredClone(source ?? {}) });
  const heading = el('div', undefined, 'section-heading'), remove = el('button', root ? 'Remove creation root' : 'Remove workspace grant', 'danger'); remove.type = 'button'; heading.append(el('h3', root ? 'Approved local creation root' : 'Independent named workspace'), remove); card.append(heading);
  remove.addEventListener('click', () => { if (!confirm(root ? 'Remove this creation root from the draft? Saving denies future creation and access to existing workspaces through this template; files remain. To stop only new creation, disable workspaceCreate tool.' : 'Remove this named workspace grant? Saving denies execution through this alias; files remain.')) return; card.remove(); markDirty(); });
  const basic = el('div', undefined, 'form-grid'), alias = labeledInput(root ? 'Public creation root alias' : 'Public workspace alias', 'ownerId', id, { required: true, pattern: '[a-zA-Z0-9_-]{1,64}', placeholder: root ? 'e.g. projects' : 'e.g. docs' }), path = labeledInput(root ? 'Approved local parent directory' : 'Existing local workspace directory', 'ownerPath', root ? source?.path ?? '' : template.workspace ?? '', { required: true, placeholder: root ? '/srv/node/projects' : '/srv/node/docs' }); basic.append(alias.wrapper, path.wrapper);
  if (root) basic.append(labeledInput('Maximum workspaces for this root', 'ownerQuota', source?.maxWorkspaces ?? 8, { type: 'number', min: '1', max: '128', required: true }).wrapper);
  card.append(basic);
  const details = el('details'); details.open = true; details.append(el('summary', root ? 'Grant template inherited by new workspaces' : 'Independent grant for this workspace'));
  const choices = el('div', undefined, 'tool-choices'), tools = template.tools ?? ['capabilities', 'readFile', 'readChunk', 'listDirectory', 'searchFiles'];
  for (const [tool, labelText] of Object.entries(TOOL_LABELS)) { if (['workspaceList', 'workspaceCreate'].includes(tool)) continue; const label = el('label'), check = el('input'), text = el('span', labelText); check.type = 'checkbox'; check.name = 'template-tool'; check.value = tool; check.checked = tools.includes(tool); text.append(el('small', tool)); label.append(check, text); choices.append(label); } details.append(choices);
  const modeLabel = el('label', 'Directory scope'), mode = el('select'); mode.dataset.templateMode = ''; const scoped = el('option', 'Directory restrictions (unmatched paths denied)'); scoped.value = 'scoped'; mode.append(scoped);
  if (!root) { const legacy = el('option', 'Whole workspace'); legacy.value = 'legacy'; mode.append(legacy); }
  mode.value = root || !source || template.directories !== undefined ? 'scoped' : 'legacy'; modeLabel.append(mode); details.append(modeLabel);
  const directoryBox = el('div'); directoryBox.dataset.templateDirectories = ''; for (const rule of template.directories ?? (source ? [] : [{ path: '', read: true, write: false }])) addTemplateDirectory(directoryBox, rule, false); details.append(directoryBox);
  const add = el('button', '+ Add template directory rule', 'secondary'); add.type = 'button'; add.addEventListener('click', () => addTemplateDirectory(directoryBox)); details.append(add, el('p', 'Rules apply recursively; the most specific directory wins. Empty rules deny all file paths. Whole-workspace mode ignores directory rules.', 'muted'));
  const processNotice = el('div', undefined, 'notice warn'); processNotice.dataset.templateProcessWarning = ''; processNotice.append(el('p', 'exec / MCP use host process privileges and can access paths outside template directory rules. Directory grants do not sandbox processes.')); const processLabel = el('label', undefined, 'checkbox'), allow = el('input'); allow.type = 'checkbox'; allow.dataset.templateUnsandboxed = ''; allow.checked = template.allowUnsandboxedProcesses === true; processLabel.append(allow, el('span', 'Explicitly allow reviewed unsandboxed host processes')); processNotice.append(processLabel); details.append(processNotice);
  const quotas = el('div', undefined, 'form-grid'); quotas.append(labeledInput('Template concurrency limit', 'templateConcurrency', template.maxConcurrent ?? 1, { type: 'number', min: '1', max: '32', required: true }).wrapper, labeledInput('Template timeout limit (ms)', 'templateTimeout', template.maxTimeoutMs ?? 2000, { type: 'number', min: '10', max: '86400000', required: true }).wrapper); details.append(quotas);
  const advanced = el('details'), extra = structuredClone(template); for (const key of MANAGED_FIELDS) delete extra[key]; advanced.append(el('summary', 'Advanced template fields: commands, resources, and other limits'), labeledInput('Approved command aliases (JSON object)', 'templateCommands', JSON.stringify(template.execCommands ?? {}, null, 2), { textarea: true, spellcheck: false }).wrapper, labeledInput('Other template fields (JSON object)', 'templateExtra', JSON.stringify(extra, null, 2), { textarea: true, spellcheck: false }).wrapper); details.append(advanced); card.append(details);
  const update = () => { const process = [...card.querySelectorAll('[name=template-tool]:checked')].some(input => PROCESS_TOOLS.includes(input.value)); processNotice.hidden = !process; directoryBox.hidden = mode.value === 'legacy'; add.hidden = mode.value === 'legacy'; };
  card.addEventListener('input', update); card.addEventListener('change', update); update();
  $(root ? 'owner-creation-roots' : 'owner-workspaces').append(card); if (focus) { markDirty(); alias.input.focus(); }
}
function readOwnerWorkspaces() {
  const workspaces = {}, roots = {};
  for (const container of ['owner-workspaces', 'owner-creation-roots']) for (const card of $(container).children) {
    const root = card.dataset.ownerKind === 'root', id = card.querySelector('[data-owner-id]').value.trim(), workspace = card.querySelector('[data-owner-path]').value.trim();
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id) || (!root && (id === 'default' || id.startsWith('ws_')))) throw new Error('Workspace/root alias must contain 1–64 letters, digits, underscores, or hyphens; named workspaces cannot use default or ws_ prefix');
    const target = root ? roots : workspaces; if (Object.hasOwn(target, id)) throw new Error(`Duplicate alias: ${id}`);
    if (!workspace) throw new Error(`Enter the local directory for ${id}`);
    const { template, source } = ownerTemplateSources.get(card), directories = [...card.querySelector('[data-template-directories]').children].map(row => ({ path: row.querySelector('[data-template-path]').value, read: row.querySelector('[data-read]').checked, write: row.querySelector('[data-write]').checked }));
    const grant = buildGrant(template, { workspace, tools: [...card.querySelectorAll('[name=template-tool]:checked')].map(input => input.value), mode: card.querySelector('[data-template-mode]').value, directories, allowUnsandboxed: card.querySelector('[data-template-unsandboxed]').checked, maxConcurrent: Number(card.querySelector('[data-template-concurrency]').value), maxTimeoutMs: Number(card.querySelector('[data-template-timeout]').value), commands: card.querySelector('[data-template-commands]').value, extra: card.querySelector('[data-template-extra]').value });
    delete grant.workspaces; delete grant.workspaceProvisioning;
    // Preserve the exact existing template when defaults were not edited: its raw hash is a safety boundary.
    if (Object.keys(template).length) {
      grant.tools = [...(template.tools ?? []).filter(tool => grant.tools.includes(tool)), ...grant.tools.filter(tool => !(template.tools ?? []).includes(tool))];
      for (const [key, fallback] of [['maxConcurrent', 1], ['maxTimeoutMs', 2000], ['allowUnsandboxedProcesses', false]]) if (!Object.hasOwn(template, key) && grant[key] === fallback) delete grant[key];
      if (!Object.hasOwn(template, 'execCommands') && !Object.keys(grant.execCommands ?? {}).length) delete grant.execCommands;
    }
    if (root) { delete grant.workspace; const maxWorkspaces = Number(card.querySelector('[data-owner-quota]').value); if (!Number.isSafeInteger(maxWorkspaces) || maxWorkspaces < 1 || maxWorkspaces > 128) throw new Error(`Workspace count for creation root ${id} must be an integer from 1 to 128`); target[id] = { ...source, path: workspace, maxWorkspaces, grant }; }
    else target[id] = grant;
  }
  return { workspaces, workspaceProvisioning: { roots } };
}

function bindingState() { return state?.workspaces ?? { revision: 0, bindings: [], autoProvision: [] }; }
function workspaceContext() {
  const logicalWorkspaceId = $('logical-workspace').value.trim(), peerId = $('workspace-peer').value;
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(logicalWorkspaceId) || !peerId) throw new Error('Enter a valid logical workspace ID and select an execution node');
  return { logicalWorkspaceId, peerId };
}
function catalogMatches() { return workspaceCatalog && workspaceCatalog.peerId === $('workspace-peer').value && workspaceCatalog.logicalWorkspaceId === $('logical-workspace').value.trim(); }
function bindingRevisionMatches() { return catalogMatches() && workspaceCatalog.revision === bindingState().revision; }
function requireBindingRevision() { if (!bindingRevisionMatches()) throw new Error('Workspace mappings changed or have not been loaded; reload available workspaces first'); }
function showWorkspaceResult(message) { $('workspace-result').hidden = false; $('workspace-result').textContent = message; }
function invalidateWorkspaceCatalog() { workspaceCatalog = null; $('workspace-catalog').hidden = true; $('workspace-conflict').hidden = true; $('workspace-result').hidden = true; syncButtons(); }
function renderWorkspaces() {
  const registry = bindingState(), previous = $('workspace-peer').value;
  $('workspace-peer').replaceChildren();
  for (const peer of state.status.peers ?? []) { const option = el('option', `${peer.id}${peer.connected ? ' · Connected' : ' · Disconnected'}`); option.value = peer.id; $('workspace-peer').append(option); }
  if ((state.status.peers ?? []).some(peer => peer.id === previous)) $('workspace-peer').value = previous;
  if (workspaceCatalog && !catalogMatches()) invalidateWorkspaceCatalog();
  $('binding-version').textContent = `Local mapping version ${registry.revision ?? 0} · ${registry.bindings?.length ?? 0} active bindings`;
  $('workspace-bindings').replaceChildren();
  for (const binding of registry.bindings ?? []) {
    const row = el('div', undefined, 'grant-card'), heading = el('div', undefined, 'section-heading'), action = el('button', 'Unbind', 'danger');
    heading.append(el('h3', `${binding.logicalWorkspaceId} → ${binding.peerId} / ${binding.workspaceId}`), action); row.append(heading, el('p', `Bound · ${formatTime(binding.updatedAt ?? binding.createdAt)}`, 'muted'));
    const revision = registry.revision;
    action.addEventListener('click', () => guarded(async () => { if (!confirm(`Remove ${binding.logicalWorkspaceId} → ${binding.peerId} / ${binding.workspaceId} routing binding? Files remain. Automatic provisioning may create a workspace again on next use; disable the automatic rule to prevent this.`)) return; await command({ command: 'unbindWorkspace', logicalWorkspaceId: binding.logicalWorkspaceId, peerId: binding.peerId, expectedRevision: revision }); showWorkspaceResult('Routing binding removed; remote files remain. Check whether automatic provisioning should also be disabled.'); await refresh(); })); $('workspace-bindings').append(row);
  }
  if (!registry.bindings?.length) empty($('workspace-bindings'), 'No active bindings. Bind an existing workspace or enable automatic provisioning.');
  renderLocalCreations();
  $('workspace-auto-rules').replaceChildren();
  for (const rule of registry.autoProvision ?? []) {
    const row = el('div', undefined, 'peer-row'), actions = el('div', undefined, 'inline-actions compact'); row.append(rowContent(`${rule.logicalWorkspaceId} → ${rule.peerId}`, `${rule.enabled ? 'Automatic provisioning enabled' : 'Automatic provisioning disabled'} · Creation root ${rule.rootId}`));
    const edit = el('button', 'View / Use', 'secondary'); edit.addEventListener('click', () => { $('logical-workspace').value = rule.logicalWorkspaceId; $('workspace-peer').value = rule.peerId; void guarded(loadWorkspaceCatalog); }); actions.append(edit);
    if (rule.enabled) { const disable = el('button', 'Disable automatic provisioning', 'danger'), revision = registry.revision; disable.addEventListener('click', () => guarded(async () => { if (!confirm(`Disable ${rule.logicalWorkspaceId} → ${rule.peerId} automatic creation? Existing bindings and files remain.`)) return; await command({ command: 'setWorkspaceAutoProvision', logicalWorkspaceId: rule.logicalWorkspaceId, peerId: rule.peerId, rootId: rule.rootId, enabled: false, expectedRevision: revision }); showWorkspaceResult('Automatic provisioning disabled; existing bindings and files remain.'); await refresh(); })); actions.append(disable); }
    row.append(actions); $('workspace-auto-rules').append(row);
  }
  if (!registry.autoProvision?.length) empty($('workspace-auto-rules'), 'Automatic provisioning is disabled; unbound logical workspaces deny remote execution by default.');
  $('workspace-conflict').hidden = !catalogMatches() || bindingRevisionMatches();
}
function renderLocalCreations() {
  $('local-workspace-creations').replaceChildren();
  for (const creation of bindingState().creations ?? []) {
    const row = el('div', undefined, 'peer-row'); row.append(rowContent(`${creation.name} · ${creation.id}`, `Caller ${creation.masterId} · Creation root ${creation.rootId}`), creation.state === 'ready' ? el('span', 'Creation recorded', 'pill') : statusPill(creation.state));
    if (creation.state === 'unknown') { const button = el('button', 'Reconcile creation', 'secondary'); button.addEventListener('click', () => { $('creation-master').value = creation.masterId; $('creation-id').value = creation.id; $('creation-note').value = ''; $('creation-recovery').open = true; $('creation-recovery').scrollIntoView({ block: 'start' }); $('creation-note').focus(); }); row.append(button); }
    $('local-workspace-creations').append(row);
  }
  if (!bindingState().creations?.length) empty($('local-workspace-creations'), 'No workspace creation requests received by this node');
}
async function reconcileCreation() {
  const masterId = $('creation-master').value.trim(), workspaceId = $('creation-id').value.trim(), resolution = $('creation-resolution').value, note = $('creation-note').value.trim();
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(masterId) || !/^[a-zA-Z0-9_-]{1,64}$/.test(workspaceId) || note.length < 3) throw new Error('Enter valid caller and workspace ID and independent evidence of at least 3 characters');
  if (!confirm(`Based on independent local evidence, mark ${masterId} / ${workspaceId} as "${resolution === 'completed' ? 'Creation completed' : 'Confirmed not created'}"? This does not recreate directories or delete files.`)) return;
  await command({ command: 'reconcileWorkspaceCreation', masterId, workspaceId, resolution, note }); await refresh(); showWorkspaceResult('Unknown creation reconciled; check the original task status and routing bindings.');
}

function catalogItemSummary(item, root = false) {
  const card = el('div', undefined, 'grant-card'); card.append(el('h3', root ? `Approved creation roots: ${item.id}` : `Workspace: ${item.name ?? item.id}`));
  card.append(el('p', root ? `Quota ${item.used ?? 0} / ${item.maxWorkspaces} · Remaining ${item.remaining ?? 'Subject to server validation'}` : `ID ${item.id} · ${{ default: 'Default workspace', configured: 'Owner configured', provisioned: 'System provisioned' }[item.kind] ?? item.kind ?? 'Authorized workspace'}`, 'muted'));
  if (!root && item.state !== 'ready') { card.append(statusPill(item.state ?? 'unavailable'), el('p', 'This workspace cannot currently be bound or used for execution; ask the servant local owner to inspect creation records and grants.', 'notice warn')); return card; }
  card.append(el('p', `Inherited tools: ${(item.tools ?? []).map(tool => TOOL_LABELS[tool] ?? tool).join(' · ') || 'No tools granted'}`, 'grant-tools'));
  const scope = el('div', undefined, 'grant-scopes'), filesystem = item.filesystem ?? {}; renderScopes(scope, filesystem.mode === 'scoped' ? { directories: filesystem.directories ?? [] } : {}); card.append(scope);
  if (filesystem.processAccess === 'outside-directory-policy' || (item.tools ?? []).some(tool => PROCESS_TOOLS.includes(tool))) card.append(el('p', 'Includes unsandboxed host processes; directory rules do not restrict their access.', 'notice warn'));
  return card;
}
async function loadWorkspaceCatalog() {
  const context = workspaceContext(), catalog = await command({ command: 'remoteWorkspaces', peerId: context.peerId });
  await refresh(); workspaceCatalog = { ...catalog, ...context, revision: bindingState().revision };
  $('workspace-catalog').hidden = false; $('workspace-conflict').hidden = true; $('catalog-summary').replaceChildren();
  const existing = catalog.workspaces ?? [], roots = catalog.creationRoots ?? [];
  for (const item of existing) $('catalog-summary').append(catalogItemSummary(item));
  for (const item of roots) $('catalog-summary').append(catalogItemSummary(item, true));
  if (!existing.length && !roots.length) empty($('catalog-summary'), 'This node publishes no available workspaces or creation roots; ask its owner to grant a scope.');
  for (const id of ['existing-workspace', 'auto-root', 'create-root']) $(id).replaceChildren();
  for (const item of existing.filter(item => item.state === 'ready')) { const option = el('option', `${item.name ?? item.id} (${item.id})`); option.value = item.id; $('existing-workspace').append(option); }
  for (const item of roots) for (const id of ['auto-root', 'create-root']) { const option = el('option', `${item.id} · Remaining ${item.remaining ?? 'Pending validation'}`); option.value = item.id; $(id).append(option); }
  const rule = (bindingState().autoProvision ?? []).find(item => item.peerId === context.peerId && item.logicalWorkspaceId === context.logicalWorkspaceId);
  $('auto-enabled').checked = rule?.enabled === true;
  if (roots.some(item => item.id === rule?.rootId)) $('auto-root').value = rule.rootId;
  const bound = (bindingState().bindings ?? []).find(item => item.peerId === context.peerId && item.logicalWorkspaceId === context.logicalWorkspaceId);
  if (existing.some(item => item.id === bound?.workspaceId)) $('existing-workspace').value = bound.workspaceId;
  renderAutoRoot(); showWorkspaceResult(`Loaded available scopes for ${context.peerId}. ${bound ? `Current binding: ${bound.workspaceId}.` : 'No current binding.'}`); syncButtons();
}
function renderAutoRoot() { $('auto-root-summary').replaceChildren(); const root = workspaceCatalog?.creationRoots?.find(item => item.id === $('auto-root').value); if (root) $('auto-root-summary').append(catalogItemSummary(root, true)); }
async function saveWorkspaceAuto() {
  requireBindingRevision(); const context = workspaceContext(), rootId = $('auto-root').value, enabled = $('auto-enabled').checked;
  if (!rootId) throw new Error('No creation roots available; ask the execution node owner to configure one');
  if (!confirm(`${enabled ? 'Enable' : 'Disable'} ${context.logicalWorkspaceId} → ${context.peerId} automatic provisioning?\nApproved creation roots: ${rootId}\n${enabled ? 'First use may create a directory and binding, inheriting the root’s grant template and quota. Saving the rule does not create directories.' : 'Existing bindings and files remain.'}`)) return;
  await command({ command: 'setWorkspaceAutoProvision', ...context, rootId, enabled, expectedRevision: workspaceCatalog.revision }); await loadWorkspaceCatalog(); showWorkspaceResult(enabled ? 'Automatic provisioning rule saved; no new workspace created. Select Prepare now / Use, or let the first dispatch provision it automatically.' : 'Automatic provisioning disabled; existing bindings and files remain.');
}
async function ensureWorkspace() {
  requireBindingRevision(); const context = workspaceContext(), exists = (bindingState().bindings ?? []).find(item => item.peerId === context.peerId && item.logicalWorkspaceId === context.logicalWorkspaceId);
  if (!exists && !confirm(`Prepare now ${context.logicalWorkspaceId} → ${context.peerId}? If no binding exists, the saved automatic rule creates a workspace under an approved root and inherits its template permissions.`)) return;
  const result = await command({ command: 'ensureWorkspaceBinding', ...context }); await loadWorkspaceCatalog(); const binding = result.binding ?? result; showWorkspaceResult(`System binding confirmed: ${binding.workspaceId ?? 'Check the current binding'}. Future calls reuse this binding; execution still requires the servant’s current authorization.`);
}
async function bindWorkspace() {
  requireBindingRevision(); const context = workspaceContext(), workspaceId = $('existing-workspace').value;
  if (!workspaceId || !workspaceCatalog.workspaces?.some(item => item.id === workspaceId)) throw new Error('Select a workspace published by the execution node');
  if (!confirm(`Bind ${context.logicalWorkspaceId} to ${context.peerId} / ${workspaceId}? Future remote tasks use this workspace; previous workspace files are not moved or deleted.`)) return;
  await command({ command: 'bindWorkspace', ...context, workspaceId, expectedRevision: workspaceCatalog.revision }); await loadWorkspaceCatalog(); showWorkspaceResult('Selected workspace bound; future logical workspace dispatches use this mapping.');
}
async function createWorkspace() {
  requireBindingRevision(); const context = workspaceContext(), rootId = $('create-root').value, name = $('create-workspace-name').value.trim();
  if (!rootId || !workspaceCatalog.creationRoots?.some(root => root.id === rootId)) throw new Error('Select a creation root published by the execution node');
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(name)) throw new Error('Workspace names must contain 1–64 letters, digits, underscores, or hyphens, starting with a letter or digit');
  const target = JSON.stringify({ ...context, rootId, name });
  if (!pendingCreations.has(target)) { if (pendingCreations.size >= 128) throw new Error('This page reached the creation request limit; review existing requests before reopening the console'); pendingCreations.set(target, `ui_${crypto.randomUUID()}`); }
  if (!confirm(`On ${context.peerId} approved root ${rootId} create "${name}" and bind ${context.logicalWorkspaceId}? The new workspace inherits the root’s tools, directory scope, and limits.`)) return;
  await command({ command: 'createWorkspace', ...context, rootId, name, creationRequestId: pendingCreations.get(target), expectedRevision: workspaceCatalog.revision }); $('create-workspace-name').value = ''; await loadWorkspaceCatalog(); showWorkspaceResult('Workspace created and bound; permissions inherit the template configured by the execution node owner.');
}

export function initialize() {
  mountTools(); updateTaskFields(); updateJobFields();
  document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => { changeView(button.dataset.view); if (currentView === 'logs' && csrf) void guarded(showLogs); if (currentView === 'identity' && csrf) void guarded(loadPairing); }));
  $('creation-reconcile-form').addEventListener('submit', event => { event.preventDefault(); void guarded(reconcileCreation); });
  $('workspace-context-form').addEventListener('submit', event => { event.preventDefault(); void guarded(loadWorkspaceCatalog); });
  for (const id of ['logical-workspace', 'workspace-peer']) $(id).addEventListener('input', invalidateWorkspaceCatalog);
  $('auto-root').addEventListener('change', renderAutoRoot);
  $('workspace-auto-form').addEventListener('submit', event => { event.preventDefault(); void guarded(saveWorkspaceAuto); });
  $('ensure-workspace').addEventListener('click', () => guarded(ensureWorkspace));
  $('workspace-bind-form').addEventListener('submit', event => { event.preventDefault(); void guarded(bindWorkspace); });
  $('workspace-create-form').addEventListener('submit', event => { event.preventDefault(); void guarded(createWorkspace); });
  $('open-permissions').addEventListener('click', () => changeView('permissions'));
  $('open-recovery').addEventListener('click', () => { changeView('tasks'); $('recovery-panel').scrollIntoView({ block: 'start' }); });
  $('login-form').addEventListener('submit', event => { event.preventDefault(); void guarded(async () => { const token = $('owner-token').value.trim(); $('owner-token').value = ''; const data = await api('/api/session', { token }); unlock(data); await refresh(); notice('Local owner authenticated; obtain a new one-time token after this session expires'); }); });
  $('refresh').addEventListener('click', () => guarded(async () => { await refresh(); if (currentView === 'logs') await showLogs(); }));
  $('refresh-logs').addEventListener('click', () => guarded(showLogs));
  $('logout').addEventListener('click', () => guarded(async () => { if (!mayDiscard()) return; await api('/api/logout', {}); lock(); notice('Signed out; session invalidated and local drafts and results cleared'); }));
  $('stop').addEventListener('click', () => guarded(async () => { if (!confirm('Stop this node? All peer connections will close. Running tasks may need reconciliation; existing effects are not rolled back.')) return; await command({ command: 'shutdown' }); stopped = true; $('connection').textContent = 'Stop requested'; $('connection').className = 'pill off'; notice('Safe shutdown requested. Restart the service and open a new console.'); }));
  $('reload-policy').addEventListener('click', () => guarded(async () => { if (!mayDiscard()) return; if (!confirm('Reload policy from disk? This replaces the current persistent policy and may restore revoked grants. Review the configuration first.')) return; await command({ command: 'reloadPolicy' }); editorInitialized = false; notice('Permissions reloaded from disk; review the active grants'); await refresh(); }));
  $('new-grant').addEventListener('click', () => { resetGrant(); $('grant-editor').scrollIntoView({ block: 'start' }); });
  $('discard-grant').addEventListener('click', () => { if (!mayDiscard()) return; const id = editor.peerId; editor.dirty = false; if (id && policy().grants[id]) editGrant(id, policy().grants[id]); else resetGrant(false); });
  $('add-owner-workspace').addEventListener('click', () => addOwnerWorkspace('workspace'));
  $('add-creation-root').addEventListener('click', () => addOwnerWorkspace('root'));
  for (const [id, tool] of [['owner-list-enabled', 'workspaceList'], ['owner-create-enabled', 'workspaceCreate']]) $(id).addEventListener('input', () => { const input = [...document.querySelectorAll('[name=tool]')].find(item => item.value === tool); input.checked = $(id).checked; });
  $('add-directory').addEventListener('click', () => addDirectory());
  $('grant-form').addEventListener('input', markDirty);
  $('grant-form').addEventListener('change', markDirty);
  document.querySelectorAll('[data-preset]').forEach(button => button.addEventListener('click', () => { const preset = button.dataset.preset, tools = preset === 'clear' ? [] : ['capabilities', ...(preset === 'write' ? FILE_TOOLS : ['readFile', 'readChunk', 'listDirectory', 'searchFiles'])]; document.querySelectorAll('[name=tool]').forEach(input => { input.checked = tools.includes(input.value); }); markDirty(); }));
  $('grant-form').addEventListener('submit', event => { event.preventDefault(); void guarded(saveGrant); });
  $('revoke-grant').addEventListener('click', () => guarded(async () => { const id = editor.peerId; if (!id || !policy().grants[id]) throw new Error('Select an existing caller grant first'); if (!confirm(`Permanently revoke all execution grants for ${id} and cancel related running tasks/jobs? Identity trust remains; existing effects are not rolled back. The current draft will be cleared.`)) return; await command({ command: 'revoke', masterId: id }); editorInitialized = false; notice(`Revoked all execution grants for ${id}`); await refresh(); }));
  $('check-peer').addEventListener('change', updateCheckWorkspaces);
  $('permission-check').addEventListener('submit', event => { event.preventDefault(); const result = fileAccess(checkedGrant(), $('check-tool').value, $('check-path').value); $('check-result').hidden = false; $('check-result').className = `notice ${result.allowed ? '' : 'warn'}`; $('check-result').textContent = `${result.allowed ? 'Allowed by tool and directory grants' : 'Denied'}: ${result.reason}. Execution also requires identity, path safety, limit, and runtime checks.`; });
  for (const id of ['check-peer', 'check-workspace', 'check-tool', 'check-path']) $(id).addEventListener('input', () => { $('check-result').hidden = true; });
  for (const id of ['task-kind', 'task-filter']) $(id).addEventListener('change', renderTasks); $('task-search').addEventListener('input', renderTasks);
  $('task-direction').addEventListener('change', updateTaskFields); $('task-action').addEventListener('change', updateTaskFields);
  $('task-form').addEventListener('submit', event => { event.preventDefault(); void guarded(runTask); });
  $('job-action').addEventListener('change', updateJobFields);
  for (const id of ['job-master', 'job-id', 'job-stream']) $(id).addEventListener('input', () => { jobPage = null; $('job-output-panel').hidden = true; syncButtons(); });
  $('job-form').addEventListener('submit', event => { event.preventDefault(); void guarded(() => runJob()); });
  $('job-next-page').addEventListener('click', () => guarded(() => runJob(true)));
  $('refresh-pairing').addEventListener('click', () => guarded(loadPairing));
  $('pair-request-form').addEventListener('submit', event => { event.preventDefault(); void guarded(() => submitPairing('request')); });
  $('pair-confirm-form').addEventListener('submit', event => { event.preventDefault(); void guarded(() => submitPairing('confirm')); });
  $('log-event').addEventListener('change', renderLogs); $('log-search').addEventListener('input', renderLogs);
  window.addEventListener('beforeunload', event => { if (csrf && editor.dirty) { event.preventDefault(); event.returnValue = ''; } });
  // Remove the one-use bootstrap fragment before the first network request.
  const fragment = new URLSearchParams(location.hash.slice(1)), token = fragment.get('token');
  if (location.hash) history.replaceState(null, '', location.pathname);
  void guarded(async () => { if (token) { const data = await api('/api/session', { token }); unlock(data); await refresh(); } else { try { const data = await api('/api/session'); unlock(data); await refresh(); } catch (error) { lock(); if (!error.message.includes('UNAUTHENTICATED')) notice(error.message, true); } } });
  setInterval(() => { if (csrf && !busy && !stopped && document.visibilityState === 'visible') void guarded(refresh); }, 10000);
}
if (typeof document !== 'undefined') initialize();
