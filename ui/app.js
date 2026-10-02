'use strict';

// Pure helpers are also exercised by Node tests without opening a browser.
export const FILE_TOOLS = ['readFile', 'readChunk', 'listDirectory', 'searchFiles', 'writeFile', 'writeChunk', 'editFile', 'mkdir'];
export const PROCESS_TOOLS = ['exec', 'mcpList', 'mcpCall'];
const MANAGED_FIELDS = ['tools', 'workspace', 'root', 'maxConcurrent', 'maxTimeoutMs', 'execCommands', 'directories', 'allowUnsandboxedProcesses', 'workspaces', 'workspaceProvisioning'];
const ACTIVE_STATES = ['running', 'starting', 'received', 'accepted', 'queued', 'sent', 'dispatching', 'pending'];
export const TOOL_GROUPS = [
  ['文件读取', [['readFile', '读取文件'], ['readChunk', '分块读取'], ['listDirectory', '列出目录'], ['searchFiles', '搜索文件']]],
  ['文件修改', [['writeFile', '写入文件'], ['writeChunk', '分块写入'], ['editFile', '精确编辑'], ['mkdir', '创建目录']]],
  ['受信任进程（不受目录沙箱保护）', [['exec', '固定命令执行'], ['mcpList', '列出 MCP 工具'], ['mcpCall', '调用 MCP 工具']]],
  ['作业管理', [['jobStatus', '读取作业状态'], ['jobOutput', '读取作业输出'], ['jobCancel', '取消作业'], ['jobStdin', '写入进程输入']]],
  ['工作区系统管理', [['workspaceList', '公布工作区与创建根'], ['workspaceCreate', '允许系统创建工作区']]],
  ['资源与基础能力', [['resourceList', '列出批准资源'], ['resourceRead', '读取批准资源'], ['capabilities', '查询已授予能力'], ['echo', '回显测试'], ['wait', '等待测试']]],
];
const TOOL_LABELS = Object.fromEntries(TOOL_GROUPS.flatMap(([, items]) => items));
const STATES = { ready: '可用', unavailable: '不可用', intent: '创建意图待确认', created: '已创建待确认', unknown: '待核对', dispatching: '派发中', pending: '等待中', running: '执行中', starting: '启动中', received: '已接收', accepted: '已接受', queued: '排队中', sent: '已派发', completed: '已完成', succeeded: '成功', failed: '失败', error: '错误', cancelled: '已取消', timed_out: '超时', reconciled: '已人工核对', not_found: '未找到', expired: '记录已过期', rejected: '已拒绝', not_applied: '确认未执行' };
export function stateLabel(value) { return STATES[value] ?? value ?? '未知状态'; }
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
  if (!Array.isArray(rules) || rules.length > 128) throw new Error('目录规则最多 128 条');
  const seen = new Set();
  return rules.map(rule => {
    if (!validRelativePath(rule.path, true)) throw new Error('目录须为规范的相对路径；根目录留空，不能包含 ..、反斜线或绝对路径');
    if (seen.has(rule.path)) throw new Error(`目录规则重复：${rule.path || '工作区根目录'}`);
    if (typeof rule.read !== 'boolean' || typeof rule.write !== 'boolean') throw new Error('每条目录规则须明确指定读写权限');
    seen.add(rule.path); return { path: rule.path, read: rule.read, write: rule.write };
  });
}
export function fileAccess(grant, tool, name) {
  if (!FILE_TOOLS.includes(tool)) return { allowed: false, reason: '请选择内建文件工具' };
  const directory = ['listDirectory', 'searchFiles', 'mkdir'].includes(tool);
  if (!validRelativePath(name, ['listDirectory', 'searchFiles'].includes(tool))) return { allowed: false, reason: '路径格式无效；请使用工作区内的规范相对路径' };
  if (!(grant?.tools ?? []).includes(tool)) return { allowed: false, reason: `未授予 ${TOOL_LABELS[tool]}（${tool}）` };
  if (!grant.workspace && !grant.root) return { allowed: false, reason: '未配置受控工作区' };
  const target = directory ? name : (name.includes('/') ? name.slice(0, name.lastIndexOf('/')) : '');
  const rules = grant.directories;
  if (rules === undefined) return { allowed: true, reason: '整个工作区模式；此工具已授予，未设置目录规则', mode: 'workspace' };
  const rule = [...rules].filter(r => r.path === '' || target === r.path || target.startsWith(`${r.path}/`)).sort((a, b) => b.path.length - a.path.length)[0];
  if (!rule) return { allowed: false, reason: '没有匹配的目录规则，默认拒绝', mode: 'scoped' };
  const read = ['readFile', 'readChunk', 'listDirectory', 'searchFiles', 'editFile'].includes(tool);
  const write = ['writeFile', 'writeChunk', 'editFile', 'mkdir'].includes(tool);
  const allowed = (!read || rule.read) && (!write || rule.write);
  return { allowed, reason: `匹配“${rule.path || '工作区根目录'}”：${scopeLabel(rule)}${tool === 'editFile' ? '；精确编辑需要同时允许读和写' : ''}`, rule, mode: 'scoped' };
}
export function scopeLabel(rule) { return rule.read ? (rule.write ? '读写' : '只读') : (rule.write ? '仅写入' : '禁止读写'); }
export function parseObject(text, label) {
  let value; try { value = JSON.parse(text); } catch { throw new Error(`${label}不是有效 JSON`); }
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error(`${label}必须是 JSON 对象`);
  return value;
}
export function buildGrant(existing, fields) {
  const extra = parseObject(fields.extra, '其他授权字段');
  if (Object.keys(extra).some(key => MANAGED_FIELDS.includes(key))) throw new Error('高级字段不能重复定义工具、工作区、目录规则、基础限额或进程确认，请使用上方表单');
  const grant = { ...structuredClone(existing ?? {}), ...extra, tools: [...fields.tools], maxConcurrent: fields.maxConcurrent, maxTimeoutMs: fields.maxTimeoutMs, execCommands: parseObject(fields.commands, '固定命令别名') };
  delete grant.root;
  if (fields.workspace && fields.mode !== 'none') grant.workspace = fields.workspace; else delete grant.workspace;
  if (!Number.isInteger(grant.maxConcurrent) || grant.maxConcurrent < 1 || grant.maxConcurrent > 32) throw new Error('并发任务上限须为 1–32 的整数');
  if (!Number.isInteger(grant.maxTimeoutMs) || grant.maxTimeoutMs < 10 || grant.maxTimeoutMs > 86400000) throw new Error('超时上限须为 10–86400000 毫秒的整数');
  if (fields.mode === 'scoped') {
    if (!grant.workspace) throw new Error('按目录限制需要填写本机受控工作区');
    grant.directories = validateDirectories(fields.directories);
    grant.allowUnsandboxedProcesses = fields.allowUnsandboxed === true;
    if (grant.tools.some(tool => PROCESS_TOOLS.includes(tool)) && !grant.allowUnsandboxedProcesses) throw new Error('exec / MCP 可越过目录边界，须先勾选明确允许未隔离进程的确认');
  } else {
    delete grant.directories; delete grant.allowUnsandboxedProcesses;
  }
  if (grant.tools.some(tool => FILE_TOOLS.includes(tool) || ['exec', 'mcpList', 'mcpCall', 'resourceRead', 'resourceList'].includes(tool)) && !grant.workspace) throw new Error('所选文件、资源或执行工具需要受控工作区');
  return grant;
}
export function filterRecords(items, filter = 'all', search = '') {
  const query = search.trim().toLocaleLowerCase();
  return items.filter(item => (filter === 'all' || (filter === 'unknown' ? item.state === 'unknown' : filter === 'active' ? ACTIVE_STATES.includes(item.state) : !ACTIVE_STATES.includes(item.state) && item.state !== 'unknown')) && [item.taskId, item.id, item.peerId, item.masterId, item.peer, item.tool].some(value => String(value ?? '').toLocaleLowerCase().includes(query)));
}
export function taskCommand({ direction, action, peer, taskId, resolution, note }) {
  const incoming = direction === 'incoming';
  if (!['incoming', 'outgoing'].includes(direction)) throw new Error('请选择有效任务方向');
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(peer) || !/^[a-zA-Z0-9_-]{1,100}$/.test(taskId)) throw new Error('请填写有效的对端与任务 ID');
  if (action === 'events' && !incoming) throw new Error('事件查询仅适用于本机接收任务');
  if (action === 'query' && incoming) throw new Error('远端查询仅适用于远程派发任务');
  const command = { status: incoming ? 'taskStatus' : 'operationStatus', events: 'taskEvents', query: 'query', cancel: incoming ? 'cancelTask' : 'cancel', reconcile: 'reconcile' }[action];
  if (!command) throw new Error('请选择有效任务操作');
  const value = { command, [incoming ? 'masterId' : 'peerId']: peer, taskId };
  if (action === 'reconcile') { if (!note?.trim()) throw new Error('人工核对必须提供独立的外部证据'); if (!['completed', 'not_applied'].includes(resolution)) throw new Error('请选择有效核对结论'); value.resolution = resolution; value.note = note.trim(); }
  return value;
}

const $ = id => document.getElementById(id);
let csrf = null, state = null, busy = false, stopped = false, online = false, expiresAt = null, currentView = 'overview';
let workspaceCatalog = null; const pendingCreations = new Map();
let editor = { peerId: null, epoch: null, dirty: false }, editorInitialized = false, directorySerial = 0, logs = [], jobPage = null;
const headings = { overview: '节点总览', workspaces: '工作区映射', tasks: '任务与核对', permissions: '目录与权限', identity: '身份与配对', logs: '审计日志' };
const ERRORS = { UNAUTHENTICATED: '会话已到期或令牌无效，请重新验证本机所有者', POLICY_CONFLICT: '权限版本已变化；草稿已保留，请放弃草稿并重新读取后编辑', DIRECTORY_DENIED: '此目录没有所需的读写授权', TASK_POLICY_CHANGED: '权限已更新；旧任务/作业结果需要本机所有者检查', CSRF_DENIED: '会话验证失败，请退出后重新登录', RATE_LIMITED: '尝试过于频繁，请稍后重试' };
function notice(message, error = false) { $('notice').hidden = false; $('notice').textContent = message; $('notice').className = `notice${error ? ' error' : ''}`; $('notice').setAttribute('role', error ? 'alert' : 'status'); }
function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function empty(container, text) { container.replaceChildren(el('div', text, 'empty')); }
function rowContent(id, detail) { const div = el('div'); div.append(el('strong', id), el('small', detail)); return div; }
function statusPill(value) { return el('span', stateLabel(value), `pill ${Object.hasOwn(STATES, value) ? value : 'off'}`); }
function fillDl(root, entries) { root.replaceChildren(); for (const [key, value] of entries) root.append(el('dt', key), el('dd', String(value ?? '—'))); }
function formatTime(value) { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('zh-CN', { hour12: false }); }
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
  catch { online = false; $('connection').textContent = '连接中断 · 状态可能过期'; $('connection').className = 'pill off'; throw new Error(value !== undefined && route === '/api/command' ? '请求结果未确认，请先刷新并检查状态，不要重复提交有副作用的操作' : '无法连接本机节点，请检查进程是否仍在运行'); }
  let data; try { data = await response.json(); } catch { throw new Error('节点返回了无法读取的响应，请刷新确认状态'); }
  if (!response.ok || data.ok === false) { const code = data.error?.code; if (code === 'UNAUTHENTICATED') lock(); throw new Error(`${ERRORS[code] ?? data.error?.message ?? '请求失败'}（${code ?? response.status}）`); }
  return data;
}
async function command(value) { if (!csrf || stopped) throw new Error('请先验证运行中的本机节点'); return (await api('/api/command', value)).result; }
function lock() {
  csrf = null; state = null; online = false; workspaceCatalog = null; pendingCreations.clear(); logs = []; jobPage = null; editorInitialized = false; editor = { peerId: null, epoch: null, dirty: false };
  $('login').hidden = false; $('workspace').hidden = true; $('logout').hidden = true; $('owner-token').value = '';
  $('connection').textContent = '尚未验证'; $('connection').className = 'pill off'; $('node-context').textContent = '先验证本机所有者身份';
  document.querySelectorAll('#workspace form').forEach(form => form.reset());
  for (const id of ['local-workspace-creations', 'owner-workspaces', 'owner-creation-roots', 'workspace-bindings', 'workspace-auto-rules', 'catalog-summary', 'auto-root-summary', 'workspace-result', 'policy-json', 'grant-list', 'directory-rules', 'grant-preview', 'peers', 'incoming-peers', 'runtime', 'task-rows', 'job-rows', 'task-result', 'job-result', 'task-result-summary', 'job-result-summary', 'job-output-text', 'job-output-meta', 'recovery-list', 'identity-summary', 'trusted-peers', 'pair-result', 'pair-result-summary', 'logs-output', 'log-rows', 'check-result']) $(id).replaceChildren();
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
  $('connection').textContent = '本机所有者已验证'; $('connection').className = 'pill';
  if (!editorInitialized) resetGrant(false);
  render(); $('last-updated').textContent = `上次更新 ${formatTime(Date.now())}`;
  $('session-expiry').textContent = expiresAt ? `会话到期 ${formatTime(expiresAt)}` : '';
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
  $('node-id').textContent = status.id; $('node-agent').textContent = status.agent ? `出站代理：${status.agent}` : '纯接收节点 · 未配置出站代理';
  $('node-context').textContent = `${status.id} · 本机管理 · 策略版本 ${epoch()}`;
  $('peer-count').textContent = `${(status.peers ?? []).filter(peer => peer.connected).length} / ${(status.peers ?? []).length}`;
  $('active-count').textContent = status.active ?? 0;
  const unknown = (status.unknownIncoming ?? records('incoming').filter(r => r.state === 'unknown').length) + (status.unknownOutgoing ?? records('outgoing').filter(r => r.state === 'unknown').length) + (state.jobs?.jobs ?? []).filter(job => job.state === 'unknown').length + (state.workspaces?.creations ?? []).filter(item => item.state === 'unknown').length;
  $('unknown-count').textContent = unknown; $('nav-unknown').textContent = unknown; $('nav-unknown').hidden = !unknown;
  $('health-warning').hidden = !status.storageFailed; $('health-warning').textContent = '持久存储故障：请先检查本机磁盘与日志，不要把缺少记录当作未执行的证据';
  $('peers').replaceChildren();
  for (const peer of status.peers ?? []) { const row = el('div', undefined, 'peer-row'); row.append(rowContent(`${status.id} → ${peer.id}`, '远端目录与工具权限须在对端控制台查看'), el('span', peer.connected ? '已连接' : '未连接', `pill${peer.connected ? '' : ' off'}`)); $('peers').append(row); }
  if (!status.peers?.length) empty($('peers'), '未配置出站关系；此节点仍可接收已授权的工作');
  $('incoming-peers').replaceChildren();
  for (const [id, grant] of Object.entries(p.grants)) { const row = el('div', undefined, 'peer-row'); row.append(rowContent(`${id} → ${status.id}`, `${grant.tools?.length ?? 0} 个工具 · ${grant.directories === undefined ? '整个工作区' : `${grant.directories.length} 条目录规则`}`), el('span', trusted.has(id) ? '已授权' : '缺少有效身份', `pill${trusted.has(id) ? '' : ' off'}`)); $('incoming-peers').append(row); }
  if (!Object.keys(p.grants).length) empty($('incoming-peers'), '没有调用方授权；所有入站工具调用默认拒绝');
  fillDl($('runtime'), [['加密传输', status.transport], ['节点监听端口', status.port], ['持久账本', status.durable ? '已启用' : '未启用'], ['策略版本', epoch()], ['本机任务记录', status.taskRecords], ['结果缓存', `${status.cacheBytes ?? 0} 字节`]]);
  renderGrants(trusted); renderWorkspaces(); renderIdentity(); renderTasks(); renderJobs(); renderRecovery(); renderEditorStatus();
}
function renderScopes(container, grant) {
  if (grant.directories === undefined) { container.append(el('span', '整个工作区 · 无目录细分', 'scope-chip')); return; }
  if (!grant.directories.length) { container.append(el('span', '所有文件路径均拒绝', 'scope-chip block')); return; }
  for (const rule of grant.directories) container.append(el('span', `${rule.path || '/（工作区根目录）'} · ${scopeLabel(rule)}`, `scope-chip${!rule.read && !rule.write ? ' block' : ''}`));
}
function renderGrants(trusted) {
  const p = policy(); $('grant-list').replaceChildren();
  for (const [id, grant] of Object.entries(p.grants)) {
    const card = el('article', undefined, 'grant-card'), heading = el('div', undefined, 'section-heading'), actions = el('div', undefined, 'inline-actions compact');
    heading.append(el('h3', id)); const edit = el('button', '编辑授权', 'secondary'); edit.addEventListener('click', () => editGrant(id, grant)); actions.append(edit); heading.append(actions); card.append(heading);
    card.append(el('p', `${trusted.has(id) ? '身份已信任' : '身份未生效，不能仅凭此授权执行'} · 工作区：${grant.workspace ?? grant.root ?? '无文件工作区'}`, 'muted'));
    const scopes = el('div', undefined, 'grant-scopes'); renderScopes(scopes, grant); card.append(scopes);
    card.append(el('p', `工具：${(grant.tools ?? []).map(tool => TOOL_LABELS[tool] ?? tool).join(' · ') || '无（全部拒绝）'}`, 'grant-tools'));
    card.append(el('p', `并发 ≤ ${grant.maxConcurrent ?? 1} · 超时 ≤ ${grant.maxTimeoutMs ?? 2000} ms`, 'muted'));
    const processTools = (grant.tools ?? []).filter(tool => PROCESS_TOOLS.includes(tool));
    if (processTools.length) card.append(el('p', `${processTools.join(' / ')} 是未隔离的受信任宿主进程，可访问目录规则之外的资源`, 'notice warn'));
    if (grant.workspaces) card.append(el('p', `命名工作区：${Object.keys(grant.workspaces).join('、')}`, 'muted'));
    if (grant.workspaceProvisioning) card.append(el('p', `批准创建根：${Object.keys(grant.workspaceProvisioning.roots ?? {}).join('、')} · ${grant.tools?.includes('workspaceCreate') ? '创建已允许' : '创建工具关闭'}`, 'muted'));
    $('grant-list').append(card);
  }
  if (!Object.keys(p.grants).length) empty($('grant-list'), '尚无有效授权。新增授权从明确的目录范围开始。');
  $('policy-version').textContent = `当前策略版本 ${epoch()} · ${Object.keys(p.grants).length} 个调用方 · 此列表为正在生效的权限`;
  $('revoked-summary').textContent = state.permissions?.revoked?.length ? `已撤销：${state.permissions.revoked.join('、')}。编辑其他调用方不会恢复这些授权。` : '';
  $('policy-json').textContent = JSON.stringify({ ...p, revokedPeerIds: state.permissions?.revoked ?? [] }, null, 2);
  const selection = $('check-peer').value; $('check-peer').replaceChildren();
  for (const id of Object.keys(p.grants)) { const option = el('option', id); option.value = id; $('check-peer').append(option); }
  if (p.grants[selection]) $('check-peer').value = selection;
  updateCheckWorkspaces();
  $('known-peers').replaceChildren(); for (const id of trusted) { const option = el('option'); option.value = id; $('known-peers').append(option); }
}
function updateCheckWorkspaces() {
  const selection = $('check-workspace').value, grant = policy().grants[$('check-peer').value]; $('check-workspace').replaceChildren();
  const items = [['default', '默认工作区'], ...Object.keys(grant?.workspaces ?? {}).map(id => [id, `命名工作区 · ${id}`])];
  for (const [id, label] of items) { const option = el('option', label); option.value = id; $('check-workspace').append(option); }
  if (items.some(([id]) => id === selection)) $('check-workspace').value = selection; $('check-result').hidden = true;
}
function checkedGrant() { const grant = policy().grants[$('check-peer').value]; return $('check-workspace').value === 'default' ? grant : grant?.workspaces?.[$('check-workspace').value]; }
function renderIdentity() {
  const identity = state.identity ?? {};
  fillDl($('identity-summary'), [['节点 ID', identity.nodeId], ['到期时间', formatTime(identity.validTo)], ['剩余天数', identity.expiresInDays], ['SHA-256', identity.fingerprint256]]);
  $('trusted-peers').replaceChildren();
  for (const peer of identity.trustedPeers ?? []) {
    const row = el('div', undefined, 'trust-row'), info = rowContent(peer.id, `${peer.pins.length} 个已固定指纹`), actions = el('div', undefined, 'trust-actions');
    for (const pin of peer.pins) {
      info.append(el('code', pin));
      if (peer.pins.length > 1) { const button = el('button', `移除 …${pin.slice(-8)}`, 'secondary'); button.addEventListener('click', () => guarded(async () => { if (!confirm(`移除 ${peer.id} 的指纹 ${pin}？现有连接将关闭，旧证书无法再次通过身份验证。`)) return; await command({ command: 'removePeerPin', peerId: peer.id, fingerprint: pin }); notice(`已移除 ${peer.id} 的所选指纹`); await refresh(); })); actions.append(button); }
    }
    const button = el('button', '撤销身份', 'danger'); button.addEventListener('click', () => guarded(async () => { if (!confirm(`撤销 ${peer.id} 的信任、连接和所有执行权限？撤销会持久保存，运行任务/作业将取消。`)) return; await command({ command: 'revokePeer', peerId: peer.id }); notice(`已撤销 ${peer.id} 的身份与授权`); await refresh(); })); actions.append(button); row.append(info, actions); $('trusted-peers').append(row);
  }
  if (!identity.trustedPeers?.length) empty($('trusted-peers'), '尚未固定任何对端身份');
}
function tableEmpty(root, message) { const row = el('tr'), cell = el('td', message, 'empty'); cell.colSpan = 5; row.append(cell); root.append(row); }
function renderTasks() {
  const kind = $('task-kind').value, all = records(kind), filtered = filterRecords(all, $('task-filter').value, $('task-search').value); $('task-rows').replaceChildren();
  $('task-count').textContent = `显示 ${filtered.length} / ${all.length} 条已加载记录`;
  for (const record of filtered) {
    const peerId = record.peerId ?? record.masterId ?? record.peer ?? '—', taskId = record.taskId ?? record.id ?? '—', row = el('tr'), idCell = el('td'); idCell.append(rowContent(taskId, formatTime(record.updatedAt ?? record.createdAt))); row.append(idCell, el('td', peerId));
    const status = el('td'); status.append(statusPill(record.state ?? record.status)); row.append(status, el('td', TOOL_LABELS[record.tool] ?? record.tool ?? '—'));
    const cell = el('td'), button = el('button', '查看任务', 'secondary'); button.addEventListener('click', () => selectTask(kind, peerId, taskId)); cell.append(button); row.append(cell); $('task-rows').append(row);
  }
  if (!filtered.length) tableEmpty($('task-rows'), all.length ? '没有符合筛选条件的任务' : '此方向暂无任务记录');
}
function renderJobs() {
  $('job-rows').replaceChildren();
  for (const job of state.jobs?.jobs ?? []) {
    const row = el('tr'), id = el('td'); id.append(rowContent(job.jobId, job.taskId ? `原始任务：${job.taskId}` : '未记录原始任务 ID')); row.append(id, el('td', job.masterId)); const status = el('td'); status.append(statusPill(job.state)); row.append(status, el('td', job.command)); const cell = el('td'), button = el('button', '查看作业', 'secondary'); button.addEventListener('click', () => selectJob(job)); cell.append(button); row.append(cell); $('job-rows').append(row);
  }
  if (!(state.jobs?.jobs ?? []).length) tableEmpty($('job-rows'), '暂无后台作业');
}
function renderRecovery() {
  $('recovery-list').replaceChildren(); let count = 0;
  for (const job of state.jobs?.jobs ?? []) if (job.state === 'unknown') { count++; const row = el('div', undefined, 'recovery-row'), button = el('button', '检查作业', 'secondary'); row.append(rowContent(job.jobId, `后台作业 · ${job.masterId} · 原始任务 ${job.taskId ?? '未记录'}`)); button.addEventListener('click', () => selectJob(job)); row.append(button); $('recovery-list').append(row); }
  for (const kind of ['incoming', 'outgoing']) for (const record of records(kind)) if (record.state === 'unknown') { count++; const peer = record.peerId ?? record.masterId ?? record.peer, id = record.taskId ?? record.id, row = el('div', undefined, 'recovery-row'), button = el('button', kind === 'outgoing' ? '查询远端' : '检查任务', 'secondary'); row.append(rowContent(id, `${kind === 'incoming' ? '本机接收' : '远程派发'} · ${peer}`)); button.addEventListener('click', () => selectTask(kind, peer, id, kind === 'outgoing' ? 'query' : 'status')); row.append(button); $('recovery-list').append(row); }
  for (const creation of state.workspaces?.creations ?? []) if (creation.state === 'unknown') { count++; const row = el('div', undefined, 'recovery-row'), button = el('button', '核对创建', 'secondary'); row.append(rowContent(creation.id, `工作区创建 · ${creation.masterId} · ${creation.rootId}/${creation.name}`)); button.addEventListener('click', () => { changeView('workspaces'); $('creation-master').value = creation.masterId; $('creation-id').value = creation.id; $('creation-note').value = ''; $('creation-recovery').open = true; $('creation-recovery').scrollIntoView({ block: 'start' }); }); row.append(button); $('recovery-list').append(row); }
  $('recovery-count').textContent = `${count} 条已加载待核对记录`;
  if (!count) empty($('recovery-list'), '已加载记录中没有未知结果；更早任务仍可通过 ID 查询');
}
function selectTask(direction, peer, id, action = 'status') {
  changeView('tasks', false); $('task-direction').value = direction; $('task-peer').value = peer; $('task-id').value = id; $('task-action').value = action; $('reconcile-note').value = ''; updateTaskFields(); $('task-result-summary').replaceChildren(); $('task-result').textContent = '尚未查询此任务'; $('task-detail').scrollIntoView({ block: 'start' }); $('task-id').focus({ preventScroll: true });
}
function selectJob(job) {
  changeView('tasks', false); $('job-master').value = job.masterId; $('job-id').value = job.jobId; $('job-action').value = 'jobStatus'; $('job-offset').value = '0'; $('job-note').value = ''; jobPage = null; updateJobFields(); $('job-result-summary').replaceChildren(); $('job-result').textContent = '尚未查询此作业'; $('job-output-panel').hidden = true; $('job-detail').scrollIntoView({ block: 'start' }); $('job-id').focus({ preventScroll: true }); syncButtons();
}
function renderEditorStatus() {
  const stale = editor.epoch !== null && editor.epoch !== epoch();
  $('policy-conflict').hidden = !stale;
  $('draft-state').textContent = stale ? '版本冲突 · 草稿保留' : editor.dirty ? `未保存 · 基于版本 ${editor.epoch}` : editor.peerId ? `编辑中 · 版本 ${editor.epoch}` : '新授权草稿';
}
function markDirty() { if (editor.epoch === null) editor.epoch = epoch(); editor.dirty = true; renderEditorStatus(); renderGrantPreview(); syncButtons(); }
function mayDiscard() { return !editor.dirty || confirm('放弃当前尚未保存的授权草稿？'); }
function resetGrant(check = true) {
  if (check && !mayDiscard()) return;
  $('grant-form').reset(); $('grant-peer').readOnly = false; $('grant-peer').value = ''; $('grant-workspace').value = ''; $('grant-concurrency').value = '1'; $('grant-timeout').value = '2000'; $('exec-commands').value = '{}'; $('grant-extra').value = '{}'; $('directory-mode').value = 'scoped'; $('allow-unsandboxed').checked = false;
  document.querySelectorAll('[name=tool]').forEach(input => { input.checked = ['capabilities', 'readFile', 'readChunk', 'listDirectory', 'searchFiles'].includes(input.value); });
  $('owner-workspaces').replaceChildren(); $('owner-creation-roots').replaceChildren();
  $('directory-rules').replaceChildren(); editor = { peerId: null, epoch: state ? epoch() : null, dirty: false }; editorInitialized = true; $('grant-title').textContent = '新增调用方授权'; $('advanced-grant').open = false; updateDirectoryMode(); renderEditorStatus(); renderGrantPreview(); syncButtons();
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
  $('grant-title').textContent = `编辑 ${id} 的授权`; updateDirectoryMode(); renderEditorStatus(); renderGrantPreview(); syncButtons(); $('grant-editor').scrollIntoView({ block: 'start' }); $('grant-workspace').focus({ preventScroll: true });
}
function addDirectory(rule = { path: '', read: false, write: false }, focus = true) {
  if ($('directory-rules').children.length >= 128) { notice('目录规则最多 128 条', true); return; }
  const row = el('div', undefined, 'directory-row'), pathLabel = el('label', '相对目录'), input = el('input'); input.dataset.rulePath = ''; input.value = rule.path; input.placeholder = '例如 docs；留空表示根目录'; input.autocomplete = 'off'; pathLabel.append(input); row.append(pathLabel);
  for (const [access, label] of [['read', '允许读'], ['write', '允许写']]) { const wrapper = el('label', undefined, 'checkbox'), check = el('input'); check.type = 'checkbox'; check.dataset[access] = ''; check.checked = rule[access] === true; check.id = `directory-${++directorySerial}-${access}`; wrapper.append(check, el('span', label)); row.append(wrapper); }
  const remove = el('button', '删除规则', 'danger'); remove.type = 'button'; remove.title = '删除后恢复父目录规则的继承，可能重新允许访问'; remove.addEventListener('click', () => { if (!confirm(`删除“${input.value || '工作区根目录'}”规则？删除会恢复父目录继承，可能重新允许访问。若要禁止此目录，请保留规则并取消读和写。`)) return; row.remove(); markDirty(); updateDirectoryMode(); }); row.append(remove); $('directory-rules').append(row); if (focus) { markDirty(); input.focus(); } updateDirectoryMode();
}
function readDirectoryRows() { return [...$('directory-rules').children].map(row => ({ path: row.querySelector('[data-rule-path]').value, read: row.querySelector('[data-read]').checked, write: row.querySelector('[data-write]').checked })); }
function updateDirectoryMode() {
  const scoped = $('directory-mode').value === 'scoped', none = $('directory-mode').value === 'none'; $('grant-workspace').disabled = none; $('directory-section').hidden = !scoped; $('legacy-warning').hidden = scoped; $('legacy-warning').textContent = none ? '默认文件工作区关闭；只可使用下方独立配置的命名工作区或创建根模板。请取消默认文件与进程工具，仅保留所需工作区管理能力。' : '整个工作区内的文件工具均只受工具开关限制，没有更细的目录规则。'; $('no-directories').hidden = $('directory-rules').children.length > 0;
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
    const grant = grantFromForm(); root.append(el('p', `调用方：${$('grant-peer').value.trim() || '尚未填写'} → ${state?.status?.id ?? '本机'} · ${grant.tools.length} 个工具`));
    const scopes = el('div', undefined, 'grant-scopes'); renderScopes(scopes, grant); root.append(scopes);
    root.append(el('p', `工作区：${grant.workspace ?? '无'} · 并发 ${grant.maxConcurrent} · 超时 ${grant.maxTimeoutMs} ms`));
    if (grant.workspaces) root.append(el('p', `独立工作区：${Object.keys(grant.workspaces).join('、')}`));
    if (grant.workspaceProvisioning) root.append(el('p', `允许创建根：${Object.entries(grant.workspaceProvisioning.roots).map(([id, item]) => `${id}（上限 ${item.maxWorkspaces}）`).join('、')} · ${grant.tools.includes('workspaceCreate') ? '已授予创建工具' : '创建工具关闭，不会自动创建'}`));
    if (!grant.tools.length) root.append(el('p', '未选任何工具，目录允许也不能执行。'));
    if (grant.tools.includes('editFile')) root.append(el('p', '精确编辑需要目标目录同时允许读和写。'));
    if (grant.tools.some(tool => PROCESS_TOOLS.includes(tool))) root.append(el('p', '包含受信任宿主进程能力：文件目录范围不是这些进程的沙箱。'));
  } catch (error) { root.append(el('p', error.message, 'muted')); }
}
async function saveGrant() {
  const id = $('grant-peer').value.trim(); if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) throw new Error('请填写有效调用方 ID');
  if (editor.epoch !== epoch()) throw new Error(ERRORS.POLICY_CONFLICT);
  if (!editor.peerId && policy().grants[id]) throw new Error('此调用方已有授权，请先从上方列表选择“编辑授权”，避免意外覆盖');
  const grant = grantFromForm(), next = structuredClone(policy()); next.grants[id] = grant;
  const scopes = grant.directories === undefined ? '整个工作区，无目录细分' : grant.directories.map(rule => `${rule.path || '工作区根目录'}：${scopeLabel(rule)}`).join('\n') || '所有文件路径均拒绝';
  if (!confirm(`保存 ${id} → ${state.status.id} 的持久授权？\n工作区：${grant.workspace ?? '无'}\n工具：${grant.tools.join('、') || '无'}\n目录：\n${scopes}\n${grant.tools.some(tool => PROCESS_TOOLS.includes(tool)) ? '注意：exec / MCP 是可越过目录规则的受信任宿主进程。\n' : ''}命名工作区：${Object.keys(grant.workspaces ?? {}).join('、') || '无'}\n批准创建根：${Object.entries(grant.workspaceProvisioning?.roots ?? {}).map(([name, item]) => `${name} → ${item.path}（上限 ${item.maxWorkspaces}）；工具 ${item.grant.tools.join('、') || '无'}；目录 ${item.grant.directories.map(rule => `${rule.path || '根'}:${scopeLabel(rule)}`).join('、') || '全部拒绝'}${item.grant.tools.some(tool => PROCESS_TOOLS.includes(tool)) ? '；包含未隔离宿主进程' : ''}`).join('\n') || '无'}\n移除创建根或修改模板会停止已有创建工作区的访问授权，文件仍保留。\n策略更新可能中止现有任务和作业；已经发生的效果不会回滚。`)) return;
  await command({ command: 'setPolicy', policy: next, expectedEpoch: editor.epoch }); editor.dirty = false; editorInitialized = false; notice(`已验证并持久保存 ${id} 的授权`); await refresh(); const saved = policy().grants[id]; if (saved) editGrant(id, saved);
}
function updateTaskFields() {
  const incoming = $('task-direction').value === 'incoming';
  for (const option of $('task-action').options) option.disabled = (option.value === 'events' && !incoming) || (option.value === 'query' && incoming);
  if ($('task-action').selectedOptions[0]?.disabled) $('task-action').value = 'status';
  const reconcile = $('task-action').value === 'reconcile'; $('task-reconcile-fields').hidden = !reconcile; $('reconcile-note').required = reconcile;
  $('task-submit').textContent = { status: '读取任务记录', events: '读取任务事件', query: '查询远端结果', cancel: '确认取消任务', reconcile: '审阅并记录核对结论' }[$('task-action').value];
}
function updateJobFields() {
  const action = $('job-action').value; $('job-output-fields').hidden = action !== 'jobOutput'; $('job-reconcile-fields').hidden = action !== 'reconcileJob'; $('job-note').required = action === 'reconcileJob';
  $('job-submit').textContent = { jobStatus: '读取作业状态', jobOutput: '读取这一页输出', jobCancel: '确认停止作业', reconcileJob: '审阅并记录核对结论' }[action];
}
function showResult(prefix, result) {
  $(`${prefix}-result`).textContent = JSON.stringify(result, null, 2);
  const summary = $(`${prefix}-result-summary`); summary.replaceChildren();
  const value = result?.record ?? result?.result ?? result;
  if (value && typeof value === 'object') {
    const stateValue = value.state ?? value.status ?? result.state;
    if (stateValue) summary.append(statusPill(stateValue));
    const entries = [['任务 ID', value.taskId], ['作业 ID', value.jobId], ['调用方', value.masterId ?? value.peerId], ['命令别名', value.command], ['工具', value.tool], ['更新时间', value.updatedAt ? formatTime(value.updatedAt) : undefined], ['退出码', value.exitCode], ['错误码', value.error?.code ?? value.response?.error?.code], ['核对结论', value.resolution ? stateLabel(value.resolution) : undefined], ['节点 ID', value.nodeId], ['到期时间', value.validTo], ['SHA-256', value.fingerprint256]].filter(([, v]) => v !== undefined && v !== null);
    if (entries.length) { const list = el('dl'); fillDl(list, entries); summary.append(list); }
    if (value.events) { const list = el('ol'); for (const event of value.events) list.append(el('li', `${event.seq ?? ''} · ${event.event ?? event.type ?? '事件'} · ${stateLabel(event.state ?? event.status)}`)); summary.append(list); if (!value.events.length) summary.append(el('p', '没有可显示的事件')); }
    if (stateValue === 'unknown' || value.outcomeUnknown) summary.append(el('p', '结果不确定：先独立核实效果，再人工核对。取消、超时与未找到记录均不能证明没有执行。', 'notice warn'));
    if (['not_found', 'expired'].includes(stateValue)) summary.append(el('p', '缺少保留记录不等于未执行，不会自动解除未知效果门禁。', 'notice warn'));
    if (value.requested !== undefined) summary.append(el('p', value.requested ? '已提交取消请求；请继续读取状态确认结果。已产生的效果不会回滚。' : '没有可取消的活动任务；请读取记录确认最终状态。'));
    if (value.restartRequired) summary.append(el('p', '配置已保存，需要按运维流程重启才会扩大信任；尚未添加执行授权。', 'notice warn'));
  }
  if (!summary.children.length) summary.append(el('p', '操作已返回。展开完整响应查看详细信息。'));
}
async function runTask() {
  const action = $('task-action').value, value = taskCommand({ direction: $('task-direction').value, action, peer: $('task-peer').value.trim(), taskId: $('task-id').value.trim(), resolution: $('resolution').value, note: $('reconcile-note').value });
  if (action === 'cancel' && !confirm(`取消 ${value.taskId}？已发生的外部效果不会回滚，最终状态仍需检查。`)) return;
  if (action === 'reconcile' && !confirm(`按独立证据将 ${value.taskId} 标记为“${stateLabel(value.resolution)}”？此操作只记录结论，不会执行或重放任务。`)) return;
  showResult('task', await command(value)); if (['reconcile', 'cancel'].includes(action)) notice('任务操作已返回，请检查下方状态与恢复清单'); await refresh();
}
function jobPageMatches() { return jobPage && jobPage.masterId === $('job-master').value.trim() && jobPage.jobId === $('job-id').value.trim() && jobPage.stream === $('job-stream').value; }
async function runJob(next = false) {
  const input = { command: next ? 'jobOutput' : $('job-action').value, masterId: $('job-master').value.trim(), jobId: $('job-id').value.trim() };
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(input.masterId) || !/^[a-zA-Z0-9_-]{1,100}$/.test(input.jobId)) throw new Error('请填写有效调用方与作业 ID');
  if (input.command === 'jobOutput') { if (next && (!jobPageMatches() || jobPage.eof)) throw new Error('请先读取当前作业的第一页'); input.offset = next ? jobPage.nextOffset : Number($('job-offset').value); if (!Number.isSafeInteger(input.offset) || input.offset < 0) throw new Error('输出偏移须为非负整数'); input.limit = 16384; input.stream = $('job-stream').value; }
  if (input.command === 'jobCancel' && !confirm(`停止后台作业 ${input.jobId}？已经发生的外部效果不会回滚，仍需检查最终状态。`)) return;
  if (input.command === 'reconcileJob') { input.resolution = $('job-resolution').value; input.note = $('job-note').value.trim(); if (!input.note) throw new Error('请填写独立核对依据'); if (!confirm(`将未知作业 ${input.jobId} 核对为“${stateLabel(input.resolution)}”？不会执行或重放命令。随后还需核对原始启动任务。`)) return; }
  const result = await command(input); showResult('job', result);
  if (input.command === 'jobOutput') { jobPage = { ...result, masterId: input.masterId, jobId: input.jobId, stream: input.stream }; $('job-output-panel').hidden = false; $('job-output-text').textContent = result.text || '（此页没有输出）'; $('job-output-meta').textContent = `${input.stream} · 字节 ${result.offset ?? input.offset}–${result.nextOffset} / ${result.totalBytes}${result.eof ? ' · 已到当前末尾' : ''}`; $('job-offset').value = result.nextOffset; }
  else { jobPage = null; $('job-output-panel').hidden = true; }
  await refresh();
}
function pairInput() {
  const input = { peerId: $('pair-id').value.trim(), expectedFingerprint: $('pair-pin').value.trim(), certificatePem: $('pair-cert').value.trim(), outOfBandVerified: $('pair-verified').checked, rotation: $('pair-rotation').checked };
  if ($('pair-host').value.trim()) input.peer = { host: $('pair-host').value.trim(), port: Number($('pair-port').value) };
  if (!$('pair-host').value.trim() && $('pair-port').value) throw new Error('填写出站端口时也需要填写出站 IP');
  return input;
}
async function showLogs() {
  const data = await api('/api/logs'); logs = data.records ?? []; $('logs-output').textContent = data.unavailable ? data.message : logs.map(record => JSON.stringify(record)).join('\n') || '尚无持久审计记录';
  const selected = $('log-event').value; $('log-event').replaceChildren(el('option', '全部事件')); $('log-event').firstElementChild.value = '';
  for (const event of [...new Set(logs.map(record => record.event).filter(Boolean))].sort()) { const option = el('option', event); option.value = event; $('log-event').append(option); }
  if (logs.some(record => record.event === selected)) $('log-event').value = selected;
  renderLogs(); if (data.unavailable) $('log-count').textContent = data.message ?? '未配置持久审计日志';
}
function renderLogs() {
  const query = $('log-search').value.toLocaleLowerCase(), event = $('log-event').value, filtered = logs.filter(record => (!event || record.event === event) && JSON.stringify(record).toLocaleLowerCase().includes(query)); $('log-rows').replaceChildren(); $('log-count').textContent = `显示 ${filtered.length} / ${logs.length} 条已加载元数据记录`;
  for (const record of filtered) { const row = el('tr'); for (const value of [formatTime(record.timestamp ?? record.time), record.event ?? '—', [record.masterId ?? record.peerId ?? record.nodeId, record.taskId, record.jobId].filter(Boolean).join(' / ') || '—', [record.state ? stateLabel(record.state) : record.status, record.error?.code ?? record.code, record.command].filter(Boolean).join(' · ') || '—']) row.append(el('td', value)); $('log-rows').append(row); }
  if (!filtered.length) { const row = el('tr'), cell = el('td', logs.length ? '没有符合筛选条件的日志' : '暂无审计记录', 'empty'); cell.colSpan = 4; row.append(cell); $('log-rows').append(row); }
}
function mountTools() {
  for (const [name, tools] of TOOL_GROUPS) { const group = el('div', undefined, 'tool-group'), list = el('div', undefined, 'tool-choices'); group.append(el('h3', name)); for (const [value, label] of tools) { const wrapper = el('label'), input = el('input'), text = el('span', label); input.type = 'checkbox'; input.name = 'tool'; input.value = value; text.append(el('small', value)); wrapper.append(input, text); list.append(wrapper); } group.append(list); $('tool-groups').append(group); }
  for (const tool of FILE_TOOLS) { const option = el('option', `${TOOL_LABELS[tool]}（${tool}）`); option.value = tool; $('check-tool').append(option); }
}
const ownerTemplateSources = new WeakMap();
function labeledInput(label, key, value = '', options = {}) {
  const wrapper = el('label', label), input = el(options.textarea ? 'textarea' : 'input'); input.dataset[key] = ''; input.value = value;
  for (const [property, item] of Object.entries(options)) if (property !== 'textarea') input[property] = item;
  wrapper.append(input); return { wrapper, input };
}
function addTemplateDirectory(container, rule = { path: '', read: false, write: false }, focus = true) {
  const row = el('div', undefined, 'template-directory-row'); row.dataset.templateRule = '';
  const field = labeledInput('模板相对目录（根目录留空）', 'templatePath', rule.path); row.append(field.wrapper);
  for (const access of ['read', 'write']) { const label = el('label', undefined, 'checkbox'), input = el('input'); input.type = 'checkbox'; input.dataset[access] = ''; input.checked = rule[access] === true; label.append(input, el('span', access === 'read' ? '允许读' : '允许写')); row.append(label); }
  const remove = el('button', '删除规则', 'danger'); remove.type = 'button'; remove.addEventListener('click', () => { if (!confirm('删除模板目录规则会恢复父目录继承，可能重新允许访问。确认删除？若要禁止，请保留规则并取消读和写。')) return; row.remove(); markDirty(); }); row.append(remove); container.append(row); if (focus) { markDirty(); field.input.focus(); }
}
function addOwnerWorkspace(kind, id = '', source = null, focus = true) {
  if ($(kind === 'root' ? 'owner-creation-roots' : 'owner-workspaces').children.length >= (kind === 'root' ? 16 : 32)) { notice(kind === 'root' ? '每个调用方最多 16 个创建根' : '每个调用方最多 32 个命名工作区', true); return; }
  const root = kind === 'root', template = structuredClone(root ? source?.grant ?? {} : source ?? {}), card = el('div', undefined, 'owner-workspace-card'); card.dataset.ownerKind = kind; ownerTemplateSources.set(card, { template, source: structuredClone(source ?? {}) });
  const heading = el('div', undefined, 'section-heading'), remove = el('button', root ? '移除创建根' : '移除工作区授权', 'danger'); remove.type = 'button'; heading.append(el('h3', root ? '批准的本机创建根' : '独立命名工作区'), remove); card.append(heading);
  remove.addEventListener('click', () => { if (!confirm(root ? '从草稿中移除此创建根？保存后会拒绝未来创建，也会停止已有工作区通过此模板的访问授权，文件保留。若只停止新建，请关闭 workspaceCreate 工具。' : '移除此命名工作区授权？保存后拒绝通过该别名执行，文件不会删除。')) return; card.remove(); markDirty(); });
  const basic = el('div', undefined, 'form-grid'), alias = labeledInput(root ? '公开创建根别名' : '公开工作区别名', 'ownerId', id, { required: true, pattern: '[a-zA-Z0-9_-]{1,64}', placeholder: root ? '例如 projects' : '例如 docs' }), path = labeledInput(root ? '本机允许创建的父目录' : '本机现有工作区目录', 'ownerPath', root ? source?.path ?? '' : template.workspace ?? '', { required: true, placeholder: root ? '/srv/node/projects' : '/srv/node/docs' }); basic.append(alias.wrapper, path.wrapper);
  if (root) basic.append(labeledInput('此根最大工作区数量', 'ownerQuota', source?.maxWorkspaces ?? 8, { type: 'number', min: '1', max: '128', required: true }).wrapper);
  card.append(basic);
  const details = el('details'); details.open = true; details.append(el('summary', root ? '新建子工作区继承的授权模板' : '此工作区的独立授权'));
  const choices = el('div', undefined, 'tool-choices'), tools = template.tools ?? ['capabilities', 'readFile', 'readChunk', 'listDirectory', 'searchFiles'];
  for (const [tool, labelText] of Object.entries(TOOL_LABELS)) { if (['workspaceList', 'workspaceCreate'].includes(tool)) continue; const label = el('label'), check = el('input'), text = el('span', labelText); check.type = 'checkbox'; check.name = 'template-tool'; check.value = tool; check.checked = tools.includes(tool); text.append(el('small', tool)); label.append(check, text); choices.append(label); } details.append(choices);
  const modeLabel = el('label', '目录范围'), mode = el('select'); mode.dataset.templateMode = ''; const scoped = el('option', '按目录限制（未匹配默认拒绝）'); scoped.value = 'scoped'; mode.append(scoped);
  if (!root) { const legacy = el('option', '整个工作区（兼容已有授权）'); legacy.value = 'legacy'; mode.append(legacy); }
  mode.value = root || !source || template.directories !== undefined ? 'scoped' : 'legacy'; modeLabel.append(mode); details.append(modeLabel);
  const directoryBox = el('div'); directoryBox.dataset.templateDirectories = ''; for (const rule of template.directories ?? (source ? [] : [{ path: '', read: true, write: false }])) addTemplateDirectory(directoryBox, rule, false); details.append(directoryBox);
  const add = el('button', '＋ 添加模板目录规则', 'secondary'); add.type = 'button'; add.addEventListener('click', () => addTemplateDirectory(directoryBox)); details.append(add, el('p', '规则递归生效，最具体目录优先；清空规则将拒绝所有文件路径。整个工作区模式会忽略这些目录规则。', 'muted'));
  const processNotice = el('div', undefined, 'notice warn'); processNotice.dataset.templateProcessWarning = ''; processNotice.append(el('p', 'exec / MCP 使用宿主进程权限，可访问模板目录规则之外。目录授权不是进程沙箱。')); const processLabel = el('label', undefined, 'checkbox'), allow = el('input'); allow.type = 'checkbox'; allow.dataset.templateUnsandboxed = ''; allow.checked = template.allowUnsandboxedProcesses === true; processLabel.append(allow, el('span', '明确允许已审阅的未隔离宿主进程')); processNotice.append(processLabel); details.append(processNotice);
  const quotas = el('div', undefined, 'form-grid'); quotas.append(labeledInput('模板并发上限', 'templateConcurrency', template.maxConcurrent ?? 1, { type: 'number', min: '1', max: '32', required: true }).wrapper, labeledInput('模板超时上限（毫秒）', 'templateTimeout', template.maxTimeoutMs ?? 2000, { type: 'number', min: '10', max: '86400000', required: true }).wrapper); details.append(quotas);
  const advanced = el('details'), extra = structuredClone(template); for (const key of MANAGED_FIELDS) delete extra[key]; advanced.append(el('summary', '高级模板字段：固定命令、资源与其他限额'), labeledInput('固定命令别名（JSON 对象）', 'templateCommands', JSON.stringify(template.execCommands ?? {}, null, 2), { textarea: true, spellcheck: false }).wrapper, labeledInput('其他模板字段（JSON 对象）', 'templateExtra', JSON.stringify(extra, null, 2), { textarea: true, spellcheck: false }).wrapper); details.append(advanced); card.append(details);
  const update = () => { const process = [...card.querySelectorAll('[name=template-tool]:checked')].some(input => PROCESS_TOOLS.includes(input.value)); processNotice.hidden = !process; directoryBox.hidden = mode.value === 'legacy'; add.hidden = mode.value === 'legacy'; };
  card.addEventListener('input', update); card.addEventListener('change', update); update();
  $(root ? 'owner-creation-roots' : 'owner-workspaces').append(card); if (focus) { markDirty(); alias.input.focus(); }
}
function readOwnerWorkspaces() {
  const workspaces = {}, roots = {};
  for (const container of ['owner-workspaces', 'owner-creation-roots']) for (const card of $(container).children) {
    const root = card.dataset.ownerKind === 'root', id = card.querySelector('[data-owner-id]').value.trim(), workspace = card.querySelector('[data-owner-path]').value.trim();
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id) || (!root && (id === 'default' || id.startsWith('ws_')))) throw new Error('工作区/根别名须为 1–64 位字母、数字、下划线或短横线；命名工作区不能使用 default 或 ws_ 前缀');
    const target = root ? roots : workspaces; if (Object.hasOwn(target, id)) throw new Error(`别名重复：${id}`);
    if (!workspace) throw new Error(`请填写 ${id} 的本机目录`);
    const { template, source } = ownerTemplateSources.get(card), directories = [...card.querySelector('[data-template-directories]').children].map(row => ({ path: row.querySelector('[data-template-path]').value, read: row.querySelector('[data-read]').checked, write: row.querySelector('[data-write]').checked }));
    const grant = buildGrant(template, { workspace, tools: [...card.querySelectorAll('[name=template-tool]:checked')].map(input => input.value), mode: card.querySelector('[data-template-mode]').value, directories, allowUnsandboxed: card.querySelector('[data-template-unsandboxed]').checked, maxConcurrent: Number(card.querySelector('[data-template-concurrency]').value), maxTimeoutMs: Number(card.querySelector('[data-template-timeout]').value), commands: card.querySelector('[data-template-commands]').value, extra: card.querySelector('[data-template-extra]').value });
    delete grant.workspaces; delete grant.workspaceProvisioning;
    // Preserve the exact existing template when defaults were not edited: its raw hash is a safety boundary.
    if (Object.keys(template).length) {
      grant.tools = [...(template.tools ?? []).filter(tool => grant.tools.includes(tool)), ...grant.tools.filter(tool => !(template.tools ?? []).includes(tool))];
      for (const [key, fallback] of [['maxConcurrent', 1], ['maxTimeoutMs', 2000], ['allowUnsandboxedProcesses', false]]) if (!Object.hasOwn(template, key) && grant[key] === fallback) delete grant[key];
      if (!Object.hasOwn(template, 'execCommands') && !Object.keys(grant.execCommands ?? {}).length) delete grant.execCommands;
    }
    if (root) { delete grant.workspace; const maxWorkspaces = Number(card.querySelector('[data-owner-quota]').value); if (!Number.isSafeInteger(maxWorkspaces) || maxWorkspaces < 1 || maxWorkspaces > 128) throw new Error(`创建根 ${id} 的工作区数量须为 1–128 的整数`); target[id] = { ...source, path: workspace, maxWorkspaces, grant }; }
    else target[id] = grant;
  }
  return { workspaces, workspaceProvisioning: { roots } };
}

function bindingState() { return state?.workspaces ?? { revision: 0, bindings: [], autoProvision: [] }; }
function workspaceContext() {
  const logicalWorkspaceId = $('logical-workspace').value.trim(), peerId = $('workspace-peer').value;
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(logicalWorkspaceId) || !peerId) throw new Error('请填写有效逻辑工作区 ID 并选择执行节点');
  return { logicalWorkspaceId, peerId };
}
function catalogMatches() { return workspaceCatalog && workspaceCatalog.peerId === $('workspace-peer').value && workspaceCatalog.logicalWorkspaceId === $('logical-workspace').value.trim(); }
function bindingRevisionMatches() { return catalogMatches() && workspaceCatalog.revision === bindingState().revision; }
function requireBindingRevision() { if (!bindingRevisionMatches()) throw new Error('工作区映射已变化或尚未读取，请重新读取可用工作区后操作'); }
function showWorkspaceResult(message) { $('workspace-result').hidden = false; $('workspace-result').textContent = message; }
function invalidateWorkspaceCatalog() { workspaceCatalog = null; $('workspace-catalog').hidden = true; $('workspace-conflict').hidden = true; $('workspace-result').hidden = true; syncButtons(); }
function renderWorkspaces() {
  const registry = bindingState(), previous = $('workspace-peer').value;
  $('workspace-peer').replaceChildren();
  for (const peer of state.status.peers ?? []) { const option = el('option', `${peer.id}${peer.connected ? ' · 已连接' : ' · 未连接'}`); option.value = peer.id; $('workspace-peer').append(option); }
  if ((state.status.peers ?? []).some(peer => peer.id === previous)) $('workspace-peer').value = previous;
  if (workspaceCatalog && !catalogMatches()) invalidateWorkspaceCatalog();
  $('binding-version').textContent = `本机映射版本 ${registry.revision ?? 0} · ${registry.bindings?.length ?? 0} 个实际绑定`;
  $('workspace-bindings').replaceChildren();
  for (const binding of registry.bindings ?? []) {
    const row = el('div', undefined, 'grant-card'), heading = el('div', undefined, 'section-heading'), action = el('button', '解除绑定', 'danger');
    heading.append(el('h3', `${binding.logicalWorkspaceId} → ${binding.peerId} / ${binding.workspaceId}`), action); row.append(heading, el('p', `已实际绑定 · ${formatTime(binding.updatedAt ?? binding.createdAt)}`, 'muted'));
    const revision = registry.revision;
    action.addEventListener('click', () => guarded(async () => { if (!confirm(`解除 ${binding.logicalWorkspaceId} → ${binding.peerId} / ${binding.workspaceId} 的路由绑定？文件不会删除。若自动准备仍启用，后续系统使用可能再次准备工作区；如需停止，请同时关闭自动规则。`)) return; await command({ command: 'unbindWorkspace', logicalWorkspaceId: binding.logicalWorkspaceId, peerId: binding.peerId, expectedRevision: revision }); showWorkspaceResult('已解除路由绑定，远端文件保留。请检查是否还需要关闭自动准备规则。'); await refresh(); })); $('workspace-bindings').append(row);
  }
  if (!registry.bindings?.length) empty($('workspace-bindings'), '尚无实际绑定。可绑定已有工作区，或启用系统自动准备。');
  renderLocalCreations();
  $('workspace-auto-rules').replaceChildren();
  for (const rule of registry.autoProvision ?? []) {
    const row = el('div', undefined, 'peer-row'), actions = el('div', undefined, 'inline-actions compact'); row.append(rowContent(`${rule.logicalWorkspaceId} → ${rule.peerId}`, `${rule.enabled ? '自动准备已启用' : '自动准备已关闭'} · 创建根 ${rule.rootId}`));
    const edit = el('button', '查看 / 使用', 'secondary'); edit.addEventListener('click', () => { $('logical-workspace').value = rule.logicalWorkspaceId; $('workspace-peer').value = rule.peerId; void guarded(loadWorkspaceCatalog); }); actions.append(edit);
    if (rule.enabled) { const disable = el('button', '关闭自动准备', 'danger'), revision = registry.revision; disable.addEventListener('click', () => guarded(async () => { if (!confirm(`关闭 ${rule.logicalWorkspaceId} → ${rule.peerId} 的自动创建？已有绑定和文件保留。`)) return; await command({ command: 'setWorkspaceAutoProvision', logicalWorkspaceId: rule.logicalWorkspaceId, peerId: rule.peerId, rootId: rule.rootId, enabled: false, expectedRevision: revision }); showWorkspaceResult('已关闭自动准备；已有绑定与文件未删除。'); await refresh(); })); actions.append(disable); }
    row.append(actions); $('workspace-auto-rules').append(row);
  }
  if (!registry.autoProvision?.length) empty($('workspace-auto-rules'), '尚未启用系统自动准备，未绑定的逻辑工作区默认拒绝远程执行。');
  $('workspace-conflict').hidden = !catalogMatches() || bindingRevisionMatches();
}
function renderLocalCreations() {
  $('local-workspace-creations').replaceChildren();
  for (const creation of bindingState().creations ?? []) {
    const row = el('div', undefined, 'peer-row'); row.append(rowContent(`${creation.name} · ${creation.id}`, `调用方 ${creation.masterId} · 创建根 ${creation.rootId}`), creation.state === 'ready' ? el('span', '创建已记录', 'pill') : statusPill(creation.state));
    if (creation.state === 'unknown') { const button = el('button', '核对创建', 'secondary'); button.addEventListener('click', () => { $('creation-master').value = creation.masterId; $('creation-id').value = creation.id; $('creation-note').value = ''; $('creation-recovery').open = true; $('creation-recovery').scrollIntoView({ block: 'start' }); $('creation-note').focus(); }); row.append(button); }
    $('local-workspace-creations').append(row);
  }
  if (!bindingState().creations?.length) empty($('local-workspace-creations'), '本机没有接收过工作区创建请求');
}
async function reconcileCreation() {
  const masterId = $('creation-master').value.trim(), workspaceId = $('creation-id').value.trim(), resolution = $('creation-resolution').value, note = $('creation-note').value.trim();
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(masterId) || !/^[a-zA-Z0-9_-]{1,64}$/.test(workspaceId) || note.length < 3) throw new Error('填写有效调用方、工作区 ID 和至少 3 个字符的独立核对依据');
  if (!confirm(`根据本机独立证据，将 ${masterId} 的 ${workspaceId} 标记为“${resolution === 'completed' ? '已创建完成' : '确认未创建'}”？此操作不会重新创建目录或删除文件。`)) return;
  await command({ command: 'reconcileWorkspaceCreation', masterId, workspaceId, resolution, note }); await refresh(); showWorkspaceResult('未知创建的核对结论已记录；请继续检查原始任务状态与路由绑定。');
}

function catalogItemSummary(item, root = false) {
  const card = el('div', undefined, 'grant-card'); card.append(el('h3', root ? `批准创建根：${item.id}` : `工作区：${item.name ?? item.id}`));
  card.append(el('p', root ? `额度 ${item.used ?? 0} / ${item.maxWorkspaces} · 剩余 ${item.remaining ?? '以服务端校验为准'}` : `标识 ${item.id} · ${{ default: '默认工作区', configured: '所有者配置', provisioned: '系统创建' }[item.kind] ?? item.kind ?? '已授权工作区'}`, 'muted'));
  if (!root && item.state !== 'ready') { card.append(statusPill(item.state ?? 'unavailable'), el('p', '此工作区当前不可用于绑定或执行；请由 servant 本机所有者检查创建记录与授权。', 'notice warn')); return card; }
  card.append(el('p', `继承工具：${(item.tools ?? []).map(tool => TOOL_LABELS[tool] ?? tool).join(' · ') || '未授予工具'}`, 'grant-tools'));
  const scope = el('div', undefined, 'grant-scopes'), filesystem = item.filesystem ?? {}; renderScopes(scope, filesystem.mode === 'scoped' ? { directories: filesystem.directories ?? [] } : {}); card.append(scope);
  if (filesystem.processAccess === 'outside-directory-policy' || (item.tools ?? []).some(tool => PROCESS_TOOLS.includes(tool))) card.append(el('p', '包含未隔离宿主进程，其访问不受文件目录规则限制。', 'notice warn'));
  return card;
}
async function loadWorkspaceCatalog() {
  const context = workspaceContext(), catalog = await command({ command: 'remoteWorkspaces', peerId: context.peerId });
  await refresh(); workspaceCatalog = { ...catalog, ...context, revision: bindingState().revision };
  $('workspace-catalog').hidden = false; $('workspace-conflict').hidden = true; $('catalog-summary').replaceChildren();
  const existing = catalog.workspaces ?? [], roots = catalog.creationRoots ?? [];
  for (const item of existing) $('catalog-summary').append(catalogItemSummary(item));
  for (const item of roots) $('catalog-summary').append(catalogItemSummary(item, true));
  if (!existing.length && !roots.length) empty($('catalog-summary'), '该节点没有公布可用工作区或创建根，请由执行节点所有者授予范围。');
  for (const id of ['existing-workspace', 'auto-root', 'create-root']) $(id).replaceChildren();
  for (const item of existing.filter(item => item.state === 'ready')) { const option = el('option', `${item.name ?? item.id}（${item.id}）`); option.value = item.id; $('existing-workspace').append(option); }
  for (const item of roots) for (const id of ['auto-root', 'create-root']) { const option = el('option', `${item.id} · 剩余 ${item.remaining ?? '待校验'}`); option.value = item.id; $(id).append(option); }
  const rule = (bindingState().autoProvision ?? []).find(item => item.peerId === context.peerId && item.logicalWorkspaceId === context.logicalWorkspaceId);
  $('auto-enabled').checked = rule?.enabled === true;
  if (roots.some(item => item.id === rule?.rootId)) $('auto-root').value = rule.rootId;
  const bound = (bindingState().bindings ?? []).find(item => item.peerId === context.peerId && item.logicalWorkspaceId === context.logicalWorkspaceId);
  if (existing.some(item => item.id === bound?.workspaceId)) $('existing-workspace').value = bound.workspaceId;
  renderAutoRoot(); showWorkspaceResult(`已读取 ${context.peerId} 的可用范围。${bound ? `当前绑定 ${bound.workspaceId}。` : '当前尚无绑定。'}`); syncButtons();
}
function renderAutoRoot() { $('auto-root-summary').replaceChildren(); const root = workspaceCatalog?.creationRoots?.find(item => item.id === $('auto-root').value); if (root) $('auto-root-summary').append(catalogItemSummary(root, true)); }
async function saveWorkspaceAuto() {
  requireBindingRevision(); const context = workspaceContext(), rootId = $('auto-root').value, enabled = $('auto-enabled').checked;
  if (!rootId) throw new Error('尚无可选择的创建根，请先由执行节点所有者配置');
  if (!confirm(`${enabled ? '启用' : '关闭'} ${context.logicalWorkspaceId} → ${context.peerId} 的系统自动准备？\n批准创建根：${rootId}\n${enabled ? '系统首次使用时可能创建目录并建立绑定，继承该根的授权模板和额度。保存规则本身不创建目录。' : '已有绑定与文件保留。'}`)) return;
  await command({ command: 'setWorkspaceAutoProvision', ...context, rootId, enabled, expectedRevision: workspaceCatalog.revision }); await loadWorkspaceCatalog(); showWorkspaceResult(enabled ? '自动准备规则已保存；尚未因此创建新工作区。可点击“现在准备 / 使用”，或由首次系统派发自动准备。' : '自动准备已关闭；已有绑定与文件保留。');
}
async function ensureWorkspace() {
  requireBindingRevision(); const context = workspaceContext(), exists = (bindingState().bindings ?? []).find(item => item.peerId === context.peerId && item.logicalWorkspaceId === context.logicalWorkspaceId);
  if (!exists && !confirm(`现在准备 ${context.logicalWorkspaceId} → ${context.peerId}？若尚无绑定，系统会依据已保存的自动规则，在执行节点批准根中创建并继承模板权限。`)) return;
  const result = await command({ command: 'ensureWorkspaceBinding', ...context }); await loadWorkspaceCatalog(); const binding = result.binding ?? result; showWorkspaceResult(`系统绑定已确认：${binding.workspaceId ?? '请查看当前实际绑定'}。后续使用复用此绑定，实际执行仍须通过仆从当前授权检查。`);
}
async function bindWorkspace() {
  requireBindingRevision(); const context = workspaceContext(), workspaceId = $('existing-workspace').value;
  if (!workspaceId || !workspaceCatalog.workspaces?.some(item => item.id === workspaceId)) throw new Error('请从执行节点公布的工作区中选择');
  if (!confirm(`将 ${context.logicalWorkspaceId} 绑定到 ${context.peerId} / ${workspaceId}？后续远程任务使用此工作区，原工作区文件不会移动或删除。`)) return;
  await command({ command: 'bindWorkspace', ...context, workspaceId, expectedRevision: workspaceCatalog.revision }); await loadWorkspaceCatalog(); showWorkspaceResult('已绑定所选工作区，后续逻辑工作区派发使用此映射。');
}
async function createWorkspace() {
  requireBindingRevision(); const context = workspaceContext(), rootId = $('create-root').value, name = $('create-workspace-name').value.trim();
  if (!rootId || !workspaceCatalog.creationRoots?.some(root => root.id === rootId)) throw new Error('请选择执行节点公布的创建根');
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i.test(name)) throw new Error('工作区名称须为 1–64 位字母、数字、下划线或短横线，且首位为字母或数字');
  const target = JSON.stringify({ ...context, rootId, name });
  if (!pendingCreations.has(target)) { if (pendingCreations.size >= 128) throw new Error('本页创建请求已达安全上限，请先核对现有请求后重新打开控制台'); pendingCreations.set(target, `ui_${crypto.randomUUID()}`); }
  if (!confirm(`在 ${context.peerId} 批准根 ${rootId} 中创建“${name}”并绑定 ${context.logicalWorkspaceId}？新工作区继承该根的工具、目录范围和限额。`)) return;
  await command({ command: 'createWorkspace', ...context, rootId, name, creationRequestId: pendingCreations.get(target), expectedRevision: workspaceCatalog.revision }); $('create-workspace-name').value = ''; await loadWorkspaceCatalog(); showWorkspaceResult('工作区已创建并绑定；权限继承执行节点所有者配置的模板。');
}

export function initialize() {
  mountTools(); updateTaskFields(); updateJobFields();
  document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => { changeView(button.dataset.view); if (currentView === 'logs' && csrf) void guarded(showLogs); }));
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
  $('login-form').addEventListener('submit', event => { event.preventDefault(); void guarded(async () => { const token = $('owner-token').value.trim(); $('owner-token').value = ''; const data = await api('/api/session', { token }); unlock(data); await refresh(); notice('已验证本机所有者；会话到期后需重新获取一次性令牌'); }); });
  $('refresh').addEventListener('click', () => guarded(async () => { await refresh(); if (currentView === 'logs') await showLogs(); }));
  $('refresh-logs').addEventListener('click', () => guarded(showLogs));
  $('logout').addEventListener('click', () => guarded(async () => { if (!mayDiscard()) return; await api('/api/logout', {}); lock(); notice('已退出，会话已失效；本页授权草稿与结果已清除'); }));
  $('stop').addEventListener('click', () => guarded(async () => { if (!confirm('确定停止此节点？全部对端连接将断开。正在执行的任务可能需要核对；已发生的效果不会回滚。')) return; await command({ command: 'shutdown' }); stopped = true; $('connection').textContent = '已请求停止'; $('connection').className = 'pill off'; notice('已请求安全停止。请重新启动服务后打开新的控制台。'); }));
  $('reload-policy').addEventListener('click', () => guarded(async () => { if (!mayDiscard()) return; if (!confirm('从磁盘配置重新加载策略？这会替换当前持久策略，并可能恢复已撤销权限。请先审查配置文件。')) return; await command({ command: 'reloadPolicy' }); editorInitialized = false; notice('已从磁盘重新加载权限，请核对当前有效授权'); await refresh(); }));
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
  $('revoke-grant').addEventListener('click', () => guarded(async () => { const id = editor.peerId; if (!id || !policy().grants[id]) throw new Error('先选择已有调用方授权'); if (!confirm(`持久撤销 ${id} 的全部执行权限并取消相关运行任务/作业？此调用方的身份信任仍保留；已发生的效果不会回滚。当前草稿会清除。`)) return; await command({ command: 'revoke', masterId: id }); editorInitialized = false; notice(`已撤销 ${id} 的全部执行权限`); await refresh(); }));
  $('check-peer').addEventListener('change', updateCheckWorkspaces);
  $('permission-check').addEventListener('submit', event => { event.preventDefault(); const result = fileAccess(checkedGrant(), $('check-tool').value, $('check-path').value); $('check-result').hidden = false; $('check-result').className = `notice ${result.allowed ? '' : 'warn'}`; $('check-result').textContent = `${result.allowed ? '工具与目录交集允许' : '拒绝'}：${result.reason}。实际执行还须通过身份、路径安全、限额和运行门禁。`; });
  for (const id of ['check-peer', 'check-workspace', 'check-tool', 'check-path']) $(id).addEventListener('input', () => { $('check-result').hidden = true; });
  for (const id of ['task-kind', 'task-filter']) $(id).addEventListener('change', renderTasks); $('task-search').addEventListener('input', renderTasks);
  $('task-direction').addEventListener('change', updateTaskFields); $('task-action').addEventListener('change', updateTaskFields);
  $('task-form').addEventListener('submit', event => { event.preventDefault(); void guarded(runTask); });
  $('job-action').addEventListener('change', updateJobFields);
  for (const id of ['job-master', 'job-id', 'job-stream']) $(id).addEventListener('input', () => { jobPage = null; $('job-output-panel').hidden = true; syncButtons(); });
  $('job-form').addEventListener('submit', event => { event.preventDefault(); void guarded(() => runJob()); });
  $('job-next-page').addEventListener('click', () => guarded(() => runJob(true)));
  $('review-peer').addEventListener('click', () => guarded(async () => { showResult('pair', await command({ command: 'reviewPeer', ...pairInput() })); }));
  $('pair-form').addEventListener('submit', event => { event.preventDefault(); void guarded(async () => { const input = pairInput(); if (!input.outOfBandVerified) throw new Error('请先通过独立渠道核对指纹，并勾选复核完成'); if (!confirm(`保存 ${input.peerId} 的已核对身份？扩大信任需重启生效，不会添加执行权限。`)) return; showResult('pair', await command({ command: 'pairPeer', ...input })); notice('信任配置已保存。请按运维流程重启，再单独配置执行权限。'); }); });
  $('log-event').addEventListener('change', renderLogs); $('log-search').addEventListener('input', renderLogs);
  window.addEventListener('beforeunload', event => { if (csrf && editor.dirty) { event.preventDefault(); event.returnValue = ''; } });
  // Remove the one-use bootstrap fragment before the first network request.
  const fragment = new URLSearchParams(location.hash.slice(1)), token = fragment.get('token');
  if (location.hash) history.replaceState(null, '', location.pathname);
  void guarded(async () => { if (token) { const data = await api('/api/session', { token }); unlock(data); await refresh(); } else { try { const data = await api('/api/session'); unlock(data); await refresh(); } catch (error) { lock(); if (!error.message.includes('UNAUTHENTICATED')) notice(error.message, true); } } });
  setInterval(() => { if (csrf && !busy && !stopped && document.visibilityState === 'visible') void guarded(refresh); }, 10000);
}
if (typeof document !== 'undefined') initialize();
