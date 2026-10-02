import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fail, isObject } from './errors.mjs';
import { validateRelativePath, requireRoot, inspectRoot, safeRead, mutateFile, readRange, listDirectory, searchFiles, makeDirectory, writeChunk } from './workspace-files.mjs';
import { workspaceIdValid, creationIdValid, workspaceNameValid } from './workspaces.mjs';
import { JobManager } from './jobs.mjs';
import { validateResourceTask, executeResourceTask, resourceToolSchemas } from './resources.mjs';
import { validateMcpTask, executeMcpTask, mcpToolSchemas, isMcpSideEffecting } from './mcp.mjs';
import { verifyApprovedCode } from './code-policy.mjs';
import { assertDirectoryAccess, directoryAccess, directoryPolicySummary, PROCESS_TOOLS } from './directory-policy.mjs';

export const MAX_TASK_TIMEOUT_MS = 86400000;
export const TOOL_NAMES = new Set(['workspaceList', 'workspaceCreate', 'echo', 'wait', 'capabilities', 'readFile', 'writeFile', 'editFile', 'listDirectory', 'searchFiles', 'mkdir', 'readChunk', 'writeChunk', 'exec', 'jobStatus', 'jobOutput', 'jobCancel', 'jobStdin', 'resourceList', 'resourceRead', 'mcpList', 'mcpCall']);
const MAX_ARG_BYTES = 4096, MAX_ARGS_BYTES = 16384;
const resourceNames = new Set(['resourceList', 'resourceRead']), mcpNames = new Set(['mcpList', 'mcpCall']);
const int = (value, min, max, name) => { if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min > max) fail('INVALID_POLICY', `Invalid local ${name} bound`); if (!Number.isSafeInteger(value) || value < min || value > max) fail('INVALID_ARGS', `${name} must be ${min}..${max}`); };
const onlyKeys = (args, allowed) => { if (Object.keys(args).some(key => !allowed.includes(key))) fail('INVALID_ARGS', 'Unexpected tool argument'); };
const byteLimit = (value, name) => { if (!Number.isSafeInteger(value) || value < 1 || value > 16777216) fail('INVALID_POLICY', `A bounded local ${name} is required`); return value; };
const optionalPath = value => { if (value !== undefined && value !== '') validateRelativePath(value); };
function validateToolInput(task, policy) {
  if (!isObject(task) || typeof task.tool !== 'string' || !TOOL_NAMES.has(task.tool) || !policy.tools?.has(task.tool)) fail('TOOL_DENIED', 'Tool is not in this node’s local allowlist');
  if (!isObject(task.args)) fail('INVALID_TASK', 'args must be an object');
  if (policy.directories !== undefined && PROCESS_TOOLS.has(task.tool) && policy.allowUnsandboxedProcesses !== true) fail('INVALID_POLICY', 'Unsandboxed processes require a separate owner acknowledgement with directory-scoped grants');
  if (resourceNames.has(task.tool)) return validateResourceTask(task, policy);
  if (mcpNames.has(task.tool)) return validateMcpTask(task, policy);
  const args = task.args;
  switch (task.tool) {
    case 'workspaceList': onlyKeys(args, ['offset','limit']); if(args.offset!==undefined)int(args.offset,0,2048,'offset');if(args.limit!==undefined)int(args.limit,1,32,'limit');break;
    case 'workspaceCreate':
      onlyKeys(args, ['rootId','name','requestId']);
      if (!workspaceIdValid(args.rootId) || !workspaceNameValid(args.name) || !creationIdValid(args.requestId)) fail('INVALID_ARGS', 'Workspace creation requires an approved rootId, safe name and stable requestId');
      if (!policy.workspaceProvisioning?.has(args.rootId)) fail('WORKSPACE_CREATE_DENIED', 'Workspace creation root was not approved');
      break;
    case 'capabilities': onlyKeys(args, []); break;
    case 'echo': onlyKeys(args, ['text']); if (typeof args.text !== 'string' || Buffer.byteLength(args.text) > 4096) fail('INVALID_ARGS', 'echo requires text up to 4096 bytes'); break;
    case 'wait': onlyKeys(args, ['ms']); int(args.ms, 0, policy.maxWaitMs, 'ms'); break;
    case 'readFile': case 'readChunk':
      onlyKeys(args, ['path', 'offset', 'length']); validateRelativePath(args.path); requireRoot(policy); byteLimit(policy.maxReadBytes, 'maxReadBytes');
      if (args.offset !== undefined) int(args.offset, 0, Number.MAX_SAFE_INTEGER - policy.maxReadBytes, 'offset');
      if (args.length !== undefined) int(args.length, 1, policy.maxReadBytes, 'length'); break;
    case 'writeFile':
      onlyKeys(args, ['path', 'text', 'overwrite']); validateRelativePath(args.path); requireRoot(policy);
      if (typeof args.text !== 'string' || (args.overwrite !== undefined && typeof args.overwrite !== 'boolean')) fail('INVALID_ARGS', 'writeFile requires text and an optional boolean overwrite');
      if (Buffer.byteLength(args.text) > byteLimit(policy.maxWriteBytes, 'maxWriteBytes')) fail('FILE_TOO_LARGE', 'Write exceeds local byte limit'); break;
    case 'editFile':
      onlyKeys(args, ['path', 'oldText', 'newText']); validateRelativePath(args.path); requireRoot(policy);
      if (typeof args.oldText !== 'string' || !args.oldText || typeof args.newText !== 'string') fail('INVALID_ARGS', 'editFile requires nonempty oldText and string newText');
      if (Buffer.byteLength(args.oldText) > byteLimit(policy.maxReadBytes, 'maxReadBytes') || Buffer.byteLength(args.newText) > byteLimit(policy.maxWriteBytes, 'maxWriteBytes')) fail('FILE_TOO_LARGE', 'Edit text exceeds local byte limit'); break;
    case 'listDirectory':
      onlyKeys(args, ['path', 'offset', 'limit']); optionalPath(args.path); requireRoot(policy);
      if (args.offset !== undefined) int(args.offset, 0, policy.maxDirectoryEntries ?? 1000, 'offset');
      if (args.limit !== undefined) int(args.limit, 1, Math.min(100, policy.maxDirectoryEntries ?? 1000), 'limit'); break;
    case 'searchFiles':
      onlyKeys(args, ['path', 'query', 'maxResults']); optionalPath(args.path); requireRoot(policy);
      if (typeof args.query !== 'string' || !args.query || args.query.includes('\n') || Buffer.byteLength(args.query) > 256) fail('INVALID_ARGS', 'Search needs a single-line literal query up to 256 bytes');
      if (args.maxResults !== undefined) int(args.maxResults, 1, 50, 'maxResults'); break;
    case 'mkdir': onlyKeys(args, ['path']); validateRelativePath(args.path); requireRoot(policy); break;
    case 'writeChunk': {
      onlyKeys(args, ['path', 'base64', 'offset', 'overwrite']); validateRelativePath(args.path); requireRoot(policy);
      if (typeof args.base64 !== 'string' || args.base64.length > Math.ceil(byteLimit(policy.maxWriteBytes, 'maxWriteBytes') / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(args.base64) || Buffer.from(args.base64, 'base64').toString('base64') !== args.base64) fail('INVALID_ARGS', 'Transfer requires canonical bounded base64');
      if (Buffer.from(args.base64, 'base64').length > policy.maxWriteBytes) fail('FILE_TOO_LARGE', 'Transfer chunk exceeds local limit');
      if (args.offset !== undefined) int(args.offset, 0, policy.maxTransferBytes ?? 67108864, 'offset');
      if (args.overwrite !== undefined && typeof args.overwrite !== 'boolean') fail('INVALID_ARGS', 'overwrite must be boolean');
      if ((args.offset ?? 0) + Buffer.from(args.base64, 'base64').length > (policy.maxTransferBytes ?? 67108864)) fail('FILE_TOO_LARGE', 'Transfer exceeds total file limit'); break;
    }
    case 'exec': {
      onlyKeys(args, ['command', 'args', 'background', 'stdin', 'durationMs']); requireRoot(policy);
      if (typeof args.command !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/u.test(args.command) || !Array.isArray(args.args)) fail('INVALID_ARGS', 'exec requires a configured command alias and an args array');
      const command = policy.execCommands?.get(args.command);
      if (!command) fail('COMMAND_DENIED', 'Command is not in the local executable allowlist');
      if (typeof command.file !== 'string' || !path.isAbsolute(command.file) || !Array.isArray(command.args) || command.args.some(arg => typeof arg !== 'string' || arg.includes('\0')) || !Number.isSafeInteger(command.maxArgs) || command.maxArgs < 0 || !isObject(command.env) || Object.entries(command.env).some(([key, value]) => !key || /[=\0]/u.test(key) || typeof value !== 'string' || value.includes('\0'))) fail('INVALID_POLICY', 'Executable must have a validated local definition');
      if (command.allowedArgs !== undefined && (!Array.isArray(command.allowedArgs) || command.allowedArgs.some(arg => typeof arg !== 'string'))) fail('INVALID_POLICY', 'allowedArgs must be explicit strings');
      if (args.args.length > command.maxArgs || (args.args.length && command.argsAllowed !== true) || args.args.some(arg => typeof arg !== 'string' || arg.includes('\0') || Buffer.byteLength(arg) > MAX_ARG_BYTES || (command.allowedArgs && !command.allowedArgs.includes(arg))) || args.args.reduce((bytes, arg) => bytes + Buffer.byteLength(arg), 0) > MAX_ARGS_BYTES) fail('INVALID_ARGS', 'Command arguments exceed the local allowance');
      if (args.background !== undefined && typeof args.background !== 'boolean') fail('INVALID_ARGS', 'background must be boolean');
      if (args.stdin !== undefined && (command.stdinAllowed !== true || typeof args.stdin !== 'string' || Buffer.byteLength(args.stdin) > (command.maxStdinBytes ?? 65536))) fail('STDIN_DENIED', 'Initial stdin exceeds the configured command allowance');
      if (args.durationMs !== undefined) int(args.durationMs, 10, MAX_TASK_TIMEOUT_MS, 'durationMs');
      byteLimit(policy.maxOutputBytes, 'maxOutputBytes'); break;
    }
    case 'jobStatus': case 'jobOutput': case 'jobCancel': case 'jobStdin': {
      const extra = task.tool === 'jobOutput' ? ['offset', 'limit', 'stream'] : task.tool === 'jobStdin' ? ['text', 'eof'] : [];
      onlyKeys(args, ['jobId', ...extra]);
      if (typeof args.jobId !== 'string' || !/^[a-zA-Z0-9_-]{1,100}$/u.test(args.jobId)) fail('INVALID_ARGS', 'Invalid job identifier');
      if (task.tool === 'jobOutput') {
        if (args.offset !== undefined) int(args.offset, 0, Number.MAX_SAFE_INTEGER - 16384, 'offset');
        if (args.limit !== undefined) int(args.limit, 1, policy.maxOutputPageBytes ?? 16384, 'limit');
        if (args.stream !== undefined && !['combined', 'stdout', 'stderr'].includes(args.stream)) fail('INVALID_ARGS', 'Unknown job output stream');
      }
      if (task.tool === 'jobStdin' && (typeof args.text !== 'string' || Buffer.byteLength(args.text) > 65536 || (args.eof !== undefined && typeof args.eof !== 'boolean'))) fail('INVALID_ARGS', 'Invalid bounded stdin write'); break;
    }
  }
  if (['readFile', 'readChunk', 'editFile'].includes(task.tool)) assertDirectoryAccess(policy, args.path, 'read');
  if (['writeFile', 'writeChunk', 'editFile'].includes(task.tool)) assertDirectoryAccess(policy, args.path, 'write');
  if (['listDirectory', 'searchFiles'].includes(task.tool)) assertDirectoryAccess(policy, args.path ?? '', 'read', true);
  if (task.tool === 'mkdir') assertDirectoryAccess(policy, args.path, 'write', true);
}

export function validateRequest(task, masterId, policy) {
  if (!policy.allowedMasters?.has(masterId)) fail('MASTER_DENIED', 'This relationship is not allowed locally');
  if (!isObject(task) || typeof task.taskId !== 'string' || !/^[a-zA-Z0-9_-]{1,100}$/u.test(task.taskId)) fail('INVALID_TASK', 'Invalid taskId');
  validateToolInput(task, policy);
  if (!Number.isSafeInteger(task.timeoutMs) || task.timeoutMs < 10 || task.timeoutMs > MAX_TASK_TIMEOUT_MS) fail('INVALID_TASK', `timeoutMs must be 10..${MAX_TASK_TIMEOUT_MS}`);
  if (!Number.isSafeInteger(policy.maxTimeoutMs) || policy.maxTimeoutMs < 10 || policy.maxTimeoutMs > MAX_TASK_TIMEOUT_MS) fail('INVALID_POLICY', 'Invalid local timeout limit');
  return Math.min(task.timeoutMs, policy.maxTimeoutMs);
}
export function isSideEffecting(task, policy = {}) {
  return ['workspaceCreate', 'writeFile', 'editFile', 'mkdir', 'writeChunk', 'exec', 'jobStdin'].includes(task?.tool) || (mcpNames.has(task?.tool) && isMcpSideEffecting(task, policy));
}

const string = { type: 'string' }, integer = { type: 'integer', minimum: 0 }, boolean = { type: 'boolean' };
const schema = (name, description, properties, required = []) => ({ name, description, inputSchema: { type: 'object', properties, required, additionalProperties: false } });
const builtinSchemas = [
  schema('workspaceList', 'Page through workspaces and creation roots approved for this peer; no host paths', {offset:integer,limit:integer}),
  schema('workspaceCreate', 'Create a workspace only under an owner-approved root with a stable requestId', {rootId:string,name:string,requestId:string}, ['rootId','name','requestId']),
  schema('echo', '返回有界文本', { text: string }, ['text']), schema('wait', '等待本地批准的时长', { ms: integer }, ['ms']), schema('capabilities', '返回当前 peer 被授予的工具、参数与限额', {}),
  schema('readFile', 'UTF-8 读取；offset/length 为字节范围，未提供范围时超大文件拒绝', { path: string, offset: integer, length: integer }, ['path']),
  schema('writeFile', '原子写入 UTF-8 文件；覆盖须显式 overwrite', { path: string, text: string, overwrite: boolean }, ['path', 'text']),
  schema('editFile', '精确替换唯一匹配的文本', { path: string, oldText: string, newText: string }, ['path', 'oldText', 'newText']),
  schema('listDirectory', '有界分页列举目录；空 path 表示已批准工作区', { path: string, offset: integer, limit: integer }),
  schema('searchFiles', '按字面文本递归搜索；返回扫描限额和截断原因', { path: string, query: string, maxResults: integer }, ['query']),
  schema('mkdir', '创建一个目录；父目录必须已存在', { path: string }, ['path']),
  schema('readChunk', '按字节分块下载，含 base64 与 SHA-256', { path: string, offset: integer, length: integer }, ['path']),
  schema('writeChunk', '分块上传；offset=0 创建/覆盖，后续 offset 必须等于当前大小', { path: string, base64: string, offset: integer, overwrite: boolean }, ['path', 'base64']),
  schema('exec', '启动本地配置的命令别名；无 shell；后台任务返回 jobId', { command: string, args: { type: 'array', items: string }, background: boolean, stdin: string, durationMs: integer }, ['command', 'args']),
  schema('jobStatus', '查看当前 peer 的作业状态', { jobId: string }, ['jobId']),
  schema('jobOutput', '按字节分页读取持久化输出；分页使用 base64 保留 UTF-8 边界', { jobId: string, offset: integer, limit: integer, stream: { enum: ['combined', 'stdout', 'stderr'] } }, ['jobId']),
  schema('jobCancel', '取消当前 peer 的运行作业并等待进程清理', { jobId: string }, ['jobId']),
  schema('jobStdin', '仅向本地命令显式允许的 stdin 写入', { jobId: string, text: string, eof: boolean }, ['jobId', 'text'])
];
export function capabilitySchema(policy) {
  const tools = structuredClone([...builtinSchemas, ...resourceToolSchemas, ...mcpToolSchemas].filter(item => policy.tools?.has(item.name)));
  for (const tool of tools) {
    const properties = tool.inputSchema.properties;
    if (['readFile', 'readChunk'].includes(tool.name)) properties.length = { type: 'integer', minimum: 1, maximum: policy.maxReadBytes };
    if (tool.name === 'wait') properties.ms = { type: 'integer', minimum: 0, maximum: policy.maxWaitMs };
    if (tool.name === 'listDirectory') properties.limit = { type: 'integer', minimum: 1, maximum: Math.min(100, policy.maxDirectoryEntries ?? 1000) };
    if (tool.name === 'searchFiles') properties.maxResults = { type: 'integer', minimum: 1, maximum: 50 };
    if (tool.name === 'jobOutput') properties.limit = { type: 'integer', minimum: 1, maximum: policy.maxOutputPageBytes ?? 16384 };
    if (tool.name === 'exec') { properties.command = { type: 'string', enum: [...(policy.execCommands?.keys() ?? [])] }; properties.durationMs = { type: 'integer', minimum: 10, maximum: MAX_TASK_TIMEOUT_MS }; }
  }
  return { version: 3, tools, filesystem: directoryPolicySummary(policy),
    limits: Object.fromEntries(['maxTimeoutMs', 'maxJobTimeoutMs', 'maxReadBytes', 'maxWriteBytes', 'maxOutputBytes', 'maxOutputPageBytes', 'maxTransferBytes', 'maxDirectoryEntries', 'maxSearchFiles', 'maxSearchBytes', 'maxJobs', 'maxConcurrent'].filter(key => policy[key] !== undefined).map(key => [key, policy[key]])),
    commands: policy.tools?.has('exec') ? [...(policy.execCommands ?? [])].map(([alias, value]) => ({ alias, argsAllowed: value.argsAllowed, maxArgs: value.maxArgs, ...(value.allowedArgs ? { allowedArgs: value.allowedArgs } : {}), stdinAllowed: value.stdinAllowed === true })) : [],
    resources: policy.tools?.has('resourceList') ? [...(policy.resources?.values() ?? [])].filter(resource => directoryAccess(policy, resource.path, 'read')).map(({ id, kind }) => ({ id, kind, discoveryTool: 'resourceList' })) : [],
    mcpServers: policy.tools?.has('mcpList') ? [...(policy.mcpServers?.values() ?? [])].map(server => ({ alias: server.alias, discoveryTool: 'mcpList', permissionAuthority: 'servant-local-grant', tools: [...server.tools.values()].map(({ name, readOnly }) => ({ name, readOnly })) })) : [] };
}

async function verifyExecCode(command, signal) {
  await verifyApprovedCode(command, signal, 'EXEC_CODE_CHANGED');
}

export async function runTool(task, policy, signal = new AbortController().signal, options = {}) {
  signal.throwIfAborted(); validateToolInput(task, policy);
  if (isSideEffecting(task, policy)) options.jobManager?.assertCanWrite(options.masterId, options.runId);
  if (resourceNames.has(task.tool)) return executeResourceTask(task, policy, signal, options);
  if (mcpNames.has(task.tool)) return executeMcpTask(task, policy, signal, options);
  switch (task.tool) {
    case 'workspaceList':
      if (!options.workspaceRegistry || !options.masterId) fail('WORKSPACE_REGISTRY_REQUIRED', 'Workspace management requires the authenticated node registry');
      return options.workspaceRegistry.catalog(options.masterId, task.args);
    case 'workspaceCreate':
      if (!options.workspaceRegistry || !options.masterId) fail('WORKSPACE_REGISTRY_REQUIRED', 'Workspace management requires the authenticated node registry');
      return options.workspaceRegistry.create(options.masterId, task.args, signal);
    case 'capabilities': return capabilitySchema(policy);
    case 'echo': return { text: task.args.text };
    case 'wait': await sleep(task.args.ms, undefined, { signal }); return { waitedMs: task.args.ms };
    case 'readFile': return task.args.offset !== undefined || task.args.length !== undefined ? readRange(policy.root, task.args, policy.maxReadBytes, signal) : safeRead(policy.root, task.args.path, policy.maxReadBytes, signal);
    case 'readChunk': return readRange(policy.root, task.args, policy.maxReadBytes, signal, true);
    case 'writeFile': case 'editFile': return mutateFile(task, policy, signal);
    case 'writeChunk': return writeChunk(policy.root, task.args, policy, signal);
    case 'mkdir': return makeDirectory(policy.root, task.args, signal);
    case 'listDirectory': return listDirectory(policy.root, task.args, policy, signal);
    case 'searchFiles': return searchFiles(policy.root, task.args, policy, signal);
    case 'exec': {
      await inspectRoot(requireRoot(policy), signal);
      await verifyExecCode(policy.execCommands.get(task.args.command), signal);
      if (task.args.background && !options.jobManager) fail('JOB_MANAGER_REQUIRED', 'Background jobs require the node-owned durable job manager');
      const manager = options.jobManager ?? new JobManager();
      const result = await manager.run(task, policy, signal, options);
      if (!options.jobManager && !task.args.background && !result.outputTruncated) { const { jobId, state, ...legacy } = result; return legacy; }
      return result;
    }
    default: {
      if (!options.jobManager || !options.masterId) fail('JOB_MANAGER_REQUIRED', 'Job controls require an authenticated node-owned job manager');
      const manager = options.jobManager;
      if (task.tool === 'jobStatus') return manager.status(options.masterId, task.args.jobId);
      if (task.tool === 'jobOutput') return manager.output(options.masterId, task.args, policy);
      if (task.tool === 'jobCancel') return manager.cancel(options.masterId, task.args.jobId);
      if (task.tool === 'jobStdin') return manager.stdin(options.masterId, task.args, policy, signal);
    }
  }
}
