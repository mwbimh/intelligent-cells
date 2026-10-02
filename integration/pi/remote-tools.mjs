import { randomUUID } from 'node:crypto';
import { Type } from 'typebox';

export const REMOTE_TOOL_NAMES = Object.freeze([
  'remote_capabilities', 'remote_read', 'remote_write', 'remote_edit', 'remote_exec', 'remote_echo', 'remote_wait',
  'remote_list', 'remote_search', 'remote_read_chunk', 'remote_mkdir', 'remote_write_chunk',
  'remote_job_status', 'remote_job_output', 'remote_job_cancel', 'remote_job_stdin',
  'remote_resources', 'remote_resource_read', 'remote_mcp_list', 'remote_mcp_call',
]);
export const STOCK_TOOL_NAMES = Object.freeze(['read', 'bash', 'edit', 'write', 'ls', 'grep', 'find', 'powershell']);

/** Session routing is owner-selected metadata, never a model-facing tool argument. */
export function workspaceSelection({ logicalWorkspaceId, workspaceId } = {}) {
  if (logicalWorkspaceId !== undefined && workspaceId !== undefined) throw Object.assign(new Error('Select either a logical workspace or an explicit servant workspace'), { code: 'INVALID_TASK' });
  for (const [name, value] of Object.entries({ logicalWorkspaceId, workspaceId })) {
    if (value !== undefined && (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(value))) throw Object.assign(new Error(`Invalid ${name}`), { code: 'INVALID_TASK' });
  }
  return Object.freeze({ ...(logicalWorkspaceId !== undefined ? { logicalWorkspaceId } : {}), ...(workspaceId !== undefined ? { workspaceId } : {}) });
}

/** Model-facing schema is a convenience; the servant remains the policy authority. */
export function createRemoteTools({ dispatch, cancel, peerIds, onDispatch = () => {}, onCancel = () => {}, runId = 'pi-default', logicalWorkspaceId, workspaceId, ensureWorkspaceBinding }) {
  const workspace = workspaceSelection({ logicalWorkspaceId, workspaceId });
  if (logicalWorkspaceId !== undefined && typeof ensureWorkspaceBinding !== 'function') throw Object.assign(new Error('Logical workspace routing requires the system binding hook'), { code: 'WORKSPACE_BINDING_REQUIRED' });
  const peerId = Type.String({ minLength: 1, maxLength: 64, description: `Configured servant ID: ${peerIds.join(', ')}` });
  const timeoutMs = Type.Optional(Type.Integer({ minimum: 10, maximum: 86400000 }));
  const text = () => Type.String({ maxLength: 32768 });
  const path = () => Type.String({ minLength: 1, maxLength: 4096 });
  if (typeof runId !== 'string' || !/^[a-zA-Z0-9_-]{1,100}$/.test(runId)) throw Object.assign(new Error('Invalid Pi runId'), { code: 'INVALID_RUN' });
  const logicalCalls = new Map();
  let uncertain = false;
  const readOnly = new Set(['capabilities','readFile','readChunk','listDirectory','searchFiles','echo','wait','resourceList','resourceRead','mcpList','jobStatus','jobOutput']);
  const jobId = () => Type.String({ minLength: 1, maxLength: 100 });
  const definitions = [
    ['remote_capabilities', 'capabilities', 'Get current servant-owned tool schemas, aliases and limits', {}],
    ['remote_read', 'readFile', 'Read a file from a servant-approved workspace', { path: path() }],
    ['remote_write', 'writeFile', 'Create or explicitly overwrite a file inside a servant-approved workspace', { path: path(), text: text(), overwrite: Type.Optional(Type.Boolean()) }],
    ['remote_edit', 'editFile', 'Replace exact text inside a servant-approved file', { path: path(), oldText: text(), newText: text() }],
    ['remote_exec', 'exec', 'Run a servant-local allowlisted command alias; no shell or arbitrary executable', { command: Type.String({ minLength: 1, maxLength: 64 }), args: Type.Array(Type.String({ maxLength: 4096 }), { maxItems: 32 }), background: Type.Optional(Type.Boolean()), stdin: Type.Optional(Type.String({ maxLength: 8192 })), durationMs: Type.Optional(Type.Integer({minimum:10,maximum:86400000})) }],
    ['remote_echo', 'echo', 'Return text from a remote servant', { text: text() }],
    ['remote_wait', 'wait', 'Wait for a bounded interval on a servant', { ms: Type.Integer({ minimum: 0, maximum: 86400000 }) }],
    ['remote_list', 'listDirectory', 'List bounded directory entries in the approved remote workspace', { path: Type.Optional(path()), offset: Type.Optional(Type.Integer({minimum:0})), limit: Type.Optional(Type.Integer({minimum:1,maximum:100})) }],
    ['remote_search', 'searchFiles', 'Search literal text in the approved remote workspace', { path: Type.Optional(path()), query: Type.String({minLength:1,maxLength:256}), maxResults: Type.Optional(Type.Integer({minimum:1,maximum:50})) }],
    ['remote_read_chunk', 'readChunk', 'Read a bounded remote file chunk', { path: path(), offset: Type.Optional(Type.Integer({minimum:0})), length: Type.Optional(Type.Integer({minimum:1,maximum:65536})) }],
    ['remote_mkdir', 'mkdir', 'Create a directory within the approved remote workspace', { path: path() }],
    ['remote_write_chunk', 'writeChunk', 'Write a bounded base64 chunk in the approved remote workspace', { path:path(),base64:Type.String({maxLength:87384}),offset:Type.Optional(Type.Integer({minimum:0})),overwrite:Type.Optional(Type.Boolean()) }],
    ['remote_job_status', 'jobStatus', 'Inspect an owned remote development job', {jobId:jobId()}],
    ['remote_job_output', 'jobOutput', 'Read bounded owned job output', {jobId:jobId(),offset:Type.Optional(Type.Integer({minimum:0})),limit:Type.Optional(Type.Integer({minimum:1,maximum:65536})),stream:Type.Optional(Type.Union([Type.Literal('combined'),Type.Literal('stdout'),Type.Literal('stderr')]))}],
    ['remote_job_cancel', 'jobCancel', 'Request cancellation of an owned remote job; cannot roll back effects', {jobId:jobId()}],
    ['remote_job_stdin', 'jobStdin', 'Write bounded input to an owned remote job', {jobId:jobId(),text:Type.String({maxLength:8192}),eof:Type.Optional(Type.Boolean())}],
    ['remote_resources', 'resourceList', 'List the resources explicitly approved by the servant for this master', {}],
    ['remote_resource_read', 'resourceRead', 'Read bounded approved instruction, skill, or prompt text by resource alias', {resource:Type.String({minLength:1,maxLength:64})}],
    ['remote_mcp_list', 'mcpList', 'List servant-authorized MCP bindings from an approved local server alias', {server:Type.String({minLength:1,maxLength:64})}],
    ['remote_mcp_call', 'mcpCall', 'Invoke an approved MCP tool through servant-owned bindings; no URL or command selection', {server:Type.String({minLength:1,maxLength:64}),tool:Type.String({minLength:1,maxLength:64}),arguments:Type.Record(Type.String(),Type.Unknown())}],
  ];
  return definitions.map(([name, tool, description, properties]) => ({
    name, label: name, description,
    parameters: Type.Object({ peerId, timeoutMs, ...properties }, { additionalProperties: false }),
    async execute(_toolCallId, params, signal, _onUpdate, _ctx) {
      if (signal?.aborted) throw new Error('Pi tool call aborted before remote dispatch');
      const { peerId: target, timeoutMs: timeout = 1000, ...args } = params;
      if (!peerIds.includes(target)) throw Object.assign(new Error('UNKNOWN_PEER: Not a configured outgoing servant'), { code: 'UNKNOWN_PEER' });
      if (uncertain && !readOnly.has(tool)) throw Object.assign(new Error('RUN_OUTCOME_UNKNOWN: Side effects are blocked until the owner queries and reconciles the uncertain outcome'), { code: 'RUN_OUTCOME_UNKNOWN' });
      const fingerprint = JSON.stringify({target,tool,args,timeout,runId,workspace});
      const previous = logicalCalls.get(_toolCallId);
      if (previous && previous.fingerprint !== fingerprint) throw Object.assign(new Error('TASK_ID_CONFLICT: Pi reused a tool-call ID with different arguments'), {code:'TASK_ID_CONFLICT'});
      if (previous?.result) return previous.result;
      // This is a system lifecycle hook, not an agent-callable provisioning tool.
      // Await it before dispatch/cancellation registration; an aborted preparation
      // must never send the requested file or process operation afterward.
      if (logicalWorkspaceId !== undefined) {
        try { await ensureWorkspaceBinding(target, logicalWorkspaceId); }
        catch (error) {
          if (error.code && !error.message.includes(error.code)) throw Object.assign(new Error(`${error.code}: ${error.message}`), { code:error.code });
          throw error;
        }
      }
      if (signal?.aborted) throw new Error('Pi tool call aborted before remote dispatch');
      const task = previous?.task ?? { taskId: `pi_${randomUUID().replaceAll('-', '')}`, runId, ...workspace, tool, args, timeoutMs: timeout };
      const logical = previous ?? {fingerprint,task};
      logicalCalls.set(_toolCallId,logical);
      const requestCancel = () => {
        if (!cancel) return;
        try {
          Promise.resolve(cancel(target, task.taskId)).then(
            () => onCancel({ peerId: target, taskId: task.taskId, requested: true }),
            () => onCancel({ peerId: target, taskId: task.taskId, requested: false }),
          );
        } catch { onCancel({ peerId: target, taskId: task.taskId, requested: false }); }
      };
      signal?.addEventListener('abort', requestCancel, { once: true });
      let response;
      try {
        // Dispatch synchronously before reporting it, so an onDispatch abort cannot
        // send cancel before the task frame. Await the original terminal response.
        const pending = dispatch(target, task, { signal });
        onDispatch({ peerId: target, taskId: task.taskId, ...workspace, tool });
        response = await pending;
      } catch(error) {
        if (['OUTCOME_UNKNOWN','RUN_OUTCOME_UNKNOWN','UNCERTAIN_SIDE_EFFECT','TASK_HISTORY_EXPIRED'].includes(error.code) || /OUTCOME_UNKNOWN/.test(error.message)) uncertain = true;
        if (error.code && !error.message.includes(error.code)) throw Object.assign(new Error(`${error.code}: ${error.message}`), {code:error.code});
        throw error;
      } finally { signal?.removeEventListener('abort', requestCancel); }
      // A transport uncertainty is surfaced to Pi. Never replay or execute locally.
      if (['OUTCOME_UNKNOWN','RUN_OUTCOME_UNKNOWN','UNCERTAIN_SIDE_EFFECT','TASK_HISTORY_EXPIRED'].includes(response.error?.code)) uncertain = true;
      if (response.status !== 'ok') throw Object.assign(new Error(`${response.error?.code ?? 'REMOTE_ERROR'}: ${response.error?.message ?? 'Servant refused execution'}`), { code: response.error?.code ?? 'REMOTE_ERROR' });
      if (response.result?.isError === true) throw Object.assign(new Error('MCP_TOOL_ERROR: ' + JSON.stringify(response.result.content)), {code:'MCP_TOOL_ERROR'});
      logical.result = { content: [{ type: 'text', text: JSON.stringify(response.result) }], details: { peerId: target, taskId: task.taskId, runId, ...workspace, status: response.status } };
      return logical.result;
    },
  }));
}
