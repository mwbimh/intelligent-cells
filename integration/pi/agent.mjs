import {
  createAgentSession, ModelRuntime, SessionManager, SettingsManager, VERSION,
} from '@earendil-works/pi-coding-agent';
import { loadApprovedResources } from './resources.mjs';
import { startMockModel, scenarioCalls, developmentFinal } from './mock-model.mjs';
import { createRemoteTools, REMOTE_TOOL_NAMES, STOCK_TOOL_NAMES, workspaceSelection } from './remote-tools.mjs';

export const PI_PACKAGE = '@earendil-works/pi-coding-agent';
export const PI_VERSION = '0.99.2';

// Do not read ~/.pi/auth.json, environment API keys, models.json, or write credentials.
// The mock provider is explicitly registered with a non-secret test token instead.
const emptyCredentials = Object.freeze({
  read: async () => undefined,
  list: async () => [],
  modify: async () => { throw new Error('Credentials are disabled in the mocked harness'); },
  delete: async () => { throw new Error('Credentials are disabled in the mocked harness'); },
});

/** Run the actual pinned Pi AgentSession with an HTTP model double and remote-only tools. */
export async function runPiMock({ dispatch, cancel, signal, peerIds, prompt, scenario = 'read', calls, cwd = process.cwd(), onEvent = () => {}, runId = 'pi-default', resourceConfiguration = {}, promptResource, logicalWorkspaceId, workspaceId, ensureWorkspaceBinding }) {
  if (VERSION !== PI_VERSION) throw new Error(`Unsupported Pi SDK version: ${VERSION}`);
  if (typeof prompt !== 'string' || prompt.length === 0 || prompt.length > 8192) throw Object.assign(new Error('prompt must contain 1..8192 characters'), { code: 'INVALID_PROMPT' });
  if (!Array.isArray(peerIds) || !peerIds.length) throw Object.assign(new Error('Pi requires at least one configured servant'), { code: 'NO_SERVANTS' });
  if (signal?.aborted) throw Object.assign(new Error('Pi run was aborted'), { code: 'AGENT_ABORTED' });
  const workspace = workspaceSelection({ logicalWorkspaceId, workspaceId });
  if (logicalWorkspaceId !== undefined && typeof ensureWorkspaceBinding !== 'function') throw Object.assign(new Error('Logical workspace routing requires the system binding hook'), { code: 'WORKSPACE_BINDING_REQUIRED' });
  const script = calls ?? scenarioCalls(scenario, peerIds[0]);
  const audit = [], dispatches = [];
  const emit = event => { const scoped = { ...workspace, ...event }; audit.push(scoped); onEvent(scoped); };
  const preparations = new Map(), workspaceBindings = new Map();
  const prepareWorkspace = (peerId, selectedLogicalWorkspaceId) => {
    if (!peerIds.includes(peerId)) throw Object.assign(new Error('Not a configured outgoing servant'), { code: 'UNKNOWN_PEER' });
    if (selectedLogicalWorkspaceId !== logicalWorkspaceId) throw Object.assign(new Error('Pi workspace scope cannot change during a run'), { code: 'INVALID_TASK' });
    if (!preparations.has(peerId)) {
      const pending = Promise.resolve().then(() => {
        if (signal?.aborted) throw Object.assign(new Error('Pi run was aborted'), { code: 'AGENT_ABORTED' });
        return ensureWorkspaceBinding(peerId, logicalWorkspaceId);
      }).then(binding => {
        const resolved = { peerId, logicalWorkspaceId, workspaceId: binding.workspaceId };
        workspaceBindings.set(peerId, resolved);
        emit({ type: 'workspace_ready', ...resolved });
        return binding;
      });
      preparations.set(peerId, pending);
    }
    return preparations.get(peerId);
  };
  const resourceDispatch = async (peerId, task) => {
    if (logicalWorkspaceId !== undefined) await prepareWorkspace(peerId, logicalWorkspaceId);
    if (signal?.aborted) throw Object.assign(new Error('Pi run was aborted'), { code: 'AGENT_ABORTED' });
    return dispatch(peerId, { ...task, ...workspace }, { signal });
  };
  let resources;
  try { resources = await loadApprovedResources({dispatch:resourceDispatch,cancel,peerIds,configuration:resourceConfiguration,signal,runId,emit}); }
  catch(error) {
    if(signal?.aborted) throw Object.assign(new Error('Pi run was aborted while reading approved resources'),{code:'AGENT_ABORTED'});
    throw error;
  }
  const effectivePrompt = resources.expandPrompt(prompt,promptResource);
  const mock = await startMockModel({ calls: script, finalize: scenario === 'development' ? developmentFinal : undefined, onRequest: event => emit({ type: 'mock_request', ...event }) });
  let session;
  const abort = () => { session?.abort().catch(() => {}); };
  try {
    const modelRuntime = await ModelRuntime.create({
      credentials: emptyCredentials, modelsPath: null, allowModelNetwork: false, refreshOnCreate: false,
    });
    modelRuntime.registerProvider('intelligent-cells-local-mock', {
      baseUrl: mock.url, api: 'openai-completions', apiKey: 'not-a-secret-local-test-token', authHeader: false,
      models: [{ id: 'intelligent-cells-mock', name: 'Local deterministic mock (not a real LLM)', reasoning: false,
        input: ['text'], cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 65536, maxTokens: 8192,
        compat: { supportsStore: false, supportsDeveloperRole: false, supportsUsageInStreaming: true } }],
    });
    const settingsManager = SettingsManager.inMemory({
      compaction: { enabled: false }, retry: { enabled: false, maxRetries: 0, provider: { maxRetries: 0, timeoutMs: 5000 } },
      cacheWarming: 'off', enableInstallTelemetry: false, enableAnalytics: false, enableSkillCommands: false,
      images: { blockImages: true, autoResize: false }, defaultTools: [...REMOTE_TOOL_NAMES],
    });
    ({ session } = await createAgentSession({
      cwd, modelRuntime, model: modelRuntime.getModel('intelligent-cells-local-mock', 'intelligent-cells-mock'), thinkingLevel: 'off',
      resourceLoader: resources.loader, sessionManager: SessionManager.inMemory(cwd), settingsManager,
      // 0.99.2 uses a names allowlist and filters the entire tool registry, including
      // custom tools. tools:[] would disable remote tools too. Never omit this list.
      tools: [...REMOTE_TOOL_NAMES], noTools: 'builtin', excludeTools: [...STOCK_TOOL_NAMES],
      customTools: createRemoteTools({ dispatch, cancel, peerIds, runId, ...workspace, ensureWorkspaceBinding:prepareWorkspace, onCancel: item => emit({ type: 'remote_cancel', ...item }), onDispatch: item => { dispatches.push(item); emit({ type: 'remote_dispatch', ...item }); } }),
    }));
    const activeTools = session.getActiveToolNames().sort();
    const allTools = session.getAllTools().map(x => x.name).sort();
    const expected = [...REMOTE_TOOL_NAMES].sort();
    if (JSON.stringify(activeTools) !== JSON.stringify(expected) || JSON.stringify(allTools) !== JSON.stringify(expected)) {
      throw new Error('Pi tool registry violated the remote-only invariant');
    }
    emit({ type: 'pi_ready', package: PI_PACKAGE, version: VERSION, activeTools, allTools });
    session.subscribe(event => {
      if (event.type === 'tool_execution_start') emit({ type: event.type, toolName: event.toolName, toolCallId: event.toolCallId });
      if (event.type === 'tool_execution_end') emit({ type: event.type, toolName: event.toolName, toolCallId: event.toolCallId, isError: event.isError });
      if (event.type === 'agent_start' || event.type === 'agent_end' || event.type === 'agent_settled') emit({ type: event.type });
    });
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) throw Object.assign(new Error('Pi run was aborted'), { code: 'AGENT_ABORTED' });
    await session.prompt(effectivePrompt, { expandPromptTemplates: false, source: 'rpc' });
    if (signal?.aborted) throw Object.assign(new Error('Pi run was aborted; remote cancellation is best effort and cannot roll back committed I/O'), { code: 'AGENT_ABORTED' });
    const messages = structuredClone(session.messages);
    const final = messages.findLast(message => message.role === 'assistant');
    if (!final || final.stopReason !== 'stop') throw Object.assign(new Error(final?.errorMessage ?? 'Pi did not produce a final response'), { code: 'MODEL_ERROR' });
    const text = final.content.filter(block => block.type === 'text').map(block => block.text).join('\n');
    return { package: PI_PACKAGE, version: VERSION, model: 'intelligent-cells-local-mock/intelligent-cells-mock',
      mockedModel: true, runId, ...workspace, workspaceBindings:[...workspaceBindings.values()], resources: resources.loaded.map(({peerId,id,kind,sha256})=>({peerId,id,kind,sha256})), trustedExtensions: resources.extensions, activeTools, allTools, final: text, messages, audit, dispatches, modelRequests: mock.requests.length,
      modelContext: (mock.requests[0]?.messages ?? []).filter(message => ['system','user','developer'].includes(message.role)),
      modelToolDeclarations: mock.requests.map(request => (request.tools ?? []).map(tool => tool.function?.name)),
    };
  } finally {
    signal?.removeEventListener('abort', abort);
    session?.dispose();
    await mock.close();
  }
}

/** This wrapper is instantiated only by a node explicitly configured with pi-mock. */
export async function createPiRemoteAgent({ node }) {
  if (node?.config?.agent !== 'pi-mock') throw Object.assign(new Error('A servant without a configured agent cannot load Pi'), { code: 'AGENT_REQUIRED' });
  let activePromise, controller, disposed = false;
  return {
    name: `pi-mock/${PI_VERSION}`,
    async run({ prompt, scenario = 'read', runId = 'pi-default', promptResource, logicalWorkspaceId, workspaceId } = {}) {
      if (disposed) throw Object.assign(new Error('Pi agent is disposed'), { code: 'SHUTTING_DOWN' });
      if (activePromise) throw Object.assign(new Error('One Pi run is already active on this master'), { code: 'AGENT_BUSY' });
      controller = new AbortController();
      try {
        activePromise = runPiMock({ dispatch: (peerId, task, options) => node.dispatch(peerId, task, { signal:options?.signal ?? controller.signal }),
          cancel: (peerId, taskId) => node.cancel(peerId, taskId), signal: controller.signal,
          peerIds: [...node.peers.keys()], prompt, scenario, runId, promptResource, logicalWorkspaceId, workspaceId,
          ensureWorkspaceBinding: (peerId, selectedLogicalWorkspaceId) => node.ensureWorkspaceBinding(peerId, selectedLogicalWorkspaceId), resourceConfiguration: node.config.pi ?? {},
          onEvent: event => node.log('pi_event', event),
        });
        return await activePromise;
      } finally { activePromise = null; controller = null; }
    },
    async dispose() {
      disposed = true;
      controller?.abort();
      await activePromise?.catch(() => {});
    },
  };
}
