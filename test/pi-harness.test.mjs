import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { runPiMock, createPiRemoteAgent, PI_VERSION, PI_PACKAGE } from '../integration/pi/agent.mjs';
import { REMOTE_TOOL_NAMES } from '../integration/pi/remote-tools.mjs';
import { startMockModel } from '../integration/pi/mock-model.mjs';

const base = { peerIds: ['servant'], prompt: 'Read the approved servant file' };
const toolResults = result => result.messages.filter(x => x.role === 'toolResult');

test('actual pinned Pi SDK performs streaming model -> tool execution -> next model request -> final answer', async () => {
  const dispatched = [];
  const result = await runPiMock({ ...base, dispatch: async (peerId, task) => {
    dispatched.push({ peerId, task });
    return { status: 'ok', result: { text: 'SERVANT_RESULT_UNIQUE_MARKER' } };
  } });
  assert.equal(result.package, PI_PACKAGE);
  assert.equal(result.version, PI_VERSION);
  assert.equal(result.mockedModel, true);
  assert.equal(result.modelRequests, 2);
  assert.equal(dispatched.length, 1);
  assert.equal(dispatched[0].peerId, 'servant');
  assert.equal(dispatched[0].task.tool, 'readFile');
  assert.deepEqual(dispatched[0].task.args, { path: 'hello.txt' });
  assert.match(dispatched[0].task.taskId, /^pi_[a-f0-9]{32}$/);
  assert.deepEqual(result.activeTools, [...REMOTE_TOOL_NAMES].sort());
  assert.deepEqual(result.allTools, [...REMOTE_TOOL_NAMES].sort());
  for (const names of result.modelToolDeclarations) assert.deepEqual([...names].sort(), [...REMOTE_TOOL_NAMES].sort());
  assert.ok(result.audit.some(x => x.type === 'tool_execution_start' && x.toolName === 'remote_read'));
  assert.ok(result.audit.some(x => x.type === 'tool_execution_end' && x.isError === false));
  assert.match(result.final, /SERVANT_RESULT_UNIQUE_MARKER/);
  assert.equal(toolResults(result)[0].isError, false);
  assert.equal(result.messages.findLast(x => x.role === 'assistant').stopReason, 'stop');
});

test('a hostile model cannot invoke any stock Pi filesystem or shell tool', async () => {
  const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'pi-no-local-'));
  try {
    let dispatches = 0;
    const result = await runPiMock({ ...base, cwd, scenario: 'local-bypass', dispatch: async () => { dispatches++; throw new Error('Should never dispatch'); } });
    assert.equal(dispatches, 0);
    assert.equal(result.modelRequests, 9);
    assert.equal(toolResults(result).length, 8);
    assert.ok(toolResults(result).every(x => x.isError));
    assert.ok(toolResults(result).every(x => /not found/i.test(JSON.stringify(x.content))));
    assert.deepEqual(await fs.readdir(cwd), []);
    assert.doesNotMatch(result.final, /root:x:0:/);
  } finally { await fs.rm(cwd, { recursive: true, force: true }); }
});

test('Pi validates malformed tool arguments before remote dispatch', async () => {
  let count = 0;
  const result = await runPiMock({ ...base, calls: [{ name: 'remote_read', arguments: { peerId: 'servant' } }],
    dispatch: async () => { count++; throw new Error('Must not execute'); } });
  assert.equal(count, 0);
  assert.equal(toolResults(result)[0].isError, true);
  assert.match(result.final, /path/);
});

test('unknown servant is refused without transport or local fallback', async () => {
  let count = 0;
  const result = await runPiMock({ ...base, calls: [{ name: 'remote_echo', arguments: { peerId: 'not-configured', text: 'x' } }],
    dispatch: async () => { count++; } });
  assert.equal(count, 0);
  assert.equal(toolResults(result)[0].isError, true);
  assert.match(result.final, /UNKNOWN_PEER/);
});

test('servant policy denials become Pi error tool results and reach the final model', async () => {
  let count = 0;
  const result = await runPiMock({ ...base, dispatch: async () => {
    count++; return { status: 'error', error: { code: 'PATH_DENIED', message: 'Outside servant workspace' } };
  } });
  assert.equal(count, 1);
  assert.equal(toolResults(result)[0].isError, true);
  assert.match(result.final, /PATH_DENIED/);
  assert.equal(result.modelRequests, 2);
});

test('transport uncertainty reaches Pi without replay or local fallback', async () => {
  let count = 0;
  const result = await runPiMock({ ...base, dispatch: async () => {
    count++; throw Object.assign(new Error('OUTCOME_UNKNOWN: disconnected after dispatch'), { code: 'OUTCOME_UNKNOWN' });
  } });
  assert.equal(count, 1);
  assert.equal(toolResults(result)[0].isError, true);
  assert.match(result.final, /OUTCOME_UNKNOWN/);
});

test('non-agent nodes and invalid input cannot start a Pi run', async () => {
  await assert.rejects(createPiRemoteAgent({ node: { config: {} } }), { code: 'AGENT_REQUIRED' });
  await assert.rejects(runPiMock({ ...base, peerIds: [] }), { code: 'NO_SERVANTS' });
  await assert.rejects(runPiMock({ ...base, prompt: '' }), { code: 'INVALID_PROMPT' });
  await assert.rejects(runPiMock({ ...base, scenario: 'does-not-exist' }), { code: 'INVALID_SCENARIO' });
});

test('mock model listener is loopback-only, bounded and closes cleanly', async () => {
  const mock = await startMockModel({ calls: [] });
  assert.match(mock.url, /^http:\/\/127\.0\.0\.1:\d+\/v1$/);
  const bad = await fetch(mock.url + '/invalid');
  assert.equal(bad.status, 404);
  const response = await fetch(mock.url + '/chat/completions', {
    method: 'POST', body: JSON.stringify({ model: 'intelligent-cells-mock', stream: true, messages: [] }),
  });
  assert.equal(response.status, 200);
  assert.match(await response.text(), /data: \[DONE\]/);
  assert.equal(mock.requests.length, 1);
  await mock.close();
  await new Promise((resolve, reject) => {
    const socket = net.connect(mock.port, '127.0.0.1');
    socket.on('connect', () => { socket.destroy(); reject(new Error('Mock listener still active')); });
    socket.on('error', error => { assert.equal(error.code, 'ECONNREFUSED'); resolve(); });
  });
});

test('Pi abort sends best-effort cancellation for the same remote task and waits for its result', async () => {
  const controller = new AbortController();
  let resolveRemote, taskId, cancelled = 0;
  const run = runPiMock({ ...base, signal: controller.signal,
    dispatch: async (_peer, task) => { taskId = task.taskId; return new Promise(resolve => { resolveRemote = resolve; }); },
    cancel: async (peerId, id) => {
      assert.equal(peerId, 'servant'); assert.equal(id, taskId); cancelled++;
      resolveRemote({ status: 'error', error: { code: 'CANCELLED', message: 'Servant cancellation confirmed' } });
      return { requested: true };
    },
    onEvent: event => { if (event.type === 'remote_dispatch') controller.abort(); },
  });
  await assert.rejects(run, { code: 'AGENT_ABORTED' });
  assert.equal(cancelled, 1);
});

test('one master rejects concurrent Pi runs and dispose prevents future runs', async () => {
  let notifyDispatched;
  const dispatched = new Promise(resolve => { notifyDispatched = resolve; });
  let resolveRemote;
  const node = {
    config: { agent: 'pi-mock' }, peers: new Map([['servant', {}]]),
    log: () => {},
    dispatch: async () => { notifyDispatched(); return new Promise(resolve => { resolveRemote = resolve; }); },
    cancel: () => { resolveRemote({ status: 'error', error: { code: 'CANCELLED', message: 'cancelled' } }); return { requested: true }; },
  };
  const agent = await createPiRemoteAgent({ node });
  const first = agent.run({ prompt: 'Read remote file' });
  const rejection = assert.rejects(first, { code: 'AGENT_ABORTED' });
  await dispatched;
  await assert.rejects(agent.run({ prompt: 'Second concurrent prompt' }), { code: 'AGENT_BUSY' });
  await agent.dispose();
  await rejection;
  await assert.rejects(agent.run({ prompt: 'After disposal' }), { code: 'SHUTTING_DOWN' });
});
