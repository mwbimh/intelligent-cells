import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { loadPolicy } from '../src/config.mjs';
import { runTool, capabilitySchema, validateRequest } from '../src/tools.mjs';
import { makeWorkspace, startNode, peer, waitConnected, stopAll } from '../scripts/process-helper.mjs';
import { connectOperator } from '../scripts/operator.mjs';

// Only disposable synthetic workspaces and output-only approved processes are
// used. This suite does not exercise previously denied browser or Unix IPC paths.
const fileTools = ['readFile', 'writeFile', 'editFile', 'listDirectory', 'searchFiles', 'mkdir', 'readChunk', 'writeChunk'];
const rule = (path, read, write) => ({ path, read, write });
const grants = [rule('docs', true, false), rule('work', true, true), rule('work/private', false, false), rule('work/private/reopened', true, false), rule('drop', false, true)];
async function fixture(t) {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'accept-directory-')));
  const root = path.join(directory, 'workspace');
  await fs.mkdir(root);
  for (const name of ['docs', 'work/private/reopened', 'drop', 'docs-extra']) await fs.mkdir(path.join(root, name), { recursive: true });
  for (const [name, contents] of Object.entries({ 'root.txt': 'root marker', 'docs/readme.txt': 'needle public docs', 'docs-extra/other.txt': 'needle sibling', 'work/public.txt': 'needle work', 'work/private/hidden.txt': 'needle private', 'work/private/reopened/open.txt': 'needle reopened', 'drop/input.txt': 'drop original' })) await fs.writeFile(path.join(root, name), contents);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  let sequence = 0;
  const compile = async (extra = {}, tools = fileTools) => (await loadPolicy({ grants: { master: { tools, workspace: root, directories: grants, ...extra } } }, directory)).grants.get('master');
  const execute = (grant, tool, args) => runTool({ taskId: `accept_${++sequence}`, tool, args, timeoutMs: 1000 }, grant);
  return { directory, root, compile, execute };
}

test('directory acceptance: separate readable, editable, write-only and excluded directories enforce all file operations', async t => {
  const { root, compile, execute } = await fixture(t), grant = await compile();
  assert.equal((await execute(grant, 'readFile', { path: 'docs/readme.txt' })).text, 'needle public docs');
  assert.deepEqual((await execute(grant, 'listDirectory', { path: 'docs' })).entries.map(e => e.name), ['readme.txt']);
  assert.equal((await execute(grant, 'searchFiles', { path: 'docs', query: 'needle' })).matches[0].path, 'docs/readme.txt');
  assert.equal(Buffer.from((await execute(grant, 'readChunk', { path: 'docs/readme.txt', length: 6 })).base64, 'base64').toString(), 'needle');
  for (const [tool, args] of [
    ['writeFile', { path: 'docs/new.txt', text: 'denied' }], ['editFile', { path: 'docs/readme.txt', oldText: 'needle', newText: 'denied' }],
    ['mkdir', { path: 'docs/new' }], ['writeChunk', { path: 'docs/new.bin', base64: 'AA==' }],
    ['readFile', { path: 'drop/input.txt' }], ['readChunk', { path: 'drop/input.txt' }], ['listDirectory', { path: 'drop' }],
    ['searchFiles', { path: 'drop', query: 'original' }], ['editFile', { path: 'drop/input.txt', oldText: 'original', newText: 'changed' }],
  ]) await assert.rejects(execute(grant, tool, args), { code: 'DIRECTORY_DENIED' }, `${tool} must honor independent read/write checks`);
  await execute(grant, 'mkdir', { path: 'work/generated' });
  await execute(grant, 'writeFile', { path: 'work/generated/result.txt', text: 'original' });
  await execute(grant, 'editFile', { path: 'work/generated/result.txt', oldText: 'original', newText: 'updated' });
  assert.equal((await execute(grant, 'readFile', { path: 'work/generated/result.txt' })).text, 'updated');
  await execute(grant, 'writeFile', { path: 'drop/output.txt', text: 'blind upload' });
  await execute(grant, 'writeFile', { path: 'drop/input.txt', text: 'replaced', overwrite: true });
  await execute(grant, 'mkdir', { path: 'drop/generated' });
  const payload = Buffer.from([0, 255, 128, 65]);
  const created = await execute(grant, 'writeChunk', { path: 'drop/transfer.bin', base64: payload.subarray(0, 2).toString('base64') });
  const appended = await execute(grant, 'writeChunk', { path: 'drop/transfer.bin', base64: payload.subarray(2).toString('base64'), offset: 2 });
  assert.deepEqual(Object.keys(created).sort(), ['bytes', 'nextOffset', 'offset', 'path']);
  assert.deepEqual(Object.keys(appended).sort(), ['bytes', 'nextOffset', 'offset', 'path']);
  assert.deepEqual(await fs.readFile(path.join(root, 'drop/transfer.bin')), payload);
  await execute(grant, 'writeChunk', { path: 'work/roundtrip.bin', base64: payload.toString('base64') });
  assert.deepEqual(Buffer.from((await execute(grant, 'readChunk', { path: 'work/roundtrip.bin' })).base64, 'base64'), payload);
  await assert.rejects(execute(grant, 'writeChunk', { path: 'work/roundtrip.bin', base64: 'AA==', offset: 1 }), { code: 'OFFSET_MISMATCH' });
  assert.deepEqual(await fs.readFile(path.join(root, 'work/roundtrip.bin')), payload);
  assert.equal(await fs.readFile(path.join(root, 'docs/readme.txt'), 'utf8'), 'needle public docs');
  await assert.rejects(fs.stat(path.join(root, 'docs/new.txt')), { code: 'ENOENT' });
});

test('directory acceptance: longest complete-segment rule wins; listing/search prune excluded descendants deterministically', async t => {
  const { compile, execute } = await fixture(t), grant = await compile();
  for (const relative of ['root.txt', 'docs-extra/other.txt', 'work/private/hidden.txt']) {
    await assert.rejects(execute(grant, 'readFile', { path: relative }), { code: 'DIRECTORY_DENIED' });
    await assert.rejects(execute(grant, 'writeFile', { path: relative, text: 'denied', overwrite: true }), { code: 'DIRECTORY_DENIED' });
  }
  for (const tool of ['listDirectory', 'searchFiles']) await assert.rejects(execute(grant, tool, tool === 'searchFiles' ? { query: 'needle' } : {}), { code: 'DIRECTORY_DENIED' });
  const page = await execute(grant, 'listDirectory', { path: 'work', limit: 1 });
  assert.deepEqual(page.entries.map(e => e.name), ['public.txt']);
  assert.equal(page.total, 1); assert.equal(page.eof, true);
  const result = await execute(grant, 'searchFiles', { path: 'work', query: 'needle' });
  assert.deepEqual(result.matches.map(m => m.path), ['work/public.txt']);
  assert.doesNotMatch(JSON.stringify(result), /hidden\.txt|reopened|needle private/);
  assert.equal((await execute(grant, 'readFile', { path: 'work/private/reopened/open.txt' })).text, 'needle reopened');
  assert.deepEqual((await execute(grant, 'searchFiles', { path: 'work/private/reopened', query: 'needle' })).matches.map(m => m.path), ['work/private/reopened/open.txt']);
  const reverse = await compile({ directories: [...grants].reverse() });
  assert.deepEqual(await execute(reverse, 'listDirectory', { path: 'work' }), await execute(grant, 'listDirectory', { path: 'work' }));
  await assert.rejects(execute(reverse, 'readFile', { path: 'work/private/hidden.txt' }), { code: 'DIRECTORY_DENIED' });
  const rootRead = await compile({ directories: [rule('', true, false), rule('work/private', false, false)] });
  assert.equal((await execute(rootRead, 'readFile', { path: 'root.txt' })).text, 'root marker');
  assert.ok(!(await execute(rootRead, 'searchFiles', { query: 'needle' })).matches.some(m => m.path.startsWith('work/private/')));
});

test('directory acceptance: ACL never creates a tool grant, omitted legacy differs from explicit empty and malformed rules reject', async t => {
  const { compile, execute } = await fixture(t);
  const future = await compile({ directories: [rule('future', true, true)] });
  await execute(future, 'mkdir', { path: 'future' });
  await execute(future, 'writeFile', { path: 'future/new.txt', text: 'owner approved future directory' });
  assert.equal((await execute(future, 'readFile', { path: 'future/new.txt' })).text, 'owner approved future directory');
  await assert.rejects(compile({ directories: [rule('docs/readme.txt', true, false)] }), { code: 'INVALID_CONFIG' });
  const empty = await compile({ directories: [] });
  for (const [tool, args] of [['readFile', { path: 'docs/readme.txt' }], ['writeFile', { path: 'work/no.txt', text: 'no' }], ['listDirectory', {}]]) await assert.rejects(execute(empty, tool, args), { code: 'DIRECTORY_DENIED' });
  const legacy = await compile({ directories: undefined });
  assert.equal((await execute(legacy, 'readFile', { path: 'root.txt' })).text, 'root marker');
  const toolRestricted = await compile({ directories: [rule('', true, true)] }, ['readFile']);
  await assert.rejects(execute(toolRestricted, 'writeFile', { path: 'work/no.txt', text: 'no' }), { code: 'TOOL_DENIED' });
  assert.throws(() => validateRequest({ taskId: 'other_peer', tool: 'readFile', args: { path: 'docs/readme.txt' }, timeoutMs: 1000 }, 'other', toolRestricted), { code: 'MASTER_DENIED' });
  for (const directories of [null, {}, 'docs', [rule('docs', true, false), rule('docs', false, true)], [{ path: 'docs', read: true }], [{ path: 'docs', read: 'yes', write: false }], [{ path: 'docs', read: true, write: false, unsupported: true }], Array.from({ length: 129 }, (_, i) => rule(`dir${i}`, true, false))]) await assert.rejects(compile({ directories }), { code: 'INVALID_CONFIG' });
  for (const name of ['/absolute', '../parent', 'docs/../work', 'docs//child', 'docs\\child', 'docs/', 'docs/.', 'NUL', 'docs:alias']) await assert.rejects(compile({ directories: [rule(name, true, false)] }), { code: 'INVALID_CONFIG' });
  for (const name of ['../parent', '/absolute', 'docs//readme.txt', 'docs\\readme.txt']) await assert.rejects(execute(legacy, 'readFile', { path: name }), { code: 'PATH_DENIED' });
});

test('directory acceptance: approved resources and capability discovery respect the same effective read rules', async t => {
  const { compile, execute, root } = await fixture(t);
  const grant = await compile({ resources: { visible: { kind: 'instruction', path: 'docs/readme.txt' }, hidden: { kind: 'skill', path: 'work/private/hidden.txt' }, writeonly: { kind: 'prompt', path: 'drop/input.txt' } } }, [...fileTools, 'capabilities', 'resourceList', 'resourceRead']);
  assert.deepEqual((await execute(grant, 'resourceList', {})).resources.map(r => r.id), ['visible']);
  assert.equal((await execute(grant, 'resourceRead', { resource: 'visible' })).text, 'needle public docs');
  for (const resource of ['hidden', 'writeonly']) await assert.rejects(execute(grant, 'resourceRead', { resource }), { code: 'DIRECTORY_DENIED' });
  const caps = capabilitySchema(grant);
  assert.deepEqual(caps.resources.map(r => r.id), ['visible']);
  assert.equal(JSON.stringify(caps).includes(root), false, 'Remote capabilities must not disclose host workspace path');
  assert.doesNotMatch(JSON.stringify(caps.resources), /hidden|writeonly/);
});

test('directory acceptance: scoped process grants require explicit unsandboxed acknowledgement and never arise from file rights', async t => {
  const { directory, root, compile, execute } = await fixture(t);
  const script = path.join(directory, 'approved-output-only.mjs');
  await fs.writeFile(script, "process.stdout.write('approved output only');\n");
  const commands = { describe: { file: process.execPath, args: [script] } };
  for (const tool of ['exec', 'mcpList', 'mcpCall']) {
    for (const acknowledgement of [undefined, false]) await assert.rejects(compile({ execCommands: tool === 'exec' ? commands : {}, allowUnsandboxedProcesses: acknowledgement }, [tool]), { code: 'INVALID_CONFIG' });
    assert.ok(await compile({ execCommands: tool === 'exec' ? commands : {}, allowUnsandboxedProcesses: true }, [tool]));
  }
  const fileOnly = await compile({ execCommands: commands });
  await assert.rejects(execute(fileOnly, 'exec', { command: 'describe', args: [] }), { code: 'TOOL_DENIED' });
  const approved = await compile({ directories: [], execCommands: commands, allowUnsandboxedProcesses: true }, ['exec', 'readFile']);
  assert.equal((await execute(approved, 'exec', { command: 'describe', args: [] })).stdout, 'approved output only');
  await assert.rejects(execute(approved, 'readFile', { path: 'docs/readme.txt' }), { code: 'DIRECTORY_DENIED' });
  // Compile-only invariant: directory restrictions do not relax code isolation.
  const inside = path.join(root, 'work', 'empty.mjs'); await fs.writeFile(inside, '');
  await assert.rejects(compile({ execCommands: { local: { file: process.execPath, args: [inside] } }, allowUnsandboxedProcesses: true }, ['exec', 'writeFile']), { code: 'UNSAFE_EXEC_POLICY' });
});

test('directory acceptance: real mTLS peer separation and owner HTTP update, conflict, revoke and restart persist exact scope', { timeout: 30000 }, async t => {
  const dir = await makeWorkspace('accept-directory-owner-'), nodes = [];
  let client;
  try {
    for (const name of ['docs', 'work']) await fs.mkdir(path.join(dir, 'workspace', name));
    await fs.writeFile(path.join(dir, 'workspace/docs/guide.txt'), 'shared synthetic guide');
    await fs.writeFile(path.join(dir, 'workspace/work/task.txt'), 'synthetic editable task');
    const policy = { grants: {
      master: { tools: [...fileTools, 'capabilities'], workspace: 'workspace', directories: [rule('docs', true, false), rule('work', true, true)] },
      observer: { tools: ['readFile', 'listDirectory'], workspace: 'workspace', directories: [rule('docs', true, false)] },
    } };
    const config = { id: 'servant', port: 0, operator: { enabled: true, port: 0 }, policy };
    let servant = await startNode(dir, config); nodes.push(servant);
    client = await connectOperator((await servant.wait(e => e.event === 'operator_ready')).ownerFile, { sessionFile: true });
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', peers: [peer(servant)], policy: {} }); nodes.push(master);
    const observer = await startNode(dir, { id: 'observer', port: 0, agent: 'deterministic-demo', peers: [peer(servant)], policy: {} }); nodes.push(observer);
    await Promise.all([waitConnected(master, 'servant'), waitConnected(observer, 'servant')]);
    let sequence = 0;
    const dispatch = async (source, tool, args) => (await source.command({ command: 'dispatch', peerId: 'servant', task: { taskId: `owner_accept_${++sequence}`, tool, args, timeoutMs: 1000 } })).result;
    assert.equal((await dispatch(master, 'readFile', { path: 'work/task.txt' })).status, 'ok');
    assert.equal((await dispatch(observer, 'readFile', { path: 'work/task.txt' })).error.code, 'DIRECTORY_DENIED');
    assert.equal((await dispatch(observer, 'readFile', { path: 'docs/guide.txt' })).result.text, 'shared synthetic guide');
    assert.equal((await dispatch(master, 'writeFile', { path: 'work/created.txt', text: 'approved' })).status, 'ok');
    assert.equal((await dispatch(master, 'writeFile', { path: 'docs/no.txt', text: 'denied' })).error.code, 'DIRECTORY_DENIED');
    const before = (await client.request('/api/state')).permissions;
    assert.deepEqual(before.effectivePolicy.grants.master.directories, policy.grants.master.directories);
    assert.equal(before.directoryPolicies.master.mode, 'scoped');
    assert.equal(before.directoryPolicies.master.defaultAccess, 'deny');
    assert.deepEqual(before.directoryPolicies.master.directories, policy.grants.master.directories);
    assert.equal(before.directoryPolicies.master.processAccess, 'not-granted');
    const capabilities = (await dispatch(master, 'capabilities', {})).result;
    assert.deepEqual(capabilities.filesystem, before.directoryPolicies.master);
    const updated = structuredClone(policy); updated.grants.master.directories = [rule('docs', true, false)];
    const applied = (await client.request('/api/command', { command: 'setPolicy', policy: updated, expectedEpoch: before.epoch })).result;
    assert.equal(applied.epoch, before.epoch + 1);
    const retained = await master.command({ command: 'dispatch', peerId: 'servant', task: { taskId: 'owner_accept_1', tool: 'readFile', args: { path: 'work/task.txt' }, timeoutMs: 1000 } });
    assert.equal(retained.result.error.code, 'TASK_POLICY_CHANGED', 'A previously readable cached result cannot outlive the permission epoch');
    assert.equal((await dispatch(master, 'readFile', { path: 'work/task.txt' })).error.code, 'DIRECTORY_DENIED');
    assert.equal((await dispatch(observer, 'readFile', { path: 'docs/guide.txt' })).status, 'ok');
    await assert.rejects(client.request('/api/command', { command: 'setPolicy', policy, expectedEpoch: before.epoch }), /POLICY_CONFLICT/);
    const invalid = structuredClone(updated); invalid.grants.master.directories = [rule('docs', true, false), rule('docs', false, true)];
    await assert.rejects(client.request('/api/command', { command: 'setPolicy', policy: invalid, expectedEpoch: applied.epoch }), /INVALID_CONFIG/);
    assert.equal((await client.request('/api/state')).permissions.epoch, applied.epoch);
    const port = servant.port, afterMaster = master.events.length, afterObserver = observer.events.length;
    await client.request('/api/logout', {}); client = null; await servant.stop();
    servant = await startNode(dir, { ...config, port }); nodes.push(servant);
    await Promise.all([waitConnected(master, 'servant', afterMaster), waitConnected(observer, 'servant', afterObserver)]);
    client = await connectOperator((await servant.wait(e => e.event === 'operator_ready')).ownerFile, { sessionFile: true });
    const restarted = (await client.request('/api/state')).permissions;
    assert.equal(restarted.epoch, applied.epoch);
    assert.deepEqual(restarted.effectivePolicy, updated, 'Restart must use persisted update rather than initial config');
    assert.equal((await dispatch(master, 'readFile', { path: 'work/task.txt' })).error.code, 'DIRECTORY_DENIED');
    assert.equal((await dispatch(master, 'readFile', { path: 'docs/guide.txt' })).status, 'ok');
    const revoked = (await client.request('/api/command', { command: 'revoke', masterId: 'master' })).result;
    assert.equal(revoked.revoked, 'master');
    assert.equal((await dispatch(master, 'readFile', { path: 'docs/guide.txt' })).error.code, 'MASTER_DENIED');
    assert.equal((await dispatch(observer, 'readFile', { path: 'docs/guide.txt' })).status, 'ok');
    const afterObserver2 = observer.events.length;
    await client.request('/api/logout', {}); client = null; await servant.stop();
    servant = await startNode(dir, { ...config, port }); nodes.push(servant);
    await Promise.all([servant.wait(e => e.event === 'relationship_denied' && e.claimedNodeId === 'master'), waitConnected(observer, 'servant', afterObserver2)]);
    client = await connectOperator((await servant.wait(e => e.event === 'operator_ready')).ownerFile, { sessionFile: true });
    const state = await client.request('/api/state');
    assert.ok(state.permissions.revoked.includes('master')); assert.equal(state.permissions.effectivePolicy.grants.master, undefined);
    assert.deepEqual(state.permissions.effectivePolicy.grants.observer, policy.grants.observer);
    const disconnected = await master.command({ command: 'dispatch', peerId: 'servant', task: { taskId: 'revoked_after_restart', tool: 'readFile', args: { path: 'docs/guide.txt' }, timeoutMs: 1000 } });
    assert.equal(disconnected.error.code, 'PEER_UNAVAILABLE');
    assert.equal((await dispatch(observer, 'readFile', { path: 'docs/guide.txt' })).status, 'ok');
    assert.equal(await fs.readFile(path.join(dir, 'workspace/work/created.txt'), 'utf8'), 'approved');
    await assert.rejects(fs.stat(path.join(dir, 'workspace/docs/no.txt')), { code: 'ENOENT' });
  } finally { await client?.request('/api/logout', {}).catch(() => {}); await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});
