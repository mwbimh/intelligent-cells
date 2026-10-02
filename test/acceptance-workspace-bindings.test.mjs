import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, startNode, peer, waitConnected, stopAll } from '../scripts/process-helper.mjs';
import { connectOperator } from '../scripts/operator.mjs';

// Disposable local fixtures only. These checks never use a production workspace,
// a browser, a Unix socket, an external listener or a remotely supplied shell.
const directory = (read, write) => [{ path: '', read, write }];
const createdTools = ['capabilities', 'readFile', 'readChunk', 'listDirectory', 'searchFiles', 'writeFile', 'writeChunk', 'editFile', 'mkdir'];
let sequence = 0;
const task = (tool, args, selectors = {}) => ({ taskId: `workspace_accept_${++sequence}`, tool, args, timeoutMs: 2000, ...selectors });
async function owner(node) {
  const ready = await node.wait(event => event.event === 'operator_ready');
  return connectOperator(ready.ownerFile, { sessionFile: true });
}
async function dispatch(node, servant, tool, args, selectors) {
  const response = await node.command({ command: 'dispatch', peerId: servant.id, task: task(tool, args, selectors) });
  return response.result ?? { status: 'error', error: response.error };
}
const success = response => { assert.equal(response.status, 'ok', JSON.stringify(response)); return response.result; };
const command = async (client, value) => (await client.request('/api/command', value)).result;
const bindings = client => command(client, { command: 'listWorkspaceBindings' });
const catalogue = (client, peerId) => command(client, { command: 'remoteWorkspaces', peerId });
async function layout(dir) {
  for (const name of ['reference', 'pool-master']) await fs.mkdir(path.join(dir, name));
  await fs.writeFile(path.join(dir, 'reference', 'origin.txt'), 'configured reference');
}
function servantConfig() {
  return { id: 'servant', port: 0, operator: { enabled: true, port: 0 }, policy: { grants: {
    master: {
      tools: ['workspaceList', 'workspaceCreate', 'readFile'], workspace: 'workspace', directories: directory(true, false),
      workspaces: { reference: { tools: ['readFile', 'listDirectory'], workspace: 'reference', directories: directory(true, false) } },
      workspaceProvisioning: { roots: { projects: { path: 'pool-master', maxWorkspaces: 2, grant: { tools: createdTools, directories: directory(true, true) } } } },
    },
    observer: { tools: ['workspaceList', 'readFile'], workspace: 'workspace', directories: directory(true, false) },
  } } };
}

test('workspace acceptance: owner HTTP catalogues, exact bindings and provisioning are peer-scoped, idempotent and restart durable', { timeout: 30000 }, async () => {
  const dir = await makeWorkspace('accept-workspace-lifecycle-'), nodes = [];
  let client;
  try {
    await layout(dir);
    const config = servantConfig();
    let servant = await startNode(dir, config); nodes.push(servant);
    const masterConfig = { id: 'master', port: 0, agent: 'deterministic-demo', operator: { enabled: true, port: 0 }, peers: [peer(servant)], policy: {} };
    let master = await startNode(dir, masterConfig); nodes.push(master); client = await owner(master);
    const observer = await startNode(dir, { id: 'observer', port: 0, agent: 'deterministic-demo', peers: [peer(servant)], policy: {} }); nodes.push(observer);
    await Promise.all([waitConnected(master, 'servant'), waitConnected(observer, 'servant')]);
    const catalog = await catalogue(client, 'servant');
    assert.ok(catalog.workspaces.some(workspace => workspace.id === 'default'));
    assert.ok(catalog.workspaces.some(workspace => workspace.id === 'reference'));
    assert.equal(catalog.creationRoots.find(root => root.id === 'projects').used, 0);
    assert.equal(catalog.creationRoots.find(root => root.id === 'projects').remaining, 2);
    assert.equal(JSON.stringify(catalog).includes(dir), false, 'Remote catalog must not expose physical owner paths');
    assert.equal((await client.request('/api/state')).workspaces.revision, (await bindings(client)).revision);
    const before = await bindings(client);
    await command(client, { command: 'bindWorkspace', logicalWorkspaceId: 'project', peerId: 'servant', workspaceId: 'reference', expectedRevision: before.revision });
    const bound = await bindings(client);
    assert.equal(bound.bindings.find(binding => binding.logicalWorkspaceId === 'project' && binding.peerId === 'servant').workspaceId, 'reference');
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'origin.txt' }, { logicalWorkspaceId: 'project' })).text, 'configured reference');
    assert.match(success(await dispatch(master, servant, 'readFile', { path: 'hello.txt' })).text, /servant-owned/);
    await assert.rejects(command(client, { command: 'bindWorkspace', logicalWorkspaceId: 'project', peerId: 'servant', workspaceId: 'default', expectedRevision: before.revision }), /WORKSPACE_BINDING_CONFLICT/);
    await assert.rejects(command(client, { command: 'bindWorkspace', logicalWorkspaceId: 'project', peerId: 'servant', workspaceId: 'missing', expectedRevision: bound.revision }), /WORKSPACE_DENIED/);
    assert.equal((await bindings(client)).revision, bound.revision);
    await assert.rejects(command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'missing', name: 'safe-name', creationRequestId: 'bad_root' }), /WORKSPACE_CREATE_DENIED/);
    await assert.rejects(command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'projects', name: 'not-a-child/name', creationRequestId: 'invalid_name' }), /INVALID_ARGS/);
    assert.equal((await catalogue(client, 'servant')).creationRoots.find(root => root.id === 'projects').used, 0);
    const first = await command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'projects', name: 'project-one', creationRequestId: 'create_one' });
    assert.ok(first.workspace.id.startsWith('ws_'));
    const firstId = first.workspace.id;
    const repeat = await command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'projects', name: 'project-one', creationRequestId: 'create_one' });
    assert.equal(repeat.workspace.id, firstId);
    await assert.rejects(command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'projects', name: 'different-name', creationRequestId: 'create_one' }), /WORKSPACE_REQUEST_CONFLICT|TASK_ID_CONFLICT/);
    await assert.rejects(command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'projects', name: 'project-one', creationRequestId: 'different_request' }), /WORKSPACE_NAME_CONFLICT/);
    assert.equal((await catalogue(client, 'servant')).creationRoots.find(root => root.id === 'projects').used, 1);
    await command(client, { command: 'bindWorkspace', logicalWorkspaceId: 'project', peerId: 'servant', workspaceId: firstId, expectedRevision: (await bindings(client)).revision });
    assert.equal(success(await dispatch(master, servant, 'writeFile', { path: 'project.txt', text: 'first persistent project' }, { logicalWorkspaceId: 'project' })).path, 'project.txt');
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'project.txt' }, { logicalWorkspaceId: 'project' })).text, 'first persistent project');
    assert.equal((await dispatch(master, servant, 'writeFile', { path: 'not-default.txt', text: 'denied' })).error.code, 'TOOL_DENIED');
    assert.equal((await dispatch(observer, servant, 'readFile', { path: 'project.txt' }, { workspaceId: firstId })).error.code, 'WORKSPACE_DENIED');
    const observerCatalogue = success(await dispatch(observer, servant, 'workspaceList', {}));
    assert.ok(!observerCatalogue.workspaces.some(workspace => workspace.id === firstId));
    assert.deepEqual(observerCatalogue.creationRoots, []);
    const latest = await bindings(client);
    const second = await command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'projects', name: 'project-two', creationRequestId: 'create_two', logicalWorkspaceId: 'second', expectedRevision: latest.revision });
    assert.notEqual(second.workspace.id, firstId);
    const secondId = second.workspace.id;
    assert.equal((await bindings(client)).bindings.find(binding => binding.logicalWorkspaceId === 'second').workspaceId, secondId);
    success(await dispatch(master, servant, 'writeFile', { path: 'project.txt', text: 'second persistent project' }, { logicalWorkspaceId: 'second' }));
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'project.txt' }, { logicalWorkspaceId: 'project' })).text, 'first persistent project');
    await assert.rejects(command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'projects', name: 'project-three', creationRequestId: 'create_three' }), /WORKSPACE_QUOTA/);
    assert.equal((await catalogue(client, 'servant')).creationRoots.find(root => root.id === 'projects').used, 2);
    await command(client, { command: 'unbindWorkspace', logicalWorkspaceId: 'project', peerId: 'servant', expectedRevision: (await bindings(client)).revision });
    assert.equal((await dispatch(master, servant, 'readFile', { path: 'hello.txt' }, { logicalWorkspaceId: 'project' })).error.code, 'WORKSPACE_BINDING_NOT_FOUND');
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'project.txt' }, { workspaceId: firstId })).text, 'first persistent project', 'Unbind never deletes the servant directory');
    const persisted = await bindings(client), port = servant.port;
    await client.request('/api/logout', {}); client = null; await master.stop(); await servant.stop();
    servant = await startNode(dir, { ...config, port }); nodes.push(servant);
    master = await startNode(dir, masterConfig); nodes.push(master); await waitConnected(master, 'servant'); client = await owner(master);
    const restartedBindings = await bindings(client);
    assert.deepEqual(restartedBindings, persisted);
    const restartedCatalog = await catalogue(client, 'servant');
    assert.equal(restartedCatalog.workspaces.filter(workspace => [firstId, secondId].includes(workspace.id)).length, 2);
    assert.equal(restartedCatalog.creationRoots.find(root => root.id === 'projects').used, 2);
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'project.txt' }, { logicalWorkspaceId: 'second' })).text, 'second persistent project');
    assert.equal((await dispatch(master, servant, 'readFile', { path: 'hello.txt' }, { logicalWorkspaceId: 'project' })).error.code, 'WORKSPACE_BINDING_NOT_FOUND');
    assert.equal((await command(client, { command: 'createWorkspace', peerId: 'servant', rootId: 'projects', name: 'project-one', creationRequestId: 'create_one' })).workspace.id, firstId);
    assert.equal((await catalogue(client, 'servant')).creationRoots.find(root => root.id === 'projects').used, 2);
    await assert.rejects(fs.stat(path.join(dir, 'workspace', 'not-default.txt')), { code: 'ENOENT' });
  } finally { await client?.request('/api/logout', {}).catch(() => {}); await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('workspace acceptance: one logical project binds independently per servant and selector conflicts never broaden routing', { timeout: 20000 }, async () => {
  const dir = await makeWorkspace('accept-workspace-routing-'), nodes = [];
  let client;
  try {
    for (const id of ['a', 'b']) { await fs.mkdir(path.join(dir, `work-${id}`)); await fs.writeFile(path.join(dir, `work-${id}/origin.txt`), `servant-${id}`); }
    const servers = [];
    for (const id of ['a', 'b']) { const node = await startNode(dir, { id: `servant-${id}`, port: 0, policy: { grants: { master: { tools: ['workspaceList'], workspaces: { repo: { workspace: `work-${id}`, tools: ['readFile'], directories: directory(true, false) } } } } } }); nodes.push(node); servers.push(node); }
    const master = await startNode(dir, { id: 'master', port: 0, agent: 'deterministic-demo', operator: { enabled: true, port: 0 }, peers: servers.map(peer), policy: {} }); nodes.push(master); client = await owner(master);
    await Promise.all(servers.map(server => waitConnected(master, server.id)));
    for (const servant of servers) {
      await command(client, { command: 'bindWorkspace', logicalWorkspaceId: 'same-project', peerId: servant.id, workspaceId: 'repo', expectedRevision: (await bindings(client)).revision });
      assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'origin.txt' }, { logicalWorkspaceId: 'same-project' })).text, servant.id);
      assert.equal((await dispatch(master, servant, 'readFile', { path: 'origin.txt' })).error.code, 'TOOL_DENIED');
      const invalid = await dispatch(master, servant, 'readFile', { path: 'origin.txt' }, { logicalWorkspaceId: 'same-project', workspaceId: 'repo' });
      assert.equal(invalid.status, 'error'); assert.ok(invalid.error);
    }
    assert.equal((await bindings(client)).bindings.filter(binding => binding.logicalWorkspaceId === 'same-project').length, 2);
    await command(client, { command: 'unbindWorkspace', logicalWorkspaceId: 'same-project', peerId: servers[0].id, expectedRevision: (await bindings(client)).revision });
    assert.equal((await dispatch(master, servers[0], 'readFile', { path: 'origin.txt' }, { logicalWorkspaceId: 'same-project' })).error.code, 'WORKSPACE_BINDING_NOT_FOUND');
    assert.equal(success(await dispatch(master, servers[1], 'readFile', { path: 'origin.txt' }, { logicalWorkspaceId: 'same-project' })).text, servers[1].id);
  } finally { await client?.request('/api/logout', {}).catch(() => {}); await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});

test('workspace acceptance: first logical selection automatically creates and binds; concurrent/repeated/restarted selections reuse it without default fallback', { timeout: 30000 }, async () => {
  const dir = await makeWorkspace('accept-workspace-auto-'), nodes = [];
  let client;
  try {
    await layout(dir);
    const config = servantConfig();
    config.policy.grants.master.workspaceProvisioning.roots.projects.grant.maxConcurrent = 4;
    let servant = await startNode(dir, config); nodes.push(servant);
    const masterConfig = { id: 'master', port: 0, agent: 'deterministic-demo', operator: { enabled: true, port: 0 }, peers: [peer(servant)], policy: {} };
    let master = await startNode(dir, masterConfig); nodes.push(master); await waitConnected(master, 'servant'); client = await owner(master);
    const before = await bindings(client);
    await assert.rejects(command(client, { command: 'setWorkspaceAutoProvision', logicalWorkspaceId: 'alpha', peerId: 'servant', rootId: 'missing', enabled: true, expectedRevision: before.revision }), /WORKSPACE_CREATE_DENIED/);
    assert.equal((await bindings(client)).revision, before.revision);
    await command(client, { command: 'setWorkspaceAutoProvision', logicalWorkspaceId: 'alpha', peerId: 'servant', rootId: 'projects', enabled: true, expectedRevision: before.revision });
    assert.equal((await bindings(client)).bindings.length, 0, 'Saving auto-create intent does not create until selected');
    assert.equal((await catalogue(client, 'servant')).creationRoots.find(root => root.id === 'projects').used, 0);
    success(await dispatch(master, servant, 'mkdir', { path: 'src' }, { logicalWorkspaceId: 'alpha' }));
    const alpha = (await bindings(client)).bindings.find(binding => binding.logicalWorkspaceId === 'alpha');
    assert.ok(alpha.workspaceId.startsWith('ws_'));
    assert.equal((await catalogue(client, 'servant')).creationRoots.find(root => root.id === 'projects').used, 1);
    success(await dispatch(master, servant, 'writeFile', { path: 'src/value.txt', text: 'automatic alpha' }, { logicalWorkspaceId: 'alpha' }));
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'src/value.txt' }, { logicalWorkspaceId: 'alpha' })).text, 'automatic alpha');
    await command(client, { command: 'setWorkspaceAutoProvision', logicalWorkspaceId: 'beta', peerId: 'servant', rootId: 'projects', enabled: true, expectedRevision: (await bindings(client)).revision });
    const concurrent = await Promise.all([
      dispatch(master, servant, 'capabilities', {}, { logicalWorkspaceId: 'beta' }),
      dispatch(master, servant, 'capabilities', {}, { logicalWorkspaceId: 'beta' }),
    ]);
    for (const response of concurrent) assert.equal(success(response).filesystem.mode, 'scoped');
    const betaBindings = (await bindings(client)).bindings.filter(binding => binding.logicalWorkspaceId === 'beta');
    assert.equal(betaBindings.length, 1); assert.notEqual(betaBindings[0].workspaceId, alpha.workspaceId);
    assert.equal((await catalogue(client, 'servant')).creationRoots.find(root => root.id === 'projects').used, 2, 'Concurrent selection must coalesce the creation');
    success(await dispatch(master, servant, 'writeFile', { path: 'value.txt', text: 'automatic beta' }, { logicalWorkspaceId: 'beta' }));
    await command(client, { command: 'setWorkspaceAutoProvision', logicalWorkspaceId: 'overquota', peerId: 'servant', rootId: 'projects', enabled: true, expectedRevision: (await bindings(client)).revision });
    const full = await dispatch(master, servant, 'readFile', { path: 'hello.txt' }, { logicalWorkspaceId: 'overquota' });
    assert.equal(full.error.code, 'WORKSPACE_QUOTA');
    assert.ok(!(await bindings(client)).bindings.some(binding => binding.logicalWorkspaceId === 'overquota'));
    assert.equal((await dispatch(master, servant, 'readFile', { path: 'hello.txt' }, { logicalWorkspaceId: 'not-enabled' })).error.code, 'WORKSPACE_BINDING_NOT_FOUND');
    assert.equal((await master.command({ command: 'status' })).result.unknownOutgoing, 0, 'Definite allocation refusals must not become uncertain effects');
    await command(client, { command: 'setWorkspaceAutoProvision', logicalWorkspaceId: 'alpha', peerId: 'servant', rootId: 'projects', enabled: false, expectedRevision: (await bindings(client)).revision });
    await command(client, { command: 'unbindWorkspace', logicalWorkspaceId: 'alpha', peerId: 'servant', expectedRevision: (await bindings(client)).revision });
    assert.equal((await dispatch(master, servant, 'readFile', { path: 'hello.txt' }, { logicalWorkspaceId: 'alpha' })).error.code, 'WORKSPACE_BINDING_NOT_FOUND');
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'src/value.txt' }, { workspaceId: alpha.workspaceId })).text, 'automatic alpha');
    await command(client, { command: 'setWorkspaceAutoProvision', logicalWorkspaceId: 'alpha', peerId: 'servant', rootId: 'projects', enabled: true, expectedRevision: (await bindings(client)).revision });
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'src/value.txt' }, { logicalWorkspaceId: 'alpha' })).text, 'automatic alpha');
    assert.equal((await bindings(client)).bindings.find(binding => binding.logicalWorkspaceId === 'alpha').workspaceId, alpha.workspaceId);
    const expected = await bindings(client), port = servant.port;
    await client.request('/api/logout', {}); client = null; await master.stop(); await servant.stop();
    servant = await startNode(dir, { ...config, port }); nodes.push(servant);
    master = await startNode(dir, masterConfig); nodes.push(master); await waitConnected(master, 'servant'); client = await owner(master);
    assert.deepEqual(await bindings(client), expected);
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'src/value.txt' }, { logicalWorkspaceId: 'alpha' })).text, 'automatic alpha');
    assert.equal(success(await dispatch(master, servant, 'readFile', { path: 'value.txt' }, { logicalWorkspaceId: 'beta' })).text, 'automatic beta');
    assert.equal((await catalogue(client, 'servant')).creationRoots.find(root => root.id === 'projects').used, 2);
    assert.equal((await dispatch(master, servant, 'readFile', { path: 'hello.txt' }, { logicalWorkspaceId: 'overquota' })).error.code, 'WORKSPACE_QUOTA');
    assert.equal((await fs.readdir(path.join(dir, 'pool-master'))).length, 2, 'Only two physical servant child directories were allocated');
    await assert.rejects(fs.stat(path.join(dir, 'workspace', 'src')), { code: 'ENOENT' });
  } finally { await client?.request('/api/logout', {}).catch(() => {}); await stopAll(nodes); await fs.rm(dir, { recursive: true, force: true }); }
});
