import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { loadPolicy } from '../src/config.mjs';
import { directoryAccess, directoryPolicySummary } from '../src/directory-policy.mjs';
import { runTool, capabilitySchema, validateRequest } from '../src/tools.mjs';

// Synthetic disposable data only. These tests never spawn approved programs,
// contact a browser, bind owner IPC, or access real user files/credentials.
async function fixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'directory-policy-')));
  await fs.mkdir(path.join(root, 'docs')); await fs.mkdir(path.join(root, 'dropbox'));
  await fs.mkdir(path.join(root, 'docs', 'private')); await fs.mkdir(path.join(root, 'docs', 'private', 'public'));
  await fs.writeFile(path.join(root, 'docs', 'guide.txt'), 'public needle');
  await fs.writeFile(path.join(root, 'docs', 'private', 'note.txt'), 'private needle');
  await fs.writeFile(path.join(root, 'docs', 'private', 'public', 'note.txt'), 'reopened needle');
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const tools = ['capabilities', 'readFile', 'readChunk', 'writeFile', 'writeChunk', 'editFile', 'mkdir', 'listDirectory', 'searchFiles', 'resourceList', 'resourceRead'];
  const compile = async overrides => (await loadPolicy({ grants: { peer: { workspace: root, tools, ...overrides } } })).grants.get('peer');
  const run = (policy, tool, args) => runTool({ taskId: 'synthetic', timeoutMs: 1000, tool, args }, policy);
  return { root, tools, compile, run };
}

test('directory rules are complete, bounded, distinct canonical directory prefixes', async t => {
  const { root, compile } = await fixture(t);
  const valid = { path: 'docs', read: true, write: false };
  for (const directories of [null, {}, [null], [{ path: 'docs', read: true }], [{ ...valid, extra: false }], [valid, valid],
    [{ ...valid, path: '.' }], [{ ...valid, path: 'docs/' }], [{ ...valid, path: 'docs//private' }], [{ ...valid, path: '../docs' }],
    [{ ...valid, path: root }], [{ ...valid, path: 'docs/guide.txt' }], [{ ...valid, write: 'false' }], Array.from({ length: 129 }, (_, i) => ({ ...valid, path: `dir${i}` }))]) {
    await assert.rejects(compile({ directories }), { code: 'INVALID_CONFIG' });
  }
  const future = await compile({ directories: [{ path: 'future/child', read: true, write: true }] });
  assert.equal(directoryAccess(future, 'future/child/file.txt', 'read'), true);
  await assert.rejects(compile({ directories: [], allowUnsandboxedProcesses: 'yes' }), { code: 'INVALID_CONFIG' });
  await assert.rejects(loadPolicy({ grants: { peer: { directories: [], tools: ['echo'] } } }), { code: 'INVALID_CONFIG' });
});

test('legacy omission, explicit deny-all, root and longest segment rules have deterministic semantics', async t => {
  const { compile, run } = await fixture(t);
  const legacy = await compile({});
  assert.equal((await run(legacy, 'readFile', { path: 'docs/guide.txt' })).text, 'public needle');
  assert.equal(directoryPolicySummary(legacy).mode, 'workspace');
  const denied = await compile({ directories: [] });
  await assert.rejects(run(denied, 'readFile', { path: 'docs/guide.txt' }), { code: 'DIRECTORY_DENIED' });
  const rules = [{ path: 'docs/private/public', read: true, write: false }, { path: '', read: true, write: true }, { path: 'docs/private', read: false, write: false }, { path: 'docs', read: true, write: false }];
  for (const directories of [rules, [...rules].reverse()]) {
    const policy = await compile({ directories });
    assert.equal(directoryAccess(policy, 'docs/guide.txt', 'read'), true);
    assert.equal(directoryAccess(policy, 'docs/guide.txt', 'write'), false);
    assert.equal(directoryAccess(policy, 'docs/private/note.txt', 'read'), false);
    assert.equal(directoryAccess(policy, 'docs/private/public/note.txt', 'read'), true);
    assert.equal(directoryAccess(policy, 'docs-two/guide.txt', 'write'), true);
    // Directory names are not file-name ACLs: a file's containing directory
    // determines its read/write grant, avoiding future-file prefix confusion.
    assert.equal(directoryAccess(policy, 'docs', 'write'), true);
  }
});

test('directory and tool permissions intersect, write-only excludes content-dependent edit', async t => {
  const { root, compile, run } = await fixture(t);
  const policy = await compile({ directories: [{ path: 'dropbox', read: false, write: true }, { path: 'docs', read: true, write: false }] });
  await run(policy, 'writeFile', { path: 'dropbox/new.txt', text: 'opaque content' });
  await run(policy, 'writeChunk', { path: 'dropbox/binary.bin', base64: 'AQID' });
  await run(policy, 'writeChunk', { path: 'dropbox/binary.bin', base64: 'BA==', offset: 3 });
  await run(policy, 'mkdir', { path: 'dropbox/nested' });
  assert.deepEqual(await fs.readFile(path.join(root, 'dropbox', 'binary.bin')), Buffer.from([1, 2, 3, 4]));
  for (const [tool, args] of [['readFile', { path: 'dropbox/new.txt' }], ['readChunk', { path: 'dropbox/new.txt' }], ['editFile', { path: 'dropbox/new.txt', oldText: 'opaque', newText: 'edited' }], ['listDirectory', { path: 'dropbox' }], ['searchFiles', { path: 'dropbox', query: 'content' }], ['writeFile', { path: 'docs/new.txt', text: 'no' }]]) {
    await assert.rejects(run(policy, tool, args), { code: 'DIRECTORY_DENIED' });
  }
  assert.equal(await fs.readFile(path.join(root, 'dropbox', 'new.txt'), 'utf8'), 'opaque content');
  policy.tools.delete('readFile');
  assert.throws(() => validateRequest({ taskId: 'denied', tool: 'readFile', args: { path: 'docs/guide.txt' }, timeoutMs: 1000 }, 'peer', policy), { code: 'TOOL_DENIED' });
});

test('listing, searching and resource discovery omit denied subtrees but direct deeper grant remains available', async t => {
  const { compile, run } = await fixture(t);
  const policy = await compile({ directories: [{ path: 'docs', read: true, write: false }, { path: 'docs/private', read: false, write: false }, { path: 'docs/private/public', read: true, write: false }],
    resources: { visible: { kind: 'instruction', path: 'docs/guide.txt' }, hidden: { kind: 'instruction', path: 'docs/private/note.txt' } } });
  await assert.rejects(run(policy, 'listDirectory', {}), { code: 'DIRECTORY_DENIED' });
  await assert.rejects(run(policy, 'searchFiles', { query: 'needle' }), { code: 'DIRECTORY_DENIED' });
  assert.deepEqual((await run(policy, 'listDirectory', { path: 'docs' })).entries.map(entry => entry.name), ['guide.txt']);
  assert.deepEqual((await run(policy, 'searchFiles', { path: 'docs', query: 'needle' })).matches.map(match => match.path), ['docs/guide.txt']);
  assert.equal((await run(policy, 'readFile', { path: 'docs/private/public/note.txt' })).text, 'reopened needle');
  assert.deepEqual((await run(policy, 'resourceList', {})).resources.map(resource => resource.id), ['visible']);
  assert.deepEqual(capabilitySchema(policy).resources.map(resource => resource.id), ['visible']);
  await assert.rejects(run(policy, 'resourceRead', { resource: 'hidden' }), { code: 'DIRECTORY_DENIED' });
});

test('unsandboxed exec and MCP scopes require explicit separate owner acknowledgement only with directory rules', async t => {
  const { compile } = await fixture(t);
  for (const tool of ['exec', 'mcpList', 'mcpCall']) {
    await assert.rejects(compile({ tools: [tool], directories: [] }), { code: 'INVALID_CONFIG' });
    await assert.rejects(compile({ tools: [tool], directories: [], allowUnsandboxedProcesses: false }), { code: 'INVALID_CONFIG' });
    const policy = await compile({ tools: [tool], directories: [], allowUnsandboxedProcesses: true });
    assert.equal(capabilitySchema(policy).filesystem.processSandboxed, false);
    assert.equal(capabilitySchema(policy).filesystem.processAccess, 'outside-directory-policy');
    assert.equal(capabilitySchema(policy).filesystem.unsandboxedProcessesAcknowledged, true);
    assert.deepEqual(capabilitySchema(policy).filesystem.processTools, [tool]);
    assert.equal(directoryPolicySummary(await compile({ tools: [tool] })).mode, 'workspace');
  }
});
