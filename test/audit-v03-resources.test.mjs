import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createHash } from 'node:crypto';
import { compileResourcePolicy, executeResourceTask } from '../src/resources.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
const signal = () => new AbortController().signal;

test('v0.3 independent resource audit: aliases are explicit data grants, links/digests/size/encoding fail closed', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'audit-v03-resources-'));
  const root = path.join(dir, 'workspace');
  await fs.mkdir(root);
  const text = 'Project instruction: use only approved remote tools.\n';
  await fs.writeFile(path.join(root, 'AGENTS.md'), text);
  await fs.writeFile(path.join(dir, 'outside.md'), 'PRIVATE_OUTSIDE_RESOURCE');
  await fs.writeFile(path.join(root, 'unapproved.md'), 'PRIVATE_UNAPPROVED_RESOURCE');
  try {
    const compile = async resources => ({ root, tools: new Set(['resourceList', 'resourceRead']), ...await compileResourcePolicy({ resources }, dir, root) });
    const grant = await compile({ project: { kind: 'instruction', path: 'AGENTS.md', sha256: digest(text) } });
    const read = (resource, args = {}) => executeResourceTask({ tool: 'resourceRead', args: { resource, ...args } }, grant, signal());
    const denied = (operation, code) => assert.rejects(operation, error => error.code === code);
    const listed = await executeResourceTask({ tool: 'resourceList', args: {} }, grant, signal());
    assert.deepEqual(listed.resources.map(item => item.id), ['project']);
    assert.equal(JSON.stringify(listed).includes(root), false);
    assert.equal(JSON.stringify(listed).includes('unapproved'), false);
    assert.equal((await read('project')).text, text);
    await denied(() => read('unapproved'), 'RESOURCE_DENIED');
    await denied(() => read('../outside.md'), 'INVALID_ARGS');
    await denied(() => read('project', { path: '../outside.md' }), 'INVALID_ARGS');
    await denied(() => executeResourceTask({ tool: 'resourceRead', args: { resource: 'project' } }, { ...grant, tools: new Set() }, signal()), 'TOOL_DENIED');
    await t.test('changes to owner-pinned resource content are rejected before disclosure', async () => {
      await fs.writeFile(path.join(root, 'AGENTS.md'), 'changed instruction');
      await denied(() => read('project'), 'RESOURCE_CHANGED');
      await fs.writeFile(path.join(root, 'AGENTS.md'), text);
    });
    await t.test('symlink aliases, hardlinks and linked parents cannot disclose outside text', async () => {
      await fs.symlink(path.join(dir, 'outside.md'), path.join(root, 'link.md'));
      await fs.link(path.join(dir, 'outside.md'), path.join(root, 'hard.md'));
      await fs.symlink(dir, path.join(root, 'alias'));
      for (const name of ['link.md', 'hard.md', 'alias/outside.md']) {
        const linked = await compile({ project: { kind: 'skill', path: name } });
        await denied(() => executeResourceTask({ tool: 'resourceRead', args: { resource: 'project' } }, linked, signal()), 'PATH_DENIED');
      }
    });
    await t.test('oversize and invalid UTF-8 are rejected, unapproved executable resource kinds cannot compile', async () => {
      await fs.writeFile(path.join(root, 'bad.md'), Buffer.from([0xff, 0xfe]));
      const bad = await compile({ project: { kind: 'prompt', path: 'bad.md' } });
      await denied(() => executeResourceTask({ tool: 'resourceRead', args: { resource: 'project' } }, bad, signal()), 'INVALID_ENCODING');
      const small = await compile({ project: { kind: 'instruction', path: 'AGENTS.md', maxBytes: 1 } });
      await denied(() => executeResourceTask({ tool: 'resourceRead', args: { resource: 'project' } }, small, signal()), 'RESOURCE_TOO_LARGE');
      for (const item of [{ kind: 'extension', path: 'AGENTS.md' }, { kind: 'skill', path: '../outside.md' }, { kind: 'skill', path: 'AGENTS.md', execute: true }]) {
        await denied(() => compile({ project: item }), 'INVALID_CONFIG');
      }
    });
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
