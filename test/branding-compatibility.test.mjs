import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { IntelligentCell, UnifiedNode } from '../src/node.mjs';
import { loadConfig } from '../src/config.mjs';
import { makeWorkspace, testSecurity } from '../scripts/process-helper.mjs';
import { servicePlan } from '../scripts/service-plan.mjs';

const root = new URL('../', import.meta.url);

test('Intelligent Cells package, lockfile and console use the publication name', async () => {
  const pkg = JSON.parse(await fs.readFile(new URL('package.json', root), 'utf8'));
  const lock = JSON.parse(await fs.readFile(new URL('package-lock.json', root), 'utf8'));
  assert.equal(pkg.name, 'intelligent-cells');
  assert.equal(pkg.private, true);
  assert.equal(lock.name, pkg.name);
  assert.equal(lock.packages[''].name, pkg.name);
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  assert.equal(lock.packages[''].license, pkg.license);
  const html = await fs.readFile(new URL('ui/index.html', root), 'utf8');
  assert.match(html, /<title>Intelligent Cells · 本机控制台<\/title>/);
  assert.match(html, /Intelligent Cells<small>LOCAL OPERATOR<\/small>/);
});

test('legacy UnifiedNode import aliases the same IntelligentCell constructor', () => {
  assert.equal(UnifiedNode, IntelligentCell);
  assert.equal(IntelligentCell.name, 'IntelligentCell');
});

test('rename preserves the legacy default ledger directory and explicit state overrides', async () => {
  const dir = await makeWorkspace('intelligent-cells-compatibility-');
  try {
    const filename = path.join(dir, 'config.json');
    const raw = { id: 'compatibility', port: 0, security: await testSecurity(dir, 'compatibility', []), policy: { grants: {} } };
    await fs.writeFile(filename, JSON.stringify(raw));
    assert.equal((await loadConfig(filename)).stateDir, path.join(dir, '.unified-node-state', raw.id));
    raw.stateDir = '.intelligent-cells-state/explicit';
    await fs.writeFile(filename, JSON.stringify(raw));
    assert.equal((await loadConfig(filename)).stateDir, path.join(dir, raw.stateDir));
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});

test('service plans use the new default while accepting an existing service name', () => {
  const options = { platform: 'linux', project: '/opt/intelligent-cells', config: '/etc/intelligent-cells/node.json', stateDir: '/var/lib/intelligent-cells', node: '/usr/bin/node', user: 'cells' };
  const plan = servicePlan(options);
  assert.equal(plan.name, 'intelligent-cells');
  assert.equal(plan.filename, 'intelligent-cells.service');
  assert.match(plan.contents, /Description=Intelligent Cells execution node/);
  assert.equal(plan.installed, false);
  assert.equal(servicePlan({ ...options, name: 'existing-node' }).filename, 'existing-node.service');
});
