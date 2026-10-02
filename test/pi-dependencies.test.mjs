import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { createRequire } from 'node:module';

const requirePi = createRequire(import.meta.resolve('@earendil-works/pi-coding-agent'));

test('published Pi dependency uses the reviewed compatible security resolution', async () => {
  const lock = JSON.parse(await fs.readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));
  const parent = 'node_modules/@earendil-works/pi-coding-agent';
  assert.equal(lock.packages[parent].version, '0.99.2');
  assert.equal(lock.packages[parent].hasShrinkwrap, undefined, 'root lock must remain authoritative for clean npm ci');
  assert.equal(lock.packages[`${parent}/node_modules/brace-expansion`].version, '5.0.12');
  const installed = JSON.parse(await fs.readFile(requirePi.resolve('brace-expansion/package.json'), 'utf8'));
  assert.equal(installed.version, '5.0.12', 'run npm ci --ignore-scripts using the hardened lock before testing');
});
