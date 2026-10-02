import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

// Static contract checks only. Actual browser rendering, focus, pointer input,
// history behavior and accessibility are explicitly outside this evidence.
const htmlUrl = new URL('../ui/index.html', import.meta.url);
const jsUrl = new URL('../ui/app.js', import.meta.url);

test('control UI acceptance: every navigation destination and explicit form label owns a unique element', async () => {
  const html = await fs.readFile(htmlUrl, 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(ids.length, new Set(ids).size, 'Controls must have unique IDs');
  const destinations = [...html.matchAll(/\bdata-view="([^"]+)"/g)].map(match => match[1]);
  const panels = [...html.matchAll(/\bdata-panel="([^"]+)"/g)].map(match => match[1]);
  assert.equal(destinations.length, new Set(destinations).size);
  assert.deepEqual([...destinations].sort(), [...panels].sort());
  assert.deepEqual(new Set(destinations), new Set(['overview', 'tasks', 'permissions', 'workspaces', 'identity', 'logs']));
  for (const [, target] of html.matchAll(/<label\b[^>]*\bfor="([^"]+)"/g)) assert.ok(ids.includes(target), `Label targets absent control ${target}`);
  assert.match(html, /<nav\b[^>]*aria-label=/);
  assert.match(html, /id="notice"[^>]*role="status"/);
  assert.match(html, /<html\b[^>]*lang="zh-CN"/);
});

test('control UI acceptance: authentication and policy editing remain same-origin with no persistent token or HTML/code sinks', async () => {
  const [html, script] = await Promise.all([fs.readFile(htmlUrl, 'utf8'), fs.readFile(jsUrl, 'utf8')]);
  assert.doesNotMatch(html, /\son(?:click|load|submit|change|error)\s*=/i);
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  assert.ok(scripts.length > 0);
  for (const [, attrs, body] of scripts) {
    assert.match(attrs, /\bsrc="\/(?!\/)[^"]+"/);
    assert.equal(body.trim(), '', 'Scripts must be loaded from the same-origin served assets');
  }
  assert.doesNotMatch(script, /innerHTML|outerHTML|insertAdjacentHTML|document\.write\s*\(|\beval\s*\(|new\s+Function\s*\(|localStorage|sessionStorage/);
  assert.match(script, /credentials:\s*'same-origin'/);
  assert.match(script, /X-Operator-CSRF/);
  assert.match(script, /history\.replaceState\(null, '', location\.pathname\)/);
  assert.match(script, /expectedEpoch/);
  assert.match(script, /DIRECTORY|director/);
});
