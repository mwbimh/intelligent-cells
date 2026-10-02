import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { DurableStore, acquireStateLock, readChecked, writeChecked } from '../src/durable.mjs';

async function fixture(prefix) { return fs.mkdtemp(path.join(os.tmpdir(), prefix)); }

test('v0.3 independent durable audit: 5000 operations cross 4096 safely and retired IDs stay rejected after reopen', { timeout: 60000 }, async () => {
  const dir = await fixture('audit-v03-retention-');
  try {
    const store = new DurableStore({ directory: path.join(dir, 'journal') }).open();
    for (let i = 0; i < 5000; i++) store.put(`peer:task_${i}`, { state: 'completed', updatedAt: i, value: `result_${i}` });
    assert.ok(store.info().records <= 4096);
    assert.ok(store.info().retiredCount > 0);
    assert.equal(store.get('peer:task_4999').value, 'result_4999');
    assert.equal(store.get('peer:task_0'), undefined);
    assert.equal(store.retired('peer:task_0'), true);
    assert.throws(() => store.put('peer:task_0', { state: 'pending' }), error => error.code === 'TASK_HISTORY_EXPIRED');
    const reopened = new DurableStore({ directory: path.join(dir, 'journal') }).open();
    assert.equal(reopened.retired('peer:task_0'), true);
    assert.equal(reopened.get('peer:task_4999').value, 'result_4999');
    assert.throws(() => reopened.put('peer:task_0', { state: 'pending' }), error => error.code === 'TASK_HISTORY_EXPIRED');
    reopened.put('peer:new_after_restart', { state: 'completed', updatedAt: 5001 });
    assert.ok(reopened.get('peer:new_after_restart'));
    const files = await fs.readdir(path.join(dir, 'journal'));
    assert.ok(files.length <= 4097);
    for (const file of files) assert.equal((await fs.stat(path.join(dir, 'journal', file))).mode & 0o077, 0);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('v0.3 independent durable audit: unknown/inflight records cannot be retired to make room', async () => {
  const dir = await fixture('audit-v03-unknown-retention-');
  try {
    const store = new DurableStore({ directory: path.join(dir, 'journal'), maxRecords: 4 }).open();
    for (const [i,state] of ['unknown','running','dispatching','pending'].entries()) store.put(`peer:${i}`, { state });
    assert.throws(() => store.put('peer:next', { state: 'pending' }), error => error.code === 'TASK_STORE_FULL');
    assert.equal(store.info().retiredCount, 0);
    const reopened = new DurableStore({ directory: path.join(dir, 'journal'), maxRecords: 4 }).open();
    assert.deepEqual([...reopened.values()].map(record => record.state).sort(), ['dispatching','pending','running','unknown']);
    reopened.put('peer:0', { state: 'reconciled', updatedAt: 1 });
    reopened.put('peer:next', { state: 'pending' });
    assert.equal(reopened.retired('peer:0'), true);
    for (const i of [1,2,3]) assert.equal(reopened.retired(`peer:${i}`), false);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('v0.3 independent durable audit: live owner lock, journal corruption, missing tombstones and unsafe paths fail closed', async t => {
  const dir = await fixture('audit-v03-integrity-');
  try {
    await t.test('same-process second owner cannot open active state', async () => {
      const locked = path.join(dir, 'locked');
      const release = acquireStateLock(locked);
      try { assert.throws(() => acquireStateLock(locked), error => error.code === 'STATE_LOCKED'); }
      finally { release(); }
      acquireStateLock(locked)();
    });
    await t.test('checksummed record tamper is refused rather than silently discarded', async () => {
      const file = path.join(dir, 'checked.json'); writeChecked(file, { value: 'original' });
      assert.deepEqual(readChecked(file), { value: 'original' });
      await fs.writeFile(file, (await fs.readFile(file, 'utf8')).replace('original','modified'));
      assert.throws(() => readChecked(file), error => error.code === 'JOURNAL_CORRUPT');
    });
    await t.test('missing metadata never silently forgets retained operation IDs', async () => {
      const journal = path.join(dir, 'missing-meta');
      const store = new DurableStore({ directory: journal }).open(); store.put('peer:id', { state: 'completed' });
      await fs.unlink(path.join(journal, 'meta.json'));
      assert.throws(() => new DurableStore({ directory: journal }).open(), error => error.code === 'JOURNAL_CORRUPT');
    });
    await t.test('group-readable directory and symlink state path cannot be opened', async () => {
      const unsafe = path.join(dir, 'unsafe'); await fs.mkdir(unsafe, { mode: 0o755 });
      assert.throws(() => new DurableStore({ directory: unsafe }).open(), error => error.code === 'UNSAFE_STATE_DIRECTORY');
      const real = path.join(dir, 'real'); await fs.mkdir(real, { mode: 0o700 }); await fs.symlink(real, path.join(dir, 'alias'));
      assert.throws(() => new DurableStore({ directory: path.join(dir, 'alias') }).open(), error => error.code === 'UNSAFE_STATE_DIRECTORY');
    });
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});
