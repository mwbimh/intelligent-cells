import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { runTool, validateRequest } from '../src/tools.mjs';
import { NodeError } from '../src/errors.mjs';

const task = (tool, args, timeoutMs = 1000) => ({ taskId: 'tool_test', tool, args, timeoutMs });
const errorCode = code => error => error?.code === code;

async function fixture(t, overrides = {}) {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'intelligent-cells-tools-v2-')));
  const root = path.join(directory, 'workspace');
  await fs.mkdir(root);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const policy = {
    allowedMasters: new Set(['master']), tools: new Set(['echo', 'wait', 'readFile', 'writeFile', 'editFile', 'exec']),
    root, maxTimeoutMs: 500, maxWaitMs: 500, maxReadBytes: 1024, maxWriteBytes: 1024, maxOutputBytes: 1024,
    maxConcurrent: 2, maxTasksPerMinute: 60, execCommands: new Map(), ...overrides
  };
  const command = async (name, source, options = {}) => {
    const filename = path.join(directory, `${name}.mjs`);
    await fs.writeFile(filename, source);
    policy.execCommands.set(name, { file: process.execPath, args: [filename], argsAllowed: false, maxArgs: 0, env: {}, ...options });
  };
  const execute = (tool, args, signal) => {
    const request = task(tool, args);
    validateRequest(request, 'master', policy);
    return runTool(request, policy, signal);
  };
  return { directory, root, policy, command, execute };
}

test('tool validation fails closed and clamps the servant deadline', async t => {
  const { policy } = await fixture(t);
  assert.equal(validateRequest(task('echo', { text: 'ok' }), 'master', policy), 500);
  assert.equal(validateRequest(task('echo', { text: 'ok' }, 20), 'master', policy), 20);
  assert.throws(() => validateRequest(task('echo', { text: 'ok' }), 'stranger', policy), errorCode('MASTER_DENIED'));
  assert.throws(() => validateRequest(task('shell', {}), 'master', policy), errorCode('TOOL_DENIED'));
  assert.throws(() => validateRequest(task('echo', { text: 'ok' }, 86400001), 'master', policy), errorCode('INVALID_TASK'));
  assert.throws(() => validateRequest(task('echo', { text: 'ok' }, 9), 'master', policy), errorCode('INVALID_TASK'));
  assert.throws(() => validateRequest({ ...task('echo', { text: 'ok' }), taskId: '../bad' }, 'master', policy), errorCode('INVALID_TASK'));
  const empty = { ...policy, tools: new Set() };
  assert.throws(() => validateRequest({ ...task('writeFile', { path: 'x', text: 'x' }), policy }, 'master', empty), errorCode('TOOL_DENIED'));
  await assert.rejects(runTool(task('echo', { text: 'ok' }), empty), errorCode('TOOL_DENIED'));
  for (const [tool, args] of [
    ['echo', { text: 'ok' }], ['wait', { ms: 0 }], ['readFile', { path: 'x' }],
    ['writeFile', { path: 'x', text: 'x' }], ['editFile', { path: 'x', oldText: 'a', newText: 'b' }],
    ['exec', { command: 'missing', args: [] }]
  ]) {
    assert.throws(() => validateRequest(task(tool, { ...args, unexpected: true }), 'master', policy), errorCode('INVALID_ARGS'));
  }
});

test('echo and wait remain bounded and cancellation-aware', async t => {
  const { execute, policy } = await fixture(t);
  assert.deepEqual(await execute('echo', { text: '你好' }), { text: '你好' });
  assert.deepEqual(await execute('wait', { ms: 0 }), { waitedMs: 0 });
  assert.throws(() => validateRequest(task('echo', { text: 'é'.repeat(2049) }), 'master', policy), errorCode('INVALID_ARGS'));
  assert.throws(() => validateRequest(task('wait', { ms: 501 }), 'master', policy), errorCode('INVALID_ARGS'));
  assert.throws(() => validateRequest(task('wait', { ms: -1 }), 'master', policy), errorCode('INVALID_ARGS'));
  const controller = new AbortController();
  const pending = execute('wait', { ms: 500 }, controller.signal);
  controller.abort(new NodeError('TASK_CANCELLED', 'test cancellation'));
  await assert.rejects(pending, error => error.name === 'AbortError');
  await assert.rejects(execute('echo', { text: 'x' }, controller.signal), errorCode('TASK_CANCELLED'));
});

test('all filesystem tools reject traversal, absolute paths and portable path aliases', async t => {
  const { policy } = await fixture(t);
  const paths = ['', '.', '..', '../outside', '/etc/passwd', 'a/../b', 'a//b', './a', 'a/',
    'C:\\Windows\\x', 'C:/Windows/x', '\\\\host\\share', 'nested\\file', 'file:stream',
    'a\0b', 'a\nb', 'NUL', 'con.txt', 'COM1.log', 'LPT9', 'trailing.', 'trailing ', 'a/'.repeat(251)];
  for (const name of paths) {
    for (const [tool, args] of [
      ['readFile', { path: name }], ['writeFile', { path: name, text: 'x' }],
      ['editFile', { path: name, oldText: 'x', newText: 'y' }]
    ]) assert.throws(() => validateRequest(task(tool, args), 'master', policy), errorCode('PATH_DENIED'), `${tool}: ${JSON.stringify(name)}`);
  }
  for (const [tool, args] of [
    ['readFile', { path: 'x' }], ['writeFile', { path: 'x', text: 'x' }],
    ['editFile', { path: 'x', oldText: 'x', newText: 'y' }], ['exec', { command: 'x', args: [] }]
  ]) assert.throws(() => validateRequest(task(tool, args), 'master', { ...policy, root: null }), errorCode('PATH_DENIED'));
});

test('readFile returns exact bounded UTF-8 bytes and only regular files', async t => {
  const { root, execute, policy } = await fixture(t);
  await fs.mkdir(path.join(root, 'nested'));
  await fs.writeFile(path.join(root, 'nested', 'text.txt'), 'héllo\n');
  assert.deepEqual(await execute('readFile', { path: 'nested/text.txt' }), { text: 'héllo\n', bytes: 7 });
  await fs.writeFile(path.join(root, 'empty'), '');
  assert.deepEqual(await execute('readFile', { path: 'empty' }), { text: '', bytes: 0 });
  await fs.writeFile(path.join(root, 'limit'), 'é'.repeat(512));
  assert.equal((await execute('readFile', { path: 'limit' })).bytes, policy.maxReadBytes);
  await fs.appendFile(path.join(root, 'limit'), 'x');
  await assert.rejects(execute('readFile', { path: 'limit' }), errorCode('FILE_TOO_LARGE'));
  await assert.rejects(execute('readFile', { path: 'nested' }), errorCode('PATH_DENIED'));
  await assert.rejects(execute('readFile', { path: 'missing' }), errorCode('ENOENT'));
});

test('symlinks, hardlinks, parent aliases and changed workspace roots are denied', async t => {
  const { directory, root, execute, policy } = await fixture(t);
  const outside = path.join(directory, 'outside.txt');
  await fs.writeFile(outside, 'untouched');
  await fs.mkdir(path.join(root, 'nested'));
  await fs.writeFile(path.join(root, 'nested', 'file'), 'inside');
  try {
    await fs.symlink(outside, path.join(root, 'symlink'));
    await fs.symlink(path.join(root, 'nested'), path.join(root, 'parent-link'), 'dir');
    await fs.link(outside, path.join(root, 'hardlink'));
  } catch (error) {
    if (['EPERM', 'EACCES', 'ENOTSUP'].includes(error.code)) { t.skip('Filesystem links unavailable on this account'); return; }
    throw error;
  }
  for (const name of ['symlink', 'hardlink', 'parent-link/file']) {
    await assert.rejects(execute('readFile', { path: name }), errorCode('PATH_DENIED'));
    await assert.rejects(execute('writeFile', { path: name, text: 'bad', overwrite: true }), errorCode('PATH_DENIED'));
    await assert.rejects(execute('editFile', { path: name, oldText: 'untouched', newText: 'bad' }), errorCode('PATH_DENIED'));
  }
  await assert.rejects(execute('writeFile', { path: 'parent-link/new', text: 'bad' }), errorCode('PATH_DENIED'));
  assert.equal(await fs.readFile(outside, 'utf8'), 'untouched');
  const rootAlias = path.join(directory, 'root-alias');
  await fs.symlink(root, rootAlias, 'dir');
  await assert.rejects(runTool(task('readFile', { path: 'nested/file' }), { ...policy, root: rootAlias }), errorCode('PATH_DENIED'));
});

test('writeFile is atomic, requires overwrite approval and has byte and schema limits', async t => {
  const { root, execute, policy } = await fixture(t);
  await fs.mkdir(path.join(root, 'nested'));
  assert.deepEqual(await execute('writeFile', { path: 'nested/new.txt', text: '你好' }), { path: 'nested/new.txt', bytes: 6 });
  assert.equal(await fs.readFile(path.join(root, 'nested/new.txt'), 'utf8'), '你好');
  await assert.rejects(execute('writeFile', { path: 'nested/new.txt', text: 'changed' }), errorCode('FILE_EXISTS'));
  assert.equal(await fs.readFile(path.join(root, 'nested/new.txt'), 'utf8'), '你好');
  assert.deepEqual(await execute('writeFile', { path: 'nested/new.txt', text: '', overwrite: true }), { path: 'nested/new.txt', bytes: 0 });
  assert.equal(await fs.readFile(path.join(root, 'nested/new.txt'), 'utf8'), '');
  if (process.platform !== 'win32') assert.equal((await fs.stat(path.join(root, 'nested/new.txt'))).mode & 0o777, 0o600);
  assert.deepEqual(await fs.readdir(path.join(root, 'nested')), ['new.txt']);
  assert.throws(() => validateRequest(task('writeFile', { path: 'bad', text: 'é'.repeat(513) }), 'master', policy), errorCode('FILE_TOO_LARGE'));
  for (const args of [{ path: 'x', text: 3 }, { path: 'x', text: 'x', overwrite: 'yes' }]) {
    assert.throws(() => validateRequest(task('writeFile', args), 'master', policy), errorCode('INVALID_ARGS'));
  }
  await assert.rejects(execute('writeFile', { path: 'missing-parent/x', text: 'x' }), errorCode('ENOENT'));
  await assert.rejects(execute('writeFile', { path: 'nested', text: 'x', overwrite: true }), errorCode('PATH_DENIED'));
});

test('editFile replaces exactly one literal occurrence, including overlapping-match rejection', async t => {
  const { root, execute, policy } = await fixture(t);
  await fs.writeFile(path.join(root, 'document'), 'alpha café omega');
  assert.deepEqual(await execute('editFile', { path: 'document', oldText: 'café', newText: '茶' }), { path: 'document', bytes: 15 });
  assert.equal(await fs.readFile(path.join(root, 'document'), 'utf8'), 'alpha 茶 omega');
  await assert.rejects(execute('editFile', { path: 'document', oldText: 'absent', newText: 'x' }), errorCode('EDIT_MATCH_COUNT'));
  await fs.writeFile(path.join(root, 'document'), 'aaa');
  await assert.rejects(execute('editFile', { path: 'document', oldText: 'aa', newText: 'x' }), errorCode('EDIT_MATCH_COUNT'));
  await assert.rejects(execute('editFile', { path: 'document', oldText: 'a', newText: 'x' }), errorCode('EDIT_MATCH_COUNT'));
  assert.equal(await fs.readFile(path.join(root, 'document'), 'utf8'), 'aaa');
  assert.throws(() => validateRequest(task('editFile', { path: 'document', oldText: '', newText: 'x' }), 'master', policy), errorCode('INVALID_ARGS'));
  await fs.writeFile(path.join(root, 'document'), 'X' + 'y'.repeat(1023));
  await assert.rejects(execute('editFile', { path: 'document', oldText: 'X', newText: 'longer' }), errorCode('FILE_TOO_LARGE'));
  assert.equal((await fs.readFile(path.join(root, 'document'))).length, 1024);
  await fs.appendFile(path.join(root, 'document'), 'z');
  await assert.rejects(execute('editFile', { path: 'document', oldText: 'X', newText: '' }), errorCode('FILE_TOO_LARGE'));
});

test('same-process concurrent creates never overwrite each other', async t => {
  const { root, execute } = await fixture(t);
  const results = await Promise.allSettled([
    execute('writeFile', { path: 'contended', text: 'one' }),
    execute('writeFile', { path: 'contended', text: 'two' })
  ]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.code, 'FILE_EXISTS');
  assert.equal(await fs.readFile(path.join(root, 'contended'), 'utf8'), 'one');
  assert.deepEqual(await fs.readdir(root), ['contended']);
});

test('editFile preserves UTF-8 BOM and refuses lossy edits of malformed UTF-8', async t => {
  const { root, execute } = await fixture(t);
  const filename = path.join(root, 'text');
  await fs.writeFile(filename, '\ufeffalpha beta');
  await execute('editFile', { path: 'text', oldText: 'beta', newText: '茶' });
  assert.deepEqual(await fs.readFile(filename), Buffer.from('\ufeffalpha 茶'));
  const malformed = Buffer.from([0x61, 0x62, 0x63, 0xff]);
  await fs.writeFile(filename, malformed);
  await assert.rejects(execute('editFile', { path: 'text', oldText: 'abc', newText: 'x' }), errorCode('INVALID_ENCODING'));
  assert.deepEqual(await fs.readFile(filename), malformed);
});

test('cancelled queued mutations cannot bypass serialization or alter the target', async t => {
  const { root, execute } = await fixture(t);
  const controller = new AbortController();
  const first = execute('writeFile', { path: 'queued', text: 'first' });
  const cancelled = execute('writeFile', { path: 'queued', text: 'cancelled', overwrite: true }, controller.signal);
  const last = execute('editFile', { path: 'queued', oldText: 'first', newText: 'last' });
  controller.abort(new NodeError('TASK_CANCELLED', 'cancel queued mutation'));
  await assert.rejects(cancelled, errorCode('TASK_CANCELLED'));
  await first;
  await last;
  assert.equal(await fs.readFile(path.join(root, 'queued'), 'utf8'), 'last');
  assert.deepEqual(await fs.readdir(root), ['queued']);
});

test('cancellation before mutation commit preserves the target and removes staging files', async t => {
  const { root, execute } = await fixture(t);
  await fs.writeFile(path.join(root, 'document'), 'old');
  const controller = new AbortController();
  const originalOpen = fs.open;
  t.mock.method(fs, 'open', async (...args) => {
    const handle = await originalOpen(...args);
    if (path.basename(args[0]).startsWith('.intelligent-cells-')) {
      const originalSync = handle.sync.bind(handle);
      handle.sync = async () => { await originalSync(); controller.abort(new NodeError('TASK_CANCELLED', 'test cancellation before rename')); };
    }
    return handle;
  });
  await assert.rejects(execute('writeFile', { path: 'document', text: 'new', overwrite: true }, controller.signal), errorCode('TASK_CANCELLED'));
  assert.equal(await fs.readFile(path.join(root, 'document'), 'utf8'), 'old');
  assert.deepEqual(await fs.readdir(root), ['document']);
});

test('already committed file effects are not rolled back by late cancellation', async t => {
  const { root, execute } = await fixture(t);
  const controller = new AbortController();
  const originalRename = fs.rename;
  t.mock.method(fs, 'rename', async (...args) => {
    await originalRename(...args);
    controller.abort(new NodeError('TASK_CANCELLED', 'test late cancellation'));
  });
  assert.deepEqual(await execute('writeFile', { path: 'committed', text: 'committed' }, controller.signal), { path: 'committed', bytes: 9 });
  assert.equal(await fs.readFile(path.join(root, 'committed'), 'utf8'), 'committed');
});

test('exec accepts only configured aliases and bounded literal arguments', async t => {
  const { policy, command, execute, root } = await fixture(t);
  await command('inspect', `process.stdout.write(JSON.stringify({args:process.argv.slice(2),cwd:process.cwd(),env:process.env}));`, {
    argsAllowed: true, maxArgs: 8, env: { APPROVED_VALUE: 'safe' }
  });
  policy.execCommands.get('inspect').args.push('fixed-prefix');
  const sentinel = 'INTELLIGENT_CELLS_TEST_SECRET';
  const previous = process.env[sentinel];
  process.env[sentinel] = 'must-not-be-inherited';
  t.after(() => { if (previous === undefined) delete process.env[sentinel]; else process.env[sentinel] = previous; });
  const args = ['; touch NOT_A_COMMAND', '$(echo nope)', 'é'];
  const result = await execute('exec', { command: 'inspect', args });
  const output = JSON.parse(result.stdout);
  assert.deepEqual(output.args, ['fixed-prefix', ...args]);
  assert.equal(output.cwd, root);
  assert.equal(output.env.APPROVED_VALUE, 'safe');
  assert.equal(output.env[sentinel], undefined);
  assert.equal(output.env.NODE_OPTIONS, undefined);
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.equal(result.stderr, '');
  assert.deepEqual(await fs.readdir(root), []);
  for (const value of ['node', 'bash', 'sh']) {
    assert.throws(() => validateRequest(task('exec', { command: value, args: [] }), 'master', policy), errorCode('COMMAND_DENIED'));
  }
  for (const args of [['x'.repeat(4097)], ['é'.repeat(2049)], ['x\0y'], [3], Array(9).fill('x'), Array(5).fill('x'.repeat(4096))]) {
    assert.throws(() => validateRequest(task('exec', { command: 'inspect', args }), 'master', policy), errorCode('INVALID_ARGS'));
  }
  for (const args of [{ command: '/bin/sh', args: [] }, { command: 'inspect' }, { command: 'inspect', args: [], shell: true }, { file: process.execPath, args: [] }]) {
    assert.throws(() => validateRequest(task('exec', args), 'master', policy), errorCode('INVALID_ARGS'));
  }
  await command('fixed', 'process.stdout.write("fixed");');
  assert.throws(() => validateRequest(task('exec', { command: 'fixed', args: ['injected'] }), 'master', policy), errorCode('INVALID_ARGS'));
});

test('exec returns nonzero exit status and catches spawn failure', async t => {
  const { policy, command, execute, directory } = await fixture(t);
  await command('nonzero', 'process.stdout.write("out"); process.stderr.write("err"); process.exitCode = 7;');
  assert.deepEqual(await execute('exec', { command: 'nonzero', args: [] }), { stdout: 'out', stderr: 'err', exitCode: 7, signal: null });
  policy.execCommands.set('missing', { file: path.join(directory, 'nonexistent-node'), args: [], argsAllowed: false, maxArgs: 0, env: {} });
  await assert.rejects(execute('exec', { command: 'missing', args: [] }), errorCode('EXEC_FAILED'));
});

test('exec output cap includes stdout and stderr and kills runaway direct children', { timeout: 5000 }, async t => {
  const { command, execute } = await fixture(t, { maxOutputBytes: 32 });
  await command('exact', 'process.stdout.write("é".repeat(8)); process.stderr.write("x".repeat(16));');
  const exact = await execute('exec', { command: 'exact', args: [] });
  assert.equal(Buffer.byteLength(exact.stdout) + Buffer.byteLength(exact.stderr), 32);
  await command('flood', 'process.stdout.write("x".repeat(20)); process.stderr.write("y".repeat(20)); setInterval(() => {}, 1000);');
  await assert.rejects(execute('exec', { command: 'flood', args: [] }), errorCode('OUTPUT_TOO_LARGE'));
});

test('exec abort/deadline waits for direct child termination without spawning a shell', { timeout: 10000 }, async t => {
  const { command, execute, root } = await fixture(t);
  await command('long', 'import fs from "node:fs"; fs.writeFileSync("child.pid", String(process.pid)); setInterval(() => {}, 1000);');
  for (const code of ['TASK_CANCELLED', 'TASK_TIMEOUT']) {
    await fs.rm(path.join(root, 'child.pid'), { force: true });
    const controller = new AbortController();
    const running = execute('exec', { command: 'long', args: [] }, controller.signal);
    // Attach a rejection handler immediately; assert below checks its exact cause.
    running.catch(() => {});
    t.after(() => controller.abort(new NodeError('TASK_CANCELLED', 'test cleanup')));
    let pid;
    for (let attempt = 0; attempt < 300; attempt++) {
      try { pid = Number(await fs.readFile(path.join(root, 'child.pid'), 'utf8')); if (pid) break; }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      await sleep(10);
    }
    assert.ok(pid > 0, 'direct child reported its PID');
    const reason = new NodeError(code, 'test stop');
    controller.abort(reason);
    await assert.rejects(running, error => error === reason);
    assert.throws(() => process.kill(pid, 0), errorCode('ESRCH'));
  }
});
