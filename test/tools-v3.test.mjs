import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { setTimeout as sleep } from 'node:timers/promises';
import { runTool, validateRequest, capabilitySchema, TOOL_NAMES } from '../src/tools.mjs';
import { JobManager } from '../src/jobs.mjs';
import { NodeError } from '../src/errors.mjs';
const errorCode = code => error => error?.code === code;
async function fixture(t, overrides = {}) {
  const directory = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'intelligent-cells-v03-tools-'))), root = path.join(directory, 'workspace'), stateDir = path.join(directory, 'jobs');
  await fs.mkdir(root); const events = [];
  const policy = { allowedMasters: new Set(['master']), tools: new Set(TOOL_NAMES), root, maxTimeoutMs: 120000, maxWaitMs: 120000,
    maxReadBytes: 1024, maxWriteBytes: 1024, maxTransferBytes: 4096, maxOutputBytes: 65536, maxOutputPageBytes: 16384,
    maxSearchFiles: 100, maxSearchBytes: 4096, maxDirectoryEntries: 100, maxConcurrent: 2, maxJobs: 32, maxJobTimeoutMs: 120000, execCommands: new Map(), ...overrides };
  const manager = new JobManager({ stateDir, onOutput: event => events.push(event) }); await manager.start();
  t.after(async () => { await manager.shutdown(); await fs.rm(directory, { recursive: true, force: true }); });
  let sequence = 0;
  const execute = (tool, args, signal, options = {}) => runTool({ taskId: `t${++sequence}`, tool, args, timeoutMs: 65000 }, policy, signal, { jobManager: manager, masterId: 'master', runId: 'dev', ...options });
  const command = async (name, source, options = {}) => { const filename = path.join(directory, `${name}.mjs`); await fs.writeFile(filename, source); policy.execCommands.set(name, { file: process.execPath, args: [filename], argsAllowed: false, maxArgs: 0, env: {}, ...options }); return filename; };
  return { directory, root, stateDir, events, policy, manager, execute, command };
}
async function until(check, label) { for (let i = 0; i < 300; i++) { if (await check()) return; await sleep(10); } assert.fail(`等待超时: ${label}`); }

test('能力发现只公开已授予工具和别名，时长允许大于30秒且本地上限仍生效', async t => {
  const { policy } = await fixture(t); policy.tools = new Set(['readFile', 'exec']);
  policy.execCommands.set('build', { file: '/private/executable', args: ['/private/script'], argsAllowed: true, maxArgs: 1, allowedArgs: ['--check'], env: { SECRET: 'not-visible' } });
  const capability = capabilitySchema(policy), encoded = JSON.stringify(capability);
  assert.deepEqual(capability.tools.map(tool => tool.name), ['readFile', 'exec']); assert.equal(encoded.includes('/private'), false); assert.equal(encoded.includes('not-visible'), false);
  assert.equal(validateRequest({ taskId: 'long', tool: 'readFile', args: { path: 'x' }, timeoutMs: 65000 }, 'master', policy), 65000);
  assert.equal(validateRequest({ taskId: 'long', tool: 'readFile', args: { path: 'x' }, timeoutMs: 3600000 }, 'master', policy), 120000);
  assert.throws(() => validateRequest({ taskId: 'bad', tool: 'exec', args: { command: 'build', args: ['--unsafe'] }, timeoutMs: 1000 }, 'master', policy), errorCode('INVALID_ARGS'));
});

test('大文件只读取指定字节范围，二进制分块往返、偏移和总量有界', async t => {
  const { root, execute } = await fixture(t);
  const large = await fs.open(path.join(root, 'large.bin'), 'w'); await large.truncate(32 * 1024 * 1024); await large.write(Buffer.from('tail'), 0, 4, 32 * 1024 * 1024 - 4); await large.close();
  await assert.rejects(execute('readFile', { path: 'large.bin' }), errorCode('FILE_TOO_LARGE'));
  const tail = await execute('readChunk', { path: 'large.bin', offset: 32 * 1024 * 1024 - 4, length: 4 });
  assert.equal(Buffer.from(tail.base64, 'base64').toString(), 'tail'); assert.equal(tail.eof, true); assert.equal(tail.bytes, 4);
  assert.equal((await execute('readFile', { path: 'large.bin', offset: 32 * 1024 * 1024 - 4, length: 4 })).text, 'tail');
  const payload = Buffer.from([0, 255, 128, 1, 226, 130, 172]);
  await execute('writeChunk', { path: 'upload.bin', base64: payload.subarray(0, 3).toString('base64') });
  await execute('writeChunk', { path: 'upload.bin', offset: 3, base64: payload.subarray(3).toString('base64') });
  assert.deepEqual(await fs.readFile(path.join(root, 'upload.bin')), payload);
  await assert.rejects(execute('writeChunk', { path: 'upload.bin', offset: 2, base64: 'AA==' }), errorCode('OFFSET_MISMATCH'));
  await assert.rejects(execute('writeChunk', { path: 'upload.bin', base64: 'AA==' }), errorCode('FILE_EXISTS'));
  await assert.rejects(execute('writeChunk', { path: 'bad', base64: 'AB==' }), errorCode('INVALID_ARGS'));
  await assert.rejects(execute('readChunk', { path: 'large.bin', length: 1025 }), errorCode('INVALID_ARGS'));
  assert.deepEqual((await fs.readdir(root)).sort(), ['large.bin', 'upload.bin']);
});

test('目录创建/分页和字面搜索受路径、条目、文件及字节预算约束', async t => {
  const { root, execute, policy } = await fixture(t);
  await execute('mkdir', { path: 'src' });
  await execute('writeFile', { path: 'src/a.txt', text: 'hello\nneedle one\nneedle two' });
  await execute('writeFile', { path: 'src/b.txt', text: 'second' });
  const page = await execute('listDirectory', { path: 'src', limit: 1 }); assert.equal(page.entries[0].name, 'a.txt'); assert.equal(page.eof, false);
  assert.equal((await execute('listDirectory', { path: 'src', offset: page.nextOffset, limit: 1 })).entries[0].name, 'b.txt');
  const found = await execute('searchFiles', { query: 'needle' }); assert.equal(found.matches.length, 2); assert.equal(found.matches[0].line, 2);
  assert.equal((await execute('searchFiles', { query: 'needle', maxResults: 1 })).reason, 'maxResults');
  await fs.writeFile(path.join(root, 'too-large'), 'x'.repeat(2048)); assert.equal((await execute('searchFiles', { query: 'needle' })).skippedFiles, 1);
  policy.maxSearchBytes = 1; assert.equal((await execute('searchFiles', { query: 'needle' })).reason, 'maxSearchBytes');
  policy.maxDirectoryEntries = 1; await assert.rejects(execute('listDirectory', { path: 'src' }), errorCode('DIRECTORY_TOO_LARGE'));
  for (const name of ['../escape', '/etc', 'src/../escape', 'src\\evil', 'NUL']) {
    await assert.rejects(execute('mkdir', { path: name }), errorCode('PATH_DENIED'));
    await assert.rejects(execute('searchFiles', { path: name, query: 'x' }), errorCode('PATH_DENIED'));
  }
});

test('新文件工具不跟随软链接、硬链接及目录别名', async t => {
  const { directory, root, execute } = await fixture(t);
  await fs.writeFile(path.join(directory, 'outside'), 'secret');
  await fs.symlink(path.join(directory, 'outside'), path.join(root, 'link'));
  await fs.link(path.join(directory, 'outside'), path.join(root, 'hard'));
  await fs.symlink(directory, path.join(root, 'dirlink'), 'dir');
  for (const file of ['link', 'hard', 'dirlink/outside']) {
    await assert.rejects(execute('readChunk', { path: file }), errorCode('PATH_DENIED'));
    await assert.rejects(execute('writeChunk', { path: file, base64: 'AA==', overwrite: true }), errorCode('PATH_DENIED'));
  }
  await assert.rejects(execute('listDirectory', { path: 'dirlink' }), errorCode('PATH_DENIED'));
  assert.equal((await execute('searchFiles', { query: 'secret' })).matches.length, 0);
  assert.equal(await fs.readFile(path.join(directory, 'outside'), 'utf8'), 'secret');
});

test('真实构建进程提前流式输出、可配置65秒时限、长输出分页无内存整包读取', async t => {
  const { execute, command, events, manager } = await fixture(t);
  await command('build', `console.log('build-start');setTimeout(()=>{process.stdout.write('A'.repeat(20000));console.error('test-pass');},180);`);
  const timerDurations = [], originalTimer = globalThis.setTimeout;
  t.mock.method(globalThis, 'setTimeout', (callback, duration, ...args) => { timerDurations.push(duration); return originalTimer(callback, duration, ...args); });
  let finished = false; const resultPromise = execute('exec', { command: 'build', args: [], durationMs: 65000 }).then(result => { finished = true; return result; });
  await until(() => events.some(event => event.text.includes('build-start')), '首次流式输出'); assert.equal(finished, false);
  const result = await resultPromise; assert.ok(timerDurations.includes(65000)); assert.equal(result.exitCode, 0); assert.equal(result.outputTruncated, true); assert.ok(events.every(event => event.bytes <= 4096));
  let offset = 0, bytes = [];
  do { const page = await execute('jobOutput', { jobId: result.jobId, offset, limit: 777, stream: 'stdout' }); bytes.push(Buffer.from(page.base64, 'base64')); offset = page.nextOffset; if (page.eof) break; } while (true);
  assert.equal(Buffer.concat(bytes).toString(), 'build-start\n' + 'A'.repeat(20000));
  assert.equal(manager.status('master', result.jobId).state, 'succeeded');
});

test('后台作业可持续stdin、状态查询、跨peer隔离及终止', async t => {
  const { execute, command, events, manager, policy } = await fixture(t);
  await command('interactive', `process.stdout.write('ready');process.stdin.on('data',x=>process.stdout.write(x));process.stdin.on('end',()=>process.exit(0));`, { stdinAllowed: true, maxStdinBytes: 8 });
  const job = await execute('exec', { command: 'interactive', args: [], background: true }); assert.equal(job.background, true);
  await until(() => events.some(event => event.text.includes('ready')), '后台进程就绪');
  assert.equal((await execute('jobStatus', { jobId: job.jobId })).state, 'running');
  await assert.rejects(execute('jobOutput', { jobId: job.jobId }, undefined, { masterId: 'other' }), errorCode('JOB_NOT_FOUND'));
  await execute('jobStdin', { jobId: job.jobId, text: 'hello' });
  await assert.rejects(execute('jobStdin', { jobId: job.jobId, text: 'more' }), errorCode('STDIN_TOO_LARGE'));
  await execute('jobStdin', { jobId: job.jobId, text: '!', eof: true });
  await until(() => manager.status('master', job.jobId).state === 'succeeded', 'stdin EOF退出');
  assert.equal((await execute('jobOutput', { jobId: job.jobId })).text, 'readyhello!');
  policy.execCommands.get('interactive').stdinAllowed = false;
  await assert.rejects(execute('jobStdin', { jobId: job.jobId, text: 'x' }), errorCode('STDIN_DENIED'));
});

test('进程组取消会清理正常继承的子进程，输出上限会终止洪水', { timeout: 10000 }, async t => {
  const { root, execute, command, manager, policy } = await fixture(t);
  const grandchild = await command('tick', `import fs from 'node:fs';setInterval(()=>fs.appendFileSync('ticks','x'),10);`);
  await command('tree', `import {spawn} from 'node:child_process';spawn(process.execPath,[${JSON.stringify(grandchild)}],{stdio:'inherit'});console.log('tree-ready');setInterval(()=>{},1000);`);
  const job = await execute('exec', { command: 'tree', args: [], background: true });
  await until(async () => (await fs.stat(path.join(root, 'ticks')).catch(() => null))?.size > 1, '子进程写入');
  const cancelled = await execute('jobCancel', { jobId: job.jobId }); assert.equal(cancelled.accepted, true); assert.equal(cancelled.state, 'cancelled');
  const size = (await fs.stat(path.join(root, 'ticks'))).size; await sleep(80); assert.equal((await fs.stat(path.join(root, 'ticks'))).size, size);
  assert.equal(manager.jobs.get(job.jobId).child, undefined);
  assert.throws(() => manager.assertCanWrite('master', 'new-after-cancel'), errorCode('OUTCOME_UNKNOWN'));
  await manager.reconcileJob({ masterId: 'master', jobId: job.jobId, resolution: 'completed', note: '已检查 ticks 文件和子进程，确认取消后的效果' });
  policy.maxOutputBytes = 64; await command('flood', `process.stdout.write('x'.repeat(1000000));setInterval(()=>{},1000);`);
  await assert.rejects(execute('exec', { command: 'flood', args: [] }), errorCode('OUTPUT_TOO_LARGE'));
});

test('durable未知作业禁止同peer新runId写入；仅本地主人有证据核对后恢复', async t => {
  const { execute, command, manager, stateDir, policy } = await fixture(t);
  await command('short', `console.log('done')`); await execute('exec', { command: 'short', args: [] });
  const job = [...manager.jobs.values()][0], filename = path.join(stateDir, `${job.jobId}.json`);
  const record = JSON.parse(await fs.readFile(filename)); record.state = 'running'; await fs.writeFile(filename, JSON.stringify(record));
  const recovered = new JobManager({ stateDir }); await recovered.start(); t.after(() => recovered.shutdown());
  assert.equal(recovered.status('master', job.jobId).state, 'unknown');
  assert.throws(() => recovered.assertCanWrite('master', 'totally-new-run'), errorCode('OUTCOME_UNKNOWN'));
  await assert.rejects(runTool({ tool: 'writeFile', args: { path: 'no-replay', text: 'x' } }, policy, undefined, { jobManager: recovered, masterId: 'master', runId: 'new' }), errorCode('OUTCOME_UNKNOWN'));
  await assert.rejects(recovered.reconcileJob({ masterId: 'master', jobId: job.jobId, resolution: 'completed' }), errorCode('INVALID_ARGS'));
  await recovered.reconcileJob({ masterId: 'master', jobId: job.jobId, resolution: 'completed', note: '本地检查已确认输出及文件效果' }); recovered.assertCanWrite('master', 'new');
});

test('终态作业按配额回收而不会32次执行后永久堵塞，活动进程不可挤出', async t => {
  const { execute, command, manager, policy } = await fixture(t, { maxJobs: 2, maxConcurrent: 1 });
  await command('short', `process.stdout.write('ok')`);
  let first;
  for (let i = 0; i < 5; i++) { assert.equal((await execute('exec', { command: 'short', args: [] })).stdout, 'ok'); first ??= [...manager.jobs.keys()][0]; }
  assert.equal(manager.jobs.size, 2); assert.throws(() => manager.status('master', first), errorCode('JOB_NOT_FOUND'));
  await command('long', `setInterval(()=>{},1000)`);
  const results = await Promise.allSettled([execute('exec', { command: 'long', args: [], background: true }), execute('exec', { command: 'long', args: [], background: true })]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1); assert.equal(results.find(result => result.status === 'rejected').reason.code, 'BUSY');
  await execute('jobCancel', { jobId: results.find(result => result.status === 'fulfilled').value.jobId });
});

test('已批准执行入口在运行前再次核验，不允许后来换成链接或丢失的源文件', async t => {
  const { execute, command, policy, directory, manager } = await fixture(t);
  const script = await command('source', `process.stdout.write('trusted')`);
  const executable = await fs.realpath(process.execPath);
  policy.execCommands.get('source').codeFiles = [executable, script];
  assert.equal((await execute('exec', { command: 'source', args: [] })).stdout, 'trusted');
  const count = manager.jobs.size, alternate = path.join(directory, 'alternate.mjs');
  await fs.writeFile(alternate, `process.stdout.write('unapproved replacement')`); await fs.unlink(script); await fs.symlink(alternate, script);
  await assert.rejects(execute('exec', { command: 'source', args: [] }), errorCode('EXEC_CODE_CHANGED'));
  await fs.unlink(script); await fs.link(alternate, script);
  await assert.rejects(execute('exec', { command: 'source', args: [] }), errorCode('EXEC_CODE_CHANGED'));
  await fs.unlink(script);
  await assert.rejects(execute('exec', { command: 'source', args: [] }), errorCode('EXEC_CODE_CHANGED'));
  assert.equal(manager.jobs.size, count, '源核验失败时没有派生新进程');
});

test('后台作业不能跨peer绕过节点全局进程上限，私有状态目录不能是公开目录', async t => {
  const { execute, command, manager, directory } = await fixture(t);
  manager.maxConcurrent = 1;
  await command('long', `setInterval(()=>{},1000)`);
  const first = await execute('exec', { command: 'long', args: [], background: true });
  await assert.rejects(execute('exec', { command: 'long', args: [], background: true }, undefined, { masterId: 'other' }), errorCode('BUSY'));
  await execute('jobCancel', { jobId: first.jobId });
  if (process.platform !== 'win32') {
    const publicState = path.join(directory, 'public-state'); await fs.mkdir(publicState, { mode: 0o755 });
    await assert.rejects(new JobManager({ stateDir: publicState }).start(), errorCode('JOB_STORE_UNSAFE'));
  }
});
