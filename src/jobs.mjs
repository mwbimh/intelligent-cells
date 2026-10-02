import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { fail, NodeError, errorData } from './errors.mjs';

const TERMINAL = new Set(['succeeded', 'failed', 'cancelled', 'timed_out', 'unknown', 'reconciled']);
const VALID_STATE = new Set(['starting', 'running', ...TERMINAL]);
const ID = /^[a-zA-Z0-9_-]{1,100}$/u;
const STREAMS = ['combined', 'stdout', 'stderr'];
const MAX_JOBS = 256, MAX_OUTPUT = 16777216, PREVIEW_BYTES = 8192;
const noSignal = () => new AbortController().signal;
const publicJob = job => ({ jobId: job.jobId, masterId: job.masterId, runId: job.runId, command: job.command,
  ...(job.workspaceId !== undefined ? {workspaceId:job.workspaceId} : {}),
  ...(job.taskId ? { taskId: job.taskId } : {}), ...(job.policyEpoch !== undefined ? { policyEpoch: job.policyEpoch } : {}),
  state: job.state, outcomeUnknown: job.outcomeUnknown === true, startedAt: job.startedAt, finishedAt: job.finishedAt ?? null, pid: job.pid ?? null,
  exitCode: job.exitCode ?? null, signal: job.exitSignal ?? null, outputBytes: job.outputBytes,
  stdoutBytes: job.stdoutBytes, stderrBytes: job.stderrBytes, stdinBytes: job.stdinBytes ?? 0,
  ...(job.error ? { error: job.error } : {}), ...(job.resolution ? { resolution: job.resolution, reconciliationNote: job.reconciliationNote } : {}) });
function safeStat(stat) { if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (process.getuid && stat.uid !== process.getuid()) || (process.platform !== 'win32' && (stat.mode & 0o077))) fail('JOB_STORE_UNSAFE', 'Job store contains a linked or nonregular file'); }

// This manages cooperative trusted programs, not a hostile-process sandbox.
// POSIX descendants that stay in the original group are killed together. A
// process can deliberately escape via setsid(); deploy an OS sandbox for that.
export function terminateProcessTree(child) {
  if (!child?.pid) return Promise.resolve();
  if (process.platform !== 'win32') {
    try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') { try { child.kill('SIGKILL'); } catch {} } }
    return Promise.resolve();
  }
  // Absolute OS path; never resolve taskkill through a remotely set PATH.
  const systemRoot = process.env.SystemRoot || 'C:\\Windows';
  return new Promise(resolve => {
    const killer = spawn(path.win32.join(systemRoot, 'System32', 'taskkill.exe'), ['/PID', String(child.pid), '/T', '/F'],
      { shell: false, windowsHide: true, stdio: 'ignore', env: { SystemRoot: systemRoot } });
    const timer = setTimeout(() => { killer.kill(); child.kill(); resolve(); }, 5000);
    killer.once('error', () => { clearTimeout(timer); child.kill(); resolve(); });
    killer.once('close', () => { clearTimeout(timer); child.kill(); resolve(); });
  });
}

export class JobManager {
  constructor({ stateDir = null, onOutput, onState, maxConcurrent = 32 } = {}) {
    if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 256) fail('INVALID_POLICY', 'Invalid global live process limit');
    this.maxConcurrent = maxConcurrent; this.stateDir = stateDir; this.onOutput = onOutput; this.onState = onState;
    this.jobs = new Map(); this.started = false; this.stopping = false; this.admission = Promise.resolve();
  }
  filename(jobId, suffix = 'json') { return path.join(this.stateDir, `${jobId}.${suffix}`); }
  async start() {
    if (this.started) return;
    this.initializing ??= this.initialize();
    return this.initializing;
  }
  async initialize() {
    if (this.stateDir) {
      await fs.mkdir(this.stateDir, { recursive: true, mode: 0o700 });
      const root = await fs.lstat(this.stateDir);
      if (!root.isDirectory() || root.isSymbolicLink() || await fs.realpath(this.stateDir) !== this.stateDir || (process.getuid && root.uid !== process.getuid()) || (process.platform !== 'win32' && (root.mode & 0o077))) fail('JOB_STORE_UNSAFE', 'Job state directory must be a canonical private directory');
      const entries = [];
      for await (const entry of await fs.opendir(this.stateDir)) {
        if (entries.length >= MAX_JOBS * 4 + 16) fail('JOB_STORE_FULL', 'Job store contains too many entries');
        entries.push(entry.name);
      }
      for (const name of entries.filter(name => name.endsWith('.json'))) {
        const jobId = name.slice(0, -5);
        if (!ID.test(jobId)) fail('JOB_STORE_CORRUPT', 'Invalid durable job filename');
        const filename = this.filename(jobId), stat = await fs.lstat(filename); safeStat(stat);
        if (stat.size > 16384) fail('JOB_STORE_CORRUPT', 'Oversized durable job metadata');
        const job = JSON.parse(await fs.readFile(filename, 'utf8'));
        if ((job.workspaceId !== undefined && (typeof job.workspaceId !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(job.workspaceId))) || job.version !== 1 || job.jobId !== jobId || !ID.test(job.masterId) || !ID.test(job.runId) || !VALID_STATE.has(job.state) || !Number.isSafeInteger(job.maxOutputBytes) || job.maxOutputBytes < 1 || job.maxOutputBytes > MAX_OUTPUT) fail('JOB_STORE_CORRUPT', 'Invalid durable job record');
        for (const stream of STREAMS) {
          const outputStat = await fs.lstat(this.filename(jobId, stream)); safeStat(outputStat);
          if (outputStat.size > job.maxOutputBytes) fail('JOB_STORE_CORRUPT', 'Durable job output exceeds local cap');
          job[stream === 'combined' ? 'outputBytes' : `${stream}Bytes`] = outputStat.size;
        }
        if (job.stdoutBytes + job.stderrBytes !== job.outputBytes && ['succeeded', 'failed', 'cancelled', 'timed_out'].includes(job.state)) fail('JOB_STORE_CORRUPT', 'Durable output is inconsistent');
        if (!TERMINAL.has(job.state)) {
          job.state = 'unknown'; job.outcomeUnknown = true; job.finishedAt = new Date().toISOString();
          job.error = { code: 'OUTCOME_UNKNOWN', message: 'Node restarted before this process completed; inspect effects and reconcile locally. No automatic replay.' };
          await this.save(job);
        }
        this.jobs.set(jobId, job);
        if (job.state === 'unknown' || job.outcomeUnknown) await this.emitState(job);
      }
      for (const name of entries) {
        const match = /^([a-zA-Z0-9_-]{1,100})\.(combined|stdout|stderr)$/.exec(name);
        if (match && !this.jobs.has(match[1])) { const filename = path.join(this.stateDir, name); safeStat(await fs.lstat(filename)); await fs.unlink(filename); }
      }
      if (this.jobs.size > MAX_JOBS) fail('JOB_STORE_FULL', 'Too many durable jobs');
    }
    this.started = true;
  }
  async save(job) {
    if (!this.stateDir) return;
    try { safeStat(await fs.lstat(this.filename(job.jobId))); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const data = { version: 1, ...publicJob(job), maxOutputBytes: job.maxOutputBytes, stdinAllowed: job.stdinAllowed, maxStdinBytes: job.maxStdinBytes,
      ...(job.exitSignal !== undefined ? { exitSignal: job.exitSignal } : {}) };
    const temporary = this.filename(job.jobId, `${randomUUID()}.tmp`);
    let handle;
    try {
      handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
      await handle.writeFile(JSON.stringify(data)); await handle.sync(); await handle.close(); handle = null;
      await fs.rename(temporary, this.filename(job.jobId));
      if (process.platform !== 'win32') { const directory = await fs.open(this.stateDir, constants.O_RDONLY); try { await directory.sync(); } finally { await directory.close(); } }
    } finally { if (handle) await handle.close(); await fs.rm(temporary, { force: true }); }
  }
  async emitState(job, callback) {
    const event = publicJob(job);
    if (this.onState) await this.onState(event);
    if (callback && callback !== this.onState) await callback(event);
  }
  get(masterId, jobId) {
    const job = this.jobs.get(jobId);
    if (!job || job.masterId !== masterId) fail('JOB_NOT_FOUND', 'No accessible job with this identifier');
    return job;
  }
  assertCanWrite(masterId, _runId = 'default') {
    const job = [...this.jobs.values()].find(job => job.masterId === masterId && (job.state === 'unknown' || job.outcomeUnknown));
    if (job) {
      const error = new NodeError('OUTCOME_UNKNOWN', 'A prior job for this peer requires local reconciliation before further side effects');
      error.uncertainty = { ...(job.taskId ? { taskId: job.taskId } : {}), jobId: job.jobId }; throw error;
    }
  }
  assertPolicy(masterId, jobId, policyEpoch) {
    if (this.get(masterId, jobId).policyEpoch !== policyEpoch) fail('TASK_POLICY_CHANGED', 'Job belongs to an earlier policy epoch; retained output and controls require local owner inspection');
  }
  status(masterId, jobId) { return publicJob(this.get(masterId, jobId)); }
  async reconcileJob({ masterId, jobId, resolution, note }) {
    if (!['completed', 'not_applied', 'effects-confirmed', 'no-effects', 'effects-inspected'].includes(resolution)) fail('INVALID_ARGS', 'Reconciliation requires an explicit inspected-effects resolution');
    if (typeof note !== 'string' || !note.trim() || Buffer.byteLength(note) > 2000) fail('INVALID_ARGS', 'Reconciliation requires a bounded local evidence note');
    const job = this.get(masterId, jobId);
    if (job.state !== 'unknown' && !job.outcomeUnknown) fail('JOB_NOT_UNKNOWN', 'Only an unknown job requires reconciliation');
    job.state = 'reconciled'; job.outcomeUnknown = false; job.resolution = resolution; job.reconciliationNote = note; await this.save(job); await this.emitState(job); return publicJob(job);
  }
  async output(masterId, { jobId, offset = 0, limit = 16384, stream = 'combined' }, policy = {}) {
    const job = this.get(masterId, jobId);
    if (!STREAMS.includes(stream) || !Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > (policy.maxOutputPageBytes ?? 16384)) fail('INVALID_ARGS', 'Invalid output page');
    const key = stream === 'combined' ? 'outputBytes' : `${stream}Bytes`, totalBytes = job[key];
    let data;
    if (!this.stateDir) {
      const buffer = Buffer.alloc(Math.min(limit, Math.max(0, totalBytes - offset)));
      let sourceOffset = 0, copied = 0;
      for (const chunk of job.memory?.[stream] ?? []) {
        if (sourceOffset + chunk.length > offset && copied < buffer.length) {
          const begin = Math.max(0, offset - sourceOffset), count = Math.min(chunk.length - begin, buffer.length - copied);
          chunk.copy(buffer, copied, begin, begin + count); copied += count;
        }
        sourceOffset += chunk.length; if (copied === buffer.length) break;
      }
      data = buffer.subarray(0, copied);
    }
    else {
      const filename = this.filename(jobId, stream), before = await fs.lstat(filename); safeStat(before);
      const handle = await fs.open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      try {
        const stat = await handle.stat(); safeStat(stat);
        if (stat.dev !== before.dev || stat.ino !== before.ino || stat.size > job.maxOutputBytes) fail('JOB_STORE_UNSAFE', 'Job output changed unexpectedly');
        const buffer = Buffer.alloc(Math.min(limit, Math.max(0, totalBytes - offset)));
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset); data = buffer.subarray(0, bytesRead);
      } finally { await handle.close(); }
    }
    return { jobId, stream, offset, bytes: data.length, base64: data.toString('base64'), text: data.toString('utf8'),
      nextOffset: offset + data.length, totalBytes, eof: offset + data.length >= totalBytes, state: job.state, outcomeUnknown: job.outcomeUnknown === true, ...(job.taskId ? { taskId: job.taskId } : {}) };
  }
  async stdin(masterId, args, policy, signal = noSignal()) {
    const job = this.get(masterId, args.jobId);
    const previous = job.stdinQueue ?? Promise.resolve();
    const operation = previous.catch(() => {}).then(() => this.writeStdin(masterId, args, policy, signal));
    job.stdinQueue = operation.catch(() => {});
    return operation;
  }
  async writeStdin(masterId, { jobId, text, eof = false }, policy, signal) {
    signal.throwIfAborted();
    const job = this.get(masterId, jobId), command = policy.execCommands?.get(job.command);
    if (!job.stdinAllowed || command?.stdinAllowed !== true) fail('STDIN_DENIED', 'This configured command does not permit stdin');
    if (job.state !== 'running' || !job.child?.stdin || job.child.stdin.destroyed || job.stdinClosed) fail('JOB_NOT_RUNNING', 'Job stdin is not available');
    const bytes = Buffer.byteLength(text);
    if (job.stdinBytes + bytes > Math.min(job.maxStdinBytes, command.maxStdinBytes ?? 65536)) fail('STDIN_TOO_LARGE', 'Job lifetime stdin cap exceeded');
    job.stdinBytes += bytes;
    // Journal intent before the irreversible write. A crash is then recovered as unknown.
    await this.save(job); signal.throwIfAborted();
    const onAbort = () => job.stop?.(signal.reason ?? new NodeError('CANCELLED', 'Stdin request cancelled'));
    signal.addEventListener('abort', onAbort, { once: true });
    try {
      if (signal.aborted) onAbort();
      await new Promise((resolve, reject) => job.child.stdin.write(text, error => error ? reject(new NodeError('STDIN_FAILED', 'Job stdin could not be written')) : resolve()));
      signal.throwIfAborted();
    } catch (cause) { job.stop?.(cause); throw cause; }
    finally { signal.removeEventListener('abort', onAbort); }
    if (eof) { job.stdinClosed = true; job.child.stdin.end(); }
    return { jobId, bytes, stdinBytes: job.stdinBytes, eof };
  }
  async cancel(masterId, jobId, reason = new NodeError('CANCELLED', 'Authenticated caller cancelled the job')) {
    const job = this.get(masterId, jobId);
    if (!job.stop || TERMINAL.has(job.state)) return { jobId, accepted: false, state: job.state, outcomeUnknown: job.outcomeUnknown === true, ...(job.taskId ? { taskId: job.taskId } : {}) };
    job.stop(reason); await job.done.catch(() => {}); return { jobId, accepted: true, state: job.state, outcomeUnknown: job.outcomeUnknown === true, ...(job.taskId ? { taskId: job.taskId } : {}) };
  }
  async cancelMaster(masterId, reason = new NodeError('POLICY_REVOKED', 'Local peer policy changed')) {
    await Promise.all([...this.jobs.values()].filter(job => job.masterId === masterId && job.stop && !TERMINAL.has(job.state)).map(job => this.cancel(masterId, job.jobId, reason)));
  }
  async cancelAll(reason = new NodeError('SHUTTING_DOWN', 'Node is stopping')) {
    await Promise.all([...this.jobs.values()].filter(job => job.stop && !TERMINAL.has(job.state)).map(job => this.cancel(job.masterId, job.jobId, reason)));
  }
  async shutdown() { this.stopping = true; await this.admission; await this.cancelAll(); }

  async retireCompleted(masterId, retain) {
    const candidates = [...this.jobs.values()].filter(job => ['succeeded', 'failed', 'cancelled', 'timed_out', 'reconciled'].includes(job.state) && !job.outcomeUnknown && !job.child).sort((a, b) => a.startedAt.localeCompare(b.startedAt));
    while ([...this.jobs.values()].filter(job => job.masterId === masterId).length >= retain || this.jobs.size >= MAX_JOBS) {
      const index = [...this.jobs.values()].filter(job => job.masterId === masterId).length >= retain ? candidates.findIndex(job => job.masterId === masterId) : 0;
      if (index < 0 || !candidates.length) return;
      const [job] = candidates.splice(index, 1);
      if (this.stateDir) {
        // Metadata is removed first: any crash leaves only non-authoritative output.
        // The task journal remains authoritative for deduplication and side effects.
        await fs.unlink(this.filename(job.jobId));
        for (const stream of STREAMS) await fs.unlink(this.filename(job.jobId, stream));
      }
      this.jobs.delete(job.jobId);
    }
  }

  async run(task, policy, signal = noSignal(), options = {}) {
    await this.start(); signal.throwIfAborted();
    if (this.stopping) fail('SHUTTING_DOWN', 'Job manager is stopping');
    const masterId = options.masterId ?? [...(policy.allowedMasters ?? ['local'])][0] ?? 'local', runId = options.runId ?? 'default';
    if (!ID.test(masterId) || !ID.test(runId)) fail('INVALID_TASK', 'Invalid job owner or run identifier');
    const previous = this.admission; let release; this.admission = new Promise(resolve => { release = resolve; });
    await previous;
    let command, background, job; const handles = {};
    try {
    signal.throwIfAborted(); if (this.stopping) fail('SHUTTING_DOWN', 'Job manager is stopping');
    this.assertCanWrite(masterId, runId);
    await this.retireCompleted(masterId, policy.maxJobs ?? 32);
    if (this.jobs.size >= MAX_JOBS || [...this.jobs.values()].filter(job => job.masterId === masterId).length >= (policy.maxJobs ?? 32)) fail('JOB_STORE_FULL', 'Job record quota reached; inspect and archive locally');
    if ([...this.jobs.values()].filter(job => !TERMINAL.has(job.state)).length >= this.maxConcurrent) fail('BUSY', 'Global live process limit reached');
    if ([...this.jobs.values()].filter(job => job.masterId === masterId && !TERMINAL.has(job.state)).length >= (policy.maxConcurrent ?? 1)) fail('BUSY', 'Per-peer live process limit reached');
    command = policy.execCommands.get(task.args.command); background = task.args.background === true;
    job = { version: 1, jobId: randomUUID(), masterId, runId, taskId: task.taskId, workspaceId: options.workspaceId, policyEpoch: options.policyEpoch, command: task.args.command, state: 'starting', startedAt: new Date().toISOString(),
      outputBytes: 0, stdoutBytes: 0, stderrBytes: 0, stdinBytes: 0, maxOutputBytes: policy.maxOutputBytes,
      stdinAllowed: command.stdinAllowed === true, maxStdinBytes: command.maxStdinBytes ?? 65536, memory: { combined: [], stdout: [], stderr: [] } };
    try {
      if (this.stateDir) for (const stream of STREAMS) handles[stream] = await fs.open(this.filename(job.jobId, stream), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
      await this.save(job);
    } catch (error) { for (const handle of Object.values(handles)) await handle.close(); throw error; }
    this.jobs.set(job.jobId, job);
    } finally { release(); }
    const child = spawn(command.file, [...command.args, ...task.args.args], {
      cwd: policy.root, env: { ...command.env }, shell: false, windowsHide: true, detached: process.platform !== 'win32',
      stdio: [job.stdinAllowed ? 'pipe' : 'ignore', 'pipe', 'pipe']
    });
    job.child = child;
    let error = null, timer, sequence = 0, written = Promise.resolve(), stopping = Promise.resolve(), spawnResolved = false, launching = Promise.resolve(), pendingOutputBytes = 0;
    const decoders = { stdout: new StringDecoder('utf8'), stderr: new StringDecoder('utf8') };
    const stop = reason => {
      error ??= reason instanceof Error ? reason : new NodeError('EXEC_FAILED', String(reason));
      stopping = terminateProcessTree(child);
      // Closing read ends also prevents escaped descendants holding pipes open.
      child.stdout.destroy(); child.stderr.destroy(); child.stdin?.destroy();
    };
    job.stop = stop;
    const onAbort = () => stop(signal.reason ?? new NodeError('CANCELLED', 'Task cancelled'));
    signal.addEventListener('abort', onAbort, { once: true });
    if (signal.aborted) onAbort();
    let resolveStarted, rejectStarted;
    const started = new Promise((resolve, reject) => { resolveStarted = resolve; rejectStarted = reject; });
    started.catch(() => {});
    const enqueue = (stream, chunk) => {
      if (error) return;
      if (chunk.length > 4096) { for (let offset = 0; offset < chunk.length; offset += 4096) enqueue(stream, chunk.subarray(offset, offset + 4096)); return; }
      if (sequence >= 4096) { stop(new NodeError('OUTPUT_TOO_LARGE', 'Command output event count exceeds local bounded journal')); return; }
      child.stdout.pause(); child.stderr.pause();
      const remaining = job.maxOutputBytes - job.outputBytes;
      if (chunk.length > remaining) { stop(new NodeError('OUTPUT_TOO_LARGE', 'Combined command output exceeds local byte limit')); return; }
      // Reserve the budget before async writes so simultaneous pipes cannot overrun it.
      pendingOutputBytes += chunk.length;
      const offset = job.outputBytes; job.outputBytes += chunk.length; job[`${stream}Bytes`] += chunk.length;
      const event = { jobId: job.jobId, masterId, runId, seq: sequence++, stream, offset, bytes: chunk.length, base64: chunk.toString('base64'), text: decoders[stream].write(chunk) };
      written = written.then(async () => {
        if (this.stateDir) { await handles.combined.writeFile(chunk); await handles[stream].writeFile(chunk); await handles.combined.sync(); await handles[stream].sync(); }
        else { const copy = Buffer.from(chunk); job.memory.combined.push(copy); job.memory[stream].push(copy); }
        if (this.onOutput) await this.onOutput(event);
        if (options.onOutput && options.onOutput !== this.onOutput) await options.onOutput(event);
      }).catch(cause => { stop(new NodeError(cause.code ?? 'JOB_STORE_FAILED', cause.message ?? 'Job output persistence failed')); });
      written.finally(() => { pendingOutputBytes -= chunk.length; if (!error && pendingOutputBytes === 0) { child.stdout.resume(); child.stderr.resume(); } });
    };
    child.stdout.on('data', chunk => enqueue('stdout', chunk)); child.stderr.on('data', chunk => enqueue('stderr', chunk));
    child.stdout.on('error', cause => stop(new NodeError('EXEC_FAILED', `Command output failed: ${cause.code ?? 'I/O error'}`)));
    child.stderr.on('error', cause => stop(new NodeError('EXEC_FAILED', `Command output failed: ${cause.code ?? 'I/O error'}`)));
    child.stdin?.on('error', () => {});
    child.once('error', cause => { error ??= new NodeError('EXEC_FAILED', `Could not execute configured command: ${cause.code ?? 'spawn error'}`); rejectStarted(error); });
    child.once('spawn', () => { launching = (async () => {
      job.pid = child.pid; job.state = 'running';
      const duration = Math.min(task.args.durationMs ?? (background ? policy.maxJobTimeoutMs ?? policy.maxTimeoutMs : task.timeoutMs ?? policy.maxTimeoutMs), policy.maxJobTimeoutMs ?? policy.maxTimeoutMs ?? 3600000);
      timer = setTimeout(() => stop(new NodeError('TASK_TIMEOUT', 'Process-local job duration exceeded')), duration);
      try {
        await this.save(job); await this.emitState(job, options.onState);
        if (task.args.stdin !== undefined) await this.stdin(masterId, { jobId: job.jobId, text: task.args.stdin, eof: true }, policy);
        if (background) signal.removeEventListener('abort', onAbort);
        spawnResolved = true; resolveStarted(publicJob(job));
      } catch (cause) { stop(cause); rejectStarted(cause); }
    })(); });
    job.done = new Promise((resolve, reject) => {
      child.once('close', async (exitCode, exitSignal) => {
        clearTimeout(timer); signal.removeEventListener('abort', onAbort);
        await launching; await stopping;
        // A successful root exit must not leave ordinary same-group descendants
        // running without a live supervisor record. Escaped sessions are outside this contract.
        if (process.platform !== 'win32') await terminateProcessTree(child);
        await written;
        job.exitCode = exitCode; job.exitSignal = exitSignal; job.finishedAt = new Date().toISOString();
        job.state = error?.code === 'TASK_TIMEOUT' ? 'timed_out' : error ? 'cancelled' === error.code?.toLowerCase() || ['TASK_CANCELLED', 'SHUTTING_DOWN', 'POLICY_REVOKED'].includes(error.code) ? 'cancelled' : 'failed' : exitCode === 0 ? 'succeeded' : 'failed';
        job.outcomeUnknown = Boolean(job.pid && (error || exitSignal));
        if (error) job.error = errorData(error);
        try {
          for (const handle of Object.values(handles)) { await handle.sync(); await handle.close(); }
          await this.save(job); await this.emitState(job, options.onState);
          const stdout = await this.output(masterId, { jobId: job.jobId, stream: 'stdout', limit: Math.min(PREVIEW_BYTES, policy.maxOutputPageBytes ?? 16384) });
          const stderr = await this.output(masterId, { jobId: job.jobId, stream: 'stderr', limit: Math.min(PREVIEW_BYTES, policy.maxOutputPageBytes ?? 16384) });
          const result = { jobId: job.jobId, state: job.state, ...(job.outcomeUnknown ? { outcomeUnknown: true } : {}), stdout: stdout.text, stderr: stderr.text, exitCode, signal: exitSignal,
            ...(job.stdoutBytes > stdout.bytes || job.stderrBytes > stderr.bytes ? { jobId: job.jobId, outputTruncated: true, outputBytes: job.outputBytes } : {}) };
          if (error) reject(error); else resolve(result);
        } catch (cause) {
          job.state = 'unknown'; job.outcomeUnknown = true; job.error = errorData(cause);
          // Even if the final job file/output write failed, the prior running
          // record remains recovery-safe and the node must quarantine its master.
          try { await this.save(job); } catch {}
          try { await this.emitState(job, options.onState); } catch {}
          reject(cause);
        }
        finally { delete job.child; delete job.stop; if (!spawnResolved) rejectStarted(error ?? new NodeError('EXEC_FAILED', 'Process ended before start was confirmed')); }
      });
    });
    job.done.catch(() => {});
    if (background) { const state = await started; return { ...state, background: true }; }
    return job.done;
  }
}
