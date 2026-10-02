import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { loadConfig, loadPolicy, validatePolicyIsolation } from '../src/config.mjs';
import { compileMcpPolicy, verifyMcpCodePolicy } from '../src/mcp.mjs';
import { verifyApprovedCode } from '../src/code-policy.mjs';

// Configuration-only checks. Fixtures are empty files; no child program or
// private identity data is created, invoked or read by these regressions.
test('permission invariant: readable and writable workspaces are disjoint from every protected tree', () => {
  const base = path.join(os.tmpdir(), 'synthetic-permission-layout');
  const config = {
    filename: path.join(base, 'node.json'), stateDir: path.join(base, 'state'),
    securityFiles: [path.join(base, 'identities', 'certificate.pem')],
    logFile: path.join(base, 'logs', 'audit.jsonl'),
    operator: { sessionDirectory: path.join(base, 'sessions'), socketPath: path.join(base, 'ipc', 'owner.sock') },
  };
  const policy = (root, tools) => ({ grants: new Map([['peer', { root, tools: new Set(tools) }]]) });
  for (const tools of [['readFile'], ['writeFile'], ['readChunk']]) {
    for (const tree of ['state', 'identities', 'logs', 'sessions', 'ipc']) {
      for (const root of [base, path.join(base, tree), path.join(base, tree, 'empty-child')]) {
        assert.throws(() => validatePolicyIsolation(policy(root, tools), config), { code: 'UNSAFE_STATE_POLICY' });
      }
      assert.doesNotThrow(() => validatePolicyIsolation(policy(path.join(base, `${tree}-sibling`), tools), config));
    }
    assert.throws(() => validatePolicyIsolation(policy(path.join(base, 'node.json', 'empty-child'), tools), config), { code: 'UNSAFE_STATE_POLICY' });
    assert.doesNotThrow(() => validatePolicyIsolation(policy(path.join(base, 'workspace'), tools), config));
  }
  // Intentional colocated config/log files do not reserve their entire parent.
  assert.doesNotThrow(() => validatePolicyIsolation(policy(path.join(base, 'workspace'), ['writeFile']), { ...config, logFile: path.join(base, 'audit.jsonl') }));
});

test('permission invariant: explicit empty protected paths reject before identity loading', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'permission-empty-paths-'));
  const filename = path.join(directory, 'node.json');
  try {
    for (const values of [{ stateDir: '' }, { logFile: '' }, { operator: { sessionDirectory: '' } }, { operator: { socketPath: '' } }, ...['cert', 'key', 'ca'].map(key => ({ security: { [key]: '' } }))]) {
      await fs.writeFile(filename, JSON.stringify({ id: 'synthetic', port: 0, ...values }));
      await assert.rejects(loadConfig(filename), { code: 'INVALID_CONFIG' });
    }
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('permission invariant: exec and MCP require explicit local entrypoints and reject ambiguous launch forms', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'permission-code-policy-'));
  const root = path.join(directory, 'workspace'), script = path.join(directory, 'approved-empty.mjs');
  await fs.mkdir(root); await fs.writeFile(script, '');
  const command = { file: process.execPath, args: [script] };
  const execPolicy = value => loadPolicy({ grants: { peer: { tools: ['exec', 'writeFile'], workspace: root, execCommands: { approved: value } } } });
  const mcpPolicy = value => compileMcpPolicy({ mcpServers: { approved: { trusted: true, tools: {}, ...value } } }, directory, root);
  try {
    const policy = await execPolicy(command), compiled = await mcpPolicy(command);
    const executable = policy.grants.get('peer').execCommands.get('approved');
    assert.deepEqual(executable.codeFiles, [await fs.realpath(process.execPath), script]);
    await verifyApprovedCode(executable, new AbortController().signal, 'EXEC_CODE_CHANGED');
    await verifyMcpCodePolicy({ grants: new Map([['peer', { root, tools: new Set(['writeFile']), ...compiled }]]) });
    for (const args of [[], [''], ['relative-empty.mjs'], ['--import=', ''], ['--require', ''], ['--eval', ''], ['--', '']]) {
      await assert.rejects(execPolicy({ ...command, args }), { code: 'UNSAFE_EXEC_POLICY' });
      await assert.rejects(mcpPolicy({ ...command, args }), { code: 'UNSAFE_MCP_POLICY' });
    }
    const missing = path.join(directory, 'missing-empty.mjs');
    await assert.rejects(execPolicy({ ...command, args: [missing] }), { code: 'UNSAFE_EXEC_POLICY' });
    await assert.rejects(mcpPolicy({ ...command, args: [missing] }), { code: 'UNSAFE_MCP_POLICY' });
    await assert.rejects(loadPolicy({ grants: { peer: { tools: ['readFile'], workspace: '' } } }), { code: 'INVALID_CONFIG' });
    await assert.rejects(execPolicy({ ...command, launchMode: 'native' }), { code: 'UNSAFE_EXEC_POLICY' });
    await assert.rejects(mcpPolicy({ ...command, launchMode: 'unsupported' }), { code: 'UNSAFE_MCP_POLICY' });
    const localCode = path.join(root, 'empty.mjs'); await fs.writeFile(localCode, '');
    await assert.rejects(execPolicy({ ...command, args: [localCode] }), { code: 'UNSAFE_EXEC_POLICY' });
    const mcp = await mcpPolicy({ ...command, args: [localCode] });
    await assert.rejects(verifyMcpCodePolicy({ grants: new Map([['peer', { root, tools: new Set(['writeFile']), ...mcp }]]) }), { code: 'UNSAFE_MCP_POLICY' });
    // Replacing an approved empty file invalidates both captured approvals.
    await fs.rename(script, path.join(directory, 'previous-empty.mjs')); await fs.writeFile(script, '');
    await assert.rejects(verifyApprovedCode(executable, new AbortController().signal, 'EXEC_CODE_CHANGED'), { code: 'EXEC_CODE_CHANGED' });
    await assert.rejects(verifyApprovedCode(compiled.mcpServers.get('approved'), new AbortController().signal, 'MCP_CODE_CHANGED'), { code: 'MCP_CODE_CHANGED' });
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('permission invariant: explicit native aliases preserve fixed-argv development commands without spawning', async t => {
  const file = '/usr/bin/git';
  try { await fs.access(file); } catch { t.skip('This platform has no /usr/bin/git binary for the compile-only fixture'); return; }
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'permission-native-policy-'));
  const command = { file, args: ['--version'], launchMode: 'native' };
  const compile = value => loadPolicy({ grants: { peer: { tools: ['exec'], workspace: root, execCommands: { git_version: value } } } });
  try {
    const policy = await compile(command), native = policy.grants.get('peer').execCommands.get('git_version');
    assert.equal(native.launchMode, 'native'); assert.deepEqual(native.codeFiles, [await fs.realpath(file)]);
    await verifyApprovedCode(native, new AbortController().signal, 'EXEC_CODE_CHANGED');
    await assert.rejects(compile({ ...command, argsAllowed: true }), { code: 'UNSAFE_EXEC_POLICY' });
    await assert.rejects(compile({ ...command, stdinAllowed: true }), { code: 'UNSAFE_EXEC_POLICY' });
    const mcp = await compileMcpPolicy({ mcpServers: { native: { ...command, trusted: true, tools: {} } } }, root, root);
    assert.equal(mcp.mcpServers.get('native').launchMode, 'native');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
