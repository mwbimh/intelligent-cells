import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { runPiMock } from '../integration/pi/agent.mjs';
import { REMOTE_TOOL_NAMES } from '../integration/pi/remote-tools.mjs';

test('independent Pi audit: stock tools and project resources cannot execute on the master', { timeout: 30000 }, async () => {
  const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'pi-isolation-audit-'));
  const marker = path.join(cwd, 'extension-ran');
  const localFile = path.join(cwd, 'pi-local-bypass-sentinel.txt');
  try {
    await fs.mkdir(path.join(cwd, '.pi', 'extensions'), { recursive: true });
    await fs.writeFile(path.join(cwd, '.pi', 'extensions', 'audit.mjs'), `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'EXECUTED'); export default function() {}`);
    await fs.writeFile(path.join(cwd, 'AGENTS.md'), 'AUDIT_CONTEXT_SECRET_DO_NOT_READ_5367');
    await fs.writeFile(localFile, 'ORIGINAL_LOCAL_FILE_5367');
    const dispatches = [];
    const result = await runPiMock({ cwd, peerIds: ['servant'], prompt: 'Test stock tool attempts', scenario: 'local-bypass', dispatch: async (...args) => { dispatches.push(args); throw new Error('No remote dispatch expected'); } });
    assert.deepEqual(result.allTools, [...REMOTE_TOOL_NAMES].sort());
    assert.deepEqual(result.activeTools, [...REMOTE_TOOL_NAMES].sort());
    assert.equal(dispatches.length, 0);
    const toolResults = result.messages.filter(m => m.role === 'toolResult');
    assert.equal(toolResults.length, 8);
    assert.ok(toolResults.every(m => m.isError === true));
    assert.equal(await fs.readFile(localFile, 'utf8'), 'ORIGINAL_LOCAL_FILE_5367');
    assert.equal(await fs.stat(marker).then(() => true, () => false), false);
    assert.ok(!JSON.stringify(result.messages).includes('ORIGINAL_LOCAL_FILE_5367'));
    assert.ok(!JSON.stringify(result.messages).includes('AUDIT_CONTEXT_SECRET_DO_NOT_READ_5367'));
    assert.equal(result.modelRequests, 9);
    for (const names of result.modelToolDeclarations) assert.deepEqual([...names].sort(), [...REMOTE_TOOL_NAMES].sort());
  } finally { await fs.rm(cwd, { recursive: true, force: true }); }
});

test('independent Pi audit: unconfigured peers and malformed model arguments never dispatch', { timeout: 30000 }, async () => {
  const dispatches = [];
  const result = await runPiMock({ peerIds: ['servant'], prompt: 'Reject malformed model calls',
    calls: [
      { name: 'remote_echo', arguments: { peerId: 'unconfigured', text: 'no' } },
      { name: 'remote_read', arguments: { peerId: 'servant', path: { unexpected: true } } },
      { name: 'remote_exec', arguments: { peerId: 'servant', command: 'fixture', args: [], shell: true } },
      { name: 'remote_echo', arguments: { peerId: 'servant', text: 'no', timeoutMs: 0 } },
    ], dispatch: async (...args) => { dispatches.push(args); throw new Error('No dispatch expected'); },
  });
  const results = result.messages.filter(m => m.role === 'toolResult');
  assert.equal(results.length, 4);
  assert.ok(results.every(m => m.isError === true));
  assert.equal(dispatches.length, 0);
  assert.match(result.final, /UNKNOWN_PEER/);
});
