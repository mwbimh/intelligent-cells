import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
const source = await readFile(new URL('./app.js', import.meta.url), 'utf8');
const ui = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
const master = { id: 'a6b32385-42d7-4e92-8acf-4d43fbd2a45e', host: '100.64.0.1', port: 18434, fingerprint256: 'ab'.repeat(32) };
test('servant request carries independently entered master identity', () => {
  assert.deepEqual(ui.pairingCommand('request', { ...master, port: '18434' }), { command: 'pairingRequest', master });
});
test('confirmation uses the same request and grants no tools implicitly', () => {
  assert.deepEqual(ui.pairingCommand('confirm', { ...master, requestId: 'request-123' }), { command: 'pairingConfirm', master, requestId: 'request-123' });
  assert.throws(() => ui.pairingCommand('confirm', master), /request/i);
});
test('approval requires explicit verified fingerprint and rejection does not', () => {
  assert.throws(() => ui.pairingCommand('approve', { requestId: 'r' }), /fingerprint/i);
  assert.deepEqual(ui.pairingCommand('approve', { requestId: 'r', fingerprint256: master.fingerprint256 }), { command: 'pairingApprove', requestId: 'r', expectedFingerprint: master.fingerprint256 });
  assert.deepEqual(ui.pairingCommand('reject', { requestId: 'r' }), { command: 'pairingReject', requestId: 'r' });
});
test('malformed endpoint, identity and action are rejected before submission', () => {
  for (const update of [{ id: 'display name' }, { host: '' }, { port: 0 }, { port: 65536 }, { fingerprint256: 'short' }]) assert.throws(() => ui.pairingCommand('request', { ...master, ...update }));
  assert.throws(() => ui.pairingCommand('unexpected', master));
});
test('pairing interface uses live requests and has no manual certificate form', async () => {
  const html = await readFile(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /id="pairing-requests"/);
  assert.match(html, /id="pair-request-form"/);
  assert.doesNotMatch(html, /id="pair-cert"|id="pair-rotation"/);
  assert.doesNotMatch(source, /command: 'pairPeer'|command: 'reviewPeer'|command: 'removePeerPin'/);
});
