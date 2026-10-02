import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeFrame, sendFrame, MAX_FRAME } from '../src/wire.mjs';

test('serialization fails closed for circular/deep data and oversize output', () => {
  const circular = {}; circular.self = circular;
  assert.equal(encodeFrame(circular), null);
  let deep = 0; for (let i = 0; i < 15000; i++) deep = [deep];
  assert.equal(encodeFrame(deep), null);
  assert.equal(encodeFrame({ text: 'x'.repeat(MAX_FRAME) }), null);
  const socket = { writable: true, destroyed: false, writableLength: 0, destroy() { this.destroyed = true; }, write() { throw new Error('must not write'); } };
  assert.equal(sendFrame(socket, circular), false); assert.equal(socket.destroyed, true);
});
