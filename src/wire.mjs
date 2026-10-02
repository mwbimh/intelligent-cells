import { isObject } from './errors.mjs';
export const MAX_FRAME = 131072;
const MAX_DEPTH = 32;
export function encodeFrame(value) {
  try {
    const frame = JSON.stringify(value) + '\n';
    return Buffer.byteLength(frame) <= MAX_FRAME ? frame : null;
  } catch { return null; }
}
export function sendFrame(socket, value) {
  if (!socket || socket.destroyed || !socket.writable) return false;
  const frame = encodeFrame(value);
  if (frame === null || socket.writableLength > MAX_FRAME * 2) { socket.destroy(); return false; }
  socket.write(frame); return true;
}
function boundedDepth(text) {
  let depth = 0, quoted = false, escaped = false;
  for (const character of text) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quoted = false;
    } else if (character === '"') quoted = true;
    else if (character === '{' || character === '[') { if (++depth > MAX_DEPTH) return false; }
    else if (character === '}' || character === ']') depth--;
  }
  return true;
}
// Used for network sockets AND local stdin. Invalid/oversized input closes only
// that stream. Closing operator stdin deliberately requests clean node shutdown.
export function receiveFrames(stream, onFrame, onInvalid) {
  let buffer = Buffer.alloc(0);
  const invalid = reason => { onInvalid(reason); stream.destroy(); };
  stream.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    while (!stream.destroyed) {
      const index = buffer.indexOf(10);
      if (index < 0) break;
      if (index + 1 > MAX_FRAME) { invalid('frame too large'); return; }
      const line = buffer.subarray(0, index).toString('utf8'); buffer = buffer.subarray(index + 1);
      if (!line.trim()) continue;
      if (!boundedDepth(line)) { invalid('JSON nesting too deep'); return; }
      try {
        const parsed = JSON.parse(line);
        if (!isObject(parsed)) throw new Error('object required');
        onFrame(parsed);
      } catch { invalid('invalid JSON frame'); return; }
    }
    if (buffer.length >= MAX_FRAME) invalid('frame too large');
  });
}
