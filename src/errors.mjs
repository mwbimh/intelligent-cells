export class NodeError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
export function fail(code, message) { throw new NodeError(code, message); }
export function errorData(error) { return { code: error.code || 'INTERNAL_ERROR', message: error.message || 'Unknown error' }; }
export const isObject = x => x !== null && typeof x === 'object' && !Array.isArray(x);
export function integer(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('INVALID_CONFIG', `${name} must be ${min}..${max}`);
  return value;
}
