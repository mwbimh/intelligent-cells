import fs from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import net from 'node:net';
import { certificateIdentity, normalizeFingerprint } from './identity.mjs';
import { fail } from './errors.mjs';

export function reviewIdentity(certificatePem, expectedId, expectedFingerprint, caPem) {
  if (typeof certificatePem !== 'string' || Buffer.byteLength(certificatePem) > 32768) fail('INVALID_CERTIFICATE', 'Certificate PEM is required and must be <=32 KiB');
  const own = certificateIdentity(certificatePem);
  if (own.nodeId !== expectedId) fail('IDENTITY_MISMATCH', 'Certificate identity differs from the requested peer ID');
  const expected = normalizeFingerprint(expectedFingerprint);
  if (own.fingerprint256 !== expected) fail('PIN_MISMATCH', 'Certificate fingerprint differs from the independently verified pin');
  const now = Date.now(), validToMs = Date.parse(own.validTo);
  if (now < Date.parse(own.validFrom) || now >= validToMs) fail('CERTIFICATE_EXPIRED', 'Certificate is expired or not yet valid');
  if (own.cert.ca) fail('INVALID_CERTIFICATE', 'A CA certificate cannot be paired as a node identity');
  // A supplied matching pin is not enough: the node must chain directly to one
  // of the configured roots. Intermediates need explicit offline verification.
  if (caPem) {
    const roots = String(caPem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
    if (!roots.some(pem => { const ca = new X509Certificate(pem); return ca.ca && now >= Date.parse(ca.validFrom) && now < Date.parse(ca.validTo) && own.cert.checkIssued(ca) && own.cert.verify(ca.publicKey); })) fail('UNTRUSTED_CA', 'Peer certificate is not signed by a current configured CA');
  }
  return { nodeId: own.nodeId, fingerprint256: own.fingerprint256, validFrom: own.validFrom, validTo: own.validTo, expiresInDays: Math.floor((validToMs - now) / 86400000), expiringSoon: validToMs - now < 30 * 86400000, independentlyVerifiedPin: true };
}
export function identitySummary(node) {
  const own = certificateIdentity(node.config.security.cert);
  return { nodeId: own.nodeId, fingerprint256: own.fingerprint256, validFrom: own.validFrom, validTo: own.validTo, expiresInDays: Math.floor((Date.parse(own.validTo) - Date.now()) / 86400000),
    trustedPeers: [...node.config.security.trustedPeers].map(([id, pins]) => ({ id, pins: [...pins] })), restartRequiredForTrustChanges: true };
}
export async function applyPairing(node, command) {
  if (!node.config.filename) fail('CONFIG_REQUIRED', 'Pairing needs a durable configuration file');
  if (command.peerId === node.config.id) fail('IDENTITY_MISMATCH', 'Cannot pair this node with itself');
  if (command.outOfBandVerified !== true) fail('PIN_REVIEW_REQUIRED', 'Confirm the pin was verified through an independent channel');
  const reviewed = reviewIdentity(command.certificatePem, command.peerId, command.expectedFingerprint, node.config.security.ca);
  const raw = JSON.parse(await fs.readFile(node.config.filename, 'utf8'));
  const pins = raw.security.trustedPeers ??= {};
  if (Object.keys(pins).length >= 128 && !Object.hasOwn(pins, reviewed.nodeId)) fail('INVALID_CONFIG', 'At most 128 trusted peer identities');
  const current = pins[reviewed.nodeId] ? (Array.isArray(pins[reviewed.nodeId]) ? pins[reviewed.nodeId] : [pins[reviewed.nodeId]]).map(normalizeFingerprint) : [];
  if (command.rotation === true) {
    const next = [...new Set([...current, reviewed.fingerprint256])];
    if (next.length > 4) fail('PIN_LIMIT', 'Remove an obsolete pin before adding another rotation pin');
    pins[reviewed.nodeId] = next;
  } else {
    if (current.length && !current.includes(reviewed.fingerprint256)) fail('ROTATION_REQUIRED', 'Existing identity requires explicit rotation review');
    pins[reviewed.nodeId] = [...new Set([...current, reviewed.fingerprint256])];
  }
  if (command.peer !== undefined) {
    const p = command.peer;
    if (!p || !net.isIP(p.host) || !Number.isInteger(p.port) || p.port < 1 || p.port > 65535 || (p.host !== '127.0.0.1' && raw.security.allowExternal !== true)) fail('INVALID_PEER', 'Peer requires a valid IP/port and explicit external TLS configuration');
    if (!raw.agent) fail('AGENT_REQUIRED', 'Outgoing execution relationships require an agent');
    raw.peers ??= [];
    const index = raw.peers.findIndex(peer => peer.id === reviewed.nodeId);
    if (index < 0 && raw.peers.length >= 32) fail('INVALID_CONFIG', 'At most 32 outgoing peers');
    const target = { id: reviewed.nodeId, host: p.host, port: p.port };
    if (index < 0) raw.peers.push(target); else raw.peers[index] = target;
  }
  const { atomicWriteJson } = await import('./durable.mjs');
  await atomicWriteJson(node.config.filename, raw);
  node.log('identity_paired', { peerId: reviewed.nodeId, status: 'restart_required' });
  return { ...reviewed, persisted: true, restartRequired: true, grantsAdded: false };
}
export async function removePairingPin(node, command) {
  const pin = normalizeFingerprint(command.fingerprint);
  if (typeof command.peerId !== 'string') fail('INVALID_PEER', 'Peer identity required');
  const raw = JSON.parse(await fs.readFile(node.config.filename, 'utf8'));
  const current = raw.security.trustedPeers?.[command.peerId];
  if (!current) fail('UNKNOWN_PEER', 'Peer has no trust entry');
  const remaining = (Array.isArray(current) ? current : [current]).map(normalizeFingerprint).filter(value => value !== pin);
  if (!remaining.length) fail('REVOKE_REQUIRED', 'Use revokePeer to remove the final trusted pin and permissions');
  raw.security.trustedPeers[command.peerId] = remaining;
  const { atomicWriteJson } = await import('./durable.mjs'); await atomicWriteJson(node.config.filename, raw);
  // Old sessions cannot be kept alive after their pin is removed.
  for (const socket of node.inbound ?? []) if (socket.authenticatedId === command.peerId) socket.destroy();
  node.peers.get(command.peerId)?.socket?.destroy();
  const activePins = node.config.security.trustedPeers.get(command.peerId) ?? new Set();
  const narrowed = new Set(remaining.filter(value => activePins.has(value)));
  if (narrowed.size) node.config.security.trustedPeers.set(command.peerId, narrowed); else node.config.security.trustedPeers.delete(command.peerId);
  node.log('identity_pin_removed', { peerId: command.peerId });
  return { removed: true, peerId: command.peerId, restartRequired: true };
}
export async function revokePairing(node, command) {
  if (typeof command.peerId !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(command.peerId)) fail('INVALID_PEER', 'Valid peer ID is required');
  // Revoke execution first; later persistence failure keeps the running node
  // denied and never expands authority.
  await node.command({ command: 'revoke', masterId: command.peerId });
  const peer = node.peers.get(command.peerId);
  if (peer) { clearTimeout(peer.retry); node.peers.delete(command.peerId); peer.socket?.destroy(); }
  node.config.security.trustedPeers.delete(command.peerId);
  for (const socket of node.inbound ?? []) if (socket.authenticatedId === command.peerId) socket.destroy();
  const raw = JSON.parse(await fs.readFile(node.config.filename, 'utf8'));
  delete raw.security.trustedPeers?.[command.peerId];
  if (raw.policy?.grants) delete raw.policy.grants[command.peerId];
  raw.peers = (raw.peers ?? []).filter(p => p.id !== command.peerId);
  const { atomicWriteJson } = await import('./durable.mjs'); await atomicWriteJson(node.config.filename, raw);
  node.log('identity_revoked', { peerId: command.peerId });
  return { revoked: command.peerId, persisted: true, restartRequired: false };
}
