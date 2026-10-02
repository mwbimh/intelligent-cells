import tls from 'node:tls';
import fs from 'node:fs/promises';
import path from 'node:path';
import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { fail, isObject } from './errors.mjs';

export function normalizeFingerprint(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$|^[0-9a-f]{64}$/i.test(value)) fail('INVALID_CONFIG', 'Certificate pin must be a SHA-256 fingerprint');
  return value.replaceAll(':', '').toUpperCase();
}
export function certificateIdentity(pem) {
  const cert = new X509Certificate(pem);
  const subject = cert.subject.split('\n');
  const ids = subject.filter(x => x.startsWith('CN=')).map(x => x.slice(3));
  if (ids.length !== 1 || !/^[a-zA-Z0-9_-]{1,64}$/.test(ids[0])) fail('IDENTITY_MISMATCH', 'Certificate must have exactly one valid node ID as its CN');
  return { nodeId: ids[0], fingerprint256: normalizeFingerprint(cert.fingerprint256), validFrom: cert.validFrom, validTo: cert.validTo, cert };
}
export async function loadSecurity(raw, base, nodeId) {
  if (!isObject(raw) || !['cert', 'key', 'ca'].every(k => typeof raw[k] === 'string')) fail('SECURITY_REQUIRED', 'Explicit certificate, private key, CA and pinned trust are mandatory; plaintext is not supported');
  const read = name => fs.readFile(path.resolve(base, raw[name]));
  const [cert, key, ca] = await Promise.all(['cert', 'key', 'ca'].map(read));
  const own = certificateIdentity(cert);
  if (own.nodeId !== nodeId) fail('IDENTITY_MISMATCH', 'Local certificate identity differs from configured node ID');
  const now = Date.now();
  if (now < Date.parse(own.validFrom) || now > Date.parse(own.validTo)) fail('CERTIFICATE_EXPIRED', 'Local certificate is expired or not yet valid');
  if (!own.cert.publicKey.equals(createPublicKey(createPrivateKey(key)))) fail('IDENTITY_MISMATCH', 'Certificate and private key do not match');
  if (!isObject(raw.trustedPeers ?? {})) fail('INVALID_CONFIG', 'trustedPeers must map node IDs to pinned certificate fingerprints');
  const trustedPeers = new Map();
  for (const [id, values] of Object.entries(raw.trustedPeers ?? {})) {
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id) || id === nodeId) fail('INVALID_CONFIG', 'Invalid trusted peer identity');
    const pins = Array.isArray(values) ? values : [values];
    if (!pins.length || pins.length > 4) fail('INVALID_CONFIG', 'Each trusted identity needs one to four certificate pins');
    trustedPeers.set(id, new Set(pins.map(normalizeFingerprint)));
  }
  // Let OpenSSL validate syntax/key strength at startup, before listening.
  tls.createSecureContext({ cert, key, ca, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
  return { cert, key, ca, trustedPeers, allowExternal: raw.allowExternal === true, fingerprint256: own.fingerprint256 };
}
export function authenticateCertificate(peerCertificate, security, expectedId = null) {
  if (!peerCertificate?.raw) fail('IDENTITY_MISMATCH', 'No peer certificate');
  const identity = certificateIdentity(peerCertificate.raw);
  if (expectedId !== null && identity.nodeId !== expectedId) fail('IDENTITY_MISMATCH', 'Peer certificate has an unexpected node identity');
  const pins = security.trustedPeers.get(identity.nodeId);
  if (!pins?.has(identity.fingerprint256)) fail('UNTRUSTED_IDENTITY', 'Peer certificate is not explicitly pinned for its node identity');
  const now = Date.now();
  if (now < Date.parse(identity.validFrom) || now > Date.parse(identity.validTo)) fail('CERTIFICATE_EXPIRED', 'Peer certificate is expired or not yet valid');
  return identity.nodeId;
}
export const tlsOptions = security => ({ cert: security.cert, key: security.key, ca: security.ca, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', rejectUnauthorized: true });
