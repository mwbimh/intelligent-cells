// Read-only validation. Does not listen, create an identity, or change trust.
import { loadConfig } from '../src/config.mjs';
try {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/check-config.mjs <config.json>');
  const config = await loadConfig(process.argv[2]);
  console.log(JSON.stringify({ valid: true, nodeId: config.id, transport: 'TLSv1.3-mTLS-pinned', host: config.host,
    externalBindingRequested: config.host !== '127.0.0.1', certificateFingerprint: config.security.fingerprint256,
    outgoing: config.peers.map(p => p.id), incomingGrants: [...config.policy.grants.keys()], changedAnything: false }, null, 2));
} catch (error) { console.error(JSON.stringify({ valid: false, code: error.code ?? 'INVALID_CONFIG', message: error.message })); process.exitCode = 1; }
