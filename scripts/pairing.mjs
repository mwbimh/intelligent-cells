// Read-only identity/trust planning. Does NOT generate keys or grant access.
import fs from 'node:fs/promises';
import { certificateIdentity } from '../src/identity.mjs';
import { pathToFileURL } from 'node:url';
export async function inspectIdentity(certFile, expectedId) {
  const result = certificateIdentity(await fs.readFile(certFile));
  if (expectedId !== undefined && result.nodeId !== expectedId) throw new Error('Certificate identity does not match requested peer');
  return { nodeId: result.nodeId, fingerprint256: result.fingerprint256, validFrom: result.validFrom, validTo: result.validTo,
    trustFragment: { trustedPeers: { [result.nodeId]: result.fingerprint256 } },
    warning: 'Verify this fingerprint out-of-band with the peer owner. This output grants no permission and changes no configuration.' };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, file, id] = process.argv.slice(2);
  if (command !== 'inspect' || !file) { console.error('Usage: node scripts/pairing.mjs inspect <peer-certificate.pem> [expected-node-id]'); process.exitCode = 1; }
  else { try { console.log(JSON.stringify(await inspectIdentity(file, id), null, 2)); } catch (error) { console.error(error.message); process.exitCode = 1; } }
}
