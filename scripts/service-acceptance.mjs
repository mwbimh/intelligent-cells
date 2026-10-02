// Read-only acceptance against an already running owner-authorized node.
// Does not provision hosts, keys, access, tasks, services or firewall rules.
import { connectOperator } from './operator.mjs';
import { pathToFileURL } from 'node:url';
export async function inspectRunningService(socketPath, options = {}) {
  const checks = [], client = await connectOperator(socketPath, options);
  try {
    const state = await client.request('/api/state'), logs = await client.request('/api/logs');
    checks.push({ name: 'local-owner-authentication', status: 'passed' });
    checks.push({ name: 'durable-ledger-enabled', status: state.status.durable ? 'passed' : 'failed' });
    checks.push({ name: 'tls13-mtls-pinned-config', status: state.status.transport === 'TLSv1.3-mTLS-pinned' ? 'passed' : 'failed' });
    checks.push({ name: 'local-certificate-current', status: Date.parse(state.identity.validTo) > Date.now() && Date.parse(state.identity.validFrom) <= Date.now() ? 'passed' : 'failed', expiresInDays: state.identity.expiresInDays });
    checks.push({ name: 'audit-configured', status: logs.unavailable ? 'not_configured' : 'passed' });
    checks.push({ name: 'known-outgoing-peers-connected', status: state.status.peers?.length ? state.status.peers.every(peer => peer.connected) ? 'passed' : 'failed' : 'not_applicable' });
    checks.push({ name: 'operator-cross-origin-rejection', status: (await fetch(`${client.origin}/api/state`, { headers: { Origin: 'https://untrusted.invalid' } })).status === 403 ? 'passed' : 'failed' });
    checks.push(...['external-vps-network-path', 'real-windows-host', 'service-manager-registration', 'reboot-and-login-behavior', 'production-certificate-rollover', 'external-side-effect-idempotency'].map(name => ({ name, status: 'not_run', reason: 'Requires an explicitly authorized target environment and separate evidence' })));
    return { timestamp: new Date().toISOString(), scope: 'read-only local running process', nodeId: state.status.id, checks, passed: !checks.some(check => check.status === 'failed'), productionVerified: false };
  } finally { await client.request('/api/logout', {}); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { if (!['--socket', '--session-file'].includes(process.argv[2]) || !process.argv[3]) throw new Error('Usage: service-acceptance.mjs --socket|--session-file <owner-access-path>'); const result = await inspectRunningService(process.argv[3], { sessionFile: process.argv[2] === '--session-file' }); console.log(JSON.stringify(result, null, 2)); if (!result.passed) process.exitCode = 1; } catch (error) { console.error(error.message); process.exitCode = 1; }
}
