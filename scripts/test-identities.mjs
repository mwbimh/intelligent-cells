// Disposable test identities ONLY. Never use these CA/keys for deployments.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { certificateIdentity } from '../src/identity.mjs';
const exec = promisify(execFile);
const queues = new Map();
async function checkDisposable(dir) {
  const root = await fs.realpath(dir), temp = await fs.realpath(os.tmpdir());
  if (!root.startsWith(temp + path.sep) || await fs.readFile(path.join(root, '.disposable-test-only'), 'utf8') !== 'ephemeral identities\n') throw new Error('Test identity generation requires a marked disposable directory under OS temp');
}
export async function initTestCA(dir) {
  await checkDisposable(dir);
  await fs.mkdir(path.join(dir, 'identities'), { mode: 0o700 });
  const p = name => path.join(dir, 'identities', name);
  await exec('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', p('ca.key'), '-out', p('ca.pem'), '-days', '1', '-subj', '/CN=DISPOSABLE-TEST-ONLY', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
  await fs.chmod(p('ca.key'), 0o600);
}
export async function createTestIdentity(dir, id, { expired = false, suffix = '' } = {}) {
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id) || !/^[a-zA-Z0-9_-]*$/.test(suffix)) throw new Error('Invalid test identity');
  const previous = queues.get(dir) ?? Promise.resolve();
  const job = previous.catch(() => {}).then(async () => {
    await checkDisposable(dir);
    const p = name => path.join(dir, 'identities', name), name = id + suffix;
    try { const cert = await fs.readFile(p(name + '.pem')); return { id, cert: p(name + '.pem'), key: p(name + '.key'), fingerprint256: certificateIdentity(cert).fingerprint256 }; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await exec('openssl', ['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', p(name + '.key'), '-out', p(name + '.csr'), '-subj', '/CN=' + id]);
    await fs.chmod(p(name + '.key'), 0o600);
    await fs.writeFile(p(name + '.ext'), `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:${id}\n`);
    if (expired) {
      const work = p(name + '-ca-work'); await fs.mkdir(work);
      await fs.writeFile(path.join(work, 'index'), ''); await fs.writeFile(path.join(work, 'serial'), '1000\n');
      const conf = `[ca]\ndefault_ca=CA_default\n[CA_default]\ndatabase=${work}/index\nserial=${work}/serial\nnew_certs_dir=${work}\ncertificate=${p('ca.pem')}\nprivate_key=${p('ca.key')}\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n`;
      await fs.writeFile(path.join(work, 'config'), conf);
      await exec('openssl', ['ca', '-batch', '-notext', '-config', path.join(work, 'config'), '-in', p(name + '.csr'), '-out', p(name + '.pem'), '-startdate', '20000101000000Z', '-enddate', '20010101000000Z', '-extfile', p(name + '.ext')]);
    } else await exec('openssl', ['x509', '-req', '-in', p(name + '.csr'), '-CA', p('ca.pem'), '-CAkey', p('ca.key'), '-CAcreateserial', '-out', p(name + '.pem'), '-days', '1', '-extfile', p(name + '.ext')]);
    return { id, cert: p(name + '.pem'), key: p(name + '.key'), fingerprint256: certificateIdentity(await fs.readFile(p(name + '.pem'))).fingerprint256 };
  });
  queues.set(dir, job); return job;
}
export async function testSecurity(dir, id, trustedIds = []) {
  const own = await createTestIdentity(dir, id), trustedPeers = {};
  for (const other of new Set(trustedIds)) if (other !== id) trustedPeers[other] = (await createTestIdentity(dir, other)).fingerprint256;
  return { cert: own.cert, key: own.key, ca: path.join(dir, 'identities', 'ca.pem'), trustedPeers };
}
export async function testTlsOptions(dir, id = 'master', options = {}) {
  const own = await createTestIdentity(dir, id, options);
  return { cert: await fs.readFile(own.cert), key: await fs.readFile(own.key), ca: await fs.readFile(path.join(dir, 'identities', 'ca.pem')), minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', rejectUnauthorized: true, checkServerIdentity: () => undefined };
}
