// Read-only certificate lifecycle plans. Operational key generation and trust
// changes require the owner's explicit action outside this planning command.
import fs from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { certificateIdentity } from '../src/identity.mjs';
import { reviewIdentity } from '../src/operator-identity.mjs';
export async function inspectCertificate(filename, now = Date.now()) {
  const identity = certificateIdentity(await fs.readFile(filename));
  const starts = Date.parse(identity.validFrom), expires = Date.parse(identity.validTo);
  return { nodeId: identity.nodeId, fingerprint256: identity.fingerprint256, validFrom: identity.validFrom, validTo: identity.validTo, expiresInDays: Math.floor((expires - now) / 86400000), status: now < starts ? 'not_yet_valid' : now >= expires ? 'expired' : expires - now < 30 * 86400000 ? 'expiring_soon' : 'valid', privateKeyRead: false, changed: false };
}
export async function rotationPlan({ oldCertificate, newCertificate, expectedFingerprint, caCertificate }) {
  const previous = await inspectCertificate(oldCertificate);
  const next = reviewIdentity(await fs.readFile(newCertificate, 'utf8'), previous.nodeId, expectedFingerprint, caCertificate ? await fs.readFile(caCertificate, 'utf8') : undefined);
  if (previous.fingerprint256 === next.fingerprint256) throw new Error('New certificate must have a new fingerprint');
  return { nodeId: previous.nodeId, previous, next, overlapPins: [previous.fingerprint256, next.fingerprint256], changed: false, steps: [
    '在每个对端所有者的独立渠道核对新证书指纹；不要从同一个未验证连接获取预期指纹',
    '先在对端使用控制台轮换审查添加新指纹，保持旧指纹；重启对端并确认策略与账本保留',
    '在此节点停机后，由所有者安全替换已签发的证书和对应私钥；检查权限，再重启',
    '核验双向 TLS、预期节点 ID、新指纹及获准工具执行；保留可回滚的旧证书材料',
    '确认所有对端切换成功后，通过控制台移除旧指纹并检查旧证书被拒绝',
    '按组织保留策略由所有者处理旧私钥；本工具不会生成、传输或删除私钥'
  ] };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, ...args] = process.argv.slice(2);
  try {
    if (command === 'inspect' && args.length === 1) console.log(JSON.stringify(await inspectCertificate(args[0]), null, 2));
    else if (command === 'rotation-plan' && args.length >= 3 && args.length <= 4) console.log(JSON.stringify(await rotationPlan({ oldCertificate: args[0], newCertificate: args[1], expectedFingerprint: args[2], caCertificate: args[3] }), null, 2));
    else throw new Error('Usage: identity-lifecycle.mjs inspect <certificate.pem> | rotation-plan <old.pem> <new.pem> <independently-verified-new-pin> [ca.pem]');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
