import fs from 'node:fs/promises';

/**
 * Explicit, reproducible dependency-resolution repair; no install lifecycle hook.
 * Pi 0.99.2 ships a nested shrinkwrap fixing brace-expansion at vulnerable 5.0.9.
 * npm 11.9 ignores both overrides and a changed nested root-lock entry while the
 * Pi entry is marked hasShrinkwrap. Keep Pi's original tarball/integrity, remove
 * that marker so OUR complete lock governs npm ci, and select the compatible
 * official 5.0.12 tarball. No upstream source/package archive is modified.
 * If upstream changes, fail for review rather than silently choosing new versions.
 */
const lockPath = new URL('../../package-lock.json', import.meta.url);
const lock = JSON.parse(await fs.readFile(lockPath, 'utf8'));
const parent = 'node_modules/@earendil-works/pi-coding-agent';
const child = `${parent}/node_modules/brace-expansion`;
if (lock.packages[parent]?.version !== '0.99.2' || !['5.0.9', '5.0.12'].includes(lock.packages[child]?.version)) {
  throw new Error('Unexpected dependency versions. Review upstream before applying the compatibility patch.');
}
delete lock.packages[parent].hasShrinkwrap;
lock.packages[child] = {
  version: '5.0.12',
  resolved: 'https://registry.npmjs.org/brace-expansion/-/brace-expansion-5.0.12.tgz',
  integrity: 'sha512-YovQ3rzhaLMIrDjNDMkNS01tea93qhEhG5xy8f6+R0l+dw3Ki+5sCoIoI942iuLZTHWogWktgwVDhU09iNEimQ==',
  license: 'MIT', dependencies: { 'balanced-match': '^4.0.2' }, engines: { node: '20 || >=22' },
};
await fs.writeFile(lockPath, JSON.stringify(lock, null, 2) + '\n');
console.log('Root lock hardened: genuine Pi 0.99.2 with official brace-expansion 5.0.12; run npm ci --ignore-scripts');
