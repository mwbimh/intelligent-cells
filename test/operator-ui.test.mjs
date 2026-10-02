import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, testSecurity } from '../scripts/process-helper.mjs';
import { createTestIdentity } from '../scripts/test-identities.mjs';
import { loadConfig } from '../src/config.mjs';
import { IntelligentCell } from '../src/node.mjs';
import { startOperator } from '../src/operator.mjs';
import { reviewIdentity, applyPairing, removePairingPin, revokePairing } from '../src/operator-identity.mjs';
import { AuditLog } from '../src/operator-audit.mjs';
import { fileOwnerSession, connectOperator } from '../scripts/operator.mjs';
import { inspectCertificate, rotationPlan } from '../scripts/identity-lifecycle.mjs';
import { servicePlan } from '../scripts/service-plan.mjs';
import { inspectRunningService } from '../scripts/service-acceptance.mjs';
let dir, node, operator, raw;
before(async () => {
  dir = await makeWorkspace('operator-test-');
  raw = { id:'owner-test',host:'127.0.0.1',port:0,stateDir:path.join(dir,'state'),logFile:path.join(dir,'audit.jsonl'),security:await testSecurity(dir,'owner-test',['peer-test']),policy:{grants:{'peer-test':{tools:['echo'],maxConcurrent:1}}} };
  await fs.writeFile(path.join(dir,'config.json'),JSON.stringify(raw));
  node = new IntelligentCell(await loadConfig(path.join(dir,'config.json'))); await node.start();
  operator = await startOperator(node,{port:0,sessionDirectory:path.join(dir,'owner-access')});
});
after(async () => { await operator?.close(); await node?.shutdown(); await fs.rm(dir,{recursive:true,force:true}); });
async function request(route, value, headers = {}) { const response = await fetch(operator.url+route,{...(value?{method:'POST',body:JSON.stringify(value)}:{}),headers:{...(value?{Origin:operator.url,'Content-Type':'application/json'}:{}),...headers}}); return {status:response.status,data:await response.json(),cookie:response.headers.get('set-cookie')?.split(';')[0]}; }
test('owner bootstrap is single-use; Host, Origin, session and CSRF fail closed',async()=>{
  assert.equal((await request('/api/state')).status,403);
  assert.equal((await request('/api/state',null,{Host:'attacker.invalid'})).status,403);
  assert.equal((await request('/api/session',{token:operator.bootstrapToken},{Origin:'https://attacker.invalid'})).status,403);
  const login=await request('/api/session',{token:operator.bootstrapToken}); assert.equal(login.status,200); assert.ok(login.cookie); assert.ok(login.data.csrf);
  assert.equal((await request('/api/session',{token:operator.bootstrapToken})).status,403);
  assert.equal((await request('/api/command',{command:'revoke',masterId:'peer-test'},{Cookie:login.cookie})).status,403);
  assert.equal((await request('/api/command',{command:'status'},{Cookie:login.cookie,'X-Operator-CSRF':login.data.csrf,'Sec-Fetch-Site':'cross-site'})).status,403);
  const state=await request('/api/state',null,{Cookie:login.cookie}); assert.equal(state.status,200); assert.equal(state.data.status.id,'owner-test'); assert.ok(state.data.jobs);
  assert.equal((await request('/api/command',{command:'dispatch'},{Cookie:login.cookie,'X-Operator-CSRF':login.data.csrf})).status,400);
  assert.equal((await request('/api/command',{command:'setPolicy',policy:{grants:{}}},{Cookie:login.cookie,'X-Operator-CSRF':login.data.csrf})).data.error.code,'POLICY_CONFLICT');
  await request('/api/logout',{}, {Cookie:login.cookie,'X-Operator-CSRF':login.data.csrf});
  assert.equal((await request('/api/state',null,{Cookie:login.cookie})).status,403);
});
test('owner-file fallback stays private, issues fresh one-use sessions and is removed on shutdown',async()=>{
  const s=await fs.stat(operator.ownerFile); assert.equal(s.mode&0o077,0);
  const session=await fileOwnerSession(operator.ownerFile); assert.ok(session.url.startsWith(operator.url+'/#token='));
  const client=await connectOperator(operator.ownerFile,{sessionFile:true}); assert.equal((await client.request('/api/state')).status.id,'owner-test'); await client.request('/api/logout',{});
  const report=await inspectRunningService(operator.ownerFile,{sessionFile:true}); assert.equal(report.passed,true); assert.equal(report.productionVerified,false); assert.ok(report.checks.some(check=>check.name==='real-windows-host'&&check.status==='not_run'));
  const other=await startOperator(node,{sessionDirectory:path.join(dir,'second-owner')}); const filename=other.ownerFile; await other.close(); await assert.rejects(fs.stat(filename),{code:'ENOENT'});
});
test('operator rejects externally bound HTTP and unsafe owner directories',async()=>{
  await assert.rejects(startOperator(node,{host:'0.0.0.0'}),{code:'OPERATOR_LOOPBACK_ONLY'});
  const unsafe=path.join(dir,'unsafe-owner'); await fs.mkdir(unsafe,{mode:0o755});
  await assert.rejects(startOperator(node,{sessionDirectory:unsafe}),{code:'UNSAFE_OWNER_DIRECTORY'});
});
test('Chinese UI serves with strict CSP and no embedded owner capability',async()=>{
  const response=await fetch(operator.url); const html=await response.text(); assert.match(html,/本机控制台/); assert.match(html,/人工核对/); assert.match(html,/后台作业/); assert.ok(!html.includes(operator.bootstrapToken)); assert.match(response.headers.get('content-security-policy'),/frame-ancestors 'none'/); assert.equal(response.headers.get('cache-control'),'no-store');
  const script=await (await fetch(operator.url+'/app.js')).text(); assert.match(script,/history.replaceState/); assert.ok(!/localStorage|sessionStorage|innerHTML/.test(script));
});
test('certificate review requires independent matching pin, current validity and configured CA',async()=>{
  const identity=await createTestIdentity(dir,'new-peer'); const pem=await fs.readFile(identity.cert,'utf8');
  assert.throws(()=>reviewIdentity(pem,'new-peer','A'.repeat(64),node.config.security.ca),{code:'PIN_MISMATCH'});
  assert.throws(()=>reviewIdentity(pem,'other-peer',identity.fingerprint256,node.config.security.ca),{code:'IDENTITY_MISMATCH'});
  assert.equal(reviewIdentity(pem,'new-peer',identity.fingerprint256,node.config.security.ca).nodeId,'new-peer');
  const expired=await createTestIdentity(dir,'expired-peer',{expired:true}); assert.throws(()=>reviewIdentity(fsSyncRead(expired.cert,"utf8"),'expired-peer',expired.fingerprint256,node.config.security.ca),{code:'CERTIFICATE_EXPIRED'});
  const unrelated=await makeWorkspace('operator-other-ca-'); try { const bad=await createTestIdentity(unrelated,'new-peer'); assert.throws(()=>reviewIdentity(fsSyncRead(bad.cert,"utf8"),'new-peer',bad.fingerprint256,node.config.security.ca),{code:'UNTRUSTED_CA'}); } finally { await fs.rm(unrelated,{recursive:true,force:true}); }
});
import { readFileSync as fsSyncRead } from 'node:fs';
test('pairing persists pin without a live grant; rotation narrows active trust, never expands it early',async()=>{
  const identity=await createTestIdentity(dir,'new-peer'); const certificatePem=await fs.readFile(identity.cert,'utf8');
  await assert.rejects(applyPairing(node,{peerId:'new-peer',certificatePem,expectedFingerprint:identity.fingerprint256}),{code:'PIN_REVIEW_REQUIRED'});
  const result=await applyPairing(node,{peerId:'new-peer',certificatePem,expectedFingerprint:identity.fingerprint256,outOfBandVerified:true});
  assert.equal(result.restartRequired,true); assert.equal(result.grantsAdded,false); assert.ok(!node.config.security.trustedPeers.has('new-peer')); assert.ok(!node.config.policy.grants.has('new-peer'));
  const old=await createTestIdentity(dir,'peer-test'), next=await createTestIdentity(dir,'peer-test',{suffix:'rotation'});
  await applyPairing(node,{peerId:'peer-test',certificatePem:await fs.readFile(next.cert,'utf8'),expectedFingerprint:next.fingerprint256,outOfBandVerified:true,rotation:true});
  assert.ok(node.config.security.trustedPeers.get('peer-test').has(old.fingerprint256)); assert.ok(!node.config.security.trustedPeers.get('peer-test').has(next.fingerprint256));
  await removePairingPin(node,{peerId:'peer-test',fingerprint:old.fingerprint256}); assert.ok(!node.config.security.trustedPeers.has('peer-test'));
  const persisted=JSON.parse(await fs.readFile(node.config.filename,'utf8')); assert.deepEqual(persisted.security.trustedPeers['peer-test'],[next.fingerprint256]);
  const plan=await rotationPlan({oldCertificate:old.cert,newCertificate:next.cert,expectedFingerprint:next.fingerprint256,caCertificate:path.join(dir,'identities','ca.pem')}); assert.equal(plan.changed,false); assert.equal(plan.overlapPins.length,2);
  assert.equal((await inspectCertificate(next.cert)).privateKeyRead,false);
});
test('peer revoke removes persisted trust and grants and stays denied',async()=>{
  const result=await revokePairing(node,{peerId:'peer-test'}); assert.equal(result.persisted,true); assert.ok(!node.config.security.trustedPeers.has('peer-test')); assert.ok(!node.config.policy.grants.has('peer-test'));
  const persisted=JSON.parse(await fs.readFile(node.config.filename,'utf8')); assert.ok(!persisted.security.trustedPeers['peer-test']); assert.ok(!persisted.policy.grants['peer-test']);
});
test('audit redacts payloads and rotates within configured retained bounds',async()=>{
  const logDir=path.join(dir,'rotation'); await fs.mkdir(logDir,{mode:0o700}); const filename=path.join(logDir,'audit.jsonl'); const audit=new AuditLog({filename,maxBytes:1024,retention:2});
  for(let i=0;i<60;i++) audit.append({timestamp:new Date().toISOString(),event:'task_finished',taskId:'task-'+i,result:'SECRET_RESULT',args:{password:'SECRET_PASSWORD'},prompt:'SECRET_PROMPT',error:{code:'SAFE_CODE',message:'SECRET_ERROR'},token:'SECRET_TOKEN'});
  const files=await fs.readdir(logDir); assert.ok(files.length<=3); let all=''; for(const file of files) all+=await fs.readFile(path.join(logDir,file),'utf8'); assert.ok(!all.includes('SECRET')); assert.match(all,/SAFE_CODE/);
  const query=audit.query({limit:5,event:'task_finished'}); assert.equal(query.records.length,5); assert.equal(query.records[0].taskId,'task-59'); assert.ok(query.payloadRedacted);
});
test('service plans never register or install and reject privileged/invalid plans',()=>{
  const linux=servicePlan({platform:'linux',project:'/opt/intelligent-cells',config:'/etc/intelligent-cells/node.json',stateDir:'/var/lib/intelligent-cells',node:'/usr/bin/node',user:'intelligentcells'}); assert.equal(linux.dryRun,true); assert.equal(linux.registered,false); assert.match(linux.contents,/--daemon/); assert.match(linux.contents,/NoNewPrivileges=yes/); assert.ok(!linux.contents.includes('#token='));
  assert.throws(()=>servicePlan({platform:'linux',project:'/opt/app',config:'/etc/app.json',stateDir:'/var/lib/app',user:'root'}));
  const windows=servicePlan({platform:'windows',project:'C:\\IntelligentCells',config:'C:\\IntelligentCells\\node.json',stateDir:'C:\\IntelligentCells\\state',node:'C:\\Program Files\\nodejs\\node.exe',user:'DESKTOP\\nodeowner'}); assert.match(windows.contents,/InteractiveToken/); assert.match(windows.contents,/LeastPrivilege/); assert.equal(windows.installed,false); assert.match(windows.note,/不是 Windows 服务/);
});
