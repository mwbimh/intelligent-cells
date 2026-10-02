import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import syncFs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { DurableStore, readChecked } from '../src/durable.mjs';
import { IntelligentCell } from '../src/node.mjs';
import { loadConfig } from '../src/config.mjs';
import { makeWorkspace, startNode, peer, waitConnected, stopAll, testSecurity } from '../scripts/process-helper.mjs';

const task = (taskId, tool, args) => ({taskId, tool, args, timeoutMs: 4000});
async function pair(prefix) {
  const dir = await makeWorkspace(prefix), nodes = [];
  const script = path.join(dir, 'approved-signal.mjs');
  await fs.writeFile(script, "console.log('approved harmless fixture');process.kill(process.pid,'SIGTERM');\n");
  const policy = {grants:{master:{tools:['exec','writeFile','jobStatus','jobOutput','jobStdin','jobCancel','echo'],workspace:'workspace',maxTimeoutMs:4000,execCommands:{signal:{file:process.execPath,args:[script]}}}}};
  const first = await startNode(dir,{id:'servant-a',port:0,policy}); nodes.push(first);
  const second = await startNode(dir,{id:'servant-b',port:0,policy:{grants:{master:{tools:['writeFile','echo'],workspace:'workspace'}}}}); nodes.push(second);
  const masterConfig = {id:'master',port:0,agent:'deterministic-demo',peers:[peer(first),peer(second)],policy:{}};
  const master = await startNode(dir,masterConfig); nodes.push(master);
  await Promise.all([waitConnected(master,first.id),waitConnected(master,second.id)]);
  return {dir,nodes,first,second,master,masterConfig,policy};
}
async function resolveSource(first, master, taskId, jobId) {
  const note = 'Inspected the approved output-only fixture and confirmed its process ended';
  assert.equal((await first.command({command:'reconcileJob',masterId:'master',jobId,resolution:'completed',note})).ok,true);
  assert.equal((await first.command({command:'reconcile',masterId:'master',taskId,resolution:'completed',note})).ok,true);
  assert.equal((await master.command({command:'query',peerId:first.id,taskId})).result.state,'reconciled');
}

test('v0.3.1 foreground signal preserves effect uncertainty and source owner reconciliation releases cross-peer quarantine', {timeout:20000}, async () => {
  const f = await pair('v031-foreground-');
  try {
    const result = await f.master.command({command:'dispatch',peerId:f.first.id,task:task('signal_origin','exec',{command:'signal',args:[]})});
    assert.equal(result.result.status,'ok');
    assert.equal(result.result.result.signal,'SIGTERM');
    assert.equal(result.result.result.outcomeUnknown,true);
    assert.equal(result.result.outcomeUnknown,true);
    assert.equal((await f.first.command({command:'taskStatus',masterId:'master',taskId:'signal_origin'})).result.state,'unknown');
    assert.equal((await f.master.command({command:'status'})).result.unknownOutgoing,1);
    const write = task('other_peer','writeFile',{path:'after-signal.txt',text:'owner inspected'});
    assert.equal((await f.master.command({command:'dispatch',peerId:f.second.id,task:write})).error.code,'UNCERTAIN_SIDE_EFFECT');
    await resolveSource(f.first,f.master,'signal_origin',result.result.result.jobId);
    assert.equal((await f.master.command({command:'dispatch',peerId:f.second.id,task:write})).result.status,'ok');
  } finally {await stopAll(f.nodes);await fs.rm(f.dir,{recursive:true,force:true});}
});

test('v0.3.1 uncertainty admission denial quarantines a clean observer and source query releases only correlated records', {timeout:20000}, async () => {
  const f = await pair('v031-denial-');
  try {
    const result = await f.master.command({command:'dispatch',peerId:f.first.id,task:task('deny_source','exec',{command:'signal',args:[]})});
    await f.master.stop();
    const observer = await startNode(f.dir,{...f.masterConfig,stateDir:'fresh-observer'}); f.nodes.push(observer);
    await Promise.all([waitConnected(observer,f.first.id),waitConnected(observer,f.second.id)]);
    const denial = await observer.command({command:'dispatch',peerId:f.first.id,task:task('denied_write','writeFile',{path:'never-written.txt',text:'blocked'})});
    assert.equal(denial.result.error.code,'UNCERTAIN_SIDE_EFFECT');
    assert.equal(denial.result.outcomeUnknown,true);
    assert.equal(denial.result.uncertainty.taskId,'deny_source');
    assert.equal((await observer.command({command:'operationStatus',peerId:f.first.id,taskId:'denied_write'})).result.state,'unknown');
    assert.equal((await observer.command({command:'dispatch',peerId:f.second.id,task:task('blocked_elsewhere','writeFile',{path:'never-written2.txt',text:'blocked'})})).error.code,'UNCERTAIN_SIDE_EFFECT');
    await assert.rejects(fs.stat(path.join(f.dir,'workspace','never-written.txt')),{code:'ENOENT'});
    await resolveSource(f.first,observer,'deny_source',result.result.result.jobId);
    assert.equal((await observer.command({command:'operationStatus',peerId:f.first.id,taskId:'denied_write'})).result.state,'reconciled');
    assert.equal((await observer.command({command:'dispatch',peerId:f.second.id,task:task('allowed_after_inspection','writeFile',{path:'allowed.txt',text:'confirmed'})})).result.status,'ok');
  } finally {await stopAll(f.nodes);await fs.rm(f.dir,{recursive:true,force:true});}
});

test('v0.3.1 completed job output and controls stay behind their creation policy epoch while local owner retains access', {timeout:15000}, async () => {
  const f = await pair('v031-job-epoch-');
  try {
    const result = await f.master.command({command:'dispatch',peerId:f.first.id,task:task('old_epoch','exec',{command:'signal',args:[]})});
    const jobId = result.result.result.jobId;
    await resolveSource(f.first,f.master,'old_epoch',jobId);
    assert.equal((await f.first.command({command:'setPolicy',policy:f.policy})).ok,true);
    for (const tool of ['jobStatus','jobOutput','jobStdin','jobCancel']) {
      const response = await f.master.command({command:'dispatch',peerId:f.first.id,task:task(`old_${tool}`,tool,{jobId,...(tool==='jobStdin'?{text:'blocked'}:{})})});
      assert.equal(response.result.error.code,'TASK_POLICY_CHANGED',JSON.stringify(response));
      assert.equal(response.result.outcomeUnknown,undefined);
    }
    assert.equal((await f.first.command({command:'jobStatus',masterId:'master',jobId})).result.state,'reconciled');
    assert.match((await f.first.command({command:'jobOutput',masterId:'master',jobId})).result.text,/approved harmless fixture/);
  } finally {await stopAll(f.nodes);await fs.rm(f.dir,{recursive:true,force:true});}
});

test('v0.3.1 1 MiB live TLS journals compact growing 64 KiB results and remain usable after both processes restart', {timeout:20000}, async () => {
  const dir=await makeWorkspace('v031-large-results-'),nodes=[];
  try {
    await fs.writeFile(path.join(dir,'workspace','large.txt'),'x'.repeat(65536));
    const servantConfig={id:'servant',port:0,policy:{maxJournalBytes:1048576,grants:{master:{tools:['readFile'],workspace:'workspace',maxReadBytes:65536,maxTasksPerMinute:1000}}}};
    let servant=await startNode(dir,servantConfig);nodes.push(servant);
    const masterConfig={id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{maxJournalBytes:1048576}};
    let master=await startNode(dir,masterConfig);nodes.push(master);await waitConnected(master,servant.id);
    for(let i=0;i<20;i++) {
      const response=await master.command({command:'dispatch',peerId:servant.id,task:task(`read_${i}`,'readFile',{path:'large.txt'})});
      assert.equal(response.result.status,'ok',JSON.stringify(response));assert.equal(response.result.result.bytes,65536);
    }
    for(const node of [master,servant]) {const s=(await node.command({command:'status'})).result;assert.equal(s.storageFailed,false);assert.ok((node===master?s.outgoing:s.incoming).retiredCount>0);}
    const port=servant.port;await master.stop();await servant.stop();
    servant=await startNode(dir,{...servantConfig,port});nodes.push(servant);
    master=await startNode(dir,masterConfig);nodes.push(master);await waitConnected(master,servant.id);
    assert.equal((await master.command({command:'dispatch',peerId:servant.id,task:task('read_0','readFile',{path:'large.txt'})})).error.code,'TASK_HISTORY_EXPIRED');
    assert.equal((await master.command({command:'dispatch',peerId:servant.id,task:task('after_restart','readFile',{path:'large.txt'})})).result.status,'ok');
  } finally {await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});

test('v0.3.1 capacity refusal preserves an active record without declaring I/O failure; actual journal I/O failure fails closed', async () => {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'v031-store-failure-'));
  try {
    const store=new DurableStore({directory:dir,maxRecords:4,maxBytes:500}).open();
    store.put('peer:unknown',{state:'unknown',payload:'a'.repeat(200)});
    store.put('peer:active',{state:'running'});
    assert.throws(()=>store.put('peer:active',{state:'completed',payload:'b'.repeat(400)}),{code:'TASK_STORE_FULL'});
    assert.equal(store.get('peer:active').state,'running');assert.equal(store.failed,false);assert.equal(store.retiredCount,0);
    const rename=syncFs.renameSync;
    try {syncFs.renameSync=()=>{const e=new Error('Injected journal I/O failure');e.code='EIO';throw e;};assert.throws(()=>store.put('peer:active',{state:'completed'}),{code:'EIO'});}
    finally {syncFs.renameSync=rename;}
    assert.equal(store.failed,true);assert.throws(()=>store.put('peer:new',{state:'running'}),{code:'JOURNAL_UNAVAILABLE'});
    assert.equal(new DurableStore({directory:dir,maxRecords:4,maxBytes:500}).open().get('peer:active').state,'running');
  } finally {await fs.rm(dir,{recursive:true,force:true});}
});

test('v0.3.1 second-store preflight and control-write failures cannot partially commit new journal limits', async () => {
  const dir=await makeWorkspace('v031-policy-failure-');let node;
  try {
    const filename=path.join(dir,'local.json'),security=await testSecurity(dir,'servant',['master']);
    await fs.writeFile(filename,JSON.stringify({id:'servant',port:0,security,policy:{maxTaskRecords:4}}));
    node=new IntelligentCell(await loadConfig(filename));await node.start();
    node.ledger.put('peer:a',{state:'completed'});node.ledger.put('peer:b',{state:'completed'});
    const initial=readChecked(node.controlPath);
    await assert.rejects(node.setPolicy({maxTaskRecords:1}),{code:'JOURNAL_CAPACITY'});
    assert.equal(node.journal.maxRecords,4);assert.equal(node.ledger.maxRecords,4);assert.deepEqual(readChecked(node.controlPath),initial);
    const rename=syncFs.renameSync;
    try {syncFs.renameSync=(source,target)=>{if(target===node.controlPath){const e=new Error('Injected control I/O failure');e.code='EIO';throw e;}return rename(source,target);};await assert.rejects(node.setPolicy({maxTaskRecords:3}),{code:'EIO'});}
    finally {syncFs.renameSync=rename;}
    assert.equal(node.journal.maxRecords,4);assert.equal(node.ledger.maxRecords,4);assert.equal(node.config.policy.maxTaskRecords,4);assert.equal(node.policyEpoch,0);assert.deepEqual(readChecked(node.controlPath),initial);
    assert.equal(node.storageFailed,true);
  } finally {await node?.shutdown();await fs.rm(dir,{recursive:true,force:true});}
});

test('v0.3.1 startup upgrades retained v0.3 launch and nested uncertainty records without discarding consumed IDs', async () => {
  const dir=await makeWorkspace('v031-legacy-');let node;
  try {
    const filename=path.join(dir,'local.json'),security=await testSecurity(dir,'master',['servant']);
    await fs.writeFile(filename,JSON.stringify({id:'master',port:0,security,agent:'deterministic-demo',policy:{}}));
    const config=await loadConfig(filename),store=new DurableStore({directory:path.join(config.stateDir,'outgoing')}).open();
    store.put('servant:legacy_background',{peerId:'servant',taskId:'legacy_background',tool:'exec',sideEffect:true,state:'completed',response:{status:'ok',result:{jobId:'job_background',background:true,state:'running'}}});
    store.put('servant:legacy_signal',{peerId:'servant',taskId:'legacy_signal',tool:'exec',sideEffect:true,state:'completed',response:{status:'ok',result:{jobId:'job_signal',state:'failed',signal:'SIGTERM'}}});
    store.put('servant:legacy_status',{peerId:'servant',taskId:'legacy_status',tool:'jobStatus',sideEffect:false,state:'completed',response:{status:'ok',result:{jobId:'job_status',state:'timed_out',outcomeUnknown:true}}});
    node=new IntelligentCell(config);await node.start();
    assert.equal((await node.command({command:'status'})).unknownOutgoing,3);
    assert.throws(()=>node.assertUncertainGate(node.ledger),{code:'UNCERTAIN_SIDE_EFFECT'});
    for(const id of ['legacy_background','legacy_signal','legacy_status']) {const record=await node.command({command:'operationStatus',peerId:'servant',taskId:id});assert.equal(record.state,'unknown');assert.equal(record.response.outcomeUnknown,true);}
    assert.equal(node.ledger.retiredCount,0);
    node.ledger.put('observation:servant:retired_query',{peerId:'servant',taskId:'retired_query',state:'reconciled',observationOnly:true,updatedAt:0});
    node.ledger.configure({maxRecords:4,maxBytes:node.ledger.maxBytes});
    node.ledger.put('servant:new_terminal',{state:'completed',updatedAt:Date.now()});
    assert.equal((await node.command({command:'operationStatus',peerId:'servant',taskId:'retired_query'})).state,'expired');
  } finally {await node?.shutdown();await fs.rm(dir,{recursive:true,force:true});}
});

test('v0.3.1 a clean master source query alone learns durable cross-peer uncertainty', {timeout:20000}, async () => {
  const f=await pair('v031-query-only-');
  try {
    const launched=await f.master.command({command:'dispatch',peerId:f.first.id,task:task('query_origin','exec',{command:'signal',args:[]})});
    await f.master.stop();
    const observerConfig={...f.masterConfig,stateDir:'query-observer'};
    let observer=await startNode(f.dir,observerConfig);f.nodes.push(observer);
    await Promise.all([waitConnected(observer,f.first.id),waitConnected(observer,f.second.id)]);
    assert.equal((await observer.command({command:'query',peerId:f.first.id,taskId:'query_origin'})).result.state,'unknown');
    assert.equal((await observer.command({command:'operationStatus',peerId:f.first.id,taskId:'query_origin'})).result.state,'unknown');
    assert.equal((await observer.command({command:'dispatch',peerId:f.first.id,task:task('query_origin','exec',{command:'signal',args:[]})})).error.code,'OUTCOME_UNKNOWN');
    await observer.stop();observer=await startNode(f.dir,observerConfig);f.nodes.push(observer);
    await Promise.all([waitConnected(observer,f.first.id),waitConnected(observer,f.second.id)]);
    const next=task('query_block','writeFile',{path:'query-block.txt',text:'after owner inspection'});
    assert.equal((await observer.command({command:'dispatch',peerId:f.second.id,task:next})).error.code,'UNCERTAIN_SIDE_EFFECT');
    await resolveSource(f.first,observer,'query_origin',launched.result.result.jobId);
    assert.equal((await observer.command({command:'dispatch',peerId:f.second.id,task:next})).result.status,'ok');
  } finally {await stopAll(f.nodes);await fs.rm(f.dir,{recursive:true,force:true});}
});
