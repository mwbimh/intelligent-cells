import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace,startNode,peer,waitConnected,stopAll } from '../scripts/process-helper.mjs';
import { connectOperator } from '../scripts/operator.mjs';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));

test('v0.3 independent real owner HTTP audit: cancel incoming task/job, inspect output and reconcile without remote admin authority', {timeout:20000},async t=>{
 const dir=await makeWorkspace('audit-v03-owner-actions-'),nodes=[];let client;
 try{
  const script=path.join(dir,'trusted-wait.mjs');await fs.writeFile(script,"console.log('owner-job-ready');setInterval(()=>{},1000);\n");
  const policy={grants:{master:{tools:['wait','exec'],workspace:'workspace',maxTimeoutMs:5000,maxWaitMs:5000,maxJobTimeoutMs:10000,execCommands:{waiting:{file:process.execPath,args:[script]}}}}};
  const servant=await startNode(dir,{id:'servant',port:0,operator:{enabled:true,port:0},policy});nodes.push(servant);
  const ready=await servant.wait(event=>event.event==='operator_ready');assert.ok(ready.ownerFile);
  client=await connectOperator(ready.ownerFile,{sessionFile:true});
  const master=await startNode(dir,{id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{}});nodes.push(master);await waitConnected(master,'servant');
  await t.test('servant owner stops a running incoming read-only task',async()=>{
   const pending=master.command({command:'dispatch',peerId:'servant',task:{taskId:'owner_cancel_wait',tool:'wait',args:{ms:4000},timeoutMs:5000}});
   await servant.wait(event=>event.event==='task_started'&&event.taskId==='owner_cancel_wait');
   assert.equal((await client.request('/api/command',{command:'cancelTask',masterId:'master',taskId:'owner_cancel_wait'})).result.requested,true);
   assert.equal((await pending).result.error.code,'CANCELLED');
  });
  await t.test('owner reads background output, cancels actual process and records explicit effects inspection',async()=>{
   const started=await master.command({command:'dispatch',peerId:'servant',task:{taskId:'owner_background',tool:'exec',args:{command:'waiting',args:[],background:true},timeoutMs:5000}});assert.equal(started.result.status,'ok');
   const jobId=started.result.result.jobId;assert.ok(jobId);
   let output;for(let i=0;i<100;i++){output=(await client.request('/api/command',{command:'jobOutput',masterId:'master',jobId})).result;if(output.text.includes('owner-job-ready'))break;await pause(10);}assert.match(output.text,/owner-job-ready/);
   assert.equal((await client.request('/api/command',{command:'jobCancel',masterId:'master',jobId})).result.accepted,true);
   const status=(await client.request('/api/command',{command:'jobStatus',masterId:'master',jobId})).result;assert.equal(status.state,'cancelled');assert.equal(status.outcomeUnknown,true);
   const reconciled=(await client.request('/api/command',{command:'reconcileJob',masterId:'master',jobId,resolution:'completed',note:'Inspected trusted fixture, output only, confirmed cancelled process ended'})).result;assert.equal(reconciled.state,'reconciled');assert.equal(reconciled.outcomeUnknown,false);
  });
  await t.test('stale owner policy epoch cannot overwrite a newer permission change',async()=>{
   const epoch=(await client.request('/api/state')).permissions.epoch;
   assert.equal((await client.request('/api/command',{command:'setPolicy',policy,expectedEpoch:epoch})).result.epoch,epoch+1);
   await assert.rejects(client.request('/api/command',{command:'setPolicy',policy,expectedEpoch:epoch}),/POLICY_CONFLICT/);
   assert.equal((await client.request('/api/state')).permissions.epoch,epoch+1);
  });
 }finally{await client?.request('/api/logout',{}).catch(()=>{});await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});
