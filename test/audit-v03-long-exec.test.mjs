import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, startNode, peer, waitConnected, stopAll } from '../scripts/process-helper.mjs';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));

test('v0.3 independent long exec audit: real encrypted foreground process runs beyond30 seconds and streams before final', {timeout:60000},async()=>{
 const dir=await makeWorkspace('audit-v03-real-long-'),nodes=[];
 try{
  const script=path.join(dir,'trusted-long.mjs');await fs.writeFile(script,"console.log('actual-long-start');setTimeout(()=>console.log('actual-long-end'),31000);\n");
  const servant=await startNode(dir,{id:'servant',port:0,policy:{grants:{master:{tools:['exec'],workspace:'workspace',maxTimeoutMs:40000,maxJobTimeoutMs:40000,execCommands:{long:{file:process.execPath,args:[script]}}}}}});nodes.push(servant);
  const master=await startNode(dir,{id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{}});nodes.push(master);await waitConnected(master,'servant');
  const started=Date.now(),requestId='audit_actual_long';let finished=false;
  const result=master.wait(event=>event.event==='command_result'&&event.requestId===requestId,50000).then(value=>{finished=true;return value;});
  master.child.stdin.write(JSON.stringify({requestId,command:'dispatch',peerId:'servant',task:{taskId:'long_real',tool:'exec',args:{command:'long',args:[]},timeoutMs:40000}})+'\n');
  let observed;for(let i=0;i<100;i++){const record=(await master.command({command:'operationStatus',peerId:'servant',taskId:'long_real'})).result;if(record.events?.some(event=>event.text?.includes('actual-long-start'))){observed=record;break;}await pause(20);}
  assert.ok(observed,'Start output must arrive over encrypted connection before process exits');assert.equal(finished,false);assert.ok(Date.now()-started<10000);
  const response=await result;assert.equal(response.ok,true,JSON.stringify(response));assert.equal(response.result.status,'ok');
  assert.ok(Date.now()-started>=30000,'Real elapsed time, not a mocked timer');assert.match(response.result.result.stdout,/actual-long-start[\s\S]*actual-long-end/);assert.equal(response.result.result.exitCode,0);
  assert.equal((await servant.command({command:'status'})).result.active,0);
 }finally{await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});
