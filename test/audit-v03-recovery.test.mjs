import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import tls from 'node:tls';
import { EventEmitter } from 'node:events';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { makeWorkspace, startNode, peer, waitConnected, stopAll, testTlsOptions, testSecurity } from '../scripts/process-helper.mjs';

const task=(taskId,tool,args,runId='original_run')=>({taskId,tool,args,runId,timeoutMs:5000});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(check,timeout=4000){const end=Date.now()+timeout;while(Date.now()<end){const value=await check();if(value)return value;await pause(10);}throw new Error('Audit observation timed out');}
async function rawClient(dir,port){
 const socket=tls.connect({...await testTlsOptions(dir,'master'),host:'127.0.0.1',port}),messages=[],bus=new EventEmitter();let buffer='';socket.setEncoding('utf8');socket.on('error',()=>{});
 socket.on('data',data=>{buffer+=data;while(buffer.includes('\n')){const i=buffer.indexOf('\n'),message=JSON.parse(buffer.slice(0,i));buffer=buffer.slice(i+1);messages.push(message);bus.emit('message',message);}});
 await new Promise((resolve,reject)=>{socket.once('secureConnect',resolve);socket.once('error',reject);});
 const wait=(predicate,after=0)=>{const found=messages.slice(after).find(predicate);if(found)return Promise.resolve(found);return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{bus.off('message',listener);reject(new Error('Audit wire timeout'));},4000);const listener=message=>{if(predicate(message)){clearTimeout(timer);bus.off('message',listener);resolve(message);}};bus.on('message',listener);});};
 const send=message=>socket.write(JSON.stringify({v:2,...message})+'\n');send({type:'hello',nodeId:'master'});return{socket,messages,wait,send};
}
async function kill(node){node.child.kill('SIGKILL');assert.equal((await node.exit).signal,'SIGKILL');}

test('v0.3 independent actual restart audit: completed write is deduplicated and revocation persists despite original config', {timeout:20000},async()=>{
 const dir=await makeWorkspace('audit-v03-restart-'),nodes=[];let raw;
 try{
  const config={id:'servant',port:0,policy:{grants:{master:{tools:['writeFile','readFile','echo'],workspace:'workspace',maxTimeoutMs:5000}}}};
  let servant=await startNode(dir,config);nodes.push(servant);
  const master=await startNode(dir,{id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{}});nodes.push(master);await waitConnected(master,'servant');
  const value=task('durable_write','writeFile',{path:'persist.txt',text:'FIRST',overwrite:true});
  assert.equal((await master.command({command:'dispatch',peerId:'servant',task:value})).result.status,'ok');
  await fs.writeFile(path.join(dir,'workspace','persist.txt'),'LOCAL_LATER_EDIT');
  const port=servant.port;await kill(servant);const after=master.events.length;
  servant=await startNode(dir,{...config,port});nodes.push(servant);await waitConnected(master,'servant',after);
  assert.equal((await master.command({command:'dispatch',peerId:'servant',task:value})).result.status,'ok');
  assert.equal(await fs.readFile(path.join(dir,'workspace','persist.txt'),'utf8'),'LOCAL_LATER_EDIT');
  assert.equal(servant.events.filter(event=>event.event==='task_started'&&event.taskId===value.taskId).length,0);
  assert.equal((await servant.command({command:'revoke',masterId:'master'})).ok,true);
  assert.equal((await master.command({command:'query',peerId:'servant',taskId:value.taskId})).error.code,'MASTER_DENIED');
  await kill(servant);servant=await startNode(dir,{...config,port});nodes.push(servant);
  raw=await rawClient(dir,port);assert.equal((await raw.wait(message=>message.type==='error')).error.code,'MASTER_DENIED');raw.socket.destroy();
  assert.ok((await servant.command({command:'permissions'})).result.revoked.includes('master'));
  assert.equal((await servant.command({command:'reloadPolicy'})).ok,true);
  raw=await rawClient(dir,port);await raw.wait(message=>message.type==='welcome');
  raw.send({type:'query',requestId:'old_output_query',taskId:value.taskId});assert.equal((await raw.wait(message=>message.type==='task_status')).error.code,'TASK_POLICY_CHANGED');
 }finally{raw?.socket.destroy();await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});

test('v0.3 independent crash audit: committed side effect survives kill, new task/run IDs blocked on both nodes until owner reconciliation', {timeout:25000},async()=>{
 const dir=await makeWorkspace('audit-v03-unknown-'),nodes=[];let raw,fixturePid;
 try{
  const fixture=path.join(dir,'trusted-effect.mjs');await fs.writeFile(fixture,`import fs from 'node:fs';fs.appendFileSync('effects.txt','EFFECT\\n');fs.writeFileSync('fixture-pid.txt',String(process.pid));console.log('effect committed');setTimeout(()=>process.exit(0),1500);\n`);
  const servantConfig={id:'servant',port:0,policy:{grants:{master:{tools:['exec','writeFile','readFile','echo'],workspace:'workspace',maxTimeoutMs:5000,maxJobTimeoutMs:10000,execCommands:{effect:{file:process.execPath,args:[fixture]}}}}}};
  let servant=await startNode(dir,servantConfig);nodes.push(servant);const port=servant.port;
  const masterConfig={id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{}};
  let master=await startNode(dir,masterConfig);nodes.push(master);await waitConnected(master,'servant');
  const original=task('effect_original','exec',{command:'effect',args:[]});
  const pending=master.command({command:'dispatch',peerId:'servant',task:original});
  const job=await servant.wait(event=>event.event==='job_state'&&event.state==='running');
  await until(async()=>fs.readFile(path.join(dir,'workspace','effects.txt'),'utf8').then(text=>text==='EFFECT\n',()=>false));
  fixturePid=Number(await fs.readFile(path.join(dir,'workspace','fixture-pid.txt'),'utf8'));
  await kill(servant);assert.equal((await pending).error.code,'OUTCOME_UNKNOWN');await kill(master);
  servant=await startNode(dir,{...servantConfig,port});nodes.push(servant);master=await startNode(dir,masterConfig);nodes.push(master);await waitConnected(master,'servant');
  assert.equal((await master.command({command:'operationStatus',peerId:'servant',taskId:original.taskId})).result.state,'unknown');
  assert.equal((await servant.command({command:'taskStatus',masterId:'master',taskId:original.taskId})).result.state,'unknown');
  const fresh=task('new_id_same_effect','writeFile',{path:'must-not-exist.txt',text:'blocked'},'new_run');
  assert.equal((await master.command({command:'dispatch',peerId:'servant',task:fresh})).error.code,'UNCERTAIN_SIDE_EFFECT');
  assert.equal(master.events.filter(event=>event.event==='task_dispatched'&&event.taskId===fresh.taskId).length,0);
  raw=await rawClient(dir,port);await raw.wait(message=>message.type==='welcome');raw.send({type:'task',...fresh});assert.equal((await raw.wait(message=>message.type==='result'&&message.taskId===fresh.taskId)).error.code,'UNCERTAIN_SIDE_EFFECT');
  raw.send({type:'task',...original});assert.equal((await raw.wait(message=>message.type==='result'&&message.taskId===original.taskId)).outcomeUnknown,true);
  await assert.rejects(fs.stat(path.join(dir,'workspace','must-not-exist.txt')),{code:'ENOENT'});
  assert.equal(servant.events.some(event=>event.event==='task_started'),false);
  await pause(1600);assert.equal(await fs.readFile(path.join(dir,'workspace','effects.txt'),'utf8'),'EFFECT\n');
  const jobReconcile=await servant.command({command:'reconcile',masterId:'master',jobId:job.jobId,resolution:'completed',note:'Observed single effect and trusted process exit'});assert.equal(jobReconcile.ok,true,JSON.stringify(jobReconcile));
  const recovered=await servant.command({command:'reconcile',masterId:'master',taskId:original.taskId,resolution:'completed',note:'Read effects.txt and verified one committed line',result:{manuallyVerified:true}});assert.equal(recovered.ok,true);
  const queried=await master.command({command:'query',peerId:'servant',taskId:original.taskId});assert.equal(queried.result.state,'reconciled');
  assert.equal((await master.command({command:'dispatch',peerId:'servant',task:fresh})).result.status,'ok');
  assert.equal(await fs.readFile(path.join(dir,'workspace','must-not-exist.txt'),'utf8'),'blocked');
  assert.equal(await fs.readFile(path.join(dir,'workspace','effects.txt'),'utf8'),'EFFECT\n');
 }finally{raw?.socket.destroy();await stopAll(nodes);if(fixturePid){try{process.kill(-fixturePid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}}await fs.rm(dir,{recursive:true,force:true});}
});


test('v0.3 independent runtime retention audit: task capacity compacts both ledgers without accepting retired IDs', {timeout:15000},async()=>{
 const dir=await makeWorkspace('audit-v03-runtime-retention-'),nodes=[];let raw;
 try{
  const servant=await startNode(dir,{id:'servant',port:0,policy:{maxTaskRecords:4,grants:{master:{tools:['echo']}}}});nodes.push(servant);
  const master=await startNode(dir,{id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{maxTaskRecords:4}});nodes.push(master);await waitConnected(master,'servant');
  for(let i=0;i<12;i++)assert.equal((await master.command({command:'dispatch',peerId:'servant',task:task(`retire_${i}`,'echo',{text:String(i)})})).result.status,'ok');
  const m=(await master.command({command:'status'})).result,s=(await servant.command({command:'status'})).result;
  assert.ok(m.outgoing.retiredCount>0);assert.ok(s.incoming.retiredCount>0);assert.ok(m.outgoing.records<=4);assert.ok(s.incoming.records<=4);
  assert.equal((await master.command({command:'dispatch',peerId:'servant',task:task('retire_0','echo',{text:'0'})})).error.code,'TASK_HISTORY_EXPIRED');
  raw=await rawClient(dir,servant.port);await raw.wait(message=>message.type==='welcome');raw.send({type:'task',...task('retire_0','echo',{text:'0'})});assert.equal((await raw.wait(message=>message.type==='result')).error.code,'TASK_HISTORY_EXPIRED');
  assert.equal(servant.events.filter(event=>event.event==='task_started'&&event.taskId==='retire_0').length,1);
 }finally{raw?.socket.destroy();await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});

test('v0.3 independent daemon audit: real --daemon serves encrypted tasks with closed stdin and stops on owner SIGTERM', {timeout:15000},async()=>{
 const dir=await makeWorkspace('audit-v03-daemon-');let child,raw,exit;
 try{
  const security=await testSecurity(dir,'servant',['master']),config=path.join(dir,'servant.json');
  await fs.writeFile(config,JSON.stringify({id:'servant',port:0,security,policy:{grants:{master:{tools:['echo']}}}}));
  child=spawn(process.execPath,[fileURLToPath(new URL('../src/main.mjs',import.meta.url)),'--config',config,'--daemon'],{stdio:['ignore','pipe','pipe']});
  const events=[];let buffer='',stderr='';child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');
  child.stdout.on('data',data=>{buffer+=data;while(buffer.includes('\n')){const i=buffer.indexOf('\n');try{events.push(JSON.parse(buffer.slice(0,i)));}catch{}buffer=buffer.slice(i+1);}});child.stderr.on('data',data=>stderr+=data);
  exit=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
  const ready=await until(()=>events.find(event=>event.event==='node_ready'));assert.equal(child.exitCode,null,stderr);
  raw=await rawClient(dir,ready.port);await raw.wait(message=>message.type==='welcome');raw.send({type:'task',...task('after_eof','echo',{text:'daemon still serving'})});
  assert.equal((await raw.wait(message=>message.type==='result')).result.text,'daemon still serving');raw.socket.destroy();raw=null;
  child.kill('SIGTERM');assert.deepEqual(await exit,{code:0,signal:null});assert.ok(events.some(event=>event.event==='node_stopped'));
 }finally{raw?.socket.destroy();if(child&&child.exitCode===null){child.kill('SIGKILL');await exit;}await fs.rm(dir,{recursive:true,force:true});}
});

test('v0.3 independent cache-pressure audit: lost mutating MCP response cannot shed unknown flag or unlock fresh side effects', {timeout:15000},async()=>{
 const dir=await makeWorkspace('audit-v03-cache-unknown-'),nodes=[];let raw;
 try{
  const script=path.join(dir,'trusted-mcp-drop.mjs');await fs.writeFile(script,`import fs from 'node:fs';import readline from 'node:readline';for await(const line of readline.createInterface({input:process.stdin})){const m=JSON.parse(line);const send=result=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:m.id,result})+'\\n');if(m.method==='initialize')send({protocolVersion:'2025-06-18',capabilities:{tools:{}},serverInfo:{name:'audit',version:'1'}});else if(m.method==='tools/list')send({tools:[{name:'commit'}]});else if(m.method==='tools/call'){fs.appendFileSync('effects.txt','ONCE\\n');process.exit(0);}}\n`);
  const grant={tools:['echo','mcpCall','writeFile'],workspace:'workspace',maxTimeoutMs:5000,mcpServers:{local:{trusted:true,file:process.execPath,args:[script],tools:{commit:{readOnly:false,inputSchema:{type:'object',properties:{},additionalProperties:false}}}}}};
  const servant=await startNode(dir,{id:'servant',port:0,policy:{maxCacheBytes:1024,grants:{master:grant}}});nodes.push(servant);
  const master=await startNode(dir,{id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{}});nodes.push(master);await waitConnected(master,'servant');
  assert.equal((await master.command({command:'dispatch',peerId:'servant',task:task('fill_cache','echo',{text:'x'.repeat(850)})})).result.status,'ok');
  const response=await master.command({command:'dispatch',peerId:'servant',task:task('mcp_ambiguous','mcpCall',{server:'local',tool:'commit',arguments:{}})});
  assert.equal(await fs.readFile(path.join(dir,'workspace','effects.txt'),'utf8'),'ONCE\n');
  assert.equal(response.result.error.code,'RESULT_CACHE_FULL');assert.equal(response.result.outcomeUnknown,true);
  assert.equal((await servant.command({command:'taskStatus',masterId:'master',taskId:'mcp_ambiguous'})).result.state,'unknown');
  const fresh=task('cache_bypass','writeFile',{path:'must-not-exist.txt',text:'blocked'},'different_run');
  assert.equal((await master.command({command:'dispatch',peerId:'servant',task:fresh})).error.code,'UNCERTAIN_SIDE_EFFECT');
  raw=await rawClient(dir,servant.port);await raw.wait(message=>message.type==='welcome');raw.send({type:'task',...fresh});assert.equal((await raw.wait(message=>message.type==='result')).error.code,'UNCERTAIN_SIDE_EFFECT');
  await assert.rejects(fs.stat(path.join(dir,'workspace','must-not-exist.txt')),{code:'ENOENT'});
 }finally{raw?.socket.destroy();await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});
