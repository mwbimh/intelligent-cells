import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { runPiMock } from '../integration/pi/agent.mjs';
import { createRemoteTools } from '../integration/pi/remote-tools.mjs';
import { compileResourcePolicy, executeResourceTask } from '../src/resources.mjs';
import { compileMcpPolicy, executeMcpTask } from '../src/mcp.mjs';
import { validatePiConfiguration } from '../src/pi-policy.mjs';

const mockServer=fileURLToPath(new URL('../integration/pi/mock-mcp-server.mjs',import.meta.url));
const schema={type:'object',properties:{a:{type:'integer',minimum:-100,maximum:100},b:{type:'integer',minimum:-100,maximum:100}},required:['a','b'],additionalProperties:false};

test('real Pi loads explicit remote instruction/skill/prompt data and only an owner-approved built-in extension', {timeout:20000}, async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'pi-resources-'));
  try {
    const texts={guide:'RESOURCE_PROJECT_RULE_951: Run the configured test alias before reporting completion.',skill:'RESOURCE_SKILL_951: Fix the arithmetic fixture using an exact edit.',prompt:'RESOURCE_PROMPT_951: $USER_PROMPT'};
    const resources={};
    for(const [id,text] of Object.entries(texts)) {await fs.writeFile(path.join(root,`${id}.md`),text);resources[id]={kind:id==='guide'?'instruction':id==='skill'?'skill':'prompt',path:`${id}.md`,sha256:createHash('sha256').update(text).digest('hex')};}
    const grant={root,tools:new Set(['resourceRead']),...await compileResourcePolicy({resources},root,root)};
    const dispatches=[];
    const result=await runPiMock({peerIds:['servant'],prompt:'Review approved project',calls:[],
      resourceConfiguration:{resources:Object.keys(resources).map(resource=>({peerId:'servant',resource})),trustedExtensions:[{id:'remote-audit-v1',approved:true}]},
      promptResource:{peerId:'servant',resource:'prompt'},
      dispatch:async(peerId,task)=>{assert.equal(peerId,'servant');dispatches.push(task);return {status:'ok',result:await executeResourceTask(task,grant)};},
    });
    assert.equal(result.version,'0.99.2');
    assert.equal(dispatches.length,3);assert.ok(dispatches.every(task=>task.tool==='resourceRead'&&task.runId==='pi-default'));
    assert.equal(result.resources.length,3);
    const actualRequest=JSON.stringify(result.modelContext);
    assert.match(actualRequest,/RESOURCE_PROJECT_RULE_951/);assert.match(actualRequest,/RESOURCE_SKILL_951/);assert.match(actualRequest,/RESOURCE_PROMPT_951: Review approved project/);
    assert.ok(result.audit.some(event=>event.type==='trusted_extension_event'&&event.event==='agent_start'));
    assert.deepEqual(result.trustedExtensions,['remote-audit-v1']);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('resource denial fails closed before model startup; prompt and extension selectors cannot expand owner approval',async()=>{
  const base={peerIds:['servant'],prompt:'x',calls:[],resourceConfiguration:{resources:[{peerId:'servant',resource:'guide'}]},dispatch:async()=>({status:'error',error:{code:'RESOURCE_DENIED',message:'Owner revoked resource'}})};
  await assert.rejects(runPiMock(base),{code:'RESOURCE_DENIED'});
  await assert.rejects(runPiMock({...base,resourceConfiguration:{},promptResource:{peerId:'servant',resource:'hidden'}}),{code:'RESOURCE_DENIED'});
  for(const trustedExtensions of [[{id:'/tmp/plugin.mjs',approved:true}],[{id:'remote-audit-v1',approved:false}],[{id:'remote-audit-v1',approved:true,code:'process.exit()'}]])assert.throws(()=>validatePiConfiguration({trustedExtensions}),{code:'UNTRUSTED_EXTENSION'});
});

test('genuine Pi remote MCP tool uses initialize/list/call on a separate bounded stdio server', {timeout:20000},async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'pi-mcp-'));
  try {
    const grant={root,tools:new Set(['mcpList','mcpCall']),...await compileMcpPolicy({mcpServers:{math:{trusted:true,file:process.execPath,args:[mockServer],tools:{add:{inputSchema:schema,readOnly:true}}}}},root,root)};
    const tasks=[];
    const result=await runPiMock({peerIds:['servant'],prompt:'Add using the approved MCP binding',calls:[
      {name:'remote_mcp_list',arguments:{peerId:'servant',server:'math'}},
      {name:'remote_mcp_call',arguments:{peerId:'servant',server:'math',tool:'add',arguments:{a:19,b:23}}},
      {name:'remote_mcp_call',arguments:{peerId:'servant',server:'math',tool:'unapproved',arguments:{}}},
    ],dispatch:async(_peer,task)=>{tasks.push(task);try{return{status:'ok',result:await executeMcpTask(task,grant)}}catch(error){return{status:'error',error:{code:error.code,message:error.message}}}}});
    assert.equal(result.version,'0.99.2');assert.deepEqual(tasks.map(t=>t.tool),['mcpList','mcpCall','mcpCall']);
    const results=result.messages.filter(message=>message.role==='toolResult');
    assert.deepEqual(results.map(item=>item.isError),[false,false,true]);
    const list=JSON.parse(results[0].content[0].text);assert.deepEqual(list.tools.map(item=>item.name),['add']);assert.equal(list.tools[0].permissionAuthority,'servant-local-grant');
    const called=JSON.parse(results[1].content[0].text);const actual=JSON.parse(called.content[0].text);assert.equal(actual.sum,42);assert.notEqual(actual.serverPid,process.pid);
    assert.match(result.final,/42/);assert.match(result.final,/MCP_TOOL_DENIED/);
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('Pi blocks fresh tool-call IDs after uncertain side effects while permitting read-only inspection',async()=>{
  const dispatched=[];
  const result=await runPiMock({peerIds:['servant'],prompt:'Do not repeat unknown writes',runId:'same-workflow',calls:[
    {name:'remote_write',arguments:{peerId:'servant',path:'effect.txt',text:'once'}},
    {name:'remote_write',arguments:{peerId:'servant',path:'effect.txt',text:'once'}},
    {name:'remote_exec',arguments:{peerId:'servant',command:'test',args:[]}},
    {name:'remote_read',arguments:{peerId:'servant',path:'effect.txt'}},
  ],dispatch:async(_peer,task)=>{dispatched.push(task);return task.tool==='readFile'?{status:'ok',result:{text:'actual inspection'}}:{status:'error',error:{code:'OUTCOME_UNKNOWN',message:'Response lost after possible commit'}};}});
  assert.deepEqual(dispatched.map(task=>task.tool),['writeFile','readFile']);assert.ok(dispatched.every(task=>task.runId==='same-workflow'));
  assert.match(result.final,/RUN_OUTCOME_UNKNOWN/);assert.match(result.final,/actual inspection/);
});

test('repeated Pi tool-call ID reuses its original result and conflicting arguments never get a new task ID',async()=>{
  let count=0;
  const tool=createRemoteTools({peerIds:['servant'],dispatch:async()=>{count++;return{status:'ok',result:{bytes:1}}}}).find(item=>item.name==='remote_write');
  const params={peerId:'servant',path:'x.txt',text:'x'};
  const first=await tool.execute('stable-call',params);
  assert.deepEqual(await tool.execute('stable-call',params),first);assert.equal(count,1);
  await assert.rejects(tool.execute('stable-call',{...params,text:'different'}),{code:'TASK_ID_CONFLICT'});assert.equal(count,1);
});

test('Pi enforces the servant per-peer aggregate resource context budget',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'pi-resource-budget-'));
  try {
    await fs.writeFile(path.join(root,'a.md'),'123456');await fs.writeFile(path.join(root,'b.md'),'abcdef');
    const grant={root,tools:new Set(['resourceRead']),...await compileResourcePolicy({maxResourceTotalBytes:10,resources:{a:{kind:'skill',path:'a.md'},b:{kind:'instruction',path:'b.md'}}},root,root)};
    await assert.rejects(runPiMock({peerIds:['servant'],prompt:'Bound resource context',calls:[],resourceConfiguration:{resources:[{peerId:'servant',resource:'a'},{peerId:'servant',resource:'b'}]},dispatch:async(_peer,task)=>({status:'ok',result:await executeResourceTask(task,grant)})}),{code:'RESOURCE_TOO_LARGE'});
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('MCP rejects invalid UTF-8 before accepting a JSON-RPC handshake',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'mcp-utf8-'));
  try {
    const script=path.join(root,'invalid-utf8.mjs');
    await fs.writeFile(script,`process.stdin.once('data',()=>process.stdout.write(Buffer.from([0xff,10])));`);
    const grant={root,tools:new Set(['mcpList']),...await compileMcpPolicy({mcpServers:{bad:{trusted:true,file:process.execPath,args:[script],tools:{}}}},root,root)};
    await assert.rejects(executeMcpTask({tool:'mcpList',args:{server:'bad'}},grant,AbortSignal.timeout(1000)),{code:'MCP_PROTOCOL_ERROR'});
  }finally{await fs.rm(root,{recursive:true,force:true});}
});

test('Pi cancellation also targets an in-flight approved resource read before the session starts',async()=>{
  const controller=new AbortController();let taskId,resolveRemote,cancelled=0;
  const run=runPiMock({peerIds:['servant'],prompt:'Load resource',calls:[],signal:controller.signal,resourceConfiguration:{resources:[{peerId:'servant',resource:'guide'}]},
    dispatch:async(_peer,task)=>{taskId=task.taskId;controller.abort();return new Promise(resolve=>{resolveRemote=resolve;});},
    cancel:async(peerId,id)=>{assert.equal(peerId,'servant');assert.equal(id,taskId);cancelled++;resolveRemote({status:'error',error:{code:'CANCELLED',message:'cancelled'}});},
  });
  await assert.rejects(run,{code:'AGENT_ABORTED'});assert.equal(cancelled,1);
});
