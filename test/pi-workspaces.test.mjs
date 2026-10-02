import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { runPiMock, createPiRemoteAgent } from '../integration/pi/agent.mjs';
import { createRemoteTools, REMOTE_TOOL_NAMES } from '../integration/pi/remote-tools.mjs';

const toolResults = result => result.messages.filter(message => message.role === 'toolResult');
const resourceText = 'SCOPED_SERVANT_GUIDANCE: Keep all project work in this session workspace.';
const resourceResult = { id:'guide', kind:'instruction', description:'Scoped guidance', text:resourceText,
  sha256:createHash('sha256').update(resourceText).digest('hex'), maxTotalBytes:65536 };

test('real Pi lazily prepares an addressed workspace before resource and tool I/O; unused peers are not provisioned', async () => {
  const order = [], tasks = [], events = [];
  const result = await runPiMock({
    peerIds:['unused-servant','servant'], logicalWorkspaceId:'master-project-a', runId:'scoped-a', prompt:'Use the scoped remote project',
    resourceConfiguration:{resources:[{peerId:'servant',resource:'guide'}]},
    calls:[
      {name:'remote_capabilities',arguments:{peerId:'servant'}},
      {name:'remote_write',arguments:{peerId:'servant',path:'result.txt',text:'PROJECT_A'}},
      {name:'remote_read',arguments:{peerId:'servant',path:'result.txt'}},
      {name:'remote_resource_read',arguments:{peerId:'servant',resource:'guide'}},
    ],
    ensureWorkspaceBinding:async (peerId,logicalWorkspaceId) => {
      order.push('ensure'); assert.equal(peerId,'servant'); assert.equal(logicalWorkspaceId,'master-project-a');
      return {peerId,logicalWorkspaceId,workspaceId:'remote-a'};
    },
    dispatch:async (peerId,task) => {
      order.push(task.tool); tasks.push(task); assert.equal(peerId,'servant');
      assert.equal(task.logicalWorkspaceId,'master-project-a'); assert.equal(task.workspaceId,undefined);
      return {status:'ok',result:task.tool==='resourceRead'?resourceResult:{text:'PROJECT_A'}};
    },
    onEvent:event => { events.push(event); if(event.type==='mock_request') order.push('model'); },
  });
  assert.deepEqual(order.slice(0,3),['ensure','resourceRead','model']);
  assert.equal(order.filter(item=>item==='ensure').length,1);
  assert.equal(tasks.length,5); assert.ok(toolResults(result).every(item=>!item.isError));
  assert.deepEqual(result.workspaceBindings,[{peerId:'servant',logicalWorkspaceId:'master-project-a',workspaceId:'remote-a'}]);
  assert.equal(result.logicalWorkspaceId,'master-project-a');
  assert.ok(result.dispatches.every(item=>item.logicalWorkspaceId==='master-project-a'));
  assert.ok(events.find(item=>item.type==='workspace_ready'&&item.workspaceId==='remote-a'));
  assert.match(JSON.stringify(result.modelContext),/SCOPED_SERVANT_GUIDANCE/);
  assert.ok(result.modelToolDeclarations.flat().every(name=>REMOTE_TOOL_NAMES.includes(name)));
  assert.ok(!result.modelToolDeclarations.flat().some(name=>/workspace.?create/i.test(name)));
});

test('real Pi prepares only the first addressed servant when a logical session has no resources', async () => {
  const order=[];
  const result=await runPiMock({peerIds:['unused','servant'],logicalWorkspaceId:'master-a',prompt:'Read the selected remote project',
    calls:[{name:'remote_read',arguments:{peerId:'servant',path:'hello.txt'}}],
    ensureWorkspaceBinding:async(peerId,logicalWorkspaceId)=>{order.push(`ensure:${peerId}`);return{peerId,logicalWorkspaceId,workspaceId:'remote-a'};},
    dispatch:async(peerId,task)=>{order.push(`dispatch:${peerId}`);assert.equal(task.logicalWorkspaceId,'master-a');return{status:'ok',result:{text:'scoped'}};},
    onEvent:event=>{if(event.type==='mock_request')order.push('model');},
  });
  assert.deepEqual(order,['model','ensure:servant','dispatch:servant','model']);
  assert.equal(toolResults(result)[0].isError,false);
});

test('explicit servant workspace is passed to resource and model dispatch without provisioning', async () => {
  const tasks=[];
  const result=await runPiMock({peerIds:['servant'],workspaceId:'existing',prompt:'Read an explicitly selected workspace',
    resourceConfiguration:{resources:[{peerId:'servant',resource:'guide'}]},
    ensureWorkspaceBinding:async()=>{assert.fail('Explicit workspace must not auto-provision');},
    dispatch:async(_peer,task)=>{tasks.push(task);return{status:'ok',result:task.tool==='resourceRead'?resourceResult:{text:'existing'}};},
  });
  assert.equal(result.workspaceId,'existing'); assert.deepEqual(result.workspaceBindings,[]);
  assert.equal(tasks.length,2); assert.ok(tasks.every(task=>task.workspaceId==='existing'&&task.logicalWorkspaceId===undefined));
});

test('workspace selection is immutable owner metadata and the mock model cannot override it', async () => {
  let ensured=0,dispatched=0;
  const result=await runPiMock({peerIds:['servant'],logicalWorkspaceId:'master-a',prompt:'Reject workspace overrides',
    calls:[
      {name:'remote_read',arguments:{peerId:'servant',path:'hello.txt',workspaceId:'other'}},
      {name:'remote_write',arguments:{peerId:'servant',path:'hello.txt',text:'wrong',logicalWorkspaceId:'other'}},
      {name:'workspaceCreate',arguments:{peerId:'servant',rootId:'unapproved'}},
      {name:'remote_read',arguments:{peerId:'unknown',path:'hello.txt'}},
    ],
    ensureWorkspaceBinding:async()=>{ensured++;return{workspaceId:'remote-a'};},
    dispatch:async()=>{dispatched++;assert.fail('Malformed scope override must not dispatch');},
  });
  assert.equal(ensured,0); assert.equal(dispatched,0); assert.ok(toolResults(result).every(item=>item.isError));
  for(const workspace of [{logicalWorkspaceId:'a',workspaceId:'b'},{logicalWorkspaceId:'../escape'},{workspaceId:''},{logicalWorkspaceId:null}]) {
    await assert.rejects(runPiMock({peerIds:['servant'],prompt:'x',...workspace}),{code:'INVALID_TASK'});
    assert.throws(()=>createRemoteTools({peerIds:['servant'],...workspace}),{code:'INVALID_TASK'});
  }
  await assert.rejects(runPiMock({peerIds:['servant'],prompt:'x',logicalWorkspaceId:'a'}),{code:'WORKSPACE_BINDING_REQUIRED'});
});

test('failed system binding stops scoped Pi I/O without reading the master local fallback', async () => {
  const cwd=await fs.mkdtemp(path.join(os.tmpdir(),'pi-workspace-no-fallback-'));
  try {
    await fs.writeFile(path.join(cwd,'hello.txt'),'MASTER_ONLY_FILE_8031');
    let dispatches=0;
    const options={cwd,peerIds:['servant'],logicalWorkspaceId:'missing',prompt:'Read hello.txt',
      ensureWorkspaceBinding:async()=>{throw Object.assign(new Error('No owner-approved binding or auto-create rule'),{code:'WORKSPACE_BINDING_NOT_FOUND'});},
      dispatch:async()=>{dispatches++;assert.fail('No dispatch without binding');},
    };
    const result=await runPiMock(options);
    assert.equal(dispatches,0); assert.equal(toolResults(result)[0].isError,true);
    assert.match(result.final,/WORKSPACE_BINDING_NOT_FOUND/); assert.doesNotMatch(result.final,/MASTER_ONLY_FILE_8031/);
    assert.equal(await fs.readFile(path.join(cwd,'hello.txt'),'utf8'),'MASTER_ONLY_FILE_8031');
    await assert.rejects(runPiMock({...options,resourceConfiguration:{resources:[{peerId:'servant',resource:'guide'}]}}),{code:'WORKSPACE_BINDING_NOT_FOUND'});
  }finally{await fs.rm(cwd,{recursive:true,force:true});}
});

test('aborting Pi during system preparation cannot dispatch the requested model side effect afterward', async () => {
  const controller=new AbortController();let dispatches=0;
  const run=runPiMock({peerIds:['servant'],logicalWorkspaceId:'a',prompt:'Prepare project',signal:controller.signal,
    calls:[{name:'remote_write',arguments:{peerId:'servant',path:'never.txt',text:'no'}}],
    ensureWorkspaceBinding:async()=>{controller.abort();return{workspaceId:'prepared'};},
    dispatch:async()=>{dispatches++;assert.fail('Aborted run must not write');},
  });
  await assert.rejects(run,{code:'AGENT_ABORTED'});assert.equal(dispatches,0);
});

test('node Pi adapter propagates logical and explicit session selection through the system hook', async () => {
  const seen=[];
  const agent=await createPiRemoteAgent({node:{config:{agent:'pi-mock'},peers:new Map([['servant',{}]]),log:()=>{},
    ensureWorkspaceBinding:async(peerId,logicalWorkspaceId)=>{seen.push({peerId,logicalWorkspaceId});return{peerId,logicalWorkspaceId,workspaceId:'remote-a'};},
    dispatch:async(_peer,task)=>{seen.push(task);return{status:'ok',result:{text:'remote'}};},
  }});
  try {
    await agent.run({prompt:'Read project a',logicalWorkspaceId:'master-a'});
    await agent.run({prompt:'Read explicit workspace',workspaceId:'existing'});
    assert.equal(seen.length,3);assert.deepEqual(seen[0],{peerId:'servant',logicalWorkspaceId:'master-a'});
    assert.equal(seen[1].logicalWorkspaceId,'master-a');assert.equal(seen[2].workspaceId,'existing');
  }finally{await agent.dispose();}
});
