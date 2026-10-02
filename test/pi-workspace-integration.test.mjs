import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, startNode, peer, waitConnected, stopAll } from '../scripts/process-helper.mjs';
import { runPiMock } from '../integration/pi/agent.mjs';

function commandResult(response) {
  if (!response.ok) throw Object.assign(new Error(response.error?.message ?? 'Node command failed'), {code:response.error?.code});
  return response.result;
}
const observations = result => result.messages.filter(message=>message.role==='toolResult');

test('real Pi and mTLS automatically create two servant workspaces, isolate file flows, and reuse bindings after both node restarts', {timeout:40000}, async () => {
  const dir=await makeWorkspace('pi-workspace-e2e-'),nodes=[];
  try {
    const projects=path.join(dir,'approved-projects');await fs.mkdir(projects,{mode:0o700});
    const servantConfig={id:'servant-a',port:0,policy:{grants:{master:{tools:['workspaceList','workspaceCreate'],
      workspaceProvisioning:{roots:{projects:{path:projects,maxWorkspaces:4,grant:{
        tools:['readFile','writeFile','editFile','listDirectory','capabilities','wait'],directories:[{path:'',read:true,write:true}],
      }}}},
    }}}};
    let servant=await startNode(dir,servantConfig);nodes.push(servant);
    const masterConfig={id:'master',port:0,agent:'pi-mock',peers:[peer(servant)],policy:{grants:{}}};
    let master=await startNode(dir,masterConfig);nodes.push(master);await waitConnected(master,servant.id);
    const logicalIds=['project-a','project-b'];
    for(const logicalWorkspaceId of logicalIds) {
      const snapshot=commandResult(await master.command({command:'listWorkspaceBindings'}));
      commandResult(await master.command({command:'setWorkspaceAutoProvision',peerId:servant.id,logicalWorkspaceId,rootId:'projects',enabled:true,expectedRevision:snapshot.revision}));
    }
    assert.deepEqual(await fs.readdir(projects),[],'Enabling auto-create must not allocate unused workspaces');

    for(const logicalWorkspaceId of logicalIds) {
      // The existing deterministic write scenario requires no project seed. Its
      // name is historical; this fixture explicitly grants the requested write.
      const first=commandResult(await master.command({command:'agent',scenario:'tool-denial',logicalWorkspaceId,runId:`first-${logicalWorkspaceId}`,prompt:'Write in the current remote project'}));
      assert.equal(first.version,'0.99.2');assert.ok(observations(first).every(item=>!item.isError),first.final);
      assert.equal(first.logicalWorkspaceId,logicalWorkspaceId);assert.equal(first.workspaceBindings.length,1);
      assert.deepEqual(first.dispatches.map(item=>item.tool),['writeFile']);
      assert.ok(first.audit.findIndex(item=>item.type==='workspace_ready')<first.audit.findIndex(item=>item.type==='remote_dispatch'));
      assert.ok(!first.modelToolDeclarations.flat().some(name=>/workspace.?create/i.test(name)));
    }
    const initial=commandResult(await master.command({command:'listWorkspaceBindings'}));
    assert.equal(initial.bindings.length,2);assert.equal(new Set(initial.bindings.map(item=>item.workspaceId)).size,2);
    assert.equal((await fs.readdir(projects)).length,2);

    for(const [index,logicalWorkspaceId] of logicalIds.entries()) {
      const original=`ONLY_PROJECT_${index}_8137`,edited=`${original}_EDITED`;
      const result=await runPiMock({peerIds:[servant.id],logicalWorkspaceId,runId:`files-${logicalWorkspaceId}`,prompt:'Write, edit and read the selected remote project',
        ensureWorkspaceBinding:async(peerId,logicalWorkspaceId)=>commandResult(await master.command({command:'ensureWorkspaceBinding',peerId,logicalWorkspaceId})),
        dispatch:async(peerId,task)=>commandResult(await master.command({command:'dispatch',peerId,task})),
        calls:[
          {name:'remote_write',arguments:{peerId:servant.id,path:'hello.txt',text:original}},
          {name:'remote_read',arguments:{peerId:servant.id,path:'hello.txt'}},
          {name:'remote_edit',arguments:{peerId:servant.id,path:'hello.txt',oldText:original,newText:edited}},
          {name:'remote_read',arguments:{peerId:servant.id,path:'hello.txt'}},
          {name:'remote_list',arguments:{peerId:servant.id}},
        ],
      });
      assert.ok(observations(result).every(item=>!item.isError),result.final);
      assert.equal(JSON.parse(observations(result)[3].content[0].text).text,edited);
      assert.ok(result.dispatches.every(item=>item.logicalWorkspaceId===logicalWorkspaceId));
      assert.doesNotMatch(result.final,new RegExp(`ONLY_PROJECT_${1-index}_8137`));
    }
    const created=commandResult(await servant.command({command:'listWorkspaceBindings'})).creations;
    assert.equal(created.length,2);assert.ok(created.every(item=>item.masterId==='master'&&item.state==='ready'));
    for(const [index,logicalWorkspaceId] of logicalIds.entries()) {
      const binding=initial.bindings.find(item=>item.logicalWorkspaceId===logicalWorkspaceId);
      const allocation=created.find(item=>item.id===binding.workspaceId);assert.ok(allocation);
      assert.equal(await fs.readFile(path.join(projects,allocation.name,'hello.txt'),'utf8'),`ONLY_PROJECT_${index}_8137_EDITED`);
      assert.equal(await fs.readFile(path.join(projects,allocation.name,'denied.txt'),'utf8'),'Must be refused by the servant policy');
    }
    assert.equal(await fs.readFile(path.join(dir,'workspace','hello.txt'),'utf8'),'Hello from the servant-owned approved workspace.\n');
    assert.equal(servant.events.filter(event=>event.event==='task_started'&&event.tool==='workspaceCreate').length,2);
    assert.equal(master.events.filter(event=>event.event==='task_started').length,0);

    const controller=new AbortController();let waitingTaskId;
    await assert.rejects(runPiMock({peerIds:[servant.id],logicalWorkspaceId:'project-a',prompt:'Wait in the selected remote project',signal:controller.signal,
      ensureWorkspaceBinding:async(peerId,logicalWorkspaceId)=>commandResult(await master.command({command:'ensureWorkspaceBinding',peerId,logicalWorkspaceId})),
      dispatch:async(peerId,task)=>{waitingTaskId=task.taskId;return commandResult(await master.command({command:'dispatch',peerId,task}));},
      cancel:async(peerId,taskId)=>commandResult(await master.command({command:'cancel',peerId,taskId})),
      calls:[{name:'remote_wait',arguments:{peerId:servant.id,ms:1500,timeoutMs:2000}}],
      onEvent:event=>{if(event.type==='remote_dispatch')controller.abort();},
    }),{code:'AGENT_ABORTED'});
    const cancelled=await servant.wait(event=>event.event==='task_finished'&&event.taskId===waitingTaskId);
    assert.equal(cancelled.error?.code,'CANCELLED','Scoped task frame must precede its cancellation frame');

    await master.stop();await servant.stop();
    servant=await startNode(dir,{...servantConfig,port:servant.port});nodes.push(servant);
    master=await startNode(dir,{...masterConfig,peers:[peer(servant)]});nodes.push(master);await waitConnected(master,servant.id);
    for(const [index,logicalWorkspaceId] of logicalIds.entries()) {
      const result=commandResult(await master.command({command:'agent',logicalWorkspaceId,prompt:'Read the saved remote project after restart'}));
      assert.ok(observations(result).every(item=>!item.isError),result.final);
      assert.match(result.final,new RegExp(`ONLY_PROJECT_${index}_8137_EDITED`));
      assert.doesNotMatch(result.final,new RegExp(`ONLY_PROJECT_${1-index}_8137`));
      assert.equal(result.workspaceBindings[0].workspaceId,initial.bindings.find(item=>item.logicalWorkspaceId===logicalWorkspaceId).workspaceId);
    }
    assert.deepEqual(commandResult(await master.command({command:'listWorkspaceBindings'})).bindings,initial.bindings);
    assert.equal(commandResult(await servant.command({command:'listWorkspaceBindings'})).creations.length,2);
    assert.equal(servant.events.filter(event=>event.event==='task_started'&&event.tool==='workspaceCreate').length,0);
    assert.equal(master.events.filter(event=>event.event==='task_started').length,0);
  }finally{await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});
