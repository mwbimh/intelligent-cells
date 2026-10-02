import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, startNode, peer, waitConnected, stopAll } from '../scripts/process-helper.mjs';

test('workspace job output and controls remain attached to the selected workspace across servant restart', {timeout:30000}, async()=>{
  const dir=await makeWorkspace('workspace-job-scope-'),nodes=[];
  try{
    await fs.mkdir(path.join(dir,'second'));const script=path.join(dir,'approved-output-only.mjs');await fs.writeFile(script,"process.stdout.write('synthetic workspace job');\n");
    const grant=workspace=>({workspace,tools:['exec','jobStatus','jobOutput','jobCancel'],directories:[{path:'',read:true,write:false}],allowUnsandboxedProcesses:true,execCommands:{describe:{file:process.execPath,args:[script]}}});
    const config={id:'servant',port:0,policy:{grants:{master:{tools:['workspaceList'],workspaces:{one:grant('workspace'),two:grant('second')}}}}};
    let servant=await startNode(dir,config);nodes.push(servant);
    const master=await startNode(dir,{id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{}});nodes.push(master);await waitConnected(master,'servant');
    let sequence=0;const dispatch=async(workspaceId,tool,args)=>(await master.command({command:'dispatch',peerId:'servant',task:{taskId:`workspace_job_${++sequence}`,tool,args,workspaceId,timeoutMs:2000}})).result;
    const launched=await dispatch('one','exec',{command:'describe',args:[],background:true});assert.equal(launched.status,'ok');const jobId=launched.result.jobId;assert.ok(jobId);
    for(const tool of ['jobStatus','jobOutput','jobCancel'])assert.equal((await dispatch('two',tool,{jobId})).error.code,'WORKSPACE_DENIED');
    assert.equal((await dispatch('one','jobStatus',{jobId})).status,'ok');
    await new Promise(resolve=>setTimeout(resolve,80));
    const port=servant.port,after=master.events.length;await servant.stop();servant=await startNode(dir,{...config,port});nodes.push(servant);await waitConnected(master,'servant',after);
    assert.equal((await dispatch('two','jobOutput',{jobId})).error.code,'WORKSPACE_DENIED');
    assert.equal((await dispatch('one','jobStatus',{jobId})).status,'ok');
  }finally{await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});
