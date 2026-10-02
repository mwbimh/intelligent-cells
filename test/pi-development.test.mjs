import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace,startNode,peer,waitConnected,stopAll } from '../scripts/process-helper.mjs';
import { prepareDevelopmentFixture } from '../integration/pi/development-fixture.mjs';

test('real encrypted Pi fixed workflow reads actual repository, fixes bug, builds, tests, checks git diff and calls MCP', {timeout:40000}, async()=>{
  const dir=await makeWorkspace('pi-development-e2e-'),nodes=[];
  try {
    const fixture=await prepareDevelopmentFixture(dir);
    const servant=await startNode(dir,{id:'servant-a',port:0,policy:{grants:{master:fixture.grant}}});nodes.push(servant);
    const master=await startNode(dir,{id:'master',port:0,agent:'pi-mock',peers:[peer(servant)],pi:fixture.pi,policy:{grants:{}}});nodes.push(master);
    await waitConnected(master,servant.id);
    const response=await master.command({command:'agent',scenario:'development',runId:'trusted-fix-001',prompt:'修复 add 函数并验证',promptResource:{peerId:'servant-a',resource:'task'}});
    assert.equal(response.ok,true,JSON.stringify(response.error));
    const result=response.result;
    assert.equal(result.version,'0.99.2');assert.equal(result.mockedModel,true);assert.equal(result.runId,'trusted-fix-001');
    assert.equal(result.dispatches.length,13);assert.equal(result.modelRequests,14);assert.equal(result.resources.length,3);
    assert.ok(result.messages.filter(item=>item.role==='toolResult').every(item=>!item.isError),result.final);
    const final=JSON.parse(result.final);assert.equal(final.verified,true,result.final);assert.equal(final.baselineTestFailed,true);assert.equal(final.buildPassed,true);assert.equal(final.testPassed,true);assert.equal(final.mcpSum,42);
    assert.equal(await fs.readFile(path.join(fixture.root,'src/math.mjs'),'utf8'),'export function add(a, b) { return a + b; }\n');
    assert.equal(await fs.readFile(path.join(fixture.root,'dist/math.mjs'),'utf8'),'export function add(a, b) { return a + b; }\n');
    assert.equal(master.events.filter(event=>event.event==='task_started').length,0);
    assert.equal(servant.events.filter(event=>event.event==='task_started').length,16);
    assert.ok(result.audit.some(event=>event.type==='trusted_extension_event'&&event.event==='tool_call'));
    assert.notEqual(master.child.pid,servant.child.pid);
    // Graceful restart creates a fresh Pi session, but persisted remote task
    // identities/results and repository changes survive on the same state paths.
    const taskId=result.dispatches.find(item=>item.tool==='editFile').taskId;
    await master.stop();await servant.stop();
    const restartedServant=await startNode(dir,{...servant.config,port:servant.port});nodes.push(restartedServant);
    const restartedMaster=await startNode(dir,{...master.config,peers:[peer(restartedServant)]});nodes.push(restartedMaster);
    await waitConnected(restartedMaster,restartedServant.id);
    const known=await restartedMaster.command({command:'operationStatus',peerId:'servant-a',taskId});
    assert.equal(known.ok,true);assert.equal(known.result.response.status,'ok');
    const query=await restartedMaster.command({command:'query',peerId:'servant-a',taskId});assert.equal(query.ok,true);assert.equal(query.result.state,'completed');
    const readback=await restartedMaster.command({command:'agent',scenario:'development-readback',runId:'trusted-fix-001',prompt:'读取重启后保存的修复'});
    assert.equal(readback.ok,true);assert.match(readback.result.final,/return a \+ b/);
    assert.equal(restartedServant.events.filter(event=>event.event==='task_started'&&event.tool==='editFile').length,0);
  }finally{await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});

test('Pi MCP uncertain commit survives both node restarts and fresh Pi IDs cannot repeat it', {timeout:40000},async()=>{
  const dir=await makeWorkspace('pi-uncertain-durable-'),nodes=[];
  try {
    const serverFile=path.join(dir,'trusted-commit-then-disconnect.mjs');
    await fs.writeFile(serverFile,`import fs from 'node:fs';import readline from 'node:readline';\nfor await(const line of readline.createInterface({input:process.stdin})){const q=JSON.parse(line);const send=result=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:q.id,result})+'\\n');if(q.method==='initialize')send({protocolVersion:'2025-06-18',capabilities:{tools:{}},serverInfo:{name:'trusted-fixture',version:'1'}});else if(q.method==='tools/list')send({tools:[{name:'commit',inputSchema:{type:'object'}}]});else if(q.method==='tools/call'){fs.appendFileSync('effects.log','applied\\n');process.exit(0);}}`);
    const grant={tools:['mcpCall','writeFile','readFile'],workspace:'workspace',maxTimeoutMs:2000,
      mcpServers:{fixture_effect:{trusted:true,file:process.execPath,args:[serverFile],tools:{commit:{readOnly:false,inputSchema:{type:'object',properties:{},additionalProperties:false}}}}}};
    const servant=await startNode(dir,{id:'servant-a',port:0,policy:{grants:{master:grant}}});nodes.push(servant);
    const master=await startNode(dir,{id:'master',port:0,agent:'pi-mock',peers:[peer(servant)],policy:{grants:{}}});nodes.push(master);
    await waitConnected(master,servant.id);
    const first=await master.command({command:'agent',scenario:'mcp-uncertain',runId:'effect-001',prompt:'Exercise uncertain committed effect'});
    assert.equal(first.ok,true,JSON.stringify(first.error));assert.match(first.result.final,/OUTCOME_UNKNOWN/);
    assert.deepEqual(first.result.dispatches.map(item=>item.tool),['mcpCall','readFile']);
    assert.equal(await fs.readFile(path.join(dir,'workspace/effects.log'),'utf8'),'applied\n');
    await assert.rejects(fs.stat(path.join(dir,'workspace/after-unknown.txt')),{code:'ENOENT'});
    const taskId=first.result.dispatches[0].taskId;
    assert.equal((await master.command({command:'status'})).result.unknownOutgoing,1);
    assert.equal((await servant.command({command:'status'})).result.unknownIncoming,1);
    await master.stop();await servant.stop();
    const servant2=await startNode(dir,{...servant.config,port:servant.port});nodes.push(servant2);
    const master2=await startNode(dir,{...master.config,peers:[peer(servant2)]});nodes.push(master2);
    await waitConnected(master2,servant2.id);
    const second=await master2.command({command:'agent',scenario:'mcp-uncertain',runId:'effect-001',prompt:'Repeat attempt after restart must be refused'});
    assert.equal(second.ok,true);assert.match(second.result.final,/UNCERTAIN_SIDE_EFFECT/);
    assert.notEqual(first.result.dispatches[0].taskId,second.result.dispatches[0].taskId);
    assert.equal(servant2.events.filter(event=>event.event==='task_started'&&event.tool==='mcpCall').length,0);
    assert.equal(await fs.readFile(path.join(dir,'workspace/effects.log'),'utf8'),'applied\n');
    const query=await master2.command({command:'query',peerId:'servant-a',taskId});assert.equal(query.ok,true);assert.equal(query.result.state,'unknown');
    // Explicit local owner reconciliation is grounded in the actual inspected effect.
    const reconcile=await servant2.command({command:'reconcile',masterId:'master',taskId,resolution:'completed',note:'Fixture owner verified exactly one applied line in effects.log',result:{applied:1}});
    assert.equal(reconcile.ok,true,JSON.stringify(reconcile.error));
    const resolved=await master2.command({command:'query',peerId:'servant-a',taskId});assert.equal(resolved.result.state,'reconciled');
    assert.equal((await master2.command({command:'status'})).result.unknownOutgoing,0);
    assert.equal(await fs.readFile(path.join(dir,'workspace/effects.log'),'utf8'),'applied\n');
  }finally{await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
});
