import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { makeWorkspace,startNode,peer,waitConnected,stopAll } from '../../scripts/process-helper.mjs';
import { prepareDevelopmentFixture } from './development-fixture.mjs';

const dir=await makeWorkspace('intelligent-cells-real-development-'),nodes=[];
try {
  const fixture=await prepareDevelopmentFixture(dir);
  const servant=await startNode(dir,{id:'servant-a',port:0,policy:{grants:{master:fixture.grant}}});nodes.push(servant);
  const master=await startNode(dir,{id:'master',port:0,agent:'pi-mock',peers:[peer(servant)],pi:fixture.pi,policy:{grants:{}}});nodes.push(master);
  await waitConnected(master,servant.id);
  const response=await master.command({command:'agent',scenario:'development',runId:'demo-development',prompt:'修复加法函数，并通过 build、test、git diff 和 MCP 验证',promptResource:{peerId:'servant-a',resource:'task'}});
  assert.equal(response.ok,true,JSON.stringify(response.error));
  const result=response.result, final=JSON.parse(result.final);
  assert.equal(final.verified,true,result.final);
  const localExecutions=master.events.filter(event=>event.event==='task_started').length;
  assert.equal(localExecutions,0);
  console.log(JSON.stringify({proof:'Genuine Pi 0.99.2 → fixed HTTP/SSE model script → mTLS servant permissions → actual repository edit/build/tests/git → stdio MCP → verified final',
    package:result.package,version:result.version,mockedModel:true,runId:result.runId,masterPid:master.child.pid,servantPid:servant.child.pid,
    modelRequests:result.modelRequests,remoteTaskCount:result.dispatches.length,masterLocalExecutions:localExecutions,
    resources:result.resources,trustedExtensions:result.trustedExtensions,final,
    limitations:['固定模型剧本；真实 provider 和持续会话按用户要求延后','受信任的临时开发 fixture；执行器 allowlist 不是 OS sandbox','MCP 只实现有界 stdio tools 子集，未连接外部账号或服务'],
  },null,2));
}finally{await stopAll(nodes);await fs.rm(dir,{recursive:true,force:true});}
