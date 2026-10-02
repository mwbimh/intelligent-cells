import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { makeWorkspace,startNode,peer,waitConnected,stopAll } from '../scripts/process-helper.mjs';

test('4100 actual encrypted operations cross the 4096-record limit; both restarted nodes refuse retired IDs', {timeout:180000}, async t=>{
  const directory=await makeWorkspace('capacity-4100-'), nodes=[];
  try {
    const servantConfig={id:'servant',port:0,policy:{maxTaskRecords:4096,grants:{master:{tools:['echo'],maxTasksPerMinute:10000}}}};
    let servant=await startNode(directory,servantConfig);nodes.push(servant);
    const masterConfig={id:'master',port:0,agent:'deterministic-demo',peers:[peer(servant)],policy:{maxTaskRecords:4096}};
    let master=await startNode(directory,masterConfig);nodes.push(master);await waitConnected(master,'servant');
    const task=index=>({taskId:`capacity_${index}`,tool:'echo',args:{text:`payload-${index}`},timeoutMs:1000});
    for(let index=0;index<4100;index++) {
      const result=await master.command({command:'dispatch',peerId:'servant',task:task(index)});
      assert.equal(result.ok,true,`operator ${index}: ${JSON.stringify(result.error)}`);
      assert.equal(result.result.status,'ok',`task ${index}: ${JSON.stringify(result.result.error)}`);
      assert.equal(result.result.result.text,`payload-${index}`);
    }
    const beforeMaster=(await master.command({command:'status'})).result.outgoing;
    const beforeServant=(await servant.command({command:'status'})).result.incoming;
    assert.ok(beforeMaster.retiredCount>=1024);assert.ok(beforeServant.retiredCount>=1024);
    assert.ok(beforeMaster.records<=4096);assert.ok(beforeServant.records<=4096);
    const servantPort=servant.port;
    await master.stop();await servant.stop();
    servant=await startNode(directory,{...servantConfig,port:servantPort});nodes.push(servant);
    master=await startNode(directory,masterConfig);nodes.push(master);await waitConnected(master,'servant');
    assert.equal((await master.command({command:'dispatch',peerId:'servant',task:task(0)})).error.code,'TASK_HISTORY_EXPIRED');
    assert.equal((await master.command({command:'query',peerId:'servant',taskId:'capacity_0'})).result.state,'expired');
    assert.equal(servant.events.some(event=>event.event==='task_started'),false);
    assert.equal((await master.command({command:'dispatch',peerId:'servant',task:task(4100)})).result.status,'ok');
    t.diagnostic(`Verified 4100 successful mTLS tasks before restart; retained ${beforeMaster.records}/${beforeServant.records}, retired ${beforeMaster.retiredCount}/${beforeServant.retiredCount}; old ID rejected and new ID accepted after restart`);
  } finally {await stopAll(nodes);await fs.rm(directory,{recursive:true,force:true});}
});
