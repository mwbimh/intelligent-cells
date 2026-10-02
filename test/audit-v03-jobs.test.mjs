import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { JobManager } from '../src/jobs.mjs';

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(check, timeout = 3000) { const end = Date.now()+timeout; while(Date.now()<end) { const result=await check(); if(result)return result; await pause(10); } throw new Error('Audit observation timed out'); }
async function running(pid) { try { process.kill(pid,0); } catch(error) { if(error.code==='ESRCH')return false; throw error; } try { return !/\) Z /.test(await fs.readFile(`/proc/${pid}/stat`,'utf8')); } catch(error) { if(error.code==='ENOENT')return false; throw error; } }

test('v0.3 independent job audit: output separation/stdin ownership and POSIX descendant cancellation', { timeout: 15000 }, async t => {
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'audit-v03-jobs-')), root=path.join(dir,'workspace'), script=path.join(dir,'trusted.mjs');
  await fs.mkdir(root);
  await fs.writeFile(script,`import {spawn} from 'node:child_process';
const mode=process.argv[2]; if(mode==='stdin'){process.stdin.setEncoding('utf8');process.stdin.on('data',x=>process.stdout.write('reply:'+x));process.stdin.on('end',()=>process.exit(0));process.stderr.write('stderr-marker\\n');}
else if(mode==='tree'){const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});console.log(JSON.stringify({parent:process.pid,child:c.pid}));setInterval(()=>{},1000);}
else console.log('completed');\n`);
  const events=[], manager=new JobManager({stateDir:path.join(dir,'jobs'),onOutput:event=>events.push(event)});
  const policy={root,allowedMasters:new Set(['master']),maxConcurrent:2,maxTimeoutMs:5000,maxJobTimeoutMs:10000,maxOutputBytes:16384,maxOutputPageBytes:16384,maxJobs:32,execCommands:new Map([
    ['stdin',{file:process.execPath,args:[script,'stdin'],env:{},stdinAllowed:true,maxStdinBytes:32}],
    ['tree',{file:process.execPath,args:[script,'tree'],env:{}}],
    ['simple',{file:process.execPath,args:[script,'simple'],env:{}}],
  ])};
  const run=command=>manager.run({tool:'exec',timeoutMs:5000,args:{command,args:[],background:true}},policy,new AbortController().signal,{masterId:'master',runId:'run1'});
  try {
    await t.test('only authenticated job owner can read output, write stdin or cancel',async()=>{
      const job=await run('stdin');
      await until(()=>events.some(event=>event.jobId===job.jobId&&event.stream==='stderr'));
      assert.throws(()=>manager.status('other',job.jobId),error=>error.code==='JOB_NOT_FOUND');
      await assert.rejects(manager.output('other',{jobId:job.jobId}),error=>error.code==='JOB_NOT_FOUND');
      await assert.rejects(manager.stdin('other',{jobId:job.jobId,text:'bad'},policy),error=>error.code==='JOB_NOT_FOUND');
      await assert.rejects(manager.cancel('other',job.jobId),error=>error.code==='JOB_NOT_FOUND');
      await manager.stdin('master',{jobId:job.jobId,text:'approved input\n',eof:true},policy);
      await until(()=>manager.status('master',job.jobId).state==='succeeded');
      assert.equal((await manager.output('master',{jobId:job.jobId,stream:'stdout'})).text,'reply:approved input\n');
      assert.equal((await manager.output('master',{jobId:job.jobId,stream:'stderr'})).text,'stderr-marker\n');
      const collected=events.filter(event=>event.jobId===job.jobId);
      assert.deepEqual(collected.map(event=>event.seq),collected.map((_,i)=>i));
      for(const event of collected)assert.equal(Buffer.from(event.base64,'base64').length,event.bytes);
    });
    await t.test('cancel actually stops both direct process and child in its process group',async()=>{
      const job=await run('tree');
      const output=await until(async()=>{const data=await manager.output('master',{jobId:job.jobId,stream:'stdout'});return data.text.includes('\n')&&data.text;});
      const pids=JSON.parse(output.trim());assert.notEqual(pids.parent,pids.child);
      assert.equal(await running(pids.parent),true);assert.equal(await running(pids.child),true);
      assert.equal((await manager.cancel('master',job.jobId)).accepted,true);
      await until(async()=>!await running(pids.parent)&&!await running(pids.child));
      assert.equal(manager.status('master',job.jobId).state,'cancelled');
      assert.equal((await manager.cancel('master',job.jobId)).accepted,false);
      assert.equal(manager.status('master',job.jobId).outcomeUnknown,true);
      await manager.reconcileJob({masterId:'master',jobId:job.jobId,resolution:'completed',note:'Verified both fixture processes stopped and no external effects occurred'});
    });
    await t.test('terminal job retention allows repeated commands beyond configured maxJobs',async()=>{
      const bounded={...policy,maxJobs:2};
      for(let i=0;i<8;i++){const result=await manager.run({tool:'exec',timeoutMs:5000,args:{command:'simple',args:[]}},bounded,new AbortController().signal,{masterId:'master',runId:'retention_run'});assert.equal(result.exitCode,0);}
      assert.ok([...manager.jobs.values()].filter(job=>job.masterId==='master').length<=2);
    });
    await t.test('live output cannot expose another job file by crafted jobId',async()=>{
      for(const jobId of ['../trusted.mjs','/etc/passwd','x.combined',''])await assert.rejects(manager.output('master',{jobId}),error=>error.code==='JOB_NOT_FOUND');
    });
  } finally {await manager.shutdown();await fs.rm(dir,{recursive:true,force:true});}
});
