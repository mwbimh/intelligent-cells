import test from 'node:test';
import assert from 'node:assert/strict';
import { effectivePolicy, validRelativePath, validateDirectories, fileAccess, buildGrant, filterRecords, taskCommand, scopeLabel } from '../ui/app.js';
import { directoryAccess } from '../src/directory-policy.mjs';

const rules = [{ path:'',read:true,write:false },{ path:'work',read:true,write:true },{ path:'work/private',read:false,write:false },{ path:'work/private/public',read:true,write:false }];
const grant = { workspace:'/srv/work',tools:['readFile','readChunk','writeFile','writeChunk','editFile','mkdir','listDirectory','searchFiles'],directories:rules };
const form = { workspace:'/srv/work',tools:['readFile'],mode:'scoped',directories:[{path:'docs',read:true,write:false}],allowUnsandboxed:false,maxConcurrent:1,maxTimeoutMs:2000,extra:'{}',commands:'{}' };

test('control page: effective policy excludes revoked peers without mutating backend state',()=>{
 const state={permissions:{policy:{grants:{alpha:grant,beta:grant}},revoked:['alpha']}};
 const value=effectivePolicy(state); assert.deepEqual(Object.keys(value.grants),['beta']); assert.ok(state.permissions.policy.grants.alpha); value.grants.beta.tools=[]; assert.notEqual(value.grants.beta.tools.length,state.permissions.policy.grants.beta.tools.length);
});
test('control page: strict relative directory paths, deny rules, duplicates and root semantics',()=>{
 for(const path of ['../secret','docs/../secret','/root','docs/','docs//a','a\\b','C:foo','a\0b','docs.','docs ','CON','docs/NUL.txt'])assert.equal(validRelativePath(path,true),false,path);
 assert.equal(validRelativePath('',true),true);assert.equal(validRelativePath(''),false);assert.equal(validRelativePath('资料/文档'),true);
 assert.throws(()=>validateDirectories([...rules,rules[0]]),/重复/);assert.throws(()=>validateDirectories([{path:'docs',read:true}]),/读写/);
 assert.deepEqual(validateDirectories([{path:'',read:false,write:false}]),[{path:'',read:false,write:false}]);assert.equal(scopeLabel({read:false,write:true}),'仅写入');
});
test('control page: file preview agrees with core directory ACL for nested and sibling file paths',()=>{
 for(const tool of grant.tools)for(const name of ['root.txt','work/a.txt','work/private/a.txt','work/private/public/a.txt','worker/a.txt','work','work/private','']){
  const directory=['listDirectory','searchFiles','mkdir'].includes(tool),reads=['readFile','readChunk','editFile','listDirectory','searchFiles'].includes(tool),writes=['writeFile','writeChunk','editFile','mkdir'].includes(tool);
  if(!validRelativePath(name,['listDirectory','searchFiles'].includes(tool)))continue;
  const expected=(!reads||directoryAccess(grant,name,'read',directory))&&(!writes||directoryAccess(grant,name,'write',directory));assert.equal(fileAccess(grant,tool,name).allowed,expected,`${tool} ${name}`);
 }
 assert.equal(fileAccess(grant,'mkdir','').allowed,false);
 assert.equal(fileAccess({...grant,tools:['writeFile']},'readFile','work/a').allowed,false);
 assert.equal(fileAccess({...grant,directories:[]},'readFile','root.txt').allowed,false);
 const legacy={...grant};delete legacy.directories;assert.equal(fileAccess(legacy,'writeFile','any/file').allowed,true);
 assert.equal(fileAccess({...grant,directories:[{path:'work',read:false,write:true}]},'editFile','work/a').allowed,false);
 assert.equal(fileAccess(grant,'readFile','work/private').allowed,true,'a file named private belongs to work; directory rule applies to directories');
});
test('control page: new scoped grant never inherits broad access, explicit empty list denies paths',()=>{
 const next=buildGrant(undefined,{...form,directories:[]});assert.deepEqual(next.directories,[]);assert.equal(next.allowUnsandboxedProcesses,false);
 const managed=buildGrant(undefined,{...form,workspace:'',tools:['workspaceList','workspaceCreate'],mode:'none'});assert.equal(Object.hasOwn(managed,'workspace'),false);assert.equal(Object.hasOwn(managed,'directories'),false);
 const legacy=buildGrant(grant,{...form,mode:'legacy'});assert.equal(Object.hasOwn(legacy,'directories'),false);
});
test('control page: process exception requires explicit acknowledgement and does not auto-enable',()=>{
 for(const tool of ['exec','mcpList','mcpCall']){
  assert.throws(()=>buildGrant(undefined,{...form,tools:[tool]}),/勾选/);
  const acknowledged=buildGrant(undefined,{...form,tools:[tool],allowUnsandboxed:true});assert.equal(acknowledged.allowUnsandboxedProcesses,true);
 }
 assert.throws(()=>buildGrant(undefined,{...form,workspace:''}),/工作区/);
});
test('control page: advanced settings preserved, malformed objects and shadowed managed fields fail',()=>{
 const saved=buildGrant({...grant,maxReadBytes:4096,resources:{guide:{path:'docs/a'}}},form);assert.equal(saved.maxReadBytes,4096);assert.deepEqual(saved.resources,{guide:{path:'docs/a'}});
 for(const extra of ['[]','null','"text"','{bad'])assert.throws(()=>buildGrant(undefined,{...form,extra}));
 for(const field of ['tools','directories','workspace','allowUnsandboxedProcesses','maxTimeoutMs'])assert.throws(()=>buildGrant(undefined,{...form,extra:JSON.stringify({[field]:true})}),/重复定义/);
 assert.throws(()=>buildGrant(undefined,{...form,maxConcurrent:1.5}),/整数/);assert.throws(()=>buildGrant(undefined,{...form,maxTimeoutMs:0}),/整数/);
});
test('control page: task command routing, cancellation and recovery never trigger a replay',()=>{
 const input={direction:'incoming',action:'cancel',peer:'master',taskId:'task-1'};assert.deepEqual(taskCommand(input),{command:'cancelTask',masterId:'master',taskId:'task-1'});
 assert.equal(taskCommand({...input,direction:'outgoing'}).command,'cancel');
 assert.throws(()=>taskCommand({...input,action:'query'}),/远端查询/);assert.throws(()=>taskCommand({...input,direction:'outgoing',action:'events'}),/事件查询/);
 assert.throws(()=>taskCommand({...input,action:'reconcile',resolution:'completed',note:' '}),/证据/);
 const value=taskCommand({...input,action:'reconcile',resolution:'not_applied',note:'  独立核对无修改  '});assert.equal(value.command,'reconcile');assert.equal(value.note,'独立核对无修改');assert.equal(value.resolution,'not_applied');assert.ok(!('args' in value));
});
test('control page: loaded record filters distinguish unknown, active and terminal states',()=>{
 assert.equal(filterRecords([{taskId:'x',state:'dispatching'},{taskId:'y',state:'pending'}],'active').length,2);
 const rows=[{taskId:'a',state:'unknown',peerId:'Alpha'},{taskId:'b',state:'running',masterId:'beta'},{taskId:'c',state:'succeeded',tool:'readFile'}];
 assert.deepEqual(filterRecords(rows,'unknown').map(r=>r.taskId),['a']);assert.deepEqual(filterRecords(rows,'active').map(r=>r.taskId),['b']);assert.deepEqual(filterRecords(rows,'finished').map(r=>r.taskId),['c']);assert.deepEqual(filterRecords(rows,'all','READfile').map(r=>r.taskId),['c']);
});
