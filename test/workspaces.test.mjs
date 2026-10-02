import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { loadPolicy, validatePolicyIsolation } from '../src/config.mjs';
import { WorkspaceRegistry, directoryIdentity, workspaceHash } from '../src/workspaces.mjs';
import { readChecked, writeChecked } from '../src/durable.mjs';
import { IntelligentCell } from '../src/node.mjs';
import { runTool } from '../src/tools.mjs';

const directories = [{path:'',read:true,write:true}];
const template = () => ({tools:['capabilities','readFile','writeFile','mkdir','listDirectory'],directories});
async function fixture(t, maxWorkspaces = 3) {
  const dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'workspace-registry-')));
  for (const name of ['pool','named','state']) await fs.mkdir(path.join(dir,name),{mode:0o700});
  t.after(()=>fs.rm(dir,{recursive:true,force:true}));
  const raw = { grants: { master: { tools: ['workspaceList','workspaceCreate'], workspaces: { reference: { tools: ['readFile'], workspace: 'named', directories: [{path:'',read:true,write:false}] } } } } };
  raw.grants.master.workspaceProvisioning={roots:{projects:{path:'pool',maxWorkspaces,grant:template()}}};
  const policy=await loadPolicy(raw,dir);
  const node={config:{id:'servant',stateDir:path.join(dir,'state'),policy},storageFailed:false,assertStorage(){assert.equal(this.storageFailed,false);}};
  const registry=new WorkspaceRegistry(node).open(); node.workspaceRegistry=registry;
  return {dir,raw,node,registry};
}
const create=(registry,name='alpha',requestId='request_alpha')=>registry.create('master',{rootId:'projects',name,requestId},new AbortController().signal);

test('workspace policy: separate defaults, explicit provisioning rights and full nested grants compile without a default workspace', async t=>{
  const {dir,raw,node}=await fixture(t);
  const parent=node.config.policy.grants.get('master');
  assert.equal(parent.root,null);assert.equal(parent.tools.has('writeFile'),false);
  assert.equal(parent.workspaceProvisioning.get('projects').grant.tools.has('writeFile'),true);
  for(const change of [r=>delete r.grants.master.workspaceProvisioning.roots.projects.grant.directories,r=>delete r.grants.master.workspaceProvisioning.roots.projects.grant.tools,r=>r.grants.master.workspaceProvisioning.roots.projects.maxWorkspaces=0,r=>r.grants.master.workspaceProvisioning.roots.projects.maxWorkspaces=129,r=>r.grants.master.workspaceProvisioning.roots.projects.grant.workspace='named',r=>r.grants.master.workspaceProvisioning.roots.projects.grant.tools.push('workspaceCreate'),r=>r.grants.master.workspaces.default=r.grants.master.workspaces.reference,r=>r.grants.master.workspaces.ws_reserved=r.grants.master.workspaces.reference]){
    const invalid=structuredClone(raw);change(invalid);await assert.rejects(loadPolicy(invalid,dir),{code:'INVALID_CONFIG'});
  }
});

test('workspace policy: provisioning roots are disjoint from configured workspaces, other roots, protected state and executable code', async t=>{
  const {dir,raw,node}=await fixture(t);
  const overlap=structuredClone(raw);overlap.grants.master.workspaceProvisioning.roots.projects.path='named';
  await assert.rejects(loadPolicy(overlap,dir),{code:'INVALID_CONFIG'});
  const duplicate=structuredClone(raw);duplicate.grants.observer=structuredClone(duplicate.grants.master);
  await assert.rejects(loadPolicy(duplicate,dir),{code:'INVALID_CONFIG'});
  const protectedConfig={filename:path.join(dir,'config.json'),stateDir:path.join(dir,'pool'),securityFiles:[]};
  assert.throws(()=>validatePolicyIsolation(node.config.policy,protectedConfig),{code:'UNSAFE_STATE_POLICY'});
  const approved=path.join(dir,'pool','approved-empty.mjs');await fs.writeFile(approved,'');
  const command={file:process.execPath,args:[approved]};
  for(const type of ['exec','mcp']){
    const config=structuredClone(raw),grant=config.grants.master.workspaces.reference;
    grant.tools=[type==='exec'?'exec':'mcpList'];grant.allowUnsandboxedProcesses=true;
    if(type==='exec')grant.execCommands={approved:command};else grant.mcpServers={approved:{...command,trusted:true,tools:{}}};
    await assert.rejects(loadPolicy(config,dir),{code:type==='exec'?'UNSAFE_EXEC_POLICY':'UNSAFE_MCP_POLICY'});
  }
});

test('workspace registry: create commits stable peer-owned IDs, inherited ACL, catalog without paths, retry before quota and restart persistence', async t=>{
  const {dir,registry,node}=await fixture(t,1);
  const created=create(registry);assert.match(created.id,/^ws_/);assert.equal(created.name,'alpha');
  const grant=registry.resolve('master',created.id);
  await runTool({taskId:'write',tool:'writeFile',args:{path:'result.txt',text:'workspace owned'},timeoutMs:1000},grant);
  assert.equal(await fs.readFile(path.join(dir,'pool','alpha','result.txt'),'utf8'),'workspace owned');
  assert.deepEqual(create(registry),created);
  assert.throws(()=>create(registry,'beta','request_beta'),{code:'WORKSPACE_QUOTA'});
  assert.throws(()=>create(registry,'beta','request_alpha'),{code:'WORKSPACE_REQUEST_CONFLICT'});
  assert.throws(()=>registry.resolve('other',created.id),{code:'MASTER_DENIED'});
  assert.equal(JSON.stringify(registry.catalog('master')).includes(dir),false);
  registry.bind('servant','logical',created.id,0);registry.setAuto('servant','logical','projects',true,1);
  const reopened=new WorkspaceRegistry(node).open();assert.deepEqual(reopened.snapshot(),registry.snapshot());
  assert.equal(reopened.resolve('master',created.id).root,path.join(dir,'pool','alpha'));
});

test('workspace registry: durable intent without identity stays unknown, consumes quota and requires owner reconciliation without replay', async t=>{
  const {dir,registry,node}=await fixture(t,1);
  const state=readChecked(registry.filename),root=node.config.policy.grants.get('master').workspaceProvisioning.get('projects');
  state.creations.push({id:'ws_interrupted',masterId:'master',rootId:'projects',requestId:'intent_request',name:'interrupted',parent:root.path,parentIdentity:root.identity,templateHash:root.templateHash,state:'intent',createdAt:Date.now()});
  await fs.mkdir(path.join(dir,'pool','interrupted'),{mode:0o700});writeChecked(registry.filename,state);
  const reopened=new WorkspaceRegistry(node).open();
  assert.equal(reopened.snapshot().creations[0].state,'unknown');
  assert.equal(reopened.catalog('master').creationRoots[0].remaining,0);
  assert.throws(()=>reopened.resolve('master','ws_interrupted'),{code:'WORKSPACE_DENIED'});
  assert.throws(()=>create(reopened,'interrupted','intent_request'),{code:'WORKSPACE_CREATE_UNKNOWN'});
  assert.throws(()=>create(reopened,'different','new_request'),{code:'WORKSPACE_QUOTA'});
  assert.throws(()=>reopened.reconcile({workspaceId:'ws_interrupted',masterId:'master',resolution:'not_created',note:'Synthetic owner check'}),{code:'WORKSPACE_DENIED'});
  reopened.reconcile({workspaceId:'ws_interrupted',masterId:'master',resolution:'completed',note:'Synthetic owner inspected empty created directory'});
  assert.equal(reopened.resolve('master','ws_interrupted').root,path.join(dir,'pool','interrupted'));
});

test('workspace registry: proven created identity recovers once; absent intent can be owner-resolved without permitting the same request to run', async t=>{
  const {dir,registry,node}=await fixture(t,2);
  const created=create(registry),state=readChecked(registry.filename);state.creations[0].state='created';writeChecked(registry.filename,state);
  const reopened=new WorkspaceRegistry(node).open();assert.equal(reopened.resolve('master',created.id).root,path.join(dir,'pool','alpha'));
  const root=node.config.policy.grants.get('master').workspaceProvisioning.get('projects'),next=readChecked(registry.filename);
  next.creations.push({id:'ws_absent',masterId:'master',rootId:'projects',requestId:'absent_request',name:'absent',parent:root.path,parentIdentity:root.identity,templateHash:root.templateHash,state:'intent',createdAt:Date.now()});writeChecked(registry.filename,next);
  const missing=new WorkspaceRegistry(node).open();missing.reconcile({workspaceId:'ws_absent',masterId:'master',resolution:'not_created',note:'Owner verified no directory exists'});
  assert.equal(missing.catalog('master').creationRoots[0].remaining,1);
  assert.throws(()=>create(missing,'absent','absent_request'),{code:'WORKSPACE_NAME_CONFLICT'});
  await assert.rejects(fs.stat(path.join(dir,'pool','absent')),{code:'ENOENT'});
});

test('workspace registry: changed defaults/revoked roots deny old provisioned IDs instead of silently changing grants', async t=>{
  const {dir,raw,node,registry}=await fixture(t);const created=create(registry);
  const narrowed=structuredClone(raw);narrowed.grants.master.workspaceProvisioning.roots.projects.grant.directories=[{path:'',read:true,write:false}];node.config.policy=await loadPolicy(narrowed,dir);
  assert.throws(()=>registry.resolve('master',created.id),{code:'WORKSPACE_DENIED'});
  assert.equal(registry.catalog('master').workspaces.find(item=>item.id===created.id).state,'unavailable');
  node.config.policy=await loadPolicy(raw,dir);assert.equal(registry.resolve('master',created.id).tools.has('writeFile'),true);
  const noCreation=structuredClone(raw);noCreation.grants.master.tools=['workspaceList'];node.config.policy=await loadPolicy(noCreation,dir);
  assert.equal(registry.resolve('master',created.id).tools.has('writeFile'),true);
  assert.throws(()=>create(registry,'new','new_request'),{code:'WORKSPACE_CREATE_DENIED'});
});

test('workspace automatic selection: concurrent distinct mappings do not conflict on unrelated global revisions', async t=>{
  const {registry}=await fixture(t);
  registry.setAuto('servant','alpha','projects',true);registry.setAuto('servant','beta','projects',true);
  let created=0;
  const node={config:{id:'master'},workspaceRegistry:registry,workspaceEnsures:new Map(),peers:new Map([['servant',{}]]),ledger:{get(){return undefined;}},validateBindingTarget:IntelligentCell.prototype.validateBindingTarget,remoteWorkspaces:async()=>({workspaces:[]}),createWorkspace:async command=>{created++;await new Promise(resolve=>setTimeout(resolve,10));return{workspace:{id:`ws_${command.name}`}};}};
  const ensure=(id)=>IntelligentCell.prototype.ensureWorkspaceBinding.call(node,'servant',id);
  const [a,a2,b]=await Promise.all([ensure('alpha'),ensure('alpha'),ensure('beta')]);
  assert.equal(a.workspaceId,a2.workspaceId);assert.notEqual(a.workspaceId,b.workspaceId);assert.equal(created,2);assert.equal(registry.snapshot().bindings.length,2);
});

test('workspace provisioning: MCP configured working directory is relocated to the selected child while approved code remains fixed', async t=>{
  const {dir,raw,node,registry}=await fixture(t);const script=path.join(dir,'approved-empty.mjs');await fs.writeFile(script,'');
  const grant=raw.grants.master.workspaceProvisioning.roots.projects.grant;
  grant.tools.push('mcpList');grant.allowUnsandboxedProcesses=true;grant.mcpServers={approved:{file:process.execPath,args:[script],trusted:true,tools:{}}};
  node.config.policy=await loadPolicy(raw,dir);const created=create(registry);const resolved=registry.resolve('master',created.id);
  assert.equal(resolved.mcpServers.get('approved').root,path.join(dir,'pool','alpha'));
  assert.deepEqual(resolved.mcpServers.get('approved').args,[script]);
  assert.equal(node.config.policy.grants.get('master').workspaceProvisioning.get('projects').grant.mcpServers.get('approved').root,path.join(dir,'pool'));
});
