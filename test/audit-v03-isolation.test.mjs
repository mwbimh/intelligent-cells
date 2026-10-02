import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { makeWorkspace, testSecurity } from '../scripts/process-helper.mjs';
import { loadConfig } from '../src/config.mjs';

test('v0.3 independent isolation audit: remote writable paths cannot contain state, config, TLS credentials or audit logs',async()=>{
 const dir=await makeWorkspace('audit-v03-isolation-');
 try{
  const security=await testSecurity(dir,'servant',['master']), filename=path.join(dir,'node.json');
  const base={id:'servant',port:0,security,stateDir:path.join(dir,'state'),policy:{grants:{master:{tools:['readFile','writeFile'],workspace:'workspace'}}}};
  await fs.writeFile(filename,JSON.stringify(base));await loadConfig(filename);
  for(const raw of [
   {...base,stateDir:path.join(dir,'workspace','state')},
   {...base,policy:{grants:{master:{tools:['writeFile'],workspace:'.'}}}},
   {...base,policy:{grants:{master:{tools:['writeFile'],workspace:'identities'}}}},
   {...base,logFile:path.join(dir,'workspace','audit.jsonl')},
   {...base,policy:{grants:{master:{tools:['readFile'],workspace:'.'}}}},
   {...base,policy:{grants:{master:{tools:['readChunk'],workspace:'identities'}}}},
   {...base,operator:{enabled:true,sessionDirectory:path.join(dir,'workspace','owner-sessions')}},
  ]){
   await fs.writeFile(filename,JSON.stringify(raw));await assert.rejects(loadConfig(filename),error=>error.code==='UNSAFE_STATE_POLICY');
  }
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});

test('v0.3 independent isolation audit: symlink config alias cannot conceal writable protected configuration',async()=>{
 const dir=await makeWorkspace('audit-v03-config-alias-');
 try{
  const security=await testSecurity(dir,'servant',['master']),target=path.join(dir,'workspace','node.json'),alias=path.join(dir,'alias.json');
  const raw={id:'servant',port:0,security,stateDir:path.join(dir,'state'),policy:{grants:{master:{tools:['writeFile'],workspace:path.join(dir,'workspace')}}}};
  await fs.writeFile(target,JSON.stringify(raw));await fs.symlink(target,alias);
  await assert.rejects(loadConfig(alias),error=>['UNSAFE_STATE_POLICY','UNSAFE_CONFIG_FILE','INVALID_CONFIG'].includes(error.code));
 }finally{await fs.rm(dir,{recursive:true,force:true});}
});
