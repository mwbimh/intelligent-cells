import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { startOperator } from '../src/operator.mjs';
import { makeWorkspace, testSecurity } from '../scripts/process-helper.mjs';

const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const ipcCall=(socketPath,command)=>new Promise((resolve,reject)=>{const socket=net.connect(socketPath);let data='';socket.on('error',reject);socket.on('data',chunk=>data+=chunk);socket.on('end',()=>{try{resolve(JSON.parse(data));}catch(error){reject(error);}});socket.on('connect',()=>socket.write(JSON.stringify(command)+'\n'));});

test('v0.3 independent operator audit: owner session/Host/Origin/CSRF protect every state or command path', {timeout:15000},async t=>{
 const dir=await makeWorkspace('audit-v03-owner-');const calls=[];let operator;
 try{
  const raw=await testSecurity(dir,'owner',[]);
  const node={config:{id:'owner',security:{cert:await fs.readFile(raw.cert),ca:await fs.readFile(raw.ca),trustedPeers:new Map()}},peers:new Map(),inbound:new Set(),log(){},async command(value){calls.push(structuredClone(value));if(value.command==='status')return{id:'owner',peers:[],durable:true};if(value.command==='permissions')return{grants:{}};if(value.command==='listTasks')return{records:[]};return{applied:true};}};
  const socketPath=path.join(dir,'operator','owner.sock');
  operator=await startOperator(node,{host:'127.0.0.1',port:0,sessionTtlMs:1000});
  let origin=operator.url;
  const request=(route,{method='GET',body,headers={}}={})=>new Promise((resolve,reject)=>{const content=body?JSON.stringify(body):undefined;const req=http.request(new URL(origin+route),{method,headers:{...(content?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(content)}:{}),...headers}},res=>{let text='';res.on('data',chunk=>text+=chunk);res.on('end',()=>{let data;try{data=JSON.parse(text);}catch{}resolve({response:{status:res.statusCode,headers:{get:key=>{const value=res.headers[key.toLowerCase()];return Array.isArray(value)?value.join(';'):value;}}},data});});});req.on('error',reject);req.end(content);});
  const staticPage=await fetch(origin+'/');assert.equal(staticPage.status,200);assert.doesNotMatch(await staticPage.text(),new RegExp(operator.bootstrapToken));
  assert.match(staticPage.headers.get('content-security-policy'),/frame-ancestors 'none'/);assert.equal(staticPage.headers.get('cache-control'),'no-store');
  assert.equal((await request('/api/state')).response.status,403);
  for(const headers of [{Origin:'https://attacker.invalid'},{Origin:origin,Host:'attacker.invalid'},{Origin:origin,'Sec-Fetch-Site':'cross-site'},{}]){
    assert.equal((await request('/api/session',{method:'POST',body:{token:operator.bootstrapToken},headers})).response.status,403);
  }
  assert.equal(calls.length,0);
  const login=await request('/api/session',{method:'POST',body:{token:operator.bootstrapToken},headers:{Origin:origin}});
  assert.equal(login.response.status,200);
  const setCookie=login.response.headers.get('set-cookie');assert.match(setCookie,/HttpOnly/);assert.match(setCookie,/SameSite=Strict/);
  const Cookie=setCookie.split(';')[0], csrf=login.data.csrf;
  assert.equal((await request('/api/session',{method:'POST',body:{token:operator.bootstrapToken},headers:{Origin:origin}})).response.status,403);
  assert.equal((await request('/api/state',{headers:{Cookie}})).response.status,200);
  calls.length=0;
  await t.test('cookie alone, wrong origin/host/csrf and simple cross-origin forms cannot mutate',async()=>{
   for(const headers of [{Cookie,Origin:origin},{Cookie,Origin:origin,'X-Operator-CSRF':'wrong'},{Cookie,Origin:'https://attacker.invalid','X-Operator-CSRF':csrf},{Cookie,Origin:origin,Host:'attacker.invalid','X-Operator-CSRF':csrf},{Cookie,'X-Operator-CSRF':csrf}]){
    assert.equal((await request('/api/command',{method:'POST',body:{command:'setPolicy',policy:{grants:{}},expectedEpoch:0},headers})).response.status,403);
   }
   const simple=await fetch(origin+'/api/command',{method:'POST',headers:{Origin:origin,Cookie,'X-Operator-CSRF':csrf,'Content-Type':'text/plain'},body:JSON.stringify({command:'setPolicy',policy:{grants:{}},expectedEpoch:0})});assert.equal(simple.status,400);
   assert.equal(calls.length,0);
  });
  await t.test('valid owner command succeeds once; tool-dispatch and injected JavaScript are not API commands',async()=>{
   assert.equal((await request('/api/command',{method:'POST',body:{command:'setPolicy',policy:{grants:{}},expectedEpoch:0},headers:{Cookie,Origin:origin,'X-Operator-CSRF':csrf}})).response.status,200);
   assert.equal(calls.length,1);assert.equal(calls[0].command,'setPolicy');
   for(const command of ['dispatch','exec','eval'])assert.equal((await request('/api/command',{method:'POST',body:{command},headers:{Cookie,Origin:origin,'X-Operator-CSRF':csrf}})).data.error.code,'INVALID_COMMAND');
   assert.equal(calls.length,1);
  });
  await t.test('owner-only Unix IPC only mints session bootstrap, not arbitrary commands',async sub=>{
   let ipcOperator;try{try{ipcOperator=await startOperator(node,{host:'127.0.0.1',port:0,socketPath});}catch(error){if(error.code==='EPERM'){sub.skip('This executor denies Unix socket bind (EPERM), including approved unsandboxed test; IPC is unverified');return;}throw error;}
   assert.equal((await fs.stat(path.dirname(socketPath))).mode&0o077,0);assert.equal((await fs.stat(socketPath)).mode&0o077,0);
   const minted=await ipcCall(socketPath,{command:'operatorSession'});assert.ok(minted.url.startsWith(ipcOperator.url+'/#token='));
   assert.equal((await ipcCall(socketPath,{command:'setPolicy',policy:{grants:{}},expectedEpoch:0})).error,'Invalid owner IPC command');
   assert.equal(calls.length,1);
   }finally{await ipcOperator?.close();}
  });
  await t.test('session expiry and logout actually revoke cookie access',async()=>{
   await pause(1050);assert.equal((await request('/api/state',{headers:{Cookie}})).response.status,403);
   await operator.close();operator=await startOperator(node,{host:'127.0.0.1',port:0,sessionTtlMs:1000});origin=operator.url;
   const next=await request('/api/session',{method:'POST',body:{token:operator.bootstrapToken},headers:{Origin:origin}}),cookie2=next.response.headers.get('set-cookie').split(';')[0];
   assert.equal((await request('/api/logout',{method:'POST',body:{},headers:{Cookie:cookie2,Origin:origin,'X-Operator-CSRF':next.data.csrf}})).response.status,200);
   assert.equal((await request('/api/state',{headers:{Cookie:cookie2}})).response.status,403);
  });
 }finally{await operator?.close();await fs.rm(dir,{recursive:true,force:true});}
});
