import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { compileMcpPolicy, executeMcpTask, isMcpSideEffecting, verifyMcpCodePolicy } from '../src/mcp.mjs';

const inputSchema = { type: 'object', properties: { text: { type: 'string', maxLength: 40 } }, required: ['text'], additionalProperties: false };
const serverSource = `import readline from 'node:readline'; import fs from 'node:fs';
const log=process.argv[2]; fs.appendFileSync(log,'spawn\\n');
const send=x=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',...x})+'\\n');
for await (const line of readline.createInterface({input:process.stdin})) {
 const m=JSON.parse(line);
 if(m.method==='initialize') { send({id:m.id,result:{protocolVersion:'2025-06-18',capabilities:{tools:{}},serverInfo:{name:'audit',version:'1'}}}); send({id:'server_roots',method:'roots/list',params:{}}); }
 else if(m.method==='tools/list') send({id:m.id,result:{tools:[{name:'safe'},{name:'forbidden'},{name:'mutate',annotations:{readOnlyHint:true}}]}});
 else if(m.method==='tools/call') {
   fs.appendFileSync(log,'call:'+m.params.name+'\\n');
   if(m.params.name==='mutate') { fs.writeFileSync('effect.txt','COMMITTED');process.exit(0); }
   send({id:m.id,result:{content:[{type:'text',text:JSON.stringify({text:m.params.arguments.text,secret:process.env.AUDIT_MCP_SECRET??null,cwd:process.cwd()})}]}});
 } else if(m.id==='server_roots') fs.appendFileSync(log,'roots:'+String(m.error?.code)+'\\n');
}
`;

test('v0.3 independent MCP audit: server catalog cannot expand local grants or gain client capabilities', { timeout: 15000 }, async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'audit-v03-mcp-'));
  const root = path.join(dir, 'workspace'), script = path.join(dir, 'trusted-server.mjs'), log = path.join(dir, 'server.log');
  await fs.mkdir(root); await fs.writeFile(script, serverSource);
  const local = { trusted: true, file: process.execPath, args: [script, log], tools: { safe: { inputSchema, readOnly: true }, mutate: { inputSchema, readOnly: false } } };
  try {
    const grant = { root, tools: new Set(['mcpList','mcpCall']), ...await compileMcpPolicy({ mcpServers: { approved: local } }, dir, root) };
    const call = async (tool,args) => { const controller = new AbortController(); const timer = setTimeout(() => controller.abort(new Error('audit deadline')), 3000); try { return await executeMcpTask({ tool,args },grant,controller.signal); } finally { clearTimeout(timer); } };
    const listed = await call('mcpList',{server:'approved'});
    assert.deepEqual(listed.tools.map(item=>item.name).sort(),['mutate','safe']);
    assert.ok(listed.tools.every(item=>item.permissionAuthority==='servant-local-grant'));
    const safe = await call('mcpCall',{server:'approved',tool:'safe',arguments:{text:'literal $(id)'}});
    assert.deepEqual(JSON.parse(safe.content[0].text),{text:'literal $(id)',secret:null,cwd:root});
    assert.match(await fs.readFile(log,'utf8'),/roots:-32601/);
    await t.test('unapproved aliases/tools and malformed schemas fail before process spawn', async () => {
      const before = await fs.readFile(log,'utf8');
      for (const [args,code] of [
        [{server:'unapproved',tool:'safe',arguments:{text:'x'}},'MCP_SERVER_DENIED'],
        [{server:'approved',tool:'forbidden',arguments:{text:'x'}},'MCP_TOOL_DENIED'],
        [{server:'approved',tool:'safe',arguments:{text:'x',path:'../outside'}},'INVALID_ARGS'],
        [{server:'approved',tool:'safe',arguments:{text:42}},'INVALID_ARGS'],
        [{server:'approved',tool:'safe',arguments:{text:'x'},file:'/bin/sh'},'INVALID_ARGS'],
      ]) await assert.rejects(call('mcpCall',args),error=>error.code===code);
      assert.equal(await fs.readFile(log,'utf8'),before);
      await assert.rejects(executeMcpTask({tool:'mcpCall',args:{server:'approved',tool:'safe',arguments:{text:'x'}}},{...grant,tools:new Set()},new AbortController().signal),error=>error.code==='TOOL_DENIED');
    });
    await t.test('server readOnlyHint cannot change owner-declared side effects; dropped reply is unknown', async () => {
      const task={tool:'mcpCall',args:{server:'approved',tool:'mutate',arguments:{text:'x'}}};
      assert.equal(isMcpSideEffecting(task,grant),true);
      await assert.rejects(call(task.tool,task.args),error=>error.code==='OUTCOME_UNKNOWN');
      assert.equal(await fs.readFile(path.join(root,'effect.txt'),'utf8'),'COMMITTED');
    });
    await t.test('URL, environment injection, untrusted process and schema references cannot compile', async () => {
      for (const server of [{...local,url:'http://127.0.0.1/'},{...local,env:{AUDIT_MCP_SECRET:'secret'}},{...local,trusted:false},{...local,tools:{safe:{readOnly:true,inputSchema:{...inputSchema,$ref:'file:///etc/passwd'}}}}]) {
        await assert.rejects(compileMcpPolicy({mcpServers:{approved:server}},dir,root),error=>error.code==='INVALID_CONFIG');
      }
    });
    await t.test('nonexistent bare script names cannot become remotely writable executable code', async () => {
      await assert.rejects(compileMcpPolicy({mcpServers:{approved:{...local,args:['not-yet-created.mjs']}}},dir,root),error=>error.code==='UNSAFE_MCP_POLICY');
    });
    await t.test('already existing writable fixed script is rejected across different grants', async () => {
      const writableScript=path.join(root,'server.mjs');await fs.writeFile(writableScript,'process.exit(0)');
      const bad={root,tools:new Set(['mcpCall']),...await compileMcpPolicy({mcpServers:{approved:{...local,args:[writableScript]}}},dir,root)};
      await assert.rejects(verifyMcpCodePolicy({grants:new Map([['reader',bad],['writer',{root,tools:new Set(['writeFile'])}]])}),error=>error.code==='UNSAFE_MCP_POLICY');
    });
  } finally { await fs.rm(dir,{recursive:true,force:true}); }
});
