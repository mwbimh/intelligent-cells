import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fail, integer, isObject, NodeError } from './errors.mjs';
import { compileApprovedCode, verifyCodeIsolation, verifyApprovedCode } from './code-policy.mjs';

export const MCP_PROTOCOL_VERSION = '2025-06-18';
const aliasOK = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(value);
const toolOK = value => typeof value === 'string' && /^[a-zA-Z0-9_.-]{1,64}$/.test(value);
const objectSchema = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
export const mcpToolSchemas = Object.freeze([
  { name: 'mcpList', description: 'Negotiate with a servant-owned trusted stdio MCP server and list only locally approved bindings', inputSchema: objectSchema({ server: { type:'string',minLength:1,maxLength:64 } }, ['server']) },
  { name: 'mcpCall', description: 'Call an approved MCP server/tool binding through the servant policy boundary; no URLs or commands', inputSchema: objectSchema({ server:{type:'string',minLength:1,maxLength:64}, tool:{type:'string',minLength:1,maxLength:64}, arguments:{type:'object'} }, ['server','tool','arguments']) },
]);
export function isMcpSideEffecting(task, grant) {
  return task.tool === 'mcpCall' && grant?.mcpServers?.get(task.args?.server)?.tools?.get(task.args?.tool)?.readOnly !== true;
}

const schemaKeys = new Set(['type','properties','required','additionalProperties','items','minItems','maxItems','minLength','maxLength','minimum','maximum','enum','description']);
/** Deliberately small, rejecting JSON Schema subset. No refs, regex, coercion or remote resolution. */
export function validateMcpSchema(schema, depth = 0) {
  if (!isObject(schema) || depth > 6 || Object.keys(schema).some(key => !schemaKeys.has(key)) || !['object','array','string','integer','number','boolean','null'].includes(schema.type)) fail('INVALID_CONFIG', 'MCP inputSchema uses an unsupported JSON Schema feature');
  if (schema.description !== undefined && (typeof schema.description !== 'string' || Buffer.byteLength(schema.description)>1024)) fail('INVALID_CONFIG','MCP schema description too large');
  for (const key of ['minItems','maxItems','minLength','maxLength']) if (schema[key] !== undefined && (!Number.isSafeInteger(schema[key]) || schema[key] < 0 || schema[key]>65536)) fail('INVALID_CONFIG','Invalid MCP schema bound');
  for (const key of ['minimum','maximum']) if (schema[key] !== undefined && (typeof schema[key] !== 'number' || !Number.isFinite(schema[key]))) fail('INVALID_CONFIG','Invalid MCP numeric bound');
  if (schema.enum !== undefined && (!Array.isArray(schema.enum) || schema.enum.length > 32 || schema.enum.some(x => x !== null && !['string','number','boolean'].includes(typeof x)))) fail('INVALID_CONFIG','MCP enum must contain bounded scalar values');
  if (schema.type === 'object') {
    if (!isObject(schema.properties) || Object.keys(schema.properties).length>32 || schema.additionalProperties !== false ||
        !Array.isArray(schema.required ?? []) || (schema.required ?? []).some(key => !Object.hasOwn(schema.properties,key))) fail('INVALID_CONFIG', 'MCP objects require explicit properties and additionalProperties:false');
    for (const [key,child] of Object.entries(schema.properties)) { if (!toolOK(key)) fail('INVALID_CONFIG','Invalid MCP schema property'); validateMcpSchema(child,depth+1); }
  }
  if (schema.type === 'array') validateMcpSchema(schema.items,depth+1);
}
export function matchesMcpSchema(value,schema) {
  if (schema.enum && !schema.enum.some(item => Object.is(item,value))) return false;
  switch(schema.type) {
    case 'object': return isObject(value) && Object.keys(value).every(key => Object.hasOwn(schema.properties,key) && matchesMcpSchema(value[key],schema.properties[key])) && (schema.required ?? []).every(key => Object.hasOwn(value,key));
    case 'array': return Array.isArray(value) && value.length >= (schema.minItems ?? 0) && value.length <= Math.min(schema.maxItems ?? 128,128) && value.every(item => matchesMcpSchema(item,schema.items));
    case 'string': return typeof value === 'string' && value.length >= (schema.minLength ?? 0) && value.length <= Math.min(schema.maxLength ?? 8192,8192);
    case 'number': case 'integer': return typeof value === 'number' && Number.isFinite(value) && (schema.type !== 'integer' || Number.isSafeInteger(value)) && value >= (schema.minimum ?? -Infinity) && value <= (schema.maximum ?? Infinity);
    case 'boolean': return typeof value === 'boolean';
    case 'null': return value === null;
    default:return false;
  }
}

export async function compileMcpPolicy(raw, _base, root) {
  if (!isObject(raw.mcpServers ?? {})) fail('INVALID_CONFIG','mcpServers must be an explicit local alias map');
  const mcpServers = new Map();
  const maxMcpBytes = integer(raw.maxMcpBytes ?? 32768,256,65536,'maxMcpBytes');
  if (Object.keys(raw.mcpServers ?? {}).length > 8) fail('INVALID_CONFIG','At most 8 MCP servers per grant');
  for (const [alias,item] of Object.entries(raw.mcpServers ?? {})) {
    if (!root || !aliasOK(alias) || !isObject(item) || item.trusted !== true || typeof item.file !== 'string' || !path.isAbsolute(item.file) ||
        Object.keys(item).some(key => !['trusted','file','args','launchMode','tools','maxOutputBytes'].includes(key)) ||
        !Array.isArray(item.args ?? []) || (item.args ?? []).length > 16 || (item.args ?? []).some(arg => typeof arg !== 'string' || arg.includes('\0') || Buffer.byteLength(arg)>4096) ||
        !isObject(item.tools) || Object.keys(item.tools).length>32) fail('INVALID_CONFIG','MCP requires an explicitly trusted local command with fixed args and approved tools');
    const file = await fs.realpath(item.file);
    if (!(await fs.stat(file)).isFile()) fail('INVALID_CONFIG','MCP executable must be a regular file');
    const bindings = new Map();
    for (const [name,binding] of Object.entries(item.tools)) {
      if (!toolOK(name) || !isObject(binding) || Object.keys(binding).some(key => !['inputSchema','readOnly','description'].includes(key)) || typeof binding.readOnly !== 'boolean' ||
          (binding.description !== undefined && (typeof binding.description!=='string' || Buffer.byteLength(binding.description)>1024))) fail('INVALID_CONFIG','MCP binding requires local inputSchema and readOnly declaration');
      if (binding.inputSchema?.type !== 'object' || Buffer.byteLength(JSON.stringify(binding.inputSchema))>16384) fail('INVALID_CONFIG','MCP binding inputSchema must be a bounded object schema');
      validateMcpSchema(binding.inputSchema);
      bindings.set(name,{name,inputSchema:structuredClone(binding.inputSchema),readOnly:binding.readOnly,description:binding.description ?? name});
    }
    const approvedCode = await compileApprovedCode(file, item.args ?? [], 'UNSAFE_MCP_POLICY', item);
    mcpServers.set(alias,{alias,file,args:[...(item.args ?? [])],...approvedCode,tools:bindings,root,maxOutputBytes:integer(item.maxOutputBytes ?? maxMcpBytes,256,maxMcpBytes,'mcp.maxOutputBytes')});
  }
  return {mcpServers,maxMcpBytes};
}

export async function verifyMcpCodePolicy(policy, additionalWritableRoots = []) {
  const writableRoots = [...additionalWritableRoots, ...[...policy.grants.values()].filter(g => ['writeFile','editFile','writeChunk','mkdir'].some(name => g.tools.has(name))).map(g => g.root).filter(Boolean)];
  for (const grant of policy.grants.values()) for (const server of grant.mcpServers?.values() ?? []) {
    verifyCodeIsolation(server, writableRoots, 'UNSAFE_MCP_POLICY');
  }
}

export function validateMcpTask(task,grant) {
  const args=task.args;
  if (!isObject(args) || !aliasOK(args.server) || Object.keys(args).some(key => !(task.tool==='mcpList'?['server']:['server','tool','arguments']).includes(key))) fail('INVALID_ARGS','MCP accepts only approved server/tool aliases and arguments');
  const server=grant.mcpServers?.get(args.server);
  if (!server) fail('MCP_SERVER_DENIED','MCP server is not approved for this master');
  if (task.tool==='mcpList') return;
  if (task.tool!=='mcpCall') fail('TOOL_DENIED','Unknown MCP operation');
  const binding=server.tools.get(args.tool);
  if (!toolOK(args.tool) || !binding) fail('MCP_TOOL_DENIED','MCP tool is not approved for this master');
  if (!isObject(args.arguments) || Buffer.byteLength(JSON.stringify(args.arguments))>16384 || !matchesMcpSchema(args.arguments,binding.inputSchema)) fail('INVALID_ARGS','MCP arguments violate the local binding schema');
}

/** A fresh bounded stdio session for each node task. Only MCP tools protocol is supported. */
async function openStdio(server,signal) {
  signal.throwIfAborted();
  await verifyApprovedCode(server, signal, 'MCP_CODE_CHANGED');
  const child=spawn(server.file,server.args,{cwd:server.root,env:{},shell:false,windowsHide:true,detached:process.platform!=='win32',stdio:['pipe','pipe','pipe']});
  let nextId=0,buffer='',total=0,closed=false,closeReason,callSent=false;
  const pending=new Map();
  const stop = () => {
    if (closed) return;
    try { if(process.platform!=='win32') process.kill(-child.pid,'SIGKILL'); else child.kill('SIGKILL'); } catch { child.kill('SIGKILL'); }
    child.stdout.destroy();child.stderr.destroy();child.stdin.destroy();
  };
  const rejectAll = error => { closeReason ??= error;for(const item of pending.values())item.reject(error);pending.clear(); };
  const write = message => {
    if(closed || closeReason) throw closeReason ?? new NodeError('MCP_DISCONNECTED','MCP server closed');
    child.stdin.write(JSON.stringify(message)+'\n');
  };
  const onAbort=()=>{rejectAll(signal.reason ?? new NodeError('CANCELLED','MCP cancelled'));stop();};
  const completion=new Promise(resolve => child.once('close',()=>{closed=true;rejectAll(new NodeError('MCP_DISCONNECTED','MCP server disconnected'));resolve();}));
  child.once('error',error=>{rejectAll(new NodeError('MCP_SPAWN_FAILED',`MCP server failed: ${error.code ?? 'spawn error'}`));stop();});
  child.stdin.on('error',()=>{rejectAll(new NodeError('MCP_DISCONNECTED','MCP stdin closed'));stop();});
  child.stdout.on('error',()=>{rejectAll(new NodeError('MCP_PROTOCOL_ERROR','MCP stdout failed'));stop();});
  child.stderr.on('error',()=>{});
  const limit=()=>{rejectAll(new NodeError('MCP_OUTPUT_TOO_LARGE','MCP output exceeds the local byte budget'));stop();};
  child.stderr.on('data',chunk=>{total+=chunk.length;if(total>server.maxOutputBytes)limit();});
  const utf8=new TextDecoder('utf-8',{fatal:true});
  child.stdout.on('data',chunk=>{
    total+=chunk.length;if(total>server.maxOutputBytes){limit();return;}
    try {buffer+=utf8.decode(chunk,{stream:true});}catch {rejectAll(new NodeError('MCP_PROTOCOL_ERROR','MCP messages must contain valid UTF-8'));stop();return;}
    while(buffer.includes('\n')) {
      const cut=buffer.indexOf('\n'),line=buffer.slice(0,cut);buffer=buffer.slice(cut+1);
      try {
        const message=JSON.parse(line);
        if(!isObject(message)||message.jsonrpc!=='2.0')throw new Error('invalid envelope');
        if(typeof message.method==='string') {
          // We expose no roots, sampling, elicitation, credentials or local tools.
          if(Object.hasOwn(message,'id')) write(message.method==='ping'?{jsonrpc:'2.0',id:message.id,result:{}}:{jsonrpc:'2.0',id:message.id,error:{code:-32601,message:'Client capability not supported'}});
          continue;
        }
        const item=pending.get(message.id);
        if(!item || (Object.hasOwn(message,'result')===Object.hasOwn(message,'error')))throw new Error('unexpected response');
        pending.delete(message.id);
        if(message.error) item.reject(new NodeError('MCP_RPC_ERROR',`MCP returned JSON-RPC error ${message.error.code ?? 'unknown'}`));
        else item.resolve(message.result);
      }catch {rejectAll(new NodeError('MCP_PROTOCOL_ERROR','Invalid MCP JSON-RPC response'));stop();return;}
    }
  });
  signal.addEventListener('abort',onAbort,{once:true});if(signal.aborted)onAbort();
  return {
    get callSent(){return callSent;},
    request(method,params) {
      if(signal.aborted)return Promise.reject(signal.reason);
      const id=++nextId;
      return new Promise((resolve,reject)=>{
        pending.set(id,{resolve,reject});
        try { write({jsonrpc:'2.0',id,method,params});if(method==='tools/call')callSent=true; } catch(error){pending.delete(id);reject(error);}
      });
    },
    notify(method,params){write({jsonrpc:'2.0',method,...(params?{params}:{})});},
    async close(){signal.removeEventListener('abort',onAbort);stop();await completion;},
  };
}

export async function executeMcpTask(task,grant,signal=new AbortController().signal) {
  signal.throwIfAborted();
  if(!grant.tools?.has(task.tool))fail('TOOL_DENIED','MCP tool is not granted');
  validateMcpTask(task,grant);
  const server=grant.mcpServers.get(task.args.server);
  const client=await openStdio(server,signal);
  try {
    const initialized=await client.request('initialize',{protocolVersion:MCP_PROTOCOL_VERSION,capabilities:{},clientInfo:{name:'intelligent-cells-servant',version:'0.4.0'}});
    if(initialized?.protocolVersion!==MCP_PROTOCOL_VERSION || !isObject(initialized?.capabilities?.tools) || !isObject(initialized?.serverInfo))fail('MCP_NEGOTIATION_FAILED','MCP server does not support the pinned tools protocol');
    client.notify('notifications/initialized');
    // Always consult the real server, but never infer permissions from its descriptions/annotations.
    const catalog=await client.request('tools/list',{});
    if(!Array.isArray(catalog?.tools) || catalog.tools.length>128 || catalog.nextCursor!==undefined || catalog.tools.some(tool=>!isObject(tool)||!toolOK(tool.name)) || new Set(catalog.tools.map(tool=>tool.name)).size!==catalog.tools.length)fail('MCP_PROTOCOL_ERROR','MCP catalog is invalid, paginated or exceeds the bounded subset');
    const exposed=new Set(catalog.tools.map(tool=>tool.name));
    if(task.tool==='mcpList')return {server:server.alias,protocolVersion:MCP_PROTOCOL_VERSION,transport:'stdio',tools:[...server.tools.values()].filter(binding=>exposed.has(binding.name)).map(binding=>({...binding,permissionAuthority:'servant-local-grant'}))};
    if(!exposed.has(task.args.tool))fail('MCP_TOOL_UNAVAILABLE','The approved MCP tool is unavailable on the server');
    const result=await client.request('tools/call',{name:task.args.tool,arguments:task.args.arguments});
    if(!isObject(result)||!Array.isArray(result.content)||result.content.length>64||result.content.some(item=>!isObject(item)||item.type!=='text'||typeof item.text!=='string')||(result.isError!==undefined&&typeof result.isError!=='boolean'))fail('MCP_PROTOCOL_ERROR','This bounded MCP adapter supports text tool results only');
    return {server:server.alias,tool:task.args.tool,content:result.content,isError:result.isError===true,protocolVersion:MCP_PROTOCOL_VERSION};
  } catch(error) {
    // A dropped stdio response after a mutating call is as uncertain as a dropped TLS reply.
    if(client.callSent && isMcpSideEffecting(task,grant) && error.code!=='MCP_RPC_ERROR')throw new NodeError('OUTCOME_UNKNOWN','MCP call was sent but its final outcome is unknown; owner reconciliation is required');
    throw error;
  } finally {await client.close();}
}
