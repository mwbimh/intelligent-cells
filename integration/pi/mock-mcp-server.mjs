// Trusted deterministic MCP test double. No network, credentials or arbitrary code evaluation.
// Only the third-party MCP service behavior is mocked; the protocol and servant bridge are real.
import readline from 'node:readline';
let initialized=false,ready=false;
const tools=[
  {name:'add',description:'Add two bounded integers',inputSchema:{type:'object',properties:{a:{type:'integer'},b:{type:'integer'}},required:['a','b'],additionalProperties:false}},
  {name:'fail',description:'Return a tool-level failure',inputSchema:{type:'object',properties:{},additionalProperties:false}},
  {name:'unapproved',description:'An exposed server tool grants no local permission',inputSchema:{type:'object',properties:{},additionalProperties:false}},
];
const send=(id,result)=>process.stdout.write(JSON.stringify({jsonrpc:'2.0',id,result})+'\n');
for await(const line of readline.createInterface({input:process.stdin})) {
  const request=JSON.parse(line);
  if(request.method==='initialize') {
    initialized=true;
    send(request.id,{protocolVersion:'2025-06-18',capabilities:{tools:{}},serverInfo:{name:'deterministic-local-mcp',version:'1.0.0'}});
  } else if(request.method==='notifications/initialized'&&initialized)ready=true;
  else if(request.method==='tools/list'&&ready)send(request.id,{tools});
  else if(request.method==='tools/call'&&ready) {
    if(request.params.name==='add')send(request.id,{content:[{type:'text',text:JSON.stringify({sum:request.params.arguments.a+request.params.arguments.b,serverPid:process.pid})}]});
    else send(request.id,{content:[{type:'text',text:'deterministic tool failure'}],isError:true});
  } else if(request.id!==undefined)process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:request.id,error:{code:-32600,message:'Initialization required'}})+'\n');
}
