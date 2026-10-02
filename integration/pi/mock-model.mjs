import http from 'node:http';

const MAX_BODY_BYTES = 512 * 1024;
const MAX_REQUESTS = 32;

/**
 * Deterministic OpenAI-compatible model double. Only model responses are mocked:
 * the published Pi SDK parses SSE, validates calls, executes tools, and loops.
 * This server is always ephemeral and binds only 127.0.0.1.
 */
export async function startMockModel({ calls = [], onRequest = () => {}, finalize } = {}) {
  if (!Array.isArray(calls) || calls.length > 20) throw new Error('Mock script must contain at most 20 calls');
  const script = structuredClone(calls);
  const requests = [];
  const sockets = new Set();
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method !== 'POST' || req.url !== '/v1/chat/completions') {
        res.writeHead(404); res.end('Mock model route not found'); return;
      }
      if (requests.length >= MAX_REQUESTS) throw new Error('Mock model request budget exceeded');
      let size = 0; const chunks = [];
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) throw new Error('Mock model request too large');
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (body.model !== 'intelligent-cells-mock' || body.stream !== true || !Array.isArray(body.messages)) {
        throw new Error('Expected Pi streaming chat completion request');
      }
      requests.push(body);
      onRequest({ request: requests.length, tools: (body.tools ?? []).map(x => x.function?.name), model: body.model });
      const results = body.messages.filter(x => x.role === 'tool');
      const step = results.length;
      const id = `mock-completion-${requests.length}`;
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
      const emit = (delta, finish_reason = null) => res.write(`data: ${JSON.stringify({
        id, object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000), model: body.model,
        choices: [{ index: 0, delta, finish_reason }],
      })}\n\n`);
      emit({ role: 'assistant' });
      if (step < script.length) {
        const call = script[step];
        emit({ tool_calls: [{ index: 0, id: `mock-call-${step + 1}`, type: 'function',
          function: { name: call.name, arguments: JSON.stringify(call.arguments ?? {}) } }] });
        emit({}, 'tool_calls');
      } else {
        const observations = results.map(result => ({ toolCallId: result.tool_call_id, content: result.content }));
        const text = finalize ? finalize(observations) : `Mock model completed after observing ${observations.length} Pi tool result(s).\n${JSON.stringify(observations)}`;
        emit({ content: text });
        emit({}, 'stop');
      }
      res.write(`data: ${JSON.stringify({ id, object: 'chat.completion.chunk', created: Math.floor(Date.now() / 1000),
        model: body.model, choices: [], usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 } })}\n\n`);
      res.end('data: [DONE]\n\n');
    } catch (error) {
      if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: error.message, type: 'mock_error' } }));
    }
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
  });
  const port = server.address().port;
  return {
    url: `http://127.0.0.1:${port}/v1`, port, requests,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => server.close(resolve));
    },
  };
}

export function scenarioCalls(scenario = 'read', peerId) {
  const args = value => ({ peerId, ...value });
  switch (scenario) {
    case 'read':
    case 'success':
      return [{ name: 'remote_read', arguments: args({ path: 'hello.txt' }) }];
    case 'echo':
      return [{ name: 'remote_echo', arguments: args({ text: 'Pi invoked a servant over the encrypted node connection' }) }];
    case 'wait':
      return [{ name: 'remote_wait', arguments: args({ ms: 1500, timeoutMs: 2000 }) }];
    case 'workflow':
      return [
        { name: 'remote_read', arguments: args({ path: 'hello.txt' }) },
        { name: 'remote_write', arguments: args({ path: 'pi-result.txt', text: 'Created by the servant through Pi.\n' }) },
        { name: 'remote_edit', arguments: args({ path: 'pi-result.txt', oldText: 'Created', newText: 'Edited' }) },
        { name: 'remote_exec', arguments: args({ command: 'fixture', args: ['pi-remote-exec'] }) },
        { name: 'remote_read', arguments: args({ path: 'pi-result.txt' }) },
      ];
    case 'development':
      return [
        { name: 'remote_capabilities', arguments: args({}) },
        { name: 'remote_list', arguments: args({}) },
        { name: 'remote_read', arguments: args({ path: 'package.json' }) },
        { name: 'remote_search', arguments: args({ path: 'src', query: 'return a - b' }) },
        { name: 'remote_read', arguments: args({ path: 'src/math.mjs' }) },
        { name: 'remote_exec', arguments: args({ command: 'test', args: [], timeoutMs: 5000 }) },
        { name: 'remote_edit', arguments: args({ path: 'src/math.mjs', oldText: 'return a - b;', newText: 'return a + b;' }) },
        { name: 'remote_exec', arguments: args({ command: 'build', args: [], timeoutMs: 5000 }) },
        { name: 'remote_exec', arguments: args({ command: 'test', args: [], timeoutMs: 5000 }) },
        { name: 'remote_exec', arguments: args({ command: 'git_diff', args: [], timeoutMs: 5000 }) },
        { name: 'remote_read', arguments: args({ path: 'src/math.mjs' }) },
        { name: 'remote_mcp_list', arguments: args({ server: 'fixture_math' }) },
        { name: 'remote_mcp_call', arguments: args({ server: 'fixture_math', tool: 'add', arguments: { a: 19, b: 23 } }) },
      ];
    case 'mcp-uncertain':
      return [
        { name: 'remote_mcp_call', arguments: args({ server: 'fixture_effect', tool: 'commit', arguments: {} }) },
        { name: 'remote_mcp_call', arguments: args({ server: 'fixture_effect', tool: 'commit', arguments: {} }) },
        { name: 'remote_write', arguments: args({ path: 'after-unknown.txt', text: 'must remain blocked' }) },
        { name: 'remote_read', arguments: args({ path: 'effects.log' }) },
      ];
    case 'development-readback':
      return [{ name: 'remote_read', arguments: args({ path: 'src/math.mjs' }) }];
    case 'denial':
      return [{ name: 'remote_read', arguments: args({ path: '../outside.txt' }) }];
    case 'exec-denial':
      return [{ name: 'remote_exec', arguments: args({ command: 'unapproved-shell', args: ['-c', 'echo blocked'] }) }];
    case 'tool-denial':
      return [{ name: 'remote_write', arguments: args({ path: 'denied.txt', text: 'Must be refused by the servant policy' }) }];
    case 'invalid-arguments':
      return [{ name: 'remote_read', arguments: args({}) }];
    case 'local-bypass':
      return [
        { name: 'read', arguments: { path: '/etc/passwd' } },
        { name: 'bash', arguments: { command: 'echo SHOULD_NOT_EXECUTE_LOCALLY' } },
        { name: 'write', arguments: { path: 'pi-local-bypass-sentinel.txt', content: 'forbidden' } },
        { name: 'edit', arguments: { path: 'pi-local-bypass-sentinel.txt', oldText: 'forbidden', newText: 'bypass' } },
        { name: 'ls', arguments: { path: '.' } },
        { name: 'grep', arguments: { pattern: '.', path: '.' } },
        { name: 'find', arguments: { pattern: '*' } },
        { name: 'powershell', arguments: { command: 'Write-Output SHOULD_NOT_EXECUTE_LOCALLY' } },
      ];
    default:
      throw Object.assign(new Error(`Unknown mock scenario: ${String(scenario)}`), { code: 'INVALID_SCENARIO' });
  }
}

/** Assert real observations rather than blindly printing a scripted success claim. */
export function developmentFinal(observations) {
  const parsed=observations.map(item=>{try{return JSON.parse(item.content);}catch{return null;}});
  const initialTest=parsed[5], edited=parsed[6], build=parsed[7], finalTest=parsed[8], diff=parsed[9], source=parsed[10], mcp=parsed[12];
  let mcpSum;try{mcpSum=JSON.parse(mcp?.content?.[0]?.text).sum;}catch{}
  const verified=observations.length===13 && initialTest?.exitCode===1 && edited?.path==='src/math.mjs' && build?.exitCode===0 && /BUILD_OK/.test(build?.stdout??'') && finalTest?.exitCode===0 && /TEST_OK/.test(finalTest?.stdout??'') && diff?.exitCode===0 && /return a \+ b/.test(diff?.stdout??'') && /return a \+ b/.test(source?.text??'') && mcpSum===42;
  return JSON.stringify({mockedModel:true,workflow:'fixed-real-repository-development',verified,baselineTestFailed:initialTest?.exitCode===1,buildPassed:build?.exitCode===0,testPassed:finalTest?.exitCode===0,mcpSum,changedFile:'src/math.mjs',...(verified?{summary:'已读取真实仓库、复现测试失败、修复加法 bug，并通过配置的 build/test；git diff 和源文件回读已验证，MCP 结果为 42。'}:{summary:'固定开发流程未通过全部真实结果断言，不能报告成功。',observations})});
}
