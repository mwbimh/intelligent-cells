import { fail } from './errors.mjs';
// Replace this adapter with a real agent by implementing plan(input, context).
// An agent produces task proposals; the target node remains the policy authority.
export class DeterministicDemoAgent {
  name = 'deterministic-demo';
  async plan(input, { peers, prefix }) {
    if (!peers.length) fail('NO_SERVANTS', 'No outgoing relationships are configured');
    if (input.goal === 'demo') return [
      { peerId: peers[0], task: { taskId: `${prefix}_echo`, tool: 'echo', args: { text: 'hello from the deterministic demo agent' }, timeoutMs: 1000 } },
      { peerId: peers[1] ?? peers[0], task: { taskId: `${prefix}_read`, tool: 'readFile', args: { path: 'hello.txt' }, timeoutMs: 1000 } }
    ];
    if (input.goal === 'echo' && typeof input.text === 'string') return [{ peerId: peers[0], task: { taskId: `${prefix}_echo`, tool: 'echo', args: { text: input.text }, timeoutMs: 1000 } }];
    fail('UNSUPPORTED_GOAL', 'Demo agent supports only goal=demo or goal=echo with text; no LLM is configured');
  }
}
