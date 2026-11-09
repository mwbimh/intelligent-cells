# CLI and harness integration

IC runs as a resident service. A harness attaches a stdio MCP session through `ic mcp connect`; disconnecting that client does not shut down the node. Start the harness directly. The removed `call` and `launch` commands have no aliases.

```sh
ic config init
ic config check
ic serve
```

Run management commands in another terminal:

```sh
ic nodes list
ic nodes status
ic pair list
ic mcp list
ic mcp give --harness claude-code --target /absolute/claude-mcp.json --cwd /absolute/project
ic mcp give --harness codex --target /absolute/codex-config.toml --cwd /absolute/project
```

`give` writes the selected harness MCP configuration. The target parent directory must already exist. It preserves the native JSON/TOML format and records the current absolute `IC_HOME` for the harness environment. Restart the harness after registration. It accepts optional `--session ID` to reconnect to a persisted session. Pi does not provide the supported native MCP configuration interface and is not accepted by `give`; the command reports this explicitly.

```sh
ic mcp connect --cwd /absolute/project
ic mcp connect --session SESSION_UUID
```

`connect` and `give` accept `--local-sync`, which requires an explicit `--cwd`. This mode exposes `ic_workspace` and `ic_sync` and synchronizes approved remote execution using the bound project; native harness file tools stay local. A resumed session must retain its original mode.

Supply cwd explicitly for a directory binding. Without it, targets use permitted session-specific temporary directories. The bridge does not assume its own process cwd is the agent's project. Built-in IC tools execute on remote nodes only. Aggregated MCP tools carry a separate origin and obey local/master visibility settings.

## Agent tool names and default peer

Agent-facing IC tools use the `ic_*` namespace, including `ic_peers`, `ic_peer`, `ic_exec`, `ic_workspace` and `ic_sync`. Internal wire tool names such as `readFile` and `exec` are unchanged.

Call `ic_peers` to inspect available peers, then select an already-paired servant for the session:

```json
{"name":"ic_peer","arguments":{"peerId":"SERVANT_UUID"}}
```

The selected default persists with the session and is restored on resume. Subsequent remote tool calls may omit `peerId`. Supplying `peerId` on an individual call overrides the destination for that call only; it does not change the session default. A remote call without either an explicit peer or a selected default returns `PEER_REQUIRED`.

`ic_peer` selects an existing relationship. Agent tools cannot create a pairing, approve a request, grant permissions or bypass the selected servant's policy. Use the owner CLI for those actions. Underlying wire primitives remain internal; they are not public aliases for removed agent tools.

## Simplified agent catalog

The ordinary built-in catalog has 15 tools; local-sync has 11. Aggregated provider tools are additional entries. Local-sync exposes `ic_workspace` to select the same synchronization scope previously handled by `ic_sync_scope`; it does not create a workspace or change directory bindings. `ic_workspace` is available only in local-sync sessions.

Use `ic_process` for background process control:

```json
{"name":"ic_process","arguments":{"action":"status","jobId":"JOB_ID"}}
```

`action` is `status`, `output` or `cancel`; `jobId` is required. `peerId` and `timeoutMs` are optional. Only `output` accepts `offset`, `limit` and `stream`. Destination selection follows the same persistent `ic_peer` default and per-call override rules.

The agent catalog no longer exposes chunk-transfer tools, resource tools or the four separate job-control tools. `ic_exec` no longer accepts stdin input, and `ic_process` does not provide stdin. There are no public compatibility aliases. Internal file, resource and job primitives remain available to the runtime; removing agent wrappers does not remove those primitives or relax permissions. Authentication, grant checks and persistent execution history remain in effect.

## Commands

```text
ic config [show|init|use|set|check] [--config FILE]
ic config set --key dotted.path --value JSON
ic nodes [list|status]
ic nodes status --peer UUID
ic nodes rename --peer UUID --name NAME
ic nodes bind --peer UUID --local PATH --workspace ID
ic nodes unbind --peer UUID --local PATH
ic nodes command --json JSON
ic pair [list|status]
ic pair request --master JSON
ic pair approve --request ID --fingerprint SHA256
ic pair reject --request ID
ic pair confirm --request ID --master JSON [--grant JSON]
ic mcp list
ic mcp add --name NAME --definition JSON
ic mcp remove --id UUID
ic mcp update --id UUID --patch JSON
ic mcp builtin --tool NAME --patch JSON
ic mcp give --harness claude-code|codex --target FILE [--cwd PATH] [--session ID] [--local-sync]
ic mcp connect [--cwd PATH] [--session ID] [--local-sync]
ic mock-model --kind pi|claude|codex --script FILE [--port N]
```

Only `config` accepts `--config`. `config use --config FILE` selects a settings file. Other commands use that selection. `nodes command` is an authenticated local management interface, not an agent tool or remote authorization bypass. Use each command's `--help` for the exact accepted arguments.
