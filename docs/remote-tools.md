# Remote tools

Tools execute in a servant-authorized workspace. Capabilities describe approved schemas, limits and command aliases, without disclosing executable paths or environment values. IC built-in tools are remote-only; the local agent cannot use them to execute against its own node.

| Tools | Purpose |
|---|---|
| `echo`, `wait` | Bounded text and cancellable delay |
| `readFile`, `writeFile`, `editFile` | UTF-8 access, explicit overwrite and unique literal edits |
| `listDirectory`, `searchFiles` | Bounded listing and literal search |
| `mkdir`, `readChunk`, `writeChunk` | Single-directory creation and bounded binary transfer |
| `exec` | Approved command aliases, foreground or background |
| `jobStatus`, `jobOutput`, `jobCancel`, `jobStdin` | Identity-, workspace- and epoch-scoped job control |
| `resourceList`, `resourceRead` | Approved resource aliases |
| `mcpList`, `mcpCall` | Approved provider discovery and invocation |
| `workspaceList`, `workspaceCreate` | Approved workspace lifecycle |
| `syncInventory`, `syncUpload`, `syncApply`, `syncExec` | Internal bounded synchronization |

Tasks carry `taskId`, `tool`, `args` and `timeoutMs`, with optional run/workspace metadata. Paths are relative to the approved root. Absolute paths, traversal, links, hardlinks and special files are rejected. Writes use atomic replacement and fsync.

## Agent interface

The table above uses internal task names. Agent-facing MCP tools use the `ic_*` namespace. `ic_peers` lists peers; `ic_peer {peerId}` selects an already-paired servant as the persistent session default. Remote calls accept an optional `peerId` override that applies only to that call. Without an explicit peer or a selected default, remote calls return `PEER_REQUIRED`.

Peer selection does not pair nodes or change grants. The selected target still enforces its existing tools, workspace and directory permissions. The internal primitives in the table remain available to the runtime. The agent surface omits chunk and resource tools and the four separate job-control wrappers; no public aliases remain.

### Process control

`ic_process` requires `action` (`status`, `output` or `cancel`) and `jobId`. Optional `peerId` and `timeoutMs` apply to all actions; `offset`, `limit` and `stream` apply only to output. It replaces separate agent job-control wrappers and offers no stdin action. Current identity, workspace, authorization epoch and history checks still apply.

The built-in agent catalog contains 15 ordinary tools or 11 local-sync tools, before external providers are added. In local-sync, `ic_workspace` selects synchronization scope and `ic_sync` performs the mirror; workspace selection does not alter owner-approved bindings.

## Approved execution

```json
{"tools":["exec"],"workspace":"/srv/project","execCommands":{"check":{"file":"/opt/approved/check","args":[],"launchMode":"native","argsAllowed":false,"env":{}}}}
```

`native` runs a fixed approved executable and arguments. `node-script` runs an approved Node executable with a fixed absolute script; it is an external workload, not the IC runtime. Code identity is checked before execution and must be isolated from remote writes. Remote callers cannot supply environment or cwd overrides. Additional arguments require explicit approval. Internal stdin support remains policy-controlled, but agent-facing `ic_exec` does not accept stdin.

Background jobs retain quota and workspace locks until the process closes. Output is bounded and persisted; byte-accurate pages use base64. Cancellation, timeout and output overflow terminate the POSIX process group, but escaped descendants or external effects may survive. Restarted active jobs become unknown; IC does not kill an old PID or replay the command blindly. See [recovery](durability.md).
