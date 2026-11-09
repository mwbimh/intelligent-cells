# Local editing and remote synchronization

Directory binding alone does not transfer files. Local synchronization captures an explicitly selected local scope, transfers missing content and applies a strict mirror before approved remote execution. Native harness file tools remain local; IC does not replace them or fall back to local execution after a remote failure.

Bindings and scopes are node metadata in `nodes.json`. Owner-approved local roots must be canonical, private and isolated from code, configuration, state and credentials. Mapping revisions and directory identity are checked again before applying effects. Agent sessions select cwd through these bindings.

## Session entry

```sh
ic mcp connect --local-sync --cwd /absolute/project
ic mcp give --harness codex --target /absolute/config.toml --local-sync --cwd /absolute/project
```

`--local-sync` requires `--cwd` and uses owner-approved directory bindings. Set scope through `ic_workspace`, then call `ic_sync` for an explicit mirror or `ic_exec` for synchronization followed by approved execution. `ic_workspace` is local-sync-only and selects scope; it neither creates a workspace nor changes directory bindings. The former scope-tool name is not retained as an alias. A resumed session keeps its original synchronization mode. Select a persistent default servant with `ic_peer {peerId}` or pass an explicit `peerId` on a synchronization call. A per-call override does not change the default. Without either destination, the call returns `PEER_REQUIRED`.

## Backends and grants

Native synchronization is the default. Optional rsync requires both nodes to select it explicitly:

```json
{"sync":{"backend":"rsync","rsync":{"file":"/opt/ic-approved/rsync","sha256":"VERIFIED_64_LOWERCASE_HEX_SHA256"}}}
```

The executable must be an approved canonical absolute, single-link file, version 3.4.1 or newer. A missing executable, changed pin or unsupported version fails explicitly; no fallback is attempted. Deploy the Rust `ic-rsync-stdio` companion alongside `ic`.

| Operation | Native grant | rsync grant |
|---|---|---|
| Manual mirror | `syncInventory`, `syncUpload`, `syncApply` | `syncTransfer`, `syncApply` |
| Mirror then execute | `syncInventory`, `syncUpload`, `syncExec`, `exec` | `syncTransfer`, `syncExec`, `exec` |

Rsync needs explicit `allowUnsandboxedProcesses:true`; both backends need scope read/write permission. Execution additionally requires an approved command alias. Reverse-direction access is a separate grant.

Rsync uses the existing IC mTLS connection, not SSH. Transfers go through a private flat staging area and content-hash verification, then the normal IC mirror implementation. Rsync never writes directly into the real workspace. Payload byte counters exclude TLS, JSON and base64 overhead and are not wire-throughput measurements.

## Scope and effects

Scopes contain 1–32 nonoverlapping relative prefixes. `""` selects the whole root. Absolute paths, traversal, globs, exclusions, duplicates, links, hardlinks and special files are rejected. Defining a scope does not transfer files.

**Remote files and directories present only inside the selected scope are deleted.** Files outside the scope remain. Bytes, hashes, executable bits and empty directories are preserved; full ownership, timestamps and extended attributes are not. Unchanged files retain inode and mtime.

The manifest limit is 256 entries and 60000 JSON bytes. File and selected-tree limits are each 64 MiB; binary chunks are 16 KiB. Native blob staging is bounded, and rsync stages are checked independently. Each internal transfer operation consumes normal task quotas.

Changed snapshots, mappings, directory identities, cancellation, quota exhaustion or uncertain upload results stop subsequent execution. Foreground synchronized execution holds a physical workspace lock across mirror and command; background synchronized execution is rejected. Conflicting active jobs also prevent synchronization.

## Recovery

A process crash may leave a workspace lock. Inspect related processes, jobs, tasks and actual filesystem effects first. The local owner may then submit `recoverWorkspaceLock` with the approved `masterId`, optional `workspaceId`, and a note describing the checks. Arbitrary physical paths are not accepted; active or unknown work prevents recovery.

Failure after mirroring begins can leave file effects. IC does not roll them back automatically or retry unknown writes. Follow [task reconciliation](durability.md) before proceeding.
