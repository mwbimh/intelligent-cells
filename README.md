# Intelligent Cells

IC is a resident Rust service for authenticated connections between nodes, approved remote tools, persistent agent sessions, and MCP aggregation. The v0.6 command and storage redesign is breaking: old CLI aliases and combined configuration files are not supported.

A node can act as a master toward one peer and a servant toward another. Each servant controls its incoming permissions. Pairing establishes identity and a relationship; it does not grant tools automatically. Node records use stable UUIDs, with display names stored separately.

## Build and start

```sh
cargo build --release --bin ic --bin ic-rsync-stdio
./target/release/ic --help
ic config check
ic serve
```

Builds require Rust/Cargo, a C toolchain and Perl for vendored OpenSSL. Deployed Rust binaries do not require Node.js; individual external harnesses or approved MCP providers may have their own dependencies. Linux builds using system OpenSSL require the corresponding runtime library.

Select and edit runtime settings through `ic config`. Other commands discover the selected configuration and do not accept `--config`. Keep the service running while harnesses attach MCP sessions. `serve` runs in the foreground until stopped and never reads management commands from stdin. `--daemon` is a redundant supported flag; it does not install an operating-system service.

## Separate persistent records

| File or store | Purpose |
|---|---|
| `config.json` | Runtime settings, listeners, limits, operator entry and session policy |
| `nodes.json` | UUID identity and display name, relationships, trust, grants and directory bindings |
| `mcp.json` | Aggregated MCP providers, tool enablement and visibility |
| Private runtime state | Session/execution history, tasks, jobs and recovery metadata |

Certificates are provisioned automatically for the node identity. Trust still requires explicit pairing. The servant initiates a join request; the master selects and approves it, then the servant confirms. Use `ic pair` to inspect requests and `ic nodes` to inspect relationships and online status.

## MCP and sessions

`ic mcp` manages providers with `add`, `remove`, `update` and `list`; `give` installs IC as an MCP entry for a selected harness. IC tools and aggregated provider tools have distinct origins. Enablement and visibility are separate from remote grants: an externally provided tool hidden locally cannot be exposed to masters. IC built-in execution tools are always hidden from the local agent.

Agent-facing IC tools use `ic_*` names. `ic_peer {peerId}` selects an already-paired servant as a persistent session default; an optional per-call `peerId` overrides only that call. Without either, remote calls return `PEER_REQUIRED`. Agent tools cannot pair nodes or grant permissions. The built-in catalog contains 15 ordinary tools or 11 local-sync tools. `ic_process` combines status/output/cancel; local-sync uses `ic_workspace` for scope selection. Chunk/resource wrappers, separate job-control wrappers and agent exec stdin are removed, while internal primitives and execution history remain.

An agent supplies its current working directory when opening a session. IC resolves the target workspace through directory bindings in `nodes.json`. Omitted cwd selects a session-specific temporary directory on each target; targets may disable temporary sessions. Explicit but unmapped directories are not silently replaced with temporary directories. Session records persist as execution history.

## Documentation

- [CLI and harness integration](docs/pi-integration.md)
- [Operations and configuration](docs/operations.md)
- [Pairing](docs/pairing.md)
- [Directory bindings and sessions](docs/workspace-bindings.md)
- [MCP providers and visibility](docs/pi-resources.md)
- [Remote tools](docs/remote-tools.md)
- [Directory permissions](docs/directory-permissions.md)
- [Synchronization](docs/local-sync.md)
- [Durability and recovery](docs/durability.md)
- [Testing](docs/testing.md)
- [Breaking migration](docs/migration.md)

## Trust boundary

Business transport uses TLS 1.3 mutual authentication and pinned peer identities. Tailnet access provides network reachability, not IC authorization. Filesystem APIs enforce path, link, directory and byte limits. Approved processes run with the service account's operating-system permissions; file ACLs are not a process sandbox.

Unknown side effects require inspection and explicit reconciliation. Cancellation does not prove that effects were rolled back. IC targets Linux and macOS; it does not promise cross-system exactly-once execution, NAT traversal, disk encryption or a production process sandbox.

License: [GNU AGPL v3](LICENSE).
