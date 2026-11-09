# Breaking v0.6 migration

This redesign intentionally provides no legacy CLI aliases or automatic combined-file compatibility.

| Removed interface | Replacement |
|---|---|
| `call`, `launch` | Resident service plus harness MCP sessions; launch the harness directly |
| `check-config` | `config check` |
| `owner` | `nodes`, `pair` and authenticated local management |
| `mock-server` | `mock-model` |
| `identity-fixture` | Automatic node identity/certificate provisioning |
| Per-command `--config` | Select settings with `config` |
| `mcp` owning the node process | MCP management and sessions attached to resident service |
| Name-based persisted identities | UUID identity plus separate display name |
| Combined runtime/peer/MCP settings | Separate `config.json`, `nodes.json`, `mcp.json` |

Keep a backup of previous configuration and state. Create the new settings layout, inspect identity/trust records, pair nodes explicitly, and recreate reviewed grants and directory bindings. Do not copy old names into UUID keys or assume pairing grants tools. Do not silently import stale certificates or permissions.

Update harness MCP entries through `mcp give`. Supply the agent cwd for mapped workspaces, or deliberately omit it for target-approved temporary sessions. Future cross-host acceptance uses `tky`; historical `cal` evidence is not validation of this release.
