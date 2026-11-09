# Rust verification matrix

The current redesign requires fresh results. Historical logs in `verification/` remain evidence for their original binaries only. Do not report an unrun row as passing.

| Area | Required evidence |
|---|---|
| CLI/settings | Removed commands rejected; selected config and config check; no per-command config override |
| Storage | Separate config/nodes/MCP files; private atomic writes; UUID identity and display name |
| Pairing | Servant request, master selection/approval, servant confirmation, restart and revoke |
| Transport | Mutual TLS, pin/identity rejection, pooled connections, no uncertain replay |
| Sessions | Resident attachment, cwd mapping, temporary opt-out, persistence and history |
| MCP | Provider CRUD, harness give, origin distinction, per-tool/server visibility and enablement |
| Files/processes | ACL/path/link limits, approved code, bounded output and cancellation |
| Recovery | Durable unknown gates, reconciliation, workspace locks and policy epochs |
| Web | Replaceable configured entry, authentication, CSRF and path safety |
| Cross-host | Local machine and tky; exact binary hashes and isolated state |
| Harness | Real installed clients with deterministic mock-model; report skips |

Run fmt, clippy, targeted tests and full regression as appropriate. See [testing instructions](testing.md).
