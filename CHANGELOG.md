# Changelog

## 0.6 — resident service redesign

Breaking CLI and storage redesign: remove `call`, `launch` and `identity-fixture`; replace `check-config` with `config check`, `owner` with node/pair management, and `mock-server` with `mock-model`. Configuration selection belongs to `config`.

Separate runtime settings, UUID-based node relationships/directory bindings, and MCP aggregation records. Automatically provision node identities. Keep IC resident while agent sessions attach with cwd mappings or permitted per-session temporary workspaces. Persist sessions as execution history.

Add MCP provider management, harness registration, explicit origin labels, tool/server enablement and visibility controls. Make the operator page entry configurable. Maintained documentation and user-facing project text use English. New cross-host acceptance targets tky.

These release notes describe the redesign scope, not a claim that every acceptance check has run. Consult verification logs for completed validation.

## 0.5 — historical Rust runtime

Replaced the JavaScript node runtime with Rust; retained the browser UI. Added authenticated remote tools, durable tasks/jobs, directory permissions, local synchronization, controlled MCP providers, pooled connections and dynamic pairing. Runtime logs use English text with field-specific terminal colors and an optional JSON format. Historical validation artifacts remain in `verification/`.
