# Multi-host mock verification

Use the local machine and `tky` for new cross-host testing. Do not deploy this redesign to `cal`. Keep acceptance configuration, state, workspaces and model mocks isolated from production paths.

Start resident services on both hosts over tailnet. Verify automatically provisioned distinct identities, servant-initiated pairing, explicit master approval and servant confirmation, UUID records, and persistence across restarts. Pairing alone must not permit a tool call.

Grant only the test workspace and required tools. Attach a harness session with a bound cwd and verify target placement. Also test omitted cwd, target temporary-directory opt-out, an unmapped explicit cwd, session history, online status and revoked permissions.

For MCP aggregation, test distinct IC/external origin labels, provider/tool enablement, local visibility, all-master and selected-master visibility, and the rule that locally hidden external tools cannot be exposed remotely.

Use `ic mock-model` with a deterministic script and a real installed harness. A hand-written tool client is protocol coverage, not proof that the harness integration works. Archive exact commands, logs and binary hashes. Report skipped harnesses and unavailable dependencies explicitly; documentation commands alone are not pass evidence.
