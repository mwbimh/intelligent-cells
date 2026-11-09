# Testing and acceptance

Write or update meaningful tests before implementation. Create or select a visible Herdr build pane, verify its current pane ID, and run builds and tests there; do not reuse a stale hardcoded pane ID or create hidden parallel build terminals. Use `umask 077` and a fresh canonical private `TMPDIR` so workspace locks from earlier runs do not contaminate results.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets -- --test-threads=1
cargo build --release --bin ic --bin ic-rsync-stdio
```

Unit tests live in `src/`; integration tests live in `tests/`. `ic-mcp-fixture` is a deterministic protocol fixture, not a production provider. Real harness acceptance must run the installed harness against a loopback model mock; tests that return early because an environment variable is absent are skipped coverage, not successful harness runs.

## Current agent-tool simplification

Final local fmt, clippy, release build and full regression passed (`SIMPLIFY_FINAL_RC=0`): 246 reported passes, 0 failures and 11 ignored. Three external harness tests returned early without their required environment, so 243 tests exercised their scenarios. Linux targeted regression passed 35 tests (14 harness/protocol, 2 process, 2 peer, 1 sync and 16 session tests), and its release build passed (`TKY_SIMPLIFY_RC=0`). These runs do not add actual external-harness coverage.

Both isolated services were updated and restarted. The local live MCP catalog contains exactly 15 ordinary or 11 local-sync tools. Tailnet selection and bridge resume passed, including remote execution and old-alias rejection. The captured success label incorrectly says `restart_retains`; that check resumed the MCP bridge without restarting the resident service between selection and resume. An intermediate rerun failed during SSH setup before an IC call because the connection reset. The final rerun with the corrected label then passed selection and bridge resume. The retained network interruption does not establish a product test failure. See the [simplification report](../verification/tool-simplification/REPORT.md) for evidence and limits.

## Previous tool namespace and peer-selection checks

The `ic_*` namespace and persistent `ic_peer` session default passed final local fmt, clippy, release build and full regression (`PEER_FINAL_RC=0`). The test log reports 242 passes, 0 failures and 11 ignored. Three external harness tests returned early because their environment was absent, so 239 tests exercised their scenarios. Coverage includes the namespace without old aliases, default selection, per-call overrides, switching, restart persistence, unpair rejection, directory bindings and synchronization. Existing production capabilities were not removed.

The local resident service was restarted with the latest release. A real stdio `tools/list` returned 22 `ic_*` tools, including `ic_peer`. New tky verification and deployment were not completed: SSH timed out, including an escalated retry. A partial source transfer was attempted; no new remote build or service restart was performed. Earlier v0.6 remote results do not validate this feature. See the [peer-selection report](../verification/ic-peer/REPORT.md).

## Previous v0.6 acceptance

New remote verification targets `tky`, not `cal`. Required coverage includes breaking CLI rejection, selected configuration discovery, separated private stores, UUID/name identity, automatic certificate provisioning, dynamic pairing, node status, MCP aggregation and visibility, resident sessions, cwd bindings, temporary-directory opt-out, persisted execution history, and configurable web entry serving.

Final local fmt, clippy, release build and full Rust regression passed (`LOCAL_FINAL_RC=0`). The suite reports 239 passes, but 3 external harness tests returned early because their environment was absent: 236 tests exercised their scenarios. Eleven optional rsync tests remain ignored in this local run. The separate UI suite passed 5 tests.

The earlier Linux/tky full suite reported 235 passes, 0 failures and 11 ignored. Subsequent Linux checks passed: 16 final session tests, 1 managed aggregation test and all 11 optional rsync tests. The final Linux release build passed. These overlapping runs are not additive unique-test counts; the Linux full-suite run preceded the final reconciliation changes, which received targeted regression coverage.

Real local/tky tailnet acceptance passed for pairing, temporary and bound workspaces, resident MCP sessions, aggregation and visibility. Both services were restarted with the same identity/configuration; persistence, execution and aggregation were then verified again (`TAILNET_RESTART_RC=0`). Final local and remote source hashes match. No cal testing was performed.

The deployment is isolated test state: the local service runs in a foreground Herdr pane, and tky runs a detached `nohup` service. Neither is installed as a boot service. See the [v0.6 verification report](../verification/v06/REPORT.md) for logs, recovered failures and explicit coverage limits.

## Historical evidence

Prior v0.5 evidence remains under `verification/`: `colored-logs/`, `readable-logs/`, `dynamic-pairing/`, and the Rust, connection and rsync logs. These records describe earlier binaries and configuration formats. Historical `cal`, `shn` and `tky` checks do not validate the v0.6 redesign.

## Optional rsync verification

Use an explicitly approved absolute `IC_TEST_RSYNC` executable, version 3.4.1 or newer. Tests compute its pin; PATH discovery is not owner approval. Run the ignored rsync suite only when that dependency is available.

Linux Cargo output may hardlink companion executables. Copy the test binary and `ic-rsync-stdio` as ordinary independent files into a fresh private directory before running the ignored suite. Do not weaken the production single-link check or use `ln`.

```sh
cargo build --bin ic-rsync-stdio
cargo test --no-run --test rsync_backend
IC_TEST_RSYNC=/absolute/approved/rsync /absolute/private-test-dir/rsync_backend --include-ignored
```

## Limits of evidence

A passing test is scoped to the exercised scenario. Single latency samples are not throughput benchmarks. Browser visual acceptance, fault injection, certificate lifecycle and production isolation require explicit evidence; do not infer them from compilation or unit tests.
