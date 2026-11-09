# Persistent sessions, tasks and recovery

One resident runtime owns a private `stateDir`. MCP clients attach sessions to that process; they do not start a competing node. Session records persist the selected cwd, target mappings and execution history.

Outgoing tasks are persisted before sending; incoming tasks are persisted before execution. Records use checksums, atomic replacement and fsync. Corrupt state, failed persistence and stale locks reject operations explicitly.

An identical request with the same identity/task ID reuses the retained result. Changed arguments conflict. Retired IDs have bounded tombstones and are not re-executed. Active and unknown records are not automatically evicted; storage exhaustion rejects new work.

Local management can inspect `listTasks`, `taskStatus`, `operationStatus` and remote `query`. Unknown mutations block later side effects; changing a task or run ID cannot bypass the block. Inspect actual files, processes and external systems before reconciling:

```json
{"command":"reconcile","masterId":"PEER_UUID","taskId":"write_1","resolution":"effects-inspected","note":"Inspected file contents and confirmed execution has stopped"}
```

Outgoing records use `peerId` instead of `masterId`. `reconcileJob` handles background jobs. Cancellation is not rollback. IC does not automatically retry an unknown write.

Reconciling an outgoing task also updates matching persistent session records. The original unknown execution remains in `history`; the resolved record stores the inspection note, resolution and timestamp. `listSessions` applies any previously saved outgoing reconciliation that has not yet reached the session record. The outgoing ledger is authoritative, and reconciliation never makes the consumed task ID reusable.

Policy epochs and revocations persist in node records. Stale results cannot be accessed through a new grant. A transport may reconnect before sending a request; once sent, a disconnected request is not silently replayed. Query/cancel use a separate bounded control connection so long tasks cannot consume all control capacity.

## Local aggregated MCP recovery

An uncertain local aggregated MCP mutation blocks later local MCP mutations across sessions and restarts. Changing the session or task ID does not bypass this gate. Read-only calls remain available. Inspect the provider's actual effects and confirm execution has stopped before reconciling the unknown record:

```sh
ic nodes command --json '{"command":"listSessions"}'
ic nodes command --json '{"command":"sessionReconcile","sessionId":"SESSION_UUID","taskId":"TASK_UUID","note":"Inspected provider effects and confirmed execution has stopped"}'
```

`sessionReconcile` is a local management action, not an agent tool. It accepts only an unknown local aggregated MCP record and a printable inspection note. It records the owner's decision; it does not undo effects or rerun the call.
