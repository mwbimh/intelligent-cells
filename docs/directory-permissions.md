# Directory permissions

The receiving node's owner controls grants. A remote master cannot submit policy to increase its own permissions. Grants and directory bindings belong in `nodes.json`, not runtime settings.

Each grant may select a default workspace, named workspaces, or explicitly approved creation roots. Directory rules apply relative to the selected workspace:

```json
{"directories":[{"path":"docs","read":true,"write":false},{"path":"work","read":true,"write":true},{"path":"work/private","read":false,"write":false}]}
```

`""` denotes the workspace root. Rules require both boolean fields. Absolute paths, parent traversal, empty segments, backslashes, unsafe names, links and duplicate rules are rejected. Existing rule paths must be directories. At most 128 rules and 500 UTF-8 bytes per path are accepted.

Omitting `directories` permits the whole workspace subject to the tool allowlist. An empty array denies all file access. In restricted mode, unmatched paths are denied. The longest complete directory prefix wins and replaces both permissions. Removing a rule restores inheritance; explicit false/false revokes a subtree. Files use the rule for their containing directory.

| Tool | Required directory permission |
|---|---|
| `readFile`, `readChunk`, `resourceRead` | read |
| `writeFile`, `writeChunk`, `mkdir` | write |
| `editFile` | read and write |
| `listDirectory`, `searchFiles`, `resourceList` | read, with inaccessible entries filtered |

Tool grants, directory rules, byte budgets and path safety all apply. Write does not imply read. Write-only access is not a guarantee that file existence or size remains secret. Listing/searching an unreadable starting directory fails; recursive search prunes denied subtrees even when a deeper rule would allow direct access.

## Process permissions

`exec`, `syncExec`, `mcpList` and `mcpCall` start approved processes. Directory ACLs do not constrain their operating-system access. Combining process tools with directory rules requires `allowUnsandboxedProcesses:true`. Approved code must remain outside remotely writable roots. Use a separate restricted account or container when operating-system isolation is required.

## Changes and revocation

Local management uses `setPolicy` with `expectedEpoch`. A stale epoch returns `POLICY_CONFLICT`; refresh before saving. Updates validate the complete policy, persist it and increment the epoch. Old tasks/jobs are cancelled; effects already produced remain. Old-epoch cached results and job controls cannot bypass current grants.

The authenticated operator API retains session, CSRF and origin checks. Remote capabilities reveal relative rules, not physical workspace paths. `DIRECTORY_DENIED` reports ACL rejection; `PATH_DENIED` reports unsafe task paths. Rejected writes are not reported as unknown effects when execution never started.
