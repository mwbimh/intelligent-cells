# MCP aggregation and approved resources

IC aggregates external stdio MCP providers as well as exposing approved remote IC tools. Provider metadata belongs in `mcp.json`; node relationships and grants belong in `nodes.json`. Origins distinguish IC tools from external providers rather than presenting them as indistinguishable tools.

```sh
ic mcp list
ic mcp add --name math --definition '{"file":"/opt/approved/math-mcp","args":[],"launchMode":"native","cwd":"/srv/mcp","visibility":{"local":true,"masters":[]}}'
ic mcp update --id PROVIDER_UUID --patch '{"enabled":false}'
ic mcp remove --id PROVIDER_UUID
```

Provider discovery executes the approved program, so review the executable and its dependencies before adding it. The provider cwd must be canonical and absolute. Approved code must remain outside remotely writable workspaces. The command lists discovered tools and stores approved schemas; upstream descriptions or annotations cannot expand permission.

## Enablement and visibility

Providers and individual tools have `enabled` and `visibility` settings. Visibility contains `local` and `masters`; masters is either `"all"` or an array of node UUIDs. Provider and tool rules intersect. New providers default to local visibility without master access.

```json
{"enabled":true,"visibility":{"local":true,"masters":["MASTER_UUID"]}}
```

An external provider/tool hidden locally is also hidden from every master, even if its master selector says all. Master visibility does not bypass incoming grants or workspace policy. IC built-in tools are always hidden locally and have separate remote controls:

```sh
ic mcp builtin --tool readFile --patch '{"enabled":true,"masters":"all"}'
```

Use `mcp update` with the provider's `tools` settings to adjust individual external tools. Review the existing entry before applying a patch.

## Approved resources

`resourceList` and `resourceRead` access owner-approved instruction, skill or prompt aliases. Resource paths, optional SHA-256, UTF-8 validity, byte budgets and directory ACLs are checked. Resource text is data; it cannot grant execution or credentials.

The stdio MCP transport uses bounded JSON-RPC messages and fixed supported protocol behavior. Providers run with the service account's OS permissions; file ACLs are not a process sandbox. Unknown side effects require reconciliation rather than automatic retry. See [durability](durability.md).
