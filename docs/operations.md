# Operations

## Runtime settings

`IC_HOME` defaults to `~/.config/ic`. Its private `selection.json` records the selected absolute `configPath`. `ic config init` initializes the default installation; `ic config init --config /absolute/config.json` initializes a chosen settings file. `ic config use --config FILE` selects an existing file.

```sh
ic config show
ic config set --key sessions.allowTemporary --value false
ic config check
ic serve --operator
```

The minimal runtime settings are:

```json
{"version":2,"host":"127.0.0.1","port":18433,"pairing":{"host":"127.0.0.1","port":18434},"security":{"allowExternal":false},"sessions":{"allowTemporary":true}}
```

`config set` validates and saves settings, then reports `restartRequired:true`. Restart the resident service to apply runtime-setting changes.

External listening requires `security.allowExternal:true`. For tailnet operation, use the node's actual tailnet address and allow the business/pairing ports in network policy. Tailnet does not replace IC identity or tool authorization.

Runtime settings exclude node IDs/names, peers, grants, certificate paths and trust pins. Adjacent `nodes.json` contains identity, relationships, grants and bindings; `mcp.json` contains provider settings. The adjacent `state/` directory stores runtime records. Private identity material is provisioned under `identity/<UUID>/` and must not be copied between nodes.

Automatic provisioning creates a stable UUID and node certificate material. It removes the manual certificate fixture workflow; do not interpret initial provisioning as a claim of tested unattended rotation or renewal. Back up the private installation consistently and protect it with the service account's permissions.

## Resident service

`serve` stays in the foreground without reading stdin. `--daemon` is a redundant supported flag. Use the operating system's service manager for automatic restarts and boot startup. One process owns a state directory. Harness MCP sessions connect to that process instead of starting competing listeners. Local management uses a private same-user socket. After a crash, startup removes a stale socket only when it is private, owned, single-link, refuses connections, and retains the same filesystem identity through the check. Live, unsafe or ambiguous paths are preserved and startup fails explicitly.

## Replaceable web entry

```json
{"operator":{"enabled":true,"uiRoot":"/absolute/custom-ui","entry":"index.html"}}
```

`operator.uiRoot` selects a directory of static assets; `operator.entry` selects a relative HTML entry within it. An entry requires a UI root. Assets remain subject to path and link validation. The bundled UI is available when no custom root is selected. Replacing the page does not remove API authentication, bootstrap/session protection, origin checks or CSRF requirements. Keep `/api` reserved for the management API.

## Runtime logs

Text logs use English messages and separate terminal colors: dim timestamps, severity colors, cyan nodes, purple tools and yellow elapsed time. Colors require a terminal and are disabled by `NO_COLOR` or `TERM=dumb`. Redirected output is plain text; JSON never contains ANSI.

```sh
ic serve --daemon --log-format json
```

Runtime logs use stderr. MCP stdout is reserved for protocol messages. Audit records remain structured and bounded; secrets, raw arguments and raw tool results are not logged indiscriminately.

## Connections and synchronization

`transport.idleTimeoutMs` defaults to 30000 and `transport.maxConnectionsPerPeer` to 4. Tasks share bounded authenticated data connections; query/cancel/ping use a separate control lane. Idle connections retire before the negotiated timeout. A sent request is not automatically replayed after connection loss.

The optional rsync backend requires approved rsync 3.4.1 or newer with an absolute executable and SHA-256 pin on both ends. Deploy `ic-rsync-stdio` alongside `ic`, as a regular single-link executable. Traffic uses IC mTLS, not SSH or an additional port. See [synchronization](local-sync.md).

New deployment acceptance uses `tky` and isolated local state. Existing historical cal deployments are not the target for this redesign.
