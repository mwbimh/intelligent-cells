# Servant-initiated pairing

The servant requests admission to a master. The master inspects and approves the request; the servant confirms. The relationship becomes visible without restarting either resident service. Identity, authorization and network reachability remain separate decisions.

Initialize both nodes through `ic config init`; node UUIDs and certificate material are provisioned automatically. Configure reachable business and pairing listeners. The servant contacts the master's pairing port, while the master must reach the servant's business port.

```sh
ic pair status
ic pair list
```

Exchange UUIDs and full certificate SHA-256 fingerprints over a trusted channel. Pairing requires UUID node identities; display names and legacy name-based identities are not accepted as identity keys. Do not trust a fingerprint solely because it appears in an unapproved request.

On the servant, request admission using the master's verified identity:

```sh
ic pair request --master '{"id":"MASTER_UUID","host":"MASTER_TAILNET_ADDRESS","port":18434,"fingerprint256":"MASTER_SHA256"}'
```

On the master, inspect requests, select the intended request and approve its verified servant fingerprint:

```sh
ic pair list
ic pair approve --request REQUEST_ID --fingerprint SERVANT_SHA256
```

Use `ic pair reject --request REQUEST_ID` to reject a request. On the servant, confirm:

```sh
ic pair confirm --request REQUEST_ID --master '{"id":"MASTER_UUID","host":"MASTER_TAILNET_ADDRESS","port":18434,"fingerprint256":"MASTER_SHA256"}'
```

An optional `--grant JSON` carries an explicitly reviewed grant. Omitting it grants no tools. Pairing does not imply file access, process execution or reverse authorization.

```sh
ic nodes list
ic nodes status
ic nodes status --peer PEER_UUID
```

Node records persist in `nodes.json`, including UUID identity, display name, relationships and trust. Outgoing peers are probed in parallel; a live authenticated incoming connection also marks a peer online. Bidirectional relationships retain both roles. An inbound-only master without a live connection or an outgoing endpoint has unknown status, not a fabricated offline result. Online status is observed runtime state, not a promise that the next task will succeed. MCP agents can discover approved remote peers but cannot approve pairing or grant themselves tools.

Local management can revoke a relationship with `ic nodes command --json '{"command":"unpair","peerId":"PEER_UUID"}'`. Remove records on both ends when intentionally dismantling both sides. Revoked requests cannot silently restore permission.
