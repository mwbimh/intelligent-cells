use intelligent_cells::{harness, node::Node, policy, tls::certificate_identity};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

fn node(root: &Path, id: &str, master: bool) -> Arc<Node> {
    let identity = root.join(format!("{id}-identity"));
    harness::fixture(&identity, &[id.into()]).unwrap();
    let workspace = root.join(format!("{id}-workspace"));
    std::fs::create_dir(&workspace).unwrap();
    let config = json!({
        "id":id,"host":"127.0.0.1","port":0,
        "agent":if master {json!("deterministic-demo")} else {Value::Null},
        "stateDir":root.join(format!("{id}-state")), "peers":[],
        "pairing":{"host":"127.0.0.1","port":0},
        "security":{"cert":identity.join(format!("{id}.pem")),
            "key":identity.join(format!("{id}.key")),"ca":identity.join("ca.pem"),
            "trustedPeers":{}},"policy":{"grants":{}}
    });
    let path = root.join(format!("{id}.json"));
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let n = Node::new(policy::load_config(&path).unwrap()).unwrap();
    n.start().unwrap();
    n
}
fn endpoint(master: &Node) -> Value {
    let s = master.command(&json!({"command":"pairingStatus"})).unwrap();
    json!({"id":master.config().id,"host":"127.0.0.1","port":s["port"],
        "fingerprint256":s["identity"]["fingerprint256"]})
}
fn request(servant: &Node, master: &Value) -> Value {
    servant
        .command(&json!({"command":"pairingRequest","master":master}))
        .unwrap()
}
fn approve(master: &Node, servant: &Node, request: &Value) {
    let pin = certificate_identity(
        &std::fs::read(servant.config().raw["security"]["cert"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    master
        .command(
            &json!({"command":"pairingApprove","requestId":request["requestId"],
        "expectedFingerprint":pin["fingerprint256"]}),
        )
        .unwrap();
}
fn echo(master: &Node, id: &str) -> Value {
    master
        .dispatch(
            "servant",
            &json!({"taskId":id,"tool":"echo","args":{"text":id},"timeoutMs":2000}),
        )
        .unwrap()
}

#[test]
fn servant_initiated_pairing_is_live_durable_and_requires_both_owners() {
    let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let master = node(d.path(), "master", true);
    let servant = node(d.path(), "servant", false);
    let address = endpoint(&master);
    let joined = request(&servant, &address);
    assert!(
        master.command(&json!({"command":"listPeers"})).unwrap()["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(servant.command(&json!({"command":"pairingConfirm","master":address,"requestId":joined["requestId"]})).is_err());
    approve(&master, &servant, &joined);
    assert!(
        master.command(&json!({"command":"listPeers"})).unwrap()["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let grant = json!({"workspace":d.path().join("servant-workspace"),"tools":["echo"],"maxTimeoutMs":3000});
    servant.command(&json!({"command":"pairingConfirm","master":address,"requestId":joined["requestId"],"grant":grant})).unwrap();
    let reply = echo(&master, "paired_live");
    assert_eq!(reply["status"], "ok", "{reply}");
    let peers = master.command(&json!({"command":"listPeers"})).unwrap();
    assert_eq!(peers["peers"][0]["id"], "servant");
    assert!(
        servant.command(&json!({"command":"listPeers"})).unwrap()["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // No one rewrites the user's static config to simulate dynamic registration.
    let original: Value =
        serde_json::from_slice(&std::fs::read(&master.config().path).unwrap()).unwrap();
    assert_eq!(original["peers"], json!([]));
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
    let restored = Node::new(policy::load_config(&master.config().path).unwrap()).unwrap();
    assert_eq!(
        restored.command(&json!({"command":"listPeers"})).unwrap()["peers"][0]["id"],
        "servant"
    );
    let restored_servant = Node::new(policy::load_config(&servant.config().path).unwrap()).unwrap();
    assert_eq!(
        restored_servant
            .command(&json!({"command":"permissions"}))
            .unwrap()["policy"]["grants"]["master"]["tools"],
        json!(["echo"])
    );
    restored.shutdown().unwrap();
    restored_servant.shutdown().unwrap();
}

#[test]
fn pairing_rejects_wrong_pin_and_does_not_grant_tools_implicitly() {
    let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let master = node(d.path(), "master", true);
    let servant = node(d.path(), "servant", false);
    let address = endpoint(&master);
    let mut bad = address.clone();
    bad["fingerprint256"] = json!("00".repeat(32));
    assert!(
        servant
            .command(&json!({"command":"pairingRequest","master":bad}))
            .is_err()
    );
    assert!(
        master
            .command(&json!({"command":"listPairingRequests"}))
            .unwrap()["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let joined = request(&servant, &address);
    assert!(master.command(&json!({"command":"pairingApprove","requestId":joined["requestId"],"expectedFingerprint":"00".repeat(32)})).is_err());
    approve(&master, &servant, &joined);
    servant
        .command(
            &json!({"command":"pairingConfirm","master":address,"requestId":joined["requestId"]}),
        )
        .unwrap();
    assert_eq!(echo(&master, "no_grant")["status"], "error");
    master
        .command(&json!({"command":"unpair","peerId":"servant"}))
        .unwrap();
    assert!(
        master.command(&json!({"command":"listPeers"})).unwrap()["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(servant.command(&json!({"command":"pairingConfirm","master":address,"requestId":joined["requestId"]})).is_err());
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
}

#[test]
fn bootstrap_rejects_owner_actions_and_identity_impersonation() {
    use intelligent_cells::{tls::Security, wire};
    use std::io::BufReader;
    let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let master = node(d.path(), "master", true);
    let servant = node(d.path(), "servant", false);
    let other = node(d.path(), "other", false);
    let address = endpoint(&master);
    let cfg = servant.config();
    let security =
        Security::load(&cfg.raw["security"], cfg.path.parent().unwrap(), "servant").unwrap();
    let own = servant
        .command(&json!({"command":"pairingStatus"}))
        .unwrap()["identity"]
        .clone();
    let foreign = other.command(&json!({"command":"pairingStatus"})).unwrap()["identity"].clone();
    for (action, identity) in [("approve", own), ("request", foreign)] {
        let stream = security
            .pairing_connect_pinned(
                "127.0.0.1",
                address["port"].as_u64().unwrap() as u16,
                "master",
                address["fingerprint256"].as_str().unwrap(),
            )
            .unwrap();
        let mut reader = BufReader::new(stream);
        assert_eq!(
            wire::read_frame(&mut reader).unwrap().unwrap()["type"],
            "pairing_identity"
        );
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 60_000;
        wire::write_frame(
            reader.get_mut(),
            &json!({"type":"pairing","v":1,"action":action,
            "identity":identity,"requestId":uuid::Uuid::new_v4().to_string(),
            "endpoint":{"host":"127.0.0.1","port":servant.port()},"expiresAt":expires}),
        )
        .unwrap();
        let response = wire::read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(response["ok"], false);
        assert_eq!(
            response["error"]["code"],
            if action == "approve" {
                "PAIRING_DENIED"
            } else {
                "IDENTITY_MISMATCH"
            }
        );
    }
    assert_eq!(
        master.command(&json!({"command":"listPeers"})).unwrap()["peers"],
        json!([])
    );
    assert_eq!(
        master
            .command(&json!({"command":"listPairingRequests"}))
            .unwrap()["requests"],
        json!([])
    );
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
    other.shutdown().unwrap();
}

#[test]
fn rejected_request_cannot_be_confirmed_or_approved_later() {
    let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let master = node(d.path(), "master", true);
    let servant = node(d.path(), "servant", false);
    let address = endpoint(&master);
    let joined = request(&servant, &address);
    master
        .command(&json!({"command":"pairingReject","requestId":joined["requestId"]}))
        .unwrap();
    assert!(servant.command(&json!({"command":"pairingConfirm","master":address,"requestId":joined["requestId"]})).is_err());
    assert!(
        master
            .command(
                &json!({"command":"pairingApprove","requestId":joined["requestId"],
        "expectedFingerprint":joined["identity"]["fingerprint256"]})
            )
            .is_err()
    );
    assert_eq!(
        master.command(&json!({"command":"listPeers"})).unwrap()["peers"],
        json!([])
    );
    assert!(
        servant.command(&json!({"command":"permissions"})).unwrap()["policy"]["grants"]["master"]
            .is_null()
    );
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
}

#[test]
fn unpair_survives_restart_and_blocks_fresh_registration() {
    let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let master = node(d.path(), "master", true);
    let servant = node(d.path(), "servant", false);
    let address = endpoint(&master);
    let joined = request(&servant, &address);
    approve(&master, &servant, &joined);
    servant
        .command(
            &json!({"command":"pairingConfirm","master":address,"requestId":joined["requestId"]}),
        )
        .unwrap();
    master
        .command(&json!({"command":"unpair","peerId":"servant"}))
        .unwrap();
    let config = master.config().path;
    master.shutdown().unwrap();
    let restored = Node::new(policy::load_config(&config).unwrap()).unwrap();
    restored.start().unwrap();
    assert_eq!(
        restored.command(&json!({"command":"listPeers"})).unwrap()["peers"],
        json!([])
    );
    let fresh = endpoint(&restored);
    assert!(
        servant
            .command(&json!({"command":"pairingRequest","master":fresh}))
            .is_err()
    );
    assert!(
        servant
            .command(
                &json!({"command":"pairingConfirm","master":fresh,"requestId":joined["requestId"]})
            )
            .is_err()
    );
    assert_eq!(
        restored.command(&json!({"command":"listPeers"})).unwrap()["peers"],
        json!([])
    );
    restored.shutdown().unwrap();
    servant.shutdown().unwrap();
}

#[test]
fn type_only_pairing_reject_never_approves_the_request() {
    let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let master = node(d.path(), "master", true);
    let servant = node(d.path(), "servant", false);
    let address = endpoint(&master);
    let joined = request(&servant, &address);
    // Supplying the correct pin must not turn a type-only reject into approve.
    master
        .command(
            &json!({"type":"pairingReject","requestId":joined["requestId"],
        "expectedFingerprint":joined["identity"]["fingerprint256"]}),
        )
        .unwrap();
    let requests = master
        .command(&json!({"command":"listPairingRequests"}))
        .unwrap();
    assert_eq!(requests["requests"][0]["status"], "rejected");
    assert!(servant.command(&json!({"command":"pairingConfirm","master":address,"requestId":joined["requestId"]})).is_err());
    assert_eq!(
        master.command(&json!({"command":"listPeers"})).unwrap()["peers"],
        json!([])
    );
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
}

#[test]
fn full_bootstrap_pool_does_not_block_business_or_shutdown() {
    use intelligent_cells::{tls::Security, wire};
    use std::io::{BufReader, Write};
    let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let master = node(d.path(), "master", true);
    let servant = node(d.path(), "servant", false);
    let address = endpoint(&master);
    let joined = request(&servant, &address);
    approve(&master, &servant, &joined);
    servant.command(&json!({"command":"pairingConfirm","master":address,"requestId":joined["requestId"],
        "grant":{"workspace":d.path().join("servant-workspace"),"tools":["echo"],"maxTimeoutMs":3000}})).unwrap();
    // Fill the servant's bootstrap pool so the following business request must
    // still be admitted by that same node's independent authenticated listener.
    let target = endpoint(&servant);
    let cfg = master.config();
    let security =
        Security::load(&cfg.raw["security"], cfg.path.parent().unwrap(), "master").unwrap();
    let mut streams = Vec::new();
    for _ in 0..8 {
        let stream = security
            .pairing_connect_pinned(
                "127.0.0.1",
                target["port"].as_u64().unwrap() as u16,
                "servant",
                target["fingerprint256"].as_str().unwrap(),
            )
            .unwrap();
        let mut reader = BufReader::new(stream);
        assert_eq!(
            wire::read_frame(&mut reader).unwrap().unwrap()["type"],
            "pairing_identity"
        );
        reader.get_mut().write_all(b" ").unwrap();
        streams.push(reader);
    }
    assert_eq!(echo(&master, "bootstrap_pool_full")["status"], "ok");
    let (send, recv) = std::sync::mpsc::channel();
    let stopping = servant.clone();
    let thread = std::thread::spawn(move || {
        send.send(stopping.shutdown()).unwrap();
    });
    recv.recv_timeout(std::time::Duration::from_secs(10))
        .expect("shutdown must close unfinished bootstrap clients")
        .unwrap();
    thread.join().unwrap();
    drop(streams);
    master.shutdown().unwrap();
}
