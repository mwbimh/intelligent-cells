use intelligent_cells::{harness, node::Node, node_store, policy, settings};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

fn production(root: &Path) -> Arc<Node> {
    let path = settings::initialize(Some(&root.join("config.json"))).unwrap();
    settings::set_config(&path, "port", json!(0)).unwrap();
    settings::set_config(&path, "pairing.port", json!(0)).unwrap();
    let node = Node::new(settings::check_config(&path).unwrap()).unwrap();
    node.start().unwrap();
    node
}
fn named_fixture(root: &Path) -> Arc<Node> {
    let directory = root.join("legacy");
    harness::fixture(&directory, &["display-name".into()]).unwrap();
    let raw = json!({"id":"display-name","host":"127.0.0.1","port":0,"agent":"deterministic-demo","peers":[],
        "stateDir":root.join("state"),"security":{"cert":directory.join("display-name.pem"),"key":directory.join("display-name.key"),"ca":directory.join("ca.pem"),"trustedPeers":{}},"policy":{}});
    let path = root.join("fixture.json");
    std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    let node = Node::new(policy::load_config(&path).unwrap()).unwrap();
    node.start().unwrap();
    node
}
fn endpoint(node: &Node) -> Value {
    let status = node.command(&json!({"command":"pairingStatus"})).unwrap();
    json!({"id":node.config().id,"host":"127.0.0.1","port":status["port"],"fingerprint256":status["identity"]["fingerprint256"]})
}

#[test]
fn production_rejects_display_name_identity_before_recording_request() {
    let d = tempfile::tempdir().unwrap();
    let master = production(&d.path().join("master"));
    let servant = named_fixture(&d.path().join("servant"));
    let result = servant.command(&json!({"command":"pairingRequest","master":endpoint(&master)}));
    assert!(
        result.is_err(),
        "display name was accepted as node identity: {result:?}"
    );
    assert!(
        master
            .command(&json!({"command":"listPairingRequests"}))
            .unwrap()["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        master.config().raw["security"]["trustedPeers"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    servant.shutdown().unwrap();
    master.shutdown().unwrap();
}

#[test]
fn production_rejects_named_master_before_dialing() {
    let d = tempfile::tempdir().unwrap();
    let node = production(d.path());
    for command in ["pairingRequest", "pairingConfirm"] {
        let error = node.command(&json!({"command":command,"requestId":uuid::Uuid::new_v4().to_string(),"master":{"id":"display-name","host":"127.0.0.1","port":1,"fingerprint256":"a".repeat(64)}})).unwrap_err();
        assert_eq!(error.code, "PAIRING_DENIED");
        assert!(error.message.contains("UUID"), "{error}");
    }
    node.shutdown().unwrap();
}

#[test]
fn production_rejects_persisted_named_identity_before_installing_trust() {
    let d = tempfile::tempdir().unwrap();
    let master = production(&d.path().join("master"));
    let peer = named_fixture(&d.path().join("peer"));
    let identity = peer.command(&json!({"command":"pairingStatus"})).unwrap()["identity"].clone();
    let config = master.config();
    master.shutdown().unwrap();
    drop(master);
    node_store::write_section(
        &node_store::directory(&config),
        "pairing",
        &json!({"nodeId":config.id,"requests":[],"peers":[{"identity":identity,"endpoint":null}]}),
    )
    .unwrap();
    let result = Node::new(config);
    match result {
        Ok(node) => {
            node.shutdown().unwrap();
            panic!("Persisted display name accepted as node identity");
        }
        Err(error) => {
            assert_eq!(error.code, "PAIRING_DENIED");
            assert!(error.message.contains("UUID"), "{error}");
        }
    }
    peer.shutdown().unwrap();
}
