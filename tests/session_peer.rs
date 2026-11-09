use intelligent_cells::{Config, harness, node::Node, tls::certificate_identity};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

fn config(dir: &Path, id: &str, peers: Value) -> Config {
    let mut trusted = serde_json::Map::new();
    for peer in ["master", "alpha", "beta"] {
        if peer != id {
            trusted.insert(
                peer.into(),
                certificate_identity(
                    &std::fs::read(dir.join("identity").join(format!("{peer}.pem"))).unwrap(),
                )
                .unwrap()["fingerprint256"]
                    .clone(),
            );
        }
    }
    let workspace = dir.join(format!("{id}-workspace"));
    std::fs::create_dir_all(&workspace).unwrap();
    let policy = if id == "master" {
        json!({"grants":{}})
    } else {
        json!({"grants":{"master":{"workspace":workspace,"tools":["echo","workspaceList"]}}})
    };
    Config {
        id: id.into(),
        host: "127.0.0.1".into(),
        port: 0,
        path: dir.join(format!("{id}.json")),
        state_dir: dir.join(format!("{id}-state")),
        raw: json!({"security":{"cert":dir.join("identity").join(format!("{id}.pem")),"key":dir.join("identity").join(format!("{id}.key")),"ca":dir.join("identity/ca.pem"),"trustedPeers":trusted},"policy":policy,"policyRaw":policy,"peers":peers}),
    }
}
struct Cluster {
    _dir: tempfile::TempDir,
    master: Arc<Node>,
    alpha: Arc<Node>,
    beta: Arc<Node>,
}
impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = self.master.shutdown();
        let _ = self.alpha.shutdown();
        let _ = self.beta.shutdown();
    }
}
fn cluster() -> Cluster {
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identity"),
        &["master".into(), "alpha".into(), "beta".into()],
    )
    .unwrap();
    let alpha = Node::new(config(dir.path(), "alpha", json!([]))).unwrap();
    alpha.start().unwrap();
    let beta = Node::new(config(dir.path(), "beta", json!([]))).unwrap();
    beta.start().unwrap();
    let master=Node::new(config(dir.path(),"master",json!([{"id":"alpha","host":"127.0.0.1","port":alpha.port()},{"id":"beta","host":"127.0.0.1","port":beta.port()}]))).unwrap();
    Cluster {
        _dir: dir,
        master,
        alpha,
        beta,
    }
}
fn call(node: &Node, id: &Value, name: &str, args: Value) -> intelligent_cells::Result<Value> {
    node.command(&json!({"command":"mcpCallTool","sessionId":id,"name":name,"arguments":args}))
}

#[test]
fn default_peer_persists_and_explicit_override_does_not_change_selection() {
    let cluster = cluster();
    let session = cluster
        .master
        .command(&json!({"command":"sessionOpen"}))
        .unwrap();
    let id = &session["sessionId"];
    assert_eq!(
        call(&cluster.master, id, "ic_echo", json!({"text":"missing"}))
            .unwrap_err()
            .code,
        "PEER_REQUIRED"
    );
    let selected = call(&cluster.master, id, "ic_peer", json!({"peerId":"alpha"})).unwrap();
    assert!(selected.to_string().contains("alpha"));
    let peers = call(&cluster.master, id, "ic_peers", json!({})).unwrap();
    let peers: Value = serde_json::from_str(peers["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(peers["sessionId"], *id);
    assert_eq!(peers["defaultPeerId"], "alpha");
    call(&cluster.master, id, "ic_echo", json!({"text":"selected"})).unwrap();
    call(
        &cluster.master,
        id,
        "ic_echo",
        json!({"peerId":"beta","text":"override"}),
    )
    .unwrap();
    let stored = cluster
        .master
        .command(&json!({"command":"sessionOpen","sessionId":id}))
        .unwrap();
    assert_eq!(stored["defaultPeerId"], "alpha");
    assert_eq!(stored["tasks"][0]["peerId"], "alpha");
    assert_eq!(stored["tasks"][1]["peerId"], "beta");
    assert_eq!(
        call(
            &cluster.master,
            id,
            "remote_echo",
            json!({"peerId":"alpha","text":"removed alias"})
        )
        .unwrap_err()
        .code,
        "TOOL_DENIED"
    );
    call(&cluster.master, id, "ic_peer", json!({"peerId":"beta"})).unwrap();
    call(&cluster.master, id, "ic_echo", json!({"text":"switched"})).unwrap();
    assert_eq!(
        cluster
            .master
            .command(&json!({"command":"sessionOpen","sessionId":id}))
            .unwrap()["defaultPeerId"],
        "beta"
    );
    let config = cluster.master.config();
    cluster.master.shutdown().unwrap();
    let resumed = Node::new(config).unwrap();
    assert_eq!(
        resumed
            .command(&json!({"command":"sessionOpen","sessionId":id}))
            .unwrap()["defaultPeerId"],
        "beta"
    );
    call(&resumed, id, "ic_echo", json!({"text":"after restart"})).unwrap();
    resumed
        .command(&json!({"command":"unpair","peerId":"beta"}))
        .unwrap();
    assert_eq!(
        call(&resumed, id, "ic_echo", json!({"text":"removed selection"}))
            .unwrap_err()
            .code,
        "UNKNOWN_PEER"
    );
    call(
        &resumed,
        id,
        "ic_echo",
        json!({"peerId":"alpha","text":"explicit remaining peer"}),
    )
    .unwrap();
    assert_eq!(
        resumed
            .command(&json!({"command":"sessionOpen","sessionId":id}))
            .unwrap()["defaultPeerId"],
        "beta"
    );
    resumed.shutdown().unwrap();
}

#[test]
fn peer_selection_rejects_unknown_self_and_unmapped_cwd_without_changes() {
    let cluster = cluster();
    let cwd = cluster._dir.path().join("project");
    std::fs::create_dir(&cwd).unwrap();
    let session = cluster
        .master
        .command(&json!({"command":"sessionOpen","cwd":cwd}))
        .unwrap();
    let id = &session["sessionId"];
    let bindings = cluster
        .master
        .command(&json!({"command":"listWorkspaceBindings"}))
        .unwrap();
    assert_eq!(
        call(&cluster.master, id, "ic_peer", json!({"peerId":"unknown"}))
            .unwrap_err()
            .code,
        "UNKNOWN_PEER"
    );
    assert_eq!(
        call(&cluster.master, id, "ic_peer", json!({"peerId":"master"}))
            .unwrap_err()
            .code,
        "LOCAL_BUILTIN_DENIED"
    );
    assert_eq!(
        call(&cluster.master, id, "ic_peer", json!({"peerId":"alpha"}))
            .unwrap_err()
            .code,
        "WORKSPACE_BINDING_NOT_FOUND"
    );
    assert_eq!(
        cluster
            .master
            .command(&json!({"command":"listWorkspaceBindings"}))
            .unwrap(),
        bindings
    );
    assert!(
        cluster
            .master
            .command(&json!({"command":"sessionOpen","sessionId":id}))
            .unwrap()["defaultPeerId"]
            .is_null()
    );
    cluster.master.command(&json!({"command":"nodesBind","peerId":"alpha","localPath":cwd,"workspaceId":"default"})).unwrap();
    let bindings = cluster
        .master
        .command(&json!({"command":"listWorkspaceBindings"}))
        .unwrap();
    call(&cluster.master, id, "ic_peer", json!({"peerId":"alpha"})).unwrap();
    assert_eq!(
        cluster
            .master
            .command(&json!({"command":"listWorkspaceBindings"}))
            .unwrap(),
        bindings
    );
}
