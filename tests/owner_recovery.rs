use intelligent_cells::{Config, harness::fixture, node::Node, owner};
use serde_json::json;
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::Path,
    sync::Arc,
};

fn node(directory: &Path) -> Arc<Node> {
    fixture(directory, &["owner".into()]).unwrap();
    Node::new(Config {
        raw:json!({"id":"owner","security":{"cert":"owner.pem","key":"owner.key","ca":"ca.pem","trustedPeers":{}},"policy":{"grants":{}},"peers":[]}),
        id:"owner".into(), host:"127.0.0.1".into(), port:0,
        path:directory.join("config.json"), state_dir:directory.join("state"),
    }).unwrap()
}

#[test]
fn crashed_owner_socket_is_recovered_after_state_lock_reacquisition() {
    let directory = tempfile::tempdir().unwrap();
    let node = node(directory.path());
    let socket = node.config().state_dir.join("owner.sock");
    let stale = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale);
    let config = node.config();
    node.shutdown().unwrap();
    drop(node);
    let node = Node::new(config).unwrap();
    let handle = owner::start(node.clone()).unwrap();
    let response = owner::request(&node.config(), &json!({"command":"status"})).unwrap();
    assert_eq!(response["id"], "owner");
    drop(handle);
    assert!(!socket.exists());
    node.shutdown().unwrap();
}

#[test]
fn live_owner_socket_is_never_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let node = node(directory.path());
    let handle = owner::start(node.clone()).unwrap();
    let socket = node.config().state_dir.join("owner.sock");
    let inode = fs::symlink_metadata(&socket).unwrap().ino();
    assert!(owner::start(node.clone()).is_err());
    assert_eq!(fs::symlink_metadata(&socket).unwrap().ino(), inode);
    assert!(owner::request(&node.config(), &json!({"command":"status"})).is_ok());
    drop(handle);
    node.shutdown().unwrap();
}

#[test]
fn unsafe_owner_paths_are_preserved() {
    for kind in ["regular", "symlink", "public_socket"] {
        let directory = tempfile::tempdir().unwrap();
        let node = node(directory.path());
        let socket = node.config().state_dir.join("owner.sock");
        match kind {
            "regular" => fs::write(&socket, "keep this file").unwrap(),
            "symlink" => std::os::unix::fs::symlink("missing", &socket).unwrap(),
            _ => {
                let stale = UnixListener::bind(&socket).unwrap();
                fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
                drop(stale);
            }
        }
        let before = fs::symlink_metadata(&socket).unwrap();
        assert!(owner::start(node.clone()).is_err(), "{kind}");
        let after = fs::symlink_metadata(&socket).unwrap();
        assert_eq!(before.ino(), after.ino(), "{kind}");
        assert_eq!(before.file_type(), after.file_type(), "{kind}");
        node.shutdown().unwrap();
    }
}
