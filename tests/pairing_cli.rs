use intelligent_cells::{harness::remote_tools, node::Node, owner};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufReader, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

fn node(dir: &Path) -> Arc<Node> {
    let path = intelligent_cells::settings::initialize(Some(&dir.join("config.json"))).unwrap();
    intelligent_cells::settings::set_config(&path, "port", json!(0)).unwrap();
    intelligent_cells::settings::set_config(&path, "pairing.port", json!(0)).unwrap();
    Node::new(intelligent_cells::settings::check_config(&path).unwrap()).unwrap()
}

#[test]
fn owner_socket_is_private_exclusive_and_preserves_command_errors() {
    let d = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let n = node(d.path());
    let path = n.config().state_dir.join("owner.sock");
    let handle = owner::start(n.clone()).unwrap();
    let m = fs::symlink_metadata(&path).unwrap();
    assert!(m.file_type().is_socket());
    assert_eq!(m.permissions().mode() & 0o777, 0o600);
    assert!(owner::start(n.clone()).is_err());
    assert_eq!(
        owner::request(&n.config(), &json!({"command":"listPeers"})).unwrap(),
        n.command(&json!({"command":"listPeers"})).unwrap()
    );
    assert!(owner::request(&n.config(), &json!({"command":"notACommand"})).is_err());
    drop(handle);
    assert!(!path.exists());
    n.shutdown().unwrap();
}

#[test]
fn owner_socket_rejects_oversized_frame_and_existing_file() {
    let d = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let n = node(d.path());
    let path = n.config().state_dir.join("owner.sock");
    fs::write(&path, b"preserve").unwrap();
    assert!(owner::start(n.clone()).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"preserve");
    fs::remove_file(&path).unwrap();
    let _handle = owner::start(n.clone()).unwrap();
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let _ = stream.write_all(&vec![b'x'; intelligent_cells::wire::MAX_FRAME + 1]);
    let reply = intelligent_cells::wire::read_frame(&mut BufReader::new(stream))
        .unwrap()
        .unwrap();
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["error"]["code"], "INVALID_FRAME");
    n.shutdown().unwrap();
}

#[test]
fn owner_cli_contacts_running_node_without_acquiring_state_lock() {
    let d = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let n = node(d.path());
    let _handle = owner::start(n.clone()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ic"))
        .env("IC_HOME", d.path())
        .args(["nodes", "command", "--json", "{\"command\":\"listPeers\"}"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v, n.command(&json!({"command":"listPeers"})).unwrap());
    n.shutdown().unwrap();
}

#[test]
fn mcp_peer_discovery_is_available_without_owner_mutations() {
    for local in [false, true] {
        let tools = remote_tools(local);
        let t = tools.iter().find(|t| t["name"] == "ic_peers").unwrap();
        assert_eq!(t["inputSchema"]["properties"], json!({}));
        assert!(
            !tools
                .iter()
                .any(|t| t["name"].as_str().unwrap().contains("pairing"))
        );
    }
    let d = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let n = node(d.path());
    let _handle = owner::start(n.clone()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ic"))
        .env("IC_HOME", d.path())
        .args(["mcp", "connect"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ic_peers\",\"arguments\":{}}}\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["result"]["isError"], false, "{v}");
    n.shutdown().unwrap();
}

#[test]
fn owner_shutdown_stops_daemon_and_removes_socket() {
    let d = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
    let n = node(d.path());
    let config = n.config();
    n.shutdown().unwrap();
    drop(n);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ic"))
        .env("IC_HOME", d.path())
        .args(["serve", "--daemon"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let socket = config.state_dir.join("owner.sock");
    while !socket.exists() && std::time::Instant::now() < until {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let result = owner::request(&config, &json!({"command":"shutdown"}));
    if result.is_err() {
        let _ = child.kill();
    }
    assert_eq!(result.unwrap()["stopping"], true);
    while child.try_wait().unwrap().is_none() && std::time::Instant::now() < until {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if child.try_wait().unwrap().is_none() {
        let _ = child.kill();
        let _ = child.wait();
        panic!("Owner shutdown did not terminate daemon");
    }
    assert!(!socket.exists());
    assert!(child.wait().unwrap().success());
}
