//! Controlled rsync acceptance. Run with IC_TEST_RSYNC set in the visible Herdr pane.
use intelligent_cells::{
    Config, harness,
    node::Node,
    tls::{Security, certificate_identity},
    wire,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, FileTimes},
    io::BufReader,
    net::{TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn approved_rsync() -> Value {
    let file = fs::canonicalize(
        std::env::var("IC_TEST_RSYNC")
            .expect("set IC_TEST_RSYNC to the owner-approved rsync >= 3.4.1 binary"),
    )
    .unwrap();
    let digest = format!("{:x}", Sha256::digest(fs::read(&file).unwrap()));
    json!({"backend":"rsync","rsync":{"file":file,"sha256":digest}})
}
fn config(
    dir: &Path,
    id: &str,
    other: &str,
    port: u16,
    peer_port: u16,
    grant: bool,
    sync: Value,
) -> Config {
    let identities = dir.join("identities");
    let pin =
        certificate_identity(&fs::read(identities.join(format!("{other}.pem"))).unwrap()).unwrap();
    let policy = if grant {
        json!({"grants":{other:{"workspace":dir.join(id),
            "tools":["workspaceList","syncInventory","syncTransfer","syncApply","readFile"],
            "directories":[{"path":"","read":true,"write":true}],
            "allowUnsandboxedProcesses":true,"maxTimeoutMs":10000}}})
    } else {
        json!({"grants":{other:{"workspace":dir.join(id),"tools":["workspaceList"]}}})
    };
    Config {
        id: id.into(),
        host: "127.0.0.1".into(),
        port,
        path: dir.join(format!("{id}.json")),
        state_dir: dir.join(format!("{id}-state")),
        raw: json!({"agent":"deterministic-demo","security":{
            "cert":identities.join(format!("{id}.pem")),"key":identities.join(format!("{id}.key")),
            "ca":identities.join("ca.pem"),"trustedPeers":{other:pin["fingerprint256"]}},
            "policy":policy,"policyRaw":policy,"sync":sync,
            "peers":[{"id":other,"host":"127.0.0.1","port":peer_port}]}),
    }
}
struct Pair {
    dir: tempfile::TempDir,
    a: Arc<Node>,
    b: Arc<Node>,
}
impl Drop for Pair {
    fn drop(&mut self) {
        let _ = self.a.shutdown();
        let _ = self.b.shutdown();
    }
}
impl Pair {
    fn new(reverse_grant: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        harness::fixture(&dir.path().join("identities"), &["a".into(), "b".into()]).unwrap();
        for id in ["a", "b"] {
            let root = dir.path().join(id);
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Reserve both addresses until configurations are constructed.
        let al = TcpListener::bind("127.0.0.1:0").unwrap();
        let bl = TcpListener::bind("127.0.0.1:0").unwrap();
        let ap = al.local_addr().unwrap().port();
        let bp = bl.local_addr().unwrap().port();
        let ac = config(
            dir.path(),
            "a",
            "b",
            ap,
            bp,
            reverse_grant,
            approved_rsync(),
        );
        let bc = config(dir.path(), "b", "a", bp, ap, true, approved_rsync());
        drop(al);
        drop(bl);
        let a = Node::new(ac).unwrap();
        let b = Node::new(bc).unwrap();
        a.start().unwrap();
        b.start().unwrap();
        Self { dir, a, b }
    }
    fn root(&self, id: &str) -> PathBuf {
        self.dir.path().join(id)
    }
    fn bind(&self, source: &str, paths: Value) {
        let (node, peer) = if source == "a" {
            (&self.a, "b")
        } else {
            (&self.b, "a")
        };
        node.command(&json!({"command":"bindWorkspace","peerId":peer,"logicalWorkspaceId":"project","workspaceId":"default","expectedRevision":0})).unwrap();
        node.command(&json!({"command":"bindLocalWorkspace","logicalWorkspaceId":"project","path":self.root(source),"expectedRevision":0})).unwrap();
        node.command(&json!({"command":"setWorkspaceSyncScope","peerId":peer,"logicalWorkspaceId":"project","scope":{"paths":paths}})).unwrap();
    }
    fn sync(&self, source: &str, task_id: &str) -> intelligent_cells::Result<Value> {
        let (node, peer) = if source == "a" {
            (&self.a, "b")
        } else {
            (&self.b, "a")
        };
        node.dispatch(peer,&json!({"taskId":task_id,"logicalWorkspaceId":"project","tool":"syncApply","args":{},"timeoutMs":10000}))
    }
    fn ok(&self, source: &str, task_id: &str) -> Value {
        let reply = self.sync(source, task_id).unwrap();
        assert_eq!(reply["status"], "ok", "{reply}");
        reply
    }
    fn receiver_session(
        &self,
        task_id: &str,
        timeout_ms: u64,
    ) -> BufReader<openssl::ssl::SslStream<TcpStream>> {
        let security =
            Security::load(&self.a.config().raw["security"], self.dir.path(), "a").unwrap();
        let mut stream = security.connect("127.0.0.1", self.b.port(), "b").unwrap();
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        wire::write_frame(&mut stream, &json!({"v":2,"type":"hello","nodeId":"a"})).unwrap();
        let mut session = BufReader::new(stream);
        assert_eq!(
            wire::read_frame(&mut session).unwrap().unwrap()["type"],
            "hello"
        );
        wire::write_frame(
            session.get_mut(),
            &json!({"v":2,"type":"task","task":{
            "taskId":task_id,"tool":"syncTransfer","workspaceId":"default","timeoutMs":timeout_ms,
            "args":{"scope":{"paths":[""]},"manifest":[{"path":"new","type":"file","size":3,
                "sha256":format!("{:x}",Sha256::digest(b"new")),"executable":0}]}}}),
        )
        .unwrap();
        let ready = wire::read_frame(&mut session).unwrap().unwrap();
        assert_eq!(ready["type"], "rsync_ready", "{ready}");
        assert_eq!(ready["taskId"], task_id, "{ready}");
        session
    }
    fn assert_receiver_cleaned(&self) {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let active = self.b.command(&json!({"command":"status"})).unwrap()["active"]
                .as_u64()
                .unwrap();
            let stages = fs::read_dir(self.b.config().state_dir.join("rsync-staging"))
                .unwrap()
                .count();
            if active == 0 && stages == 0 {
                break;
            }
            assert!(
                Instant::now() < end,
                "receiver did not release task/stage: active={active}, stages={stages}"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            fs::read(self.root("b").join("sentinel")).unwrap(),
            b"preserve"
        );
        assert!(!self.root("b").join("new").exists());
    }
}

fn receiver_ends(
    session: &mut BufReader<openssl::ssl::SslStream<TcpStream>>,
    expect_error_result: bool,
) -> Option<Value> {
    let end = Instant::now() + Duration::from_secs(3);
    let mut error_result = None;
    loop {
        assert!(
            Instant::now() < end,
            "failed receiver kept its connection open"
        );
        match wire::read_frame(session) {
            Ok(Some(frame)) => {
                if frame["status"] == "error" {
                    error_result = Some(frame);
                } else {
                    assert!(
                        matches!(frame["type"].as_str(), Some("rsync_data" | "rsync_eof")),
                        "unexpected response: {frame}"
                    );
                }
            }
            Ok(None) => break,
            Err(error) => {
                assert!(
                    !error.message.contains("timed out")
                        && !error.message.contains("temporarily unavailable"),
                    "receiver must close after failure: {error}"
                );
                break;
            }
        }
    }
    if expect_error_result {
        assert!(
            error_result.is_some(),
            "receiver must return a failed task result before closing"
        );
    }
    error_result
}

fn assert_tool_denied(reply: intelligent_cells::Result<Value>) {
    match reply {
        Err(error) => assert_eq!(error.code, "TOOL_DENIED", "{error}"),
        Ok(response) => {
            assert_eq!(response["status"], "error", "{response}");
            assert_eq!(response["error"]["code"], "TOOL_DENIED", "{response}");
        }
    }
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_live_receiver_revocation_closes_session_and_releases_staging() {
    let p = Pair::new(false);
    fs::write(p.root("b").join("sentinel"), b"preserve").unwrap();
    let mut session = p.receiver_session("revoke-live", 10000);
    p.b.invalidate_peer("a").unwrap();
    let _ = receiver_ends(&mut session, false);
    p.assert_receiver_cleaned();
    p.b.shutdown().unwrap();
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_live_receiver_timeout_closes_session_and_releases_staging() {
    let p = Pair::new(false);
    fs::write(p.root("b").join("sentinel"), b"preserve").unwrap();
    let mut session = p.receiver_session("timeout-live", 1000);
    let response = receiver_ends(&mut session, true).unwrap();
    assert_eq!(response["error"]["code"], "TASK_TIMEOUT", "{response}");
    p.assert_receiver_cleaned();
    p.b.shutdown().unwrap();
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_wrong_stream_task_identity_cannot_apply_workspace() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let p = Pair::new(false);
    fs::write(p.root("b").join("sentinel"), b"preserve").unwrap();
    let mut session = p.receiver_session("identity-live", 10000);
    wire::write_frame(session.get_mut(),&json!({"type":"rsync_data","taskId":"different-task","base64":STANDARD.encode(b"invalid")})).unwrap();
    let response = receiver_ends(&mut session, true).unwrap();
    assert_eq!(response["error"]["code"], "RSYNC_FAILED", "{response}");
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("identity mismatch"),
        "{response}"
    );
    p.assert_receiver_cleaned();
    p.b.shutdown().unwrap();
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_strict_scope_mirrors_binary_emptydirs_and_executable() {
    let p = Pair::new(false);
    for id in ["a", "b"] {
        fs::create_dir(p.root(id).join("src")).unwrap();
    }
    fs::create_dir(p.root("a").join("src/empty")).unwrap();
    fs::write(p.root("a").join("src/binary"), [0, 255, 128, 1]).unwrap();
    fs::set_permissions(
        p.root("a").join("src/binary"),
        fs::Permissions::from_mode(0o751),
    )
    .unwrap();
    fs::write(p.root("b").join("src/stale"), b"delete").unwrap();
    fs::write(p.root("b").join("outside"), b"preserve").unwrap();
    p.bind("a", json!(["src"]));
    p.ok("a", "scope");
    assert_eq!(
        fs::read(p.root("b").join("src/binary")).unwrap(),
        [0, 255, 128, 1]
    );
    assert_eq!(
        fs::metadata(p.root("b").join("src/binary")).unwrap().mode() & 0o111,
        0o111
    );
    assert!(p.root("b").join("src/empty").is_dir());
    assert!(!p.root("b").join("src/stale").exists());
    assert_eq!(fs::read(p.root("b").join("outside")).unwrap(), b"preserve");
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_same_size_and_mtime_change_is_not_skipped_and_unchanged_file_is_preserved() {
    let p = Pair::new(false);
    let source = p.root("a").join("file");
    let target = p.root("b").join("file");
    fs::write(&source, b"before").unwrap();
    p.bind("a", json!([""]));
    p.ok("a", "initial");
    let before = fs::metadata(&target).unwrap();
    p.ok("a", "unchanged");
    let after = fs::metadata(&target).unwrap();
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    let times = FileTimes::new().set_modified(fs::metadata(&source).unwrap().modified().unwrap());
    fs::write(&source, b"after!").unwrap();
    File::options()
        .write(true)
        .open(&source)
        .unwrap()
        .set_times(times)
        .unwrap();
    p.ok("a", "same-mtime");
    assert_eq!(fs::read(&target).unwrap(), b"after!");
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_explicit_grants_and_mappings_allow_role_reversal() {
    let p = Pair::new(true);
    fs::write(p.root("a").join("file"), b"forward").unwrap();
    p.bind("a", json!([""]));
    p.bind("b", json!([""]));
    p.ok("a", "forward");
    fs::write(p.root("b").join("file"), b"reverse").unwrap();
    p.ok("b", "reverse");
    assert_eq!(fs::read(p.root("a").join("file")).unwrap(), b"reverse");
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_reversing_roles_does_not_inherit_forward_authorization() {
    let p = Pair::new(false);
    fs::write(p.root("a").join("file"), b"forward").unwrap();
    p.bind("a", json!([""]));
    p.bind("b", json!([""]));
    p.ok("a", "forward");
    fs::write(p.root("b").join("file"), b"unauthorized").unwrap();
    let reply = p.sync("b", "denied");
    assert_tool_denied(reply);
    assert_eq!(fs::read(p.root("a").join("file")).unwrap(), b"forward");
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_transfer_tool_requires_its_own_grant_before_mirror_writes() {
    let p = Pair::new(false);
    fs::write(p.root("a").join("new"), b"incoming").unwrap();
    fs::write(p.root("b").join("stale"), b"must survive denial").unwrap();
    p.b.command(
        &json!({"command":"setPolicy","expectedEpoch":0,"policy":{"grants":{"a":{
        "workspace":p.root("b"),"tools":["workspaceList","syncInventory","syncApply"],
        "directories":[{"path":"","read":true,"write":true}]}}}}),
    )
    .unwrap();
    p.bind("a", json!([""]));
    let reply = p.sync("a", "transfer-denied");
    assert_tool_denied(reply);
    assert!(!p.root("b").join("new").exists());
    assert_eq!(
        fs::read(p.root("b").join("stale")).unwrap(),
        b"must survive denial"
    );
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_successful_staging_does_not_authorize_final_mirror() {
    let p = Pair::new(false);
    fs::write(p.root("a").join("new"), b"incoming").unwrap();
    fs::write(p.root("b").join("stale"), b"must survive denial").unwrap();
    p.b.command(
        &json!({"command":"setPolicy","expectedEpoch":0,"policy":{"grants":{"a":{
        "workspace":p.root("b"),"tools":["workspaceList","syncInventory","syncTransfer"],
        "directories":[{"path":"","read":true,"write":true}],
        "allowUnsandboxedProcesses":true,"maxTimeoutMs":10000}}}}),
    )
    .unwrap();
    p.bind("a", json!([""]));
    let reply = p.sync("a", "apply-denied");
    assert_tool_denied(reply);
    assert!(!p.root("b").join("new").exists());
    assert_eq!(
        fs::read(p.root("b").join("stale")).unwrap(),
        b"must survive denial"
    );
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_missing_or_mismatched_approved_binary_fails_without_native_fallback() {
    for broken in [
        json!({"backend":"rsync","rsync":{"file":"/nonexistent/ic-approved-rsync","sha256":"0".repeat(64)}}),
        {
            let mut value = approved_rsync();
            value["rsync"]["sha256"] = json!("0".repeat(64));
            value
        },
    ] {
        let d = tempfile::tempdir().unwrap();
        harness::fixture(&d.path().join("identities"), &["a".into(), "b".into()]).unwrap();
        fs::create_dir(d.path().join("a")).unwrap();
        fs::set_permissions(d.path().join("a"), fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(config(d.path(), "a", "b", 0, 1, false, broken));
        assert!(
            node.is_err(),
            "invalid rsync approval must fail configuration instead of switching backends"
        );
    }
}

#[test]
#[ignore = "requires IC_TEST_RSYNC pointing to an approved rsync >= 3.4.1"]
fn rsync_small_edit_to_large_file_transfers_blocks_instead_of_whole_file() {
    let p = Pair::new(false);
    // Deterministic high-entropy data: compressing repeated fixture bytes would
    // produce a misleading apparent delta improvement.
    let mut bytes = vec![0u8; 1024 * 1024];
    let mut state = 0x91e1_0da5_7c31_8b47u64;
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    let source = p.root("a").join("large.bin");
    fs::write(&source, &bytes).unwrap();
    p.bind("a", json!([""]));
    let initial = p.ok("a", "large-initial");
    let initial_bytes = initial["result"]["transferStats"]["transmittedBytes"]
        .as_u64()
        .expect("transfer stats required");
    assert!(
        initial_bytes >= bytes.len() as u64 / 2,
        "unexpected initial statistics: {initial}"
    );
    bytes[400_000..400_128].fill(0x6f);
    fs::write(&source, &bytes).unwrap();
    let changed = p.ok("a", "large-delta");
    let sent = changed["result"]["transferStats"]["transmittedBytes"]
        .as_u64()
        .expect("transfer stats required");
    assert!(
        sent > 0 && sent < bytes.len() as u64 / 2,
        "small edit must use real block delta: {changed}"
    );
    assert_eq!(fs::read(p.root("b").join("large.bin")).unwrap(), bytes);
}
