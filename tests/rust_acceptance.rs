//! Independent public-API acceptance regressions. Run through the shared Herdr build pane.
use intelligent_cells::{Config, Result, harness, node::Node, tls::certificate_identity};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

struct Cluster {
    _dir: tempfile::TempDir,
    master: Arc<Node>,
    servant: Arc<Node>,
    root: std::path::PathBuf,
}
impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = self.master.shutdown();
        let _ = self.servant.shutdown();
    }
}
fn config(dir: &Path, id: &str, policy: Value, peers: Value) -> Config {
    let identities = dir.join("identities");
    let mut pins = serde_json::Map::new();
    for peer in ["master", "servant", "offline"] {
        if peer != id {
            let pem = std::fs::read(identities.join(format!("{peer}.pem"))).unwrap();
            let identity = certificate_identity(&pem).unwrap();
            pins.insert(peer.into(), identity["fingerprint256"].clone());
        }
    }
    Config {
        id: id.into(),
        host: "127.0.0.1".into(),
        port: 0,
        path: dir.join(format!("{id}.json")),
        state_dir: dir.join(format!("{id}-state")),
        raw: json!({"agent":if id == "master" {json!("deterministic-demo")} else {Value::Null},
            "security":{"cert":identities.join(format!("{id}.pem")),"key":identities.join(format!("{id}.key")),"ca":identities.join("ca.pem"),"trustedPeers":pins},
            "policy":policy.clone(),"policyRaw":policy,"peers":peers}),
    }
}
fn cluster(rate: u64) -> Cluster {
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into(), "offline".into()],
    )
    .unwrap();
    let root = dir.path().join("workspace");
    std::fs::create_dir(&root).unwrap();
    let servant = Node::new(config(dir.path(), "servant", json!({"grants":{"master":{"workspace":root,"tools":["writeFile","readFile","echo","workspaceList"],"maxTasksPerMinute":rate}}}), json!([]))).unwrap();
    servant.start().unwrap();
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let offline_port = unavailable.local_addr().unwrap().port();
    drop(unavailable);
    let master = Node::new(config(
        dir.path(),
        "master",
        json!({}),
        json!([
            {"id":"servant","host":"127.0.0.1","port":servant.port()},
            {"id":"offline","host":"127.0.0.1","port":offline_port}
        ]),
    ))
    .unwrap();
    Cluster {
        _dir: dir,
        master,
        servant,
        root,
    }
}
fn task(id: &str, tool: &str, args: Value) -> Value {
    json!({"taskId":id,"runId":"independent-review","tool":tool,"args":args,"timeoutMs":1000})
}
fn error_code(result: Result<Value>) -> String {
    match result {
        Err(e) => e.code,
        Ok(v) => v["error"]["code"].as_str().unwrap_or("SUCCESS").into(),
    }
}

#[test]
fn rust_acceptance_unknown_write_blocks_new_peer_but_allows_inspection() {
    let f = cluster(120);
    let lost = f
        .master
        .dispatch(
            "offline",
            &task("lost", "writeFile", json!({"path":"lost","text":"x"})),
        )
        .unwrap();
    assert_eq!(lost["outcomeUnknown"], true, "{lost}");
    let read = f
        .master
        .dispatch(
            "servant",
            &task("inspect", "echo", json!({"text":"inspect"})),
        )
        .unwrap();
    assert_eq!(
        read["status"], "ok",
        "Read-only inspection must remain available: {read}"
    );
    let code = error_code(f.master.dispatch(
        "servant",
        &task(
            "fresh",
            "writeFile",
            json!({"path":"must-not-exist","text":"x"}),
        ),
    ));
    assert_eq!(
        code, "UNCERTAIN_SIDE_EFFECT",
        "New peer/run/task IDs must not bypass a master-wide unknown effect"
    );
    assert!(!f.root.join("must-not-exist").exists());
}

#[test]
fn rust_acceptance_servant_enforces_owner_task_rate() {
    let f = cluster(1);
    let first = f
        .master
        .dispatch("servant", &task("first", "echo", json!({"text":"one"})))
        .unwrap();
    assert_eq!(first["status"], "ok", "{first}");
    assert_eq!(
        error_code(
            f.master
                .dispatch("servant", &task("second", "echo", json!({"text":"two"})))
        ),
        "RATE_LIMITED"
    );
}

#[test]
fn rust_acceptance_local_servant_dedup_conflict_and_denied_path() {
    let f = cluster(120);
    let write = task(
        "once",
        "writeFile",
        json!({"path":"hello","text":"你好 Rust"}),
    );
    let first = f.master.dispatch("servant", &write).unwrap();
    assert_eq!(first["status"], "ok", "{first}");
    assert_eq!(f.master.dispatch("servant", &write).unwrap(), first);
    let changed = task(
        "once",
        "writeFile",
        json!({"path":"hello","text":"different"}),
    );
    assert_eq!(
        error_code(f.master.dispatch("servant", &changed)),
        "TASK_ID_CONFLICT"
    );
    assert_eq!(
        error_code(f.master.dispatch(
            "servant",
            &task(
                "escape",
                "writeFile",
                json!({"path":"../escape","text":"no"})
            )
        )),
        "PATH_DENIED"
    );
    assert_eq!(
        std::fs::read_to_string(f.root.join("hello")).unwrap(),
        "你好 Rust"
    );
    assert!(!f.root.parent().unwrap().join("escape").exists());
}

#[test]
fn rust_acceptance_dispatch_requires_one_workspace_selector() {
    let f = cluster(120);
    f.master.command(&json!({"command":"bindWorkspace","peerId":"servant","logicalWorkspaceId":"project","workspaceId":"default","expectedRevision":0})).unwrap();
    let mut ambiguous = task(
        "ambiguous",
        "writeFile",
        json!({"path":"ambiguous","text":"no"}),
    );
    ambiguous["logicalWorkspaceId"] = json!("project");
    ambiguous["workspaceId"] = json!("default");
    assert_eq!(
        error_code(f.master.dispatch("servant", &ambiguous)),
        "INVALID_TASK"
    );
    assert!(!f.root.join("ambiguous").exists());
}

#[test]
fn rust_acceptance_owner_policy_update_cannot_expose_private_state() {
    let f = cluster(120);
    let result = f.servant.command(&json!({"command":"setPolicy","expectedEpoch":0,
        "policy":{"grants":{"master":{"workspace":f.servant.config().state_dir,"tools":["readFile"]}}}}));
    assert_eq!(
        error_code(result),
        "UNSAFE_STATE_POLICY",
        "Policy updates must apply the same state/TLS/root isolation as initial configuration"
    );
}

#[test]
fn rust_acceptance_pure_servant_and_outgoing_role_config() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("role.json");
    let mut raw = json!({"id":"local","agent":null,"security":{"cert":"local.pem","key":"local.key","ca":"ca.pem"},"policy":{},"peers":[]});
    std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert!(
        intelligent_cells::policy::load_config(&path).is_ok(),
        "Pure servant must not require a model agent"
    );
    raw["peers"] = json!([{"id":"remote","host":"127.0.0.1","port":7312}]);
    std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(
        intelligent_cells::policy::load_config(&path)
            .unwrap_err()
            .code,
        "AGENT_REQUIRED"
    );
}

#[test]
fn rust_acceptance_loaded_resource_policy_starts_without_accepting_compiled_input() {
    let d = tempfile::tempdir().unwrap();
    harness::fixture(
        &d.path().join("identities"),
        &["master".into(), "servant".into(), "offline".into()],
    )
    .unwrap();
    let root = d.path().join("workspace");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("instructions.md"), "Owner approved instructions").unwrap();
    let cfg = config(
        d.path(),
        "servant",
        json!({"grants":{"master":{"workspace":root,"tools":["resourceRead"],
        "resources":{"guide":{"kind":"instruction","path":"instructions.md"}}}}}),
        json!([]),
    );
    let mut raw = cfg.raw.clone();
    raw["id"] = json!(cfg.id);
    raw["stateDir"] = json!(cfg.state_dir);
    std::fs::write(&cfg.path, serde_json::to_vec(&raw).unwrap()).unwrap();
    let loaded = intelligent_cells::policy::load_config(&cfg.path).unwrap();
    let node = Node::new(loaded)
        .unwrap_or_else(|e| panic!("Source policy must survive load_config -> Node::new: {e}"));
    node.shutdown().unwrap();
}

#[test]
fn rust_acceptance_ca_signature_does_not_replace_expected_peer_pin() {
    let f = cluster(120);
    let mut cfg = config(
        f._dir.path(),
        "master",
        json!({}),
        json!([{"id":"servant","host":"127.0.0.1","port":f.servant.port()}]),
    );
    cfg.state_dir = f._dir.path().join("wrong-pin-master-state");
    let offline_identity =
        certificate_identity(&std::fs::read(f._dir.path().join("identities/offline.pem")).unwrap())
            .unwrap();
    cfg.raw["security"]["trustedPeers"]["servant"] = offline_identity["fingerprint256"].clone();
    let master = Node::new(cfg).unwrap();
    let result = master.dispatch("servant", &task("wrong-pin", "echo", json!({"text":"no"})));
    master.shutdown().unwrap();
    assert_ne!(
        error_code(result),
        "SUCCESS",
        "A valid CA signature cannot authorize an unpinned peer identity"
    );
    let retained = f
        .servant
        .command(&json!({"command":"listTasks","kind":"incoming"}))
        .unwrap();
    assert_eq!(retained["records"].as_array().unwrap().len(), 0);
}

#[test]
fn rust_acceptance_policy_capacity_refusal_keeps_previous_epoch() {
    let f = cluster(120);
    for id in ["retained-one", "retained-two"] {
        assert_eq!(
            f.master
                .dispatch("servant", &task(id, "echo", json!({"text":id})))
                .unwrap()["status"],
            "ok"
        );
    }
    let policy =
        json!({"maxTaskRecords":1,"grants":{"master":{"workspace":f.root,"tools":["echo"]}}});
    let result = f
        .servant
        .command(&json!({"command":"setPolicy","expectedEpoch":0,"policy":policy}));
    assert_eq!(error_code(result), "JOURNAL_CAPACITY");
    assert_eq!(
        f.servant
            .command(&json!({"command":"permissions"}))
            .unwrap()["epoch"],
        0
    );
}

#[test]
fn rust_acceptance_capabilities_do_not_disclose_host_paths_or_command_environment() {
    let grant = intelligent_cells::Grant {
        root: "/private/owner-workspace".into(),
        tools: ["capabilities".into(), "exec".into()].into(),
        master_id: "master".into(),
        workspace_id: "dev".into(),
        epoch: 1,
        raw: json!({"workspace":"/private/owner-workspace","root":"/private/owner-workspace","maxReadBytes":1024,
            "execCommands":{"build":{"file":"/private/owner-executable","env":{"SECRET":"owner-secret"},"args":[],"codeSnapshots":[{"filename":"/private/owner-executable"}]}},
            "mcpServers":{"approved":{"file":"/private/owner-mcp","tools":{}}}}),
    };
    let capabilities = intelligent_cells::tools::capabilities(&grant);
    let public = capabilities.to_string();
    for secret in [
        "/private/owner-workspace",
        "/private/owner-executable",
        "/private/owner-mcp",
        "owner-secret",
    ] {
        assert!(
            !public.contains(secret),
            "Capability discovery must expose aliases and limits, never {secret}"
        );
    }
    assert_eq!(capabilities["execCommands"], json!(["build"]));
    assert_eq!(capabilities["limits"]["maxReadBytes"], 1024);
}

#[test]
fn rust_acceptance_changed_local_root_never_falls_back_to_remote_only_exec() {
    use std::os::unix::fs::PermissionsExt;
    let f = cluster(120);
    let local = f._dir.path().join("local-source");
    std::fs::create_dir(&local).unwrap();
    std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o700)).unwrap();
    f.master.command(&json!({"command":"bindLocalWorkspace","logicalWorkspaceId":"project","path":local,"expectedRevision":0})).unwrap();
    f.master.command(&json!({"command":"bindWorkspace","logicalWorkspaceId":"project","peerId":"servant","workspaceId":"default","expectedRevision":0})).unwrap();
    f.master.command(&json!({"command":"setWorkspaceSyncScope","logicalWorkspaceId":"project","peerId":"servant","scope":{"paths":[""]}})).unwrap();
    let before = f
        .servant
        .command(&json!({"command":"listTasks","kind":"incoming"}))
        .unwrap()["records"]
        .as_array()
        .unwrap()
        .len();
    std::fs::rename(&local, f._dir.path().join("old-local-source")).unwrap();
    std::fs::create_dir(&local).unwrap();
    std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut exec = task("changed-root", "exec", json!({"command":"build","args":[]}));
    exec["logicalWorkspaceId"] = json!("project");
    assert_eq!(
        error_code(f.master.dispatch("servant", &exec)),
        "LOCAL_WORKSPACE_CHANGED"
    );
    let retained = f
        .servant
        .command(&json!({"command":"listTasks","kind":"incoming"}))
        .unwrap();
    assert_eq!(
        retained["records"].as_array().unwrap().len(),
        before,
        "Changed local identity must be rejected before contacting servant"
    );
}

#[test]
fn rust_acceptance_wire_logical_selector_cannot_write_default_workspace() {
    let f = cluster(120);
    let cfg = f.master.config();
    let security = intelligent_cells::tls::Security::load(
        &cfg.raw["security"],
        cfg.path.parent().unwrap(),
        "master",
    )
    .unwrap();
    let mut stream = security
        .connect("127.0.0.1", f.servant.port(), "servant")
        .unwrap();
    intelligent_cells::wire::write_frame(
        &mut stream,
        &json!({"v":2,"type":"hello","nodeId":"master"}),
    )
    .unwrap();
    let mut reader = std::io::BufReader::new(stream);
    assert!(
        intelligent_cells::wire::read_frame(&mut reader)
            .unwrap()
            .is_some()
    );
    let mut invalid = task(
        "wire-logical",
        "writeFile",
        json!({"path":"default-write","text":"must not write"}),
    );
    invalid["logicalWorkspaceId"] = json!("project");
    intelligent_cells::wire::write_frame(
        reader.get_mut(),
        &json!({"v":2,"type":"task","task":invalid}),
    )
    .unwrap();
    let result = intelligent_cells::wire::read_frame(&mut reader)
        .unwrap()
        .unwrap();
    assert_eq!(
        result["error"]["code"], "INVALID_TASK",
        "Wire protocol accepts explicit remote selectors only: {result}"
    );
    assert!(!f.root.join("default-write").exists());
}
