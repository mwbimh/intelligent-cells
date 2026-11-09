use intelligent_cells::sessions::SessionStore;
use serde_json::json;

#[test]
fn sessions_survive_restart_with_execution_metadata_not_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let store = SessionStore::open(dir.path()).unwrap();
    let session = store.create(None).unwrap();
    let id = session["sessionId"].as_str().unwrap();
    store
        .record_start(
            id,
            "peer-uuid",
            &json!({"taskId":"task1","tool":"writeFile","args":{"content":"secret"}}),
        )
        .unwrap();
    store
        .record_finish(id, "task1", &Ok(json!({"status":"ok","result":"secret"})))
        .unwrap();
    drop(store);
    let store = SessionStore::open(dir.path()).unwrap();
    let saved = store.get(id).unwrap();
    assert_eq!(saved["tasks"][0]["state"], "completed");
    assert!(!saved.to_string().contains("secret"));
    assert_eq!(store.list().unwrap().as_array().unwrap().len(), 1);
}

#[test]
fn restart_marks_inflight_execution_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let store = SessionStore::open(dir.path()).unwrap();
    let session = store.create(None).unwrap();
    let id = session["sessionId"].as_str().unwrap();
    store
        .record_start(id, "peer", &json!({"taskId":"task","tool":"echo"}))
        .unwrap();
    drop(store);
    assert_eq!(
        SessionStore::open(dir.path()).unwrap().get(id).unwrap()["tasks"][0]["state"],
        "unknown"
    );
}

#[test]
fn cwd_must_exist_and_session_identifiers_cannot_escape_store() {
    let dir = tempfile::tempdir().unwrap();
    let store = SessionStore::open(dir.path()).unwrap();
    assert!(store.create(Some(&dir.path().join("missing"))).is_err());
    assert!(store.get("../outside").is_err());
    let session = store.create(Some(dir.path())).unwrap();
    assert_eq!(
        session["cwd"],
        std::fs::canonicalize(dir.path()).unwrap().to_str().unwrap()
    );
}

#[test]
fn temporary_local_directory_is_private_isolated_and_policy_controlled() {
    let dir = tempfile::tempdir().unwrap();
    let store = SessionStore::open(dir.path()).unwrap();
    let first = store.create(None).unwrap();
    let second = store.create(None).unwrap();
    let first_id = first["sessionId"].as_str().unwrap();
    assert_eq!(
        store.local_directory(first_id, false).unwrap_err().code,
        "TEMPORARY_WORKSPACE_DISABLED"
    );
    let first_dir = store.local_directory(first_id, true).unwrap();
    let second_dir = store
        .local_directory(second["sessionId"].as_str().unwrap(), true)
        .unwrap();
    assert_ne!(first_dir, second_dir);
    std::fs::write(first_dir.join("record"), "persisted").unwrap();
    drop(store);
    assert_eq!(
        std::fs::read_to_string(
            SessionStore::open(dir.path())
                .unwrap()
                .local_directory(first_id, true)
                .unwrap()
                .join("record")
        )
        .unwrap(),
        "persisted"
    );
}

fn runtime_config(
    dir: &std::path::Path,
    id: &str,
    policy: serde_json::Value,
    peers: serde_json::Value,
) -> intelligent_cells::Config {
    let other = if id == "master" { "servant" } else { "master" };
    let identity = intelligent_cells::tls::certificate_identity(
        &std::fs::read(dir.join("identities").join(format!("{other}.pem"))).unwrap(),
    )
    .unwrap();
    intelligent_cells::Config {
        id: id.into(),
        host: "127.0.0.1".into(),
        port: 0,
        path: dir.join(format!("{id}.json")),
        state_dir: dir.join(format!("{id}-state")),
        raw: json!({"security":{"cert":dir.join("identities").join(format!("{id}.pem")),"key":dir.join("identities").join(format!("{id}.key")),"ca":dir.join("identities/ca.pem"),"trustedPeers":{other:identity["fingerprint256"]}},"policy":policy,"policyRaw":policy,"peers":peers}),
    }
}

#[test]
fn resident_session_uses_target_temporary_root_and_keeps_execution_history() {
    use intelligent_cells::{harness, node::Node};
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let workspace = dir.path().join("approved");
    std::fs::create_dir(&workspace).unwrap();
    let servant = Node::new(runtime_config(
        dir.path(),
        "servant",
        json!({"grants":{"master":{"workspace":workspace,"tools":["readFile","writeFile"]}}}),
        json!([]),
    ))
    .unwrap();
    servant.start().unwrap();
    let master = Node::new(runtime_config(
        dir.path(),
        "master",
        json!({}),
        json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
    ))
    .unwrap();
    let session = master.command(&json!({"command":"sessionOpen"})).unwrap();
    let id = session["sessionId"].as_str().unwrap();
    let result=master.command(&json!({"command":"sessionDispatch","sessionId":id,"peerId":"servant","task":{"taskId":"write-session","tool":"writeFile","args":{"path":"proof","text":"session-owned"},"timeoutMs":1000}})).unwrap();
    assert_eq!(result["status"], "ok", "{result}");
    assert!(!workspace.join("proof").exists());
    assert_eq!(
        std::fs::read_to_string(
            servant
                .config()
                .state_dir
                .join("session-workspaces/master")
                .join(id)
                .join("proof")
        )
        .unwrap(),
        "session-owned"
    );
    let denied=master.command(&json!({"command":"sessionDispatch","sessionId":id,"peerId":"master","task":{"taskId":"local","tool":"readFile","args":{"path":"proof"},"timeoutMs":1000}})).unwrap_err();
    assert_eq!(denied.code, "LOCAL_BUILTIN_DENIED");
    assert_eq!(
        master
            .command(&json!({"command":"sessionOpen","sessionId":id}))
            .unwrap()["tasks"][0]["state"],
        "completed"
    );
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
}

#[test]
fn target_can_forbid_temporary_sessions_without_changing_grants() {
    use intelligent_cells::{harness, node::Node};
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let workspace = dir.path().join("approved");
    std::fs::create_dir(&workspace).unwrap();
    let mut config = runtime_config(
        dir.path(),
        "servant",
        json!({"grants":{"master":{"workspace":workspace,"tools":["writeFile"]}}}),
        json!([]),
    );
    config.raw["sessions"] = json!({"allowTemporary":false});
    let servant = Node::new(config).unwrap();
    servant.start().unwrap();
    let master = Node::new(runtime_config(
        dir.path(),
        "master",
        json!({}),
        json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
    ))
    .unwrap();
    let session = master.command(&json!({"command":"sessionOpen"})).unwrap();
    let result=master.command(&json!({"command":"sessionDispatch","sessionId":session["sessionId"],"peerId":"servant","task":{"taskId":"denied","tool":"writeFile","args":{"path":"proof","text":"not written"},"timeoutMs":1000}})).unwrap();
    assert_eq!(result["error"]["code"], "TEMPORARY_WORKSPACE_DISABLED");
    assert!(!workspace.join("proof").exists());
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
}

#[test]
fn mcp_error_result_is_recorded_as_failed() {
    let dir = tempfile::tempdir().unwrap();
    let store = SessionStore::open(dir.path()).unwrap();
    let session = store.create(None).unwrap();
    let id = session["sessionId"].as_str().unwrap();
    store
        .record_start(id, "local", &json!({"taskId":"mcp-fail","tool":"external"}))
        .unwrap();
    store
        .record_finish(
            id,
            "mcp-fail",
            &Ok(json!({"isError":true,"content":[{"type":"text","text":"private error"}]})),
        )
        .unwrap();
    let record = store.get(id).unwrap();
    assert_eq!(record["tasks"][0]["state"], "failed");
    assert!(!record.to_string().contains("private error"));
}

#[test]
fn replaced_session_cwd_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().join("cwd");
    std::fs::create_dir(&cwd).unwrap();
    let store = SessionStore::open(dir.path()).unwrap();
    let session = store.create(Some(&cwd)).unwrap();
    std::fs::rename(&cwd, dir.path().join("old-cwd")).unwrap();
    std::fs::create_dir(&cwd).unwrap();
    assert_eq!(
        store
            .local_directory(session["sessionId"].as_str().unwrap(), true)
            .unwrap_err()
            .code,
        "WORKSPACE_CHANGED"
    );
}

#[test]
fn session_cwd_uses_explicit_directory_binding_and_never_remote_path() {
    use intelligent_cells::{harness, node::Node};
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let workspace = dir.path().join("approved");
    std::fs::create_dir(&workspace).unwrap();
    let local = dir.path().join("local");
    std::fs::create_dir(&local).unwrap();
    let servant = Node::new(runtime_config(
        dir.path(),
        "servant",
        json!({"grants":{"master":{"workspace":workspace,"tools":["writeFile","workspaceList"]}}}),
        json!([]),
    ))
    .unwrap();
    servant.start().unwrap();
    let master = Node::new(runtime_config(
        dir.path(),
        "master",
        json!({}),
        json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
    ))
    .unwrap();
    let session = master
        .command(&json!({"command":"sessionOpen","cwd":local}))
        .unwrap();
    let task = json!({"command":"sessionDispatch","sessionId":session["sessionId"],"peerId":"servant","task":{"taskId":"bound","tool":"writeFile","args":{"path":"proof","text":"mapped"},"timeoutMs":1000}});
    assert_eq!(
        master.command(&task).unwrap_err().code,
        "WORKSPACE_BINDING_NOT_FOUND"
    );
    master.command(&json!({"command":"nodesBind","peerId":"servant","localPath":local,"workspaceId":"default"})).unwrap();
    let result = master.command(&task).unwrap();
    assert_eq!(result["status"], "ok", "{result}");
    assert_eq!(
        std::fs::read_to_string(workspace.join("proof")).unwrap(),
        "mapped"
    );
    assert!(!local.join("proof").exists());
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
}

#[test]
fn target_binding_is_pinned_persistently_and_rejects_drift() {
    let dir = tempfile::tempdir().unwrap();
    let store = SessionStore::open(dir.path()).unwrap();
    let session = store.create(Some(dir.path())).unwrap();
    let id = session["sessionId"].as_str().unwrap();
    store.bind_target(id, "peer", "workspace-1").unwrap();
    drop(store);
    let store = SessionStore::open(dir.path()).unwrap();
    store.bind_target(id, "peer", "workspace-1").unwrap();
    assert_eq!(
        store
            .bind_target(id, "peer", "workspace-2")
            .unwrap_err()
            .code,
        "WORKSPACE_MAPPING_CHANGED"
    );
}

#[test]
fn incoming_socket_status_requires_authentication_and_clears_on_revoke() {
    use intelligent_cells::transport::IncomingSockets;
    use std::{
        net::{TcpListener, TcpStream},
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let sockets = IncomingSockets::new(Duration::from_secs(30));
    let guard = sockets.register(&server).unwrap();
    assert!(sockets.authenticated_peers().is_empty());
    guard.peer("master");
    assert_eq!(sockets.authenticated_peers(), vec!["master"]);
    sockets.invalidate(Some("master"));
    assert!(sockets.authenticated_peers().is_empty());
}

#[test]
fn nodes_status_reports_incoming_connection_and_both_relationships() {
    use intelligent_cells::{harness, node::Node};
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let workspace = dir.path().join("approved");
    std::fs::create_dir(&workspace).unwrap();
    let servant = Node::new(runtime_config(
        dir.path(),
        "servant",
        json!({"grants":{"master":{"workspace":workspace,"tools":["echo"]}}}),
        json!([]),
    ))
    .unwrap();
    servant.start().unwrap();
    let master = Node::new(runtime_config(
        dir.path(),
        "master",
        json!({"grants":{"servant":{"workspace":workspace,"tools":["echo"]}}}),
        json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
    ))
    .unwrap();
    let before = servant.command(&json!({"command":"nodesList"})).unwrap();
    assert_eq!(before["nodes"][0]["online"], serde_json::Value::Null);
    let from_master = master.command(&json!({"command":"nodesList"})).unwrap();
    assert_eq!(from_master["nodes"][0]["online"], true);
    assert_eq!(from_master["nodes"][0]["relationship"], "bidirectional");
    let from_servant = servant.command(&json!({"command":"nodesList"})).unwrap();
    assert_eq!(from_servant["nodes"][0]["online"], true);
    assert_eq!(from_servant["nodes"][0]["relationship"], "master");
    master.shutdown().unwrap();
    for _ in 0..50 {
        let status = servant.command(&json!({"command":"nodesList"})).unwrap();
        if status["nodes"][0]["online"].is_null() {
            servant.shutdown().unwrap();
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    servant.shutdown().unwrap();
    panic!("Closed incoming connection remained online");
}

#[test]
fn self_rename_updates_live_name_and_preserves_identity() {
    use intelligent_cells::{harness, node::Node, node_store};
    let dir = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    harness::fixture(
        &dir.path().join("identities"),
        &[id.clone(), "master".into()],
    )
    .unwrap();
    let config = runtime_config(dir.path(), &id, json!({}), json!([]));
    node_store::initialize(&config.state_dir, &id, "Before").unwrap();
    let node = Node::new(config).unwrap();
    node.command(&json!({"command":"nodesRename","name":"After"}))
        .unwrap();
    assert_eq!(node.config().raw["name"], "After");
    assert_eq!(node.config().id, id);
    assert_eq!(
        node_store::self_identity(&node.config().state_dir).unwrap()["name"],
        "After"
    );
    node.shutdown().unwrap();
}

#[test]
fn temporary_session_exec_uses_temporary_cwd_and_preserves_approved_source_root() {
    use intelligent_cells::{harness, node::Node};
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let workspace = dir.path().join("approved");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join("proof"), "original-root-must-not-be-read").unwrap();
    let servant = Node::new(runtime_config(dir.path(), "servant", json!({"grants":{"master":{"workspace":workspace,"allowUnsandboxedProcesses":true,"tools":["exec","writeFile"],"execCommands":{"read":{"file":std::fs::canonicalize("/bin/cat").unwrap(),"launchMode":"native","args":["proof"]}}}}}), json!([]))).unwrap();
    servant.start().unwrap();
    let master = Node::new(runtime_config(
        dir.path(),
        "master",
        json!({}),
        json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
    ))
    .unwrap();
    let session = master.command(&json!({"command":"sessionOpen"})).unwrap();
    let id = &session["sessionId"];
    let write = master.command(&json!({"command":"sessionDispatch","sessionId":id,"peerId":"servant","task":{"taskId":"temp-exec-write","tool":"writeFile","args":{"path":"proof","text":"temporary-root-content"},"timeoutMs":1000}})).unwrap();
    assert_eq!(write["status"], "ok", "{write}");
    let execution = master.command(&json!({"command":"sessionDispatch","sessionId":id,"peerId":"servant","task":{"taskId":"temp-exec-read","tool":"exec","args":{"command":"read","args":[]},"timeoutMs":1000}})).unwrap();
    assert_eq!(execution["status"], "ok", "{execution}");
    assert!(
        execution.to_string().contains("temporary-root-content"),
        "{execution}"
    );
    assert!(
        !execution
            .to_string()
            .contains("original-root-must-not-be-read"),
        "{execution}"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("proof")).unwrap(),
        "original-root-must-not-be-read"
    );
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
}

#[test]
fn remote_reconciliation_preserves_unknown_history_and_applies_only_to_matching_peer() {
    let dir = tempfile::tempdir().unwrap();
    let store = SessionStore::open(dir.path()).unwrap();
    let session = store.create(None).unwrap();
    let id = session["sessionId"].as_str().unwrap();
    store
        .record_start(
            id,
            "peer-a",
            &json!({"taskId":"uncertain","tool":"writeFile"}),
        )
        .unwrap();
    store
        .record_finish(
            id,
            "uncertain",
            &Err(intelligent_cells::IcError::new("OUTCOME_UNKNOWN", "Lost connection").unknown()),
        )
        .unwrap();
    let ledger = json!({"state":"reconciled","peerId":"peer-b","taskId":"uncertain","reconciliation":{"resolution":"not_applied","note":"Inspected target; no effects","at":123}});
    store
        .reconcile_remote_records(std::slice::from_ref(&ledger))
        .unwrap();
    assert_eq!(store.get(id).unwrap()["tasks"][0]["state"], "unknown");
    let mut ledger = ledger;
    ledger["peerId"] = json!("peer-a");
    store
        .reconcile_remote_records(std::slice::from_ref(&ledger))
        .unwrap();
    store.reconcile_remote_records(&[ledger]).unwrap();
    drop(store);
    let task = SessionStore::open(dir.path()).unwrap().get(id).unwrap()["tasks"][0].clone();
    assert_eq!(task["state"], "reconciled");
    assert_eq!(task["outcomeUnknown"], false);
    assert_eq!(task["reconciliation"]["resolution"], "not_applied");
    assert_eq!(task["history"].as_array().unwrap().len(), 1);
    assert_eq!(task["history"][0]["state"], "unknown");
    assert_eq!(task["history"][0]["outcomeUnknown"], true);
    assert_eq!(task["history"][0]["code"], "OUTCOME_UNKNOWN");
}

#[test]
fn owner_reconciliation_and_session_listing_apply_authoritative_ledger_history() {
    use intelligent_cells::{durable::DurableStore, harness, node::Node};
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let config = runtime_config(dir.path(), "master", json!({}), json!([]));
    let store = SessionStore::open(&config.state_dir).unwrap();
    let session = store.create(None).unwrap();
    let id = session["sessionId"].as_str().unwrap();
    for task in ["owner-hook", "ledger-repair"] {
        store
            .record_start(id, "servant", &json!({"taskId":task,"tool":"writeFile"}))
            .unwrap();
        store
            .record_finish(
                id,
                task,
                &Err(
                    intelligent_cells::IcError::new("OUTCOME_UNKNOWN", "Connection interrupted")
                        .unknown(),
                ),
            )
            .unwrap();
    }
    drop(store);
    let mut ledger =
        DurableStore::open(&config.state_dir.join("outgoing"), 1024, 8_388_608).unwrap();
    ledger.put("servant:owner-hook", json!({"key":"servant:owner-hook","peerId":"servant","taskId":"owner-hook","state":"unknown","sideEffect":true})).unwrap();
    ledger.put("servant:ledger-repair", json!({"key":"servant:ledger-repair","peerId":"servant","taskId":"ledger-repair","state":"reconciled","reconciliation":{"resolution":"not_applied","note":"Previous inspection found no effects","at":100}})).unwrap();
    drop(ledger);
    let node = Node::new(config).unwrap();
    node.command(&json!({"command":"reconcile","peerId":"servant","taskId":"owner-hook","resolution":"not_applied","note":"Fixture confirms no operation was sent"})).unwrap();
    let session = node
        .command(&json!({"command":"sessionOpen","sessionId":id}))
        .unwrap();
    assert_eq!(session["tasks"][0]["state"], "reconciled");
    assert_eq!(session["tasks"][1]["state"], "unknown");
    let sessions = node.command(&json!({"command":"listSessions"})).unwrap();
    for task in sessions[0]["tasks"].as_array().unwrap() {
        assert_eq!(task["state"], "reconciled");
        assert_eq!(task["history"][0]["state"], "unknown");
        assert_eq!(task["reconciliation"]["resolution"], "not_applied");
    }
    node.shutdown().unwrap();
}
