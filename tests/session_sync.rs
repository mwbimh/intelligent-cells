use serde_json::json;
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
fn session_local_sync_scopes_and_mirrors_bound_directory() {
    use intelligent_cells::{harness, node::Node};
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let local = dir.path().join("local");
    let remote = dir.path().join("remote");
    std::fs::create_dir(&local).unwrap();
    std::fs::create_dir(&remote).unwrap();
    std::fs::write(local.join("proof"), "synchronized").unwrap();
    std::fs::write(remote.join("obsolete"), "delete").unwrap();
    let servant = Node::new(runtime_config(dir.path(), "servant", json!({"grants":{"master":{"tools":["workspaceList"],"workspaces":{"project":{"workspace":remote,"allowUnsandboxedProcesses":true,"execCommands":{"read":{"file":std::fs::canonicalize("/bin/cat").unwrap(),"launchMode":"native","args":["proof"]}},"tools":["syncInventory","syncUpload","syncApply","syncExec","exec"],"directories":[{"path":"","read":true,"write":true}]}}}}}), json!([]))).unwrap();
    servant.start().unwrap();
    let master = Node::new(runtime_config(
        dir.path(),
        "master",
        json!({}),
        json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
    ))
    .unwrap();
    master.command(&json!({"command":"bindLocalWorkspace","logicalWorkspaceId":"project","path":local,"expectedRevision":0})).unwrap();
    master.command(&json!({"command":"bindWorkspace","peerId":"servant","logicalWorkspaceId":"project","workspaceId":"project"})).unwrap();
    let session = master
        .command(&json!({"command":"sessionOpen","cwd":local,"localSync":true}))
        .unwrap();
    assert_eq!(session["localSync"], true);
    let id = &session["sessionId"];
    master.command(&json!({"command":"mcpCallTool","sessionId":id,"name":"ic_peer","arguments":{"peerId":"servant"}})).unwrap();
    let tools = master
        .command(&json!({"command":"mcpListTools","sessionId":id}))
        .unwrap();
    let tools = tools["tools"].as_array().unwrap();
    assert!(tools.iter().any(|t| t["name"] == "ic_sync"));
    assert!(tools.iter().any(|t| t["name"] == "ic_workspace"));
    assert!(!tools.iter().any(|t| t["name"] == "ic_sync_scope"));
    assert!(!tools.iter().any(|t| t["name"] == "ic_read"));
    let scope = master.command(&json!({"command":"mcpCallTool","sessionId":id,"name":"ic_workspace","arguments":{"scope":{"paths":[""]}}})).unwrap();
    assert_eq!(scope["isError"], false);
    let result = master
        .command(&json!({"command":"mcpCallTool","sessionId":id,"name":"ic_sync","arguments":{}}))
        .unwrap();
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        std::fs::read_to_string(remote.join("proof")).unwrap(),
        "synchronized"
    );
    assert!(!remote.join("obsolete").exists());
    let records = master.command(&json!({"command":"listSessions"})).unwrap();
    let saved = records
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["sessionId"] == *id)
        .unwrap();
    assert_eq!(saved["tasks"][0]["tool"], "syncApply");
    assert_eq!(saved["tasks"][0]["state"], "completed");
    assert_eq!(saved["targets"]["servant"], "project");
    std::fs::write(local.join("proof"), "updated before execution").unwrap();
    let execution = master.command(&json!({"command":"mcpCallTool","sessionId":id,"name":"ic_exec","arguments":{"command":"read","args":[]}})).unwrap();
    assert_eq!(execution["isError"], false, "{execution}");
    assert!(
        execution.to_string().contains("updated before execution"),
        "{execution}"
    );
    assert_eq!(
        std::fs::read_to_string(remote.join("proof")).unwrap(),
        "updated before execution"
    );
    let plain = master
        .command(&json!({"command":"sessionOpen","cwd":local}))
        .unwrap();
    assert_eq!(master.command(&json!({"command":"mcpCallTool","sessionId":plain["sessionId"],"name":"ic_sync","arguments":{}})).unwrap_err().code, "TOOL_DENIED");
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
}
