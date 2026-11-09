use intelligent_cells::harness::{executable_identity, fixture, mock_response, remote_tools};
use serde_json::json;
#[test]
fn local_sync_tools_exclude_remote_files() {
    let t = remote_tools(true);
    assert!(t.iter().any(|v| v["name"] == "ic_sync"));
    assert!(t.iter().any(|v| v["name"] == "ic_workspace"));
    assert!(!t.iter().any(|v| v["name"] == "ic_read"));
    assert!(remote_tools(false).iter().any(|v| v["name"] == "ic_read"));
}
#[test]
fn identity_changes_with_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("tool");
    std::fs::write(&p, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    let a = executable_identity(&p).unwrap();
    std::fs::write(&p, b"#!/bin/sh\nexit 1\n").unwrap();
    assert_ne!(a, executable_identity(&p).unwrap());
}
#[test]
fn fixture_is_ca_and_leaf_cert() {
    let d = tempfile::tempdir().unwrap();
    fixture(d.path(), &["master".into(), "servant".into()]).unwrap();
    let ca =
        openssl::x509::X509::from_pem(&std::fs::read(d.path().join("ca.pem")).unwrap()).unwrap();
    let leaf = openssl::x509::X509::from_pem(&std::fs::read(d.path().join("master.pem")).unwrap())
        .unwrap();
    assert!(leaf.verify(&ca.public_key().unwrap()).unwrap());
    assert!(!leaf.verify(&leaf.public_key().unwrap()).unwrap());
}
#[test]
fn mock_three_protocols_have_tool_and_completion() {
    let calls = json!([{"name":"ic_echo","arguments":{"peerId":"s","text":"mock"}}]);
    for kind in ["pi", "claude", "codex"] {
        let body = match kind {
            "pi" => json!({"model":"intelligent-cells-mock","stream":true,"messages":[]}),
            "claude" => json!({"model":"intelligent-cells-mock","stream":true,"messages":[]}),
            _ => json!({"model":"intelligent-cells-mock","input":[]}),
        };
        let text = mock_response(kind, &calls, &body, 0).unwrap().1;
        assert!(text.contains("ic_echo"));
        assert!(
            mock_response(kind, &calls, &body, 1)
                .unwrap()
                .1
                .contains("Mock completed")
        );
    }
}
#[test]
fn mcp_argument_validation_rejects_unknown_and_bad_types() {
    use intelligent_cells::harness::validate_arguments;
    let t = remote_tools(false);
    let exec = t.iter().find(|t| t["name"] == "ic_exec").unwrap();
    assert!(
        validate_arguments(
            &exec["inputSchema"],
            &json!({"peerId":"s","command":"build","args":[]})
        )
        .is_ok()
    );
    for args in [
        json!({"peerId":"s","command":"build","args":[],"file":"/bin/sh"}),
        json!({"peerId":"s","command":"build","args":[4]}),
        json!({"peerId":"s","command":"build","args":[],"timeoutMs":1}),
        json!({"peerId":7,"command":"build","args":[]}),
    ] {
        assert!(validate_arguments(&exec["inputSchema"], &args).is_err());
    }
}
#[test]
fn removed_commands_are_rejected() {
    for command in [
        "call",
        "launch",
        "check-config",
        "owner",
        "identity-fixture",
        "mock-server",
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_ic"))
            .arg(command)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "Removed command accepted: {command}"
        );
    }
}
#[test]
fn install_accepts_only_exact_safe_versions() {
    use intelligent_cells::harness::exact_version;
    for s in ["0.99.2", "2.1.288", "1.2.3-rc.1"] {
        assert!(exact_version(s));
    }
    for s in [
        "latest",
        "^1.2.3",
        "01.2.3",
        "1.2",
        "1.2.3;id",
        "1.2.3-",
        "1.2.3/escape",
    ] {
        assert!(!exact_version(s));
    }
}
#[test]
fn cli_rejects_unknown_flags() {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_ic"))
        .args(["serve", "--invented-unsafe-flag", "x"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("Unknown option"));
}
#[test]
fn daemon_sigterm_shutdown_is_clean() {
    use std::io::{BufRead, BufReader};
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let cfg = intelligent_cells::settings::initialize(Some(&root.join("config.json"))).unwrap();
    intelligent_cells::settings::set_config(&cfg, "port", json!(0)).unwrap();
    intelligent_cells::settings::set_config(&cfg, "pairing.port", json!(0)).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ic"))
        .env("IC_HOME", &root)
        .arg("serve")
        .arg("--daemon")
        .args(["--log-format", "json"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stderr.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.contains("node_ready"));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let code = child.wait().unwrap();
    assert!(
        code.success(),
        "daemon should handle SIGTERM and flush state cleanly: {code}"
    );
}
#[test]
fn mcp_revalidates_local_root_identity() {
    use std::io::{BufRead, BufReader, Write};
    let d = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(d.path()).unwrap();
    let local = base.join("local");
    std::fs::create_dir(&local).unwrap();
    let cfg = intelligent_cells::settings::initialize(Some(&base.join("config.json"))).unwrap();
    intelligent_cells::settings::set_config(&cfg, "port", json!(0)).unwrap();
    intelligent_cells::settings::set_config(&cfg, "pairing.port", json!(0)).unwrap();
    let peer_id = uuid::Uuid::new_v4().to_string();
    let mut runtime_config = intelligent_cells::settings::check_config(&cfg).unwrap();
    // Configure an outgoing target. Root identity validation must stop the call
    // before any transport attempt to this deliberately unreachable endpoint.
    runtime_config.raw["peers"] = json!([{"id":peer_id,"host":"127.0.0.1","port":1}]);
    let node = intelligent_cells::node::Node::new(runtime_config).unwrap();
    node.start().unwrap();
    let _owner = intelligent_cells::owner::start(node.clone()).unwrap();
    node.command(&json!({"command":"bindLocalWorkspace","logicalWorkspaceId":"project","path":local,"expectedRevision":0})).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ic"))
        .env("IC_HOME", &base)
        .args(["mcp", "connect", "--cwd"])
        .arg(&local)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})
    )
    .unwrap();
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap()["id"],
        1
    );
    std::fs::rename(&local, base.join("original-root")).unwrap();
    std::fs::create_dir(&local).unwrap();
    writeln!(input,"{}",json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ic_echo","arguments":{"peerId":peer_id,"text":"guard"}}})).unwrap();
    line.clear();
    output.read_line(&mut line).unwrap();
    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    // Complete sessionDetach while the resident owner socket is still alive, even
    // when a subsequent response assertion fails.
    drop(input);
    let status = child.wait().unwrap();
    node.shutdown().unwrap();
    assert!(status.success());
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(
        response["result"]["content"][0]["text"], "WORKSPACE_CHANGED: Session directory changed",
        "{response}"
    );
}
#[test]
fn harness_version_verification_is_bounded() {
    use intelligent_cells::harness::verify_harness_version;
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("version");
    std::fs::write(&p, "#!/bin/sh\nsleep 5\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    let start = std::time::Instant::now();
    assert!(verify_harness_version(&p, "1.2.3", std::time::Duration::from_millis(50)).is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(3));
    std::fs::write(&p, "#!/bin/sh\nprintf '1.2.3\\n'\n").unwrap();
    verify_harness_version(&p, "1.2.3", std::time::Duration::from_secs(1)).unwrap();
    assert!(verify_harness_version(&p, "1.2.4", std::time::Duration::from_secs(1)).is_err());
}

#[test]
fn agent_tool_names_are_ic_only_and_default_peer_is_optional() {
    for local_sync in [false, true] {
        let tools = remote_tools(local_sync);
        assert!(
            tools
                .iter()
                .all(|tool| tool["name"].as_str().unwrap().starts_with("ic_"))
        );
        assert!(
            !tools
                .iter()
                .any(|tool| tool["name"].as_str().unwrap().starts_with("remote_"))
        );
        let selection = tools
            .iter()
            .find(|tool| tool["name"] == "ic_peer")
            .expect("default peer selection tool");
        assert_eq!(selection["inputSchema"]["required"], json!(["peerId"]));
        assert!(
            selection["description"]
                .as_str()
                .unwrap()
                .contains("session")
        );
        for tool in tools.iter().filter(|tool| tool["name"] != "ic_peer") {
            assert!(
                !tool["inputSchema"]["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("peerId")),
                "peerId must be optional for {}",
                tool["name"]
            );
        }
        let echo = tools.iter().find(|tool| tool["name"] == "ic_echo").unwrap();
        intelligent_cells::harness::validate_arguments(
            &echo["inputSchema"],
            &json!({"text":"default peer"}),
        )
        .unwrap();
    }
}

#[test]
fn simplified_catalog_has_process_control_and_no_removed_aliases() {
    use intelligent_cells::harness::validate_arguments;
    for (local_sync, count) in [(false, 15), (true, 11)] {
        let tools = remote_tools(local_sync);
        assert_eq!(tools.len(), count);
        for removed in [
            "ic_read_chunk",
            "ic_write_chunk",
            "ic_resources",
            "ic_resource_read",
            "ic_job_status",
            "ic_job_output",
            "ic_job_cancel",
            "ic_job_stdin",
            "ic_sync_scope",
        ] {
            assert!(
                !tools.iter().any(|tool| tool["name"] == removed),
                "removed alias {removed}"
            );
        }
        assert_eq!(
            tools.iter().any(|tool| tool["name"] == "ic_workspace"),
            local_sync
        );
        let process = tools
            .iter()
            .find(|tool| tool["name"] == "ic_process")
            .unwrap();
        assert_eq!(
            process["inputSchema"]["properties"]["action"]["enum"],
            json!(["status", "output", "cancel"])
        );
        for action in ["status", "output", "cancel"] {
            validate_arguments(
                &process["inputSchema"],
                &json!({"action":action,"jobId":"job"}),
            )
            .unwrap();
        }
        for invalid in [
            json!({"action":"stdin","jobId":"job"}),
            json!({"jobId":"job"}),
            json!({"action":"status"}),
            json!({"action":"output","jobId":"job","stdin":"data"}),
        ] {
            assert!(
                validate_arguments(&process["inputSchema"], &invalid).is_err(),
                "{invalid}"
            );
        }
        let exec = tools.iter().find(|tool| tool["name"] == "ic_exec").unwrap();
        assert!(
            validate_arguments(
                &exec["inputSchema"],
                &json!({"command":"build","args":[],"stdin":"data"})
            )
            .is_err()
        );
    }
}

#[test]
fn schema_enum_values_are_enforced() {
    use intelligent_cells::harness::validate_arguments;
    let schema = json!({"type":"string","enum":["status","output","cancel"]});
    assert!(validate_arguments(&schema, &json!("stdin")).is_err());
    validate_arguments(&schema, &json!("status")).unwrap();
}
