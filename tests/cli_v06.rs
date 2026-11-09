use std::process::Command;

#[test]
fn help_exposes_resident_commands_only() {
    let out = Command::new(env!("CARGO_BIN_EXE_ic"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for command in [
        "ic config",
        "ic nodes",
        "ic pair",
        "ic mcp",
        "ic mock-model",
    ] {
        assert!(text.contains(command), "missing {command}: {text}");
    }
    for removed in [
        "ic call",
        "ic launch",
        "ic owner",
        "ic check-config",
        "ic identity-fixture",
        "ic mock-server",
    ] {
        assert!(!text.contains(removed), "still exposes {removed}");
    }
}

#[test]
fn removed_commands_and_non_config_config_flags_are_rejected() {
    for args in [
        vec!["call"],
        vec!["launch"],
        vec!["owner"],
        vec!["check-config"],
        vec!["identity-fixture"],
        vec!["mock-server"],
        vec!["serve", "--config", "missing.json"],
        vec!["nodes", "--config", "missing.json"],
        vec!["mcp", "connect", "--config", "missing.json"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_ic"))
            .args(&args)
            .output()
            .unwrap();
        assert!(!out.status.success(), "accepted {args:?}");
        let error = String::from_utf8(out.stderr).unwrap();
        assert!(
            error.contains("INVALID_ARGS"),
            "wrong failure for {args:?}: {error}"
        );
    }
}

#[test]
fn mcp_give_writes_native_claude_registration_without_launching() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("mcp.json");
    std::fs::write(
        &target,
        r#"{"other":true,"mcpServers":{"existing":{"command":"other"}}}"#,
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ic"))
        .args(["mcp", "give", "--harness", "claude-code", "--target"])
        .arg(&target)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(target).unwrap()).unwrap();
    assert_eq!(value["other"], true);
    assert_eq!(value["mcpServers"]["existing"]["command"], "other");
    assert_eq!(
        value["mcpServers"]["ic"]["args"],
        serde_json::json!(["mcp", "connect"])
    );
}

#[test]
fn mcp_give_rejects_pi_without_modifying_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("settings.json");
    let out = Command::new(env!("CARGO_BIN_EXE_ic"))
        .args(["mcp", "give", "--harness", "pi", "--target"])
        .arg(&target)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!target.exists());
}

#[test]
fn mcp_give_replaces_codex_table_and_preserves_unrelated_settings() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("config.toml");
    std::fs::write(&target,"model = \"example\"\n[mcp_servers.ic]\ncommand = \"old\"\nargs = []\n[mcp_servers.other]\ncommand = \"keep\"\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ic"))
        .args(["mcp", "give", "--harness", "codex", "--target"])
        .arg(&target)
        .args(["--cwd", "/tmp/project"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(target).unwrap();
    assert!(text.contains("model = \"example\""));
    assert!(text.contains("command = \"keep\""));
    assert!(!text.contains("command = \"old\""));
    assert_eq!(text.matches("[mcp_servers.ic]").count(), 1);
    assert!(text.contains("--cwd"));
    assert!(text.contains("/tmp/project"));
}

#[test]
fn config_selection_is_persistent_and_only_config_accepts_path() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config = dir.path().join("node/config.json");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_ic"))
            .env("IC_HOME", &home)
            .args(args)
            .output()
            .unwrap()
    };
    let init = run(&["config", "init", "--config", config.to_str().unwrap()]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let checked = run(&["config", "check"]);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(value["valid"], true);
    assert!(uuid::Uuid::parse_str(value["id"].as_str().unwrap()).is_ok());
    let shown = run(&["config"]);
    assert!(shown.status.success());
    let value: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(value["settings"]["version"], 2);
    for key in ["peers", "id", "grants"] {
        assert!(
            value["settings"].get(key).is_none(),
            "config contains node relationship field {key}"
        );
    }
    let invalid = run(&["config", "check", "--key", "port"]);
    assert!(!invalid.status.success());
}

#[test]
fn mcp_give_parses_quoted_toml_headers_and_refuses_invalid_toml() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("config.toml");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ic"))
            .args(["mcp", "give", "--harness", "codex", "--target"])
            .arg(&target)
            .output()
            .unwrap()
    };
    std::fs::write(&target,"# Keep this comment\n[mcp_servers.\"ic\"] # comment\ncommand = \"old\"\n[mcp_servers.other]\ncommand = \"other\"\n").unwrap();
    assert!(run().status.success());
    let text = std::fs::read_to_string(&target).unwrap();
    let parsed = text.parse::<toml_edit::DocumentMut>().unwrap();
    assert_eq!(
        parsed["mcp_servers"]["other"]["command"].as_str(),
        Some("other")
    );
    assert!(text.contains("# Keep this comment"));
    assert_ne!(parsed["mcp_servers"]["ic"]["command"].as_str(), Some("old"));
    let invalid = "[mcp_servers\n";
    std::fs::write(&target, invalid).unwrap();
    assert!(!run().status.success());
    assert_eq!(std::fs::read_to_string(target).unwrap(), invalid);
}

#[test]
fn serve_stays_resident_when_stdin_is_closed_without_daemon_flag() {
    use std::io::Read;
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_ic"))
            .env("IC_HOME", &home)
            .args(args)
            .output()
            .unwrap()
    };
    let init = run(&["config", "init"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    for key in ["port", "pairing.port"] {
        let changed = run(&["config", "set", "--key", key, "--value", "0"]);
        assert!(
            changed.status.success(),
            "{}",
            String::from_utf8_lossy(&changed.stderr)
        );
    }
    let mut service = Command::new(env!("CARGO_BIN_EXE_ic"))
        .env("IC_HOME", &home)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        if service.try_wait().unwrap().is_some() {
            break;
        }
        if run(&["pair", "status"]).status.success() {
            ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let running = service.try_wait().unwrap().is_none();
    let _ = service.kill();
    let _ = service.wait();
    let mut logs = String::new();
    service
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut logs)
        .unwrap();
    assert!(
        ready && running,
        "serve must remain resident with closed stdin: {logs}"
    );
    let mut stdout = String::new();
    service
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(
        stdout.is_empty(),
        "service stdout must not expose removed owner protocol: {stdout}"
    );
}

#[test]
fn local_sync_requires_explicit_cwd_before_contacting_service() {
    let out = Command::new(env!("CARGO_BIN_EXE_ic"))
        .args(["mcp", "connect", "--local-sync"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("local-sync requires --cwd"), "{error}");
}

#[test]
fn give_forwards_explicit_local_sync_session_settings() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("mcp.json");
    let out = Command::new(env!("CARGO_BIN_EXE_ic"))
        .args(["mcp", "give", "--harness", "claude-code", "--target"])
        .arg(&target)
        .args(["--local-sync", "--cwd", "/tmp/project"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(target).unwrap()).unwrap();
    let args = config["mcpServers"]["ic"]["args"].as_array().unwrap();
    assert!(args.contains(&serde_json::json!("--local-sync")));
    assert!(args.contains(&serde_json::json!("--cwd")));
    assert!(args.contains(&serde_json::json!("/tmp/project")));
}
