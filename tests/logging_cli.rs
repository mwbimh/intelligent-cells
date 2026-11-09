use intelligent_cells::{node::Node, owner, settings};
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn run(command: &str, options: &[&str], input: &str) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let config = settings::initialize(Some(&root.join("config.json"))).unwrap();
    settings::set_config(&config, "port", json!(0)).unwrap();
    settings::set_config(&config, "pairing.port", json!(0)).unwrap();
    let resident = if command == "mcp" {
        let node = Node::new(settings::check_config(&config).unwrap()).unwrap();
        node.start().unwrap();
        let handle = owner::start(node.clone()).unwrap();
        Some((node, handle))
    } else {
        None
    };
    let mut process = Command::new(env!("CARGO_BIN_EXE_ic"));
    process.env("IC_HOME", &root).arg(command);
    if command == "mcp" {
        process.arg("connect");
    }
    let mut child = process
        .args(options)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    if command == "serve" {
        let loaded = settings::check_config(&config).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if owner::request(&loaded, &json!({"command":"shutdown"})).is_ok() {
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("Resident service did not accept shutdown over IPC");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    let output = child.wait_with_output().unwrap();
    if let Some((node, handle)) = resident {
        drop(handle);
        node.shutdown().unwrap();
    }
    output
}

#[test]
fn default_serve_logs_are_readable_and_stdout_is_empty() {
    let output = run("serve", &[], "{\"command\":\"shutdown\"}\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Node ready"), "{stderr}");
    assert!(
        !stderr.contains("\x1b["),
        "redirected stderr must not have ANSI"
    );
    assert!(!stderr.lines().next().unwrap().starts_with('{'), "{stderr}");
    assert!(output.stdout.is_empty(), "Service stdout must remain empty");
}

#[test]
fn explicit_json_logs_are_json_lines() {
    let output = run("serve", &["--log-format", "json"], "");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let events: Vec<Value> = stderr
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events.iter().any(|event| event["event"] == "node_ready"),
        "{stderr}"
    );
}

#[test]
fn resident_mcp_stdout_contains_only_json_rpc() {
    {
        let output = run(
            "mcp",
            &[],
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let frames: Vec<Value> = stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(frames.len(), 1, "{stdout}");
        assert_eq!(frames[0]["jsonrpc"], "2.0");
        assert_eq!(frames[0]["id"], 1);
        assert!(frames[0].get("result").is_some(), "{stdout}");
        assert!(!stdout.contains("\x1b["));
    }
}

#[test]
fn invalid_log_format_is_rejected_before_config_load() {
    let output = Command::new(env!("CARGO_BIN_EXE_ic"))
        .args(["serve", "--log-format", "yaml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("log format") || stderr.contains("log-format"),
        "{stderr}"
    );
    assert!(!stderr.contains("Unknown option"), "{stderr}");
    assert!(output.stdout.is_empty());
}
