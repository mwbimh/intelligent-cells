//! Installed upstream harness CLIs against the Rust mock and Rust servant.
//! Run with IC_TEST_PI / IC_TEST_CLAUDE / IC_TEST_CODEX pointing to published binaries.
use intelligent_cells::{node::Node, owner, settings};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Mock(Child, u16);
impl Drop for Mock {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn mock(d: &Path, kind: &str, calls: Value) -> Mock {
    let script = d.join(format!("{kind}-script.json"));
    std::fs::write(&script, calls.to_string()).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_ic"))
        .args(["mock-model", "--kind", kind, "--script"])
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(c.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let v: Value = serde_json::from_str(&line).unwrap();
    Mock(c, v["port"].as_u64().unwrap() as u16)
}
fn output(mut cmd: Command) -> (i32, String, String) {
    use std::os::unix::process::CommandExt;
    cmd.process_group(0);
    let mut c = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = c.stdout.take().unwrap();
    let stderr = c.stderr.take().unwrap();
    let a = std::thread::spawn(move || {
        let mut s = String::new();
        stdout.take(2 * 1024 * 1024).read_to_string(&mut s).unwrap();
        s
    });
    let b = std::thread::spawn(move || {
        let mut s = String::new();
        stderr.take(2 * 1024 * 1024).read_to_string(&mut s).unwrap();
        s
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(s) = c.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > deadline {
            unsafe {
                libc::kill(-(c.id() as i32), libc::SIGKILL);
            }
            panic!("Installed harness mock timeout")
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    unsafe {
        libc::kill(-(c.id() as i32), libc::SIGKILL);
    }
    let a = a.join().unwrap();
    let b = b.join().unwrap();
    (status.code().unwrap_or(-1), a, b)
}
fn resident(directory: &Path) -> std::sync::Arc<Node> {
    let path = settings::initialize(Some(&directory.join("config.json"))).unwrap();
    settings::set_config(&path, "port", json!(0)).unwrap();
    settings::set_config(&path, "pairing.port", json!(0)).unwrap();
    let node = Node::new(settings::check_config(&path).unwrap()).unwrap();
    node.start().unwrap();
    node
}
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace(char::from(39), "'\"'\"'"))
}
fn check(kind: &str, variable: &str) {
    let Ok(binary) = std::env::var(variable) else {
        eprintln!("{variable} not set: installed {kind} CLI verification not requested");
        return;
    };
    let d = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(d.path()).unwrap();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let home = root.join("home");
    std::fs::create_dir(&home).unwrap();
    let servant = resident(&root.join("servant"));
    let master_home = root.join("master");
    let master = resident(&master_home);
    let _owner = owner::start(master.clone()).unwrap();
    let status = master.command(&json!({"command":"pairingStatus"})).unwrap();
    let address = json!({"id":master.config().id,"host":"127.0.0.1","port":status["port"],"fingerprint256":status["identity"]["fingerprint256"]});
    let request = servant
        .command(&json!({"command":"pairingRequest","master":address}))
        .unwrap();
    let identity = servant
        .command(&json!({"command":"pairingStatus"}))
        .unwrap();
    master.command(&json!({"command":"pairingApprove","requestId":request["requestId"],"expectedFingerprint":identity["identity"]["fingerprint256"]})).unwrap();
    servant.command(&json!({"command":"pairingConfirm","master":address,"requestId":request["requestId"],"grant":{"workspace":workspace,"tools":["echo"]}})).unwrap();
    let ic = PathBuf::from(env!("CARGO_BIN_EXE_ic"));
    let echo = json!({"peerId":servant.config().id,"text":"RUST_SERVANT_OBSERVED"});
    let calls = match kind {
        "pi" => {
            let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ic_echo","arguments":echo}}).to_string();
            json!([{"name":"bash","arguments":{"command":format!("printf '%s\\n' {} | {} mcp connect",shell_quote(&request),shell_quote(ic.to_str().unwrap()))}}])
        }
        "claude" => json!([{"name":"mcp__cells__ic_echo","arguments":echo}]),
        _ => json!([{"name":"ic_echo","arguments":echo}]),
    };
    let mock = mock(&root, kind, calls);
    let url = format!("http://127.0.0.1:{}", mock.1);
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut c = Command::new(binary);
    c.env_clear()
        .env("PATH", path)
        .env("HOME", &home)
        .env("IC_HOME", &master_home)
        .env("TMPDIR", &root)
        .current_dir(&workspace);
    match kind {
        "pi" => {
            let agentdir = home.join("pi");
            std::fs::create_dir(&agentdir).unwrap();
            std::fs::write(agentdir.join("models.json"),json!({"providers":{"cells_mock":{"baseUrl":format!("{url}/v1"),"api":"openai-completions","apiKey":"mock","models":[{"id":"intelligent-cells-mock","reasoning":false,"input":["text"],"contextWindow":65536,"maxTokens":4096}]}}}).to_string()).unwrap();
            c.env("PI_CODING_AGENT_DIR", agentdir).args([
                "--provider",
                "cells_mock",
                "--model",
                "intelligent-cells-mock",
                "--mode",
                "json",
                "--print",
                "--no-session",
                "--no-extensions",
                "--no-skills",
                "--no-prompt-templates",
                "--no-context-files",
                "--tools",
                "read,write,edit,bash",
                "Run the deterministic Rust IC fixture.",
            ]);
        }
        "claude" => {
            let mcp = json!({"mcpServers":{"cells":{"command":ic,"args":["mcp","connect"],"env":{"IC_HOME":master_home}}}});
            c.env("CLAUDE_CONFIG_DIR", home.join(".claude"))
                .env("ANTHROPIC_BASE_URL", &url)
                .env("ANTHROPIC_API_KEY", "intelligent-cells-mock")
                .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
                .env("DISABLE_NON_ESSENTIAL_MODEL_CALLS", "1")
                .env("DISABLE_TELEMETRY", "1")
                .env("DISABLE_ERROR_REPORTING", "1")
                .env("DISABLE_AUTOUPDATER", "1")
                .env("CLAUDE_CODE_SIMPLE", "1")
                .args([
                    "--bare",
                    "--print",
                    "--output-format",
                    "json",
                    "--model",
                    "intelligent-cells-mock",
                    "--tools",
                    "",
                    "--setting-sources",
                    "",
                    "--strict-mcp-config",
                    "--mcp-config",
                ])
                .arg(mcp.to_string())
                .args([
                    "--no-session-persistence",
                    "--disable-slash-commands",
                    "--no-chrome",
                    "--permission-mode",
                    "dontAsk",
                    "--allowedTools",
                    "mcp__cells__ic_echo",
                    "--",
                    "Run the deterministic Rust IC fixture.",
                ]);
        }
        _ => {
            let toml = format!(
                "model = \"intelligent-cells-mock\"\nmodel_provider = \"cells_mock\"\napproval_policy = \"never\"\nsandbox_mode = \"read-only\"\nweb_search = \"disabled\"\n[features]\nshell_tool = false\nplugins = false\nremote_plugin = false\nmulti_agent = false\n[model_providers.cells_mock]\nname = \"Rust IC loopback mock\"\nbase_url = \"{url}/v1\"\nwire_api = \"responses\"\nrequires_openai_auth = false\nrequest_max_retries = 0\nstream_max_retries = 0\n[mcp_servers.cells]\ncommand = {}\nargs = {}\ndefault_tools_approval_mode = \"approve\"\nstartup_timeout_sec = 20\n[mcp_servers.cells.env]\nIC_HOME = {}\n",
                json!(ic),
                json!(["mcp", "connect"]),
                json!(master_home)
            );
            std::fs::write(home.join("config.toml"), toml).unwrap();
            c.env("CODEX_HOME", &home).args([
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "--json",
                "Run the deterministic Rust IC fixture.",
            ]);
        }
    }
    let (code, out, err) = output(c);
    let history = servant
        .command(&json!({"command":"listTasks","kind":"incoming","limit":100}))
        .unwrap();
    let records = history["records"].as_array().unwrap();
    assert_eq!(
        records.len(),
        1,
        "{kind}: expected one real servant task: {history}\n{err}\n{out}"
    );
    assert_eq!(records[0]["tool"], "echo");
    assert_eq!(records[0]["response"]["status"], "ok");
    assert_eq!(
        records[0]["response"]["result"]["text"],
        "RUST_SERVANT_OBSERVED"
    );
    master.shutdown().unwrap();
    servant.shutdown().unwrap();
    assert_eq!(code, 0, "{kind}: {err}\n{out}");
    assert!(
        out.contains("RUST_SERVANT_OBSERVED"),
        "{kind}: real servant observation absent\n{err}\n{out}"
    );
}
#[test]
fn real_pi_cli_rust_mock_and_servant() {
    check("pi", "IC_TEST_PI")
}
#[test]
fn real_claude_cli_rust_mock_and_servant() {
    check("claude", "IC_TEST_CLAUDE")
}
#[test]
fn real_codex_cli_rust_mock_and_servant() {
    check("codex", "IC_TEST_CODEX")
}
