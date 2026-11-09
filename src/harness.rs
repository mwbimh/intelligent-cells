use crate::{IcError, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    io::{BufRead, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
fn err(s: &str) -> IcError {
    IcError::new("INVALID_ARGS", s)
}
fn option(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|s| s == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
fn required(args: &[String], name: &str) -> Result<String> {
    option(args, name).ok_or_else(|| err(&format!("Missing {name}")))
}
pub fn executable_identity(path: &Path) -> Result<Value> {
    let p = std::fs::canonicalize(path)?;
    let m = std::fs::metadata(&p)?;
    if !m.is_file() || m.mode() & 0o111 == 0 {
        return Err(err("Harness executable must be executable regular file"));
    }
    Ok(
        json!({"path":p,"dev":m.dev().to_string(),"ino":m.ino().to_string(),"size":m.len().to_string(),"mtimeNs":format!("{}:{}",m.mtime(),m.mtime_nsec()),"sha256":hex::encode(Sha256::digest(std::fs::read(&p)?))}),
    )
}
fn spec(h: &str) -> Result<(&'static str, &'static str)> {
    match h {
        "pi" => Ok(("@earendil-works/pi-coding-agent", "pi")),
        "claude-code" | "claude" => Ok(("@anthropic-ai/claude-code", "claude")),
        "codex" => Ok(("@openai/codex", "codex")),
        _ => Err(err("Unsupported harness")),
    }
}
pub fn cli(args: Vec<String>) -> Result<()> {
    match args.first().map(String::as_str) {
        Some("--help") | Some("help") | None => {
            println!(
                "ic serve [--daemon] [--operator] [--log-format text|json]\nic config [show|init|use|set|check] [--config FILE]\nic nodes [list|status|rename|bind|unbind|command]\nic pair [list|status|request|approve|reject|confirm]\nic mcp [list|add|remove|update|builtin|give|connect]\nic install --harness NAME --version EXACT --directory NEW_PATH\nic mock-model --kind pi|claude|codex --script FILE [--port N]\n\nRun ic config|nodes|pair|mcp --help for command options. All node commands use the selected configuration."
            );
            Ok(())
        }
        Some("--version") => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("config") => config_cli(&args[1..]),
        Some("nodes") => nodes_cli(&args[1..]),
        Some("pair") => pair_cli(&args[1..]),
        Some("mcp") => mcp_cli(&args[1..]),
        Some("serve") => {
            validate_flags(
                &args[1..],
                &["--log-format"],
                &["--daemon", "--operator"],
                false,
            )?;
            serve(&args)
        }
        Some("install") => {
            validate_flags(
                &args[1..],
                &["--harness", "--directory", "--version"],
                &[],
                false,
            )?;
            install(&args)
        }
        Some("mock-model") => {
            validate_flags(&args[1..], &["--kind", "--script", "--port"], &[], false)?;
            mock_server(&args)
        }
        _ => Err(err("Unknown IC command")),
    }
}
fn output(value: Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
fn resident(command: Value) -> Result<Value> {
    crate::owner::request(&crate::settings::load_selected()?, &command)
}
fn config_cli(args: &[String]) -> Result<()> {
    if args.first().is_some_and(|s| s == "--help") {
        println!(
            "ic config show [--config FILE]\nic config init [--config FILE]\nic config use --config FILE\nic config set --key dotted.path --value JSON [--config FILE]\nic config check [--config FILE]"
        );
        return Ok(());
    }
    let (sub, flags) = match args.first() {
        Some(s) if !s.starts_with('-') => (s.as_str(), &args[1..]),
        _ => ("show", args),
    };
    let allowed: &[&str] = match sub {
        "show" | "init" | "use" | "check" => &["--config"],
        "set" => &["--config", "--key", "--value"],
        _ => return Err(err("Unknown config command")),
    };
    validate_flags(flags, allowed, &[], false)?;
    let explicit = option(flags, "--config").map(PathBuf::from);
    if sub == "init" {
        let path = crate::settings::initialize(explicit.as_deref())?;
        crate::settings::select_config(&path)?;
        return output(json!({"config":path,"initialized":true}));
    }
    if sub == "use" {
        let path = PathBuf::from(required(flags, "--config")?);
        crate::settings::select_config(&path)?;
        return output(json!({"config":crate::settings::selected_config_path()?}));
    }
    let path = explicit
        .map(Ok)
        .unwrap_or_else(crate::settings::selected_config_path)?;
    match sub {
        "show" => output(
            json!({"config":path,"settings":serde_json::from_slice::<Value>(&std::fs::read(&path)?)?}),
        ),
        "set" => {
            crate::settings::set_config(
                &path,
                &required(flags, "--key")?,
                serde_json::from_str(&required(flags, "--value")?)?,
            )?;
            output(json!({"config":path,"updated":true,"restartRequired":true}))
        }
        "check" => {
            let config = crate::settings::check_config(&path)?;
            output(json!({"valid":true,"id":config.id,"config":path}))
        }
        _ => Err(err("Unknown config command")),
    }
}
fn nodes_cli(args: &[String]) -> Result<()> {
    if args.first().is_some_and(|s| s == "--help") {
        println!(
            "ic nodes list\nic nodes status [--peer ID]\nic nodes rename --peer ID --name NAME\nic nodes bind --peer ID --local PATH --workspace ID\nic nodes unbind --peer ID --local PATH\nic nodes command --json JSON"
        );
        return Ok(());
    }
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let flags = args.get(1..).unwrap_or(&[]);
    let allowed: &[&str] = match sub {
        "list" => &[],
        "status" => &["--peer"],
        "rename" => &["--peer", "--name"],
        "bind" => &["--peer", "--local", "--workspace"],
        "unbind" => &["--peer", "--local"],
        "command" => &["--json"],
        _ => return Err(err("Unknown nodes command")),
    };
    validate_flags(flags, allowed, &[], false)?;
    let command = match sub {
        "list" => json!({"command":"nodesList"}),
        "status" => json!({"command":"nodesStatus","peerId":option(flags,"--peer")}),
        "rename" => {
            json!({"command":"nodesRename","peerId":required(flags,"--peer")?,"name":required(flags,"--name")?})
        }
        "bind" => {
            json!({"command":"nodesBind","peerId":required(flags,"--peer")?,"localPath":required(flags,"--local")?,"workspaceId":required(flags,"--workspace")?})
        }
        "unbind" => {
            json!({"command":"nodesUnbind","peerId":required(flags,"--peer")?,"localPath":required(flags,"--local")?})
        }
        "command" => serde_json::from_str(&required(flags, "--json")?)?,
        _ => unreachable!(),
    };
    output(resident(command)?)
}
fn pair_cli(args: &[String]) -> Result<()> {
    use std::io::IsTerminal;
    if args.first().is_some_and(|s| s == "--help") {
        println!(
            "ic pair [list|status]\nic pair request --master JSON\nic pair approve --request ID --fingerprint SHA256\nic pair reject --request ID\nic pair confirm --request ID --master JSON [--grant JSON]\nWith no subcommand in a terminal, select a pending request to approve."
        );
        return Ok(());
    }
    if args.is_empty() && std::io::stdin().is_terminal() {
        let listed = resident(json!({"command":"listPairingRequests"}))?;
        let pending: Vec<&Value> = listed["requests"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| r["status"] == "pending")
            .collect();
        if pending.is_empty() {
            return output(listed);
        }
        for (i, request) in pending.iter().enumerate() {
            eprintln!(
                "{}. Node {} at {}:{}\n   Fingerprint: {}",
                i + 1,
                request["nodeId"],
                request["endpoint"]["host"],
                request["endpoint"]["port"],
                request["fingerprint256"]
            );
        }
        eprint!("Select request number (empty cancels): ");
        std::io::stderr().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim().is_empty() {
            return Ok(());
        }
        let selected = input
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| pending.get(n))
            .ok_or_else(|| err("Invalid request selection"))?;
        eprint!("Type the node fingerprint to approve: ");
        std::io::stderr().flush()?;
        input.clear();
        std::io::stdin().read_line(&mut input)?;
        return output(resident(
            json!({"command":"pairingApprove","requestId":selected["requestId"],"expectedFingerprint":input.trim()}),
        )?);
    }
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let flags = args.get(1..).unwrap_or(&[]);
    let allowed: &[&str] = match sub {
        "list" | "status" => &[],
        "request" => &["--master"],
        "approve" => &["--request", "--fingerprint"],
        "reject" => &["--request"],
        "confirm" => &["--request", "--master", "--grant"],
        _ => return Err(err("Unknown pair command")),
    };
    validate_flags(flags, allowed, &[], false)?;
    let mut command = match sub {
        "list" => json!({"command":"listPairingRequests"}),
        "status" => json!({"command":"pairingStatus"}),
        "request" => {
            json!({"command":"pairingRequest","master":serde_json::from_str::<Value>(&required(flags,"--master")?)?})
        }
        "approve" => {
            json!({"command":"pairingApprove","requestId":required(flags,"--request")?,"expectedFingerprint":required(flags,"--fingerprint")?})
        }
        "reject" => json!({"command":"pairingReject","requestId":required(flags,"--request")?}),
        "confirm" => {
            json!({"command":"pairingConfirm","requestId":required(flags,"--request")?,"master":serde_json::from_str::<Value>(&required(flags,"--master")?)?})
        }
        _ => unreachable!(),
    };
    if let Some(grant) = option(flags, "--grant") {
        command["grant"] = serde_json::from_str(&grant)?;
    }
    output(resident(command)?)
}
fn mcp_cli(args: &[String]) -> Result<()> {
    if args.first().is_some_and(|s| s == "--help") {
        println!(
            "ic mcp list\nic mcp add --name NAME --definition JSON\nic mcp remove --id ID\nic mcp update --id ID --patch JSON\nic mcp builtin --tool NAME --patch JSON\nic mcp give --harness claude-code|codex --target FILE [--cwd PATH] [--session ID] [--local-sync]\nic mcp connect [--cwd PATH] [--session ID] [--local-sync]\nDefinitions and patches support enabled, visibility.local and visibility.masters. Builtins are always invisible locally."
        );
        return Ok(());
    }
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let flags = args.get(1..).unwrap_or(&[]);
    let allowed: &[&str] = match sub {
        "list" => &[],
        "add" => &["--name", "--definition"],
        "remove" => &["--id"],
        "update" => &["--id", "--patch"],
        "builtin" => &["--tool", "--patch"],
        "give" => &["--harness", "--target", "--cwd", "--session"],
        "connect" => &["--cwd", "--session"],
        _ => return Err(err("Unknown mcp command")),
    };
    let switches: &[&str] = if matches!(sub, "give" | "connect") {
        &["--local-sync"]
    } else {
        &[]
    };
    validate_flags(flags, allowed, switches, false)?;
    if flags.iter().any(|flag| flag == "--local-sync") && option(flags, "--cwd").is_none() {
        return Err(err("local-sync requires --cwd"));
    }
    if sub == "connect" {
        return mcp_connect(flags);
    }
    if sub == "give" {
        return mcp_give(flags);
    }
    let operation = match sub {
        "list" => json!({"command":"list"}),
        "add" => {
            let mut definition: Value = serde_json::from_str(&required(flags, "--definition")?)?;
            if !definition.is_object() {
                return Err(err("MCP definition must be an object"));
            }
            definition["name"] = json!(required(flags, "--name")?);
            json!({"command":"add","server":definition})
        }
        "remove" => json!({"command":"remove","id":required(flags,"--id")?}),
        "update" => {
            json!({"command":"update","id":required(flags,"--id")?,"patch":serde_json::from_str::<Value>(&required(flags,"--patch")?)?})
        }
        "builtin" => {
            let mut patch: Value = serde_json::from_str(&required(flags, "--patch")?)?;
            if !patch.is_object() {
                return Err(err("Builtin patch must be an object"));
            }
            patch["command"] = json!("updateBuiltin");
            patch["tool"] = json!(required(flags, "--tool")?);
            patch
        }
        _ => unreachable!(),
    };
    output(resident(
        json!({"command":"mcpRegistry","operation":operation}),
    )?)
}
fn mcp_connect(args: &[String]) -> Result<()> {
    install_signals();
    let config = crate::settings::load_selected()?;
    let mut open = json!({"command":"sessionOpen"});
    if args.iter().any(|arg| arg == "--local-sync") {
        open["localSync"] = json!(true);
    }
    if let Some(cwd) = option(args, "--cwd") {
        open["cwd"] = json!(cwd);
    }
    if let Some(id) = option(args, "--session") {
        open["sessionId"] = json!(id);
    }
    let session = crate::owner::request(&config, &open)?;
    let session_id = session["sessionId"]
        .as_str()
        .ok_or_else(|| err("Server did not return a session ID"))?;
    eprintln!("IC session: {session_id}");
    let frames = input_frames();
    let result = (|| -> Result<()> {
        while SIGNAL.load(std::sync::atomic::Ordering::Acquire) == 0 {
            let request = match frames.recv_timeout(std::time::Duration::from_millis(20)) {
                Ok(Ok(Some(value))) => value,
                Ok(Ok(None)) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Ok(Err(_)) => {
                    println!(
                        "{}",
                        json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid JSON frame"}})
                    );
                    continue;
                }
            };
            let has_id = request.get("id").is_some();
            let response = crate::owner::request(
                &config,
                &json!({"command":"sessionMcp","sessionId":session_id,"request":request}),
            )?;
            if has_id && !response.is_null() {
                println!("{response}");
                std::io::stdout().flush()?;
            }
        }
        Ok(())
    })();
    let detached = crate::owner::request(
        &config,
        &json!({"command":"sessionDetach","sessionId":session_id}),
    );
    result?;
    detached?;
    Ok(())
}
fn mcp_give(args: &[String]) -> Result<()> {
    let harness = required(args, "--harness")?;
    if !matches!(harness.as_str(), "claude-code" | "claude" | "codex") {
        return Err(err(
            "This harness has no supported native MCP registration; use claude-code or codex",
        ));
    }
    let target = PathBuf::from(required(args, "--target")?);
    let executable = std::env::current_exe()?;
    let ic_home = crate::settings::home_dir()?;
    let mut arguments = vec!["mcp".to_owned(), "connect".to_owned()];
    for key in ["--cwd", "--session"] {
        if let Some(value) = option(args, key) {
            arguments.push(key.into());
            arguments.push(value);
        }
    }
    if args.iter().any(|arg| arg == "--local-sync") {
        arguments.push("--local-sync".into());
    }
    let text = if harness == "codex" {
        let existing = if target.exists() {
            std::fs::read_to_string(&target)?
        } else {
            String::new()
        };
        let mut document = existing
            .parse::<toml_edit::DocumentMut>()
            .map_err(|_| err("Invalid harness TOML configuration"))?;
        if document.get("mcp_servers").is_none() {
            document["mcp_servers"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        let servers = document["mcp_servers"]
            .as_table_mut()
            .ok_or_else(|| err("mcp_servers must be a TOML table"))?;
        let mut registration = match servers.get("ic") {
            Some(item) => item
                .as_table()
                .cloned()
                .ok_or_else(|| err("mcp_servers.ic must be a TOML table"))?,
            None => toml_edit::Table::new(),
        };
        registration["command"] = toml_edit::value(executable.to_string_lossy().as_ref());
        let mut array = toml_edit::Array::new();
        for argument in &arguments {
            array.push(argument.as_str());
        }
        registration["args"] = toml_edit::value(array);
        let mut environment = match registration.get("env") {
            Some(item) => item
                .as_table()
                .cloned()
                .ok_or_else(|| err("mcp_servers.ic.env must be a TOML table"))?,
            None => toml_edit::Table::new(),
        };
        environment["IC_HOME"] = toml_edit::value(ic_home.to_string_lossy().as_ref());
        registration["env"] = toml_edit::Item::Table(environment);
        servers.insert("ic", toml_edit::Item::Table(registration));
        document.to_string()
    } else {
        let mut config = if target.exists() {
            serde_json::from_slice::<Value>(&std::fs::read(&target)?)?
        } else {
            json!({})
        };
        if !config.is_object() {
            return Err(err("Harness configuration must be a JSON object"));
        }
        if config.get("mcpServers").is_none() {
            config["mcpServers"] = json!({});
        }
        if !config["mcpServers"].is_object() {
            return Err(err("mcpServers must be an object"));
        }
        if config["mcpServers"].get("ic").is_none() {
            config["mcpServers"]["ic"] = json!({});
        }
        let registration = &mut config["mcpServers"]["ic"];
        if !registration.is_object() {
            return Err(err("IC registration must be an object"));
        }
        registration["command"] = json!(executable);
        registration["args"] = json!(arguments);
        if registration.get("env").is_none() {
            registration["env"] = json!({});
        }
        if !registration["env"].is_object() {
            return Err(err("IC environment must be an object"));
        }
        registration["env"]["IC_HOME"] = json!(ic_home);
        format!("{}\n", serde_json::to_string_pretty(&config)?)
    };
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stage = parent.join(format!(".ic-mcp-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        write_private(&stage, text.as_bytes())?;
        std::fs::rename(&stage, &target)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&stage);
    }
    result?;
    output(json!({"harness":harness,"target":target,"registered":"ic","restartRequired":true}))
}

fn install(args: &[String]) -> Result<()> {
    let h = required(args, "--harness")?;
    let (package, bin) = spec(&h)?;
    let version = required(args, "--version")?;
    if !exact_version(&version) {
        return Err(err("Version must be exact"));
    }
    let d = PathBuf::from(required(args, "--directory")?);
    if !d.is_absolute() {
        return Err(err("Directory must be absolute"));
    }
    std::fs::create_dir(&d)?;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
    let status = Command::new("npm")
        .args(["install", "--prefix"])
        .arg(&d)
        .arg("--cache")
        .arg(d.join(".npm-cache"))
        .args([
            "--no-save",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--registry",
            "https://registry.npmjs.org/",
        ])
        .arg(format!("{package}@{version}"))
        .status()?;
    if !status.success() {
        return Err(err("npm install failed"));
    }
    let package_dir = d.join("node_modules").join(package);
    let metadata: Value =
        serde_json::from_slice(&std::fs::read(package_dir.join("package.json"))?)?;
    if metadata["name"] != package || metadata["version"] != version {
        return Err(err("Installed package identity/version mismatch"));
    }
    let target_bin = metadata["bin"]
        .as_str()
        .or_else(|| metadata["bin"][bin].as_str())
        .ok_or_else(|| err("Installed package binary missing"))?;
    crate::policy::relative_path(target_bin)?;
    let target = package_dir.join(target_bin);
    if (h == "claude-code" || h == "claude") && target_bin == "bin/claude.exe" {
        if version != "2.1.288" {
            return Err(err(
                "Claude native layout only reviewed for version 2.1.288",
            ));
        }
        let os = std::env::consts::OS;
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "x64",
            a => a,
        };
        let os = if os == "macos" { "darwin" } else { os };
        let native_package = format!("@anthropic-ai/claude-code-{os}-{arch}");
        if metadata["optionalDependencies"][&native_package] != version {
            return Err(err("Claude native dependency identity mismatch"));
        }
        let native_dir = d.join("node_modules").join(&native_package);
        let nm: Value = serde_json::from_slice(&std::fs::read(native_dir.join("package.json"))?)?;
        if nm["name"] != native_package || nm["version"] != version {
            return Err(err("Claude native installed identity mismatch"));
        }
        std::fs::copy(native_dir.join("claude"), &target)?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
    }
    let id = executable_identity(&d.join("node_modules/.bin").join(bin))?;
    if id["path"] != json!(std::fs::canonicalize(&target)?) {
        return Err(err("Installed harness binary differs from package entry"));
    }
    verify_harness_version(
        Path::new(id["path"].as_str().unwrap()),
        &version,
        std::time::Duration::from_secs(10),
    )?;
    let v = json!({"schema":1,"harness":h,"package":package,"version":version,"executable":id["path"],"identity":id});
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(d.join("ic-harness.json"))?;
    f.write_all(serde_json::to_string_pretty(&v)?.as_bytes())?;
    f.sync_all()?;
    println!("{v}");
    Ok(())
}
pub fn fixture(directory: &Path, ids: &[String]) -> Result<()> {
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        },
    };
    if ids.is_empty() || ids.iter().any(|v| !crate::policy::valid_id(v)) {
        return Err(err("Invalid fixture identities"));
    }
    std::fs::create_dir_all(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    let ssl = |e: openssl::error::ErrorStack| IcError::new("TLS_ERROR", e.to_string());
    let ca_key = PKey::from_rsa(Rsa::generate(2048).map_err(ssl)?).map_err(ssl)?;
    let mut name = X509NameBuilder::new().map_err(ssl)?;
    name.append_entry_by_text("CN", "IC fixture CA")
        .map_err(ssl)?;
    let name = name.build();
    let mut ca = X509::builder().map_err(ssl)?;
    ca.set_version(2).map_err(ssl)?;
    let serial = BigNum::from_u32(1)
        .map_err(ssl)?
        .to_asn1_integer()
        .map_err(ssl)?;
    ca.set_serial_number(&serial).map_err(ssl)?;
    ca.set_subject_name(&name).map_err(ssl)?;
    ca.set_issuer_name(&name).map_err(ssl)?;
    ca.set_pubkey(&ca_key).map_err(ssl)?;
    let before = Asn1Time::days_from_now(0).map_err(ssl)?;
    let after = Asn1Time::days_from_now(2).map_err(ssl)?;
    ca.set_not_before(&before).map_err(ssl)?;
    ca.set_not_after(&after).map_err(ssl)?;
    ca.append_extension(
        BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .map_err(ssl)?,
    )
    .map_err(ssl)?;
    ca.append_extension(
        KeyUsage::new()
            .key_cert_sign()
            .crl_sign()
            .build()
            .map_err(ssl)?,
    )
    .map_err(ssl)?;
    ca.sign(&ca_key, MessageDigest::sha256()).map_err(ssl)?;
    let ca = ca.build();
    write_private(&directory.join("ca.pem"), &ca.to_pem().map_err(ssl)?)?;
    for id in ids {
        let key = PKey::from_rsa(Rsa::generate(2048).map_err(ssl)?).map_err(ssl)?;
        let mut subject = X509NameBuilder::new().map_err(ssl)?;
        subject.append_entry_by_text("CN", id).map_err(ssl)?;
        let mut cert = X509::builder().map_err(ssl)?;
        cert.set_version(2).map_err(ssl)?;
        let mut sn = BigNum::new().map_err(ssl)?;
        sn.rand(128, MsbOption::MAYBE_ZERO, false).map_err(ssl)?;
        let sn = sn.to_asn1_integer().map_err(ssl)?;
        cert.set_serial_number(&sn).map_err(ssl)?;
        cert.set_subject_name(&subject.build()).map_err(ssl)?;
        cert.set_issuer_name(ca.subject_name()).map_err(ssl)?;
        cert.set_pubkey(&key).map_err(ssl)?;
        cert.set_not_before(&before).map_err(ssl)?;
        cert.set_not_after(&after).map_err(ssl)?;
        cert.append_extension(BasicConstraints::new().critical().build().map_err(ssl)?)
            .map_err(ssl)?;
        cert.append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()
                .map_err(ssl)?,
        )
        .map_err(ssl)?;
        cert.append_extension(
            ExtendedKeyUsage::new()
                .server_auth()
                .client_auth()
                .build()
                .map_err(ssl)?,
        )
        .map_err(ssl)?;
        cert.sign(&ca_key, MessageDigest::sha256()).map_err(ssl)?;
        write_private(
            &directory.join(format!("{id}.pem")),
            &cert.build().to_pem().map_err(ssl)?,
        )?;
        write_private(
            &directory.join(format!("{id}.key")),
            &key.private_key_to_pem_pkcs8().map_err(ssl)?,
        )?;
    }
    Ok(())
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn serve(args: &[String]) -> Result<()> {
    let log_format = crate::logging::LogFormat::parse(
        &option(args, "--log-format").unwrap_or_else(|| "text".into()),
    )
    .map_err(|message| err(&message))?;
    install_signals();
    let c = crate::settings::load_selected()?;
    let node = crate::node::Node::new(c)?;
    node.set_log_format(log_format);
    node.start()?;
    let owner = match crate::owner::start(node.clone()) {
        Ok(owner) => owner,
        Err(error) => {
            let _ = node.shutdown();
            return Err(error);
        }
    };
    let operator = if args.iter().any(|s| s == "--operator")
        || node.config().raw["operator"]["enabled"] == true
    {
        let handle = match crate::operator::start(node.clone()) {
            Ok(handle) => handle,
            Err(error) => {
                owner.stop();
                let _ = node.shutdown();
                return Err(error);
            }
        };
        let info = handle.info();
        node.log("operator_ready",json!({"url":info["url"],"ownerFile":info["ownerFile"],"socketPath":info["socketPath"]}));
        Some(handle)
    } else {
        None
    };
    let result = wait_service(&node);
    owner.stop();
    let operator_result = if let Some(mut o) = operator {
        o.shutdown()
    } else {
        Ok(())
    };
    let shutdown_result = node.shutdown();
    drop(owner);
    operator_result?;
    shutdown_result?;
    result
}
fn wait_service(node: &crate::node::Node) -> Result<()> {
    while SIGNAL.load(std::sync::atomic::Ordering::Acquire) == 0 && !node.is_stopping() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Ok(())
}
type ToolField = (&'static str, &'static str, bool);
type RemoteToolDefinition = (&'static str, &'static str, &'static [ToolField]);
pub(crate) const DEFINITIONS: &[RemoteToolDefinition] = &[
    ("ic_capabilities", "capabilities", &[]),
    ("ic_read", "readFile", &[("path", "string", true)]),
    (
        "ic_write",
        "writeFile",
        &[
            ("path", "string", true),
            ("text", "string", true),
            ("overwrite", "boolean", false),
        ],
    ),
    (
        "ic_edit",
        "editFile",
        &[
            ("path", "string", true),
            ("oldText", "string", true),
            ("newText", "string", true),
        ],
    ),
    (
        "ic_exec",
        "exec",
        &[
            ("command", "string", true),
            ("args", "array", true),
            ("background", "boolean", false),
            ("durationMs", "integer", false),
        ],
    ),
    ("ic_echo", "echo", &[("text", "string", true)]),
    ("ic_wait", "wait", &[("ms", "integer", true)]),
    (
        "ic_list",
        "listDirectory",
        &[
            ("path", "string", false),
            ("offset", "integer", false),
            ("limit", "integer", false),
        ],
    ),
    (
        "ic_search",
        "searchFiles",
        &[
            ("path", "string", false),
            ("query", "string", true),
            ("maxResults", "integer", false),
        ],
    ),
    ("ic_mkdir", "mkdir", &[("path", "string", true)]),
    ("ic_mcp_list", "mcpList", &[("server", "string", true)]),
    (
        "ic_mcp_call",
        "mcpCall",
        &[
            ("server", "string", true),
            ("tool", "string", true),
            ("arguments", "object", true),
        ],
    ),
];
pub fn remote_tools(local_sync: bool) -> Vec<Value> {
    let file = [
        "readFile",
        "writeFile",
        "editFile",
        "listDirectory",
        "searchFiles",
        "readChunk",
        "writeChunk",
        "mkdir",
    ];
    let mut result = vec![
        json!({"name":"ic_peer","description":"Select an approved servant as the persistent default peer for this session","inputSchema":{"type":"object","properties":{"peerId":{"type":"string","minLength":1,"maxLength":64}},"required":["peerId"],"additionalProperties":false}}),
        json!({"name":"ic_peers","description":"List currently paired servants and their connection addresses","inputSchema":{"type":"object","properties":{},"required":[],"additionalProperties":false}}),
    ];
    result.push(json!({"name":"ic_process","description":"Inspect status, read output, or cancel an approved servant process","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["status","output","cancel"]},"jobId":{"type":"string","minLength":1,"maxLength":32768},"peerId":{"type":"string","minLength":1,"maxLength":64},"timeoutMs":{"type":"integer","minimum":10,"maximum":86400000},"offset":{"type":"integer","minimum":0},"limit":{"type":"integer","minimum":1},"stream":{"type":"string","enum":["combined","stdout","stderr"]}},"required":["action","jobId"],"additionalProperties":false}}));
    for (name, tool, fields) in DEFINITIONS {
        if local_sync && file.contains(tool) {
            continue;
        }
        let mut properties = serde_json::Map::new();
        properties.insert(
            "peerId".into(),
            json!({"type":"string","minLength":1,"maxLength":64,"description":"Override the session default approved servant"}),
        );
        properties.insert(
            "timeoutMs".into(),
            json!({"type":"integer","minimum":10,"maximum":86400000}),
        );
        let mut required = Vec::new();
        for (n, t, r) in *fields {
            let mut v = json!({"type":t});
            if *t == "array" {
                v["items"] = json!({"type":"string"});
                v["maxItems"] = json!(32);
            }
            if *t == "string" {
                v["maxLength"] = json!(32768);
            }
            if *r {
                required.push(n)
            }
            properties.insert(n.to_string(), v);
        }
        result.push(json!({"name":name,"description":format!("Approved servant {tool}; no arbitrary executable or host path"),"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}}));
    }
    if local_sync {
        result.push(json!({"name":"ic_sync","description":"Strict mirror saved local scope; delete remote-only entries; execute no command","inputSchema":{"type":"object","properties":{"peerId":{"type":"string"},"timeoutMs":{"type":"integer","minimum":10,"maximum":86400000}},"required":[],"additionalProperties":false}}));
        result.push(json!({"name":"ic_workspace","description":"Select paths inside owner-registered local workspace","inputSchema":{"type":"object","properties":{"peerId":{"type":"string"},"scope":{"type":"object","properties":{"paths":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"string"}}},"required":["paths"],"additionalProperties":false}},"required":["scope"],"additionalProperties":false}}));
    }
    result
}
pub fn mock_response(
    kind: &str,
    calls: &Value,
    body: &Value,
    turn: usize,
) -> Result<(&'static str, String)> {
    let list = calls
        .as_array()
        .ok_or_else(|| err("Script must be array"))?;
    if list.len() > 20 || body["model"] != "intelligent-cells-mock" {
        return Err(err("Only bounded intelligent-cells-mock script allowed"));
    }
    let call = list.get(turn);
    let observations = match kind {
        "pi" => body["messages"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|m| m["role"] == "tool")
                    .map(|m| m["content"].clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        "claude" => body["messages"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|m| m["role"] == "user")
                    .filter_map(|m| m["content"].as_array())
                    .flatten()
                    .filter(|b| b["type"] == "tool_result")
                    .map(|b| b["content"].clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        _ => body["input"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|i| i["type"] == "function_call_output")
                    .map(|i| i["output"].clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    };
    let text = format!(
        "Mock completed after {} observed tool result(s).\n{}",
        turn,
        json!(observations)
    );
    let emit = |v: Value| format!("event: {}\ndata: {v}\n\n", v["type"].as_str().unwrap());
    match kind {
        "pi" => {
            let mut s = String::new();
            let chunk = |delta: Value, finish: Value| json!({"id":"ic-mock","object":"chat.completion.chunk","created":0,"model":"intelligent-cells-mock","choices":[{"index":0,"delta":delta,"finish_reason":finish}]});
            s.push_str(&format!(
                "data: {}\n\n",
                chunk(json!({"role":"assistant"}), Value::Null)
            ));
            let (delta, finish) = if let Some(c) = call {
                (
                    json!({"tool_calls":[{"index":0,"id":format!("mock-call-{}",turn+1),"type":"function","function":{"name":c["name"],"arguments":c["arguments"].to_string()}}]}),
                    json!("tool_calls"),
                )
            } else {
                (json!({"content":text}), json!("stop"))
            };
            s.push_str(&format!(
                "data: {}\n\ndata: {}\n\ndata: [DONE]\n\n",
                chunk(delta, Value::Null),
                chunk(json!({}), finish)
            ));
            Ok(("text/event-stream", s))
        }
        "claude" => {
            let (block, stop) = if let Some(c) = call {
                (
                    json!({"type":"tool_use","id":format!("claude-mock-call-{}",turn+1),"name":c["name"],"input":c["arguments"]}),
                    "tool_use",
                )
            } else {
                (json!({"type":"text","text":text}), "end_turn")
            };
            let message = json!({"id":format!("msg_ic_mock_{turn}"),"type":"message","role":"assistant","model":"intelligent-cells-mock","content":[block],"stop_reason":stop,"stop_sequence":null,"usage":{"input_tokens":100,"output_tokens":50}});
            if body["stream"] != true {
                return Ok(("application/json", message.to_string()));
            }
            let mut initial = message.clone();
            initial["content"] = json!([]);
            initial["stop_reason"] = Value::Null;
            initial["usage"]["output_tokens"] = json!(0);
            let mut start = block.clone();
            let delta = if call.is_some() {
                start["input"] = json!({});
                json!({"type":"input_json_delta","partial_json":block["input"].to_string()})
            } else {
                start["text"] = json!("");
                json!({"type":"text_delta","text":block["text"]})
            };
            Ok(("text/event-stream",[emit(json!({"type":"message_start","message":initial})),emit(json!({"type":"content_block_start","index":0,"content_block":start})),emit(json!({"type":"content_block_delta","index":0,"delta":delta})),emit(json!({"type":"content_block_stop","index":0})),emit(json!({"type":"message_delta","delta":{"stop_reason":stop,"stop_sequence":null},"usage":{"output_tokens":50}})),emit(json!({"type":"message_stop"}))].concat()))
        }
        "codex" => {
            let rid = format!("resp_ic_mock_{turn}");
            let mut events = vec![emit(
                json!({"type":"response.created","response":{"id":rid,"object":"response","status":"in_progress","output":[]}}),
            )];
            let item = if let Some(c) = call {
                let name = c["name"]
                    .as_str()
                    .ok_or_else(|| err("Call name required"))?;
                let namespace = body["tools"]
                    .as_array()
                    .and_then(|t| {
                        t.iter().find(|d| {
                            d["type"] == "namespace"
                                && d["tools"]
                                    .as_array()
                                    .map(|x| x.iter().any(|f| f["name"] == name))
                                    .unwrap_or(false)
                        })
                    })
                    .map(|n| n["name"].clone());
                let mut i = json!({"id":format!("fc_ic_mock_{turn}"),"type":"function_call","call_id":format!("call_ic_mock_{turn}"),"name":name,"arguments":c["arguments"].to_string(),"status":"completed"});
                if let Some(ns) = namespace {
                    i["namespace"] = ns
                }
                let mut start = i.clone();
                start["arguments"] = json!("");
                start["status"] = json!("in_progress");
                events.push(emit(
                    json!({"type":"response.output_item.added","output_index":0,"item":start}),
                ));
                events.push(emit(json!({"type":"response.function_call_arguments.delta","item_id":i["id"],"output_index":0,"delta":i["arguments"]})));
                events.push(emit(json!({"type":"response.function_call_arguments.done","item_id":i["id"],"output_index":0,"arguments":i["arguments"]})));
                i
            } else {
                let i = json!({"id":format!("msg_ic_mock_{turn}"),"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":text,"annotations":[]}]});
                let mut start = i.clone();
                start["content"] = json!([]);
                events.push(emit(
                    json!({"type":"response.output_item.added","output_index":0,"item":start}),
                ));
                events.push(emit(json!({"type":"response.content_part.added","item_id":i["id"],"output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}})));
                events.push(emit(json!({"type":"response.output_text.delta","item_id":i["id"],"output_index":0,"content_index":0,"delta":text})));
                events.push(emit(json!({"type":"response.output_text.done","item_id":i["id"],"output_index":0,"content_index":0,"text":text})));
                events.push(emit(json!({"type":"response.content_part.done","item_id":i["id"],"output_index":0,"content_index":0,"part":i["content"][0]})));
                i
            };
            events.push(emit(
                json!({"type":"response.output_item.done","output_index":0,"item":item}),
            ));
            events.push(emit(json!({"type":"response.completed","response":{"id":rid,"object":"response","status":"completed","output":[item],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}})));
            Ok(("text/event-stream", events.concat()))
        }
        _ => Err(err("Unknown mock kind")),
    }
}
fn mock_server(args: &[String]) -> Result<()> {
    use std::{io::Read, net::TcpListener};
    let kind = required(args, "--kind")?;
    if !["pi", "claude", "codex"].contains(&kind.as_str()) {
        return Err(err("Unknown mock kind"));
    }
    let calls: Value = serde_json::from_slice(&std::fs::read(required(args, "--script")?)?)?;
    let port = option(args, "--port")
        .unwrap_or("0".into())
        .parse::<u16>()
        .map_err(|_| err("Invalid port"))?;
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    println!(
        "{}",
        json!({"event":"mock_ready","port":listener.local_addr()?.port(),"url":format!("http://127.0.0.1:{}",listener.local_addr()?.port()),"mockedModel":true})
    );
    let mut turn = 0;
    for stream in listener.incoming() {
        let mut stream = stream?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut reader = std::io::BufReader::new(stream.try_clone()?);
        let mut first = String::new();
        reader.read_line(&mut first)?;
        let mut len = 0;
        let mut authorization = false;
        loop {
            let mut l = String::new();
            reader.read_line(&mut l)?;
            if l == "\r\n" || l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    len = v.trim().parse::<usize>().unwrap_or(usize::MAX)
                }
                if k.eq_ignore_ascii_case("authorization") && !v.trim().ends_with("mock") {
                    authorization = true
                }
            }
        }
        let route = match kind.as_str() {
            "pi" => "/v1/chat/completions",
            "claude" => "/v1/messages",
            _ => "/v1/responses",
        };
        let valid = first.starts_with(&format!("POST {route}"))
            && len <= 512 * 1024
            && turn < 32
            && !authorization;
        let response = if valid {
            let mut b = vec![0; len];
            reader.read_exact(&mut b)?;
            serde_json::from_slice(&b)
                .map_err(IcError::from)
                .and_then(|body:Value| {
                    let step=match kind.as_str() {"pi"=>body["messages"].as_array().map(|a|a.iter().filter(|m|m["role"]=="tool").count()).unwrap_or(0),"claude"=>body["messages"].as_array().map(|a|a.iter().filter(|m|m["role"]=="user").filter_map(|m|m["content"].as_array()).flatten().filter(|b|b["type"]=="tool_result").count()).unwrap_or(0),_=>turn};
                    eprintln!("{}",json!({"event":"mock_request","kind":kind,"request":turn+1,"step":step,"mockedModel":true}));
                    mock_response(&kind,&calls,&body,step)
                })
        } else {
            Err(err("Mock request rejected"))
        };
        let (status, ctype, body) = match response {
            Ok((t, b)) => {
                turn += 1;
                ("200 OK", t, b)
            }
            Err(e) => (
                "400 Bad Request",
                "application/json",
                json!({"error":{"message":e.to_string()}}).to_string(),
            ),
        };
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        stream.flush()?;
    }
    Ok(())
}
pub fn validate_arguments(schema: &Value, value: &Value) -> Result<()> {
    if schema["enum"]
        .as_array()
        .is_some_and(|choices| !choices.contains(value))
    {
        return Err(err("Argument is not an allowed enum value"));
    }
    match schema["type"].as_str() {
        Some("object") => {
            let obj = value
                .as_object()
                .ok_or_else(|| err("Arguments must be object"))?;
            if let Some(required) = schema["required"].as_array() {
                for k in required {
                    if !obj.contains_key(k.as_str().unwrap()) {
                        return Err(err("Required argument missing"));
                    }
                }
            }
            for (k, v) in obj {
                let s = &schema["properties"][k];
                if s.is_null() {
                    if schema["additionalProperties"] == false {
                        return Err(err("Unknown argument"));
                    }
                } else {
                    validate_arguments(s, v)?
                }
            }
        }
        Some("array") => {
            let a = value.as_array().ok_or_else(|| err("Expected array"))?;
            if schema["maxItems"]
                .as_u64()
                .is_some_and(|n| a.len() > n as usize)
                || schema["minItems"]
                    .as_u64()
                    .is_some_and(|n| a.len() < n as usize)
            {
                return Err(err("Array length out of bounds"));
            }
            for v in a {
                validate_arguments(&schema["items"], v)?
            }
        }
        Some("string") => {
            let s = value.as_str().ok_or_else(|| err("Expected string"))?;
            if schema["maxLength"]
                .as_u64()
                .is_some_and(|n| s.len() > n as usize)
                || schema["minLength"]
                    .as_u64()
                    .is_some_and(|n| s.len() < n as usize)
            {
                return Err(err("String length out of bounds"));
            }
        }
        Some("boolean") => {
            if !value.is_boolean() {
                return Err(err("Expected boolean"));
            }
        }
        Some("integer") => {
            let n = value.as_i64().ok_or_else(|| err("Expected integer"))?;
            if schema["minimum"].as_i64().is_some_and(|v| n < v)
                || schema["maximum"].as_i64().is_some_and(|v| n > v)
            {
                return Err(err("Integer out of bounds"));
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn exact_version(v: &str) -> bool {
    let (core, pre) = v
        .split_once('-')
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((v, None));
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars().all(|c| c.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
        && pre.is_none_or(|p| {
            !p.is_empty()
                && p.split('.').all(|x| {
                    !x.is_empty() && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
        })
}

fn validate_flags(args: &[String], values: &[&str], flags: &[&str], trailing: bool) -> Result<()> {
    let mut i = 0;
    let mut seen = std::collections::BTreeSet::new();
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" && trailing {
            return Ok(());
        }
        if !seen.insert(a) {
            return Err(err(&format!("Duplicate option: {a}")));
        }
        if flags.contains(&a) {
            i += 1;
            continue;
        }
        if !values.contains(&a) {
            return Err(err(&format!("Unknown option: {a}")));
        }
        i += 1;
        if i >= args.len() || args[i].starts_with("--") {
            return Err(err(&format!("Missing value: {a}")));
        }
        i += 1;
    }
    Ok(())
}

static SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
extern "C" fn handle_signal(value: libc::c_int) {
    SIGNAL.store(value, std::sync::atomic::Ordering::Release);
}
fn install_signals() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        );
    }
}
fn input_frames() -> std::sync::mpsc::Receiver<Result<Option<Value>>> {
    let (tx, rx) = std::sync::mpsc::sync_channel(8);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        loop {
            let result = crate::wire::read_frame(&mut input);
            let ended = matches!(result, Ok(None));
            if tx.send(result).is_err() || ended {
                break;
            }
        }
    });
    rx
}

pub fn verify_harness_version(
    path: &Path,
    version: &str,
    timeout: std::time::Duration,
) -> Result<()> {
    use std::{io::Read, os::unix::process::CommandExt};
    let mut child = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;
    let group = child.id() as i32;
    let (tx, rx) = std::sync::mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let a = tx.clone();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let r = stdout
            .take(16385)
            .read_to_end(&mut bytes)
            .map(|_| (true, bytes));
        let _ = a.send(r);
    });
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let r = stderr
            .take(16385)
            .read_to_end(&mut bytes)
            .map(|_| (false, bytes));
        let _ = tx.send(r);
    });
    let deadline = std::time::Instant::now() + timeout;
    let mut outputs = Vec::new();
    let mut status = None;
    let outcome = (|| -> Result<()> {
        loop {
            while let Ok(result) = rx.try_recv() {
                let output = result?;
                if output.1.len() > 16384 {
                    return Err(err("Harness version output exceeds budget"));
                }
                outputs.push(output);
            }
            if status.is_none() {
                status = child.try_wait()?;
                if status.is_some() {
                    unsafe {
                        libc::kill(-group, libc::SIGTERM);
                    }
                }
            }
            if status.is_some() && outputs.len() == 2 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(err("Harness version verification timed out"));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let stdout = &outputs.iter().find(|(is_out, _)| *is_out).unwrap().1;
        if !status.unwrap().success()
            || !String::from_utf8_lossy(stdout)
                .split_whitespace()
                .any(|s| s == version)
        {
            return Err(err("Installed version verification failed"));
        }
        Ok(())
    })();
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    outcome
}
