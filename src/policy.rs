use crate::{
    error::{IcError, Result},
    model::{Config, Grant},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn fail(code: &str, message: &str) -> IcError {
    IcError::new(code, message)
}
fn invalid(message: &str) -> IcError {
    fail("INVALID_CONFIG", message)
}
pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
pub fn paths_overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
pub fn relative_path(value: &str) -> Result<()> {
    let bad = value.is_empty()
        || value.len() > 500
        || value.starts_with('/')
        || value
            .chars()
            .any(|c| c == '\\' || c == ':' || c.is_control())
        || value.split('/').any(|part| {
            let stem = part.split('.').next().unwrap_or("").to_ascii_lowercase();
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with('.')
                || part.ends_with(' ')
                || ["con", "prn", "aux", "nul"].contains(&stem.as_str())
                || (stem.len() == 4
                    && (stem.starts_with("com") || stem.starts_with("lpt"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        });
    if bad {
        Err(fail(
            "PATH_DENIED",
            "Only a canonical relative workspace path is allowed",
        ))
    } else {
        Ok(())
    }
}
fn object<'a>(value: &'a Value, label: &str) -> Result<&'a serde_json::Map<String, Value>> {
    value.as_object().ok_or_else(|| invalid(label))
}
fn bounded(value: &Value, name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let number = match value.get(name) {
        None => default,
        Some(v) => v.as_u64().ok_or_else(|| invalid(name))?,
    };
    if number < min || number > max {
        return Err(invalid(name));
    }
    Ok(number)
}
fn absolute(base: &Path, value: &str) -> Result<PathBuf> {
    if value.is_empty() || value.contains('\0') {
        return Err(invalid("Path must be nonempty"));
    }
    let path = Path::new(value);
    let resolved = if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    };
    // Existing parents must be canonical; nonexistent suffixes are normalized lexically.
    let mut normalized = PathBuf::new();
    for part in resolved.components() {
        use std::path::Component;
        match part {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}
fn directory(base: &Path, value: &str, private: bool) -> Result<PathBuf> {
    let path = absolute(base, value)?;
    let canonical = fs::canonicalize(&path)?;
    let meta = fs::symlink_metadata(&path)?;
    if canonical != path
        || !meta.is_dir()
        || meta.file_type().is_symlink()
        || (private && (meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0))
    {
        return Err(invalid(
            "Workspace must be a canonical owner-controlled directory",
        ));
    }
    Ok(path)
}
pub fn check_directory(grant: &Grant, path: &str, write: bool, is_directory: bool) -> Result<()> {
    if !(is_directory && path.is_empty()) {
        relative_path(path)?;
    }
    let Some(rules) = grant.raw.get("directories") else {
        return Ok(());
    };
    let target = if is_directory {
        path
    } else {
        path.rsplit_once('/').map(|x| x.0).unwrap_or("")
    };
    let selected = rules
        .as_array()
        .into_iter()
        .flatten()
        .filter(|rule| {
            rule["path"].as_str().is_some_and(|p| {
                p.is_empty()
                    || p == target
                    || target.strip_prefix(p).is_some_and(|s| s.starts_with('/'))
            })
        })
        .max_by_key(|rule| rule["path"].as_str().unwrap_or("").len());
    if selected.is_some_and(|rule| rule[if write { "write" } else { "read" }] == true) {
        Ok(())
    } else {
        Err(fail(
            "DIRECTORY_DENIED",
            "Directory access was not granted by the servant owner",
        ))
    }
}
fn code_snapshot(path: &Path, code: &str) -> Result<Value> {
    let inspect = || -> Result<Value> {
        let stat = fs::symlink_metadata(path)?;
        if !path.is_absolute()
            || !stat.is_file()
            || stat.nlink() != 1
            || fs::canonicalize(path)? != path
        {
            return Err(fail(
                code,
                "Approved code must be canonical, regular and non-linked",
            ));
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let opened = file.metadata()?;
        if opened.dev() != stat.dev() || opened.ino() != stat.ino() || opened.nlink() != 1 {
            return Err(fail(code, "Approved code changed while opening"));
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        let hash = hex::encode(hash.finalize());
        let after = fs::symlink_metadata(path)?;
        if stat.dev() != after.dev()
            || stat.ino() != after.ino()
            || stat.nlink() != after.nlink()
            || stat.size() != after.size()
            || stat.mtime() != after.mtime()
            || stat.mtime_nsec() != after.mtime_nsec()
            || stat.ctime() != after.ctime()
            || stat.ctime_nsec() != after.ctime_nsec()
        {
            return Err(fail(code, "Approved code changed during inspection"));
        }
        Ok(
            json!({"filename":path,"dev":stat.dev().to_string(),"ino":stat.ino().to_string(),"size":stat.size().to_string(),"mtimeNs":format!("{}{:09}",stat.mtime(),stat.mtime_nsec()),"ctimeNs":format!("{}{:09}",stat.ctime(),stat.ctime_nsec()),"sha256":hash}),
        )
    };
    inspect().map_err(|error| fail(code, &error.message))
}
fn node_binary(name: &str) -> bool {
    let name = name.strip_suffix(".exe").unwrap_or(name);
    ["node", "nodejs"].iter().any(|prefix| {
        name == *prefix
            || name
                .strip_prefix(*prefix)
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    })
}
pub fn compile_approved_code(raw: &Value, code: &str) -> Result<Value> {
    let file = raw["file"]
        .as_str()
        .ok_or_else(|| fail(code, "Explicit absolute executable is required"))?;
    let path = Path::new(file);
    if !path.is_absolute() || file.contains('\0') {
        return Err(fail(code, "Executable must be absolute"));
    }
    let args = raw.get("args").cloned().unwrap_or(json!([]));
    let argv = args
        .as_array()
        .ok_or_else(|| invalid("args must be an array"))?;
    if argv.len() > 32
        || argv.iter().any(|v| {
            v.as_str()
                .is_none_or(|s| s.contains('\0') || s.len() > 4096)
        })
    {
        return Err(invalid("Fixed arguments exceed bounds"));
    }
    let mode = raw
        .get("launchMode")
        .and_then(Value::as_str)
        .unwrap_or("node-script");
    let mut files = vec![file.to_owned()];
    let basename = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let basename = basename.strip_suffix(".exe").unwrap_or(&basename);
    if mode == "native" {
        let blocked = [
            "python",
            "ruby",
            "perl",
            "php",
            "bash",
            "sh",
            "dash",
            "zsh",
            "ksh",
            "csh",
            "pwsh",
            "powershell",
            "cmd",
            "env",
            "npm",
            "npx",
            "bun",
            "deno",
            "java",
        ];
        if raw["argsAllowed"] == true
            || raw["stdinAllowed"] == true
            || node_binary(basename)
            || blocked.iter().any(|name| {
                basename == *name || (*name == "python" && basename.starts_with("python"))
            })
        {
            return Err(fail(
                code,
                "Native mode needs a reviewed binary, fixed argv and no caller stdin",
            ));
        }
        let bytes = fs::read(path).map_err(|e| fail(code, &e.to_string()))?;
        let header = bytes
            .get(..4)
            .ok_or_else(|| fail(code, "Native executable image required"))?;
        if header != b"\x7fELF"
            && !header.starts_with(b"MZ")
            && ![
                "feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf",
                "bfbafeca",
            ]
            .contains(&hex::encode(header).as_str())
        {
            return Err(fail(code, "Native executable image required"));
        }
    } else if mode == "node-script" {
        let script = argv
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| fail(code, "Node adapter requires an explicit absolute script"))?;
        if !node_binary(basename) || !Path::new(script).is_absolute() {
            return Err(fail(
                code,
                "Unsupported interpreter flags or dynamic entrypoint",
            ));
        }
        if script != file {
            files.push(script.to_owned());
        }
    } else {
        return Err(fail(code, "Unsupported launchMode"));
    }
    let snapshots = files
        .iter()
        .map(|file| code_snapshot(Path::new(file), code))
        .collect::<Result<Vec<_>>>()?;
    let mut out = raw.clone();
    out["file"] = json!(file);
    out["args"] = args;
    out["launchMode"] = json!(mode);
    out["codeFiles"] = json!(files);
    out["codeSnapshots"] = json!(snapshots);
    Ok(out)
}
pub fn verify_approved_code(command: &Value, code: &str) -> Result<()> {
    let snapshots = command["codeSnapshots"]
        .as_array()
        .ok_or_else(|| fail(code, "Missing owner-approved code snapshot"))?;
    for approved in snapshots {
        let filename = approved["filename"]
            .as_str()
            .ok_or_else(|| fail(code, "Malformed approved code snapshot"))?;
        if code_snapshot(Path::new(filename), code)? != *approved {
            return Err(fail(
                code,
                "Approved code changed; reload owner-reviewed policy",
            ));
        }
    }
    Ok(())
}
fn normalize_grant(raw: &Value, base: &Path, max_concurrent: u64, nested: bool) -> Result<Value> {
    object(raw, "Grant must be an object")?;
    let mut g = raw.clone();
    let tools = raw.get("tools").cloned().unwrap_or(json!([]));
    let tools = tools
        .as_array()
        .ok_or_else(|| invalid("tools must be an array"))?;
    const NAMES: &[&str] = &[
        "echo",
        "wait",
        "capabilities",
        "readFile",
        "writeFile",
        "editFile",
        "exec",
        "listDirectory",
        "searchFiles",
        "mkdir",
        "readChunk",
        "writeChunk",
        "jobStatus",
        "jobOutput",
        "jobCancel",
        "jobStdin",
        "resourceList",
        "resourceRead",
        "mcpList",
        "mcpCall",
        "workspaceList",
        "workspaceCreate",
        "syncInventory",
        "syncUpload",
        "syncTransfer",
        "syncApply",
        "syncExec",
    ];
    if tools
        .iter()
        .any(|t| !NAMES.contains(&t.as_str().unwrap_or("")))
    {
        return Err(invalid("Unknown tool grant"));
    }
    let has = |tool: &str| tools.iter().any(|t| t == tool);
    if nested
        && (raw.get("workspaces").is_some()
            || raw.get("workspaceProvisioning").is_some()
            || has("workspaceCreate")
            || has("workspaceList"))
    {
        return Err(invalid("Nested grants cannot provision workspaces"));
    }
    g["tools"] = json!(tools);
    let root = raw
        .get("workspace")
        .map(|v| directory(base, v.as_str().unwrap_or(""), false))
        .transpose()?;
    if root.is_none()
        && tools.iter().any(|t| {
            ![
                "echo",
                "wait",
                "capabilities",
                "workspaceList",
                "workspaceCreate",
                "jobStatus",
                "jobOutput",
                "jobCancel",
                "jobStdin",
            ]
            .contains(&t.as_str().unwrap_or(""))
        })
    {
        return Err(invalid(
            "Filesystem and process grants require an explicit workspace",
        ));
    }
    if has("syncExec") && !has("exec") {
        return Err(invalid("syncExec requires exec grant"));
    }
    if let Some(root) = &root {
        g["workspace"] = json!(root);
        g["root"] = json!(root);
        let stat = fs::metadata(root)?;
        g["workspaceIdentity"] = json!({"dev":stat.dev().to_string(),"ino":stat.ino().to_string()});
    }
    for (name, default, min, max) in [
        ("maxConcurrent", 1, 1, max_concurrent),
        ("maxTimeoutMs", 2000, 10, 86400000),
        ("maxWaitMs", 5000, 0, 86400000),
        ("maxReadBytes", 16384, 1, 65536),
        ("maxWriteBytes", 16384, 1, 65536),
        ("maxOutputBytes", 16384, 1, 16777216),
        ("maxJobTimeoutMs", 3600000, 10, 86400000),
        ("maxJobs", 32, 1, 256),
        ("maxOutputPageBytes", 16384, 1, 16384),
        ("maxSearchFiles", 1000, 1, 100000),
        ("maxSearchBytes", 1048576, 1, 67108864),
        ("maxDirectoryEntries", 1000, 1, 10000),
        ("maxTransferBytes", 67108864, 1, 268435456),
        ("maxTasksPerMinute", 120, 1, 10000),
        ("maxResourceBytes", 16384, 1, 65536),
        ("maxResourceTotalBytes", 65536, 1, 131072),
        ("maxMcpBytes", 32768, 256, 65536),
    ] {
        g[name] = json!(bounded(raw, name, default, min, max)?);
    }
    if raw
        .get("allowUnsandboxedProcesses")
        .is_some_and(|v| !v.is_boolean())
    {
        return Err(invalid("allowUnsandboxedProcesses must be boolean"));
    }
    if let Some(rules) = raw.get("directories") {
        let rules = rules
            .as_array()
            .ok_or_else(|| invalid("directories must be array"))?;
        if root.is_none() || rules.len() > 128 {
            return Err(invalid("Directory policy requires root and bounded rules"));
        }
        if ["exec", "syncExec", "syncTransfer", "mcpList", "mcpCall"]
            .iter()
            .any(|t| has(t))
            && raw["allowUnsandboxedProcesses"] != true
        {
            return Err(invalid(
                "Directory ACL does not sandbox processes; acknowledgement required",
            ));
        }
        let mut seen = BTreeSet::new();
        for rule in rules {
            let obj = object(rule, "Malformed directory rule")?;
            let path = rule["path"]
                .as_str()
                .ok_or_else(|| invalid("Directory path required"))?;
            if obj
                .keys()
                .any(|k| !["path", "read", "write"].contains(&k.as_str()))
                || !rule["read"].is_boolean()
                || !rule["write"].is_boolean()
                || !seen.insert(path)
            {
                return Err(invalid("Malformed or duplicate directory rule"));
            }
            if !path.is_empty() {
                relative_path(path).map_err(|_| invalid("Invalid directory path"))?;
            }
            let mut current = root.clone().unwrap();
            for part in path.split('/').filter(|p| !p.is_empty()) {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        if !meta.is_dir()
                            || meta.file_type().is_symlink()
                            || fs::canonicalize(&current)? != current
                        {
                            return Err(invalid("Directory rules cannot target aliases or files"));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    let commands = raw.get("execCommands").cloned().unwrap_or(json!({}));
    let commands = object(&commands, "execCommands must be object")?;
    let mut compiled = serde_json::Map::new();
    for (alias, cmd) in commands {
        if !valid_id(alias) {
            return Err(invalid("Invalid command alias"));
        }
        object(cmd, "Invalid command")?;
        let mut cmd = compile_approved_code(cmd, "UNSAFE_EXEC_POLICY")?;
        for (name, default, min, max) in [("maxArgs", 8, 0, 32), ("maxStdinBytes", 16384, 0, 65536)]
        {
            cmd[name] = json!(bounded(&cmd, name, default, min, max)?);
        }
        let env = cmd.get("env").cloned().unwrap_or(json!({}));
        for (key, value) in object(&env, "env must be object")? {
            if key.is_empty()
                || !key.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_uppercase() || (i > 0 && b.is_ascii_digit())
                })
                || value.as_str().is_none_or(|v| v.contains('\0'))
                || [
                    "NODE_OPTIONS",
                    "LD_PRELOAD",
                    "LD_LIBRARY_PATH",
                    "DYLD_INSERT_LIBRARIES",
                ]
                .contains(&key.as_str())
            {
                return Err(invalid("Unsafe command environment"));
            }
        }
        cmd["env"] = env;
        for key in ["argsAllowed", "stdinAllowed"] {
            if cmd.get(key).is_some_and(|v| !v.is_boolean()) {
                return Err(invalid("Command permission must be boolean"));
            }
            if cmd.get(key).is_none() {
                cmd[key] = json!(false);
            }
        }
        if let Some(args) = cmd.get("allowedArgs")
            && args.as_array().is_none_or(|a| {
                a.len() > 128
                    || a.iter().any(|v| {
                        v.as_str()
                            .is_none_or(|s| s.len() > 4096 || s.contains('\0'))
                    })
            })
        {
            return Err(invalid("Invalid argument allowlist"));
        }
        compiled.insert(alias.clone(), cmd);
    }
    g["execCommands"] = Value::Object(compiled);
    if let Some(root) = &root {
        let resources = crate::resources::compile_policy(raw, base, root)?;
        for (key, value) in object(&resources, "Invalid compiled resources")? {
            g[key] = value.clone();
        }
    } else {
        for key in ["resources", "mcpServers"] {
            if let Some(aliases) = raw.get(key)
                && !object(aliases, "Resource/server aliases must be object")?.is_empty()
            {
                return Err(invalid(
                    "Resource and MCP approvals require explicit workspace",
                ));
            }
        }
    }
    let named = raw.get("workspaces").cloned().unwrap_or(json!({}));
    let named = object(&named, "workspaces must be object")?;
    if named.len() > 32 {
        return Err(invalid("Too many named workspaces"));
    }
    let mut children = serde_json::Map::new();
    for (id, item) in named {
        if !valid_id(id)
            || id == "default"
            || id.starts_with("ws_")
            || !item["tools"].is_array()
            || !item["workspace"].is_string()
        {
            return Err(invalid(
                "Named workspace needs stable ID, root and explicit tools",
            ));
        }
        children.insert(
            id.clone(),
            normalize_grant(item, base, max_concurrent, true)?,
        );
    }
    g["workspaces"] = Value::Object(children);
    if let Some(provision) = raw.get("workspaceProvisioning") {
        let obj = object(provision, "Invalid provisioning")?;
        if obj.keys().any(|k| k != "roots") {
            return Err(invalid("Invalid provisioning keys"));
        }
        let roots = object(&provision["roots"], "Provisioning roots required")?;
        if roots.len() > 16 {
            return Err(invalid("Too many provisioning roots"));
        }
        let mut output = serde_json::Map::new();
        for (id, item) in roots {
            let obj = object(item, "Invalid provisioning root")?;
            if !valid_id(id)
                || obj
                    .keys()
                    .any(|k| !["path", "maxWorkspaces", "grant"].contains(&k.as_str()))
                || !item["grant"]["tools"].is_array()
                || !item["grant"]["directories"].is_array()
                || ["workspace", "workspaces", "workspaceProvisioning"]
                    .iter()
                    .any(|k| item["grant"].get(k).is_some())
            {
                return Err(invalid("Explicit provisioning template required"));
            }
            let path = directory(base, item["path"].as_str().unwrap_or(""), true)?;
            let stat = fs::metadata(&path)?;
            let mut template = item["grant"].clone();
            template["workspace"] = json!(path);
            output.insert(id.clone(),json!({"path":path,"identity":{"dev":stat.dev().to_string(),"ino":stat.ino().to_string()},"maxWorkspaces":bounded(item,"maxWorkspaces",0,1,128)?,"templateHash":hex::encode(Sha256::digest(serde_json::to_vec(&item["grant"])?)),"grant":normalize_grant(&template,base,max_concurrent,true)?}));
        }
        g["workspaceProvisioning"] = json!({"roots":output});
    }
    let mut catalog = g.clone();
    if let Some(obj) = catalog.as_object_mut() {
        obj.remove("workspaces");
        obj.remove("workspaceProvisioning");
    }
    if serde_json::to_vec(&catalog)?.len() > 98304 {
        return Err(invalid(
            "Compiled grant exceeds bounded transport catalog size",
        ));
    }
    Ok(g)
}
fn all_grants(policy: &Value) -> Vec<&Value> {
    let mut out = Vec::new();
    if let Some(grants) = policy["grants"].as_object() {
        for grant in grants.values() {
            out.push(grant);
            if let Some(children) = grant["workspaces"].as_object() {
                out.extend(children.values());
            }
            if let Some(roots) = grant["workspaceProvisioning"]["roots"].as_object() {
                out.extend(roots.values().map(|r| &r["grant"]));
            }
        }
    }
    out
}
fn validate_mcp_storage(config: &Value, policy: &Value) -> Result<()> {
    if config["nodesFile"].is_string()
        && all_grants(policy).iter().any(|grant| {
            grant["mcpServers"]
                .as_object()
                .is_some_and(|servers| !servers.is_empty())
        })
    {
        return Err(invalid("MCP server definitions belong in mcp.json"));
    }
    Ok(())
}
fn isolation_writable(grant: &Value, policy: &Value) -> bool {
    grant["tools"].as_array().into_iter().flatten().any(|tool| {
        [
            "writeFile",
            "editFile",
            "mkdir",
            "writeChunk",
            "syncApply",
            "syncExec",
            "syncTransfer",
            "exec",
            "mcpList",
            "mcpCall",
        ]
        .contains(&tool.as_str().unwrap_or(""))
    }) || policy["grants"]
        .as_object()
        .into_iter()
        .flat_map(|grants| grants.values())
        .any(|parent| {
            parent["workspaceProvisioning"]["roots"]
                .as_object()
                .into_iter()
                .flat_map(|roots| roots.values())
                .any(|root| root["path"] == grant["root"])
        })
}
pub fn validate_policy(raw: &Value, base: &Path) -> Result<Value> {
    object(raw, "policy must be object")?;
    if raw.get("allowedMasters").is_some() || raw.get("tools").is_some() {
        return Err(invalid("Use explicit per-master grants"));
    }
    let mut out = raw.clone();
    for (name, default, min, max) in [
        ("maxConcurrent", 4, 1, 32),
        ("maxCacheBytes", 4194304, 1024, 67108864),
        ("maxTaskRecords", 4096, 1, 100000),
        ("maxJournalBytes", 67108864, 1048576, 1073741824),
    ] {
        out[name] = json!(bounded(raw, name, default, min, max)?);
    }
    let grants = raw.get("grants").cloned().unwrap_or(json!({}));
    let grants = object(&grants, "policy.grants must be object")?;
    if grants.len() > 128 {
        return Err(invalid("Too many master grants"));
    }
    let mut normalized = serde_json::Map::new();
    for (id, g) in grants {
        if !valid_id(id) {
            return Err(invalid("Invalid master ID"));
        }
        normalized.insert(
            id.clone(),
            normalize_grant(g, base, out["maxConcurrent"].as_u64().unwrap(), false)?,
        );
    }
    out["grants"] = Value::Object(normalized);
    let all = all_grants(&out);
    let mut writable = Vec::new();
    let mut provisioning = Vec::new();
    for grant in &all {
        if let Some(root) = grant["root"].as_str()
            && isolation_writable(grant, &out)
        {
            writable.push(PathBuf::from(root));
        }
        if let Some(roots) = grant["workspaceProvisioning"]["roots"].as_object() {
            for item in roots.values() {
                let path = PathBuf::from(item["path"].as_str().unwrap());
                provisioning.push(path.clone());
                writable.push(path);
            }
        }
    }
    let static_roots: Vec<PathBuf> = out["grants"]
        .as_object()
        .into_iter()
        .flat_map(|g| g.values())
        .flat_map(|g| {
            std::iter::once(g).chain(
                g["workspaces"]
                    .as_object()
                    .into_iter()
                    .flat_map(|w| w.values()),
            )
        })
        .filter_map(|g| g["root"].as_str().map(PathBuf::from))
        .collect();
    for (i, path) in provisioning.iter().enumerate() {
        if static_roots.iter().any(|p| paths_overlap(p, path))
            || provisioning[..i].iter().any(|p| paths_overlap(p, path))
        {
            return Err(invalid("Provisioning roots must be disjoint"));
        }
    }
    for grant in all {
        for (key, code) in [
            ("execCommands", "UNSAFE_EXEC_POLICY"),
            ("mcpServers", "UNSAFE_MCP_POLICY"),
        ] {
            if let Some(commands) = grant[key].as_object() {
                for command in commands.values() {
                    if command["codeFiles"].as_array().is_some_and(|files| {
                        files.iter().any(|f| {
                            f.as_str().is_some_and(|p| {
                                writable.iter().any(|root| Path::new(p).starts_with(root))
                            })
                        })
                    }) {
                        return Err(fail(
                            code,
                            "Approved code must be outside every remotely writable workspace",
                        ));
                    }
                }
            }
        }
    }
    Ok(out)
}
pub fn resolve_grant(
    policy: &Value,
    master: &str,
    workspace: Option<&str>,
    epoch: u64,
) -> Result<Grant> {
    let parent = policy["grants"]
        .get(master)
        .ok_or_else(|| fail("MASTER_DENIED", "Peer is not allowed"))?;
    let id = workspace.unwrap_or("default");
    if !valid_id(id) {
        return Err(fail("WORKSPACE_DENIED", "Invalid workspace ID"));
    }
    let raw = if id == "default" {
        parent
    } else {
        parent["workspaces"].get(id).ok_or_else(|| {
            fail(
                "WORKSPACE_DENIED",
                "Workspace is not available to this master",
            )
        })?
    };
    let root = PathBuf::from(
        raw["root"]
            .as_str()
            .or_else(|| raw["workspace"].as_str())
            .unwrap_or(""),
    );
    if !root.as_os_str().is_empty() {
        let meta = fs::symlink_metadata(&root)
            .map_err(|_| fail("WORKSPACE_DENIED", "Workspace unavailable"))?;
        if !meta.is_dir()
            || fs::canonicalize(&root)? != root
            || raw["workspaceIdentity"]["ino"]
                .as_str()
                .is_some_and(|s| s != meta.ino().to_string())
            || raw["workspaceIdentity"]["dev"]
                .as_str()
                .is_some_and(|s| s != meta.dev().to_string())
        {
            return Err(fail("WORKSPACE_DENIED", "Workspace identity changed"));
        }
    }
    Ok(Grant {
        root,
        tools: raw["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        raw: raw.clone(),
        master_id: master.to_owned(),
        workspace_id: id.to_owned(),
        epoch,
    })
}
pub fn load_config(path: &Path) -> Result<Config> {
    let path = absolute(
        &std::env::current_dir()?,
        path.to_str()
            .ok_or_else(|| invalid("Invalid config path"))?,
    )?;
    let stat = fs::symlink_metadata(&path)?;
    if !stat.is_file() || stat.nlink() != 1 || fs::canonicalize(&path)? != path {
        return Err(invalid("Config must be canonical, regular and non-linked"));
    }
    let mut raw: Value = serde_json::from_slice(&fs::read(&path)?)?;
    object(&raw, "Config must be object")?;
    if raw["version"] == 2 {
        raw = crate::settings::compose_raw(&path, raw)?;
    }
    if let Some(sessions) = raw.get("sessions") {
        object(sessions, "sessions must be an object")?;
        if sessions
            .get("allowTemporary")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(invalid("sessions.allowTemporary must be a boolean"));
        }
    }
    crate::transport::Settings::parse(&raw)?;
    let rsync = crate::rsync::Settings::parse(&raw)?;
    if let Some(settings) = &rsync {
        settings.validate()?;
    }
    let id = raw["id"]
        .as_str()
        .filter(|s| valid_id(s))
        .ok_or_else(|| invalid("Invalid node ID"))?
        .to_owned();
    let base = path.parent().unwrap();
    let host = raw
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("127.0.0.1")
        .to_owned();
    if !valid_host(&host) || (host != "127.0.0.1" && raw["security"]["allowExternal"] != true) {
        return Err(fail(
            "LOOPBACK_ONLY",
            "External host requires explicit security.allowExternal",
        ));
    }
    let port = bounded(&raw, "port", 0, 0, 65535)? as u16;
    let peers = raw.get("peers").cloned().unwrap_or(json!([]));
    let peers = peers
        .as_array()
        .ok_or_else(|| invalid("peers must be array"))?;
    if peers.len() > 32 {
        return Err(invalid("Too many peers"));
    }
    let mut seen = BTreeSet::new();
    for peer in peers {
        object(peer, "Invalid peer")?;
        let peer_id = peer["id"].as_str().unwrap_or("");
        if !valid_id(peer_id) || peer_id == id || !seen.insert(peer_id) {
            return Err(invalid("Invalid or duplicate peer"));
        }
        let host = peer["host"].as_str().unwrap_or("");
        if !valid_host(host) || (host != "127.0.0.1" && raw["security"]["allowExternal"] != true) {
            return Err(fail(
                "LOOPBACK_ONLY",
                "External peer requires allowExternal",
            ));
        }
        bounded(peer, "port", 0, 1, 65535)?;
    }
    if !peers.is_empty() && raw.get("agent").is_none_or(Value::is_null) {
        return Err(fail(
            "AGENT_REQUIRED",
            "Outgoing relationships require an agent",
        ));
    }
    if raw.get("agent").is_some_and(|v| {
        !v.is_null() && !matches!(v.as_str(), Some("deterministic-demo" | "pi-mock"))
    }) {
        return Err(invalid("Unsupported agent"));
    }
    let state_dir = absolute(
        base,
        raw.get("stateDir")
            .and_then(Value::as_str)
            .unwrap_or(&format!(".unified-node-state/{id}")),
    )?;
    raw["stateDir"] = json!(state_dir);
    let owner_policy = raw.get("policy").cloned().unwrap_or(json!({}));
    validate_mcp_storage(&raw, &owner_policy)?;
    raw["policy"] = validate_policy(&owner_policy, base)?;
    raw["policyRaw"] = owner_policy;
    let mut protected = vec![state_dir.clone(), path.clone()];
    for field in ["nodesFile", "mcpFile"] {
        if let Some(path) = raw[field].as_str() {
            protected.push(PathBuf::from(path));
        }
    }
    if let Some(settings) = &rsync {
        protected.push(settings.file.clone());
    }
    let mut security_files = Vec::new();
    for key in ["cert", "key", "ca"] {
        let filename = raw["security"][key]
            .as_str()
            .ok_or_else(|| invalid("Explicit mTLS cert, key and ca required"))?;
        let file = absolute(base, filename)?;
        protected.push(file.clone());
        security_files.push(file.clone());
        if file.parent() != Some(base) {
            protected.push(file.parent().unwrap().to_owned());
        }
        raw["security"][key] = json!(file);
    }
    if let Some(log) = raw.get("logFile").filter(|v| !v.is_null()) {
        let file = absolute(
            base,
            log.as_str().ok_or_else(|| invalid("Invalid logFile"))?,
        )?;
        protected.push(file.clone());
        if file.parent() != Some(base) {
            protected.push(file.parent().unwrap().to_owned());
        }
        raw["logFile"] = json!(file);
    }
    if raw.get("operator").is_some_and(|v| !v.is_null()) {
        object(&raw["operator"], "operator must be object")?;
        if raw["operator"]
            .get("host")
            .is_some_and(|h| h != "127.0.0.1")
        {
            return Err(invalid("Operator must bind loopback"));
        }
        bounded(&raw["operator"], "port", 0, 0, 65535)?;
        if let Some(root) = raw["operator"].get("uiRoot") {
            let root = root
                .as_str()
                .ok_or_else(|| invalid("operator.uiRoot must be an absolute directory"))?;
            if !Path::new(root).is_absolute() {
                return Err(invalid("operator.uiRoot must be an absolute directory"));
            }
        }
        crate::operator::validate_assets(&raw["operator"])?;
        let sessions = absolute(
            base,
            raw["operator"]
                .get("sessionDirectory")
                .and_then(Value::as_str)
                .unwrap_or(state_dir.join("operator-access").to_str().unwrap()),
        )?;
        protected.push(sessions.clone());
        raw["operator"]["sessionDirectory"] = json!(sessions);
        if let Some(socket) = raw["operator"].get("socketPath") {
            let socket = absolute(
                base,
                socket
                    .as_str()
                    .ok_or_else(|| invalid("Invalid socketPath"))?,
            )?;
            protected.push(socket.parent().unwrap().to_owned());
            raw["operator"]["socketPath"] = json!(socket);
        }
        if let Some(root) = raw["operator"]["uiRoot"].as_str() {
            let root = directory(base, root, true)?;
            if protected.iter().any(|p| paths_overlap(&root, p)) {
                return Err(invalid("Public UI root must not overlap private node data"));
            }
            raw["operator"]["uiRoot"] = json!(root);
            protected.push(root);
        }
    }
    for grant in all_grants(&raw["policy"]) {
        if let Some(root) = grant["root"].as_str() {
            let root = Path::new(root);
            if protected.iter().any(|p| paths_overlap(root, p)) {
                return Err(fail(
                    "UNSAFE_STATE_POLICY",
                    "Workspaces must be disjoint from state, config, secrets and owner sessions",
                ));
            }
            if isolation_writable(grant, &raw["policy"])
                && (paths_overlap(root, Path::new(env!("CARGO_MANIFEST_DIR")))
                    || std::env::current_exe().is_ok_and(|binary| paths_overlap(root, &binary)))
            {
                return Err(fail(
                    "UNSAFE_STATE_POLICY",
                    "Writable workspace overlaps runtime code",
                ));
            }
        }
    }
    validate_pi(&raw, peers)?;
    let pins = raw["security"]
        .get("trustedPeers")
        .cloned()
        .unwrap_or(json!({}));
    let pins = object(&pins, "trustedPeers must be explicit pin map")?;
    for peer in peers {
        if !pins.contains_key(peer["id"].as_str().unwrap()) {
            return Err(invalid(
                "Every configured relationship needs certificate pins",
            ));
        }
    }
    for master in raw["policy"]["grants"].as_object().unwrap().keys() {
        if !pins.contains_key(master) {
            return Err(invalid(
                "Every configured relationship needs certificate pins",
            ));
        }
    }
    raw["host"] = json!(host);
    raw["port"] = json!(port);
    raw["securityFiles"] = json!(security_files);
    Ok(Config {
        raw,
        id,
        host,
        port,
        path,
        state_dir,
    })
}
fn valid_host(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || (!host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|s| {
                !s.is_empty()
                    && s.len() <= 63
                    && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                    && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
}
pub fn validate_config_policy(config: &Config, raw: &Value) -> Result<Value> {
    validate_mcp_storage(&config.raw, raw)?;
    let base = config
        .path
        .parent()
        .ok_or_else(|| invalid("Config has no parent directory"))?;
    let normalized = validate_policy(raw, base)?;
    let mut protected = vec![config.path.clone(), config.state_dir.clone()];
    for field in ["nodesFile", "mcpFile"] {
        if let Some(path) = config.raw[field].as_str() {
            protected.push(absolute(base, path)?);
        }
    }
    if let Some(root) = config.raw["operator"]["uiRoot"].as_str() {
        protected.push(absolute(base, root)?);
    }
    if let Some(settings) = crate::rsync::Settings::parse(&config.raw)? {
        protected.push(settings.file);
    }
    for key in ["cert", "key", "ca"] {
        if let Some(file) = config.raw["security"][key].as_str() {
            let path = absolute(base, file)?;
            protected.push(path.clone());
            if path.parent() != Some(base) {
                protected.push(path.parent().unwrap().to_owned());
            }
        }
    }
    if let Some(file) = config.raw["logFile"].as_str() {
        let path = absolute(base, file)?;
        protected.push(path.clone());
        if path.parent() != Some(base) {
            protected.push(path.parent().unwrap().to_owned());
        }
    }
    if let Some(path) = config.raw["operator"]["sessionDirectory"].as_str() {
        protected.push(absolute(base, path)?);
    }
    if let Some(path) = config.raw["operator"]["socketPath"].as_str() {
        protected.push(absolute(base, path)?.parent().unwrap().to_owned());
    }
    for grant in all_grants(&normalized) {
        if let Some(root) = grant["root"].as_str() {
            let root = Path::new(root);
            if protected.iter().any(|p| paths_overlap(root, p)) {
                return Err(fail(
                    "UNSAFE_STATE_POLICY",
                    "Workspaces must be disjoint from state, config, secrets and owner sessions",
                ));
            }
            if isolation_writable(grant, &normalized)
                && (paths_overlap(root, Path::new(env!("CARGO_MANIFEST_DIR")))
                    || std::env::current_exe().is_ok_and(|binary| paths_overlap(root, &binary)))
            {
                return Err(fail(
                    "UNSAFE_STATE_POLICY",
                    "Writable workspace overlaps runtime code",
                ));
            }
        }
    }
    let pins = config.raw["security"]["trustedPeers"].as_object();
    for master in normalized["grants"].as_object().unwrap().keys() {
        if pins.is_none_or(|p| !p.contains_key(master)) {
            return Err(invalid(
                "Every configured relationship needs certificate pins",
            ));
        }
    }
    Ok(normalized)
}
fn validate_pi(raw: &Value, peers: &[Value]) -> Result<()> {
    let pi = raw.get("pi").cloned().unwrap_or(json!({}));
    let obj = object(&pi, "Invalid Pi config")?;
    if obj
        .keys()
        .any(|k| !["resources", "trustedExtensions"].contains(&k.as_str()))
    {
        return Err(invalid("Invalid Pi config keys"));
    }
    let resources = pi.get("resources").cloned().unwrap_or(json!([]));
    let resources = resources
        .as_array()
        .ok_or_else(|| invalid("Pi resources must be array"))?;
    if resources.len() > 32 {
        return Err(invalid("Too many Pi resources"));
    }
    let mut seen = BTreeSet::new();
    for item in resources {
        let obj = object(item, "Invalid Pi resource")?;
        let peer = item["peerId"].as_str().unwrap_or("");
        let resource = item["resource"].as_str().unwrap_or("");
        if obj.len() != 2
            || !valid_id(peer)
            || !valid_id(resource)
            || !peers.iter().any(|p| p["id"] == peer)
            || !seen.insert((peer, resource))
        {
            return Err(invalid(
                "Pi resources require unique configured peer and alias",
            ));
        }
    }
    let extensions = pi.get("trustedExtensions").cloned().unwrap_or(json!([]));
    let extensions = extensions
        .as_array()
        .ok_or_else(|| invalid("Invalid Pi extensions"))?;
    if extensions.len() > 1 {
        return Err(invalid("Duplicate extension"));
    }
    for item in extensions {
        if object(item, "Invalid extension")?.len() != 2
            || item["id"] != "remote-audit-v1"
            || item["approved"] != true
        {
            return Err(fail(
                "UNTRUSTED_EXTENSION",
                "Only approved builtin extension is supported",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn policy_paths_reject_aliases_and_devices() {
        for path in [
            "../a", "a//b", "a/./b", "a\\b", "C:x", "nul.txt", "a.", "/a", "",
        ] {
            assert!(relative_path(path).is_err(), "{path}");
        }
        assert!(relative_path("src/你好.rs").is_ok());
    }
    #[test]
    fn policy_acl_uses_longest_directory_and_defaults_deny() {
        let grant = Grant {
            root: "/tmp".into(),
            tools: Default::default(),
            raw: json!({"directories":[{"path":"src","read":true,"write":true},{"path":"src/private","read":false,"write":false}]}),
            master_id: "a".into(),
            workspace_id: "default".into(),
            epoch: 1,
        };
        assert!(check_directory(&grant, "src/main.rs", true, false).is_ok());
        assert_eq!(
            check_directory(&grant, "src/private/key", false, false)
                .unwrap_err()
                .code,
            "DIRECTORY_DENIED"
        );
        assert!(check_directory(&grant, "other", false, true).is_err());
    }
    #[test]
    fn policy_named_grants_do_not_inherit_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let policy=validate_policy(&json!({"grants":{"master":{"tools":["workspaceList"],"workspaces":{"dev":{"workspace":dir.path(),"tools":["readFile"]}}}}}),dir.path()).unwrap();
        assert!(
            resolve_grant(&policy, "master", Some("dev"), 7)
                .unwrap()
                .tools
                .contains("readFile")
        );
        assert!(
            !resolve_grant(&policy, "master", Some("dev"), 7)
                .unwrap()
                .tools
                .contains("workspaceList")
        );
        assert_eq!(
            resolve_grant(&policy, "other", None, 7).unwrap_err().code,
            "MASTER_DENIED"
        );
        assert!(resolve_grant(&policy, "master", Some("missing"), 7).is_err());
    }
    #[test]
    fn policy_requires_exec_and_acknowledgement() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            validate_policy(
                &json!({"grants":{"a":{"workspace":dir.path(),"tools":["syncExec"]}}}),
                dir.path()
            )
            .is_err()
        );
        assert!(
            validate_policy(
                &json!({"grants":{"a":{"workspace":dir.path(),"tools":["exec"],"directories":[]}}}),
                dir.path()
            )
            .is_err()
        );
    }
    #[test]
    fn policy_native_code_hash_detects_changes() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("reviewed");
        std::fs::write(&file, b"\x7fELForiginal").unwrap();
        let command = compile_approved_code(
            &json!({"file":file,"launchMode":"native","args":[]}),
            "UNSAFE_EXEC_POLICY",
        )
        .unwrap();
        verify_approved_code(&command, "EXEC_CODE_CHANGED").unwrap();
        std::fs::write(&file, b"\x7fELFchanged!").unwrap();
        assert_eq!(
            verify_approved_code(&command, "EXEC_CODE_CHANGED")
                .unwrap_err()
                .code,
            "EXEC_CODE_CHANGED"
        );
    }
    #[test]
    fn policy_config_blocks_workspace_ancestor_of_state() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let path = dir.path().join("node.json");
        std::fs::write(&path,serde_json::to_vec(&json!({"id":"servant","port":0,"stateDir":data.join("state"),"security":{"cert":"cert.pem","key":"key.pem","ca":"ca.pem"},"policy":{"grants":{"master":{"workspace":data,"tools":["readFile"]}}}})).unwrap()).unwrap();
        assert_eq!(load_config(&path).unwrap_err().code, "UNSAFE_STATE_POLICY");
    }
    #[test]
    fn policy_provisioning_must_be_disjoint_from_static_workspaces() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let raw = json!({"grants":{"master":{"tools":["workspaceCreate"],"workspaces":{"dev":{"workspace":dir.path(),"tools":["readFile"]}},"workspaceProvisioning":{"roots":{"projects":{"path":dir.path(),"maxWorkspaces":2,"grant":{"tools":["readFile"],"directories":[{"path":"","read":true,"write":false}]}}}}}}});
        assert_eq!(
            validate_policy(&raw, dir.path()).unwrap_err().code,
            "INVALID_CONFIG"
        );
    }
    #[test]
    fn policy_code_isolation_spans_all_master_grants() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let code = dir.path().join("code");
        std::fs::create_dir(&data).unwrap();
        std::fs::create_dir(&code).unwrap();
        let binary = code.join("reviewed");
        std::fs::write(&binary, b"\x7fELFtest").unwrap();
        let raw = json!({"grants":{"runner":{"workspace":data,"tools":["exec"],"execCommands":{"build":{"file":binary,"launchMode":"native","args":[]}}},"writer":{"workspace":code,"tools":["writeFile"]}}});
        assert_eq!(
            validate_policy(&raw, dir.path()).unwrap_err().code,
            "UNSAFE_EXEC_POLICY"
        );
    }
    #[test]
    fn policy_approved_code_rejects_hardlinks() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("binary");
        std::fs::write(&file, b"\x7fELFtest").unwrap();
        std::fs::hard_link(&file, dir.path().join("alias")).unwrap();
        assert_eq!(
            compile_approved_code(
                &json!({"file":file,"launchMode":"native"}),
                "UNSAFE_EXEC_POLICY"
            )
            .unwrap_err()
            .code,
            "UNSAFE_EXEC_POLICY"
        );
    }
    #[test]
    fn policy_code_isolation_includes_process_writable_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let code = dir.path().join("code");
        std::fs::create_dir(&data).unwrap();
        std::fs::create_dir(&code).unwrap();
        let binary = code.join("reviewed");
        std::fs::write(&binary, b"\x7fELFtest").unwrap();
        let raw = json!({"grants":{"runner":{"workspace":data,"tools":["exec"],"execCommands":{"build":{"file":binary,"launchMode":"native","args":[]}}},"process":{"workspace":code,"tools":["exec"]}}});
        assert_eq!(
            validate_policy(&raw, dir.path()).unwrap_err().code,
            "UNSAFE_EXEC_POLICY"
        );
    }
    #[test]
    fn managed_policy_rejects_embedded_mcp_definitions_in_every_grant() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            raw: json!({"nodesFile":dir.path().join("nodes.json"),"security":{"trustedPeers":{"master":"pin"}}}),
            id: "node".into(),
            host: "127.0.0.1".into(),
            port: 0,
            path: dir.path().join("config.json"),
            state_dir: dir.path().join("state"),
        };
        for raw in [
            json!({"grants":{"master":{"tools":["echo"],"mcpServers":{"test":{}}}}}),
            json!({"grants":{"master":{"tools":["echo"],"workspaces":{"project":{"workspace":dir.path(),"tools":["echo"],"mcpServers":{"test":{}}}}}}}),
            json!({"grants":{"master":{"tools":["echo"],"workspaceProvisioning":{"roots":{"projects":{"path":dir.path(),"maxWorkspaces":1,"grant":{"tools":["echo"],"mcpServers":{"test":{}}}}}}}}}),
        ] {
            assert_eq!(
                validate_config_policy(&config, &raw).unwrap_err().message,
                "MCP server definitions belong in mcp.json"
            );
        }
        assert!(
            validate_config_policy(
                &config,
                &json!({"grants":{"master":{"tools":["echo"],"mcpServers":{}}}})
            )
            .is_ok()
        );
    }
    #[test]
    fn policy_reload_protects_node_mcp_and_public_web_files() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        for field in ["nodesFile", "mcpFile", "uiRoot"] {
            let mut stored = json!({"security":{"trustedPeers":{"master":"pin"}}});
            if field == "uiRoot" {
                stored["operator"] = json!({"uiRoot":workspace});
            } else {
                stored[field] = json!(workspace.join("private.json"));
            }
            let config = Config {
                raw: stored,
                id: "node".into(),
                host: "127.0.0.1".into(),
                port: 0,
                path: dir.path().join("config.json"),
                state_dir: dir.path().join("state"),
            };
            let raw = json!({"grants":{"master":{"workspace":workspace,"tools":["readFile"]}}});
            assert_eq!(
                validate_config_policy(&config, &raw).unwrap_err().code,
                "UNSAFE_STATE_POLICY",
                "{field}"
            );
        }
    }
    #[test]
    fn policy_reload_cannot_expose_state_parent() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let config = Config {
            raw: json!({"security":{"trustedPeers":{"master":"pin"}}}),
            id: "node".into(),
            host: "127.0.0.1".into(),
            port: 0,
            path: dir.path().join("config.json"),
            state_dir: workspace.join("state"),
        };
        let raw = json!({"grants":{"master":{"workspace":workspace,"tools":["readFile"]}}});
        assert_eq!(
            validate_config_policy(&config, &raw).unwrap_err().code,
            "UNSAFE_STATE_POLICY"
        );
    }
    #[test]
    fn policy_config_preserves_resource_owner_source_for_reload() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let path = dir.path().join("config.json");
        let policy = json!({"grants":{"master":{"workspace":workspace,"tools":["resourceRead"],"resources":{"guide":{"kind":"instruction","path":"README.md"}}}}});
        std::fs::write(&path,serde_json::to_vec(&json!({"id":"servant","port":0,"security":{"cert":"cert.pem","key":"key.pem","ca":"ca.pem","trustedPeers":{"master":"pin"}},"policy":policy})).unwrap()).unwrap();
        let config = load_config(&path).unwrap();
        assert_eq!(config.raw["policyRaw"], policy);
        assert!(validate_config_policy(&config, &config.raw["policyRaw"]).is_ok());
        assert!(validate_policy(&config.raw["policy"], dir.path()).is_err());
    }
}
