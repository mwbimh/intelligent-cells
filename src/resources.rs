use crate::{
    context::ToolContext,
    error::{IcError, Result},
    model::Grant,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
fn err(code: &str, message: &str) -> IcError {
    IcError::new(code, message)
}
fn object(v: &Value) -> Result<&serde_json::Map<String, Value>> {
    v.as_object()
        .ok_or_else(|| err("INVALID_CONFIG", "Expected explicit object"))
}
fn alias(s: &str) -> bool {
    crate::policy::valid_id(s)
}
fn tool_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn keys(v: &Value, allowed: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.keys().all(|k| allowed.contains(&k.as_str())))
}
fn bound(v: &Value, key: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    match v.get(key) {
        None => Ok(default),
        Some(x) => x
            .as_u64()
            .filter(|x| *x >= min && *x <= max)
            .ok_or_else(|| err("INVALID_CONFIG", "Invalid byte limit")),
    }
}
pub fn validate_schema(s: &Value, depth: usize) -> Result<()> {
    if depth > 6
        || !keys(
            s,
            &[
                "type",
                "properties",
                "required",
                "additionalProperties",
                "items",
                "minItems",
                "maxItems",
                "minLength",
                "maxLength",
                "minimum",
                "maximum",
                "enum",
                "description",
            ],
        )
    {
        return Err(err("INVALID_CONFIG", "Unsupported MCP schema"));
    }
    let typ = s["type"].as_str().unwrap_or("");
    if ![
        "object", "array", "string", "integer", "number", "boolean", "null",
    ]
    .contains(&typ)
    {
        return Err(err("INVALID_CONFIG", "Unsupported MCP schema type"));
    }
    if s.get("description")
        .is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 1024))
    {
        return Err(err("INVALID_CONFIG", "Invalid schema description"));
    }
    for key in ["minItems", "maxItems", "minLength", "maxLength"] {
        if let Some(v) = s.get(key)
            && v.as_u64().is_none_or(|n| n > 65536)
        {
            return Err(err("INVALID_CONFIG", "Invalid schema bound"));
        }
    }
    for key in ["minimum", "maximum"] {
        if s.get(key).is_some_and(|v| v.as_f64().is_none()) {
            return Err(err("INVALID_CONFIG", "Invalid numeric bound"));
        }
    }
    if s.get("enum").is_some_and(|v| {
        v.as_array()
            .is_none_or(|a| a.len() > 32 || a.iter().any(|x| x.is_object() || x.is_array()))
    }) {
        return Err(err("INVALID_CONFIG", "Invalid scalar enum"));
    }
    if typ == "object" {
        let properties = object(&s["properties"])?;
        if properties.len() > 32 || s["additionalProperties"] != false {
            return Err(err(
                "INVALID_CONFIG",
                "MCP objects must forbid additional properties",
            ));
        }
        if let Some(required) = s.get("required")
            && required.as_array().is_none_or(|a| {
                a.iter()
                    .any(|v| v.as_str().is_none_or(|k| !properties.contains_key(k)))
            })
        {
            return Err(err("INVALID_CONFIG", "Invalid required properties"));
        }
        for (k, v) in properties {
            if !tool_name(k) {
                return Err(err("INVALID_CONFIG", "Invalid schema property"));
            }
            validate_schema(v, depth + 1)?;
        }
    } else if typ == "array" {
        validate_schema(&s["items"], depth + 1)?;
    }
    Ok(())
}
pub fn matches_schema(v: &Value, s: &Value) -> bool {
    if s.get("enum")
        .is_some_and(|e| !e.as_array().unwrap_or(&vec![]).contains(v))
    {
        return false;
    }
    match s["type"].as_str().unwrap_or("") {
        "object" => v.as_object().is_some_and(|o| {
            o.iter()
                .all(|(k, v)| s["properties"].get(k).is_some_and(|s| matches_schema(v, s)))
                && s["required"]
                    .as_array()
                    .is_none_or(|a| a.iter().all(|k| o.contains_key(k.as_str().unwrap_or(""))))
        }),
        "array" => v.as_array().is_some_and(|a| {
            a.len() >= s["minItems"].as_u64().unwrap_or(0) as usize
                && a.len() <= s["maxItems"].as_u64().unwrap_or(128).min(128) as usize
                && a.iter().all(|v| matches_schema(v, &s["items"]))
        }),
        "string" => v.as_str().is_some_and(|v| {
            let n = v.encode_utf16().count() as u64;
            n >= s["minLength"].as_u64().unwrap_or(0)
                && n <= s["maxLength"].as_u64().unwrap_or(8192).min(8192)
        }),
        "number" | "integer" => v.as_f64().is_some_and(|n| {
            n.is_finite()
                && (s["type"] != "integer" || (n.fract() == 0.0 && n.abs() <= 9007199254740991.0))
                && n >= s["minimum"].as_f64().unwrap_or(f64::NEG_INFINITY)
                && n <= s["maximum"].as_f64().unwrap_or(f64::INFINITY)
        }),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        _ => false,
    }
}
pub fn compile_policy(raw: &Value, _base: &Path, root: &Path) -> Result<Value> {
    let max_resource = bound(raw, "maxResourceBytes", 16384, 1, 65536)?;
    let max_total = bound(raw, "maxResourceTotalBytes", 65536, 1, 131072)?;
    let max_mcp = bound(raw, "maxMcpBytes", 32768, 256, 65536)?;
    let empty = json!({});
    let resources = object(raw.get("resources").unwrap_or(&empty))?;
    let servers = object(raw.get("mcpServers").unwrap_or(&empty))?;
    if resources.len() > 32 || servers.len() > 8 {
        return Err(err(
            "INVALID_CONFIG",
            "Too many approved resources or servers",
        ));
    }
    let mut approved = serde_json::Map::new();
    for (id, r) in resources {
        if root.as_os_str().is_empty()
            || !alias(id)
            || !keys(r, &["kind", "path", "description", "maxBytes", "sha256"])
            || !["instruction", "skill", "prompt"].contains(&r["kind"].as_str().unwrap_or(""))
        {
            return Err(err("INVALID_CONFIG", "Malformed approved resource"));
        }
        let path = r["path"]
            .as_str()
            .ok_or_else(|| err("INVALID_CONFIG", "Missing resource path"))?;
        crate::policy::relative_path(path)
            .map_err(|_| err("INVALID_CONFIG", "Invalid resource path"))?;
        if path.len() > 500 {
            return Err(err("INVALID_CONFIG", "Resource path too long"));
        }
        let desc = r.get("description").and_then(Value::as_str).unwrap_or(id);
        if r.get("description").is_some_and(|x| !x.is_string()) || desc.len() > 1024 {
            return Err(err("INVALID_CONFIG", "Invalid resource description"));
        }
        if r.get("sha256").is_some_and(|v| {
            v.as_str().is_none_or(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        }) {
            return Err(err("INVALID_CONFIG", "Invalid resource digest"));
        }
        let mut r = r.clone();
        r["id"] = json!(id);
        r["description"] = json!(desc);
        r["maxBytes"] = json!(bound(&r, "maxBytes", max_resource, 1, max_resource)?);
        approved.insert(id.clone(), r);
    }
    let mut mcp = serde_json::Map::new();
    for (id, s) in servers {
        if root.as_os_str().is_empty()
            || !alias(id)
            || !keys(
                s,
                &[
                    "trusted",
                    "file",
                    "args",
                    "launchMode",
                    "tools",
                    "maxOutputBytes",
                ],
            )
            || s["trusted"] != true
        {
            return Err(err(
                "INVALID_CONFIG",
                "MCP requires trusted fixed local command",
            ));
        }
        let file = s["file"]
            .as_str()
            .ok_or_else(|| err("INVALID_CONFIG", "Missing MCP executable"))?;
        if !Path::new(file).is_absolute() {
            return Err(err("INVALID_CONFIG", "MCP executable must be absolute"));
        }
        let args = s.get("args").cloned().unwrap_or(json!([]));
        if args.as_array().is_none_or(|a| {
            a.len() > 16
                || a.iter().any(|v| {
                    v.as_str()
                        .is_none_or(|s| s.len() > 4096 || s.contains('\0'))
                })
        }) {
            return Err(err("INVALID_CONFIG", "Invalid fixed MCP argv"));
        }
        let bindings = object(&s["tools"])?;
        if bindings.len() > 32 {
            return Err(err("INVALID_CONFIG", "Too many MCP bindings"));
        }
        let mut tools = serde_json::Map::new();
        for (name, b) in bindings {
            if !tool_name(name)
                || !keys(b, &["inputSchema", "readOnly", "description"])
                || !b["readOnly"].is_boolean()
                || b["inputSchema"]["type"] != "object"
                || serde_json::to_vec(&b["inputSchema"])?.len() > 16384
                || b.get("description")
                    .is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 1024))
            {
                return Err(err("INVALID_CONFIG", "Invalid local MCP binding"));
            }
            validate_schema(&b["inputSchema"], 0)?;
            let mut b = b.clone();
            b["name"] = json!(name);
            if b.get("description").is_none() {
                b["description"] = json!(name)
            }
            tools.insert(name.clone(), b);
        }
        let mut command = crate::policy::compile_approved_code(s, "UNSAFE_MCP_POLICY")?;
        command["alias"] = json!(id);
        command["tools"] = Value::Object(tools);
        command["maxOutputBytes"] = json!(bound(s, "maxOutputBytes", max_mcp, 256, max_mcp)?);
        command["args"] = args;
        mcp.insert(id.clone(), command);
    }
    Ok(
        json!({"resources":approved,"maxResourceBytes":max_resource,"maxResourceTotalBytes":max_total,"mcpServers":mcp,"maxMcpBytes":max_mcp}),
    )
}
pub fn side_effect(task: &Value, grant: Option<&Grant>) -> bool {
    task["tool"] == "mcpCall"
        && grant.is_none_or(|g| {
            g.raw["mcpServers"][task["args"]["server"].as_str().unwrap_or("")]["tools"]
                [task["args"]["tool"].as_str().unwrap_or("")]["readOnly"]
                != true
        })
}
pub fn validate(task: &Value, grant: &Grant) -> Result<()> {
    let tool = task["tool"].as_str().unwrap_or("");
    let a = &task["args"];
    if !a.is_object() {
        return Err(err("INVALID_ARGS", "Arguments must be object"));
    }
    match tool {
        "resourceList" => {
            if !keys(a, &[]) {
                return Err(err("INVALID_ARGS", "resourceList takes no arguments"));
            }
        }
        "resourceRead" => {
            let id = a["resource"].as_str().unwrap_or("");
            if !keys(a, &["resource"]) || !alias(id) {
                return Err(err("INVALID_ARGS", "Approved resource alias required"));
            }
            let r = grant.raw["resources"]
                .get(id)
                .ok_or_else(|| err("RESOURCE_DENIED", "Resource alias is not approved"))?;
            crate::policy::check_directory(grant, r["path"].as_str().unwrap_or(""), false, false)?;
        }
        "mcpList" | "mcpCall" => {
            let id = a["server"].as_str().unwrap_or("");
            if !alias(id)
                || !keys(
                    a,
                    if tool == "mcpList" {
                        &["server"]
                    } else {
                        &["server", "tool", "arguments"]
                    },
                )
            {
                return Err(err(
                    "INVALID_ARGS",
                    "Only approved aliases and arguments accepted",
                ));
            }
            let server = grant.raw["mcpServers"]
                .get(id)
                .ok_or_else(|| err("MCP_SERVER_DENIED", "Server alias is not approved"))?;
            if tool == "mcpCall" {
                let name = a["tool"].as_str().unwrap_or("");
                let binding = server["tools"]
                    .get(name)
                    .filter(|_| tool_name(name))
                    .ok_or_else(|| err("MCP_TOOL_DENIED", "MCP binding not approved"))?;
                if !a["arguments"].is_object()
                    || serde_json::to_vec(&a["arguments"])?.len() > 16384
                    || !matches_schema(&a["arguments"], &binding["inputSchema"])
                {
                    return Err(err(
                        "INVALID_ARGS",
                        "Arguments violate approved local schema",
                    ));
                }
            }
        }
        _ => return Err(err("TOOL_DENIED", "Unknown resource/MCP operation")),
    }
    Ok(())
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn snapshot(root: &Path, relative: &str) -> Result<Vec<(PathBuf, fs::Metadata)>> {
    let mut p = root.to_path_buf();
    let mut paths = vec![p.clone()];
    for part in relative.split('/') {
        p.push(part);
        paths.push(p.clone())
    }
    let mut out = vec![];
    let n = paths.len();
    for (i, p) in paths.into_iter().enumerate() {
        let m = fs::symlink_metadata(&p)?;
        if m.file_type().is_symlink()
            || fs::canonicalize(&p)? != p
            || (if i + 1 < n {
                !m.is_dir()
            } else {
                !m.is_file() || m.nlink() != 1
            })
        {
            return Err(err(
                "PATH_DENIED",
                "Resource cannot contain links or special files",
            ));
        }
        out.push((p, m));
    }
    Ok(out)
}
fn read_resource(task: &Value, grant: &Grant, check: &dyn Fn() -> Result<()>) -> Result<Value> {
    check()?;
    validate(task, grant)?;
    if task["tool"] == "resourceList" {
        let list = grant.raw["resources"]
            .as_object()
            .map(|o| {
                o.values()
                    .filter(|r| {
                        crate::policy::check_directory(
                            grant,
                            r["path"].as_str().unwrap_or(""),
                            false,
                            false,
                        )
                        .is_ok()
                    })
                    .map(|r| {
                        let mut x = r.clone();
                        x.as_object_mut().unwrap().remove("path");
                        x
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        return Ok(
            json!({"resources":list,"maxTotalBytes":grant.limit("maxResourceTotalBytes",65536)}),
        );
    }
    let r = &grant.raw["resources"][task["args"]["resource"].as_str().unwrap()];
    let path = r["path"].as_str().unwrap();
    let before = snapshot(&grant.root, path)?;
    let (_name, stat) = before.last().unwrap();
    let limit = r["maxBytes"]
        .as_u64()
        .unwrap_or(16384)
        .min(grant.limit("maxResourceTotalBytes", 65536));
    if stat.len() > limit {
        return Err(err("RESOURCE_TOO_LARGE", "Resource exceeds budget"));
    }
    let data = crate::files::safe_read(&grant.root, path, limit).map_err(|e| {
        if e.code == "FILE_TOO_LARGE" {
            err("RESOURCE_TOO_LARGE", "Resource exceeds budget")
        } else {
            e
        }
    })?;
    check()?;
    let after = snapshot(&grant.root, path)?;
    if before.iter().zip(&after).any(|(a, b)| !same(&a.1, &b.1)) {
        return Err(err("PATH_DENIED", "Resource changed during read"));
    }
    let hash = hex::encode(Sha256::digest(&data));
    if r.get("sha256").is_some_and(|v| v.as_str() != Some(&hash)) {
        return Err(err(
            "RESOURCE_CHANGED",
            "Resource differs from approved digest",
        ));
    }
    let text = std::str::from_utf8(&data)
        .map_err(|_| err("INVALID_ENCODING", "Resources must be UTF-8"))?;
    check()?;
    Ok(
        json!({"id":r["id"],"kind":r["kind"],"description":r["description"],"text":text,"bytes":data.len(),"sha256":hash,"maxTotalBytes":grant.limit("maxResourceTotalBytes",65536),"trust":"owner-allowlisted-data-not-executable-code"}),
    )
}
pub(crate) struct StdioClient {
    child: Child,
    buffer: Vec<u8>,
    total: usize,
    limit: usize,
    next: u64,
    pub(crate) call_sent: bool,
}
impl Drop for StdioClient {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn depth(v: &Value, n: usize) -> bool {
    n <= 32
        && match v {
            Value::Array(a) => a.iter().all(|v| depth(v, n + 1)),
            Value::Object(o) => o.values().all(|v| depth(v, n + 1)),
            _ => true,
        }
}
impl StdioClient {
    pub(crate) fn open(server: &Value, root: &Path) -> Result<Self> {
        crate::files::inspect_root(root)?;
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)?;
        let before = fs::symlink_metadata(root)?;
        let opened = directory.metadata()?;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(err("PATH_DENIED", "Workspace changed before MCP launch"));
        }
        crate::policy::verify_approved_code(server, "MCP_CODE_CHANGED")?;
        let mut cmd = Command::new(
            server["file"]
                .as_str()
                .ok_or_else(|| err("INVALID_CONFIG", "Missing approved executable"))?,
        );
        for a in server["args"]
            .as_array()
            .ok_or_else(|| err("INVALID_CONFIG", "Missing fixed argv"))?
        {
            cmd.arg(
                a.as_str()
                    .ok_or_else(|| err("INVALID_CONFIG", "Invalid fixed argv"))?,
            );
        }
        cmd.current_dir(root)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(move || {
                if libc::fchdir(directory.as_raw_fd()) < 0 || libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd
            .spawn()
            .map_err(|e| err("MCP_SPAWN_FAILED", &e.to_string()))?;
        let out = Self {
            child,
            buffer: vec![],
            total: 0,
            limit: server["maxOutputBytes"].as_u64().unwrap_or(32768) as usize,
            next: 0,
            call_sent: false,
        };
        for fd in [
            out.child.stdout.as_ref().unwrap().as_raw_fd(),
            out.child.stderr.as_ref().unwrap().as_raw_fd(),
            out.child.stdin.as_ref().unwrap().as_raw_fd(),
        ] {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
        }
        Ok(out)
    }
    pub(crate) fn send(&mut self, v: &Value, check: &dyn Fn() -> Result<()>) -> Result<()> {
        let mut data = serde_json::to_vec(v)?;
        data.push(b'\n');
        let mut off = 0;
        while off < data.len() {
            check()?;
            match self.child.stdin.as_mut().unwrap().write(&data[off..]) {
                Ok(0) => return Err(err("MCP_DISCONNECTED", "MCP stdin closed")),
                Ok(n) => {
                    off += n;
                    if v["method"] == "tools/call" {
                        self.call_sent = true
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(_) => return Err(err("MCP_DISCONNECTED", "MCP stdin failed")),
            }
        }
        Ok(())
    }
    pub(crate) fn request(
        &mut self,
        method: &str,
        params: Value,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        self.next += 1;
        let id = self.next;
        self.send(
            &json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
            check,
        )?;
        loop {
            check()?;
            let mut got = false;
            let mut closed = false;
            for stderr in [true, false] {
                let mut buf = [0u8; 4096];
                loop {
                    let res = if stderr {
                        self.child.stderr.as_mut().unwrap().read(&mut buf)
                    } else {
                        self.child.stdout.as_mut().unwrap().read(&mut buf)
                    };
                    match res {
                        Ok(0) => {
                            if !stderr {
                                closed = true
                            }
                            break;
                        }
                        Ok(n) => {
                            got = true;
                            self.total += n;
                            if self.total > self.limit {
                                return Err(err(
                                    "MCP_OUTPUT_TOO_LARGE",
                                    "MCP stdout/stderr exceeds byte budget",
                                ));
                            }
                            if !stderr {
                                self.buffer.extend_from_slice(&buf[..n]);
                                if std::str::from_utf8(&self.buffer)
                                    .is_err_and(|e| e.error_len().is_some())
                                {
                                    return Err(err("MCP_PROTOCOL_ERROR", "Invalid MCP UTF-8"));
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => return Err(err("MCP_PROTOCOL_ERROR", "MCP output failed")),
                    }
                }
            }
            while let Some(pos) = self.buffer.iter().position(|b| *b == b'\n') {
                let line = self.buffer.drain(..=pos).collect::<Vec<_>>();
                let s = std::str::from_utf8(&line)
                    .map_err(|_| err("MCP_PROTOCOL_ERROR", "Invalid MCP UTF-8"))?;
                let m: Value = serde_json::from_str(s)
                    .map_err(|_| err("MCP_PROTOCOL_ERROR", "Invalid MCP JSON"))?;
                if !m.is_object() || m["jsonrpc"] != "2.0" || !depth(&m, 0) {
                    return Err(err("MCP_PROTOCOL_ERROR", "Invalid MCP envelope"));
                }
                if let Some(method) = m["method"].as_str() {
                    if m.get("id").is_some() {
                        let response = if method == "ping" {
                            json!({"jsonrpc":"2.0","id":m["id"],"result":{}})
                        } else {
                            json!({"jsonrpc":"2.0","id":m["id"],"error":{"code":-32601,"message":"Client capability not supported"}})
                        };
                        self.send(&response, check)?;
                    }
                    continue;
                }
                if m["id"] != id || m.get("result").is_some() == m.get("error").is_some() {
                    return Err(err("MCP_PROTOCOL_ERROR", "Unexpected MCP response"));
                }
                if m.get("error").is_some() {
                    return Err(err("MCP_RPC_ERROR", "MCP returned JSON-RPC error"));
                }
                return Ok(m["result"].clone());
            }
            if closed {
                if !self.buffer.is_empty() {
                    return Err(err(
                        "MCP_PROTOCOL_ERROR",
                        "MCP closed with incomplete frame",
                    ));
                }
                return Err(err("MCP_DISCONNECTED", "MCP server disconnected"));
            }
            if !got {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}
fn mcp(task: &Value, grant: &Grant, check: &dyn Fn() -> Result<()>) -> Result<Value> {
    check()?;
    validate(task, grant)?;
    let server = &grant.raw["mcpServers"][task["args"]["server"].as_str().unwrap()];
    let mut client = StdioClient::open(server, &grant.root)?;
    let result = (|| {
        let init=client.request("initialize",json!({"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"intelligent-cells-servant","version":env!("CARGO_PKG_VERSION")}}),check)?;
        if init["protocolVersion"] != MCP_PROTOCOL_VERSION
            || !init["capabilities"]["tools"].is_object()
            || !init["serverInfo"].is_object()
        {
            return Err(err(
                "MCP_NEGOTIATION_FAILED",
                "MCP pinned tools protocol unsupported",
            ));
        }
        client.send(
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            check,
        )?;
        let catalog = client.request("tools/list", json!({}), check)?;
        let tools = catalog["tools"]
            .as_array()
            .ok_or_else(|| err("MCP_PROTOCOL_ERROR", "Invalid catalog"))?;
        let mut exposed = std::collections::BTreeSet::new();
        if tools.len() > 128
            || catalog.get("nextCursor").is_some()
            || tools.iter().any(|t| {
                !t.is_object()
                    || t["name"]
                        .as_str()
                        .is_none_or(|n| !tool_name(n) || !exposed.insert(n.to_owned()))
            })
        {
            return Err(err("MCP_PROTOCOL_ERROR", "Invalid or paginated catalog"));
        }
        if task["tool"] == "mcpList" {
            let list = server["tools"]
                .as_object()
                .unwrap()
                .iter()
                .filter(|(n, _)| exposed.contains(*n))
                .map(|(_, b)| {
                    let mut v = b.clone();
                    v["permissionAuthority"] = json!("servant-local-grant");
                    v
                })
                .collect::<Vec<_>>();
            return Ok(
                json!({"server":server["alias"],"protocolVersion":MCP_PROTOCOL_VERSION,"transport":"stdio","tools":list}),
            );
        }
        let name = task["args"]["tool"].as_str().unwrap();
        if !exposed.contains(name) {
            return Err(err("MCP_TOOL_UNAVAILABLE", "Approved tool unavailable"));
        }
        let result = client.request(
            "tools/call",
            json!({"name":name,"arguments":task["args"]["arguments"]}),
            check,
        )?;
        if !result.is_object()
            || result["content"].as_array().is_none_or(|a| {
                a.len() > 64
                    || a.iter()
                        .any(|i| !i.is_object() || i["type"] != "text" || !i["text"].is_string())
            })
            || result.get("isError").is_some_and(|v| !v.is_boolean())
        {
            return Err(err(
                "MCP_PROTOCOL_ERROR",
                "Only bounded text results supported",
            ));
        }
        Ok(
            json!({"server":server["alias"],"tool":name,"content":result["content"],"isError":result["isError"]==true,"protocolVersion":MCP_PROTOCOL_VERSION}),
        )
    })();
    match result {
        Err(e)
            if client.call_sent && side_effect(task, Some(grant)) && e.code != "MCP_RPC_ERROR" =>
        {
            Err(err(
                "OUTCOME_UNKNOWN",
                "MCP mutating call sent without confirmed final outcome",
            )
            .unknown())
        }
        other => other,
    }
}
pub fn run_checked(task: &Value, grant: &Grant, check: &dyn Fn() -> Result<()>) -> Result<Value> {
    check()?;
    let tool = task["tool"].as_str().unwrap_or("");
    if !grant.tools.contains(tool) {
        return Err(err("TOOL_DENIED", "Resource/MCP operation not granted"));
    }
    if tool.starts_with("resource") {
        read_resource(task, grant, check)
    } else {
        mcp(task, grant, check)
    }
}
pub fn run(task: &Value, grant: &Grant, ctx: &ToolContext) -> Result<Value> {
    run_checked(task, grant, &|| ctx.check())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn resources_schema_rejects_unapproved_features_and_extra_arguments() {
        let schema = json!({"type":"object","properties":{"text":{"type":"string","maxLength":3}},"required":["text"],"additionalProperties":false});
        validate_schema(&schema, 0).unwrap();
        assert!(matches_schema(&json!({"text":"abc"}), &schema));
        assert!(!matches_schema(&json!({"text":"abcd"}), &schema));
        assert!(!matches_schema(
            &json!({"text":"abc","command":"bad"}),
            &schema
        ));
        assert!(validate_schema(&json!({"type":"object","properties":{},"additionalProperties":false,"$ref":"file:///etc/passwd"}),0).is_err());
    }
    #[test]
    fn resources_compile_limits_aliases_and_explicit_data_kinds() {
        let dir = tempfile::tempdir().unwrap();
        for item in [
            json!({"kind":"extension","path":"a"}),
            json!({"kind":"skill","path":"../a"}),
            json!({"kind":"prompt","path":"a","execute":true}),
        ] {
            assert!(
                compile_policy(&json!({"resources":{"a":item}}), dir.path(), dir.path()).is_err()
            );
        }
        let compiled = compile_policy(
            &json!({"resources":{"a":{"kind":"instruction","path":"AGENTS.md"}}}),
            dir.path(),
            dir.path(),
        )
        .unwrap();
        assert_eq!(compiled["resources"]["a"]["maxBytes"], 16384);
    }
    #[test]
    fn resources_read_checks_digest_links_encoding_and_budget() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("a"), "instructions").unwrap();
        let raw=compile_policy(&json!({"resources":{"a":{"kind":"instruction","path":"a","sha256":hex::encode(Sha256::digest(b"instructions"))}}}),dir.path(),&root).unwrap();
        let grant = Grant {
            root: root.clone(),
            raw,
            tools: ["resourceRead".into(), "resourceList".into()].into(),
            master_id: "a".into(),
            workspace_id: "dev".into(),
            epoch: 1,
        };
        let task = json!({"tool":"resourceRead","args":{"resource":"a"}});
        assert_eq!(
            read_resource(&task, &grant, &|| Ok(())).unwrap()["text"],
            "instructions"
        );
        std::fs::write(root.join("a"), "changed").unwrap();
        assert_eq!(
            read_resource(&task, &grant, &|| Ok(())).unwrap_err().code,
            "RESOURCE_CHANGED"
        );
        std::fs::remove_file(root.join("a")).unwrap();
        symlink("../outside", root.join("a")).unwrap();
        assert_eq!(
            read_resource(&task, &grant, &|| Ok(())).unwrap_err().code,
            "PATH_DENIED"
        );
        std::fs::remove_file(root.join("a")).unwrap();
        std::fs::write(root.join("a"), [255]).unwrap();
        let mut unpinned = grant.clone();
        unpinned.raw["resources"]["a"]
            .as_object_mut()
            .unwrap()
            .remove("sha256");
        assert_eq!(
            read_resource(&task, &unpinned, &|| Ok(()))
                .unwrap_err()
                .code,
            "INVALID_ENCODING"
        );
        std::fs::write(root.join("a"), "oversized").unwrap();
        unpinned.raw["resources"]["a"]["maxBytes"] = json!(1);
        assert_eq!(
            read_resource(&task, &unpinned, &|| Ok(()))
                .unwrap_err()
                .code,
            "RESOURCE_TOO_LARGE"
        );
    }
    #[test]
    fn resources_list_is_acl_filtered_and_never_exposes_local_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut raw=compile_policy(&json!({"resources":{"public":{"kind":"prompt","path":"public/task.md"},"private":{"kind":"skill","path":"private/secret.md"}}}),dir.path(),dir.path()).unwrap();
        raw["directories"] = json!([{"path":"public","read":true,"write":false}]);
        let grant = Grant {
            root: dir.path().into(),
            raw,
            tools: ["resourceList".into(), "resourceRead".into()].into(),
            master_id: "a".into(),
            workspace_id: "dev".into(),
            epoch: 1,
        };
        let list = run_checked(
            &json!({"tool":"resourceList","args":{}}),
            &grant,
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(list["resources"].as_array().unwrap().len(), 1);
        assert_eq!(list["resources"][0]["id"], "public");
        assert!(list["resources"][0].get("path").is_none());
        assert_eq!(
            run_checked(
                &json!({"tool":"resourceRead","args":{"resource":"private"}}),
                &grant,
                &|| Ok(())
            )
            .unwrap_err()
            .code,
            "DIRECTORY_DENIED"
        );
        let mut denied = grant.clone();
        denied.tools.clear();
        assert_eq!(
            run_checked(&json!({"tool":"resourceList","args":{}}), &denied, &|| Ok(
                ()
            ))
            .unwrap_err()
            .code,
            "TOOL_DENIED"
        );
    }
}
