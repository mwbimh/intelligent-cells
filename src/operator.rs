//! Loopback owner console. No owner capability is written to logs.
use crate::{IcError, Result, node::Node};
use serde_json::{Value, json};
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    net::UnixListener,
};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn err(code: &str, message: &str) -> IcError {
    IcError::new(code, message)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn secret() -> Result<String> {
    let mut b = [0u8; 32];
    openssl::rand::rand_bytes(&mut b).map_err(|e| err("RANDOM_ERROR", &e.to_string()))?;
    Ok(hex::encode(b))
}
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && openssl::memcmp::eq(a.as_bytes(), b.as_bytes())
}
fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || fs::canonicalize(path)? != path
    {
        return Err(err(
            "UNSAFE_OWNER_DIRECTORY",
            "Owner directory must be canonical, owned and 0700",
        ));
    }
    Ok(())
}
fn private_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m)
            if !m.is_file()
                || m.file_type().is_symlink()
                || m.nlink() != 1
                || m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o077 != 0 =>
        {
            Err(err(
                "UNSAFE_OWNER_FILE",
                "File must be private regular owner file",
            ))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
const AUDIT_KEYS: &[&str] = &[
    "timestamp",
    "nodeId",
    "pid",
    "event",
    "masterId",
    "peerId",
    "taskId",
    "requestId",
    "command",
    "ok",
    "status",
    "state",
    "code",
    "tool",
    "epoch",
    "active",
    "port",
    "transport",
    "delayMs",
    "timeoutMs",
    "count",
    "resolution",
];
fn bounded_metadata(s: &str, budget: usize) -> String {
    let mut out = String::new();
    let mut bytes = 0;
    for c in s.chars().filter(|c| !c.is_control()) {
        let cost = if c == '"' || c == '\\' {
            2
        } else {
            c.len_utf8()
        };
        if bytes + cost > budget {
            break;
        }
        bytes += cost;
        out.push(c);
    }
    out
}
pub fn redact_audit(value: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for key in AUDIT_KEYS {
        if let Some(v) = value.get(*key) {
            let v = match v {
                Value::String(s) => Value::String(bounded_metadata(s, 160)),
                Value::Null | Value::Bool(_) | Value::Number(_) => v.clone(),
                _ => continue,
            };
            out.insert(key.to_string(), v);
        }
    }
    if let Some(code) = value["error"]["code"].as_str() {
        out.insert("code".into(), json!(bounded_metadata(code, 80)));
    }
    for key in [
        "elapsedMs",
        "exitCode",
        "pairingPort",
        "peerCount",
        "grantCount",
        "toolCount",
    ] {
        if value[key].is_number() {
            out.insert(key.into(), value[key].clone());
        }
    }
    for key in ["replayed", "background", "outcomeUnknown"] {
        if value[key].is_boolean() {
            out.insert(key.into(), value[key].clone());
        }
    }
    for key in ["direction", "host", "pairingHost", "remoteAddr"] {
        if let Some(text) = value[key].as_str() {
            out.insert(key.into(), json!(bounded_metadata(text, 80)));
        }
    }
    out.insert("payloadRedacted".into(), json!(true));
    Value::Object(out)
}
pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
    retention: usize,
    lock: Mutex<()>,
}
impl AuditLog {
    pub fn new(path: &Path, max_bytes: u64, retention: usize) -> Result<Self> {
        if !path.is_absolute()
            || !(1024..=67108864).contains(&max_bytes)
            || !(1..=32).contains(&retention)
        {
            return Err(err("INVALID_CONFIG", "Invalid audit bounds"));
        }
        private_dir(path.parent().unwrap())?;
        let a = Self {
            path: path.into(),
            max_bytes,
            retention,
            lock: Mutex::new(()),
        };
        for i in 0..=retention {
            private_file(&a.file(i))?
        }
        Ok(a)
    }
    fn file(&self, i: usize) -> PathBuf {
        if i == 0 {
            self.path.clone()
        } else {
            PathBuf::from(format!("{}.{}", self.path.display(), i))
        }
    }
    pub fn append(&self, value: &Value) -> Result<()> {
        let _g = self.lock.lock().unwrap();
        let mut bytes = serde_json::to_vec(&redact_audit(value))?;
        bytes.push(b'\n');
        private_file(&self.path)?;
        let size = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if size > 0 && size + bytes.len() as u64 > self.max_bytes {
            for i in (1..=self.retention).rev() {
                let from = self.file(i - 1);
                let to = self.file(i);
                private_file(&from)?;
                private_file(&to)?;
                if i == self.retention && to.exists() {
                    fs::remove_file(&to)?
                }
                if from.exists() {
                    fs::rename(from, to)?
                }
            }
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?;
        let m = f.metadata()?;
        if m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err(err("UNSAFE_OWNER_FILE", "Unsafe audit file"));
        }
        f.write_all(&bytes)?;
        f.sync_all()?;
        Ok(())
    }
    pub fn query(&self, args: &Value) -> Result<Value> {
        let _g = self.lock.lock().unwrap();
        let limit = args["limit"].as_u64().unwrap_or(100) as usize;
        if !(1..=500).contains(&limit) {
            return Err(err("INVALID_ARGUMENT", "Audit limit must be 1..500"));
        }
        let mut records = vec![];
        for i in 0..=self.retention {
            let p = self.file(i);
            private_file(&p)?;
            if !p.exists() {
                continue;
            }
            let f = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(p)?;
            if f.metadata()?.len() > self.max_bytes + 4096 {
                return Err(err("AUDIT_TOO_LARGE", "Audit file exceeds bounds"));
            }
            let text = std::io::read_to_string(f)?;
            for line in text.lines().rev() {
                if let Ok(v) = serde_json::from_str::<Value>(line) {
                    if ["event", "taskId"]
                        .iter()
                        .any(|k| args[*k].is_string() && args[*k] != v[*k])
                        || args["peerId"].is_string()
                            && args["peerId"] != v["peerId"]
                            && args["peerId"] != v["masterId"]
                    {
                        continue;
                    }
                    records.push(redact_audit(&v));
                    if records.len() == limit {
                        break;
                    }
                }
            }
            if records.len() == limit {
                break;
            }
        }
        Ok(
            json!({"records":records,"limit":limit,"newestFirst":true,"retentionFiles":self.retention+1,"payloadRedacted":true}),
        )
    }
}
struct Session {
    csrf: String,
    until: u64,
}
struct Auth {
    tokens: BTreeMap<String, u64>,
    sessions: BTreeMap<String, Session>,
    bad: Vec<u64>,
    ttl: u64,
}
impl Auth {
    fn mint(&mut self) -> Result<String> {
        self.tokens.retain(|_, t| *t > now());
        if self.tokens.len() >= 8 {
            let k = self.tokens.keys().next().unwrap().clone();
            self.tokens.remove(&k);
        }
        let token = secret()?;
        self.tokens.insert(token.clone(), now() + 300000);
        Ok(token)
    }
    fn login(&mut self, token: &str) -> Result<(String, String, u64)> {
        self.bad.retain(|t| now() - *t < 60000);
        if self.bad.len() >= 20 {
            return Err(err("RATE_LIMITED", "Too many failed sign-ins"));
        }
        let key = self
            .tokens
            .iter()
            .find(|(k, t)| **t > now() && same(k, token))
            .map(|(k, _)| k.clone());
        let Some(key) = key else {
            self.bad.push(now());
            return Err(err(
                "UNAUTHENTICATED",
                "Owner token invalid, expired or used",
            ));
        };
        self.tokens.remove(&key);
        self.sessions.retain(|_, s| s.until > now());
        if self.sessions.len() >= 8 {
            let k = self.sessions.keys().next().unwrap().clone();
            self.sessions.remove(&k);
        }
        let sid = secret()?;
        let csrf = secret()?;
        let until = now() + self.ttl;
        self.sessions.insert(
            sid.clone(),
            Session {
                csrf: csrf.clone(),
                until,
            },
        );
        Ok((sid, csrf, until))
    }
}
fn validate_public_ui_root(node: &Node, root: &Path) -> Result<()> {
    let config = node.config();
    let mut protected = vec![config.path.clone(), config.state_dir.clone()];
    for field in ["nodesFile", "mcpFile", "logFile"] {
        if let Some(path) = config.raw[field].as_str() {
            protected.push(absolute(&config.path, path)?);
        }
    }
    for field in ["cert", "key", "ca"] {
        if let Some(path) = config.raw["security"][field].as_str() {
            protected.push(absolute(&config.path, path)?);
        }
    }
    if let Some(path) = config.raw["operator"]["sessionDirectory"].as_str() {
        protected.push(absolute(&config.path, path)?);
    }
    if let Some(path) = config.raw["operator"]["socketPath"].as_str() {
        let socket = absolute(&config.path, path)?;
        if let Some(parent) = socket.parent() {
            protected.push(parent.to_path_buf());
        }
    }
    if let Some(settings) = crate::rsync::Settings::parse(&config.raw)? {
        protected.push(settings.file);
    }
    fn collect_roots(config: &Path, value: &Value, paths: &mut Vec<PathBuf>) -> Result<()> {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    if matches!(key.as_str(), "root" | "path")
                        && let Some(path) = value.as_str()
                    {
                        paths.push(absolute(config, path)?);
                    }
                    collect_roots(config, value, paths)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    collect_roots(config, value, paths)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    let permissions = node.command(&json!({"command":"permissions"}))?;
    collect_roots(
        &config.path,
        &permissions["effectivePolicy"],
        &mut protected,
    )?;
    let workspaces = node.command(&json!({"command":"listLocalWorkspaces"}))?;
    collect_roots(&config.path, &workspaces, &mut protected)?;
    for path in protected {
        let canonical = if path.exists() {
            fs::canonicalize(&path)?
        } else {
            path.clone()
        };
        if crate::policy::paths_overlap(root, &path)
            || crate::policy::paths_overlap(root, &canonical)
        {
            return Err(err(
                "UNSAFE_UI_ROOT",
                "Public UI root must be separate from config, identities, state, logs, owner access and workspaces",
            ));
        }
    }
    Ok(())
}

// Open each path component relative to a directory descriptor so a concurrently
// replaced symlink cannot redirect a static request outside the selected root.
struct WebAssets {
    directory: fs::File,
    entry: String,
}
impl WebAssets {
    fn open_child(
        directory: &fs::File,
        name: &std::ffi::OsStr,
        directory_only: bool,
    ) -> Result<fs::File> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        };
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| err("INVALID_PATH", "NUL in asset path"))?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if directory_only { libc::O_DIRECTORY } else { 0 };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(err(
                "INVALID_PATH",
                "Asset is unavailable or contains a link",
            ));
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
    fn from_config(opts: &Value) -> Result<Option<Self>> {
        if opts.get("uiRoot").is_none() {
            if opts.get("entry").is_some() {
                return Err(err(
                    "INVALID_CONFIG",
                    "operator.entry requires operator.uiRoot",
                ));
            }
            return Ok(None);
        }
        let root = opts["uiRoot"].as_str().ok_or_else(|| {
            err(
                "INVALID_CONFIG",
                "operator.uiRoot must be an absolute directory",
            )
        })?;
        let root = Path::new(root);
        crate::files::inspect_root(root)?;
        let entry = match opts.get("entry") {
            None => "index.html",
            Some(value) => value.as_str().ok_or_else(|| {
                err(
                    "INVALID_CONFIG",
                    "operator.entry must be a relative HTML path",
                )
            })?,
        };
        crate::policy::relative_path(entry)?;
        if !matches!(
            Path::new(entry).extension().and_then(|v| v.to_str()),
            Some("html" | "htm")
        ) || entry.starts_with("api/")
            || entry.contains('%')
        {
            return Err(err(
                "INVALID_CONFIG",
                "operator.entry must be a relative HTML path outside /api",
            ));
        }
        let mut directory = fs::File::open("/")?;
        for component in root.components() {
            if let std::path::Component::Normal(name) = component {
                directory = Self::open_child(&directory, name, true)?;
            }
        }
        let assets = Self {
            directory,
            entry: entry.into(),
        };
        assets.read(entry)?;
        Ok(Some(assets))
    }
    fn read(&self, relative: &str) -> Result<Vec<u8>> {
        crate::policy::relative_path(relative)?;
        if relative.contains('%') || relative.contains('#') {
            return Err(err("INVALID_PATH", "Encoded asset paths are not supported"));
        }
        let mut directory = self.directory.try_clone()?;
        let mut components = Path::new(relative).components().peekable();
        while let Some(component) = components.next() {
            directory = Self::open_child(
                &directory,
                component.as_os_str(),
                components.peek().is_some(),
            )?;
        }
        let metadata = directory.metadata()?;
        const LIMIT: u64 = 8 * 1024 * 1024;
        if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > LIMIT {
            return Err(err(
                "INVALID_PATH",
                "Asset must be a regular single-link file of at most 8 MiB",
            ));
        }
        let mut bytes = Vec::new();
        directory.take(LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > LIMIT {
            return Err(err("INVALID_PATH", "Asset exceeds 8 MiB"));
        }
        Ok(bytes)
    }
    fn response(&self, path: &str) -> Result<HttpResponse> {
        let relative = if path == "/" { &self.entry } else { &path[1..] };
        let bytes = self.read(relative)?;
        let mime = match Path::new(relative).extension().and_then(|v| v.to_str()) {
            Some("html" | "htm") => "text/html; charset=utf-8",
            Some("js" | "mjs") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json" | "map") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("webp") => "image/webp",
            Some("ico") => "image/x-icon",
            Some("woff2") => "font/woff2",
            Some("txt") => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        };
        Ok((200, bytes, vec![("Content-Type".into(), mime.into())]))
    }
}
pub(crate) fn validate_assets(opts: &Value) -> Result<()> {
    WebAssets::from_config(opts).map(|_| ())
}

struct State {
    node: Arc<Node>,
    web: Option<WebAssets>,
    origin: String,
    auth: Mutex<Auth>,
    owner_secret: Option<String>,
    mutation: Mutex<()>,
    closed: AtomicBool,
}
pub struct OperatorHandle {
    state: Arc<State>,
    stop: Arc<AtomicBool>,
    owner_file: Option<PathBuf>,
    socket: Option<PathBuf>,
    http: Option<thread::JoinHandle<()>>,
    ipc: Option<thread::JoinHandle<()>>,
    bootstrap: String,
}
impl OperatorHandle {
    pub fn info(&self) -> Value {
        json!({"url":self.state.origin,"bootstrapToken":self.bootstrap,"ownerFile":self.owner_file,"socketPath":self.socket})
    }
    pub fn shutdown(&mut self) -> Result<()> {
        self.state.closed.store(true, Ordering::SeqCst);
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.http.take() {
            let _ = h.join();
        }
        if let Some(h) = self.ipc.take() {
            let _ = h.join();
        }
        for p in [&self.owner_file, &self.socket].into_iter().flatten() {
            if p.exists() {
                fs::remove_file(p)?
            }
        }
        let mut a = self.state.auth.lock().unwrap();
        a.tokens.clear();
        a.sessions.clear();
        Ok(())
    }
}
impl Drop for OperatorHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
const COMMANDS: &[&str] = &[
    "nodesList",
    "nodesStatus",
    "nodesRename",
    "nodesBind",
    "nodesUnbind",
    "listSessions",
    "mcpListTools",
    "mcpRegistry",
    "sessionOpen",
    "sessionDetach",
    "sessionDispatch",
    "sessionMcp",
    "mcpCallTool",
    "pairingStatus",
    "listPeers",
    "listPairingRequests",
    "pairingRequest",
    "pairingApprove",
    "pairingReject",
    "pairingConfirm",
    "unpair",
    "recoverWorkspaceLock",
    "listLocalWorkspaces",
    "bindLocalWorkspace",
    "unbindLocalWorkspace",
    "setWorkspaceSyncScope",
    "listWorkspaceBindings",
    "remoteWorkspaces",
    "bindWorkspace",
    "unbindWorkspace",
    "setWorkspaceAutoProvision",
    "ensureWorkspaceBinding",
    "createWorkspace",
    "reconcileWorkspaceCreation",
    "status",
    "permissions",
    "listTasks",
    "taskStatus",
    "taskEvents",
    "operationStatus",
    "query",
    "cancel",
    "reconcile",
    "revoke",
    "reloadPolicy",
    "setPolicy",
    "shutdown",
    "cancelTask",
    "listJobs",
    "jobStatus",
    "jobCancel",
    "reconcileJob",
    "jobOutput",
];
const READ_ONLY: &[&str] = &[
    "nodesList",
    "nodesStatus",
    "listSessions",
    "mcpListTools",
    "pairingStatus",
    "listPeers",
    "listPairingRequests",
    "listLocalWorkspaces",
    "listWorkspaceBindings",
    "remoteWorkspaces",
    "status",
    "permissions",
    "listTasks",
    "taskStatus",
    "taskEvents",
    "operationStatus",
    "query",
    "listJobs",
    "jobStatus",
    "jobOutput",
];
struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
fn parse_request(bytes: &[u8]) -> Result<Request> {
    let end = bytes
        .windows(4)
        .position(|s| s == b"\r\n\r\n")
        .ok_or_else(|| err("INVALID_REQUEST", "Missing headers"))?;
    if end > 16384 {
        return Err(err("BODY_TOO_LARGE", "Headers exceed bounds"));
    }
    let head = std::str::from_utf8(&bytes[..end])
        .map_err(|_| err("INVALID_REQUEST", "Invalid header UTF8"))?;
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap();
    let words: Vec<_> = first.split(' ').collect();
    if words.len() != 3 || words[2] != "HTTP/1.1" {
        return Err(err("INVALID_REQUEST", "HTTP/1.1 required"));
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| err("INVALID_REQUEST", "Invalid header"))?;
        if k.is_empty() || k.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-') {
            return Err(err("INVALID_REQUEST", "Invalid header name"));
        }
        if headers
            .insert(k.to_ascii_lowercase(), v.trim().to_string())
            .is_some()
        {
            return Err(err("INVALID_REQUEST", "Duplicate headers"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(err("INVALID_REQUEST", "Chunked requests unsupported"));
    }
    let n = headers
        .get("content-length")
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|_| err("INVALID_REQUEST", "Invalid body length"))?
        .unwrap_or(0);
    if n > 65536 {
        return Err(err("BODY_TOO_LARGE", "Body exceeds 64 KiB"));
    }
    let body = bytes[end + 4..].to_vec();
    if body.len() != n {
        return Err(err("INVALID_REQUEST", "Body length mismatch"));
    }
    Ok(Request {
        method: words[0].into(),
        path: words[1].into(),
        headers,
        body,
    })
}
fn json_body(r: &Request) -> Result<Value> {
    let ct = r
        .headers
        .get("content-type")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    if ct != "application/json" && ct != "application/json; charset=utf-8" {
        return Err(err("CONTENT_TYPE", "Use application/json"));
    }
    let v: Value = serde_json::from_slice(&r.body)?;
    if !v.is_object() {
        return Err(err("INVALID_JSON", "Expected object"));
    }
    Ok(v)
}
type HttpResponse = (u16, Vec<u8>, Vec<(String, String)>);
fn handle(state: &State, r: Request) -> Result<HttpResponse> {
    if state.closed.load(Ordering::SeqCst) {
        return Err(err("OPERATOR_CLOSED", "Operator is shut down"));
    }
    let host = state.origin.trim_start_matches("http://");
    if r.headers.get("host").map(String::as_str) != Some(host) {
        return Err(err("INVALID_HOST", "Host does not match local operator"));
    }
    if r.headers.get("origin").is_some_and(|s| s != &state.origin)
        || r.headers
            .get("sec-fetch-site")
            .is_some_and(|s| s != "same-origin" && s != "none")
    {
        return Err(err("INVALID_ORIGIN", "Cross origin request denied"));
    }
    if !r.path.starts_with('/') || r.path.contains('?') {
        return Err(err("INVALID_PATH", "Unexpected path"));
    }
    let mut extra = vec![];
    if r.method == "GET" {
        if let Some(web) = &state.web
            && r.path != "/api"
            && !r.path.starts_with("/api/")
        {
            return web.response(&r.path);
        }
        let asset = match r.path.as_str() {
            "/" => Some((
                include_bytes!("../ui/index.html").as_slice(),
                "text/html; charset=utf-8",
            )),
            "/app.js" => Some((
                include_bytes!("../ui/app.js").as_slice(),
                "text/javascript; charset=utf-8",
            )),
            "/app.css" => Some((
                include_bytes!("../ui/app.css").as_slice(),
                "text/css; charset=utf-8",
            )),
            _ => None,
        };
        if let Some((bytes, mime)) = asset {
            return Ok((
                200,
                bytes.to_vec(),
                vec![("Content-Type".into(), mime.into())],
            ));
        }
    }
    if r.method != "GET" && r.method != "POST" {
        return Err(err("INVALID_METHOD", "Only GET/POST supported"));
    }
    if r.method == "POST" && r.headers.get("origin") != Some(&state.origin) {
        return Err(err("INVALID_ORIGIN", "Exact origin required"));
    }
    let value = if r.method == "POST" && r.path == "/api/ownerSession" {
        let v = json_body(&r)?;
        if !state
            .owner_secret
            .as_ref()
            .is_some_and(|s| same(s, v["secret"].as_str().unwrap_or("")))
        {
            return Err(err("UNAUTHENTICATED", "Owner capability required"));
        }
        let t = state.auth.lock().unwrap().mint()?;
        json!({"ok":true,"url":format!("{}/#token={t}",state.origin),"expiresInSeconds":300})
    } else if r.method == "POST" && r.path == "/api/session" {
        let v = json_body(&r)?;
        let (sid, csrf, until) = state
            .auth
            .lock()
            .unwrap()
            .login(v["token"].as_str().unwrap_or(""))?;
        extra.push((
            "Set-Cookie".into(),
            format!(
                "op_sid={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                state.auth.lock().unwrap().ttl / 1000
            ),
        ));
        json!({"ok":true,"csrf":csrf,"expiresAt":until})
    } else {
        let sid = r
            .headers
            .get("cookie")
            .and_then(|s| s.split(';').find_map(|c| c.trim().strip_prefix("op_sid=")))
            .unwrap_or("")
            .to_string();
        let (csrf, expires_at) = {
            let a = state.auth.lock().unwrap();
            let s = a
                .sessions
                .get(&sid)
                .filter(|s| s.until > now())
                .ok_or_else(|| err("UNAUTHENTICATED", "Local owner sign-in required"))?;
            if r.method == "POST"
                && !same(
                    &s.csrf,
                    r.headers
                        .get("x-operator-csrf")
                        .map(String::as_str)
                        .unwrap_or(""),
                )
            {
                return Err(err("CSRF_DENIED", "Valid CSRF token required"));
            }
            (s.csrf.clone(), s.until)
        };
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/api/session") => json!({"ok":true,"csrf":csrf,"expiresAt":expires_at}),
            ("POST", "/api/logout") => {
                state.auth.lock().unwrap().sessions.remove(&sid);
                extra.push((
                    "Set-Cookie".into(),
                    "op_sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".into(),
                ));
                json!({"ok":true})
            }
            ("GET", "/api/state") => {
                json!({"ok":true,"status":state.node.command(&json!({"command":"status"}))?,"permissions":state.node.command(&json!({"command":"permissions"}))?,"incoming":state.node.command(&json!({"command":"listTasks","kind":"incoming","limit":100}))?,"outgoing":state.node.command(&json!({"command":"listTasks","kind":"outgoing","limit":100}))?,"jobs":state.node.command(&json!({"command":"listJobs","limit":100}))?,"workspaces":state.node.command(&json!({"command":"listWorkspaceBindings"}))?,"localWorkspaces":state.node.command(&json!({"command":"listLocalWorkspaces"}))?,"identity":identity_summary(&state.node)?})
            }
            ("GET", "/api/logs") => state
                .node
                .command(&json!({"command":"auditLogs","limit":100}))?,
            ("POST", "/api/command") => {
                let v = json_body(&r)?;
                let name = v["command"].as_str().unwrap_or("");
                reject_removed_identity_command(name)?;
                if !COMMANDS.contains(&name) {
                    return Err(err("INVALID_COMMAND", "Unavailable operator command"));
                }
                let _g = if !READ_ONLY.contains(&name) {
                    Some(state.mutation.lock().unwrap())
                } else {
                    None
                };
                if state.closed.load(Ordering::SeqCst) {
                    return Err(err("OPERATOR_CLOSED", "Operator is shut down"));
                }
                let result = owner_command(&state.node, &v)?;
                json!({"ok":true,"result":result})
            }
            _ => {
                return Ok((
                    404,
                    serde_json::to_vec(
                        &json!({"ok":false,"error":{"code":"NOT_FOUND","message":"Not found"}}),
                    )?,
                    extra,
                ));
            }
        }
    };
    Ok((200, serde_json::to_vec(&value)?, extra))
}
fn connection(mut stream: TcpStream, state: Arc<State>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let result = (|| -> Result<_> {
        if !stream.peer_addr()?.ip().is_loopback() {
            return Err(err("LOCAL_ONLY", "Loopback only"));
        }
        let mut bytes = vec![];
        let mut buf = [0u8; 4096];
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| err("REQUEST_TIMEOUT", "Operator request deadline exceeded"))?;
            stream.set_read_timeout(Some(remaining))?;
            let n = stream.read(&mut buf)?;
            if n == 0 {
                return Err(err("INVALID_REQUEST", "Incomplete request"));
            }
            bytes.extend_from_slice(&buf[..n]);
            if bytes.len() > 81920 {
                return Err(err("BODY_TOO_LARGE", "Request exceeds bounds"));
            }
            if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                let head = std::str::from_utf8(&bytes[..end])
                    .map_err(|_| err("INVALID_REQUEST", "Invalid UTF8"))?;
                let len = head
                    .split("\r\n")
                    .skip(1)
                    .find_map(|l| {
                        l.split_once(':')
                            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse::<usize>())
                    })
                    .transpose()
                    .map_err(|_| err("INVALID_REQUEST", "Invalid length"))?
                    .unwrap_or(0);
                if len > 65536 {
                    return Err(err("BODY_TOO_LARGE", "Body exceeds limit"));
                }
                if bytes.len() >= end + 4 + len {
                    break;
                }
            }
        }
        handle(&state, parse_request(&bytes)?)
    })();
    let (status, body, extra) = match result {
        Ok(v) => v,
        Err(e) => {
            let status = if [
                "UNAUTHENTICATED",
                "CSRF_DENIED",
                "INVALID_HOST",
                "INVALID_ORIGIN",
                "LOCAL_ONLY",
            ]
            .contains(&e.code.as_str())
            {
                403
            } else if e.code == "RATE_LIMITED" {
                429
            } else {
                400
            };
            (status,serde_json::to_vec(&json!({"ok":false,"error":{"code":e.code,"message":e.message.chars().take(400).collect::<String>()}})).unwrap(),vec![])
        }
    };
    let mut headers = format!(
        "HTTP/1.1 {status} OK\r\nConnection: close\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nX-Frame-Options: DENY\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n",
        body.len()
    );
    if !extra.iter().any(|(k, _)| k == "Content-Type") {
        headers.push_str("Content-Type: application/json; charset=utf-8\r\n")
    }
    for (k, v) in extra {
        headers.push_str(&format!("{k}: {v}\r\n"))
    }
    headers.push_str("\r\n");
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(&body);
}
struct ArtifactCleanup(Vec<PathBuf>);
impl Drop for ArtifactCleanup {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}
pub fn start(node: Arc<Node>) -> Result<OperatorHandle> {
    let mut cleanup = ArtifactCleanup(vec![]);
    let config = node.config();
    let opts = &config.raw["operator"];
    if let Some(root) = opts["uiRoot"].as_str() {
        validate_public_ui_root(&node, Path::new(root))?;
    }
    let web = WebAssets::from_config(opts)?;
    if opts["host"].as_str().is_some_and(|s| s != "127.0.0.1") {
        return Err(err(
            "OPERATOR_LOOPBACK_ONLY",
            "Operator binds 127.0.0.1 only",
        ));
    }
    let port = opts["port"].as_u64().unwrap_or(0);
    let ttl = opts["sessionTtlMs"].as_u64().unwrap_or(1800000);
    if port > 65535 || !(1000..=3600000).contains(&ttl) {
        return Err(err("INVALID_CONFIG", "Invalid operator port or TTL"));
    }
    let listener = TcpListener::bind(("127.0.0.1", port as u16))?;
    listener.set_nonblocking(true)?;
    let origin = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let mut auth = Auth {
        tokens: BTreeMap::new(),
        sessions: BTreeMap::new(),
        bad: vec![],
        ttl,
    };
    let bootstrap = auth.mint()?;
    let owner_secret = opts["sessionDirectory"]
        .as_str()
        .map(|_| secret())
        .transpose()?;
    let owner_file = if let Some(d) = opts["sessionDirectory"].as_str() {
        let directory = absolute(&config.path, d)?;
        private_dir(&directory)?;
        let p = directory.join(format!(
            "operator-{}-{}.json",
            std::process::id(),
            &secret()?[..12]
        ));
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&p)?;
        cleanup.0.push(p.clone());
        f.write_all(&serde_json::to_vec(&json!({"url":origin,"secret":owner_secret,"pid":std::process::id(),"createdAt":now(),"ephemeral":true}))?)?;
        f.sync_all()?;
        Some(p)
    } else {
        None
    };
    let state = Arc::new(State {
        node,
        web,
        origin,
        auth: Mutex::new(auth),
        owner_secret,
        mutation: Mutex::new(()),
        closed: AtomicBool::new(false),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let socket = opts["socketPath"]
        .as_str()
        .map(|s| absolute(&config.path, s))
        .transpose()?;
    let ipc = if let Some(p) = &socket {
        private_dir(p.parent().unwrap())?;
        if fs::symlink_metadata(p).is_ok() {
            return Err(err(
                "OPERATOR_SOCKET_EXISTS",
                "Owner socket exists; do not replace it",
            ));
        }
        let l = UnixListener::bind(p)?;
        cleanup.0.push(p.clone());
        fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
        l.set_nonblocking(true)?;
        let s = state.clone();
        let done = stop.clone();
        Some(thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                match l.accept() {
                    Ok((mut c, _)) => {
                        let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = c.set_write_timeout(Some(Duration::from_secs(5)));
                        let mut line = String::new();
                        let result = BufReader::new((&mut c).take(1025)).read_line(&mut line);
                        let v = if result.is_ok()
                            && line.len() <= 1024
                            && line.ends_with('\n')
                            && serde_json::from_str::<Value>(&line)
                                .is_ok_and(|v| v["command"] == "operatorSession")
                        {
                            s.auth.lock().unwrap().mint().map(|t|json!({"url":format!("{}/#token={t}",s.origin),"expiresInSeconds":300})).unwrap_or(json!({"error":"Mint failed"}))
                        } else {
                            json!({"error":"Invalid owner IPC command"})
                        };
                        let _ = writeln!(c, "{v}");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => break,
                }
            }
        }))
    } else {
        None
    };
    let s = state.clone();
    let done = stop.clone();
    let active = Arc::new(AtomicUsize::new(0));
    let http = thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((c, _)) => {
                    if active.fetch_add(1, Ordering::SeqCst) >= 32 {
                        active.fetch_sub(1, Ordering::SeqCst);
                        drop(c);
                        continue;
                    }
                    let s = s.clone();
                    let count = active.clone();
                    thread::spawn(move || {
                        connection(c, s);
                        count.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(_) => break,
            }
        }
    });
    cleanup.0.clear();
    Ok(OperatorHandle {
        state,
        stop,
        owner_file,
        socket,
        http: Some(http),
        ipc,
        bootstrap,
    })
}
fn absolute(config: &Path, s: &str) -> Result<PathBuf> {
    let p = PathBuf::from(s);
    let p = if p.is_absolute() {
        p
    } else {
        config.parent().unwrap_or(Path::new(".")).join(p)
    };
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(err(
            "UNSAFE_OWNER_DIRECTORY",
            "Parent path components rejected",
        ));
    }
    Ok(p)
}
fn read_cert(config: &crate::Config, key: &str) -> Result<Vec<u8>> {
    let s = config.raw["security"][key]
        .as_str()
        .ok_or_else(|| err("SECURITY_REQUIRED", "Certificate path required"))?;
    Ok(fs::read(
        config.path.parent().unwrap_or(Path::new(".")).join(s),
    )?)
}
fn normalize_pin(s: &str) -> Result<String> {
    let s = s.replace(':', "").to_ascii_uppercase();
    if s.len() != 64 || hex::decode(&s).is_err() {
        return Err(err("INVALID_FINGERPRINT", "SHA256 fingerprint required"));
    }
    Ok(s)
}
fn expiry(cert: &openssl::x509::X509Ref) -> Result<(i64, bool)> {
    let time =
        openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| err("TLS_ERROR", &e.to_string()))?;
    let diff = time
        .diff(cert.not_after())
        .map_err(|e| err("TLS_ERROR", &e.to_string()))?;
    let seconds = diff.days as i64 * 86400 + diff.secs as i64;
    Ok((seconds / 86400, seconds < 30 * 86400))
}
pub fn review_identity(pem: &str, id: &str, pin: &str, ca: &[u8]) -> Result<Value> {
    use openssl::{
        stack::Stack,
        x509::{X509, X509StoreContext, store::X509StoreBuilder},
    };
    if pem.len() > 32768 {
        return Err(err("INVALID_CERTIFICATE", "Certificate exceeds 32 KiB"));
    }
    let cert =
        X509::from_pem(pem.as_bytes()).map_err(|e| err("INVALID_CERTIFICATE", &e.to_string()))?;
    let own = crate::tls::certificate_identity(pem.as_bytes())?;
    if own["nodeId"] != id {
        return Err(err("IDENTITY_MISMATCH", "Peer CN mismatch"));
    }
    if own["fingerprint256"] != normalize_pin(pin)? {
        return Err(err("PIN_MISMATCH", "Independent fingerprint mismatch"));
    }
    let mut store = X509StoreBuilder::new().map_err(|e| err("TLS_ERROR", &e.to_string()))?;
    let roots = X509::stack_from_pem(ca).map_err(|e| err("UNTRUSTED_CA", &e.to_string()))?;
    let mut issuer = false;
    for root in roots {
        let public_key = root
            .public_key()
            .map_err(|e| err("TLS_ERROR", &e.to_string()))?;
        if root.issued(&cert) == openssl::x509::X509VerifyResult::OK
            && cert.verify(&public_key).unwrap_or(false)
        {
            issuer = true
        }
        store
            .add_cert(root)
            .map_err(|e| err("UNTRUSTED_CA", &e.to_string()))?;
    }
    let mut ctx = X509StoreContext::new().map_err(|e| err("TLS_ERROR", &e.to_string()))?;
    let chain = Stack::new().map_err(|e| err("TLS_ERROR", &e.to_string()))?;
    let trusted = ctx
        .init(&store.build(), &cert, &chain, |c| c.verify_cert())
        .map_err(|e| err("UNTRUSTED_CA", &e.to_string()))?;
    if !issuer || !trusted {
        return Err(err(
            "UNTRUSTED_CA",
            "Certificate must be directly issued by current configured CA",
        ));
    }
    let text = String::from_utf8_lossy(
        &cert
            .to_text()
            .map_err(|e| err("INVALID_CERTIFICATE", &e.to_string()))?,
    )
    .into_owned();
    if text.contains("CA:TRUE") {
        return Err(err("INVALID_CERTIFICATE", "CA cannot be paired as node"));
    }
    let mut v = own;
    let (days, soon) = expiry(&cert)?;
    v["expiresInDays"] = json!(days);
    v["expiringSoon"] = json!(soon);
    v["independentlyVerifiedPin"] = json!(true);
    Ok(v)
}
fn identity_summary(node: &Node) -> Result<Value> {
    let c = node.config();
    let pem = read_cert(&c, "cert")?;
    let mut v = crate::tls::certificate_identity(&pem)?;
    let cert = openssl::x509::X509::from_pem(&pem).map_err(|e| err("TLS_ERROR", &e.to_string()))?;
    let (days, soon) = expiry(&cert)?;
    v["expiresInDays"] = json!(days);
    v["expiringSoon"] = json!(soon);
    v["trustedPeers"]=json!(c.raw["security"]["trustedPeers"].as_object().map(|p|p.iter().map(|(id,pins)|json!({"id":id,"pins":if pins.is_array(){pins.clone()}else{json!([pins])}})).collect::<Vec<_>>()).unwrap_or_default());
    v["restartRequiredForTrustChanges"] = json!(true);
    Ok(v)
}
pub fn owner_command(node: &Arc<Node>, v: &Value) -> Result<Value> {
    let result = execute_owner_command(node, v);
    let name = v["command"]
        .as_str()
        .or_else(|| v["type"].as_str())
        .unwrap_or("");
    if !READ_ONLY.contains(&name) || result.is_err() {
        node.log("operator_command", json!({"command":name,"ok":result.is_ok(),"code":result.as_ref().err().map(|e|e.code.clone())}));
    }
    result
}
fn reject_removed_identity_command(name: &str) -> Result<()> {
    if ["reviewPeer", "pairPeer", "removePeerPin", "revokePeer"].contains(&name) {
        return Err(err(
            "REMOVED_COMMAND",
            "Manual certificate commands were removed; use ic pair for pairing and the unpair node command to remove a relationship",
        ));
    }
    Ok(())
}
fn execute_owner_command(node: &Arc<Node>, v: &Value) -> Result<Value> {
    let name = v["command"]
        .as_str()
        .or_else(|| v["type"].as_str())
        .unwrap_or("");
    for (command, field) in [
        ("setPolicy", "expectedEpoch"),
        ("bindWorkspace", "expectedRevision"),
        ("unbindWorkspace", "expectedRevision"),
        ("setWorkspaceAutoProvision", "expectedRevision"),
    ] {
        if name == command && v[field].as_u64().is_none() {
            return Err(err("POLICY_CONFLICT", "Refresh revision before mutation"));
        }
    }
    if name == "shutdown" {
        let n = node.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            let _ = n.shutdown();
        });
        return Ok(json!({"stopping":true}));
    }
    reject_removed_identity_command(name)?;
    node.command(v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_bootstrap_is_single_use_and_sessions_bounded() {
        let mut a = Auth {
            tokens: BTreeMap::new(),
            sessions: BTreeMap::new(),
            bad: vec![],
            ttl: 1000,
        };
        let t = a.mint().unwrap();
        let (sid, csrf, _) = a.login(&t).unwrap();
        assert!(!sid.is_empty() && !csrf.is_empty());
        assert_eq!(a.login(&t).unwrap_err().code, "UNAUTHENTICATED");
        for _ in 0..30 {
            let t = a.mint().unwrap();
            a.login(&t).unwrap();
        }
        assert!(a.sessions.len() <= 8 && a.tokens.len() <= 8);
    }
    #[test]
    fn audit_excludes_all_arbitrary_payload_and_rotates() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = d.path().join("audit");
        let a = AuditLog::new(&p, 1024, 2).unwrap();
        for i in 0..100 {
            a.append(&json!({"event":"done","taskId":format!("task-{i}"),"args":"SECRET","result":"SECRET","error":{"code":"SAFE","message":"SECRET"}})).unwrap();
        }
        let r = a.query(&json!({"limit":5})).unwrap();
        assert_eq!(r["records"][0]["taskId"], "task-99");
        assert_eq!(r["records"].as_array().unwrap().len(), 5);
        for entry in fs::read_dir(d.path()).unwrap() {
            let text = fs::read_to_string(entry.unwrap().path()).unwrap();
            assert!(!text.contains("SECRET"));
            assert!(text.len() < 1200);
        }
    }
    #[test]
    fn audit_unicode_metadata_stays_bounded() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let a = AuditLog::new(&d.path().join("audit"), 1024, 1).unwrap();
        let mut v = json!({});
        for key in AUDIT_KEYS {
            v[*key] = json!("界".repeat(1000));
        }
        a.append(&v).unwrap();
        assert!(a.query(&json!({"limit":1})).is_ok());
        for key in AUDIT_KEYS {
            v[*key] = json!("\"\\".repeat(1000));
        }
        a.append(&v).unwrap();
        assert!(a.query(&json!({"limit":1})).is_ok());
    }
    #[test]
    fn unsafe_owner_paths_and_hardlinks_are_denied() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            private_dir(d.path()).unwrap_err().code,
            "UNSAFE_OWNER_DIRECTORY"
        );
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = d.path().join("file");
        fs::write(&p, b"secret").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&p, d.path().join("alias")).unwrap();
        assert_eq!(private_file(&p).unwrap_err().code, "UNSAFE_OWNER_FILE");
    }
    #[test]
    fn http_parser_rejects_smuggling_and_oversize() {
        assert!(parse_request(b"POST /api/session HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}").is_err());
        assert!(
            parse_request(b"POST /api/session HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
                .is_err()
        );
    }
}
