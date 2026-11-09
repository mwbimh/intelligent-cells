use crate::{
    durable::ensure_private_dir,
    error::{IcError, Result},
    model::{Config, Grant},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
fn hash(v: &Value) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap()))
}
fn err(code: &str, message: &str) -> IcError {
    IcError::new(code, message)
}
fn identity(p: &Path, owner: bool) -> Result<Value> {
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || fs::canonicalize(p)? != p
        || owner && (m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0)
    {
        return Err(err(
            "WORKSPACE_DENIED",
            "Directory must be canonical and owner controlled",
        ));
    }
    Ok(json!({"dev":m.dev().to_string(),"ino":m.ino().to_string()}))
}
fn id(v: &Value, k: &str) -> Result<String> {
    let s = v[k]
        .as_str()
        .filter(|s| crate::policy::valid_id(s))
        .ok_or_else(|| err("INVALID_ARGS", "Invalid workspace selector"))?;
    Ok(s.into())
}
fn creation_name(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    crate::policy::valid_id(s)
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && !["con", "prn", "aux", "nul"].contains(&lower.as_str())
        && !(lower.len() == 4
            && (lower.starts_with("com") || lower.starts_with("lpt"))
            && (b'1'..=b'9').contains(&lower.as_bytes()[3]))
}
fn valid_identity(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.len() == 2)
        && v["dev"].as_str().is_some_and(|x| x.parse::<u64>().is_ok())
        && v["ino"]
            .as_str()
            .is_some_and(|x| x.parse::<u64>().is_ok_and(|n| n > 0))
}
fn valid_hash(v: &Value) -> bool {
    v.as_str().is_some_and(|x| {
        x.len() == 64
            && x.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}
fn validate_loaded(remote: &Value, local: &Value) -> Result<()> {
    let bad = || err("JOURNAL_CORRUPT", "Invalid workspace metadata");
    let mut seen = std::collections::BTreeSet::new();
    for r in remote["creations"].as_array().ok_or_else(bad)? {
        let request = r["requestId"]
            .as_str()
            .filter(|x| {
                !x.is_empty()
                    && x.len() <= 100
                    && x.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
            .ok_or_else(bad)?;
        if !r["name"].as_str().is_some_and(creation_name)
            || !valid_hash(&r["templateHash"])
            || !valid_identity(&r["parentIdentity"])
            || matches!(r["state"].as_str(), Some("created" | "ready"))
                && !valid_identity(&r["identity"])
            || !seen.insert(format!("request:{}:{request}", r["masterId"]))
            || !seen.insert(format!("id:{}", r["id"]))
        {
            return Err(bad());
        }
    }
    seen.clear();
    for r in remote["autoProvision"].as_array().ok_or_else(bad)? {
        for k in ["peerId", "logicalWorkspaceId", "rootId"] {
            id(r, k).map_err(|_| bad())?;
        }
        if !r["enabled"].is_boolean()
            || !seen.insert(format!("{}:{}", r["peerId"], r["logicalWorkspaceId"]))
        {
            return Err(bad());
        }
    }
    for r in local["roots"].as_array().ok_or_else(bad)? {
        if !valid_identity(&r["directoryIdentity"])
            || r["revision"]
                .as_u64()
                .is_none_or(|n| n == 0 || n > local["revision"].as_u64().unwrap_or(0))
        {
            return Err(bad());
        }
    }
    seen.clear();
    for s in local["scopes"].as_array().ok_or_else(bad)? {
        for k in ["peerId", "logicalWorkspaceId", "workspaceId"] {
            id(s, k).map_err(|_| bad())?;
        }
        let root = local["roots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["logicalWorkspaceId"] == s["logicalWorkspaceId"])
            .ok_or_else(bad)?;
        if s["directoryIdentity"] != root["directoryIdentity"]
            || s["localRevision"] != root["revision"]
            || s["bindingRevision"].as_u64().is_none()
            || !valid_hash(&s["bindingHash"])
            || s["revision"]
                .as_u64()
                .is_none_or(|n| n == 0 || n > local["revision"].as_u64().unwrap_or(0))
            || !seen.insert(format!("{}:{}", s["peerId"], s["logicalWorkspaceId"]))
            || crate::sync::normalize_scope(&s["scope"]).map_or(true, |v| v != s["scope"])
        {
            return Err(bad());
        }
    }
    Ok(())
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn summary(g: &Grant, id: &str, name: &str, kind: &str) -> Value {
    json!({"id":id,"name":name,"kind":kind,"state":"ready","tools":g.tools,"filesystem":{"directories":g.raw["directories"]}})
}
#[derive(Clone)]
struct State {
    remote: Value,
    local: Value,
}
pub struct WorkspaceRegistry {
    file: PathBuf,
    config: Config,
    policy: Mutex<Value>,
    failed: AtomicBool,
    state: Mutex<State>,
}
impl WorkspaceRegistry {
    pub fn new(state_dir: &Path, config: &Config) -> Result<Self> {
        ensure_private_dir(state_dir)?;
        let file = crate::node_store::directory(config);
        let mut remote = crate::node_store::read_section(&file, "workspaces")?.unwrap_or_else(||
            json!({"version":1,"nodeId":config.id,"revision":0,"bindings":[],"autoProvision":[],"creations":[]}));
        let local = crate::node_store::read_section(&file, "localWorkspaces")?.unwrap_or_else(
            || json!({"version":1,"nodeId":config.id,"revision":0,"roots":[],"scopes":[]}),
        );
        for v in [&remote, &local] {
            if v["version"] != 1 || v["nodeId"] != config.id || v["revision"].as_u64().is_none() {
                return Err(err("JOURNAL_CORRUPT", "Invalid workspace registry"));
            }
        }
        for k in ["bindings", "autoProvision", "creations"] {
            if remote[k].as_array().is_none_or(|a| a.len() > 1024) {
                return Err(err("JOURNAL_CORRUPT", "Invalid workspace collections"));
            }
        }
        for k in ["roots", "scopes"] {
            if local[k].as_array().is_none_or(|a| a.len() > 1024) {
                return Err(err("JOURNAL_CORRUPT", "Invalid local collections"));
            }
        }
        validate_loaded(&remote, &local)?;
        let mut keys = std::collections::BTreeSet::new();
        for b in remote["bindings"].as_array().unwrap() {
            for k in ["peerId", "logicalWorkspaceId", "workspaceId"] {
                id(b, k).map_err(|_| err("JOURNAL_CORRUPT", "Invalid binding"))?;
            }
            if !keys.insert(format!("{}:{}", b["peerId"], b["logicalWorkspaceId"])) {
                return Err(err("JOURNAL_CORRUPT", "Duplicate binding"));
            }
        }
        keys.clear();
        for r in local["roots"].as_array().unwrap() {
            id(r, "logicalWorkspaceId").map_err(|_| err("JOURNAL_CORRUPT", "Invalid local ID"))?;
            if r["path"]
                .as_str()
                .is_none_or(|p| !Path::new(p).is_absolute())
                || r["directoryIdentity"]["ino"].as_str().is_none()
                || r["revision"].as_u64().is_none()
                || !keys.insert(r["logicalWorkspaceId"].to_string())
            {
                return Err(err("JOURNAL_CORRUPT", "Invalid local root"));
            }
        }
        for r in remote["creations"].as_array_mut().unwrap() {
            for k in ["id", "masterId", "rootId"] {
                id(r, k).map_err(|_| err("JOURNAL_CORRUPT", "Invalid creation identity"))?;
            }
            if !matches!(
                r["state"].as_str(),
                Some("intent" | "created" | "ready" | "unknown" | "failed")
            ) || r["parent"]
                .as_str()
                .is_none_or(|p| !Path::new(p).is_absolute())
            {
                return Err(err("JOURNAL_CORRUPT", "Invalid creation"));
            }
            if r["state"] == "intent" {
                r["state"] = json!("unknown");
                r["error"] = json!("Interrupted before directory identity committed");
            } else if r["state"] == "created" {
                let good = Self::inspect_creation(r).is_ok();
                r["state"] = json!(if good { "ready" } else { "unknown" });
            }
        }
        crate::node_store::write_section(&file, "workspaces", &remote)?;
        crate::node_store::write_section(&file, "localWorkspaces", &local)?;
        Ok(Self {
            file,
            config: config.clone(),
            policy: Mutex::new(config.raw["policy"].clone()),
            failed: AtomicBool::new(false),
            state: Mutex::new(State { remote, local }),
        })
    }
    pub fn update_policy(&self, policy: Value) {
        *self.policy.lock().unwrap() = policy;
    }
    fn save_remote(&self, s: &State) -> Result<()> {
        if serde_json::to_vec(
            &json!({"format":1,"checksum":"0".repeat(64),"data":serde_json::to_string(&s.remote)?}),
        )?
        .len()
            > 8 * 1024 * 1024
        {
            return Err(err(
                "WORKSPACE_CAPACITY",
                "Workspace registry byte limit reached",
            ));
        }
        let r = crate::node_store::write_section(&self.file, "workspaces", &s.remote);
        if r.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        r
    }
    fn save_local(&self, s: &State) -> Result<()> {
        if serde_json::to_vec(
            &json!({"format":1,"checksum":"0".repeat(64),"data":serde_json::to_string(&s.local)?}),
        )?
        .len()
            > 2 * 1024 * 1024
        {
            return Err(err(
                "LOCAL_WORKSPACE_CAPACITY",
                "Local registry byte limit reached",
            ));
        }
        let r = crate::node_store::write_section(&self.file, "localWorkspaces", &s.local);
        if r.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        r
    }
    fn revise(v: &mut Value) {
        v["revision"] = json!(v["revision"].as_u64().unwrap() + 1);
    }
    fn cas(v: &Value, c: &Value, required: bool, code: &str) -> Result<()> {
        if required && c.get("expectedRevision").is_none()
            || c.get("expectedRevision")
                .is_some_and(|n| n != &v["revision"])
        {
            return Err(err(code, "Mappings changed; refresh before saving"));
        }
        Ok(())
    }
    fn local_snapshot(s: &State) -> Value {
        json!({"revision":s.local["revision"],"roots":s.local["roots"],"scopes":s.local["scopes"]})
    }
    fn remote_snapshot(s: &State) -> Value {
        let mut v = s.remote.clone();
        v.as_object_mut().unwrap().remove("version");
        v.as_object_mut().unwrap().remove("nodeId");
        for c in v["creations"].as_array_mut().unwrap() {
            for k in ["parent", "parentIdentity", "identity", "templateHash"] {
                c.as_object_mut().unwrap().remove(k);
            }
        }
        v
    }
    fn protect(&self, p: &Path) -> Result<()> {
        let mut paths = vec![
            self.config.state_dir.clone(),
            self.config.path.clone(),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        ];
        if let Ok(binary) = std::env::current_exe() {
            paths.push(binary);
        }
        if let Some(settings) = crate::rsync::Settings::parse(&self.config.raw)? {
            paths.push(settings.file);
        }
        for k in ["logFile"] {
            if let Some(x) = self.config.raw[k].as_str() {
                paths.push(PathBuf::from(x));
            }
        }
        if let Some(obj) = self.config.raw["security"].as_object() {
            for (k, v) in obj {
                if ["cert", "key", "ca", "certificate", "privateKey"].contains(&k.as_str())
                    && let Some(x) = v.as_str()
                {
                    let x = PathBuf::from(x);
                    let x = if x.is_absolute() {
                        x
                    } else {
                        self.config.path.parent().unwrap().join(x)
                    };
                    if let Some(parent) = x.parent()
                        && Some(parent) != self.config.path.parent()
                    {
                        paths.push(parent.to_path_buf());
                    }
                    paths.push(x);
                }
            }
        }
        for k in ["sessionDirectory", "socketPath"] {
            if let Some(x) = self.config.raw["operator"][k].as_str() {
                paths.push(PathBuf::from(x));
            }
        }
        if paths.iter().any(|x| overlap(p, x)) {
            return Err(err(
                "LOCAL_WORKSPACE_PROTECTED",
                "Local root overlaps runtime, state or owner secrets",
            ));
        }
        Ok(())
    }
    fn find_binding<'a>(s: &'a State, peer: &str, logical: &str) -> Option<&'a Value> {
        s.remote["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["peerId"] == peer && r["logicalWorkspaceId"] == logical)
    }
    fn find_root<'a>(s: &'a State, logical: &str) -> Option<&'a Value> {
        s.local["roots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["logicalWorkspaceId"] == logical)
    }
    fn inspect_local(&self, r: &Value) -> Result<PathBuf> {
        let p = PathBuf::from(
            r["path"]
                .as_str()
                .ok_or_else(|| err("JOURNAL_CORRUPT", "Missing root path"))?,
        );
        self.protect(&p)?;
        if identity(&p, true)
            .map_err(|_| err("LOCAL_WORKSPACE_CHANGED", "Local root unavailable"))?
            != r["directoryIdentity"]
        {
            return Err(err(
                "LOCAL_WORKSPACE_CHANGED",
                "Local root identity changed",
            ));
        }
        Ok(p)
    }
    pub fn binding(&self, peer: &str, logical: &str) -> Result<Option<String>> {
        let s = self.state.lock().unwrap();
        Ok(Self::find_binding(&s, peer, logical)
            .and_then(|r| r["workspaceId"].as_str())
            .map(str::to_string))
    }
    pub fn local_root(&self, logical: &str) -> Result<PathBuf> {
        let s = self.state.lock().unwrap();
        self.inspect_local(Self::find_root(&s, logical).ok_or_else(|| {
            err(
                "LOCAL_WORKSPACE_NOT_FOUND",
                "Owner-approved local root required",
            )
        })?)
    }
    fn mapping(&self, s: &State, peer: &str, logical: &str) -> Result<(PathBuf, String, Value)> {
        let r = Self::find_root(s, logical).ok_or_else(|| {
            err(
                "LOCAL_WORKSPACE_NOT_FOUND",
                "Owner-approved local root required",
            )
        })?;
        let p = self.inspect_local(r)?;
        let b = Self::find_binding(s, peer, logical).ok_or_else(|| {
            err(
                "WORKSPACE_BINDING_NOT_FOUND",
                "Explicit remote binding required",
            )
        })?;
        let scope = s.local["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["peerId"] == peer && x["logicalWorkspaceId"] == logical)
            .ok_or_else(|| {
                err(
                    "LOCAL_WORKSPACE_SCOPE_NOT_FOUND",
                    "Select synchronization scope first",
                )
            })?;
        if scope["bindingRevision"] != s.remote["revision"]
            || scope["bindingHash"] != hash(b)
            || scope["localRevision"] != r["revision"]
            || scope["directoryIdentity"] != r["directoryIdentity"]
        {
            return Err(err(
                "LOCAL_WORKSPACE_SCOPE_STALE",
                "Mappings changed; select scope again",
            ));
        }
        Ok((
            p,
            b["workspaceId"].as_str().unwrap().into(),
            scope["scope"].clone(),
        ))
    }
    pub fn sync_mapping(&self, peer: &str, logical: &str) -> Result<(PathBuf, String, Value)> {
        self.mapping(&self.state.lock().unwrap(), peer, logical)
    }
    pub fn check_mapping(
        &self,
        peer: &str,
        logical: &str,
        root: &Path,
        workspace: &str,
        scope: &Value,
    ) -> Result<()> {
        let current = self.sync_mapping(peer, logical)?;
        if current.0 != root || current.1 != workspace || current.2 != *scope {
            return Err(err(
                "LOCAL_WORKSPACE_SCOPE_STALE",
                "Mapping changed during transfer",
            ));
        }
        Ok(())
    }
    pub fn command(&self, c: &Value) -> Result<Value> {
        let name = c["command"]
            .as_str()
            .ok_or_else(|| err("INVALID_COMMAND", "Command required"))?;
        if self.failed.load(Ordering::SeqCst)
            && !matches!(
                name,
                "listWorkspaceBindings" | "listLocalWorkspaces" | "getLocalWorkspace"
            )
        {
            return Err(err(
                "JOURNAL_UNAVAILABLE",
                "Storage failed; inspect before restart",
            ));
        }
        let mut persisted = self.state.lock().unwrap();
        let mut s = persisted.clone();
        let result = match name {
            "getLocalWorkspace" => {
                let logical = id(c, "logicalWorkspaceId")?;
                let r = Self::find_root(&s, &logical).ok_or_else(|| {
                    err(
                        "LOCAL_WORKSPACE_NOT_FOUND",
                        "Owner-approved local root required",
                    )
                })?;
                let p = self.inspect_local(r)?;
                Ok(
                    json!({"logicalWorkspaceId":logical,"root":p,"directoryIdentity":r["directoryIdentity"],"revision":r["revision"]}),
                )
            }
            "listWorkspaceBindings" => Ok(Self::remote_snapshot(&s)),
            "listLocalWorkspaces" => Ok(Self::local_snapshot(&s)),
            "bindWorkspace" | "unbindWorkspace" | "setWorkspaceAutoProvision" => {
                let peer = id(c, "peerId")?;
                let logical = id(c, "logicalWorkspaceId")?;
                Self::cas(&s.remote, c, false, "WORKSPACE_BINDING_CONFLICT")?;
                let field = if name == "setWorkspaceAutoProvision" {
                    "autoProvision"
                } else {
                    "bindings"
                };
                let old = s.remote[field]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|x| x["peerId"] == peer && x["logicalWorkspaceId"] == logical)
                    .cloned();
                let record = if name == "bindWorkspace" {
                    json!({"peerId":peer,"logicalWorkspaceId":logical,"workspaceId":id(c,"workspaceId")?,"createdAt":old.as_ref().and_then(|x|x["createdAt"].as_u64()).unwrap_or(now()),"updatedAt":now()})
                } else if name == "setWorkspaceAutoProvision" {
                    if !c["enabled"].is_boolean() {
                        return Err(err("INVALID_ARGS", "enabled required"));
                    }
                    json!({"peerId":peer,"logicalWorkspaceId":logical,"rootId":id(c,"rootId")?,"enabled":c["enabled"],"updatedAt":now()})
                } else {
                    Value::Null
                };
                if old.is_none()
                    && name != "unbindWorkspace"
                    && s.remote[field].as_array().unwrap().len() >= 1024
                {
                    return Err(err("WORKSPACE_CAPACITY", "Registry full"));
                }
                let a = s.remote[field].as_array_mut().unwrap();
                a.retain(|x| x["peerId"] != peer || x["logicalWorkspaceId"] != logical);
                if !record.is_null() {
                    a.push(record.clone());
                }
                if old.is_some() || name != "unbindWorkspace" {
                    Self::revise(&mut s.remote);
                    self.save_remote(&s)?;
                }
                Ok(if name == "bindWorkspace" {
                    record
                } else {
                    Self::remote_snapshot(&s)
                })
            }
            "bindLocalWorkspace" | "unbindLocalWorkspace" => {
                let logical = id(c, "logicalWorkspaceId")?;
                Self::cas(&s.local, c, true, "LOCAL_WORKSPACE_CONFLICT")?;
                let previous = Self::find_root(&s, &logical).cloned();
                let record = if name == "bindLocalWorkspace" {
                    let p = PathBuf::from(
                        c["path"]
                            .as_str()
                            .ok_or_else(|| err("INVALID_ARGS", "Explicit local path required"))?,
                    );
                    if !p.is_absolute() {
                        return Err(err("INVALID_ARGS", "Canonical absolute path required"));
                    }
                    self.protect(&p)?;
                    let i = identity(&p, true)?;
                    if previous.as_ref().is_some_and(|x| {
                        x["path"] == p.to_string_lossy().as_ref() && x["directoryIdentity"] == i
                    }) {
                        return Ok(Self::local_snapshot(&s));
                    }
                    if previous.is_none() && s.local["roots"].as_array().unwrap().len() >= 1024 {
                        return Err(err("LOCAL_WORKSPACE_CAPACITY", "Local roots full"));
                    }
                    Some(
                        json!({"logicalWorkspaceId":logical,"path":p,"directoryIdentity":i,"revision":s.local["revision"].as_u64().unwrap()+1}),
                    )
                } else {
                    None
                };
                if record.is_none() && previous.is_none() {
                    return Ok(Self::local_snapshot(&s));
                }
                s.local["roots"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|x| x["logicalWorkspaceId"] != logical);
                if let Some(r) = record {
                    s.local["roots"].as_array_mut().unwrap().push(r);
                }
                s.local["scopes"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|x| x["logicalWorkspaceId"] != logical);
                Self::revise(&mut s.local);
                self.save_local(&s)?;
                Ok(Self::local_snapshot(&s))
            }
            "setWorkspaceSyncScope" => {
                let logical = id(c, "logicalWorkspaceId")?;
                let peer = id(c, "peerId")?;
                Self::cas(&s.local, c, false, "LOCAL_WORKSPACE_CONFLICT")?;
                let root = Self::find_root(&s, &logical)
                    .ok_or_else(|| {
                        err(
                            "LOCAL_WORKSPACE_NOT_FOUND",
                            "Owner must register local root",
                        )
                    })?
                    .clone();
                self.inspect_local(&root)?;
                let b = Self::find_binding(&s, &peer, &logical)
                    .ok_or_else(|| err("WORKSPACE_BINDING_NOT_FOUND", "Remote binding required"))?
                    .clone();
                let scope = crate::sync::normalize_scope(&c["scope"])?;
                let record = json!({"logicalWorkspaceId":logical,"peerId":peer,"workspaceId":b["workspaceId"],"bindingRevision":s.remote["revision"],"bindingHash":hash(&b),"localRevision":root["revision"],"directoryIdentity":root["directoryIdentity"],"scope":scope,"revision":s.local["revision"].as_u64().unwrap()+1});
                let a = s.local["scopes"].as_array_mut().unwrap();
                if a.len() >= 1024
                    && !a
                        .iter()
                        .any(|x| x["logicalWorkspaceId"] == logical && x["peerId"] == peer)
                {
                    return Err(err("LOCAL_WORKSPACE_CAPACITY", "Scopes full"));
                }
                a.retain(|x| x["logicalWorkspaceId"] != logical || x["peerId"] != peer);
                a.push(record.clone());
                Self::revise(&mut s.local);
                self.save_local(&s)?;
                Ok(record)
            }
            "reconcileWorkspaceCreation" => {
                let wid = id(c, "workspaceId")?;
                let master = id(c, "masterId")?;
                let index = s.remote["creations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .position(|r| {
                        r["id"] == wid && r["masterId"] == master && r["state"] == "unknown"
                    })
                    .ok_or_else(|| err("INVALID_COMMAND", "Unknown creation required"))?;
                if c["note"]
                    .as_str()
                    .is_none_or(|x| x.trim().len() < 3 || x.len() > 1000)
                {
                    return Err(err("INVALID_COMMAND", "Owner evidence note required"));
                }
                let r = &mut s.remote["creations"][index];
                let policy = self.policy.lock().unwrap();
                let approval = Self::root_policy(&policy, &master, r["rootId"].as_str().unwrap())?;
                if approval["path"] != r["parent"]
                    || approval["identity"] != r["parentIdentity"]
                    || approval["templateHash"] != r["templateHash"]
                {
                    return Err(err("WORKSPACE_DENIED", "Provisioning approval changed"));
                }
                let parent = PathBuf::from(r["parent"].as_str().unwrap());
                if identity(&parent, true)? != r["parentIdentity"] {
                    return Err(err("WORKSPACE_DENIED", "Parent identity changed"));
                }
                let target = parent.join(r["name"].as_str().unwrap());
                match c["resolution"].as_str() {
                    Some("completed") => {
                        r["identity"] = identity(&target, false)?;
                        r["state"] = json!("ready");
                    }
                    Some("not_created") => {
                        if fs::symlink_metadata(&target).is_ok() {
                            return Err(err("WORKSPACE_DENIED", "Directory exists"));
                        }
                        r["state"] = json!("failed");
                    }
                    _ => return Err(err("INVALID_COMMAND", "completed/not_created required")),
                }
                r["reconciledAt"] = json!(now());
                r["resolution"] = c["resolution"].clone();
                r["note"] = c["note"].clone();
                self.save_remote(&s)?;
                Ok(Self::remote_snapshot(&s))
            }
            _ => Err(err("INVALID_COMMAND", "Unknown workspace owner command")),
        };
        if result.is_ok() {
            *persisted = s;
        }
        result
    }
    fn inspect_creation(r: &Value) -> Result<()> {
        let p = PathBuf::from(r["parent"].as_str().unwrap_or(""));
        if identity(&p, true)? != r["parentIdentity"]
            || identity(&p.join(r["name"].as_str().unwrap_or("")), false)? != r["identity"]
        {
            return Err(err(
                "WORKSPACE_DENIED",
                "Provisioned directory identity changed",
            ));
        }
        Ok(())
    }
    fn root_policy<'a>(policy: &'a Value, master: &str, root_id: &str) -> Result<&'a Value> {
        policy["grants"][master]["workspaceProvisioning"]["roots"]
            .get(root_id)
            .ok_or_else(|| err("WORKSPACE_DENIED", "Provisioning approval absent"))
    }
    fn resolved_record(policy: &Value, master: &str, epoch: u64, r: &Value) -> Result<Grant> {
        if r["state"] != "ready" {
            return Err(err("WORKSPACE_DENIED", "Provisioned workspace unavailable"));
        }
        let root = Self::root_policy(policy, master, r["rootId"].as_str().unwrap())?;
        if root["path"] != r["parent"]
            || root["identity"] != r["parentIdentity"]
            || root["templateHash"] != r["templateHash"]
        {
            return Err(err("WORKSPACE_DENIED", "Provisioning approval changed"));
        }
        Self::inspect_creation(r)?;
        let path = Path::new(r["parent"].as_str().unwrap()).join(r["name"].as_str().unwrap());
        let mut p = policy.clone();
        let mut grant = root["grant"].clone();
        grant["workspace"] = json!(path);
        grant["root"] = json!(path);
        grant["workspaceIdentity"] = r["identity"].clone();
        if let Some(servers) = grant["mcpServers"].as_object_mut() {
            for (_, server) in servers {
                server["root"] = json!(path);
            }
        }
        p["grants"][master] = grant;
        let mut g = crate::policy::resolve_grant(&p, master, None, epoch)?;
        g.workspace_id = r["id"].as_str().unwrap().into();
        Ok(g)
    }
    pub fn resolve(
        &self,
        policy: &Value,
        master: &str,
        workspace: Option<&str>,
        epoch: u64,
    ) -> Result<Grant> {
        if let Some(w) = workspace
            && w.starts_with("ws_")
        {
            let s = self.state.lock().unwrap();
            let r = s.remote["creations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["masterId"] == master && r["id"] == w)
                .ok_or_else(|| err("WORKSPACE_DENIED", "Workspace unavailable"))?;
            return Self::resolved_record(policy, master, epoch, r);
        }
        crate::policy::resolve_grant(policy, master, workspace, epoch)
    }
    pub fn catalog(&self, master: &str, policy: &Value, epoch: u64, args: &Value) -> Result<Value> {
        let parent = crate::policy::resolve_grant(policy, master, None, epoch)?;
        let s = self.state.lock().unwrap();
        let mut entries: Vec<(bool, Value)> = Vec::new();
        if !parent.root.as_os_str().is_empty() {
            entries.push((false, summary(&parent, "default", "default", "default")));
        }
        if let Some(w) = parent.raw["workspaces"].as_object() {
            for (id, _) in w {
                if let Ok(g) = crate::policy::resolve_grant(policy, master, Some(id), epoch) {
                    entries.push((false, summary(&g, id, id, "configured")));
                }
            }
        }
        for r in s.remote["creations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["masterId"] == master)
        {
            let mut v = match Self::resolved_record(policy, master, epoch, r) {
                Ok(g) => summary(
                    &g,
                    r["id"].as_str().unwrap(),
                    r["name"].as_str().unwrap(),
                    "provisioned",
                ),
                Err(_) => {
                    json!({"id":r["id"],"name":r["name"],"kind":"provisioned","state":if r["state"]=="ready"{json!("unavailable")}else{r["state"].clone()}})
                }
            };
            v["rootId"] = r["rootId"].clone();
            v["requestId"] = r["requestId"].clone();
            entries.push((false, v));
        }
        if parent.tools.contains("workspaceCreate")
            && let Some(roots) = parent.raw["workspaceProvisioning"]["roots"].as_object()
        {
            for (id, r) in roots {
                let used = s.remote["creations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|c| {
                        c["masterId"] == master && c["rootId"] == *id && c["state"] != "failed"
                    })
                    .count() as u64;
                entries.push((true,json!({"id":id,"maxWorkspaces":r["maxWorkspaces"],"used":used,"remaining":r["maxWorkspaces"].as_u64().unwrap_or(0).saturating_sub(used),"tools":r["grant"]["tools"],"filesystem":{"directories":r["grant"]["directories"]}})));
            }
        }
        let offset = args["offset"].as_u64().unwrap_or(0) as usize;
        let limit = args["limit"].as_u64().unwrap_or(32) as usize;
        if limit == 0 || limit > 32 {
            return Err(err("INVALID_ARGS", "Catalog limit must be 1..32"));
        }
        let mut result = json!({"workspaces":[],"creationRoots":[],"offset":offset,"total":entries.len(),"nextOffset":null});
        let mut index = offset;
        let mut bytes = 256;
        for (root, v) in entries.iter().skip(offset).take(limit) {
            let n = serde_json::to_vec(v)?.len();
            if bytes + n > 90000 {
                break;
            }
            bytes += n;
            result[if *root { "creationRoots" } else { "workspaces" }]
                .as_array_mut()
                .unwrap()
                .push(v.clone());
            index += 1;
        }
        if index < entries.len() {
            result["nextOffset"] = json!(index);
        }
        Ok(result)
    }
    pub fn create(&self, master: &str, policy: &Value, epoch: u64, args: &Value) -> Result<Value> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(err(
                "JOURNAL_UNAVAILABLE",
                "Storage failed; inspect before restart",
            ));
        }
        let parent = crate::policy::resolve_grant(policy, master, None, epoch)?;
        let root_id = id(args, "rootId")?;
        let name = args["name"]
            .as_str()
            .ok_or_else(|| err("INVALID_ARGS", "name required"))?;
        let request = args["requestId"]
            .as_str()
            .ok_or_else(|| err("INVALID_ARGS", "requestId required"))?;
        let lower = name.to_ascii_lowercase();
        if !crate::policy::valid_id(name)
            || !name.as_bytes()[0].is_ascii_alphanumeric()
            || ["con", "prn", "aux", "nul"].contains(&lower.as_str())
            || lower.len() == 4
                && (lower.starts_with("com") || lower.starts_with("lpt"))
                && (b'1'..=b'9').contains(&lower.as_bytes()[3])
            || request.is_empty()
            || request.len() > 100
            || !request
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(err(
                "INVALID_ARGS",
                "Unsafe workspace name or creation request ID",
            ));
        }
        if !parent.tools.contains("workspaceCreate") {
            return Err(err(
                "WORKSPACE_CREATE_DENIED",
                "Workspace creation not granted",
            ));
        }
        let root = Self::root_policy(policy, master, &root_id)?;
        let mut s = self.state.lock().unwrap();
        if let Some(r) = s.remote["creations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["masterId"] == master && r["requestId"] == request)
        {
            if r["rootId"] != root_id || r["name"] != name {
                return Err(err(
                    "WORKSPACE_REQUEST_CONFLICT",
                    "Request names another workspace",
                ));
            }
            let g = Self::resolved_record(policy, master, epoch, r).map_err(|_| {
                err(
                    if r["state"] == "failed" {
                        "WORKSPACE_NAME_CONFLICT"
                    } else {
                        "WORKSPACE_CREATE_UNKNOWN"
                    },
                    "Consumed creation request cannot replay",
                )
            })?;
            let mut v = summary(&g, r["id"].as_str().unwrap(), name, "provisioned");
            v["rootId"] = json!(root_id);
            v["requestId"] = json!(request);
            return Ok(v);
        }
        if s.remote["creations"].as_array().unwrap().len() >= 1024 {
            return Err(err("WORKSPACE_CAPACITY", "Creation history full"));
        }
        let used = s.remote["creations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["masterId"] == master && r["rootId"] == root_id && r["state"] != "failed")
            .count() as u64;
        if used >= root["maxWorkspaces"].as_u64().unwrap_or(0) {
            return Err(err("WORKSPACE_QUOTA", "Approved quota exhausted"));
        }
        let path = PathBuf::from(
            root["path"]
                .as_str()
                .ok_or_else(|| err("WORKSPACE_DENIED", "Approved parent missing"))?,
        );
        let pi = identity(&path, true)?;
        if root["identity"] != pi {
            return Err(err(
                "WORKSPACE_DENIED",
                "Provisioning parent identity changed",
            ));
        }
        let target = path.join(name);
        match fs::symlink_metadata(&target) {
            Ok(_) => return Err(err("WORKSPACE_NAME_CONFLICT", "Name exists; never adopt")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut r = json!({"id":format!("ws_{}",uuid::Uuid::new_v4().simple()),"masterId":master,"rootId":root_id,"requestId":request,"name":name,"parent":path,"parentIdentity":pi,"templateHash":root["templateHash"],"state":"intent","createdAt":now()});
        let index = s.remote["creations"].as_array().unwrap().len();
        s.remote["creations"]
            .as_array_mut()
            .unwrap()
            .push(r.clone());
        self.save_remote(&s)?;
        let result = (|| -> Result<()> {
            fs::DirBuilder::new().mode(0o700).create(&target)?;
            fs::File::open(&path)?.sync_all()?;
            r["identity"] = identity(&target, false)?;
            r["state"] = json!("created");
            s.remote["creations"][index] = r.clone();
            self.save_remote(&s)?;
            Self::inspect_creation(&r)?;
            r["state"] = json!("ready");
            s.remote["creations"][index] = r.clone();
            self.save_remote(&s)
        })();
        if let Err(e) = result {
            r["state"] = json!(if e.code == "EEXIST" && r["identity"].is_null() {
                "failed"
            } else {
                "unknown"
            });
            r["error"] = json!("Interrupted creation requires owner inspection");
            s.remote["creations"][index] = r;
            let _ = self.save_remote(&s);
            return Err(e.unknown());
        }
        let g = Self::resolved_record(policy, master, epoch, &r)?;
        let mut v = summary(&g, r["id"].as_str().unwrap(), name, "provisioned");
        v["rootId"] = json!(root_id);
        v["requestId"] = json!(request);
        Ok(v)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    fn config(d: &Path) -> Config {
        Config {
            raw: json!({"masters":[],"peers":[{"id":"remote"}]}),
            id: "local".into(),
            host: "127.0.0.1".into(),
            port: 0,
            path: d.join("config.json"),
            state_dir: d.join("state"),
        }
    }
    #[test]
    fn local_mapping_requires_cas_and_scope_identity() {
        let d = tempfile::tempdir().unwrap();
        let local = d.path().join("local");
        std::fs::create_dir(&local).unwrap();
        std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o700)).unwrap();
        let cfg = config(d.path());
        let r = WorkspaceRegistry::new(&cfg.state_dir, &cfg).unwrap();
        assert!(
            r.command(
                &json!({"command":"bindLocalWorkspace","logicalWorkspaceId":"project","path":local})
            )
            .is_err()
        );
        r.command(&json!({"command":"bindLocalWorkspace","logicalWorkspaceId":"project","path":local,"expectedRevision":0})).unwrap();
        r.command(&json!({"command":"bindWorkspace","peerId":"remote","logicalWorkspaceId":"project","workspaceId":"dev"})).unwrap();
        r.command(&json!({"command":"setWorkspaceSyncScope","peerId":"remote","logicalWorkspaceId":"project","scope":{"paths":["src"]}})).unwrap();
        let (root, id, scope) = r.sync_mapping("remote", "project").unwrap();
        assert_eq!(id, "dev");
        r.check_mapping("remote", "project", &root, &id, &scope)
            .unwrap();
        r.command(
            &json!({"command":"unbindWorkspace","peerId":"remote","logicalWorkspaceId":"project"}),
        )
        .unwrap();
        assert!(
            r.check_mapping("remote", "project", &root, &id, &scope)
                .is_err()
        );
    }
    #[test]
    fn provision_request_is_stable_scoped_and_quota_enforced() {
        let d = tempfile::tempdir().unwrap();
        let parent = d.path().join("approved");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let cfg = config(d.path());
        let policy=crate::policy::validate_policy(&json!({"grants":{"master":{"tools":["workspaceList","workspaceCreate"],"workspaceProvisioning":{"roots":{"projects":{"path":parent,"maxWorkspaces":1,"grant":{"tools":["readFile","writeFile"],"directories":[{"path":"","read":true,"write":true}]}}}}}}}),d.path()).unwrap();
        let r = WorkspaceRegistry::new(&cfg.state_dir, &cfg).unwrap();
        let a = json!({"rootId":"projects","name":"project","requestId":"fixed"});
        let first = r.create("master", &policy, 2, &a).unwrap();
        let again = r.create("master", &policy, 2, &a).unwrap();
        assert_eq!(first["id"], again["id"]);
        let g = r
            .resolve(&policy, "master", first["id"].as_str(), 2)
            .unwrap();
        assert_eq!(g.root, parent.join("project"));
        assert!(!g.tools.contains("workspaceCreate"));
        assert_eq!(
            r.create(
                "master",
                &policy,
                2,
                &json!({"rootId":"projects","name":"other","requestId":"fixed"})
            )
            .unwrap_err()
            .code,
            "WORKSPACE_REQUEST_CONFLICT"
        );
        assert_eq!(
            r.create(
                "master",
                &policy,
                2,
                &json!({"rootId":"projects","name":"other","requestId":"another"})
            )
            .unwrap_err()
            .code,
            "WORKSPACE_QUOTA"
        );
        drop(r);
        let r = WorkspaceRegistry::new(&cfg.state_dir, &cfg).unwrap();
        assert_eq!(
            r.create("master", &policy, 2, &a).unwrap()["id"],
            first["id"]
        );
        let mut revoked = policy.clone();
        revoked["grants"]["master"]["workspaceProvisioning"]["roots"]["projects"]["templateHash"] =
            json!("changed");
        assert!(
            r.resolve(&revoked, "master", first["id"].as_str(), 2)
                .is_err()
        );
    }
    #[test]
    fn corrupted_creation_and_scopes_are_rejected() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let r = WorkspaceRegistry::new(&cfg.state_dir, &cfg).unwrap();
        drop(r);
        let p = crate::node_store::directory(&cfg);
        let mut state = crate::node_store::read_section(&p, "workspaces")
            .unwrap()
            .unwrap();
        state["creations"] = json!([{"id":"ws_valid","masterId":"master","rootId":"projects","state":"ready","parent":"/tmp","name":"../escape","requestId":"valid","templateHash":"x"}]);
        crate::node_store::write_section(&p, "workspaces", &state).unwrap();
        assert!(WorkspaceRegistry::new(&cfg.state_dir, &cfg).is_err());
    }
    #[test]
    fn interrupted_intent_is_unknown_and_never_replayed() {
        let d = tempfile::tempdir().unwrap();
        let cfg = config(d.path());
        let r = WorkspaceRegistry::new(&cfg.state_dir, &cfg).unwrap();
        drop(r);
        let p = crate::node_store::directory(&cfg);
        let mut state = crate::node_store::read_section(&p, "workspaces")
            .unwrap()
            .unwrap();
        state["creations"] = json!([{"id":"ws_valid","masterId":"master","rootId":"projects","state":"intent","parent":d.path(),"parentIdentity":identity(d.path(),true).unwrap(),"name":"project","requestId":"fixed","templateHash":"0".repeat(64)}]);
        crate::node_store::write_section(&p, "workspaces", &state).unwrap();
        let r = WorkspaceRegistry::new(&cfg.state_dir, &cfg).unwrap();
        let snapshot = r
            .command(&json!({"command":"listWorkspaceBindings"}))
            .unwrap();
        assert_eq!(snapshot["creations"][0]["state"], "unknown");
        assert!(!d.path().join("project").exists());
        assert!(snapshot["creations"][0].get("parent").is_none());
    }
    #[test]
    fn binding_and_scope_persist() {
        let d = tempfile::tempdir().unwrap();
        let local = d.path().join("local");
        std::fs::create_dir(&local).unwrap();
        let cfg = config(d.path());
        let r = WorkspaceRegistry::new(&cfg.state_dir, &cfg).unwrap();
        r.command(&json!({"command":"bindLocalWorkspace","logicalWorkspaceId":"p","path":local,"expectedRevision":0})).unwrap();
        drop(r);
        let r = WorkspaceRegistry::new(&cfg.state_dir, &cfg).unwrap();
        assert_eq!(r.local_root("p").unwrap(), local);
        assert!(cfg.state_dir.join("nodes.json").is_file());
        assert!(!cfg.state_dir.join("local-workspaces.json").exists());
        assert!(!cfg.state_dir.join("workspaces.json").exists());
    }
}
