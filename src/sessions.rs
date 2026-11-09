//! Durable agent sessions. Execution records contain metadata, never tool payloads.
use crate::{
    IcError, Result,
    durable::{ensure_private_dir, read_checked, write_checked},
};
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt;
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn valid_id(id: &str) -> Result<()> {
    if uuid::Uuid::parse_str(id).is_err() {
        return Err(IcError::new("INVALID_SESSION", "Session ID must be a UUID"));
    }
    Ok(())
}

pub struct SessionStore {
    directory: PathBuf,
    lock: Mutex<()>,
}
impl SessionStore {
    pub fn open(state_dir: &Path) -> Result<Self> {
        let directory = state_dir.join("sessions");
        ensure_private_dir(&directory)?;
        let store = Self {
            directory,
            lock: Mutex::new(()),
        };
        for mut session in store.list()?.as_array().unwrap().clone() {
            let mut changed = false;
            for task in session["tasks"]
                .as_array_mut()
                .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Missing session tasks"))?
            {
                if task["state"] == "running" {
                    task["state"] = json!("unknown");
                    task["outcomeUnknown"] = json!(true);
                    changed = true;
                }
            }
            if changed {
                store.save(&session)?;
            }
        }
        Ok(store)
    }
    fn path(&self, id: &str) -> Result<PathBuf> {
        valid_id(id)?;
        Ok(self.directory.join(format!("{id}.json")))
    }
    fn save(&self, session: &Value) -> Result<()> {
        let id = session["sessionId"]
            .as_str()
            .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Missing session ID"))?;
        write_checked(&self.path(id)?, session)
    }
    pub fn create(&self, cwd: Option<&Path>) -> Result<Value> {
        self.create_with_options(cwd, false)
    }
    pub fn create_with_options(&self, cwd: Option<&Path>, local_sync: bool) -> Result<Value> {
        if local_sync && cwd.is_none() {
            return Err(IcError::new(
                "INVALID_SESSION",
                "Local sync requires an explicit working directory",
            ));
        }
        let cwd = cwd.map(std::fs::canonicalize).transpose()?;
        if cwd.as_ref().is_some_and(|p| !p.is_dir()) {
            return Err(IcError::new(
                "INVALID_CWD",
                "Working directory must be a directory",
            ));
        }
        let identity = cwd
            .as_ref()
            .map(|path| std::fs::metadata(path).map(|m| json!({"dev":m.dev(),"ino":m.ino()})))
            .transpose()?;
        let value = json!({"sessionId":uuid::Uuid::new_v4().to_string(),"directoryIdentity":identity,"cwd":cwd,"localSync":local_sync,"defaultPeerId":null,"createdAt":now(),"updatedAt":now(),"targets":{},"tasks":[]});
        let _lock = self.lock.lock().unwrap();
        self.save(&value)?;
        Ok(value)
    }
    pub fn set_default_peer(&self, id: &str, peer: &str) -> Result<Value> {
        if !crate::policy::valid_id(peer) {
            return Err(IcError::new("INVALID_PEER", "Invalid peer identity"));
        }
        let _lock = self.lock.lock().unwrap();
        let mut session = self.get(id)?;
        session["defaultPeerId"] = json!(peer);
        session["updatedAt"] = json!(now());
        self.save(&session)?;
        Ok(json!({"sessionId":id,"peerId":peer}))
    }
    pub fn get(&self, id: &str) -> Result<Value> {
        let value = read_checked(&self.path(id)?)?;
        if value["sessionId"] != id || !value["tasks"].is_array() {
            return Err(IcError::new("JOURNAL_CORRUPT", "Invalid session record"));
        }
        Ok(value)
    }
    pub fn list(&self) -> Result<Value> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&self.directory)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Invalid session filename"))?;
                records.push(self.get(id)?);
            }
        }
        records.sort_by_key(|v| v["createdAt"].as_u64().unwrap_or(0));
        Ok(json!(records))
    }
    pub fn bind_target(&self, id: &str, peer: &str, workspace: &str) -> Result<()> {
        if !crate::policy::valid_id(peer) || !crate::policy::valid_id(workspace) {
            return Err(IcError::new("INVALID_WORKSPACE", "Invalid target binding"));
        }
        let _lock = self.lock.lock().unwrap();
        let mut session = self.get(id)?;
        let targets = session["targets"]
            .as_object_mut()
            .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Missing session target bindings"))?;
        if let Some(previous) = targets.get(peer) {
            if previous != workspace {
                return Err(IcError::new(
                    "WORKSPACE_MAPPING_CHANGED",
                    "Session target binding changed; start a new session",
                ));
            }
            return Ok(());
        }
        targets.insert(peer.to_string(), json!(workspace));
        session["updatedAt"] = json!(now());
        self.save(&session)
    }
    pub fn record_start(&self, id: &str, peer: &str, task: &Value) -> Result<()> {
        let _lock = self.lock.lock().unwrap();
        let mut session = self.get(id)?;
        let tasks = session["tasks"].as_array_mut().unwrap();
        if tasks.iter().any(|t| t["taskId"] == task["taskId"]) {
            return Err(IcError::new(
                "TASK_ID_CONFLICT",
                "Session task already exists",
            ));
        }
        let mut record = json!({"taskId":task["taskId"],"peerId":peer,"tool":task["tool"],"state":"running","startedAt":now()});
        if task["origin"] == "aggregated" {
            record["origin"] = json!("aggregated");
            record["sideEffect"] = json!(task["sideEffect"] != false);
        }
        tasks.push(record);
        session["updatedAt"] = json!(now());
        self.save(&session)
    }
    pub fn record_finish(&self, id: &str, task_id: &str, result: &Result<Value>) -> Result<()> {
        let _lock = self.lock.lock().unwrap();
        let mut session = self.get(id)?;
        let task = session["tasks"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|t| t["taskId"] == task_id)
            .ok_or_else(|| IcError::new("TASK_NOT_FOUND", "Session task not found"))?;
        let (failed, unknown, code) = match result {
            Ok(v) => (
                v["status"] == "error" || v["isError"] == true,
                v["outcomeUnknown"] == true,
                v["error"]["code"].clone(),
            ),
            Err(e) => (true, e.outcome_unknown, json!(e.code)),
        };
        task["state"] = json!(if unknown {
            "unknown"
        } else if failed {
            "failed"
        } else {
            "completed"
        });
        task["outcomeUnknown"] = json!(unknown);
        task["code"] = code;
        task["finishedAt"] = json!(now());
        session["updatedAt"] = json!(now());
        self.save(&session)
    }
    /// Apply authoritative owner-ledger resolutions without discarding the
    /// original uncertain execution record. Matching uses both peer and task ID.
    pub fn reconcile_remote_records(&self, records: &[Value]) -> Result<()> {
        let mut reconciled = std::collections::BTreeMap::new();
        for record in records
            .iter()
            .filter(|record| record["state"] == "reconciled")
        {
            let peer = record["peerId"]
                .as_str()
                .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Missing reconciled peer ID"))?;
            let task = record["taskId"]
                .as_str()
                .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Missing reconciled task ID"))?;
            if !record["reconciliation"].is_object() {
                return Err(IcError::new(
                    "JOURNAL_CORRUPT",
                    "Missing reconciliation audit record",
                ));
            }
            reconciled.insert((peer, task), record);
        }
        if reconciled.is_empty() {
            return Ok(());
        }
        let _lock = self.lock.lock().unwrap();
        for mut session in self.list()?.as_array().unwrap().clone() {
            let mut changed = false;
            for task in session["tasks"].as_array_mut().unwrap() {
                if task["state"] != "unknown" || task["origin"] == "aggregated" {
                    continue;
                }
                let key = (
                    task["peerId"].as_str().unwrap_or(""),
                    task["taskId"].as_str().unwrap_or(""),
                );
                let Some(record) = reconciled.get(&key) else {
                    continue;
                };
                let reconciliation = record["reconciliation"].clone();
                let mut previous = task.clone();
                previous.as_object_mut().unwrap().remove("history");
                let mut history = task.get("history").cloned().unwrap_or_else(|| json!([]));
                history
                    .as_array_mut()
                    .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Invalid session history"))?
                    .push(previous);
                task["history"] = history;
                task["state"] = json!("reconciled");
                task["outcomeUnknown"] = json!(false);
                task["code"] = Value::Null;
                task["reconciliation"] = reconciliation;
                changed = true;
            }
            if changed {
                session["updatedAt"] = json!(now());
                self.save(&session)?;
            }
        }
        Ok(())
    }
    pub fn reconcile_local_mcp(
        &self,
        id: &str,
        task_id: &str,
        node_id: &str,
        note: &str,
    ) -> Result<Value> {
        if note.trim().is_empty() || note.len() > 2000 || note.chars().any(char::is_control) {
            return Err(IcError::new(
                "INVALID_RECONCILIATION",
                "A printable owner inspection note is required",
            ));
        }
        let _lock = self.lock.lock().unwrap();
        let mut session = self.get(id)?;
        let task = session["tasks"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|task| task["taskId"] == task_id)
            .ok_or_else(|| IcError::new("TASK_NOT_FOUND", "Session task not found"))?;
        if task["origin"] != "aggregated" || task["peerId"] != node_id || task["state"] != "unknown"
        {
            return Err(IcError::new(
                "INVALID_RECONCILIATION",
                "Only unknown local aggregated MCP operations may be reconciled",
            ));
        }
        task["state"] = json!("reconciled");
        task["outcomeUnknown"] = json!(false);
        task["reconciledAt"] = json!(now());
        task["reconciliationNote"] = json!(note);
        let result = task.clone();
        session["updatedAt"] = json!(now());
        self.save(&session)?;
        Ok(result)
    }
    pub fn local_directory(&self, id: &str, allow_temporary: bool) -> Result<PathBuf> {
        let session = self.get(id)?;
        if let Some(cwd) = session["cwd"].as_str() {
            let path = PathBuf::from(cwd);
            let metadata = std::fs::metadata(&path)?;
            if std::fs::canonicalize(&path)? != path
                || !metadata.is_dir()
                || session["directoryIdentity"]
                    != json!({"dev":metadata.dev(),"ino":metadata.ino()})
            {
                return Err(IcError::new(
                    "WORKSPACE_CHANGED",
                    "Session directory changed",
                ));
            }
            return Ok(path);
        }
        if !allow_temporary {
            return Err(IcError::new(
                "TEMPORARY_WORKSPACE_DISABLED",
                "This node requires an explicit working directory",
            ));
        }
        let root = self.directory.join("workspaces").join(id);
        ensure_private_dir(&root)?;
        Ok(root)
    }
}
