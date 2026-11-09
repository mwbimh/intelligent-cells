use crate::error::{IcError, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
const BLOOM_BYTES: usize = 262144;
const MAX_RETIRED: u64 = 200000;
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || fs::canonicalize(dir)? != dir
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(IcError::new(
            "UNSAFE_STATE_DIRECTORY",
            "State directory must be canonical and owner-only",
        ));
    }
    Ok(())
}
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    private_dir(dir)
}
use std::os::unix::fs::DirBuilderExt;
fn safe_file(path: &Path, max: u64) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.nlink() != 1
        || m.len() > max
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(IcError::new(
            "JOURNAL_CORRUPT",
            "Unsafe or oversized journal file",
        ));
    }
    Ok(())
}
fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?.sync_all()?;
    Ok(())
}
pub fn write_checked(path: &Path, value: &Value) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| IcError::new("UNSAFE_STATE_FILE", "Missing parent"))?;
    ensure_private_dir(dir)?;
    match fs::symlink_metadata(path) {
        Ok(_) => safe_file(path, 16 * 1024 * 1024)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    };
    let data = serde_json::to_string(value)?;
    let envelope = json!({"format":1,"checksum":sha(data.as_bytes()),"data":data});
    let encoded = serde_json::to_vec(&envelope)?;
    if encoded.len() > 16 * 1024 * 1024 {
        return Err(IcError::new(
            "RESULT_TOO_LARGE",
            "State exceeds durable byte limit",
        ));
    }
    let temp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        sync_dir(dir)
    })();
    let _ = fs::remove_file(temp);
    result
}
pub fn read_checked(path: &Path) -> Result<Value> {
    safe_file(path, 16 * 1024 * 1024)?;
    let mut bytes = Vec::new();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.len() > 16 * 1024 * 1024
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(IcError::new("JOURNAL_CORRUPT", "Unsafe journal descriptor"));
    }
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    let parse = || -> Option<Value> {
        let e: Value = serde_json::from_slice(&bytes).ok()?;
        let data = e["data"].as_str()?;
        if e["format"] != 1 || e["checksum"] != sha(data.as_bytes()) {
            return None;
        }
        serde_json::from_str(data).ok()
    };
    parse().ok_or_else(|| {
        IcError::new(
            "JOURNAL_CORRUPT",
            "Invalid journal checksum or JSON; manual recovery required",
        )
    })
}
pub struct StateLock {
    path: PathBuf,
    nonce: String,
}
impl StateLock {
    pub fn acquire(dir: &Path) -> Result<Self> {
        ensure_private_dir(dir)?;
        let path = dir.join("owner.lock");
        let nonce = uuid::Uuid::new_v4().to_string();
        let create = || -> Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            f.write_all(&serde_json::to_vec(
                &json!({"pid":std::process::id(),"nonce":nonce}),
            )?)?;
            f.sync_all()?;
            sync_dir(dir)
        };
        match create() {
            Ok(()) => {}
            Err(e) if e.code == "EEXIST" => {
                let recovery = dir.join("recovery.lock");
                let guard = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&recovery)
                    .map_err(|_| {
                        IcError::new(
                            "STATE_LOCKED",
                            "Recovery is active or requires owner inspection",
                        )
                    })?;
                let result = (|| -> Result<()> {
                    safe_file(&path, 1024)
                        .map_err(|_| IcError::new("STATE_LOCKED", "Unsafe lock"))?;
                    let old: Value = serde_json::from_slice(&fs::read(&path)?)
                        .map_err(|_| IcError::new("STATE_LOCKED", "Corrupt lock"))?;
                    let pid = old["pid"]
                        .as_i64()
                        .filter(|p| *p > 0 && *p <= i32::MAX as i64)
                        .ok_or_else(|| IcError::new("STATE_LOCKED", "Invalid owner PID"))?
                        as i32;
                    if unsafe { libc::kill(pid, 0) } == 0
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                    {
                        return Err(IcError::new("STATE_LOCKED", "Another process owns state"));
                    }
                    fs::remove_file(&path)?;
                    create()
                })();
                drop(guard);
                fs::remove_file(&recovery)?;
                sync_dir(dir)?;
                result?;
            }
            Err(e) => return Err(e),
        }
        Ok(Self { path, nonce })
    }
}
impl Drop for StateLock {
    fn drop(&mut self) {
        if let Ok(bytes) = fs::read(&self.path)
            && let Ok(v) = serde_json::from_slice::<Value>(&bytes)
            && v["nonce"] == self.nonce
        {
            let _ = fs::remove_file(&self.path);
            if let Some(dir) = self.path.parent() {
                let _ = sync_dir(dir);
            }
        }
    }
}
fn uncertainty(v: &Value) -> bool {
    match v {
        Value::Object(o) => {
            o.get("outcomeUnknown") == Some(&Value::Bool(true)) || o.values().any(uncertainty)
        }
        Value::Array(a) => a.iter().any(uncertainty),
        _ => false,
    }
}
pub struct DurableStore {
    dir: PathBuf,
    max_records: usize,
    max_bytes: u64,
    records: BTreeMap<String, Value>,
    bytes: u64,
    bloom: Vec<u8>,
    retired_count: u64,
    failed: bool,
}
impl DurableStore {
    pub fn open(dir: &Path, max_records: usize, max_bytes: u64) -> Result<Self> {
        ensure_private_dir(dir)?;
        let mut store = Self {
            dir: dir.into(),
            max_records,
            max_bytes,
            records: BTreeMap::new(),
            bytes: 0,
            bloom: vec![0; BLOOM_BYTES],
            retired_count: 0,
            failed: false,
        };
        let entries = fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
        let meta = dir.join("meta.json");
        if meta.exists() {
            let v = read_checked(&meta)?;
            use base64::Engine;
            store.bloom = base64::engine::general_purpose::STANDARD
                .decode(v["bloom"].as_str().unwrap_or(""))
                .map_err(|_| IcError::new("JOURNAL_CORRUPT", "Invalid tombstones"))?;
            store.retired_count = v["retiredCount"].as_u64().unwrap_or(u64::MAX);
            if v["kind"] != "task-store"
                || v["bloomBytes"] != BLOOM_BYTES
                || store.bloom.len() != BLOOM_BYTES
                || store.retired_count > MAX_RETIRED
            {
                return Err(IcError::new(
                    "JOURNAL_CORRUPT",
                    "Invalid retention metadata",
                ));
            }
        } else {
            if entries
                .iter()
                .any(|e| e.path().extension().is_some_and(|x| x == "json"))
            {
                return Err(IcError::new(
                    "JOURNAL_CORRUPT",
                    "Missing retention metadata",
                ));
            }
            store.save_meta()?;
        }
        for entry in entries {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "meta.json" {
                continue;
            }
            if name.starts_with('.') && name.ends_with(".tmp") {
                let parts: Vec<_> = name.split('.').collect();
                if parts.len() != 5
                    || parts[2] != "json"
                    || uuid::Uuid::parse_str(parts[3]).is_err()
                    || !(parts[1] == "meta"
                        || parts[1].len() == 64
                            && parts[1]
                                .bytes()
                                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
                {
                    return Err(IcError::new("JOURNAL_CORRUPT", "Unexpected staging file"));
                }
                safe_file(&entry.path(), 16 * 1024 * 1024)?;
                fs::remove_file(entry.path())?;
                sync_dir(dir)?;
                continue;
            }
            if name.len() != 69
                || !name.ends_with(".json")
                || !name[..64]
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(IcError::new("JOURNAL_CORRUPT", "Unexpected journal file"));
            }
            let v = read_checked(&entry.path())?;
            let key = v["key"]
                .as_str()
                .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Invalid key"))?;
            if format!("{}.json", sha(key.as_bytes())) != name || !v["value"].is_object() {
                return Err(IcError::new("JOURNAL_CORRUPT", "Invalid record"));
            }
            let val = v["value"].clone();
            store.bytes += serde_json::to_vec(&val)?.len() as u64;
            store.records.insert(key.into(), val);
        }
        if store.records.len() > max_records || store.bytes > max_bytes {
            return Err(IcError::new(
                "JOURNAL_CAPACITY",
                "Limits below retained state",
            ));
        }
        Ok(store)
    }
    fn indexes(key: &str) -> Vec<usize> {
        let d = Sha256::digest(key.as_bytes());
        (0..7)
            .map(|i| {
                u32::from_be_bytes(d[i * 4..i * 4 + 4].try_into().unwrap()) as usize
                    % (BLOOM_BYTES * 8)
            })
            .collect()
    }
    pub fn retired(&self, key: &str) -> bool {
        Self::indexes(key)
            .iter()
            .all(|b| self.bloom[b / 8] & (1 << (b % 8)) != 0)
    }
    fn save_meta(&self) -> Result<()> {
        use base64::Engine;
        write_checked(
            &self.dir.join("meta.json"),
            &json!({"kind":"task-store","bloomBytes":BLOOM_BYTES,"retiredCount":self.retired_count,"bloom":base64::engine::general_purpose::STANDARD.encode(&self.bloom)}),
        )
    }
    pub fn get(&self, key: &str) -> Option<Value> {
        self.records.get(key).cloned()
    }
    pub fn values(&self) -> Vec<Value> {
        self.records.values().cloned().collect()
    }
    pub fn put(&mut self, key: &str, value: Value) -> Result<()> {
        if self.failed {
            return Err(IcError::new(
                "JOURNAL_UNAVAILABLE",
                "Storage failed; inspect before restart",
            ));
        }
        if !value.is_object() {
            return Err(IcError::new("INVALID_ARGS", "Record must be object"));
        }
        let existing = self.records.contains_key(key);
        if !existing && self.retired(key) {
            return Err(IcError::new(
                "TASK_HISTORY_EXPIRED",
                "Operation ID retired; never replay",
            ));
        }
        let size = serde_json::to_vec(&value)?.len() as u64;
        if size > 1024 * 1024 || size > self.max_bytes {
            return Err(IcError::new(
                "RESULT_TOO_LARGE",
                "Record exceeds storage limit",
            ));
        }
        let old = self
            .records
            .get(key)
            .map(|v| serde_json::to_vec(v).unwrap().len() as u64)
            .unwrap_or(0);
        let result = (|| -> Result<()> {
            if self.records.len() + usize::from(!existing) > self.max_records
                || self.bytes - old + size > self.max_bytes
            {
                let mut candidates: Vec<_> = self
                    .records
                    .iter()
                    .filter(|(k, v)| {
                        k.as_str() != key
                            && !uncertainty(v)
                            && !matches!(
                                v["state"].as_str(),
                                Some("unknown" | "running" | "dispatching" | "pending")
                            )
                    })
                    .map(|(k, v)| (k.clone(), v["updatedAt"].as_u64().unwrap_or(0)))
                    .collect();
                candidates.sort_by_key(|(_, t)| *t);
                let mut remove = Vec::new();
                let mut freed = 0;
                for (k, _) in candidates {
                    freed += serde_json::to_vec(&self.records[&k])?.len() as u64;
                    remove.push(k);
                    if remove.len() >= self.max_records.div_ceil(4).max(1)
                        && self.records.len() - remove.len() + usize::from(!existing)
                            <= self.max_records
                        && self.bytes - freed - old + size <= self.max_bytes
                    {
                        break;
                    }
                }
                if remove.is_empty()
                    || self.records.len() - remove.len() + usize::from(!existing) > self.max_records
                    || self.bytes - freed - old + size > self.max_bytes
                    || self.retired_count + remove.len() as u64 > MAX_RETIRED
                {
                    return Err(IcError::new(
                        "TASK_STORE_FULL",
                        "Unresolved records prevent safe retention",
                    ));
                }
                for k in &remove {
                    for b in Self::indexes(k) {
                        self.bloom[b / 8] |= 1 << (b % 8);
                    }
                }
                self.retired_count += remove.len() as u64;
                self.save_meta()?;
                for k in remove {
                    fs::remove_file(self.dir.join(format!("{}.json", sha(k.as_bytes()))))?;
                    let v = self.records.remove(&k).unwrap();
                    self.bytes -= serde_json::to_vec(&v)?.len() as u64;
                }
                sync_dir(&self.dir)?;
            }
            write_checked(
                &self.dir.join(format!("{}.json", sha(key.as_bytes()))),
                &json!({"key":key,"value":value}),
            )?;
            self.bytes = self.bytes - old + size;
            self.records.insert(key.into(), value);
            Ok(())
        })();
        if let Err(e) = &result
            && e.code != "TASK_STORE_FULL"
        {
            self.failed = true;
        }
        result
    }
    pub fn assert_limits(&self, max_records: usize, max_bytes: u64) -> Result<()> {
        if self.failed {
            return Err(IcError::new(
                "JOURNAL_UNAVAILABLE",
                "Storage failed; inspect before restart",
            ));
        }
        if self.records.len() > max_records || self.bytes > max_bytes {
            return Err(IcError::new(
                "JOURNAL_CAPACITY",
                "Proposed limits below retained state",
            ));
        }
        Ok(())
    }
    pub fn configure(&mut self, max_records: usize, max_bytes: u64) -> Result<()> {
        self.assert_limits(max_records, max_bytes)?;
        self.max_records = max_records;
        self.max_bytes = max_bytes;
        Ok(())
    }
    pub fn info(&self) -> Value {
        json!({"records":self.records.len(),"bytes":self.bytes,"maxRecords":self.max_records,"maxBytes":self.max_bytes,"retiredCount":self.retired_count,"maxRetired":MAX_RETIRED,"tombstones":"bounded-bloom-fail-closed"})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    #[test]
    fn checksum_and_owner_lock() {
        let d = dir();
        let p = d.path().join("state.json");
        write_checked(&p, &json!({"v":1})).unwrap();
        assert_eq!(read_checked(&p).unwrap()["v"], 1);
        fs::write(&p, b"{}").unwrap();
        assert_eq!(read_checked(&p).unwrap_err().code, "JOURNAL_CORRUPT");
        let lock = StateLock::acquire(d.path()).unwrap();
        assert!(StateLock::acquire(d.path()).is_err());
        drop(lock);
        StateLock::acquire(d.path()).unwrap();
    }
    #[test]
    fn retired_ids_survive_restart_unknown_never_evicted() {
        let d = dir();
        let mut s = DurableStore::open(d.path(), 1, 10000).unwrap();
        s.put("first", json!({"state":"done"})).unwrap();
        s.put("second", json!({"state":"unknown"})).unwrap();
        assert!(s.retired("first"));
        assert_eq!(
            s.put("third", json!({"state":"done"})).unwrap_err().code,
            "TASK_STORE_FULL"
        );
        drop(s);
        let mut s = DurableStore::open(d.path(), 1, 10000).unwrap();
        assert_eq!(
            s.put("first", json!({"state":"done"})).unwrap_err().code,
            "TASK_HISTORY_EXPIRED"
        );
    }
    #[test]
    fn nested_unknown_is_never_retired() {
        let d = dir();
        let mut s = DurableStore::open(d.path(), 1, 10000).unwrap();
        s.put(
            "first",
            json!({"state":"completed","response":{"error":{"outcomeUnknown":true}}}),
        )
        .unwrap();
        assert_eq!(
            s.put("second", json!({"state":"completed"}))
                .unwrap_err()
                .code,
            "TASK_STORE_FULL"
        );
        assert!(!s.retired("first"));
    }
    #[test]
    fn linked_files_rejected() {
        let d = dir();
        let p = d.path().join("data.json");
        write_checked(&p, &json!({})).unwrap();
        fs::hard_link(&p, d.path().join("link")).unwrap();
        assert!(read_checked(&p).is_err());
        assert!(write_checked(&p, &json!({})).is_err());
    }
}
