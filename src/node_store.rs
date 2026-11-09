//! Private node identity, relationships and directory mappings, separate from settings.
use crate::{
    durable::ensure_private_dir,
    error::{IcError, Result},
    model::Config,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Settings composition supplies nodesFile. Direct library fixtures keep node metadata
/// in their isolated state directory and do not use CLI configuration discovery.
pub fn directory(config: &Config) -> PathBuf {
    config.raw["nodesFile"]
        .as_str()
        .and_then(|p| Path::new(p).parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| config.state_dir.clone())
}
fn invalid(message: &str) -> IcError {
    IcError::new("INVALID_NODES", message)
}
fn inspect(file: &File) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() > MAX_BYTES
    {
        return Err(invalid(
            "Node files must be private, regular, single-link and bounded",
        ));
    }
    Ok(())
}
fn lock(directory: &Path) -> Result<File> {
    ensure_private_dir(directory)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join(".nodes.lock"))?;
    inspect(&file)?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e.into());
        }
    }
}
fn read(directory: &Path) -> Result<Value> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("nodes.json"))
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(json!({"version":1})),
        Err(e) => return Err(e.into()),
    };
    inspect(&file)?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("Node metadata exceeds byte limit"));
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if !value.is_object() || value["version"] != 1 {
        return Err(invalid("Invalid node metadata version"));
    }
    Ok(value)
}
fn write(directory: &Path, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("Node metadata exceeds byte limit"));
    }
    let temp = directory.join(format!(".nodes.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, directory.join("nodes.json"))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}
pub fn initialize(directory: &Path, id: &str, name: &str) -> Result<()> {
    uuid::Uuid::parse_str(id).map_err(|_| invalid("Node identity must be a UUID"))?;
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(invalid("Invalid node display name"));
    }
    let _lock = lock(directory)?;
    let mut value = read(directory)?;
    if let Some(identity) = value.get("self") {
        if identity["id"] != id {
            return Err(invalid("Cannot replace existing node identity"));
        }
        return Ok(());
    }
    value["self"] = json!({"id":id,"name":name});
    write(directory, &value)
}
pub fn self_identity(directory: &Path) -> Result<Value> {
    let identity = read_section(directory, "self")?
        .ok_or_else(|| IcError::new("ENOENT", "Node identity has not been initialized"))?;
    uuid::Uuid::parse_str(identity["id"].as_str().unwrap_or(""))
        .map_err(|_| invalid("Node identity must be a UUID"))?;
    if identity["name"].as_str().is_none() {
        return Err(invalid("Node display name missing"));
    }
    Ok(identity)
}
pub fn rename_self(directory: &Path, name: &str) -> Result<Value> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(invalid("Invalid node display name"));
    }
    let _lock = lock(directory)?;
    let mut value = read(directory)?;
    let identity = value
        .get_mut("self")
        .ok_or_else(|| IcError::new("ENOENT", "Node identity has not been initialized"))?;
    uuid::Uuid::parse_str(identity["id"].as_str().unwrap_or(""))
        .map_err(|_| invalid("Node identity must be a UUID"))?;
    identity["name"] = json!(name);
    let renamed = identity.clone();
    write(directory, &value)?;
    Ok(renamed)
}
pub fn read_section(directory: &Path, section: &str) -> Result<Option<Value>> {
    let _lock = lock(directory)?;
    Ok(read(directory)?.get(section).cloned())
}
pub fn write_section(directory: &Path, section: &str, section_value: &Value) -> Result<()> {
    if section == "version" || section == "self" {
        return Err(invalid("Reserved node metadata section"));
    }
    let _lock = lock(directory)?;
    let mut value = read(directory)?;
    value[section] = section_value.clone();
    write(directory, &value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[test]
    fn sections_share_one_plain_private_file_without_lost_writes() {
        let d = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        initialize(d.path(), &id, "My node").unwrap();
        std::thread::scope(|scope| {
            for n in 0..12 {
                let root = d.path();
                scope.spawn(move || {
                    write_section(root, &format!("section{n}"), &json!({"value":n})).unwrap()
                });
            }
        });
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(d.path().join("nodes.json")).unwrap()).unwrap();
        assert_eq!(raw["self"], json!({"id":id,"name":"My node"}));
        for n in 0..12 {
            assert_eq!(
                read_section(d.path(), &format!("section{n}"))
                    .unwrap()
                    .unwrap()["value"],
                n
            );
        }
        assert_eq!(
            fs::metadata(d.path().join("nodes.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(initialize(d.path(), &uuid::Uuid::new_v4().to_string(), "Replacement").is_err());
        assert_eq!(self_identity(d.path()).unwrap()["id"], id);
    }

    #[test]
    fn rename_changes_display_name_without_changing_identity_or_sections() {
        let d = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        initialize(d.path(), &id, "Old name").unwrap();
        write_section(d.path(), "control", &json!({"policyEpoch":7})).unwrap();
        let renamed = rename_self(d.path(), "New name").unwrap();
        assert_eq!(renamed, json!({"id":id,"name":"New name"}));
        assert_eq!(self_identity(d.path()).unwrap(), renamed);
        assert_eq!(
            read_section(d.path(), "control").unwrap().unwrap()["policyEpoch"],
            7
        );
        for name in ["", "bad\nname"] {
            assert!(rename_self(d.path(), name).is_err());
            assert_eq!(self_identity(d.path()).unwrap(), renamed);
        }
        assert!(rename_self(d.path(), &"a".repeat(129)).is_err());
    }

    #[test]
    fn unsafe_or_corrupt_nodes_file_is_not_replaced() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("target");
        fs::write(&target, b"sentinel").unwrap();
        symlink(&target, d.path().join("nodes.json")).unwrap();
        assert!(write_section(d.path(), "control", &json!({})).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"sentinel");
    }
}
