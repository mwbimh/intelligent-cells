//! Resident service configuration selection and automatic node identity provisioning.
use crate::{Config, IcError, Result};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn invalid(message: impl Into<String>) -> IcError {
    IcError::new("INVALID_CONFIG", message)
}
pub fn home_dir() -> Result<PathBuf> {
    let path = std::env::var_os("IC_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config/ic")))
        .ok_or_else(|| invalid("Set IC_HOME or HOME"))?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
pub fn selected_config_path() -> Result<PathBuf> {
    let home = home_dir()?;
    let selection = home.join("selection.json");
    match fs::read(&selection) {
        Ok(bytes) => {
            let value: Value = serde_json::from_slice(&bytes)?;
            let path = PathBuf::from(
                value["configPath"]
                    .as_str()
                    .ok_or_else(|| invalid("Invalid configuration selection"))?,
            );
            if !path.is_absolute() {
                return Err(invalid("Selected configuration path must be absolute"));
            }
            Ok(path)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(home.join("config.json")),
        Err(e) => Err(e.into()),
    }
}
pub fn select_config(path: &Path) -> Result<()> {
    check_config(path)?;
    let home = home_dir()?;
    crate::durable::ensure_private_dir(&home)?;
    write_json(
        &home.join("selection.json"),
        &json!({"configPath":fs::canonicalize(path)?}),
    )
}
pub fn load_selected() -> Result<Config> {
    check_config(&selected_config_path()?)
}
pub fn check_config(path: &Path) -> Result<Config> {
    let raw: Value = serde_json::from_slice(&fs::read(path)?)?;
    if raw["version"] != 2 {
        return Err(invalid(
            "Expected version 2 configuration; initialize with ic config init",
        ));
    }
    let config = crate::policy::load_config(path)?;
    crate::tls::Security::load(
        &config.raw["security"],
        config.path.parent().unwrap(),
        &config.id,
    )?
    .public_identity()?;
    Ok(config)
}
fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(stat) = fs::symlink_metadata(path)
        && (!stat.is_file()
            || stat.file_type().is_symlink()
            || stat.nlink() != 1
            || stat.uid() != unsafe { libc::geteuid() })
    {
        return Err(invalid("Refusing unsafe configuration or identity file"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Missing parent directory"))?;
    let temp = parent.join(format!(".ic-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
fn write_json(path: &Path, value: &Value) -> Result<()> {
    write_bytes(path, &serde_json::to_vec_pretty(value)?)
}

pub fn initialize(path: Option<&Path>) -> Result<PathBuf> {
    let path = path
        .map(Path::to_owned)
        .unwrap_or(home_dir()?.join("config.json"));
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Missing configuration directory"))?;
    crate::durable::ensure_private_dir(parent)?;
    let parent = fs::canonicalize(parent)?;
    let path = parent.join(
        path.file_name()
            .ok_or_else(|| invalid("Missing configuration filename"))?,
    );
    if path.exists() {
        check_config(&path)?;
        return Ok(path);
    }
    let id = match crate::node_store::self_identity(&parent) {
        Ok(value) => value["id"]
            .as_str()
            .ok_or_else(|| invalid("Missing local node identity"))?
            .to_owned(),
        Err(e) if e.code == "ENOENT" => {
            let id = uuid::Uuid::new_v4().to_string();
            crate::node_store::initialize(&parent, &id, "IC node")?;
            id
        }
        Err(e) => return Err(e),
    };
    provision_identity(&parent, &id)?;
    crate::durable::ensure_private_dir(&parent.join("state"))?;
    let raw = json!({"version":2,"host":"127.0.0.1","port":18433,"pairing":{"host":"127.0.0.1","port":18434},"security":{"allowExternal":false},"sessions":{"allowTemporary":true}});
    write_json(&path, &raw)?;
    check_config(&path)?;
    Ok(path)
}

pub fn set_config(path: &Path, key: &str, value: Value) -> Result<()> {
    check_config(path)?;
    let components: Vec<_> = key.split('.').collect();
    if components.iter().any(|k| k.is_empty())
        || matches!(
            components[0],
            "version"
                | "id"
                | "name"
                | "peers"
                | "policy"
                | "stateDir"
                | "nodesFile"
                | "mcpFile"
                | "agent"
        )
        || (components[0] == "security" && components.get(1).is_none_or(|k| *k != "allowExternal"))
    {
        return Err(invalid(
            "Identity, relationships and storage locations are not runtime settings",
        ));
    }
    let mut raw: Value = serde_json::from_slice(&fs::read(path)?)?;
    let mut cursor = &mut raw;
    for component in &components[..components.len() - 1] {
        let object = cursor
            .as_object_mut()
            .ok_or_else(|| invalid("Configuration key traverses a scalar value"))?;
        cursor = object
            .entry((*component).to_owned())
            .or_insert_with(|| json!({}));
    }
    cursor
        .as_object_mut()
        .ok_or_else(|| invalid("Configuration parent must be an object"))?
        .insert(components.last().unwrap().to_string(), value);
    let staged = path
        .parent()
        .unwrap()
        .join(format!(".config-check-{}.json", uuid::Uuid::new_v4()));
    write_json(&staged, &raw)?;
    let checked = check_config(&staged);
    fs::remove_file(&staged)?;
    checked?;
    write_json(path, &raw)
}

/// Assemble runtime-only identity and relationship fields without writing them into config.json.
pub fn compose_raw(path: &Path, mut raw: Value) -> Result<Value> {
    let directory = path
        .parent()
        .ok_or_else(|| invalid("Missing configuration directory"))?;
    for key in [
        "id",
        "name",
        "peers",
        "policy",
        "stateDir",
        "nodesFile",
        "mcpFile",
        "agent",
    ] {
        if raw.get(key).is_some() {
            return Err(invalid(format!(
                "{key} belongs in node storage, not runtime configuration"
            )));
        }
    }
    let me = crate::node_store::self_identity(directory)?;
    let id = me["id"]
        .as_str()
        .ok_or_else(|| invalid("Missing node UUID"))?;
    uuid::Uuid::parse_str(id).map_err(|_| invalid("Node identity must be a UUID"))?;
    let identity = directory.join("identity").join(id);
    raw["id"] = json!(id);
    raw["name"] = me["name"].clone();
    raw["nodesFile"] = json!(directory.join("nodes.json"));
    raw["mcpFile"] = json!(directory.join("mcp.json"));
    raw["stateDir"] = json!(directory.join("state"));
    raw["agent"] = json!("deterministic-demo");
    if raw.get("security").is_none() {
        raw["security"] = json!({});
    }
    if !raw["security"].is_object() {
        return Err(invalid("security must be an object"));
    }
    if raw["security"].get("trustedPeers").is_some() {
        return Err(invalid("Peer trust belongs in node storage"));
    }
    for (key, file) in [("cert", "cert.pem"), ("key", "key.pem"), ("ca", "ca.pem")] {
        if raw["security"].get(key).is_some() {
            return Err(invalid("Certificate paths are managed automatically"));
        }
        raw["security"][key] = json!(identity.join(file));
    }
    raw["security"]["trustedPeers"] = json!({});
    raw["peers"] = json!([]);
    if let Some(pairing) = crate::node_store::read_section(directory, "pairing")? {
        for peer in pairing["peers"].as_array().into_iter().flatten() {
            let peer_id = peer["identity"]["nodeId"]
                .as_str()
                .ok_or_else(|| invalid("Missing peer identity"))?;
            raw["security"]["trustedPeers"][peer_id] = json!([peer["identity"]["fingerprint256"]]);
            if peer["endpoint"].is_object() {
                raw["peers"].as_array_mut().unwrap().push(json!({"id":peer_id,"host":peer["endpoint"]["host"],"port":peer["endpoint"]["port"]}));
            }
        }
    }
    raw["policy"] = crate::node_store::read_section(directory, "control")?
        .and_then(|v| v.get("policyRaw").cloned())
        .unwrap_or_else(|| json!({}));
    Ok(raw)
}

fn provision_identity(directory: &Path, id: &str) -> Result<()> {
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
    let destination = directory.join("identity").join(id);
    if destination.exists() {
        for file in ["cert.pem", "key.pem", "ca.pem", "ca.key"] {
            let stat = fs::symlink_metadata(destination.join(file))?;
            if !stat.is_file()
                || stat.nlink() != 1
                || stat.mode() & 0o077 != 0
                || stat.uid() != unsafe { libc::geteuid() }
            {
                return Err(invalid("Unsafe automatic identity file"));
            }
        }
        return Ok(());
    }
    let parent = directory.join("identity");
    crate::durable::ensure_private_dir(&parent)?;
    let stage = parent.join(format!(".identity-{}", uuid::Uuid::new_v4()));
    crate::durable::ensure_private_dir(&stage)?;
    let ssl = |e: openssl::error::ErrorStack| IcError::new("TLS_ERROR", e.to_string());
    let ca_key = PKey::from_rsa(Rsa::generate(3072).map_err(ssl)?).map_err(ssl)?;
    let leaf_key = PKey::from_rsa(Rsa::generate(3072).map_err(ssl)?).map_err(ssl)?;
    let before = Asn1Time::days_from_now(0).map_err(ssl)?;
    let after = Asn1Time::days_from_now(3650).map_err(ssl)?;
    let serial = || -> Result<openssl::asn1::Asn1Integer> {
        let mut number = BigNum::new().map_err(ssl)?;
        number
            .rand(128, MsbOption::MAYBE_ZERO, false)
            .map_err(ssl)?;
        number.to_asn1_integer().map_err(ssl)
    };
    let mut ca_name = X509NameBuilder::new().map_err(ssl)?;
    ca_name
        .append_entry_by_text("CN", &format!("IC node authority {id}"))
        .map_err(ssl)?;
    let ca_name = ca_name.build();
    let mut ca = X509::builder().map_err(ssl)?;
    ca.set_version(2).map_err(ssl)?;
    let ca_serial = serial()?;
    ca.set_serial_number(ca_serial.as_ref()).map_err(ssl)?;
    ca.set_subject_name(&ca_name).map_err(ssl)?;
    ca.set_issuer_name(&ca_name).map_err(ssl)?;
    ca.set_pubkey(&ca_key).map_err(ssl)?;
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
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .map_err(ssl)?,
    )
    .map_err(ssl)?;
    ca.sign(&ca_key, MessageDigest::sha256()).map_err(ssl)?;
    let ca = ca.build();
    let mut subject = X509NameBuilder::new().map_err(ssl)?;
    subject.append_entry_by_text("CN", id).map_err(ssl)?;
    let mut cert = X509::builder().map_err(ssl)?;
    cert.set_version(2).map_err(ssl)?;
    let cert_serial = serial()?;
    cert.set_serial_number(cert_serial.as_ref()).map_err(ssl)?;
    cert.set_subject_name(&subject.build()).map_err(ssl)?;
    cert.set_issuer_name(ca.subject_name()).map_err(ssl)?;
    cert.set_pubkey(&leaf_key).map_err(ssl)?;
    cert.set_not_before(&before).map_err(ssl)?;
    cert.set_not_after(&after).map_err(ssl)?;
    cert.append_extension(BasicConstraints::new().critical().build().map_err(ssl)?)
        .map_err(ssl)?;
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()
            .map_err(ssl)?,
    )
    .map_err(ssl)?;
    cert.append_extension(
        ExtendedKeyUsage::new()
            .client_auth()
            .server_auth()
            .build()
            .map_err(ssl)?,
    )
    .map_err(ssl)?;
    cert.sign(&ca_key, MessageDigest::sha256()).map_err(ssl)?;
    write_bytes(&stage.join("ca.pem"), &ca.to_pem().map_err(ssl)?)?;
    write_bytes(
        &stage.join("ca.key"),
        &ca_key.private_key_to_pem_pkcs8().map_err(ssl)?,
    )?;
    write_bytes(
        &stage.join("cert.pem"),
        &cert.build().to_pem().map_err(ssl)?,
    )?;
    write_bytes(
        &stage.join("key.pem"),
        &leaf_key.private_key_to_pem_pkcs8().map_err(ssl)?,
    )?;
    fs::rename(&stage, &destination)?;
    fs::File::open(&parent)?.sync_all()?;
    Ok(())
}
