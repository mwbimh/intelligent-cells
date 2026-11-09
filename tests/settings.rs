use intelligent_cells::settings;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn initialization_separates_settings_and_identity_and_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(dir.path()).unwrap().join("config.json");
    settings::initialize(Some(&path)).unwrap();
    let raw: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for key in ["id", "name", "peers", "policy"] {
        assert!(raw.get(key).is_none(), "{key}");
    }
    let first = settings::check_config(&path).unwrap();
    assert!(uuid::Uuid::parse_str(&first.id).is_ok());
    let cert = fs::read(first.raw["security"]["cert"].as_str().unwrap()).unwrap();
    settings::initialize(Some(&path)).unwrap();
    let second = settings::check_config(&path).unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(
        cert,
        fs::read(second.raw["security"]["cert"].as_str().unwrap()).unwrap()
    );
    let key = second.raw["security"]["key"].as_str().unwrap();
    assert_eq!(fs::metadata(key).unwrap().permissions().mode() & 0o077, 0);
}

#[test]
fn configuration_updates_validate_and_preserve_previous_settings_on_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(dir.path()).unwrap().join("config.json");
    settings::initialize(Some(&path)).unwrap();
    settings::set_config(&path, "port", json!(18433)).unwrap();
    assert_eq!(settings::check_config(&path).unwrap().port, 18433);
    let before = fs::read(&path).unwrap();
    assert!(settings::set_config(&path, "port", json!(70000)).is_err());
    assert_eq!(before, fs::read(&path).unwrap());
    assert!(settings::set_config(&path, "id", json!("renamed")).is_err());
}

#[test]
fn configuration_rejects_invalid_session_and_web_settings_without_committing() {
    let dir = tempfile::tempdir().unwrap();
    let path = fs::canonicalize(dir.path()).unwrap().join("config.json");
    settings::initialize(Some(&path)).unwrap();
    let before = fs::read(&path).unwrap();
    for (key, value) in [
        ("sessions.allowTemporary", json!("false")),
        ("sessions", json!(false)),
        ("operator", json!({"entry":"index.html"})),
        ("operator", json!({"uiRoot":"relative/public"})),
        ("operator", json!({"uiRoot":42})),
    ] {
        assert!(
            settings::set_config(&path, key, value).is_err(),
            "accepted {key}"
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let web = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(web.path()).unwrap();
    fs::write(root.join("index.html"), "<h1>IC</h1>").unwrap();
    for entry in [
        "../index.html",
        "api/index.html",
        "index.js",
        "missing.html",
        "%2e.html",
    ] {
        assert!(
            settings::set_config(&path, "operator", json!({"uiRoot":root,"entry":entry})).is_err(),
            "accepted {entry}"
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    settings::set_config(
        &path,
        "operator",
        json!({"uiRoot":root,"entry":"index.html"}),
    )
    .unwrap();
    assert_eq!(
        settings::check_config(&path).unwrap().raw["operator"]["uiRoot"],
        json!(root)
    );
}

#[test]
fn selecting_invalid_configuration_preserves_previous_selection() {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    let path = root.join("config.json");
    settings::initialize(Some(&path)).unwrap();
    let home = root.join("selection-home");
    let select = |path: &std::path::Path| {
        std::process::Command::new(env!("CARGO_BIN_EXE_ic"))
            .env("IC_HOME", &home)
            .args(["config", "use", "--config"])
            .arg(path)
            .output()
            .unwrap()
    };
    let valid = select(&path);
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    let before = fs::read(home.join("selection.json")).unwrap();
    let bad = root.join("invalid.json");
    fs::write(&bad, "{}").unwrap();
    assert!(!select(&bad).status.success());
    assert_eq!(fs::read(home.join("selection.json")).unwrap(), before);
}
