use intelligent_cells::{
    Config,
    harness::fixture,
    node::Node,
    operator::{review_identity, start},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
};
fn node(dir: &Path) -> std::sync::Arc<Node> {
    fixture(dir, &["owner".into(), "peer".into()]).unwrap();
    let pin =
        intelligent_cells::tls::certificate_identity(&fs::read(dir.join("peer.pem")).unwrap())
            .unwrap()["fingerprint256"]
            .clone();
    let raw = json!({"id":"owner","security":{"cert":"owner.pem","key":"owner.key","ca":"ca.pem","trustedPeers":{"peer":pin}},"policy":{"grants":{}},"peers":[],"operator":{"port":0,"sessionDirectory":dir.join("owner-access"),"socketPath":dir.join("owner-access/control.sock")}});
    let path = dir.join("owner.json");
    fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    Node::new(Config {
        raw,
        id: "owner".into(),
        host: "127.0.0.1".into(),
        port: 0,
        path,
        state_dir: dir.join("state"),
    })
    .unwrap()
}
#[test]
fn owner_http_cookie_csrf_origin_and_ipc() {
    let d = tempfile::tempdir().unwrap();
    let n = node(d.path());
    let mut op = start(n.clone()).unwrap();
    assert!(start(n.clone()).is_err());
    assert_eq!(
        fs::read_dir(d.path().join("owner-access")).unwrap().count(),
        2
    );
    let info = op.info();
    let base = info["url"].as_str().unwrap();
    let client = reqwest::blocking::Client::new();
    let html = client.get(base).send().unwrap();
    assert_eq!(html.status(), 200);
    assert_eq!(html.headers()["cache-control"], "no-store");
    assert!(
        html.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    let text = html.text().unwrap();
    assert!(!text.contains(info["bootstrapToken"].as_str().unwrap()));
    let post = |route: &str, v: Value| {
        client
            .post(format!("{base}{route}"))
            .header("Origin", base)
            .json(&v)
            .send()
            .unwrap()
    };
    assert_eq!(
        client
            .get(format!("{base}/api/state"))
            .send()
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{base}/api/session"))
            .header("Origin", "https://attacker.invalid")
            .json(&json!({"token":info["bootstrapToken"]}))
            .send()
            .unwrap()
            .status(),
        403
    );
    let r = post("/api/session", json!({"token":info["bootstrapToken"]}));
    assert_eq!(r.status(), 200);
    let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let sid = cookie.split(';').next().unwrap();
    let csrf = r.json::<Value>().unwrap()["csrf"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        post("/api/session", json!({"token":info["bootstrapToken"]})).status(),
        403
    );
    let session = client
        .get(format!("{base}/api/session"))
        .header("Cookie", sid)
        .send()
        .unwrap()
        .json::<Value>()
        .unwrap();
    assert!(session["expiresAt"].is_u64());
    let state = client
        .get(format!("{base}/api/state"))
        .header("Cookie", sid)
        .send()
        .unwrap()
        .json::<Value>()
        .unwrap();
    assert_eq!(state["ok"], true, "{state}");
    assert!(state["incoming"]["records"].is_array());
    assert!(state["outgoing"]["records"].is_array());
    assert!(state["identity"]["expiresInDays"].is_number());
    assert!(state["jobs"]["jobs"].is_array());
    let logs = client
        .get(format!("{base}/api/logs"))
        .header("Cookie", sid)
        .send()
        .unwrap()
        .json::<Value>()
        .unwrap();
    assert_eq!(logs["ok"], true);
    assert!(logs["records"].is_array());

    assert_eq!(
        client
            .post(format!("{base}/api/command"))
            .header("Origin", base)
            .header("Cookie", sid)
            .json(&json!({"command":"status"}))
            .send()
            .unwrap()
            .status(),
        403
    );
    let r = client
        .post(format!("{base}/api/command"))
        .header("Origin", base)
        .header("Cookie", sid)
        .header("x-operator-csrf", csrf)
        .json(&json!({"command":"status"}))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<Value>().unwrap()["result"]["id"], "owner");
    assert_eq!(
        client
            .get(format!("{base}/api/session"))
            .header("Cookie", sid)
            .header("Host", "attacker.invalid")
            .send()
            .unwrap()
            .status(),
        403
    );
    let owner = info["ownerFile"].as_str().unwrap();
    assert_eq!(fs::metadata(owner).unwrap().permissions().mode() & 0o077, 0);
    let access: Value = serde_json::from_slice(&fs::read(owner).unwrap()).unwrap();
    assert_eq!(
        post("/api/ownerSession", json!({"secret":access["secret"]})).status(),
        200
    );
    let socket = info["socketPath"].as_str().unwrap();
    assert_eq!(
        fs::metadata(socket).unwrap().permissions().mode() & 0o077,
        0
    );
    let mut ipc = UnixStream::connect(socket).unwrap();
    ipc.write_all(b"{\"command\":\"operatorSession\"}\n")
        .unwrap();
    let mut text = String::new();
    ipc.read_to_string(&mut text).unwrap();
    assert!(
        serde_json::from_str::<Value>(&text).unwrap()["url"]
            .as_str()
            .unwrap()
            .starts_with(base)
    );
    op.shutdown().unwrap();
    assert!(!Path::new(owner).exists());
    assert!(!Path::new(socket).exists());
    n.shutdown().unwrap();
}
#[test]
fn identity_review_enforces_ca_identity_and_independent_pin() {
    let d = tempfile::tempdir().unwrap();
    fixture(d.path(), &["peer".into()]).unwrap();
    let pem = fs::read_to_string(d.path().join("peer.pem")).unwrap();
    let ca = fs::read(d.path().join("ca.pem")).unwrap();
    let pin =
        intelligent_cells::tls::certificate_identity(pem.as_bytes()).unwrap()["fingerprint256"]
            .as_str()
            .unwrap()
            .to_string();
    assert!(review_identity(&pem, "peer", &pin, &ca).is_ok());
    assert_eq!(
        review_identity(&pem, "other", &pin, &ca).unwrap_err().code,
        "IDENTITY_MISMATCH"
    );
    assert_eq!(
        review_identity(&pem, "peer", &"00".repeat(32), &ca)
            .unwrap_err()
            .code,
        "PIN_MISMATCH"
    );
    let unrelated = tempfile::tempdir().unwrap();
    fixture(unrelated.path(), &["other".into()]).unwrap();
    assert_eq!(
        review_identity(
            &pem,
            "peer",
            &pin,
            &fs::read(unrelated.path().join("ca.pem")).unwrap()
        )
        .unwrap_err()
        .code,
        "UNTRUSTED_CA"
    );
}
#[test]
fn legacy_identity_commands_cannot_mutate_configuration() {
    let d = tempfile::tempdir().unwrap();
    let n = node(d.path());
    let path = d.path().join("owner.json");
    let before = fs::read(&path).unwrap();
    for command in ["pairPeer", "removePeerPin", "revokePeer", "reviewPeer"] {
        let error = intelligent_cells::operator::owner_command(
            &n,
            &json!({"command":command,"peerId":"peer"}),
        )
        .unwrap_err();
        assert_eq!(error.code, "REMOVED_COMMAND", "{command}");
        assert!(error.message.contains("ic pair"));
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    n.shutdown().unwrap();
}

#[test]
fn custom_web_entry_rejects_private_roots_without_config_loader() {
    for relative in ["", "state", "owner-access"] {
        let d = tempfile::tempdir().unwrap();
        let original = node(d.path());
        let mut config = original.config();
        drop(original);
        let root = d.path().join(relative);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("index.html"), "Private data must not be served").unwrap();
        config.raw["operator"]["uiRoot"] = json!(root);
        let n = Node::new(config).unwrap();
        let error = match start(n.clone()) {
            Ok(mut operator) => {
                operator.shutdown().unwrap();
                panic!("Private root accepted: {relative}");
            }
            Err(error) => error,
        };
        assert_eq!(error.code, "UNSAFE_UI_ROOT");
        n.shutdown().unwrap();
    }
}

#[test]
fn custom_web_entry_and_assets_keep_api_protected() {
    let d = tempfile::tempdir().unwrap();
    let original = node(d.path());
    let root = d.path().join("web");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("assets")).unwrap();
    fs::write(root.join("console.html"), "<title>Custom console</title>").unwrap();
    fs::write(root.join("assets/main.js"), "console.log('custom');").unwrap();
    let mut config = original.config();
    drop(original);
    config.raw["operator"]["uiRoot"] = json!(root);
    config.raw["operator"]["entry"] = json!("console.html");
    let n = Node::new(config).unwrap();
    let mut op = start(n.clone()).unwrap();
    let info = op.info();
    let base = info["url"].as_str().unwrap();
    let client = reqwest::blocking::Client::new();
    assert_eq!(
        client.get(base).send().unwrap().text().unwrap(),
        "<title>Custom console</title>"
    );
    let asset = client.get(format!("{base}/assets/main.js")).send().unwrap();
    assert_eq!(asset.status(), 200);
    assert_eq!(
        asset.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );
    fs::write(root.join("console.html"), "<title>Replaced</title>").unwrap();
    assert_eq!(
        client.get(base).send().unwrap().text().unwrap(),
        "<title>Replaced</title>"
    );
    assert_eq!(
        client
            .get(format!("{base}/api/state"))
            .send()
            .unwrap()
            .status(),
        403
    );
    fs::write(d.path().join("secret"), "PRIVATE").unwrap();
    std::os::unix::fs::symlink(d.path().join("secret"), root.join("leak.txt")).unwrap();
    fs::hard_link(d.path().join("secret"), root.join("hardlink.txt")).unwrap();
    std::os::unix::fs::symlink(d.path(), root.join("outside")).unwrap();
    for path in [
        "leak.txt",
        "hardlink.txt",
        "outside/secret",
        "%2e%2e/secret",
    ] {
        let response = client.get(format!("{base}/{path}")).send().unwrap();
        assert_ne!(response.status(), 200, "{path}");
        assert!(!response.text().unwrap().contains("PRIVATE"));
    }
    op.shutdown().unwrap();
    n.shutdown().unwrap();
}

#[test]
fn custom_web_entry_rejects_escape_at_startup() {
    let d = tempfile::tempdir().unwrap();
    let original = node(d.path());
    let mut config = original.config();
    drop(original);
    config.raw["operator"]["uiRoot"] = json!(d.path());
    config.raw["operator"]["entry"] = json!("../secret.html");
    let n = Node::new(config).unwrap();
    assert!(start(n.clone()).is_err());
    n.shutdown().unwrap();
}
