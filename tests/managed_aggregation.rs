//! Full managed-settings, independent-CA pairing and remote MCP execution path.
use intelligent_cells::{node::Node, settings};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

struct Resident(Arc<Node>);
impl Drop for Resident {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}
fn resident(directory: &Path) -> Resident {
    let path = settings::initialize(Some(&directory.join("config.json"))).unwrap();
    settings::set_config(&path, "port", json!(0)).unwrap();
    settings::set_config(&path, "pairing.port", json!(0)).unwrap();
    let config = settings::check_config(&path).unwrap();
    assert!(uuid::Uuid::parse_str(&config.id).is_ok());
    assert!(config.raw["nodesFile"].is_string());
    let node = Node::new(config).unwrap();
    node.start().unwrap();
    Resident(node)
}
fn operation(node: &Node, value: Value) -> Value {
    node.command(&json!({"command":"mcpRegistry","operation":value}))
        .unwrap()
}
fn dispatch(master: &Node, session: &Value, servant: &Node, tool: &str, args: Value) -> Value {
    master.command(&json!({"command":"sessionDispatch","sessionId":session["sessionId"],"peerId":servant.config().id,"task":{"taskId":uuid::Uuid::new_v4().to_string(),"tool":tool,"args":args,"timeoutMs":5000}})).unwrap()
}

#[test]
fn managed_remote_aggregation_enforces_visibility_and_keeps_storage_separate() {
    let directory = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(directory.path()).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let master = resident(&root.join("master"));
    let servant = resident(&root.join("servant"));
    let master = &master.0;
    let servant = &servant.0;
    assert_ne!(master.config().id, servant.config().id);
    assert_ne!(
        fs::read(master.config().raw["security"]["ca"].as_str().unwrap()).unwrap(),
        fs::read(servant.config().raw["security"]["ca"].as_str().unwrap()).unwrap()
    );
    let workspace = root.join("approved-workspace");
    fs::create_dir(&workspace).unwrap();
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
    let status = master.command(&json!({"command":"pairingStatus"})).unwrap();
    let address = json!({"id":master.config().id,"host":"127.0.0.1","port":status["port"],"fingerprint256":status["identity"]["fingerprint256"]});
    let request = servant
        .command(&json!({"command":"pairingRequest","master":address}))
        .unwrap();
    let identity = servant
        .command(&json!({"command":"pairingStatus"}))
        .unwrap();
    master.command(&json!({"command":"pairingApprove","requestId":request["requestId"],"expectedFingerprint":identity["identity"]["fingerprint256"]})).unwrap();
    servant.command(&json!({"command":"pairingConfirm","master":address,"requestId":request["requestId"],"grant":{"workspace":workspace,"tools":["capabilities","mcpList","mcpCall"],"maxTimeoutMs":10000}})).unwrap();

    let executable = root.join("approved-mcp-executable");
    fs::copy(env!("CARGO_BIN_EXE_ic-mcp-fixture"), &executable).unwrap();
    let server = operation(
        servant,
        json!({"command":"add","server":{"name":"Managed aggregate proof","file":executable,"args":[],"launchMode":"native","cwd":workspace,"visibility":{"local":true,"masters":[master.config().id]},"tools":{"safe":{"readOnly":true,"inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}}}}}),
    );
    let server_id = &server["server"]["id"];
    let session = master.command(&json!({"command":"sessionOpen"})).unwrap();
    let capabilities = dispatch(master, &session, servant, "capabilities", json!({}));
    assert_eq!(capabilities["status"], "ok", "{capabilities}");
    assert_eq!(capabilities["result"]["mcpServers"][0]["id"], *server_id);
    assert_eq!(
        capabilities["result"]["mcpServers"][0]["origin"],
        "aggregated"
    );
    let listed = dispatch(
        master,
        &session,
        servant,
        "mcpList",
        json!({"server":server_id}),
    );
    assert_eq!(listed["status"], "ok", "{listed}");
    assert_eq!(listed["result"]["tools"][0]["name"], "safe");
    let result = dispatch(
        master,
        &session,
        servant,
        "mcpCall",
        json!({"server":server_id,"tool":"safe","arguments":{"text":"managed TLS aggregation"}}),
    );
    assert_eq!(result["status"], "ok", "{result}");
    let payload: Value =
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["arguments"]["text"], "managed TLS aggregation");
    assert_eq!(
        payload["cwd"],
        json!(
            servant
                .config()
                .state_dir
                .join("session-workspaces")
                .join(&master.config().id)
                .join(session["sessionId"].as_str().unwrap())
        )
    );
    assert_eq!(payload["env"], json!([]));

    operation(
        servant,
        json!({"command":"update","id":server_id,"patch":{"visibility":{"local":false,"masters":"all"}}}),
    );
    let hidden = dispatch(
        master,
        &session,
        servant,
        "mcpCall",
        json!({"server":server_id,"tool":"safe","arguments":{"text":"hidden"}}),
    );
    assert_eq!(hidden["status"], "error", "{hidden}");
    assert_eq!(hidden["error"]["code"], "MCP_SERVER_DENIED");
    let hidden_capabilities = dispatch(master, &session, servant, "capabilities", json!({}));
    assert_eq!(hidden_capabilities["result"]["mcpServers"], json!([]));
    operation(
        servant,
        json!({"command":"update","id":server_id,"patch":{"visibility":{"local":true,"masters":"all"}}}),
    );
    operation(
        servant,
        json!({"command":"updateBuiltin","tool":"mcpCall","enabled":false}),
    );
    let disabled = dispatch(
        master,
        &session,
        servant,
        "mcpCall",
        json!({"server":server_id,"tool":"safe","arguments":{"text":"disabled"}}),
    );
    assert_eq!(disabled["status"], "error", "{disabled}");
    assert_eq!(disabled["error"]["code"], "TOOL_DENIED");
    let disabled_capabilities = dispatch(master, &session, servant, "capabilities", json!({}));
    assert!(
        !disabled_capabilities["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "mcpCall")
    );

    for name in ["config.json", "nodes.json"] {
        let stored = fs::read_to_string(root.join("servant").join(name)).unwrap();
        assert!(
            !stored.contains("Managed aggregate proof"),
            "MCP definition leaked into {name}"
        );
        assert!(
            !stored.contains("approved-mcp-executable"),
            "MCP executable leaked into {name}"
        );
    }
    let registry =
        intelligent_cells::durable::read_checked(&root.join("servant/mcp.json")).unwrap();
    assert_eq!(
        registry["servers"][server_id.as_str().unwrap()]["name"],
        "Managed aggregate proof"
    );
    let sessions = master.command(&json!({"command":"listSessions"})).unwrap();
    assert!(
        sessions
            .to_string()
            .contains(session["sessionId"].as_str().unwrap())
    );
}
