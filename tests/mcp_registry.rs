use intelligent_cells::mcp_registry::McpRegistry;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;

fn fixture() -> (tempfile::TempDir, McpRegistry, Value) {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let executable = root.join("upstream");
    std::fs::copy(env!("CARGO_BIN_EXE_ic-mcp-fixture"), &executable).unwrap();
    let registry = McpRegistry::open(&root.join("mcp.json")).unwrap();
    let server = json!({"name":"Example","file":executable,"launchMode":"native","args":[],"cwd":root,"visibility":{"local":true,"masters":["master-a"]},"tools":{"safe":{"readOnly":true,"inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}}}});
    (dir, registry, server)
}

#[test]
fn aggregation_calls_real_upstream_and_persists_unique_ids() {
    let (dir, registry, server) = fixture();
    let first = registry
        .command(&json!({"command":"add","server":server}))
        .unwrap();
    let second = registry
        .command(&json!({"command":"add","server":server}))
        .unwrap();
    assert_ne!(first["server"]["id"], second["server"]["id"]);
    let catalog = registry.tools(None).unwrap();
    assert_eq!(catalog.len(), 2);
    assert_eq!(catalog[0]["_meta"]["origin"], "aggregated");
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let result = registry
        .call(
            None,
            catalog[0]["name"].as_str().unwrap(),
            &json!({"text":"hello"}),
            &root,
        )
        .unwrap();
    let payload: Value =
        serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(payload["arguments"]["text"], "hello");
    assert_eq!(payload["cwd"], json!(root));
    assert_eq!(
        McpRegistry::open(&root.join("mcp.json"))
            .unwrap()
            .tools(None)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn visibility_is_enforced_for_catalog_and_direct_calls() {
    let (dir, registry, server) = fixture();
    let added = registry
        .command(&json!({"command":"add","server":server}))
        .unwrap();
    let id = &added["server"]["id"];
    let name = registry.tools(None).unwrap()[0]["name"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(registry.tools(Some("master-a")).unwrap().len(), 1);
    assert!(registry.tools(Some("master-b")).unwrap().is_empty());
    assert!(
        registry
            .call(Some("master-b"), &name, &json!({"text":"x"}), dir.path())
            .is_err()
    );
    registry.command(&json!({"command":"update","id":id,"patch":{"visibility":{"local":false,"masters":"all"}}})).unwrap();
    assert!(registry.tools(None).unwrap().is_empty());
    assert!(registry.tools(Some("master-a")).unwrap().is_empty());
    assert!(
        registry
            .call(None, &name, &json!({"text":"x"}), dir.path())
            .is_err()
    );
}

#[test]
fn tool_disable_and_builtin_local_deny_are_independent() {
    let (_dir, registry, mut server) = fixture();
    server["tools"]["safe"]["enabled"] = json!(false);
    let added = registry
        .command(&json!({"command":"add","server":server}))
        .unwrap();
    assert!(registry.tools(None).unwrap().is_empty());
    assert!(!registry.builtin_allowed(None, "readFile"));
    assert!(registry.builtin_allowed(Some("master-a"), "readFile"));
    registry
        .command(&json!({"command":"updateBuiltin","tool":"readFile","enabled":false}))
        .unwrap();
    assert!(!registry.builtin_allowed(Some("master-a"), "readFile"));
    registry
        .command(&json!({"command":"remove","id":added["server"]["id"]}))
        .unwrap();
    assert_eq!(
        registry.command(&json!({"command":"list"})).unwrap()["servers"],
        json!([])
    );
}

#[test]
fn executable_changes_and_unapproved_tools_are_rejected() {
    let (dir, registry, server) = fixture();
    registry
        .command(&json!({"command":"add","server":server}))
        .unwrap();
    let name = registry.tools(None).unwrap()[0]["name"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        registry
            .call(
                None,
                &name.replace("__safe", "__forbidden"),
                &json!({}),
                dir.path()
            )
            .is_err()
    );
    std::fs::write(dir.path().join("upstream"), b"changed").unwrap();
    assert!(
        registry
            .call(None, &name, &json!({"text":"x"}), dir.path())
            .is_err()
    );
}

#[test]
fn remote_grant_augmentation_filters_tools_without_granting_builtin_access() {
    let (_dir, registry, server) = fixture();
    let id = registry
        .command(&json!({"command":"add","server":server}))
        .unwrap()["server"]["id"]
        .clone();
    let mut grant = intelligent_cells::Grant {
        root: "/".into(),
        tools: Default::default(),
        raw: json!({"mcpServers":{"stale":{}}}),
        master_id: "master-a".into(),
        workspace_id: "test".into(),
        epoch: 1,
    };
    registry.augment_grant(&mut grant).unwrap();
    assert!(grant.tools.is_empty());
    assert!(grant.raw["mcpServers"][id.as_str().unwrap()]["tools"]["safe"].is_object());
    assert!(grant.raw["mcpServers"].get("stale").is_none());
    grant.master_id = "master-b".into();
    registry.augment_grant(&mut grant).unwrap();
    assert_eq!(grant.raw["mcpServers"], json!({}));
}

#[test]
fn disabling_an_unavailable_server_never_launches_or_reapproves_it() {
    let (dir, registry, server) = fixture();
    let added = registry
        .command(&json!({"command":"add","server":server}))
        .unwrap();
    std::fs::write(dir.path().join("upstream"), b"changed").unwrap();
    registry
        .command(&json!({"command":"update","id":added["server"]["id"],"patch":{"enabled":false}}))
        .unwrap();
    assert!(registry.tools(None).unwrap().is_empty());
    registry
        .command(&json!({"command":"update","id":added["server"]["id"],"patch":{"enabled":true}}))
        .unwrap();
    assert!(registry.tools(None).is_err());
}

#[test]
fn capabilities_hide_disabled_builtins_and_expose_safe_aggregate_discovery() {
    let (_dir, registry, server) = fixture();
    let id = registry
        .command(&json!({"command":"add","server":server}))
        .unwrap()["server"]["id"]
        .clone();
    registry
        .command(&json!({"command":"updateBuiltin","tool":"readFile","enabled":false}))
        .unwrap();
    let mut grant = intelligent_cells::Grant {
        root: "/".into(),
        tools: ["readFile".into(), "mcpList".into(), "mcpCall".into()].into(),
        raw: json!({}),
        master_id: "master-a".into(),
        workspace_id: "test".into(),
        epoch: 1,
    };
    registry.augment_grant(&mut grant).unwrap();
    let capabilities = intelligent_cells::tools::capabilities(&grant);
    assert!(
        !capabilities["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "readFile")
    );
    assert_eq!(capabilities["tools"][0]["_meta"]["origin"], "ic");
    assert_eq!(capabilities["mcpServers"][0]["id"], id);
    assert_eq!(capabilities["mcpServers"][0]["origin"], "aggregated");
    assert_eq!(capabilities["mcpServers"][0]["tools"][0]["name"], "safe");
    assert!(!capabilities.to_string().contains("codeSnapshots"));
    assert!(!capabilities.to_string().contains("upstream"));
    grant.tools.clear();
    assert_eq!(
        intelligent_cells::tools::capabilities(&grant)["mcpServers"],
        json!([])
    );
}

#[test]
fn management_list_includes_builtin_defaults_and_marks_origins() {
    let (dir, registry, server) = fixture();
    assert!(dir.path().join("mcp.json").is_file());
    registry
        .command(&json!({"command":"add","server":server}))
        .unwrap();
    let list = registry.command(&json!({"command":"list"})).unwrap();
    assert_eq!(list["builtins"]["readFile"]["origin"], "ic");
    assert_eq!(list["builtins"]["readFile"]["local"], false);
    assert_eq!(list["builtins"]["readFile"]["enabled"], true);
    assert_eq!(list["builtins"]["readFile"]["masters"], "all");
    assert_eq!(list["servers"][0]["origin"], "aggregated");
}
