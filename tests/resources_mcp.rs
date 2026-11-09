use intelligent_cells::{
    error::{IcError, Result},
    model::Grant,
    resources,
};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, Instant},
};
fn grant(root: &Path, mode: &str) -> (Grant, tempfile::TempDir) {
    // Cargo may hardlink binary artifacts; approval requires a private single inode.
    // Keep trusted code outside the servant workspace and alive for the whole test.
    let code = tempfile::tempdir().unwrap();
    let executable = code.path().join("mcp-server");
    std::fs::copy(env!("CARGO_BIN_EXE_ic-mcp-fixture"), &executable).unwrap();
    let executable = std::fs::canonicalize(executable).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(&executable).unwrap().nlink(), 1);
    let schema = json!({"type":"object","properties":{"text":{"type":"string","maxLength":40}},"required":["text"],"additionalProperties":false});
    let raw=resources::compile_policy(&json!({"mcpServers":{"approved":{"trusted":true,"file":executable,"launchMode":"native","args":[mode],"tools":{"safe":{"readOnly":true,"inputSchema":schema},"mutate":{"readOnly":false,"inputSchema":schema}}}}}),root,root).unwrap();
    (
        Grant {
            root: root.into(),
            raw,
            tools: ["mcpList".into(), "mcpCall".into()].into(),
            master_id: "master".into(),
            workspace_id: "dev".into(),
            epoch: 1,
        },
        code,
    )
}
fn call(g: &Grant, tool: &str, args: Value) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(2);
    resources::run_checked(&json!({"tool":tool,"args":args}), g, &|| {
        if Instant::now() >= deadline {
            Err(IcError::new("TASK_TIMEOUT", "test deadline"))
        } else {
            Ok(())
        }
    })
}
#[test]
fn resources_mcp_negotiates_allowlist_empty_env_and_relocated_cwd() {
    let dir = tempfile::tempdir().unwrap();
    let relocated = dir.path().join("relocated");
    std::fs::create_dir(&relocated).unwrap();
    let (mut g, _code) = grant(dir.path(), "");
    g.root = relocated.clone();
    let catalog = call(&g, "mcpList", json!({"server":"approved"})).unwrap();
    assert_eq!(catalog["tools"].as_array().unwrap().len(), 2);
    assert!(!catalog.to_string().contains("forbidden"));
    assert!(
        catalog["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|b| b["permissionAuthority"] == "servant-local-grant")
    );
    let result = call(
        &g,
        "mcpCall",
        json!({"server":"approved","tool":"safe","arguments":{"text":"literal $(id)"}}),
    )
    .unwrap();
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["cwd"], json!(relocated));
    assert_eq!(text["env"], json!([]));
    assert_eq!(text["arguments"]["text"], "literal $(id)");
    for (args, code) in [
        (
            json!({"server":"other","tool":"safe","arguments":{"text":"x"}}),
            "MCP_SERVER_DENIED",
        ),
        (
            json!({"server":"approved","tool":"forbidden","arguments":{"text":"x"}}),
            "MCP_TOOL_DENIED",
        ),
        (
            json!({"server":"approved","tool":"safe","arguments":{"text":"x","path":"../secret"}}),
            "INVALID_ARGS",
        ),
        (
            json!({"server":"approved","tool":"safe","arguments":{"text":"x"},"env":{}}),
            "INVALID_ARGS",
        ),
    ] {
        assert_eq!(call(&g, "mcpCall", args).unwrap_err().code, code);
    }
}
#[test]
fn resources_mcp_mutating_lost_reply_is_unknown_and_stops_process() {
    let dir = tempfile::tempdir().unwrap();
    let (g, _code) = grant(dir.path(), "");
    let task = json!({"tool":"mcpCall","args":{"server":"approved","tool":"mutate","arguments":{"text":"x"}}});
    assert!(resources::side_effect(&task, Some(&g)));
    let error = call(&g, "mcpCall", task["args"].clone()).unwrap_err();
    assert_eq!(error.code, "OUTCOME_UNKNOWN");
    assert!(error.outcome_unknown);
    assert_eq!(
        std::fs::read(dir.path().join("committed.txt")).unwrap(),
        b"committed"
    );
}
#[test]
fn resources_mcp_invalid_utf8_output_budget_and_deadline_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    for (mode, code) in [
        ("invalid-utf8", "MCP_PROTOCOL_ERROR"),
        ("overflow", "MCP_OUTPUT_TOO_LARGE"),
        ("wait", "TASK_TIMEOUT"),
    ] {
        let (g, _code) = grant(dir.path(), mode);
        let start = Instant::now();
        assert_eq!(
            call(
                &g,
                "mcpCall",
                json!({"server":"approved","tool":"safe","arguments":{"text":"x"}})
            )
            .unwrap_err()
            .code,
            code
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
#[test]
fn resources_mcp_owner_policy_rejects_model_commands_and_schema_references() {
    let dir = tempfile::tempdir().unwrap();
    let (g, _code) = grant(dir.path(), "");
    let server = g.raw["mcpServers"]["approved"].clone();
    // Reconstruct source fields: compiled approval metadata is never accepted as user policy.
    let source = json!({"trusted":true,"file":server["file"],"args":[],"launchMode":"native","tools":{"safe":{"readOnly":true,"inputSchema":{"type":"object","properties":{},"additionalProperties":false}}}});
    for (key, value) in [
        ("url", json!("https://example.invalid")),
        ("env", json!({"SECRET":"x"})),
        ("trusted", json!(false)),
    ] {
        let mut item = source.clone();
        item[key] = value;
        assert!(
            resources::compile_policy(
                &json!({"mcpServers":{"approved":item}}),
                dir.path(),
                dir.path()
            )
            .is_err()
        );
    }
    let mut item = source;
    item["tools"]["safe"]["inputSchema"]["$ref"] = json!("file:///etc/passwd");
    assert!(
        resources::compile_policy(
            &json!({"mcpServers":{"approved":item}}),
            dir.path(),
            dir.path()
        )
        .is_err()
    );
}
