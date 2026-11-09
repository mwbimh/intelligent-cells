use intelligent_cells::{node::Node, settings};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

fn node(root: &Path) -> Arc<Node> {
    let path = settings::initialize(Some(&root.join("config.json"))).unwrap();
    Node::new(settings::check_config(&path).unwrap()).unwrap()
}
fn session(node: &Node, root: &Path) -> String {
    node.command(&json!({"command":"sessionOpen","cwd":root}))
        .unwrap()["sessionId"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn setup(node: &Node, root: &Path) -> (String, String) {
    let executable = root.join("upstream");
    std::fs::copy(env!("CARGO_BIN_EXE_ic-mcp-fixture"), &executable).unwrap();
    node.command(&json!({"command":"mcpRegistry","operation":{"command":"add","server":{"name":"durability fixture","file":executable,"launchMode":"native","args":[],"cwd":root,"visibility":{"local":true,"masters":[]},"tools":{"safe":{"readOnly":true,"inputSchema":{"type":"object","properties":{"secret":{"type":"string"}},"required":["secret"],"additionalProperties":false}},"mutate":{"readOnly":false,"inputSchema":{"type":"object","properties":{"secret":{"type":"string"}},"required":["secret"],"additionalProperties":false}}}}}})).unwrap();
    let catalog = node.command(&json!({"command":"mcpListTools"})).unwrap();
    let tools = catalog["tools"].as_array().unwrap();
    let name = |suffix: &str| {
        tools
            .iter()
            .find(|t| t["_meta"]["upstreamTool"] == suffix)
            .unwrap()["name"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    (name("safe"), name("mutate"))
}
fn call(node: &Node, id: &str, tool: &str) -> intelligent_cells::Result<Value> {
    node.command(&json!({"command":"mcpCallTool","sessionId":id,"name":tool,"arguments":{"secret":"NEVER_STORE_PAYLOAD"}}))
}

#[test]
fn uncertain_local_mutation_blocks_other_sessions_and_restart_until_owner_reconciles() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let n = node(&root);
    let (safe, mutate) = setup(&n, &root);
    let first = session(&n, &root);
    let second = session(&n, &root);
    let error = call(&n, &first, &mutate).unwrap_err();
    assert!(error.outcome_unknown);
    assert!(root.join("committed.txt").exists());
    std::fs::remove_file(root.join("committed.txt")).unwrap();
    assert_eq!(
        call(&n, &second, &mutate).unwrap_err().code,
        "LOCAL_MCP_OUTCOME_UNKNOWN"
    );
    assert!(
        !root.join("committed.txt").exists(),
        "Blocked mutation was replayed"
    );
    assert!(call(&n, &second, &safe).is_ok());
    let records = n.command(&json!({"command":"listSessions"})).unwrap();
    assert!(!records.to_string().contains("NEVER_STORE_PAYLOAD"));
    let record = records
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["sessionId"] == first)
        .unwrap();
    let task = record["tasks"][0]["taskId"].as_str().unwrap().to_owned();
    assert_eq!(record["tasks"][0]["origin"], "aggregated");
    assert_eq!(record["tasks"][0]["sideEffect"], true);
    n.shutdown().unwrap();
    drop(n);
    let n = node(&root);
    assert_eq!(
        call(&n, &second, &mutate).unwrap_err().code,
        "LOCAL_MCP_OUTCOME_UNKNOWN"
    );
    assert!(
        n.command(&json!({"command":"sessionReconcile","sessionId":first,"taskId":task,"note":""}))
            .is_err()
    );
    assert!(n.command(&json!({"command":"sessionReconcile","sessionId":first,"taskId":task,"note":"Inspected the committed effect"})).is_ok());
    assert!(call(&n, &second, &mutate).unwrap_err().outcome_unknown);
    assert!(root.join("committed.txt").exists());
    n.shutdown().unwrap();
}

#[test]
fn concurrent_mutations_admit_only_one_after_uncertain_effect() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let n = node(&root);
    let (_, mutate) = setup(&n, &root);
    let first = session(&n, &root);
    let second = session(&n, &root);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut workers = Vec::new();
    for id in [first, second] {
        let n = n.clone();
        let tool = mutate.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            call(&n, &id, &tool).unwrap_err()
        }));
    }
    let errors: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(
        errors
            .iter()
            .filter(|e| e.code == "LOCAL_MCP_OUTCOME_UNKNOWN")
            .count(),
        1
    );
    assert_eq!(errors.iter().filter(|e| e.outcome_unknown).count(), 1);
    n.shutdown().unwrap();
}
