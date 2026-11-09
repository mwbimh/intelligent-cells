//! Task observability regressions; run in the shared Herdr build pane.
use intelligent_cells::{Config, harness, node::Node, tls::certificate_identity};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

const SECRET: &str = "logging-test-secret-body-never-audit";

struct Cluster {
    _dir: tempfile::TempDir,
    master: Arc<Node>,
    servant: Arc<Node>,
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = self.master.shutdown();
        let _ = self.servant.shutdown();
    }
}

fn config(dir: &Path, id: &str, policy: Value, peers: Value) -> Config {
    let identities = dir.join("identities");
    let other = if id == "master" { "servant" } else { "master" };
    let identity =
        certificate_identity(&std::fs::read(identities.join(format!("{other}.pem"))).unwrap())
            .unwrap();
    Config {
        id: id.into(),
        host: "127.0.0.1".into(),
        port: 0,
        path: dir.join(format!("{id}.json")),
        state_dir: dir.join(format!("{id}-state")),
        raw: json!({
            "agent": if id == "master" { json!("deterministic-demo") } else { Value::Null },
            "security": {
                "cert": identities.join(format!("{id}.pem")),
                "key": identities.join(format!("{id}.key")),
                "ca": identities.join("ca.pem"),
                "trustedPeers": {other: identity["fingerprint256"]}
            },
            "policy": policy.clone(), "policyRaw": policy, "peers": peers
        }),
    }
}

fn cluster() -> Cluster {
    let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let dir = tempfile::tempdir_in(temp).unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let servant = Node::new(config(
        dir.path(),
        "servant",
        json!({"grants":{"master":{"workspace":workspace,"tools":["echo","readFile"]}}}),
        json!([]),
    ))
    .unwrap();
    servant.start().unwrap();
    let master = Node::new(config(
        dir.path(),
        "master",
        json!({}),
        json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
    ))
    .unwrap();
    Cluster {
        _dir: dir,
        master,
        servant,
    }
}

fn task(id: &str, tool: &str) -> Value {
    let args = if tool == "echo" {
        json!({"text":SECRET})
    } else {
        json!({"text":SECRET,"path":"forbidden.txt"})
    };
    json!({"taskId":id,"tool":tool,"args":args,"timeoutMs":1000})
}

fn events(node: &Node, id: &str, event: &str) -> Vec<Value> {
    let audit = node
        .command(&json!({"command":"auditLogs","limit":500}))
        .unwrap();
    assert!(
        !audit.to_string().contains(SECRET),
        "Task payload leaked: {audit}"
    );
    audit["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["taskId"] == id && row["event"] == event)
        .cloned()
        .collect()
}

fn finished(node: &Node, id: &str, direction: &str, peer: &str, tool: &str) -> Vec<Value> {
    let records = events(node, id, "task_finished");
    assert!(!records.is_empty(), "No task_finished for {id}");
    assert_eq!(events(node, id, "task_started").len(), records.len());
    for record in &records {
        assert_eq!(record["direction"], direction);
        assert_eq!(record["peerId"], peer);
        assert_eq!(record["tool"], tool);
        assert!(record["elapsedMs"].is_number(), "{record}");
        assert!(record["replayed"].is_boolean(), "{record}");
    }
    records
}

#[test]
fn logging_task_success_and_cached_replay_are_distinguishable() {
    let c = cluster();
    let task = task("cached-echo", "echo");
    let first = c.master.dispatch("servant", &task).unwrap();
    assert_eq!(first["status"], "ok", "{first}");
    assert_eq!(c.master.dispatch("servant", &task).unwrap(), first);
    let outgoing = finished(&c.master, "cached-echo", "outgoing", "servant", "echo");
    assert_eq!(outgoing.len(), 2);
    assert_eq!(outgoing.iter().filter(|r| r["replayed"] == true).count(), 1);
    assert!(outgoing.iter().all(|r| r["status"] == "ok"));
    let incoming = finished(&c.servant, "cached-echo", "incoming", "master", "echo");
    assert_eq!(
        incoming.len(),
        1,
        "Cached dispatch must not execute remotely again"
    );
    assert_eq!(incoming[0]["status"], "ok");
    assert_eq!(incoming[0]["replayed"], false);
}

#[test]
fn logging_remote_denial_is_error_even_when_dispatch_returns_ok() {
    let c = cluster();
    let response = c
        .master
        .dispatch("servant", &task("denied-write", "writeFile"))
        .unwrap();
    assert_eq!(response["status"], "error", "{response}");
    assert_eq!(response["error"]["code"], "TOOL_DENIED", "{response}");
    for (node, direction, peer) in [
        (&c.master, "outgoing", "servant"),
        (&c.servant, "incoming", "master"),
    ] {
        let records = finished(node, "denied-write", direction, peer, "writeFile");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["status"], "error");
        assert_eq!(records[0]["code"], "TOOL_DENIED");
        assert_eq!(records[0]["replayed"], false);
    }
}

#[test]
fn logging_early_dispatch_validation_failure_has_finished_event() {
    let c = cluster();
    let mut task = task("ambiguous-workspace", "echo");
    task["logicalWorkspaceId"] = json!("project");
    task["workspaceId"] = json!("default");
    assert_eq!(
        c.master.dispatch("servant", &task).unwrap_err().code,
        "INVALID_TASK"
    );
    let records = finished(
        &c.master,
        "ambiguous-workspace",
        "outgoing",
        "servant",
        "echo",
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["status"], "error");
    assert_eq!(records[0]["code"], "INVALID_TASK");
    assert_eq!(records[0]["replayed"], false);
    assert!(events(&c.servant, "ambiguous-workspace", "task_started").is_empty());
}
