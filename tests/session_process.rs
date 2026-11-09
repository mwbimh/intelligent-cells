use intelligent_cells::{Config, harness, node::Node, tls::certificate_identity};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc, time::Duration};

fn config(dir: &Path, id: &str, policy: Value, peers: Value) -> Config {
    let other = if id == "master" { "servant" } else { "master" };
    let identity = certificate_identity(
        &std::fs::read(dir.join("identity").join(format!("{other}.pem"))).unwrap(),
    )
    .unwrap();
    Config {
        id: id.into(),
        host: "127.0.0.1".into(),
        port: 0,
        path: dir.join(format!("{id}.json")),
        state_dir: dir.join(format!("{id}-state")),
        raw: json!({"security":{"cert":dir.join("identity").join(format!("{id}.pem")),"key":dir.join("identity").join(format!("{id}.key")),"ca":dir.join("identity/ca.pem"),"trustedPeers":{other:identity["fingerprint256"]}},"policy":policy,"policyRaw":policy,"peers":peers}),
    }
}
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
fn cluster() -> Cluster {
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identity"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let policy = json!({"grants":{"master":{"workspace":workspace,"tools":["exec","jobStatus","jobOutput","jobCancel"],"allowUnsandboxedProcesses":true,"execCommands":{"output":{"file":std::fs::canonicalize("/bin/echo").unwrap(),"launchMode":"native","args":["process-output"]},"wait":{"file":std::fs::canonicalize("/bin/sleep").unwrap(),"launchMode":"native","args":["30"]}}}}});
    let servant = Node::new(config(dir.path(), "servant", policy, json!([]))).unwrap();
    servant.start().unwrap();
    let master = Node::new(config(
        dir.path(),
        "master",
        json!({"grants":{}}),
        json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
    ))
    .unwrap();
    Cluster {
        _dir: dir,
        master,
        servant,
    }
}
fn call(node: &Node, session: &Value, name: &str, args: Value) -> intelligent_cells::Result<Value> {
    let result = node.command(
        &json!({"command":"mcpCallTool","sessionId":session,"name":name,"arguments":args}),
    )?;
    Ok(serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap())
}

#[test]
fn process_controls_real_background_jobs_through_default_peer_and_preserves_session_auth() {
    let cluster = cluster();
    let session = cluster
        .master
        .command(&json!({"command":"sessionOpen"}))
        .unwrap();
    let id = &session["sessionId"];
    call(&cluster.master, id, "ic_peer", json!({"peerId":"servant"})).unwrap();
    let output = call(
        &cluster.master,
        id,
        "ic_exec",
        json!({"command":"output","args":[],"background":true}),
    )
    .unwrap();
    let output_id = &output["jobId"];
    let mut status = Value::Null;
    for _ in 0..100 {
        status = call(
            &cluster.master,
            id,
            "ic_process",
            json!({"action":"status","jobId":output_id}),
        )
        .unwrap();
        if status["state"] == "succeeded" {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(status["state"], "succeeded", "{status}");
    let page = call(
        &cluster.master,
        id,
        "ic_process",
        json!({"action":"output","jobId":output_id,"stream":"stdout","offset":0,"limit":100}),
    )
    .unwrap();
    assert_eq!(page["text"], "process-output\n");
    let running = call(
        &cluster.master,
        id,
        "ic_exec",
        json!({"command":"wait","args":[],"background":true}),
    )
    .unwrap();
    let running_id = &running["jobId"];
    assert_eq!(
        call(
            &cluster.master,
            id,
            "ic_process",
            json!({"action":"status","jobId":running_id})
        )
        .unwrap()["state"],
        "running"
    );
    let other = cluster
        .master
        .command(&json!({"command":"sessionOpen"}))
        .unwrap();
    assert_eq!(
        call(
            &cluster.master,
            &other["sessionId"],
            "ic_process",
            json!({"action":"cancel","peerId":"servant","jobId":running_id})
        )
        .unwrap_err()
        .code,
        "JOB_NOT_FOUND"
    );
    assert_eq!(
        call(
            &cluster.master,
            id,
            "ic_process",
            json!({"action":"status","jobId":running_id})
        )
        .unwrap()["state"],
        "running"
    );
    let cancelled = call(
        &cluster.master,
        id,
        "ic_process",
        json!({"action":"cancel","jobId":running_id}),
    )
    .unwrap();
    assert_eq!(cancelled["accepted"], true);
    let stored = cluster
        .master
        .command(&json!({"command":"sessionOpen","sessionId":id}))
        .unwrap();
    let tasks = stored["tasks"].as_array().unwrap();
    for tool in ["jobStatus", "jobOutput", "jobCancel"] {
        assert!(
            tasks
                .iter()
                .any(|t| t["tool"] == tool && t["peerId"] == "servant")
        );
    }
}

#[test]
fn process_rejects_invalid_actions_action_specific_fields_and_removed_aliases() {
    let cluster = cluster();
    let session = cluster
        .master
        .command(&json!({"command":"sessionOpen"}))
        .unwrap();
    let id = &session["sessionId"];
    call(&cluster.master, id, "ic_peer", json!({"peerId":"servant"})).unwrap();
    for action in ["status", "cancel"] {
        for (field, value) in [
            ("offset", json!(0)),
            ("limit", json!(10)),
            ("stream", json!("stdout")),
        ] {
            let mut args = json!({"action":action,"jobId":"unused"});
            args[field] = value;
            assert!(call(&cluster.master, id, "ic_process", args).is_err());
        }
    }
    for action in ["stdin", "restart", "invalid"] {
        assert!(
            call(
                &cluster.master,
                id,
                "ic_process",
                json!({"action":action,"jobId":"unused"})
            )
            .is_err()
        );
    }
    for name in [
        "ic_job_status",
        "ic_job_output",
        "ic_job_cancel",
        "ic_job_stdin",
        "ic_sync_scope",
    ] {
        assert_eq!(
            call(&cluster.master, id, name, json!({"jobId":"unused"}))
                .unwrap_err()
                .code,
            "TOOL_DENIED"
        );
    }
    assert!(
        cluster
            .master
            .command(&json!({"command":"sessionOpen","sessionId":id}))
            .unwrap()["tasks"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}
