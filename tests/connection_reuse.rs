//! Public protocol regressions; run in the shared Herdr pane.
use intelligent_cells::{
    Config, harness,
    node::Node,
    tls::{Security, certificate_identity},
    wire,
};
use serde_json::{Value, json};
use std::{
    io::BufReader,
    net::{Shutdown, TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

fn config(dir: &Path, id: &str, peers: Value, idle: u64) -> Config {
    let identities = dir.join("identities");
    let other = if id == "master" { "servant" } else { "master" };
    let pin =
        certificate_identity(&std::fs::read(identities.join(format!("{other}.pem"))).unwrap())
            .unwrap();
    Config {
        id: id.into(),
        host: "127.0.0.1".into(),
        port: 0,
        path: dir.join(format!("{id}.json")),
        state_dir: dir.join(format!("{id}-state")),
        raw: json!({
        "agent":if id == "master" {json!("deterministic-demo")} else {Value::Null},
        "security":{"cert":identities.join(format!("{id}.pem")),"key":identities.join(format!("{id}.key")),"ca":identities.join("ca.pem"),"trustedPeers":{other:pin["fingerprint256"]}},
        "transport":{"idleTimeoutMs":idle,"maxConnectionsPerPeer":1},"policy":{},"policyRaw":{},"peers":peers}),
    }
}
fn task(id: &str, tool: &str) -> Value {
    json!({"taskId":id,"tool":tool,"args":if tool=="echo" {json!({"text":id})} else {json!({"path":"once","text":"effect"})},"timeoutMs":1000})
}

#[derive(Clone, Copy)]
enum Mode {
    Normal,
    CloseFirst,
    LoseFirstReply,
    WrongFirstId,
    StallTls,
    StallHello,
}
struct Scripted {
    _dir: tempfile::TempDir,
    master: Arc<Node>,
    accepts: Arc<AtomicUsize>,
    received: mpsc::Receiver<Value>,
    closed: mpsc::Receiver<usize>,
    stop: Arc<AtomicBool>,
    sockets: Arc<Mutex<Vec<TcpStream>>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Scripted {
    fn new(mode: Mode, idle: u64) -> Self {
        Self::with_peer_idle(mode, idle, idle)
    }
    fn with_peer_idle(mode: Mode, idle: u64, peer_idle: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        harness::fixture(
            &dir.path().join("identities"),
            &["master".into(), "servant".into()],
        )
        .unwrap();
        let cfg = config(dir.path(), "servant", json!([]), idle);
        let security = Security::load(&cfg.raw["security"], dir.path(), "servant").unwrap();
        let acceptor = security.acceptor().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let sockets = Arc::new(Mutex::new(Vec::new()));
        let (tx, received) = mpsc::channel();
        let (cx, closed) = mpsc::channel();
        let count = accepts.clone();
        let halt = stop.clone();
        let connections = sockets.clone();
        let thread = thread::spawn(move || {
            let mut workers = Vec::new();
            while !halt.load(Ordering::Acquire) {
                let tcp = match listener.accept() {
                    Ok((tcp, _)) => tcp,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                let number = count.fetch_add(1, Ordering::AcqRel) + 1;
                // macOS accepted sockets inherit the listener's nonblocking mode.
                tcp.set_nonblocking(false).unwrap();
                tcp.set_nodelay(true).unwrap();
                tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                connections.lock().unwrap().push(tcp.try_clone().unwrap());
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                let cx = cx.clone();
                workers.push(thread::spawn(move || {
                    if matches!(mode,Mode::StallTls){
                        let _=tx.send(json!({"stage":"tcp-accepted"}));
                        let mut tcp=tcp;let mut bytes=[0;4096];
                        while let Ok(count)=std::io::Read::read(&mut tcp,&mut bytes){if count==0{break}}
                        let _=cx.send(number);return;
                    }
                    let mut reader=BufReader::new(acceptor.accept(tcp).unwrap());
                    let hello=wire::read_frame(&mut reader).unwrap().unwrap(); assert_eq!(hello["nodeId"],"master");
                    if matches!(mode,Mode::StallHello){
                        let _=tx.send(json!({"stage":"hello-received"}));
                        let _=wire::read_frame(&mut reader);
                        let _=cx.send(number);return;
                    }
                    wire::write_frame(reader.get_mut(),&json!({"v":2,"type":"hello","nodeId":"servant","idleTimeoutMs":peer_idle})).unwrap();
                    while let Ok(Some(frame))=wire::read_frame(&mut reader) {
                        if frame["type"]=="ping" {
                            if wire::write_frame(reader.get_mut(),&json!({"v":2,"type":"pong"})).is_err(){break}
                            continue;
                        }
                        if tx.send(frame.clone()).is_err(){break}
                        if number==1 && matches!(mode,Mode::LoseFirstReply) {break}
                        let id=if number==1 && matches!(mode,Mode::WrongFirstId) {json!("wrong-id")} else {frame["task"]["taskId"].clone()};
                        if wire::write_frame(reader.get_mut(),&json!({"v":2,"type":"result","taskId":id,"status":"ok","result":{"text":frame["task"]["args"]["text"]}})).is_err() {break}
                        if number==1 && matches!(mode,Mode::CloseFirst) {
                            let _=reader.get_mut().shutdown();
                            let _=reader.get_ref().get_ref().shutdown(Shutdown::Both);
                            break;
                        }
                    }
                    drop(reader);
                    if number==1 && matches!(mode,Mode::CloseFirst) {
                        // Test already-closed idle reuse, not an arbitrary concurrent close.
                        // A channel send alone races delivery of close_notify/FIN on Linux.
                        // TCP_NODELAY + explicit FIN + loopback delivery grace precede readiness.
                        thread::sleep(Duration::from_millis(100));
                    }
                    let _=cx.send(number);
                }));
            }
            let failures = workers
                .into_iter()
                .filter_map(|worker| worker.join().err())
                .count();
            assert_eq!(failures, 0, "Scripted TLS workers failed");
        });
        let master = Node::new(config(
            dir.path(),
            "master",
            json!([{"id":"servant","host":"127.0.0.1","port":port}]),
            idle,
        ))
        .unwrap();
        Self {
            _dir: dir,
            master,
            accepts,
            received,
            closed,
            stop,
            sockets,
            thread: Some(thread),
        }
    }
    fn echo(&self, id: &str) {
        let r = self.master.dispatch("servant", &task(id, "echo")).unwrap();
        assert_eq!(r["status"], "ok", "{r}");
        assert_eq!(r["result"]["text"], id);
    }
}
impl Drop for Scripted {
    fn drop(&mut self) {
        let _ = self.master.shutdown();
        self.stop.store(true, Ordering::Release);
        let sockets = self
            .sockets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for tcp in sockets.iter() {
            let _ = tcp.shutdown(Shutdown::Both);
        }
        drop(sockets);
        if let Some(t) = self.thread.take() {
            let result = t.join();
            if !thread::panicking() {
                assert!(result.is_ok(), "Scripted TLS server failed");
            }
        }
    }
}

#[test]
fn connection_reuse_sequential_tasks_share_one_tls_handshake() {
    let f = Scripted::new(Mode::Normal, 30000);
    for id in ["first", "second", "third"] {
        f.echo(id)
    }
    assert_eq!(
        f.accepts.load(Ordering::Acquire),
        1,
        "Server accepted multiple TCP/TLS sessions for sequential requests"
    );
}

#[test]
fn connection_reuse_idle_expiry_closes_socket_then_reconnects() {
    let f = Scripted::new(Mode::Normal, 100);
    f.echo("first");
    assert_eq!(
        f.closed.recv_timeout(Duration::from_secs(2)).unwrap(),
        1,
        "Idle socket must close without needing another request"
    );
    f.echo("second");
    assert_eq!(f.accepts.load(Ordering::Acquire), 2);
    f.echo("third");
    assert_eq!(
        f.accepts.load(Ordering::Acquire),
        2,
        "Fresh session should remain reusable"
    );
}

#[test]
fn connection_reuse_server_closed_idle_session_reconnects_before_task() {
    let f = Scripted::new(Mode::CloseFirst, 30000);
    f.echo("first");
    assert_eq!(f.closed.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
    f.echo("second");
    f.echo("third");
    assert_eq!(f.accepts.load(Ordering::Acquire), 2);
}

#[test]
fn connection_reuse_negotiates_shorter_peer_idle_timeout() {
    let f = Scripted::with_peer_idle(Mode::Normal, 30000, 100);
    f.echo("first");
    assert_eq!(
        f.closed.recv_timeout(Duration::from_secs(2)).unwrap(),
        1,
        "Client must proactively honor the peer's shorter TTL without another request"
    );
    f.echo("second");
    assert_eq!(
        f.accepts.load(Ordering::Acquire),
        2,
        "The request after negotiated idle expiry must open a new session"
    );
}

fn shutdown_stalled_opening(mode: Mode, stage: &str) {
    let f = Scripted::new(mode, 30000);
    let master = f.master.clone();
    let (tx, rx) = mpsc::channel();
    let request = thread::spawn(move || {
        let result = master.dispatch("servant", &task("stalled", "echo"));
        let _ = tx.send(result);
    });
    assert_eq!(
        f.received.recv_timeout(Duration::from_secs(2)).unwrap()["stage"],
        stage
    );
    let master = f.master.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let shutdown = thread::spawn(move || {
        let _ = stop_tx.send(master.shutdown());
    });
    let stopped = stop_rx.recv_timeout(Duration::from_secs(1));
    // Join even on failure, so an assertion cannot leave running fixture threads behind.
    shutdown.join().unwrap();
    request.join().unwrap();
    stopped
        .expect("Shutdown must interrupt sockets that have not completed opening")
        .unwrap();
    let result = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(
        result.is_err() || result.unwrap()["status"] != "ok",
        "Stalled handshake must not complete as a successful task"
    );
    assert_eq!(f.closed.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
}

#[test]
fn connection_reuse_shutdown_interrupts_stalled_tls_handshake() {
    shutdown_stalled_opening(Mode::StallTls, "tcp-accepted");
}

#[test]
fn connection_reuse_shutdown_interrupts_stalled_protocol_hello() {
    shutdown_stalled_opening(Mode::StallHello, "hello-received");
}

#[test]
fn connection_reuse_bad_response_discards_session() {
    let f = Scripted::new(Mode::WrongFirstId, 30000);
    let r = f.master.dispatch("servant", &task("bad", "echo")).unwrap();
    assert_ne!(
        r["status"], "ok",
        "Mismatched task identity must be rejected"
    );
    assert_eq!(f.closed.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
    f.echo("good");
    f.echo("again");
    assert_eq!(f.accepts.load(Ordering::Acquire), 2);
}

#[test]
fn connection_reuse_lost_write_reply_is_not_replayed() {
    let f = Scripted::new(Mode::LoseFirstReply, 30000);
    let t = task("lost", "writeFile");
    let r = f.master.dispatch("servant", &t).unwrap();
    assert_eq!(r["outcomeUnknown"], true, "{r}");
    let _ = f.master.dispatch("servant", &t);
    assert_eq!(
        f.received.recv_timeout(Duration::from_secs(2)).unwrap()["task"]["taskId"],
        "lost"
    );
    assert!(
        f.received.recv_timeout(Duration::from_millis(200)).is_err(),
        "Side effect request was automatically replayed"
    );
    assert_eq!(f.accepts.load(Ordering::Acquire), 1);
}

struct Cluster {
    dir: tempfile::TempDir,
    root: std::path::PathBuf,
    master: Arc<Node>,
    servant: Arc<Node>,
}
impl Cluster {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        harness::fixture(
            &dir.path().join("identities"),
            &["master".into(), "servant".into()],
        )
        .unwrap();
        let root = dir.path().join("workspace");
        std::fs::create_dir(&root).unwrap();
        let mut cfg = config(dir.path(), "servant", json!([]), 30000);
        let policy =
            json!({"grants":{"master":{"workspace":root,"tools":["echo","wait","writeFile"]}}});
        cfg.raw["policy"] = policy.clone();
        cfg.raw["policyRaw"] = policy;
        let servant = Node::new(cfg).unwrap();
        servant.start().unwrap();
        let master = Node::new(config(
            dir.path(),
            "master",
            json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
            30000,
        ))
        .unwrap();
        Self {
            dir,
            root,
            master,
            servant,
        }
    }
    fn session(&self) -> BufReader<openssl::ssl::SslStream<TcpStream>> {
        let cfg = self.master.config();
        let security = Security::load(&cfg.raw["security"], self.dir.path(), "master").unwrap();
        let mut stream = security
            .connect("127.0.0.1", self.servant.port(), "servant")
            .unwrap();
        wire::write_frame(
            &mut stream,
            &json!({"v":2,"type":"hello","nodeId":"master"}),
        )
        .unwrap();
        let mut reader = BufReader::new(stream);
        assert_eq!(
            wire::read_frame(&mut reader).unwrap().unwrap()["type"],
            "hello"
        );
        reader
    }
}
impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = self.master.shutdown();
        let _ = self.servant.shutdown();
    }
}

#[test]
fn connection_reuse_busy_data_pool_preserves_query_and_cancel() {
    let f = Cluster::new();
    let master = f.master.clone();
    let (tx, rx) = mpsc::channel();
    let execution = thread::spawn(move || {
        let result = master.dispatch(
            "servant",
            &json!({"taskId":"long-wait","tool":"wait","args":{"ms":4000},"timeoutMs":6000}),
        );
        let _ = tx.send(result);
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while f.servant.command(&json!({"command":"status"})).unwrap()["active"] != 1 {
        assert!(
            std::time::Instant::now() < deadline,
            "wait did not become active"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let master = f.master.clone();
    let (control_tx, control_rx) = mpsc::channel();
    let control = thread::spawn(move || {
        let query =
            master.command(&json!({"command":"query","peerId":"servant","taskId":"long-wait"}));
        let cancel =
            master.command(&json!({"command":"cancel","peerId":"servant","taskId":"long-wait"}));
        let _ = control_tx.send((query, cancel));
    });
    let result = control_rx.recv_timeout(Duration::from_secs(1));
    // Always cancel and join workers even when the control lane assertion fails.
    if result.is_err() {
        let _ = f
            .servant
            .command(&json!({"command":"cancelTask","masterId":"master","taskId":"long-wait"}));
    }
    control.join().unwrap();
    execution.join().unwrap();
    let (query, cancel) = result
        .expect("query/cancel must not queue behind a long request when maxConnectionsPerPeer=1");
    assert_eq!(query.unwrap()["state"], "running");
    assert_eq!(cancel.unwrap()["type"], "cancel_ack");
    let response = rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
    assert_ne!(
        response["status"], "ok",
        "wait should have been cancelled before completion: {response}"
    );
}

#[test]
fn connection_reuse_hot_authenticated_session_observes_permission_revoke() {
    let f = Cluster::new();
    let mut session = f.session();
    wire::write_frame(
        session.get_mut(),
        &json!({"v":2,"type":"task","task":task("warm","echo")}),
    )
    .unwrap();
    assert_eq!(
        wire::read_frame(&mut session).unwrap().unwrap()["status"],
        "ok"
    );
    f.servant.command(&json!({"command":"setPolicy","expectedEpoch":0,"policy":{"grants":{"master":{"workspace":f.root,"tools":["echo"]}}}})).unwrap();
    session
        .get_ref()
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    if wire::write_frame(
        session.get_mut(),
        &json!({"v":2,"type":"task","task":task("denied","writeFile")}),
    )
    .is_ok()
    {
        match wire::read_frame(&mut session) {
            Ok(Some(response)) => assert_eq!(response["status"], "error", "{response}"),
            Ok(None) => {}
            Err(error) => assert!(
                !error.message.contains("timed out")
                    && !error.message.contains("temporarily unavailable"),
                "Revoked session must reject or close, not hang: {error}"
            ),
        }
    }
    assert!(!f.root.join("once").exists());
    let response = f
        .master
        .dispatch("servant", &task("denied-new-session", "writeFile"))
        .unwrap();
    assert_eq!(response["status"], "error", "{response}");
    assert_eq!(
        response["error"]["code"], "TOOL_DENIED",
        "Reconnecting must apply the current grant: {response}"
    );
    assert!(!f.root.join("once").exists());
}

#[test]
fn connection_reuse_shutdown_closes_incoming_idle_session() {
    let f = Cluster::new();
    let mut session = f.session();
    wire::write_frame(session.get_mut(), &json!({"v":2,"type":"ping"})).unwrap();
    assert_eq!(
        wire::read_frame(&mut session).unwrap().unwrap()["type"],
        "pong"
    );
    f.servant.shutdown().unwrap();
    session
        .get_ref()
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    match wire::read_frame(&mut session) {
        Ok(None) => {}
        Err(e) => assert!(
            !e.message.contains("timed out") && !e.message.contains("temporarily unavailable"),
            "Shutdown left idle TCP session open: {e}"
        ),
        Ok(Some(v)) => panic!("Unexpected frame after shutdown: {v}"),
    }
}

#[test]
fn connection_reuse_rejects_invalid_transport_limits() {
    let dir = tempfile::tempdir().unwrap();
    harness::fixture(
        &dir.path().join("identities"),
        &["master".into(), "servant".into()],
    )
    .unwrap();
    let invalid = [
        json!({"idleTimeoutMs":99}),
        json!({"idleTimeoutMs":300001}),
        json!({"idleTimeoutMs":1.5}),
        json!({"idleTimeoutMs":"30000"}),
        json!({"maxConnectionsPerPeer":0}),
        json!({"maxConnectionsPerPeer":9}),
        json!({"maxConnectionsPerPeer":1.5}),
        json!({"maxConnectionsPerPeer":true}),
        json!({"idleTimoutMs":30000}),
        json!([]),
        json!(false),
    ];
    for (index, transport) in invalid.into_iter().enumerate() {
        let mut cfg = config(dir.path(), "master", json!([]), 30000);
        cfg.state_dir = dir.path().join(format!("invalid-state-{index}"));
        cfg.raw["transport"] = transport.clone();
        match Node::new(cfg) {
            Err(error) => assert_eq!(error.code, "INVALID_CONFIG", "{transport}: {error}"),
            Ok(node) => {
                let _ = node.shutdown();
                panic!("Accepted invalid transport limits: {transport}");
            }
        }
    }
}
