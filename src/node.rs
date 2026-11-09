use crate::{
    IcError, Result,
    context::ToolContext,
    durable::{DurableStore, StateLock},
    jobs::JobManager,
    model::{Config, Grant},
    sync::SyncManager,
    tls::Security,
    transport::{IncomingGuard, IncomingSockets, Pool, Session, Settings},
    wire,
    workspaces::WorkspaceRegistry,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::BufReader,
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod local_mcp;
mod pairing_runtime;
mod session_runtime;
mod session_sync;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| IcError::new("INVALID_COMMAND", format!("{key} required")))
}
fn response_error(task: &str, e: &IcError) -> Value {
    json!({"v":2,"type":"result","taskId":task,"status":"error","error":e,"outcomeUnknown":e.outcome_unknown})
}
struct DispatchGuard<'a>(&'a AtomicUsize);
type SyncPreparation = (Value, Option<(Value, Value)>, Option<Value>);
impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub struct Node {
    config: RwLock<Config>,
    security: Security,
    sessions: crate::sessions::SessionStore,
    mcp: crate::mcp_registry::McpRegistry,
    local_mcp_admission: Mutex<()>,
    pairing: Mutex<crate::pairing::Registry>,
    pairing_mutation: Mutex<()>,
    pairing_port: AtomicU16,
    pairing_connections: AtomicUsize,
    pairing_sockets: Arc<IncomingSockets>,
    policy: RwLock<Value>,
    control: Mutex<Value>,
    incoming: Arc<Mutex<DurableStore>>,
    outgoing: Mutex<DurableStore>,
    state_lock: Mutex<Option<StateLock>>,
    audit: crate::operator::AuditLog,
    log_format: RwLock<crate::logging::LogFormat>,
    jobs: Arc<JobManager>,
    sync: Arc<SyncManager>,
    pub workspaces: Arc<WorkspaceRegistry>,
    ensures: Mutex<()>,
    lifecycle: Mutex<()>,
    outgoing_active: AtomicUsize,
    control_active: AtomicUsize,
    transient_blocked: Mutex<BTreeSet<String>>,
    active: Mutex<BTreeMap<String, Arc<AtomicBool>>>,
    starts: Mutex<BTreeMap<String, Vec<u64>>>,
    stopping: AtomicBool,
    started: AtomicBool,
    port: AtomicU16,
    storage_failed: Arc<AtomicBool>,
    connections: AtomicUsize,
    transport: Arc<Pool>,
    incoming_sockets: Arc<IncomingSockets>,
    transport_settings: Settings,
    rsync_settings: Option<crate::rsync::Settings>,
}
impl Node {
    pub fn new(mut config: Config) -> Result<Arc<Self>> {
        let transport_settings = Settings::parse(&config.raw)?;
        let rsync_settings = crate::rsync::Settings::parse(&config.raw)?;
        if let Some(settings) = &rsync_settings {
            settings.validate()?;
        }
        let base = config.path.parent().unwrap_or(std::path::Path::new("."));
        let security = Security::load(&config.raw["security"], base, &config.id)?;
        let state_lock = StateLock::acquire(&config.state_dir)?;
        let pairing =
            crate::pairing::Registry::open(&crate::node_store::directory(&config), &config.id)?;
        for peer in pairing.peers() {
            Self::merge_paired_config(
                &mut config,
                &peer["identity"],
                peer.get("endpoint").filter(|v| !v.is_null()),
            )?;
            security.add_paired_identity(&peer["identity"])?;
        }
        let node_directory = crate::node_store::directory(&config);
        let control = if let Some(control) =
            crate::node_store::read_section(&node_directory, "control")?
        {
            control
        } else {
            let c = json!({"nodeId":config.id,"policyEpoch":0,"policyRaw":config.raw.get("policyRaw").cloned().unwrap_or(json!({})),"blockedPeers":[]});
            crate::node_store::write_section(&node_directory, "control", &c)?;
            c
        };
        if control["nodeId"] != config.id || !control["policyEpoch"].is_u64() {
            return Err(IcError::new("JOURNAL_CORRUPT", "Invalid node control"));
        }
        let policy = crate::policy::validate_config_policy(&config, &control["policyRaw"])?;
        let max = policy["maxTaskRecords"].as_u64().unwrap_or(1024) as usize;
        let bytes = policy["maxJournalBytes"].as_u64().unwrap_or(8388608);
        let mut incoming = DurableStore::open(&config.state_dir.join("incoming"), max, bytes)?;
        let mut outgoing = DurableStore::open(&config.state_dir.join("outgoing"), max, bytes)?;
        for store in [&mut incoming, &mut outgoing] {
            for mut r in store.values() {
                if matches!(
                    r["state"].as_str(),
                    Some("running" | "dispatching" | "pending")
                ) {
                    let id = r["taskId"].as_str().unwrap_or("").to_string();
                    let side = r["sideEffect"].as_bool().unwrap_or(true);
                    r["state"] = json!(if side { "unknown" } else { "interrupted" });
                    r["response"] = response_error(
                        &id,
                        &if side {
                            IcError::new(
                                "OUTCOME_UNKNOWN",
                                "Process restart interrupted an operation",
                            )
                            .unknown()
                        } else {
                            IcError::new("TASK_INTERRUPTED", "Read interrupted on restart")
                        },
                    );
                    let key = r["key"]
                        .as_str()
                        .ok_or_else(|| IcError::new("JOURNAL_CORRUPT", "Record key missing"))?
                        .to_string();
                    store.put(&key, r)?
                }
            }
        }
        let auditpath = config.raw["logFile"]
            .as_str()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| config.state_dir.join("audit.jsonl"));
        let audit = crate::operator::AuditLog::new(&auditpath, 1048576, 4)?;
        let jobs = Arc::new(JobManager::new(
            &config.state_dir.join("jobs"),
            policy["maxConcurrent"].as_u64().unwrap_or(4) as usize,
        )?);
        let sync = Arc::new(SyncManager::new(&config.state_dir)?);
        let workspaces = Arc::new(WorkspaceRegistry::new(&config.state_dir, &config)?);
        workspaces.update_policy(policy.clone());
        let sessions = crate::sessions::SessionStore::open(&config.state_dir)?;
        let mcp = crate::mcp_registry::McpRegistry::open(&node_directory.join("mcp.json"))?;
        Ok(Arc::new(Self {
            port: AtomicU16::new(config.port),
            config: RwLock::new(config),
            security,
            sessions,
            mcp,
            local_mcp_admission: Mutex::new(()),
            pairing: Mutex::new(pairing),
            pairing_mutation: Mutex::new(()),
            pairing_port: AtomicU16::new(0),
            pairing_connections: AtomicUsize::new(0),
            pairing_sockets: IncomingSockets::new(Duration::from_secs(5)),
            policy: RwLock::new(policy),
            control: Mutex::new(control),
            incoming: Arc::new(Mutex::new(incoming)),
            outgoing: Mutex::new(outgoing),
            state_lock: Mutex::new(Some(state_lock)),
            audit,
            log_format: RwLock::new(crate::logging::LogFormat::Text),
            jobs,
            sync,
            workspaces,
            ensures: Mutex::new(()),
            lifecycle: Mutex::new(()),
            outgoing_active: AtomicUsize::new(0),
            control_active: AtomicUsize::new(0),
            transient_blocked: Mutex::new(BTreeSet::new()),
            active: Mutex::new(BTreeMap::new()),
            starts: Mutex::new(BTreeMap::new()),
            stopping: AtomicBool::new(false),
            started: AtomicBool::new(false),
            storage_failed: Arc::new(AtomicBool::new(false)),
            connections: AtomicUsize::new(0),
            transport: Pool::new(transport_settings),
            incoming_sockets: IncomingSockets::new(transport_settings.idle),
            transport_settings,
            rsync_settings,
        }))
    }
    pub fn config(&self) -> Config {
        self.config.read().unwrap().clone()
    }
    pub fn set_log_format(&self, format: crate::logging::LogFormat) {
        *self.log_format.write().unwrap() = format;
    }
    pub fn port(&self) -> u16 {
        self.port.load(Ordering::Acquire)
    }
    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }
    pub fn owner_request(self: &Arc<Self>, command: &Value) -> Result<Value> {
        let admission = self.lifecycle.lock().unwrap();
        if self.is_stopping() {
            return Err(IcError::new("NODE_STOPPING", "Node is shutting down"));
        }
        if self.control_active.fetch_add(1, Ordering::AcqRel) >= 32 {
            self.control_active.fetch_sub(1, Ordering::AcqRel);
            return Err(IcError::new("BUSY", "Owner operation capacity reached"));
        }
        let _guard = DispatchGuard(&self.control_active);
        drop(admission);
        crate::operator::owner_command(self, command)
    }
    fn epoch(&self) -> u64 {
        self.control.lock().unwrap()["policyEpoch"]
            .as_u64()
            .unwrap_or(0)
    }
    fn blocked(&self, id: &str) -> bool {
        if self.transient_blocked.lock().unwrap().contains(id) {
            return true;
        }
        self.control.lock().unwrap()["blockedPeers"]
            .as_array()
            .is_some_and(|a| a.iter().any(|p| p == id))
    }
    pub fn invalidate_peer_until_restart(&self, id: &str) -> Result<()> {
        self.transient_blocked.lock().unwrap().insert(id.into());
        self.transport.invalidate(Some(id));
        self.incoming_sockets.invalidate(Some(id));
        for (key, cancel) in self.active.lock().unwrap().iter() {
            if key.starts_with(&format!("{id}:")) {
                cancel.store(true, Ordering::Release)
            }
        }
        Ok(())
    }
    pub fn invalidate_peer(&self, id: &str) -> Result<()> {
        let mut c = self.control.lock().unwrap();
        if !c["blockedPeers"].is_array() {
            c["blockedPeers"] = json!([])
        }
        if !c["blockedPeers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == id)
        {
            c["blockedPeers"].as_array_mut().unwrap().push(json!(id));
            crate::node_store::write_section(
                &crate::node_store::directory(&self.config()),
                "control",
                &c,
            )?
        }
        drop(c);
        self.transport.invalidate(Some(id));
        self.incoming_sockets.invalidate(Some(id));
        for (key, cancel) in self.active.lock().unwrap().iter() {
            if key.starts_with(&format!("{id}:")) {
                cancel.store(true, Ordering::Release)
            }
        }
        Ok(())
    }
    pub fn start(self: &Arc<Self>) -> Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let config = self.config();
        let listener = TcpListener::bind((config.host.as_str(), config.port))?;
        self.port
            .store(listener.local_addr()?.port(), Ordering::Release);
        listener.set_nonblocking(true)?;
        self.start_pairing()?;
        let node = self.clone();
        thread::spawn(move || {
            while !node.stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((tcp, address)) => {
                        let admission = node.lifecycle.lock().unwrap();
                        if node.stopping.load(Ordering::Acquire) {
                            break;
                        }
                        let guard = match node.incoming_sockets.register(&tcp) {
                            Ok(guard) => guard,
                            Err(_) => continue,
                        };
                        if node.connections.fetch_add(1, Ordering::AcqRel) >= 32 {
                            node.connections.fetch_sub(1, Ordering::AcqRel);
                            drop(tcp);
                            continue;
                        }
                        drop(admission);
                        let n = node.clone();
                        thread::spawn(move || {
                            if let Err(e) = n.accept(tcp, guard)
                                && !n.is_stopping()
                            {
                                n.log(
                                    "connection_error",
                                    json!({"code":e.code,"remoteAddr":address.to_string()}),
                                );
                            }
                            n.connections.fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        let peers = config.raw["peers"].as_array().cloned().unwrap_or_default();
        let grants = self.policy.read().unwrap()["grants"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        self.log("node_ready",json!({"host":config.host,"port":self.port(),"transport":"TLSv1.3-mTLS-pinned","durable":true,
            "pairingHost":config.raw["pairing"]["host"],"pairingPort":self.pairing_port.load(Ordering::Acquire),"peerCount":peers.len(),"grantCount":grants.len()}));
        for peer in peers {
            self.log(
                "peer_registered",
                json!({"peerId":peer["id"],"host":peer["host"],"port":peer["port"]}),
            );
        }
        for (master, grant) in grants {
            self.log("master_authorized", json!({"peerId":master,"toolCount":grant["tools"].as_array().map_or(0, |t| t.len())}));
        }
        Ok(())
    }
    pub fn log(&self, event: &str, fields: Value) {
        let mut v = json!({"timestamp":now(),"nodeId":self.config().id,"event":event});
        if let Some(o) = fields.as_object() {
            for (k, x) in o {
                v[k] = x.clone()
            }
        }
        let dedicated_success = event == "operator_command"
            && v["ok"] == true
            && matches!(
                v["command"].as_str(),
                Some(
                    "dispatch"
                        | "pairingRequest"
                        | "pairingApprove"
                        | "pairingReject"
                        | "pairingConfirm"
                        | "unpair"
                        | "shutdown"
                )
            );
        if !dedicated_success {
            crate::logging::emit(&v, *self.log_format.read().unwrap());
        }
        if let Err(e) = self.audit.append(&v) {
            crate::logging::emit(
                &json!({"timestamp":now(),"nodeId":self.config().id,"event":"audit_error","code":e.code}),
                *self.log_format.read().unwrap(),
            );
        }
    }
    fn accept(&self, tcp: TcpStream, connection: IncomingGuard) -> Result<()> {
        connection.active();
        tcp.set_nodelay(true)?;
        tcp.set_nonblocking(false)?;
        tcp.set_read_timeout(Some(Duration::from_secs(2)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
        let stream = self
            .security
            .acceptor()?
            .accept(tcp)
            .map_err(|e| IcError::new("TLS_ERROR", e.to_string()))?;
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| IcError::new("IDENTITY_MISMATCH", "No certificate"))?;
        let master = self.security.authenticate(&cert, None)?;
        connection.peer(&master);
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(2)))?;
        if self.blocked(&master) {
            return Err(IcError::new("MASTER_DENIED", "Identity revoked"));
        }
        let mut reader = BufReader::new(stream);
        let hello = wire::read_frame(&mut reader)?
            .ok_or_else(|| IcError::new("INVALID_FRAME", "No hello"))?;
        if hello["type"] != "hello" || hello["nodeId"] != master {
            return Err(IcError::new("IDENTITY_MISMATCH", "Hello identity mismatch"));
        }
        wire::write_frame(
            reader.get_mut(),
            &json!({"v":2,"type":"hello","nodeId":self.config().id,"idleTimeoutMs":self.transport_settings.idle.as_millis()}),
        )?;
        loop {
            connection.idle();
            reader
                .get_ref()
                .get_ref()
                .set_read_timeout(Some(self.transport_settings.idle))?;
            let Some(frame) = wire::read_frame(&mut reader)? else {
                break;
            };
            connection.active();
            self.security.validate_local()?;
            self.security.authenticate(&cert, Some(&master))?;
            if self.stopping.load(Ordering::Acquire) || self.blocked(&master) {
                break;
            }
            let reply = match frame["type"].as_str() {
                Some("task") => {
                    let t = frame.get("task").unwrap_or(&frame);
                    if t["tool"] == "syncTransfer" {
                        let result = self.execute_with(&master, t, None, |task, grant, ctx| {
                            let settings = self.rsync_settings.as_ref().ok_or_else(|| {
                                IcError::new(
                                    "RSYNC_BACKEND_DISABLED",
                                    "Receiver requires explicit rsync backend",
                                )
                            })?;
                            self.sync.transfer(task, grant, ctx, |stage, check| {
                                wire::write_frame(
                                    reader.get_mut(),
                                    &json!({"v":2,"type":"rsync_ready","taskId":task["taskId"]}),
                                )?;
                                let child = crate::rsync::spawn(settings, stage, false)?;
                                let stats = crate::rsync::transfer(
                                    &mut reader,
                                    child,
                                    string(task, "taskId")?,
                                    check,
                                )?;
                                Ok(serde_json::to_value(stats)?)
                            })
                        });
                        let response = result.unwrap_or_else(|e| {
                            response_error(t["taskId"].as_str().unwrap_or(""), &e)
                        });
                        wire::write_frame(reader.get_mut(), &response)?;
                        // Protocol errors may leave unread payload frames; never reuse this stream.
                        if response["status"] != "ok" {
                            break;
                        }
                        continue;
                    }
                    let (tx, rx) = mpsc::channel();
                    thread::scope(|scope| {
                        let tx2 = tx.clone();
                        let master_ref = &master;
                        scope.spawn(move || {
                            let r = self.execute(master_ref, t, Some(tx2)).unwrap_or_else(|e| {
                                response_error(t["taskId"].as_str().unwrap_or(""), &e)
                            });
                            let _ = tx.send((true, r));
                        });
                        loop {
                            let (final_result, v) = rx.recv().map_err(|_| {
                                IcError::new("TASK_INTERRUPTED", "Execution worker closed")
                            })?;
                            if final_result {
                                break Ok(v);
                            }
                            wire::write_frame(reader.get_mut(), &v)?;
                        }
                    })
                }
                Some("query") => self.incoming_query(&master, string(&frame, "taskId")?),
                Some("cancel") => {
                    let key = format!("{}:{}", master, string(&frame, "taskId")?);
                    if let Some(c) = self.active.lock().unwrap().get(&key) {
                        c.store(true, Ordering::Release)
                    }
                    Ok(json!({"v":2,"type":"cancel_ack","taskId":frame["taskId"],"cancelled":true}))
                }
                Some("ping") => Ok(json!({"v":2,"type":"pong"})),
                _ => Err(IcError::new("INVALID_FRAME", "Unknown protocol message")),
            };
            let reply = reply.unwrap_or_else(|e| {
                response_error(
                    frame.get("task").unwrap_or(&frame)["taskId"]
                        .as_str()
                        .unwrap_or(""),
                    &e,
                )
            });
            wire::write_frame(reader.get_mut(), &reply)?;
        }
        Ok(())
    }
    fn incoming_query(&self, master: &str, id: &str) -> Result<Value> {
        self.refresh_background(master, id)?;
        let store = self.incoming.lock().unwrap();
        let key = format!("{master}:{id}");
        if let Some(r) = store.get(&key) {
            if r["policyEpoch"].as_u64() != Some(self.epoch()) {
                return Err(IcError::new(
                    "TASK_POLICY_CHANGED",
                    "Retained record policy changed",
                ));
            }
            Ok(
                json!({"v":2,"type":"query_result","taskId":id,"state":r["state"],"record":r,"response":r["response"]}),
            )
        } else {
            Ok(
                json!({"v":2,"type":"query_result","taskId":id,"state":if store.retired(&key){"expired"}else{"not_found"}}),
            )
        }
    }
    fn refresh_background(&self, master: &str, id: &str) -> Result<()> {
        let key = format!("{master}:{id}");
        let r = self.incoming.lock().unwrap().get(&key);
        if let Some(mut r) = r
            && r["response"]["result"]["background"] == true
            && r["state"] != "reconciled"
            && let Some(job) = r["response"]["result"]["jobId"].as_str()
        {
            let status = self
                .jobs
                .command(&json!({"command":"jobStatus","jobId":job}))?;
            let state = status["state"].as_str().unwrap_or("unknown");
            r["state"] = json!(if matches!(state, "starting" | "running") {
                "running"
            } else if state == "unknown" || status["outcomeUnknown"] == true {
                "unknown"
            } else {
                "completed"
            });
            r["response"]["outcomeUnknown"] = json!(status["outcomeUnknown"] == true);
            r["response"]["result"]["state"] = status["state"].clone();
            r["response"]["result"]["job"] = status;
            r["updatedAt"] = json!(now());
            self.put(true, &key, r)?
        }
        Ok(())
    }
    fn storage(&self) -> Result<()> {
        if self.storage_failed.load(Ordering::Acquire) {
            return Err(IcError::new(
                "JOURNAL_UNAVAILABLE",
                "Durable storage failed",
            ));
        }
        Ok(())
    }
    fn put(&self, incoming: bool, key: &str, value: Value) -> Result<()> {
        let result = if incoming {
            self.incoming.lock().unwrap().put(key, value)
        } else {
            self.outgoing.lock().unwrap().put(key, value)
        };
        if result.is_err() {
            self.storage_failed.store(true, Ordering::Release)
        }
        result
    }
    fn execute(
        &self,
        master: &str,
        task: &Value,
        network_events: Option<mpsc::Sender<(bool, Value)>>,
    ) -> Result<Value> {
        self.execute_with(master, task, network_events, crate::tools::run)
    }
    fn execute_with(
        &self,
        master: &str,
        task: &Value,
        network_events: Option<mpsc::Sender<(bool, Value)>>,
        run: impl FnOnce(&Value, &Grant, &ToolContext) -> Result<Value>,
    ) -> Result<Value> {
        let start = Instant::now();
        self.log("task_started", json!({"direction":"incoming","peerId":master,"taskId":task["taskId"],"tool":task["tool"]}));
        let mut replayed = false;
        let result = self.execute_with_inner(master, task, network_events, run, &mut replayed);
        self.log_task_result("incoming", master, task, start, replayed, &result);
        result
    }
    fn log_task_result(
        &self,
        direction: &str,
        peer: &str,
        task: &Value,
        started: Instant,
        replayed: bool,
        result: &Result<Value>,
    ) {
        let mut fields = json!({"direction":direction,"peerId":peer,"taskId":task["taskId"],"tool":task["tool"],
            "elapsedMs":started.elapsed().as_millis(),"replayed":replayed});
        match result {
            Ok(response) => {
                fields["status"] = response["status"].clone();
                fields["code"] = response["error"]["code"].clone();
                fields["outcomeUnknown"] = json!(
                    response["outcomeUnknown"] == true
                        || response["result"]["outcomeUnknown"] == true
                        || response["result"]["state"] == "unknown"
                );
                fields["background"] = json!(response["result"]["background"] == true);
                fields["exitCode"] = response["result"]["exitCode"].clone();
            }
            Err(error) => {
                fields["status"] = json!("error");
                fields["code"] = json!(error.code);
                fields["outcomeUnknown"] = json!(error.outcome_unknown);
            }
        }
        self.log("task_finished", fields);
    }
    fn execute_with_inner(
        &self,
        master: &str,
        task: &Value,
        network_events: Option<mpsc::Sender<(bool, Value)>>,
        run: impl FnOnce(&Value, &Grant, &ToolContext) -> Result<Value>,
        replayed: &mut bool,
    ) -> Result<Value> {
        self.storage()?;
        if task.get("logicalWorkspaceId").is_some() {
            return Err(IcError::new(
                "INVALID_TASK",
                "Wire requests require physical workspaceId",
            ));
        }
        if matches!(
            task["tool"].as_str(),
            Some("workspaceList" | "workspaceCreate")
        ) && task.get("workspaceId").is_some()
        {
            return Err(IcError::new(
                "INVALID_TASK",
                "Workspace management cannot select a workspace",
            ));
        }
        if task.get("runId").is_some()
            && !task["runId"].as_str().is_some_and(|id| {
                !id.is_empty()
                    && id.len() <= 100
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
        {
            return Err(IcError::new("INVALID_TASK", "Invalid runId"));
        }
        let id = string(task, "taskId")?;
        if id.len() > 100
            || id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(IcError::new("INVALID_TASK", "Invalid taskId"));
        }
        let key = format!("{master}:{id}");
        self.refresh_background(master, id)?;
        let hash = wire::fingerprint(task);
        let epoch = self.epoch();
        let policy = self.policy.read().unwrap().clone();
        let grant =
            self.workspaces
                .resolve(&policy, master, task["workspaceId"].as_str(), epoch)?;
        let mut grant = self.session_grant(master, task, grant)?;
        if !self
            .mcp
            .builtin_allowed(Some(master), task["tool"].as_str().unwrap_or(""))
        {
            return Err(IcError::new(
                "TOOL_DENIED",
                "Tool is disabled or hidden from this master",
            ));
        }
        if self.config().raw["nodesFile"].is_string() {
            self.mcp.augment_grant(&mut grant)?;
        }
        crate::tools::validate(task, &grant)?;
        let side = crate::tools::side_effect(task, Some(&grant));
        let mut store = self.incoming.lock().unwrap();
        if let Some(r) = store.get(&key) {
            if r["fingerprint"] != hash {
                return Err(IcError::new(
                    "TASK_ID_CONFLICT",
                    "Task ID already used for a different operation",
                ));
            }
            if r["policyEpoch"] != epoch {
                return Err(IcError::new("TASK_POLICY_CHANGED", "Task policy changed"));
            }
            if !r["response"].is_null() {
                *replayed = true;
                return Ok(r["response"].clone());
            }
            return Err(IcError::new("TASK_PENDING", "Task already running"));
        }
        if store.retired(&key) {
            return Err(IcError::new(
                "TASK_EXPIRED",
                "Retired task ID cannot run again",
            ));
        }
        if side
            && store.values().iter().any(|r| {
                r["masterId"] == master && r["state"] == "unknown" && r["sideEffect"] == true
            })
        {
            return Err(
                IcError::new("UNCERTAIN_SIDE_EFFECT", "Reconcile unknown operation first")
                    .unknown(),
            );
        }
        let max = grant.limit("maxTimeoutMs", 2000);
        let requested = task["timeoutMs"]
            .as_u64()
            .ok_or_else(|| IcError::new("INVALID_TASK", "timeoutMs required"))?;
        if !(10..=86400000).contains(&requested) {
            return Err(IcError::new(
                "INVALID_TASK",
                "timeoutMs must be 10..86400000",
            ));
        }
        let timeout = requested.min(max);
        let mut starts = self.starts.lock().unwrap();
        let recent = starts.entry(master.to_string()).or_default();
        recent.retain(|t| now().saturating_sub(*t) < 60000);
        if recent.len() >= grant.limit("maxTasksPerMinute", 120) as usize {
            return Err(IcError::new(
                "RATE_LIMITED",
                "Per-master start budget exceeded",
            ));
        }
        recent.push(now());
        drop(starts);
        let mut active = self.active.lock().unwrap();
        if self.stopping.load(Ordering::Acquire) {
            return Err(IcError::new("NODE_STOPPING", "Node is shutting down"));
        }
        if active.len() >= policy["maxConcurrent"].as_u64().unwrap_or(4) as usize
            || active
                .keys()
                .filter(|k| k.starts_with(&format!("{master}:")))
                .count()
                >= grant.limit("maxConcurrent", 4) as usize
        {
            return Err(IcError::new("BUSY", "Concurrency capacity reached"));
        }
        let mut record = json!({"key":key,"masterId":master,"taskId":id,"tool":task["tool"],"workspaceId":task["workspaceId"],"runId":task.get("runId").cloned().unwrap_or(json!("default")),"policyEpoch":epoch,"fingerprint":hash,"sideEffect":side,"state":"running","createdAt":now(),"response":null,"events":[]});
        store.put(&key, record.clone())?;
        let cancel = Arc::new(AtomicBool::new(false));
        active.insert(key.clone(), cancel.clone());
        drop(active);
        drop(store);
        let events = Arc::new(Mutex::new(Vec::new()));
        let event_copy = events.clone();
        let event_id = id.to_string();
        let event_key = key.clone();
        let event_store = self.incoming.clone();
        let event_failed = self.storage_failed.clone();
        let ctx = ToolContext {
            state_dir: self.config().state_dir,
            master_id: master.to_string(),
            workspace_id: grant.workspace_id.clone(),
            run_id: record["runId"].as_str().unwrap_or("default").to_string(),
            policy_epoch: epoch,
            policy: policy.clone(),
            cancel,
            deadline: Instant::now() + Duration::from_millis(timeout),
            event_sink: Some(Arc::new(move |v| {
                let mut e = event_copy.lock().unwrap();
                if serde_json::to_vec(&v).is_ok_and(|b| b.len() <= 16384)
                    && e.len() < 256
                    && e.iter()
                        .map(|x| serde_json::to_vec(x).map(|b| b.len()).unwrap_or(65536))
                        .sum::<usize>()
                        < 65536
                {
                    if v["type"] == "job_state" {
                        let mut store = event_store.lock().unwrap();
                        if let Some(mut record) = store.get(&event_key)
                            && record["response"]["result"]["background"] == true
                            && record["state"] != "reconciled"
                        {
                            let job = &v["job"];
                            record["state"] = json!(if job["outcomeUnknown"] == true
                                || job["state"] == "unknown"
                            {
                                "unknown"
                            } else if matches!(job["state"].as_str(), Some("running" | "starting"))
                            {
                                "running"
                            } else {
                                "completed"
                            });
                            record["response"]["result"]["job"] = job.clone();
                            record["response"]["result"]["state"] = job["state"].clone();
                            record["response"]["outcomeUnknown"] =
                                json!(job["outcomeUnknown"] == true);
                            record["events"] = json!(*e);
                            record["updatedAt"] = json!(now());
                            if store.put(&event_key, record).is_err() {
                                event_failed.store(true, Ordering::Release)
                            }
                        }
                    }
                    if let Some(tx) = &network_events {
                        let _ = tx.send((
                            false,
                            json!({"v":2,"type":"task_event","taskId":event_id,"event":v}),
                        ));
                    }
                    e.push(v)
                }
            })),
            jobs: self.jobs.clone(),
            sync: self.sync.clone(),
            workspaces: self.workspaces.clone(),
            workspace_lock: None,
        };
        let result = run(task, &grant, &ctx);
        self.active.lock().unwrap().remove(&key);
        let result = if self.epoch() != epoch {
            Err(IcError::new("TASK_POLICY_CHANGED", "Policy changed during execution").unknown())
        } else {
            result
        };
        let response = match result {
            Ok(v) => json!({"v":2,"type":"result","taskId":id,"status":"ok","result":v}),
            Err(e) => response_error(id, &e),
        };
        let unknown = response["outcomeUnknown"] == true
            || response["result"]["outcomeUnknown"] == true
            || response["result"]["state"] == "unknown";
        record["state"] = json!(if unknown {
            "unknown"
        } else if response["result"]["background"] == true {
            "running"
        } else {
            "completed"
        });
        record["response"] = response.clone();
        record["events"] = json!(*events.lock().unwrap());
        record["updatedAt"] = json!(now());
        self.put(true, &key, record)?;
        Ok(response)
    }
    fn request(&self, peer: &str, frame: &Value) -> Result<Value> {
        self.request_source(peer, frame, None)
    }
    fn request_source(
        &self,
        peer: &str,
        frame: &Value,
        source: Option<&std::path::Path>,
    ) -> Result<Value> {
        if frame["task"]["tool"] == "syncTransfer" && source.is_none() {
            return Err(IcError::new(
                "RSYNC_TRANSPORT_REQUIRED",
                "syncTransfer requires an IC frozen source",
            ));
        }
        if self.blocked(peer) {
            return Err(IcError::new("PEER_DENIED", "Peer revoked"));
        }
        let cfg = self.config();
        let p = cfg.raw["peers"]
            .as_array()
            .and_then(|p| p.iter().find(|p| p["id"] == peer))
            .ok_or_else(|| IcError::new("PEER_NOT_FOUND", "Unknown peer"))?;
        let host = p["host"].as_str().unwrap_or("127.0.0.1");
        let port = p["port"]
            .as_u64()
            .ok_or_else(|| IcError::new("INVALID_CONFIG", "Peer port required"))?
            as u16;
        let read_ms = frame
            .get("task")
            .and_then(|t| t["timeoutMs"].as_u64())
            .unwrap_or(10000)
            .min(86400000)
            + 5000;
        self.security.validate_local()?;
        let control = frame["type"] != "task";
        let mut lease =
            self.transport
                .acquire(peer, control, Duration::from_millis(read_ms), |track| {
                    if self.blocked(peer) {
                        return Err(IcError::new("PEER_DENIED", "Peer revoked"));
                    }
                    let mut stream = self.security.connect_tracked(host, port, peer, track)?;
                    if self.stopping.load(Ordering::Acquire) || self.blocked(peer) {
                        return Err(IcError::new(
                            "PEER_DENIED",
                            "Session invalidated during connection",
                        ));
                    }
                    stream
                        .get_ref()
                        .set_read_timeout(Some(Duration::from_secs(5)))?;
                    wire::write_frame(&mut stream, &json!({"v":2,"type":"hello","nodeId":cfg.id}))?;
                    let mut reader = BufReader::new(stream);
                    let h = wire::read_frame(&mut reader)?
                        .ok_or_else(|| IcError::new("PEER_UNAVAILABLE", "No hello"))?;
                    if h["nodeId"] != peer || h["type"] != "hello" {
                        return Err(IcError::new("IDENTITY_MISMATCH", "Invalid hello"));
                    }
                    let remote_idle = h["idleTimeoutMs"]
                        .as_u64()
                        .filter(|n| (100..=300000).contains(n))
                        .ok_or_else(|| {
                            IcError::new("INVALID_FRAME", "Invalid peer idle timeout")
                        })?;
                    let ms = (self.transport_settings.idle.as_millis() as u64).min(remote_idle);
                    let idle = Duration::from_millis(ms - ms / 10);
                    Ok(Session {
                        reader,
                        idle,
                        used: Instant::now(),
                    })
                })?;
        if self.blocked(peer) || self.stopping.load(Ordering::Acquire) {
            return Err(IcError::new("PEER_DENIED", "Session invalidated"));
        }
        let reader = &mut lease.session().reader;
        let cert = reader
            .get_ref()
            .ssl()
            .peer_certificate()
            .ok_or_else(|| IcError::new("IDENTITY_MISMATCH", "Missing certificate"))?;
        self.security.authenticate(&cert, Some(peer))?;
        reader
            .get_ref()
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(read_ms)))?;
        wire::write_frame(reader.get_mut(), frame)?;
        let mut early_response = None;
        if let Some(source) = source {
            let ready = wire::read_frame(reader)?
                .ok_or_else(|| IcError::new("PEER_DISCONNECTED", "No rsync readiness reply"))?;
            if ready["type"] == "result" {
                early_response = Some(ready);
            } else {
                if ready["type"] != "rsync_ready" || ready["taskId"] != frame["task"]["taskId"] {
                    return Err(IcError::new(
                        "INVALID_FRAME",
                        "Invalid rsync readiness reply",
                    ));
                }
                let settings = self.rsync_settings.as_ref().ok_or_else(|| {
                    IcError::new(
                        "RSYNC_BACKEND_DISABLED",
                        "Sender requires explicit rsync backend",
                    )
                })?;
                let child = crate::rsync::spawn(settings, source, true)?;
                let deadline = Instant::now() + Duration::from_millis(read_ms);
                let check = || {
                    if self.stopping.load(Ordering::Acquire) || self.blocked(peer) {
                        return Err(IcError::new("CANCELLED", "Rsync connection invalidated"));
                    }
                    if Instant::now() >= deadline {
                        return Err(IcError::new(
                            "TASK_TIMEOUT",
                            "Rsync transfer deadline exceeded",
                        ));
                    }
                    self.security.validate_local()?;
                    self.security.authenticate(&cert, Some(peer))?;
                    Ok(())
                };
                crate::rsync::transfer(reader, child, string(&frame["task"], "taskId")?, &check)?;
            }
        }
        let response = loop {
            let r = if let Some(response) = early_response.take() {
                response
            } else {
                wire::read_frame(reader)?
                    .ok_or_else(|| IcError::new("PEER_DISCONNECTED", "No result"))?
            };
            if r["type"] == "task_event" && frame["type"] == "task" {
                if r["taskId"] != frame["task"]["taskId"] {
                    return Err(IcError::new("INVALID_FRAME", "Event taskId mismatch"));
                }
                self.log(
                    "task_event",
                    json!({"peerId":peer,"taskId":r["taskId"],"eventData":r["event"]}),
                );
                continue;
            }
            break r;
        };
        let expected_type = match frame["type"].as_str() {
            Some("task") => "result",
            Some("query") => "query_result",
            Some("cancel") => "cancel_ack",
            Some("ping") => "pong",
            _ => "result",
        };
        let expected_id = if frame["type"] == "task" {
            &frame["task"]["taskId"]
        } else {
            &frame["taskId"]
        };
        if response["type"] != expected_type
            || (!expected_id.is_null() && response["taskId"] != *expected_id)
        {
            return Err(IcError::new(
                "INVALID_FRAME",
                "Response type or taskId mismatch",
            ));
        }
        lease.reusable();
        Ok(response)
    }
    pub fn dispatch(&self, peer: &str, task: &Value) -> Result<Value> {
        self.dispatch_source(peer, task, None)
    }
    fn dispatch_source(
        &self,
        peer: &str,
        task: &Value,
        source: Option<&std::path::Path>,
    ) -> Result<Value> {
        let started = Instant::now();
        self.log("task_started", json!({"direction":"outgoing","peerId":peer,"taskId":task["taskId"],"tool":task["tool"]}));
        let mut replayed = false;
        let result = self.dispatch_source_inner(peer, task, source, &mut replayed);
        self.log_task_result("outgoing", peer, task, started, replayed, &result);
        result
    }
    fn dispatch_source_inner(
        &self,
        peer: &str,
        task: &Value,
        source: Option<&std::path::Path>,
        replayed: &mut bool,
    ) -> Result<Value> {
        let admission = self.lifecycle.lock().unwrap();
        if self.stopping.load(Ordering::Acquire) {
            return Err(IcError::new("NODE_STOPPING", "Node is shutting down"));
        }
        if self.outgoing_active.fetch_add(1, Ordering::AcqRel) >= 128 {
            self.outgoing_active.fetch_sub(1, Ordering::AcqRel);
            return Err(IcError::new("BUSY", "Outbound operation capacity reached"));
        }
        let _guard = DispatchGuard(&self.outgoing_active);
        drop(admission);
        self.storage()?;
        if task.get("logicalWorkspaceId").is_some() && task.get("workspaceId").is_some() {
            return Err(IcError::new(
                "INVALID_TASK",
                "Use exactly one workspace selector",
            ));
        }
        let mut mapped = task.clone();
        if let Some(logical) = task["logicalWorkspaceId"].as_str() {
            let workspace = self.ensure_binding(peer, logical)?;
            mapped.as_object_mut().unwrap().remove("logicalWorkspaceId");
            mapped["workspaceId"] = json!(workspace);
        }
        let id = string(&mapped, "taskId")?;
        let key = format!("{peer}:{id}");
        let hash = wire::fingerprint(&mapped);
        let side = crate::tools::side_effect(&mapped, None);
        {
            let store = self.outgoing.lock().unwrap();
            if let Some(r) = store.get(&key) {
                if r["fingerprint"] != hash {
                    return Err(IcError::new("TASK_ID_CONFLICT", "Outgoing ID conflict"));
                }
                if !r["response"].is_null() {
                    *replayed = true;
                    return Ok(r["response"].clone());
                }
                return Err(
                    IcError::new("OUTCOME_UNKNOWN", "Outgoing operation not settled").unknown(),
                );
            }
            if store.retired(&key) {
                return Err(IcError::new("TASK_EXPIRED", "Retired ID"));
            }
            if side
                && store
                    .values()
                    .iter()
                    .any(|r| r["state"] == "unknown" && r["sideEffect"] == true)
            {
                return Err(IcError::new(
                    "UNCERTAIN_SIDE_EFFECT",
                    "Reconcile unknown outgoing operation first",
                )
                .unknown());
            }
        }
        let (wiretask, sync_versions, sync_stats) = self.prepare_sync(peer, task, &mapped)?;
        let mut record = json!({"key":key,"peerId":peer,"taskId":id,"tool":mapped["tool"],"fingerprint":hash,"sideEffect":side,"state":"dispatching","createdAt":now(),"response":null});
        {
            let mut store = self.outgoing.lock().unwrap();
            if let Some(existing) = store.get(&key) {
                if existing["fingerprint"] != hash {
                    return Err(IcError::new("TASK_ID_CONFLICT", "Outgoing ID conflict"));
                }
                if !existing["response"].is_null() {
                    *replayed = true;
                    return Ok(existing["response"].clone());
                }
                return Err(IcError::new(
                    "TASK_PENDING",
                    "Operation already dispatching",
                ));
            }
            if side
                && store
                    .values()
                    .iter()
                    .any(|r| r["state"] == "unknown" && r["sideEffect"] == true)
            {
                return Err(IcError::new(
                    "UNCERTAIN_SIDE_EFFECT",
                    "Unknown operation appeared during preparation",
                )
                .unknown());
            }
            store.put(&key, record.clone())?;
        }
        let send_result = if sync_versions
            .as_ref()
            .is_some_and(|v| self.mapping_versions().as_ref().ok() != Some(v))
        {
            Err(IcError::new(
                "SYNC_MAPPING_CHANGED",
                "Workspace mapping changed before send",
            ))
        } else {
            self.request_source(peer, &json!({"v":2,"type":"task","task":wiretask}), source)
        };
        let mut response = match send_result {
            Ok(r) => r,
            Err(e) => {
                let e = if side && e.code != "SYNC_MAPPING_CHANGED" {
                    e.unknown()
                } else {
                    e
                };
                response_error(id, &e)
            }
        };
        if response["status"] == "ok"
            && let Some(stats) = sync_stats
        {
            response["result"]["transferStats"] = stats;
        }
        record["state"] = json!(if response["outcomeUnknown"] == true
            || response["result"]["outcomeUnknown"] == true
            || response["result"]["state"] == "unknown"
        {
            "unknown"
        } else {
            "completed"
        });
        record["response"] = response.clone();
        record["updatedAt"] = json!(now());
        self.put(false, &key, record)?;
        Ok(response)
    }
    fn remote_catalog(&self, peer: &str) -> Result<Value> {
        let mut out = json!({"workspaces":[],"creationRoots":[]});
        let mut offset = 0u64;
        for _ in 0..128 {
            let response=self.dispatch(peer,&json!({"taskId":uuid::Uuid::new_v4().to_string(),"tool":"workspaceList","args":{"offset":offset,"limit":32},"timeoutMs":1000}))?;
            if response["status"] != "ok" {
                return Err(IcError::new(
                    response["error"]["code"]
                        .as_str()
                        .unwrap_or("WORKSPACE_DENIED"),
                    response["error"]["message"]
                        .as_str()
                        .unwrap_or("Catalog unavailable"),
                ));
            }
            for key in ["workspaces", "creationRoots"] {
                if let Some(items) = response["result"][key].as_array() {
                    out[key].as_array_mut().unwrap().extend(items.clone())
                }
            }
            if let Some(next) = response["result"]["nextOffset"].as_u64() {
                if next <= offset {
                    return Err(IcError::new(
                        "INVALID_FRAME",
                        "Catalog pagination did not advance",
                    ));
                }
                offset = next
            } else {
                return Ok(out);
            }
        }
        Err(IcError::new(
            "WORKSPACE_CAPACITY",
            "Catalog exceeds bounded pagination",
        ))
    }
    fn create_remote_workspace(&self, c: &Value) -> Result<Value> {
        let peer = string(c, "peerId")?;
        let request = string(c, "creationRequestId").or_else(|_| string(c, "requestId"))?;
        let digest = wire::fingerprint(
            &json!({"tool":"workspaceCreate","args":{"peerId":peer,"requestId":request}}),
        );
        let response=self.dispatch(peer,&json!({"taskId":format!("wsc_{digest}"),"tool":"workspaceCreate","args":{"rootId":c["rootId"],"name":c["name"],"requestId":request},"timeoutMs":1000}))?;
        if response["status"] != "ok" {
            return Err(IcError::new(
                response["error"]["code"]
                    .as_str()
                    .unwrap_or("WORKSPACE_CREATE_FAILED"),
                response["error"]["message"]
                    .as_str()
                    .unwrap_or("Creation failed"),
            ));
        }
        let mut result = json!({"workspace":response["result"]});
        if let Some(logical) = c["logicalWorkspaceId"].as_str() {
            let mut b = json!({"command":"bindWorkspace","peerId":peer,"logicalWorkspaceId":logical,"workspaceId":response["result"]["id"]});
            if let Some(revision) = c.get("expectedRevision") {
                b["expectedRevision"] = revision.clone()
            }
            let binding = self.workspaces.command(&b)?;
            result["binding"] = binding;
        }
        Ok(result)
    }
    fn ensure_binding(&self, peer: &str, logical: &str) -> Result<String> {
        if let Some(w) = self.workspaces.binding(peer, logical)? {
            return Ok(w);
        }
        let _guard = self.ensures.lock().unwrap();
        if let Some(w) = self.workspaces.binding(peer, logical)? {
            return Ok(w);
        }
        let registry = self
            .workspaces
            .command(&json!({"command":"listWorkspaceBindings"}))?;
        let rule = registry["autoProvision"]
            .as_array()
            .and_then(|a| {
                a.iter().find(|r| {
                    r["peerId"] == peer
                        && r["logicalWorkspaceId"] == logical
                        && r["enabled"] == true
                })
            })
            .cloned()
            .ok_or_else(|| {
                IcError::new(
                    "WORKSPACE_BINDING_NOT_FOUND",
                    "No binding and auto provisioning disabled",
                )
            })?;
        let digest = wire::fingerprint(
            &json!({"tool":"autoProvision","args":{"nodeId":self.config().id,"peerId":peer,"logicalWorkspaceId":logical,"rootId":rule["rootId"]}}),
        );
        let request = format!("auto_{digest}");
        let name = format!(
            "w_{}_{}",
            logical.chars().take(48).collect::<String>(),
            &digest[..10]
        );
        let created = self.create_remote_workspace(
            &json!({"peerId":peer,"rootId":rule["rootId"],"name":name,"creationRequestId":request}),
        )?;
        let current = self
            .workspaces
            .command(&json!({"command":"listWorkspaceBindings"}))?;
        if !current["autoProvision"]
            .as_array()
            .is_some_and(|a| a.contains(&rule))
        {
            return Err(IcError::new(
                "WORKSPACE_BINDING_CONFLICT",
                "Provisioning rule changed",
            ));
        }
        let id = string(&created["workspace"], "id")?.to_string();
        self.workspaces.command(&json!({"command":"bindWorkspace","peerId":peer,"logicalWorkspaceId":logical,"workspaceId":id}))?;
        Ok(id)
    }
    fn mapping_versions(&self) -> Result<(Value, Value)> {
        Ok((
            self.workspaces
                .command(&json!({"command":"listWorkspaceBindings"}))?["revision"]
                .clone(),
            self.workspaces
                .command(&json!({"command":"listLocalWorkspaces"}))?["revision"]
                .clone(),
        ))
    }
    fn prepare_sync(
        &self,
        peer: &str,
        original: &Value,
        mapped: &Value,
    ) -> Result<SyncPreparation> {
        let Some(logical) = original["logicalWorkspaceId"].as_str() else {
            return Ok((mapped.clone(), None, None));
        };
        if !matches!(mapped["tool"].as_str(), Some("exec" | "syncApply")) {
            return Ok((mapped.clone(), None, None));
        }
        match self.workspaces.local_root(logical) {
            Ok(_) => {}
            Err(e) if e.code == "LOCAL_WORKSPACE_NOT_FOUND" && mapped["tool"] == "exec" => {
                return Ok((mapped.clone(), None, None));
            }
            Err(e) => return Err(e),
        }
        let (root, workspace, scope) = self.workspaces.sync_mapping(peer, logical)?;
        if mapped["args"]["background"] == true {
            return Err(IcError::new(
                "SYNC_BACKGROUND_UNSUPPORTED",
                "Local sync requires foreground execution",
            ));
        }
        let versions = self.mapping_versions()?;
        let snapshot = crate::sync::capture(&root, &scope)?;
        let internal = |tool: &str, args: Value| json!({"taskId":uuid::Uuid::new_v4().to_string(),"tool":tool,"args":args,"workspaceId":workspace,"timeoutMs":mapped["timeoutMs"].as_u64().unwrap_or(10000)});
        let sync_stats = if self.rsync_settings.is_some() {
            let stage = crate::sync::materialize_rsync_source(&self.config().state_dir, &snapshot)?;
            let transfer = internal(
                "syncTransfer",
                json!({"scope":scope,"manifest":snapshot.manifest}),
            );
            let result = self.dispatch_source(peer, &transfer, Some(stage.path()))?;
            if result["status"] != "ok" {
                return Err(IcError::new(
                    result["error"]["code"]
                        .as_str()
                        .unwrap_or("SYNC_TRANSFER_FAILED"),
                    result["error"]["message"]
                        .as_str()
                        .unwrap_or("Rsync transfer failed"),
                ));
            }
            let receiver = &result["result"]["transferStats"];
            Some(
                json!({"transmittedBytes":receiver["receivedBytes"],"receivedBytes":receiver["transmittedBytes"]}),
            )
        } else {
            let inv = self.dispatch(peer, &internal("syncInventory", json!({"scope":scope})))?;
            if inv["status"] != "ok" {
                return Err(IcError::new("SYNC_INVENTORY_FAILED", inv.to_string()));
            }
            let known = inv["result"]["blobs"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            use base64::Engine;
            for (hash, data) in &snapshot.blobs {
                if known.iter().any(|h| h == hash) {
                    continue;
                }
                let mut offset = 0;
                loop {
                    let end = (offset + 16384).min(data.len());
                    let reply=self.dispatch(peer,&internal("syncUpload",json!({"sha256":hash,"offset":offset,"base64":base64::engine::general_purpose::STANDARD.encode(&data[offset..end]),"totalBytes":data.len()})))?;
                    if reply["status"] != "ok" {
                        return Err(IcError::new("SYNC_UPLOAD_FAILED", reply.to_string()));
                    }
                    let received =
                        reply["result"]["received"].as_u64().unwrap_or(end as u64) as usize;
                    if received < end || received > data.len() {
                        return Err(IcError::new(
                            "SYNC_UPLOAD_FAILED",
                            "Invalid upload acknowledgement",
                        ));
                    }
                    offset = received;
                    if offset == data.len() {
                        break;
                    }
                }
                self.workspaces
                    .check_mapping(peer, logical, &root, &workspace, &scope)?;
                if self.mapping_versions()? != versions {
                    return Err(IcError::new(
                        "SYNC_MAPPING_CHANGED",
                        "Workspace mapping revision changed",
                    ));
                }
            }
            None
        };
        self.workspaces
            .check_mapping(peer, logical, &root, &workspace, &scope)?;
        if self.mapping_versions()? != versions {
            return Err(IcError::new(
                "SYNC_MAPPING_CHANGED",
                "Workspace mapping revision changed",
            ));
        }
        if crate::sync::capture(&root, &scope)?.hash != snapshot.hash {
            return Err(IcError::new(
                "SYNC_SOURCE_CHANGED",
                "Source changed during upload",
            ));
        }
        let mut task = mapped.clone();
        task["tool"] = json!(if mapped["tool"] == "exec" {
            "syncExec"
        } else {
            "syncApply"
        });
        task["args"]["scope"] = scope;
        task["args"]["manifest"] = snapshot.manifest;
        Ok((task, Some(versions), sync_stats))
    }
    pub fn command(&self, c: &Value) -> Result<Value> {
        // Control requests may persist observations after their network reply.
        // Keep their lifecycle admission through that persistence, too.
        let ty = c["type"].as_str().or_else(|| c["command"].as_str());
        let _control_guard = if matches!(
            ty,
            Some(
                "query"
                    | "cancel"
                    | "pairingRequest"
                    | "pairingApprove"
                    | "pairingReject"
                    | "pairingConfirm"
                    | "unpair"
            )
        ) {
            let _admission = self.lifecycle.lock().unwrap();
            if self.stopping.load(Ordering::Acquire) {
                return Err(IcError::new("NODE_STOPPING", "Node is shutting down"));
            }
            if self.control_active.fetch_add(1, Ordering::AcqRel) >= 32 {
                self.control_active.fetch_sub(1, Ordering::AcqRel);
                return Err(IcError::new("BUSY", "Outbound operation capacity reached"));
            }
            Some(DispatchGuard(&self.control_active))
        } else {
            None
        };
        let result = self.command_inner(c);
        if result.as_ref().err().is_some_and(|e| {
            [
                "IO_ERROR",
                "EACCES",
                "UNSAFE_STATE_FILE",
                "JOURNAL_CORRUPT",
                "JOURNAL_UNAVAILABLE",
            ]
            .contains(&e.code.as_str())
        }) {
            self.storage_failed.store(true, Ordering::Release)
        }
        result
    }
    fn command_inner(&self, c: &Value) -> Result<Value> {
        let ty = string(c, "type").or_else(|_| string(c, "command"))?;
        match ty {
            "sessionOpen" | "sessionDetach" | "sessionReconcile" | "listSessions"
            | "sessionDispatch" | "sessionMcp" | "mcpListTools" | "mcpCallTool" => {
                self.session_command(c)
            }
            "nodesList" | "nodesStatus" | "nodesRename" | "nodesBind" | "nodesUnbind" => {
                self.nodes_command(c)
            }
            "mcpRegistry" => {
                let operation = &c["operation"];
                let _mutation = self.pairing_mutation.lock().unwrap();
                let result = self.mcp.command(operation)?;
                if operation["command"] != "list" {
                    let mut control = self.control.lock().unwrap();
                    control["policyEpoch"] =
                        json!(control["policyEpoch"].as_u64().unwrap_or(0) + 1);
                    crate::node_store::write_section(
                        &crate::node_store::directory(&self.config()),
                        "control",
                        &control,
                    )?;
                    self.transport.invalidate(None);
                }
                Ok(result)
            }
            "pairingStatus"
            | "listPeers"
            | "listPairingRequests"
            | "pairingRequest"
            | "pairingApprove"
            | "pairingReject"
            | "pairingConfirm"
            | "unpair" => self.pairing_command(c),
            "status" => Ok(
                json!({"id":self.config().id,"name":self.config().raw["name"],"port":self.port(),"transport":"TLSv1.3-mTLS-pinned","durable":true,"policyEpoch":self.epoch(),"active":self.active.lock().unwrap().len(),"storageFailed":self.storage_failed.load(Ordering::Acquire),"incoming":self.incoming.lock().unwrap().info(),"outgoing":self.outgoing.lock().unwrap().info(),"certificateFingerprint":self.security.fingerprint256,"peers":self.config().raw["peers"],"transportStats":self.transport.stats(self.connections.load(Ordering::Acquire))}),
            ),
            "auditLogs" => {
                let mut r = self.audit.query(c)?;
                r["ok"] = json!(true);
                Ok(r)
            }
            "permissions" => {
                let control = self.control.lock().unwrap().clone();
                Ok(
                    json!({"epoch":control["policyEpoch"],"policy":control["policyRaw"],"revoked":control["blockedPeers"],"effectivePolicy":*self.policy.read().unwrap()}),
                )
            }
            "dispatch" => self.dispatch(string(c, "peerId")?, &c["task"]),
            "query" => {
                let peer = string(c, "peerId")?;
                let id = string(c, "taskId")?;
                let r = self.request(peer, &json!({"v":2,"type":"query","taskId":id}))?;
                if !r["response"].is_null() {
                    let key = format!("{peer}:{id}");
                    let record = self.outgoing.lock().unwrap().get(&key);
                    if let Some(mut record) = record {
                        record["response"] = r["response"].clone();
                        record["state"] = r["state"].clone();
                        self.put(false, &key, record)?;
                    } else if r["state"] == "unknown" || r["response"]["outcomeUnknown"] == true {
                        let observed = format!("observation:{key}");
                        self.put(false,&observed,json!({"key":observed,"peerId":peer,"taskId":id,"state":"unknown","sideEffect":true,"observationOnly":true,"response":r["response"],"createdAt":now()}))?;
                    }
                }
                Ok(r)
            }
            "cancel" => self.request(
                string(c, "peerId")?,
                &json!({"v":2,"type":"cancel","taskId":c["taskId"]}),
            ),
            "cancelTask" => {
                let key = format!("{}:{}", string(c, "masterId")?, string(c, "taskId")?);
                let a = self.active.lock().unwrap();
                if let Some(cancel) = a.get(&key) {
                    cancel.store(true, Ordering::Release)
                }
                Ok(json!({"cancelled":a.contains_key(&key)}))
            }
            "listTasks" => {
                let mut records = if c["kind"] == "outgoing" {
                    self.outgoing.lock().unwrap().values()
                } else {
                    self.incoming.lock().unwrap().values()
                };
                let limit = c["limit"].as_u64().unwrap_or(100).min(1000) as usize;
                records.reverse();
                records.truncate(limit);
                Ok(json!({"records":records,"limit":limit}))
            }
            "taskStatus" | "taskEvents" => {
                let key = format!("{}:{}", string(c, "masterId")?, string(c, "taskId")?);
                let store = self.incoming.lock().unwrap();
                Ok(store
                    .get(&key)
                    .unwrap_or(json!({"state":if store.retired(&key){"expired"}else{"not_found"}})))
            }
            "operationStatus" => {
                let key = format!("{}:{}", string(c, "peerId")?, string(c, "taskId")?);
                let store = self.outgoing.lock().unwrap();
                Ok(store
                    .get(&key)
                    .unwrap_or(json!({"state":if store.retired(&key){"expired"}else{"not_found"}})))
            }
            "setPolicy" | "reloadPolicy" => {
                let current = self.epoch();
                if c.get("expectedEpoch").is_some() && c["expectedEpoch"].as_u64() != Some(current)
                {
                    return Err(IcError::new("POLICY_CONFLICT", "Refresh policy epoch"));
                }
                let cfg = self.config();
                let raw = if ty == "reloadPolicy" {
                    serde_json::from_slice::<Value>(&std::fs::read(&cfg.path)?)?["policy"].clone()
                } else {
                    c["policy"].clone()
                };
                let p = crate::policy::validate_config_policy(&cfg, &raw)?;
                let mut incoming = self.incoming.lock().unwrap();
                let mut outgoing = self.outgoing.lock().unwrap();
                let max_records = p["maxTaskRecords"].as_u64().unwrap_or(4096) as usize;
                let max_bytes = p["maxJournalBytes"].as_u64().unwrap_or(67108864);
                incoming.assert_limits(max_records, max_bytes)?;
                outgoing.assert_limits(max_records, max_bytes)?;
                let mut control = self.control.lock().unwrap();
                if control["policyEpoch"].as_u64() != Some(current) {
                    return Err(IcError::new(
                        "POLICY_CONFLICT",
                        "Policy changed concurrently",
                    ));
                }
                let mut next = control.clone();
                next["policyRaw"] = raw;
                next["policyEpoch"] = json!(current + 1);
                crate::node_store::write_section(
                    &crate::node_store::directory(&cfg),
                    "control",
                    &next,
                )?;
                *control = next;
                incoming.configure(max_records, max_bytes)?;
                outgoing.configure(max_records, max_bytes)?;
                self.workspaces.update_policy(p.clone());
                *self.policy.write().unwrap() = p;
                drop(control);
                drop(incoming);
                drop(outgoing);
                self.transport.invalidate(None);
                self.incoming_sockets.invalidate(None);
                for cancel in self.active.lock().unwrap().values() {
                    cancel.store(true, Ordering::Release)
                }
                Ok(json!({"epoch":current+1}))
            }
            "revoke" => {
                self.invalidate_peer(string(c, "masterId").or_else(|_| string(c, "peerId"))?)?;
                Ok(json!({"revoked":true}))
            }
            "reconcile" => {
                let incoming = c.get("masterId").is_some();
                let who = string(c, if incoming { "masterId" } else { "peerId" })?;
                let mut key = format!("{who}:{}", string(c, "taskId")?);
                if !incoming && self.outgoing.lock().unwrap().get(&key).is_none() {
                    key = format!("observation:{key}")
                }
                let record = if incoming {
                    self.incoming.lock().unwrap().get(&key)
                } else {
                    self.outgoing.lock().unwrap().get(&key)
                };
                let mut r = record.ok_or_else(|| IcError::new("TASK_NOT_FOUND", "No record"))?;
                if r["state"] != "unknown" {
                    return Err(IcError::new(
                        "INVALID_RECONCILIATION",
                        "Only unknown operations may be reconciled",
                    ));
                }
                if self.active.lock().unwrap().contains_key(&key) {
                    return Err(IcError::new(
                        "TASK_ACTIVE",
                        "Operation must close before reconciliation",
                    ));
                }
                let resolution = string(c, "resolution")?;
                if ![
                    "completed",
                    "not_applied",
                    "effects-confirmed",
                    "no-effects",
                    "effects-inspected",
                ]
                .contains(&resolution)
                {
                    return Err(IcError::new(
                        "INVALID_RECONCILIATION",
                        "Explicit inspected resolution required",
                    ));
                }
                let note = string(c, "note")?;
                if note.trim().is_empty() || note.len() > 2000 {
                    return Err(IcError::new(
                        "INVALID_RECONCILIATION",
                        "Owner note required",
                    ));
                }
                r["state"] = json!("reconciled");
                r["response"] = if resolution == "completed" {
                    json!({"v":2,"type":"result","taskId":r["taskId"],"status":"ok","result":c.get("result").cloned().unwrap_or(json!({"manuallyReconciled":true}))})
                } else {
                    response_error(
                        r["taskId"].as_str().unwrap_or(""),
                        &IcError::new(
                            "RECONCILED_NOT_APPLIED",
                            "Owner confirmed no effect; ID remains consumed",
                        ),
                    )
                };
                r["reconciliation"] = json!({"note":note,"resolution":resolution,"at":now()});
                self.put(incoming, &key, r.clone())?;
                if !incoming {
                    self.sessions
                        .reconcile_remote_records(std::slice::from_ref(&r))?;
                }
                Ok(r)
            }
            "recoverWorkspaceLock" => {
                let policy = self.policy.read().unwrap().clone();
                let grant = self.workspaces.resolve(
                    &policy,
                    string(c, "masterId")?,
                    c["workspaceId"].as_str(),
                    self.epoch(),
                )?;
                if self.jobs.has_active(&grant.root) || !self.active.lock().unwrap().is_empty() {
                    return Err(IcError::new(
                        "WORKSPACE_BUSY",
                        "Cannot recover while active tasks or jobs remain",
                    ));
                }
                if self
                    .incoming
                    .lock()
                    .unwrap()
                    .values()
                    .iter()
                    .any(|r| r["state"] == "unknown")
                    || self
                        .outgoing
                        .lock()
                        .unwrap()
                        .values()
                        .iter()
                        .any(|r| r["state"] == "unknown")
                {
                    return Err(IcError::new(
                        "OUTCOME_UNKNOWN",
                        "Reconcile unknown operations before recovery",
                    ));
                }
                crate::sync::WorkspaceLock::recover(&grant.root, string(c, "note")?)
            }
            "listJobs" | "jobStatus" | "jobOutput" | "jobCancel" | "reconcileJob" => {
                self.jobs.command(c)
            }
            "createWorkspace" => self.create_remote_workspace(c),
            "ensureWorkspaceBinding" => {
                let peer = string(c, "peerId")?;
                let logical = string(c, "logicalWorkspaceId")?;
                Ok(
                    json!({"peerId":peer,"logicalWorkspaceId":logical,"workspaceId":self.ensure_binding(peer,logical)?}),
                )
            }
            "remoteWorkspaces" => self.remote_catalog(string(c, "peerId")?),
            "bindWorkspace" | "setWorkspaceAutoProvision" => {
                let peer = string(c, "peerId")?;
                if !self.config().raw["peers"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|p| p["id"] == peer))
                {
                    return Err(IcError::new(
                        "UNKNOWN_PEER",
                        "Unknown outgoing relationship",
                    ));
                }
                if ty == "bindWorkspace" || c["enabled"] == true {
                    let catalog = self.remote_catalog(peer)?;
                    if ty == "bindWorkspace"
                        && !catalog["workspaces"].as_array().is_some_and(|a| {
                            a.iter()
                                .any(|w| w["id"] == c["workspaceId"] && w["state"] == "ready")
                        })
                    {
                        return Err(IcError::new(
                            "WORKSPACE_DENIED",
                            "Workspace not currently approved",
                        ));
                    }
                    if ty == "setWorkspaceAutoProvision"
                        && !catalog["creationRoots"]
                            .as_array()
                            .is_some_and(|a| a.iter().any(|w| w["id"] == c["rootId"]))
                    {
                        return Err(IcError::new(
                            "WORKSPACE_CREATE_DENIED",
                            "Provisioning root not approved",
                        ));
                    }
                }
                self.workspaces.command(c)
            }
            "shutdown" => {
                self.shutdown()?;
                Ok(json!({"stopped":true}))
            }
            _ => {
                let result = self.workspaces.command(c);
                if result.as_ref().err().is_some_and(|e| {
                    [
                        "IO_ERROR",
                        "EACCES",
                        "UNSAFE_STATE_FILE",
                        "JOURNAL_CORRUPT",
                        "JOURNAL_UNAVAILABLE",
                    ]
                    .contains(&e.code.as_str())
                }) {
                    self.storage_failed.store(true, Ordering::Release)
                }
                result
            }
        }
    }
    pub fn shutdown(&self) -> Result<()> {
        let admission = self.lifecycle.lock().unwrap();
        self.stopping.store(true, Ordering::Release);
        self.transport.shutdown();
        self.incoming_sockets.shutdown();
        self.pairing_sockets.shutdown();
        drop(admission);
        for cancel in self.active.lock().unwrap().values() {
            cancel.store(true, Ordering::Release)
        }
        self.jobs.shutdown()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.active.lock().unwrap().is_empty()
            || self.outgoing_active.load(Ordering::Acquire) > 0
            || self.control_active.load(Ordering::Acquire) > 0
            || self.connections.load(Ordering::Acquire) > 0
            || self.pairing_connections.load(Ordering::Acquire) > 0
        {
            if Instant::now() > deadline {
                return Err(IcError::new(
                    "SHUTDOWN_TIMEOUT",
                    "Active executions have not closed",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut lock = self.state_lock.lock().unwrap();
        if lock.is_some() {
            self.log("node_stopped", json!({}));
        }
        lock.take();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, KeyUsage},
        },
    };
    fn certificates(dir: &std::path::Path) -> (Value, Value) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "ca").unwrap();
        let name = name.build();
        let mut ca = X509::builder().unwrap();
        ca.set_version(2).unwrap();
        ca.set_subject_name(&name).unwrap();
        ca.set_issuer_name(&name).unwrap();
        ca.set_pubkey(&key).unwrap();
        ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        ca.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        ca.append_extension(KeyUsage::new().key_cert_sign().build().unwrap())
            .unwrap();
        ca.sign(&key, MessageDigest::sha256()).unwrap();
        let ca = ca.build();
        std::fs::write(dir.join("ca.pem"), ca.to_pem().unwrap()).unwrap();
        let mut pins = BTreeMap::new();
        for id in ["master", "servant"] {
            let k = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
            let mut n = X509NameBuilder::new().unwrap();
            n.append_entry_by_text("CN", id).unwrap();
            let n = n.build();
            let mut c = X509::builder().unwrap();
            c.set_version(2).unwrap();
            let serial = openssl::bn::BigNum::from_u32(if id == "master" { 2 } else { 3 })
                .unwrap()
                .to_asn1_integer()
                .unwrap();
            c.set_serial_number(&serial).unwrap();
            c.set_subject_name(&n).unwrap();
            c.set_issuer_name(ca.subject_name()).unwrap();
            c.set_pubkey(&k).unwrap();
            c.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            c.set_not_after(&Asn1Time::days_from_now(2).unwrap())
                .unwrap();
            c.append_extension(BasicConstraints::new().build().unwrap())
                .unwrap();
            c.append_extension(
                KeyUsage::new()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .unwrap(),
            )
            .unwrap();
            c.sign(&key, MessageDigest::sha256()).unwrap();
            let c = c.build();
            std::fs::write(dir.join(format!("{id}.pem")), c.to_pem().unwrap()).unwrap();
            std::fs::write(
                dir.join(format!("{id}.key")),
                k.private_key_to_pem_pkcs8().unwrap(),
            )
            .unwrap();
            pins.insert(
                id,
                hex::encode_upper(c.digest(MessageDigest::sha256()).unwrap()),
            );
        }
        let sec = |id: &str, peer: &str| json!({"cert":format!("{id}.pem"),"key":format!("{id}.key"),"ca":"ca.pem","trustedPeers":{peer:pins[peer]}});
        (sec("master", "servant"), sec("servant", "master"))
    }
    fn config(
        dir: &std::path::Path,
        id: &str,
        security: Value,
        policy: Value,
        peers: Value,
    ) -> Config {
        Config {
            raw: json!({"security":security,"policyRaw":policy,"policy":policy,"peers":peers}),
            id: id.into(),
            host: "127.0.0.1".into(),
            port: 0,
            path: dir.join(format!("{id}.json")),
            state_dir: dir.join(format!("{id}-state")),
        }
    }
    #[test]
    fn node_mtls_durable_ids_owner_boundary() {
        let d = tempfile::tempdir().unwrap();
        let (ms, ss) = certificates(d.path());
        let root = d.path().join("workspace");
        std::fs::create_dir(&root).unwrap();
        let cfg = config(
            d.path(),
            "servant",
            ss,
            json!({"grants":{"master":{"workspace":root,"tools":["writeFile","readFile","echo"]}}}),
            json!([]),
        );
        let servant = Node::new(cfg.clone()).unwrap();
        servant.start().unwrap();
        let master = Node::new(config(
            d.path(),
            "master",
            ms,
            json!({}),
            json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
        ))
        .unwrap();
        let task = json!({"taskId":"once","tool":"writeFile","args":{"path":"a","text":"hello"},"timeoutMs":1000});
        let first = master.dispatch("servant", &task).unwrap();
        assert_eq!(first["status"], "ok", "{first}");
        assert_eq!(master.dispatch("servant", &task).unwrap(), first);
        let mut changed = task.clone();
        changed["args"]["text"] = json!("different");
        assert_eq!(
            master.dispatch("servant", &changed).unwrap_err().code,
            "TASK_ID_CONFLICT"
        );
        let denied = master
            .request("servant", &json!({"v":2,"type":"setPolicy","policy":{}}))
            .unwrap();
        assert_eq!(denied["status"], "error");
        assert_eq!(std::fs::read_to_string(root.join("a")).unwrap(), "hello");
        servant.shutdown().unwrap();
        drop(servant);
        let restarted = Node::new(cfg).unwrap();
        let r = restarted.incoming_query("master", "once").unwrap();
        assert_eq!(r["response"], first);
        restarted.shutdown().unwrap();
        master.shutdown().unwrap();
    }
    #[test]
    fn node_mtls_rejects_pin_and_cn_mismatch() {
        let d = tempfile::tempdir().unwrap();
        let (ms, ss) = certificates(d.path());
        assert!(Security::load(&ms, d.path(), "servant").is_err());
        let mut malformed = ms.clone();
        malformed["trustedPeers"]["servant"] = json!(format!(":{}", "00".repeat(32)));
        assert!(Security::load(&malformed, d.path(), "master").is_err());
        let servant = Node::new(config(d.path(), "servant", ss, json!({}), json!([]))).unwrap();
        servant.start().unwrap();
        let mut wrong = ms;
        wrong["trustedPeers"]["servant"] = json!("00".repeat(32));
        let security = Security::load(&wrong, d.path(), "master").unwrap();
        assert_eq!(
            security
                .connect("127.0.0.1", servant.port(), "servant")
                .unwrap_err()
                .code,
            "UNTRUSTED_IDENTITY"
        );
        servant.shutdown().unwrap();
    }
    #[test]
    fn node_local_sync_manual_mirror_and_auto_provision() {
        let d = tempfile::tempdir().unwrap();
        let (ms, ss) = certificates(d.path());
        let parent = d.path().join("remote");
        let local = d.path().join("local");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&local).unwrap();
        std::fs::write(local.join("file.bin"), [0u8, 255, 42]).unwrap();
        let servant=Node::new(config(d.path(),"servant",ss,json!({"grants":{"master":{"tools":["workspaceList","workspaceCreate"],"workspaceProvisioning":{"roots":{"projects":{"path":parent,"maxWorkspaces":2,"grant":{"tools":["syncInventory","syncUpload","syncApply","readFile"],"directories":[{"path":"","read":true,"write":true}]}}}}}}}),json!([]))).unwrap();
        servant.start().unwrap();
        let master = Node::new(config(
            d.path(),
            "master",
            ms,
            json!({}),
            json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
        ))
        .unwrap();
        master.command(&json!({"command":"setWorkspaceAutoProvision","peerId":"servant","logicalWorkspaceId":"project","rootId":"projects","enabled":true})).unwrap();
        master.command(&json!({"command":"ensureWorkspaceBinding","peerId":"servant","logicalWorkspaceId":"project"})).unwrap();
        master.command(&json!({"command":"bindLocalWorkspace","logicalWorkspaceId":"project","path":local,"expectedRevision":0})).unwrap();
        master.command(&json!({"command":"setWorkspaceSyncScope","peerId":"servant","logicalWorkspaceId":"project","scope":{"paths":[""]}})).unwrap();
        let response=master.dispatch("servant",&json!({"taskId":"manual","logicalWorkspaceId":"project","tool":"syncApply","args":{},"timeoutMs":1000})).unwrap();
        assert_eq!(response["status"], "ok", "{response}");
        let remote = std::fs::read_dir(&parent)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            std::fs::read(remote.join("file.bin")).unwrap(),
            vec![0u8, 255, 42]
        );
        std::fs::write(remote.join("extra"), b"remove").unwrap();
        let response=master.dispatch("servant",&json!({"taskId":"manual2","logicalWorkspaceId":"project","tool":"syncApply","args":{},"timeoutMs":1000})).unwrap();
        assert_eq!(response["status"], "ok", "{response}");
        assert!(!remote.join("extra").exists());
        assert_eq!(
            master.command(&json!({"command":"listJobs"})).unwrap()["jobs"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        servant.shutdown().unwrap();
        master.shutdown().unwrap();
    }
    #[test]
    fn node_request_timeout_is_clamped_to_grant() {
        let d = tempfile::tempdir().unwrap();
        let (ms, ss) = certificates(d.path());
        let servant = Node::new(config(
            d.path(),
            "servant",
            ss,
            json!({"grants":{"master":{"tools":["echo","wait"],"maxTimeoutMs":30}}}),
            json!([]),
        ))
        .unwrap();
        servant.start().unwrap();
        let master = Node::new(config(
            d.path(),
            "master",
            ms,
            json!({}),
            json!([{"id":"servant","host":"127.0.0.1","port":servant.port()}]),
        ))
        .unwrap();
        let echoed = master
            .dispatch(
                "servant",
                &json!({"taskId":"clamp","tool":"echo","args":{"text":"ok"},"timeoutMs":10000}),
            )
            .unwrap();
        assert_eq!(echoed["status"], "ok", "{echoed}");
        let start = Instant::now();
        let waited = master
            .dispatch(
                "servant",
                &json!({"taskId":"deadline","tool":"wait","args":{"ms":1000},"timeoutMs":10000}),
            )
            .unwrap();
        assert_eq!(waited["error"]["code"], "TASK_TIMEOUT", "{waited}");
        assert!(start.elapsed() < Duration::from_millis(800));
        let invalid=master.dispatch("servant",&json!({"taskId":"invalidtimeout","tool":"echo","args":{"text":"no"},"timeoutMs":86400001})).unwrap();
        assert_eq!(invalid["error"]["code"], "INVALID_TASK");
        servant.shutdown().unwrap();
        master.shutdown().unwrap();
    }
    #[test]
    fn node_persisted_unknown_gate_reconciliation() {
        let d = tempfile::tempdir().unwrap();
        let (_, ss) = certificates(d.path());
        let cfg = config(
            d.path(),
            "servant",
            ss,
            json!({"grants":{"master":{"tools":["echo"]}}}),
            json!([]),
        );
        let node = Node::new(cfg).unwrap();
        node.put(true,"master:lost",json!({"key":"master:lost","masterId":"master","taskId":"lost","sideEffect":true,"state":"unknown","policyEpoch":0})).unwrap();
        assert!(
            node.command(
                &json!({"command":"reconcile","masterId":"master","taskId":"lost","note":""})
            )
            .is_err()
        );
        node.command(&json!({"command":"reconcile","masterId":"master","taskId":"lost","note":"Inspected the filesystem","resolution":"not_applied"})).unwrap();
        assert_eq!(
            node.incoming_query("master", "lost").unwrap()["state"],
            "reconciled"
        );
        node.shutdown().unwrap();
    }
}
