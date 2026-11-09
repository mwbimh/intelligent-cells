//! Separate bootstrap channel: no task or owner-command dispatch is reachable here.
use super::*;
use std::{
    io::{Read, Write},
    net::IpAddr,
};

struct DeadlineStream {
    stream: openssl::ssl::SslStream<TcpStream>,
    deadline: Instant,
}
impl Read for DeadlineStream {
    fn read(&mut self, data: &mut [u8]) -> std::io::Result<usize> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Pairing deadline exceeded")
            })?;
        self.stream.get_ref().set_read_timeout(Some(left))?;
        self.stream.read(data)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.stream.write(data)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn deny(message: &str) -> IcError {
    IcError::new("PAIRING_DENIED", message)
}
fn require_node_uuid(config: &Config, id: &str) -> Result<()> {
    // Direct library fixtures retain their explicitly supplied identities. The
    // managed service layout always uses immutable UUID identities.
    if config.raw.get("nodesFile").is_some() && uuid::Uuid::parse_str(id).is_err() {
        return Err(deny(
            "Node identity must be a UUID; display names are metadata",
        ));
    }
    Ok(())
}
fn endpoint_allowed(config: &Config, host: &str, port: u64, listener: bool) -> Result<()> {
    let ip: IpAddr = host
        .parse()
        .map_err(|_| deny("Pairing requires an IP address"))?;
    if ip.is_unspecified() || ip.is_multicast() || port > 65535 || (!listener && port == 0) {
        return Err(deny("Invalid pairing endpoint"));
    }
    if !ip.is_loopback() && config.raw["security"]["allowExternal"] != true {
        return Err(deny("External pairing requires security.allowExternal"));
    }
    Ok(())
}
impl Node {
    pub(super) fn merge_paired_config(
        config: &mut Config,
        identity: &Value,
        endpoint: Option<&Value>,
    ) -> Result<()> {
        require_node_uuid(config, string(identity, "nodeId")?)?;
        let (id, pin) = crate::tls::verify_identity_bundle(identity)?;
        if id == config.id {
            return Err(deny("Cannot pair self"));
        }
        let pins = config.raw["security"]["trustedPeers"]
            .as_object_mut()
            .ok_or_else(|| deny("Explicit trust map required"))?;
        if let Some(existing) = pins.get(&id) {
            let values = existing
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![existing.clone()]);
            if !values.iter().any(|p| {
                p.as_str()
                    .is_some_and(|v| v.replace(':', "").eq_ignore_ascii_case(&pin))
            }) {
                return Err(deny(
                    "Existing identity differs; explicit rotation required",
                ));
            }
        }
        pins.insert(id.clone(), json!(pin));
        if let Some(endpoint) = endpoint {
            let host = string(endpoint, "host")?;
            let port = endpoint["port"]
                .as_u64()
                .ok_or_else(|| deny("Port required"))?;
            endpoint_allowed(config, host, port, false)?;
            if config.raw.get("agent").is_none_or(Value::is_null) {
                return Err(deny("Outgoing relationships require an agent"));
            }
            if config.raw.get("peers").is_none() {
                config.raw["peers"] = json!([]);
            }
            let peers = config.raw["peers"]
                .as_array_mut()
                .ok_or_else(|| deny("Peers array required"))?;
            let peer = json!({"id":id,"host":host,"port":port});
            if let Some(old) = peers.iter().find(|p| p["id"] == id) {
                if old != &peer {
                    return Err(deny("Existing endpoint differs"));
                }
            } else {
                if peers.len() >= 32 {
                    return Err(deny("Peer limit reached"));
                }
                peers.push(peer);
            }
        }
        Ok(())
    }
    pub(super) fn start_pairing(self: &Arc<Self>) -> Result<()> {
        let config = self.config();
        let Some(options) = config.raw.get("pairing") else {
            return Ok(());
        };
        let host = string(options, "host")?;
        let port = options["port"]
            .as_u64()
            .ok_or_else(|| deny("Pairing port required"))?;
        endpoint_allowed(&config, host, port, true)?;
        if options.as_object().is_none_or(|o| o.len() != 2) {
            return Err(deny("Pairing accepts host and port only"));
        }
        self.security.public_identity()?;
        let listener = TcpListener::bind((host, port as u16))?;
        listener.set_nonblocking(true)?;
        self.pairing_port
            .store(listener.local_addr()?.port(), Ordering::Release);
        let node = self.clone();
        thread::spawn(move || {
            while !node.is_stopping() {
                match listener.accept() {
                    Ok((tcp, address)) => {
                        let admission = node.lifecycle.lock().unwrap();
                        if node.is_stopping() {
                            break;
                        }
                        if node.pairing_connections.fetch_add(1, Ordering::AcqRel) >= 8 {
                            node.pairing_connections.fetch_sub(1, Ordering::AcqRel);
                            continue;
                        }
                        let guard = match node.pairing_sockets.register(&tcp) {
                            Ok(guard) => guard,
                            Err(_) => {
                                node.pairing_connections.fetch_sub(1, Ordering::AcqRel);
                                continue;
                            }
                        };
                        // Reuse the socket reaper as an absolute bootstrap deadline.
                        // Never reset this timer on peer traffic, including TLS handshake bytes.
                        guard.idle();
                        drop(admission);
                        let n = node.clone();
                        thread::spawn(move || {
                            let _guard = guard;
                            // Never log submitted PEM or payloads from the bootstrap channel.
                            if let Err(e) = n.accept_pairing(tcp)
                                && !n.is_stopping()
                            {
                                n.log(
                                    "pairing_connection_error",
                                    json!({"code":e.code,"remoteAddr":address.to_string()}),
                                );
                            }
                            n.pairing_connections.fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }
    fn accept_pairing(&self, tcp: TcpStream) -> Result<()> {
        tcp.set_nonblocking(false)?;
        tcp.set_read_timeout(Some(Duration::from_secs(3)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut stream = self
            .security
            .pairing_acceptor()?
            .accept(tcp)
            .map_err(|_| deny("Pairing TLS handshake failed"))?;
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| deny("Client identity required"))?;
        wire::write_frame(
            &mut stream,
            &json!({"type":"pairing_identity","identity":self.security.public_identity()?}),
        )?;
        let mut reader = BufReader::new(DeadlineStream {
            stream,
            deadline: Instant::now() + Duration::from_secs(3),
        });
        let frame =
            wire::read_frame(&mut reader)?.ok_or_else(|| deny("Pairing request required"))?;
        let result = (|| -> Result<Value> {
            if frame["type"] != "pairing" || frame["v"] != 1 {
                return Err(deny("Invalid pairing protocol"));
            }
            Security::verify_presented_bundle(&cert, &frame["identity"])?;
            let id = string(&frame["identity"], "nodeId")?;
            require_node_uuid(&self.config(), id)?;
            if self.blocked(id) || self.is_stopping() {
                return Err(deny("Peer revoked or node stopping"));
            }
            let _mutation = self.pairing_mutation.lock().unwrap();
            if self.blocked(id) || self.is_stopping() {
                return Err(deny("Peer revoked or node stopping"));
            }
            match frame["action"].as_str() {
                Some("request") => {
                    // The proposed address is reviewed, never dialed before both owners confirm.
                    let mut proposed = self.config();
                    Self::merge_paired_config(
                        &mut proposed,
                        &frame["identity"],
                        Some(&frame["endpoint"]),
                    )?;
                    let request = json!({"requestId":frame["requestId"],"identity":frame["identity"],
                        "endpoint":frame["endpoint"],"expiresAt":frame["expiresAt"]});
                    let result = self.pairing.lock().unwrap().submit(&request)?;
                    self.log(
                        "pairing_requested",
                        json!({"peerId":id,"requestId":frame["requestId"],"host":frame["endpoint"]["host"],"port":frame["endpoint"]["port"]}),
                    );
                    Ok(result)
                }
                Some("status") | Some("complete") => {
                    let request_id = string(&frame, "requestId")?;
                    let result = self
                        .pairing
                        .lock()
                        .unwrap()
                        .complete(request_id, &frame["identity"])?;
                    if frame["action"] == "complete" {
                        let mut config = self.config();
                        Self::merge_paired_config(
                            &mut config,
                            &frame["identity"],
                            Some(&result["request"]["endpoint"]),
                        )?;
                        self.pairing
                            .lock()
                            .unwrap()
                            .activate(request_id, &frame["identity"])?;
                        self.security.add_paired_identity(&frame["identity"])?;
                        *self.config.write().unwrap() = config;
                        self.log(
                            "pairing_completed",
                            json!({"peerId":id,"requestId":request_id,"host":result["request"]["endpoint"]["host"],"port":result["request"]["endpoint"]["port"]}),
                        );
                    }
                    Ok(result)
                }
                _ => Err(deny("Only request, status and complete are available")),
            }
        })();
        wire::write_frame(
            reader.get_mut(),
            &match result {
                Ok(result) => json!({"ok":true,"result":result}),
                Err(error) => json!({"ok":false,"error":error}),
            },
        )
    }
    fn pairing_rpc(&self, master: &Value, mut frame: Value) -> Result<(Value, Value)> {
        let config = self.config();
        let host = string(master, "host")?;
        let port = master["port"]
            .as_u64()
            .ok_or_else(|| deny("Master port required"))?;
        endpoint_allowed(&config, host, port, false)?;
        let id = string(master, "id")?;
        require_node_uuid(&config, id)?;
        if self.blocked(id) {
            return Err(deny("Peer revoked"));
        }
        let pin = string(master, "fingerprint256")?;
        let stream = self
            .security
            .pairing_connect_pinned(host, port as u16, id, pin)?;
        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| deny("Master certificate required"))?;
        let mut reader = BufReader::new(stream);
        let hello =
            wire::read_frame(&mut reader)?.ok_or_else(|| deny("Master identity required"))?;
        if hello["type"] != "pairing_identity" {
            return Err(deny("Invalid pairing hello"));
        }
        Security::verify_presented_bundle(&cert, &hello["identity"])?;
        require_node_uuid(&config, string(&hello["identity"], "nodeId")?)?;
        frame["v"] = json!(1);
        frame["type"] = json!("pairing");
        frame["identity"] = self.security.public_identity()?;
        wire::write_frame(reader.get_mut(), &frame)?;
        let response = wire::read_frame(&mut reader)?.ok_or_else(|| {
            deny("Pairing response missing; retry confirmation with the same request ID")
        })?;
        if response["ok"] != true {
            return Err(deny(
                response["error"]["message"]
                    .as_str()
                    .unwrap_or("Pairing rejected"),
            ));
        }
        Ok((hello["identity"].clone(), response["result"].clone()))
    }
    // Called under pairing_mutation. Durable registry precedes runtime activation.
    fn install_paired_identity(&self, identity: &Value, endpoint: Option<&Value>) -> Result<()> {
        let id = string(identity, "nodeId")?;
        if self.blocked(id) {
            return Err(deny("Revoked identity cannot rejoin implicitly"));
        }
        let mut config = self.config();
        Self::merge_paired_config(&mut config, identity, endpoint)?;
        self.pairing
            .lock()
            .unwrap()
            .record_peer(identity, endpoint)?;
        self.security.add_paired_identity(identity)?;
        *self.config.write().unwrap() = config;
        Ok(())
    }
    pub(super) fn pairing_command(&self, command: &Value) -> Result<Value> {
        if self.is_stopping() {
            return Err(deny("Node is stopping"));
        }
        let name = string(command, "type").or_else(|_| string(command, "command"))?;
        match name {
            "pairingStatus" => Ok(
                json!({"enabled":self.pairing_port.load(Ordering::Acquire) != 0,
                "host":self.config().raw["pairing"]["host"],"port":self.pairing_port.load(Ordering::Acquire),
                "identity":self.security.public_identity()?}),
            ),
            "listPeers" => {
                Ok(json!({"peers":self.config().raw.get("peers").cloned().unwrap_or(json!([]))}))
            }
            "listPairingRequests" => Ok(self.pairing.lock().unwrap().list()),
            "pairingRequest" => {
                let request_id = uuid::Uuid::new_v4().to_string();
                let config = self.config();
                let endpoint = json!({"host":config.host,"port":self.port()});
                let (_, result) = self.pairing_rpc(
                    &command["master"],
                    json!({"action":"request","requestId":request_id,
                    "endpoint":endpoint,"expiresAt":now()+300_000}),
                )?;
                self.log(
                    "pairing_submitted",
                    json!({"peerId":command["master"]["id"],"requestId":request_id}),
                );
                Ok(
                    json!({"requestId":request_id,"status":result["status"],"master":command["master"],
                    "identity":self.security.public_identity()?,"endpoint":endpoint,"expiresAt":result["request"]["expiresAt"]}),
                )
            }
            "pairingApprove" | "pairingReject" => {
                let _mutation = self.pairing_mutation.lock().unwrap();
                let id = string(command, "requestId")?;
                let mut registry = self.pairing.lock().unwrap();
                if name == "pairingApprove"
                    && let Some(request) =
                        registry.list()["requests"].as_array().and_then(|requests| {
                            requests.iter().find(|request| request["requestId"] == id)
                        })
                {
                    require_node_uuid(&self.config(), string(request, "nodeId")?)?;
                }
                let changed = if name == "pairingReject" {
                    registry.reject(id)?
                } else {
                    registry.approve(id, string(command, "expectedFingerprint")?)?
                };
                let listed = registry.list();
                drop(registry);
                self.log(
                    if name == "pairingReject" {
                        "pairing_rejected"
                    } else {
                        "pairing_approved"
                    },
                    json!({"peerId":changed["request"]["identity"]["nodeId"],"requestId":id}),
                );
                Ok(listed)
            }
            "pairingConfirm" => {
                let _mutation = self.pairing_mutation.lock().unwrap();
                let request_id = string(command, "requestId")?;
                let (identity, approved) = self.pairing_rpc(
                    &command["master"],
                    json!({"action":"status","requestId":request_id}),
                )?;
                if approved["request"]["identity"] != self.security.public_identity()?
                    || approved["request"]["endpoint"]
                        != json!({"host":self.config().host,"port":self.port()})
                {
                    return Err(deny(
                        "Approved request does not match this servant endpoint and identity",
                    ));
                }
                let mut next = self.config();
                Self::merge_paired_config(&mut next, &identity, None)?;
                let master_id = string(&identity, "nodeId")?;
                let policy = if let Some(grant) = command.get("grant") {
                    let control = self.control.lock().unwrap();
                    let mut raw = control["policyRaw"].clone();
                    let epoch = control["policyEpoch"].as_u64().unwrap();
                    drop(control);
                    if raw.get("grants").is_none() {
                        raw["grants"] = json!({});
                    }
                    raw["grants"][master_id] = grant.clone();
                    crate::policy::validate_config_policy(&next, &raw)?;
                    Some((raw, epoch))
                } else {
                    None
                };
                self.install_paired_identity(&identity, None)?;
                if let Some((policy, epoch)) = policy {
                    self.command(
                        &json!({"command":"setPolicy","policy":policy,"expectedEpoch":epoch}),
                    )?;
                }
                self.pairing_rpc(
                    &command["master"],
                    json!({"action":"complete","requestId":request_id}),
                )?;
                self.log(
                    "pairing_confirmed",
                    json!({"peerId":master_id,"requestId":request_id,
                    "toolCount":command["grant"]["tools"].as_array().map_or(0, |t| t.len())}),
                );
                Ok(
                    json!({"paired":true,"peerId":master_id,"requestId":request_id,"restartRequired":false,
                    "grantsAdded":command.get("grant").is_some()}),
                )
            }
            "unpair" => {
                let _mutation = self.pairing_mutation.lock().unwrap();
                let id = string(command, "peerId")?;
                require_node_uuid(&self.config(), id)?;
                self.command(&json!({"command":"revoke","masterId":id}))?;
                self.invalidate_peer(id)?;
                let control = self.control.lock().unwrap();
                let mut policy = control["policyRaw"].clone();
                let epoch = control["policyEpoch"].as_u64().unwrap();
                drop(control);
                if let Some(grants) = policy["grants"].as_object_mut() {
                    grants.remove(id);
                }
                self.command(
                    &json!({"command":"setPolicy","policy":policy,"expectedEpoch":epoch}),
                )?;
                self.pairing.lock().unwrap().remove_peer(id)?;
                self.security.remove_paired_identity(id)?;
                let mut config = self.config.write().unwrap();
                if let Some(peers) = config.raw["peers"].as_array_mut() {
                    peers.retain(|p| p["id"] != id);
                }
                if let Some(pins) = config.raw["security"]["trustedPeers"].as_object_mut() {
                    pins.remove(id);
                }
                drop(config);
                self.log("peer_unpaired", json!({"peerId":id}));
                Ok(json!({"peerId":id,"removed":true,"restartRequired":false}))
            }
            _ => Err(deny("Unknown pairing command")),
        }
    }
}
