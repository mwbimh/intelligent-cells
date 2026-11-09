use super::*;
use std::{os::unix::fs::MetadataExt, path::Path};

impl Node {
    pub(super) fn session_grant(
        &self,
        master: &str,
        task: &Value,
        mut grant: Grant,
    ) -> Result<Grant> {
        if task["sessionTemporary"] != true {
            return Ok(grant);
        }
        if task.get("workspaceId").is_some() || task.get("logicalWorkspaceId").is_some() {
            return Err(IcError::new(
                "INVALID_TASK",
                "Temporary sessions cannot select a workspace",
            ));
        }
        if self.config().raw["sessions"]["allowTemporary"] == false {
            return Err(IcError::new(
                "TEMPORARY_WORKSPACE_DISABLED",
                "This node requires a directory binding",
            ));
        }
        let id = string(task, "sessionId")?;
        uuid::Uuid::parse_str(id)
            .map_err(|_| IcError::new("INVALID_SESSION", "Session ID must be a UUID"))?;
        if !crate::policy::valid_id(master) {
            return Err(IcError::new("INVALID_SESSION", "Invalid master identity"));
        }
        let root = self
            .config()
            .state_dir
            .join("session-workspaces")
            .join(master)
            .join(id);
        crate::durable::ensure_private_dir(&root)?;
        let metadata = std::fs::metadata(&root)?;
        grant.raw["root"] = json!(root);
        grant.raw["workspace"] = json!(root);
        grant.raw["workspaceIdentity"] =
            json!({"dev":metadata.dev().to_string(),"ino":metadata.ino().to_string()});
        grant.root = root;
        grant.workspace_id = format!("session_{id}");
        Ok(grant)
    }
    pub(super) fn session_task(&self, session: &Value, peer: &str, task: &Value) -> Result<Value> {
        if peer == self.config().id {
            return Err(IcError::new(
                "LOCAL_BUILTIN_DENIED",
                "Built-in tools are only available to other nodes",
            ));
        }
        let mut task = task.clone();
        let object = task
            .as_object_mut()
            .ok_or_else(|| IcError::new("INVALID_TASK", "Task must be an object"))?;
        if object.contains_key("workspaceId")
            || object.contains_key("logicalWorkspaceId")
            || object.contains_key("sessionTemporary")
        {
            return Err(IcError::new(
                "INVALID_TASK",
                "Session workspace is selected by directory bindings",
            ));
        }
        task["sessionId"] = session["sessionId"].clone();
        task["runId"] = session["sessionId"].clone();
        if let Some(cwd) = session["cwd"].as_str() {
            self.sessions
                .local_directory(string(session, "sessionId")?, false)?;
            let roots = self
                .workspaces
                .command(&json!({"command":"listLocalWorkspaces"}))?;
            let root = roots["roots"]
                .as_array()
                .and_then(|r| r.iter().find(|r| r["path"] == cwd))
                .ok_or_else(|| {
                    IcError::new(
                        "WORKSPACE_BINDING_NOT_FOUND",
                        "Session directory has no node directory binding",
                    )
                })?;
            let logical = string(root, "logicalWorkspaceId")?;
            if self.workspaces.local_root(logical)? != Path::new(cwd) {
                return Err(IcError::new(
                    "WORKSPACE_CHANGED",
                    "Session directory binding changed",
                ));
            }
            let workspace = self.workspaces.binding(peer, logical)?.ok_or_else(|| {
                IcError::new(
                    "WORKSPACE_BINDING_NOT_FOUND",
                    "Session directory is not bound to this node",
                )
            })?;
            self.sessions
                .bind_target(string(session, "sessionId")?, peer, &workspace)?;
            if session["localSync"] == true {
                task["logicalWorkspaceId"] = json!(logical);
            } else {
                task["workspaceId"] = json!(workspace);
            }
        } else {
            task["sessionTemporary"] = json!(true);
        }
        Ok(task)
    }
    pub(super) fn session_dispatch(&self, id: &str, peer: &str, task: &Value) -> Result<Value> {
        let session = self.sessions.get(id)?;
        let task = self.session_task(&session, peer, task)?;
        self.sessions.record_start(id, peer, &task)?;
        let result = self.dispatch(peer, &task);
        self.sessions
            .record_finish(id, string(&task, "taskId")?, &result)?;
        result
    }
    fn session_tools(&self, local_sync: bool) -> Result<Vec<Value>> {
        let mut tools = crate::harness::remote_tools(local_sync);
        for tool in &mut tools {
            tool["_meta"] = json!({"origin":"ic","execution":"remote"});
        }
        tools.extend(self.mcp.tools(None)?);
        Ok(tools)
    }
    pub(super) fn session_peer(&self, session: &Value, args: &Value) -> Result<String> {
        let peer = args["peerId"]
            .as_str()
            .or_else(|| session["defaultPeerId"].as_str())
            .ok_or_else(|| {
                IcError::new(
                    "PEER_REQUIRED",
                    "Select a target with ic_peer or provide peerId",
                )
            })?;
        let config = self.config();
        if peer == config.id {
            return Err(IcError::new(
                "LOCAL_BUILTIN_DENIED",
                "Built-in tools are only available to other nodes",
            ));
        }
        if !config.raw["peers"]
            .as_array()
            .is_some_and(|peers| peers.iter().any(|item| item["id"] == peer))
        {
            return Err(IcError::new(
                "UNKNOWN_PEER",
                "Target is not an approved outgoing node",
            ));
        }
        if self.blocked(peer) {
            return Err(IcError::new("PEER_DENIED", "Target node is revoked"));
        }
        Ok(peer.to_string())
    }
    fn session_call(&self, id: &str, name: &str, args: &Value) -> Result<Value> {
        let session = self.sessions.get(id)?;
        let tools = self.session_tools(session["localSync"] == true)?;
        let schema = tools
            .iter()
            .find(|t| t["name"] == name)
            .ok_or_else(|| IcError::new("TOOL_DENIED", "Tool is unknown or disabled"))?;
        crate::harness::validate_arguments(&schema["inputSchema"], args)?;
        if name == "ic_peer" {
            let peer = self.session_peer(&session, args)?;
            self.session_task(&session, &peer, &json!({"tool":"capabilities","args":{}}))?;
            let selected = self.sessions.set_default_peer(id, &peer)?;
            return Ok(
                json!({"content":[{"type":"text","text":selected.to_string()}],"isError":false}),
            );
        }
        if name == "ic_peers" {
            let mut nodes = self.nodes_command(&json!({"command":"nodesList"}))?;
            nodes["sessionId"] = json!(id);
            nodes["defaultPeerId"] = session["defaultPeerId"].clone();
            return Ok(
                json!({"content":[{"type":"text","text":nodes.to_string()}],"isError":false}),
            );
        }
        if matches!(name, "ic_sync" | "ic_workspace") {
            let result = self.session_sync_call(&session, name, args)?;
            return Ok(
                json!({"content":[{"type":"text","text":result.to_string()}],"isError":false}),
            );
        }
        let process_tool = if name == "ic_process" {
            let action = string(args, "action")?;
            let tool = match action {
                "status" => "jobStatus",
                "output" => "jobOutput",
                "cancel" => "jobCancel",
                _ => {
                    return Err(IcError::new(
                        "INVALID_ARGS",
                        "Process action must be status, output or cancel",
                    ));
                }
            };
            let allowed: &[&str] = if action == "output" {
                &[
                    "action",
                    "jobId",
                    "peerId",
                    "timeoutMs",
                    "offset",
                    "limit",
                    "stream",
                ]
            } else {
                &["action", "jobId", "peerId", "timeoutMs"]
            };
            if args
                .as_object()
                .unwrap()
                .keys()
                .any(|field| !allowed.contains(&field.as_str()))
            {
                return Err(IcError::new(
                    "INVALID_ARGS",
                    "Unexpected argument for this process action",
                ));
            }
            Some(tool)
        } else {
            None
        };
        let tool = process_tool.or_else(|| {
            crate::harness::DEFINITIONS
                .iter()
                .find(|definition| definition.0 == name)
                .map(|definition| definition.1)
        });
        if let Some(tool) = tool {
            let peer = self.session_peer(&session, args)?;
            let mut arguments = args.clone();
            arguments.as_object_mut().unwrap().remove("peerId");
            arguments.as_object_mut().unwrap().remove("timeoutMs");
            arguments.as_object_mut().unwrap().remove("action");
            let task = json!({"taskId":uuid::Uuid::new_v4().to_string(),"tool":tool,"args":arguments,"timeoutMs":args["timeoutMs"].as_u64().unwrap_or(10000)});
            let result = self.session_dispatch(id, &peer, &task)?;
            if result["status"] == "error" {
                return Err(IcError::new(
                    result["error"]["code"].as_str().unwrap_or("REMOTE_ERROR"),
                    result["error"]["message"]
                        .as_str()
                        .unwrap_or("Remote request failed"),
                ));
            }
            return Ok(
                json!({"content":[{"type":"text","text":result["result"].to_string()}],"isError":false}),
            );
        }
        let cwd = self
            .sessions
            .local_directory(id, self.config().raw["sessions"]["allowTemporary"] != false)?;
        self.local_mcp_call(id, name, args, &cwd)
    }
    pub(super) fn session_command(&self, c: &Value) -> Result<Value> {
        match string(c, "command").or_else(|_| string(c, "type"))? {
            "sessionOpen" => {
                if c.get("localSync").is_some_and(|v| !v.is_boolean()) {
                    return Err(IcError::new(
                        "INVALID_SESSION",
                        "localSync must be a boolean",
                    ));
                }
                if let Some(id) = c["sessionId"].as_str() {
                    let session = self.sessions.get(id)?;
                    if c.get("localSync")
                        .is_some_and(|mode| mode != &session["localSync"])
                    {
                        return Err(IcError::new(
                            "SESSION_MODE_CONFLICT",
                            "Resumed session has a different local-sync mode",
                        ));
                    }
                    if let Some(cwd) = c["cwd"].as_str()
                        && session["cwd"] != json!(std::fs::canonicalize(cwd)?)
                    {
                        return Err(IcError::new(
                            "SESSION_CWD_CONFLICT",
                            "Resumed session has a different directory",
                        ));
                    }
                    Ok(session)
                } else {
                    self.sessions.create_with_options(
                        c["cwd"].as_str().map(Path::new),
                        c["localSync"] == true,
                    )
                }
            }
            "sessionReconcile" => self.local_mcp_reconcile(c),
            "sessionDetach" => self.sessions.get(string(c, "sessionId")?),
            "listSessions" => {
                let outgoing = self.outgoing.lock().unwrap().values();
                self.sessions.reconcile_remote_records(&outgoing)?;
                self.sessions.list()
            }
            "sessionDispatch" => {
                self.session_dispatch(string(c, "sessionId")?, string(c, "peerId")?, &c["task"])
            }
            "mcpListTools" => {
                let local_sync = c["sessionId"]
                    .as_str()
                    .map(|id| self.sessions.get(id))
                    .transpose()?
                    .is_some_and(|session| session["localSync"] == true);
                Ok(json!({"tools":self.session_tools(local_sync)?}))
            }
            "mcpCallTool" => {
                self.session_call(string(c, "sessionId")?, string(c, "name")?, &c["arguments"])
            }
            "sessionMcp" => {
                let id = string(c, "sessionId")?;
                let session = self.sessions.get(id)?;
                let request = &c["request"];
                if request.get("id").is_none() {
                    return Ok(Value::Null);
                }
                let response = match request["method"].as_str() {
                    Some("initialize") => {
                        json!({"protocolVersion":request["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"intelligent-cells","version":env!("CARGO_PKG_VERSION")}})
                    }
                    Some("ping") => json!({}),
                    Some("tools/list") => {
                        json!({"tools":self.session_tools(session["localSync"] == true)?})
                    }
                    Some("tools/call") => {
                        let result = self.session_call(
                            id,
                            request["params"]["name"].as_str().unwrap_or(""),
                            &request["params"]
                                .get("arguments")
                                .cloned()
                                .unwrap_or_else(|| json!({})),
                        );
                        match result {
                            Ok(v) if v.get("content").is_some() => v,
                            Ok(v) => {
                                json!({"content":[{"type":"text","text":v.to_string()}],"isError":false})
                            }
                            Err(e) => {
                                json!({"content":[{"type":"text","text":e.to_string()}],"isError":true})
                            }
                        }
                    }
                    _ => {
                        return Ok(
                            json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32601,"message":"Method not found"}}),
                        );
                    }
                };
                Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":response}))
            }
            _ => Err(IcError::new("INVALID_COMMAND", "Unknown session command")),
        }
    }
}

impl Node {
    pub(super) fn nodes_command(&self, c: &Value) -> Result<Value> {
        let config = self.config();
        let directory = crate::node_store::directory(&config);
        match string(c, "command").or_else(|_| string(c, "type"))? {
            "nodesList" | "nodesStatus" => {
                let names = crate::node_store::read_section(&directory, "displayNames")?
                    .unwrap_or_else(|| json!({}));
                let paired = self.pairing.lock().unwrap().peers();
                let connected = self.incoming_sockets.authenticated_peers();
                let mut masters = self.policy.read().unwrap()["grants"]
                    .as_object()
                    .map(|grants| grants.keys().cloned().collect::<BTreeSet<_>>())
                    .unwrap_or_default();
                masters.extend(connected.iter().cloned());
                for peer in paired {
                    if peer["endpoint"].is_null() {
                        masters.insert(string(&peer["identity"], "nodeId")?.to_string());
                    }
                }
                let outgoing = config.raw["peers"].as_array().cloned().unwrap_or_default();
                let mut nodes = thread::scope(|scope| {
                    let probes = outgoing.iter().map(|peer| {
                        let names = &names;
                        let masters = &masters;
                        let connected = &connected;
                        scope.spawn(move || -> Result<Value> {
                            let id = string(peer, "id")?;
                            let started = Instant::now();
                            let ping = self.request(id, &json!({"v":2,"type":"ping","task":{"timeoutMs":1000}}));
                            let reachable = ping.as_ref().is_ok_and(|v| v["type"] == "pong");
                            let incoming = connected.iter().any(|p| p == id);
                            let both = masters.contains(id);
                            Ok(json!({"id":id,"name":names[id],"relationship":if both {"bidirectional"} else {"servant"},"relationships":if both {json!(["master","servant"])}else{json!(["servant"])},"host":peer["host"],"port":peer["port"],"online":reachable || incoming,"status":if reachable || incoming {"online"}else{"offline"},"incomingConnected":incoming,"outgoingReachable":reachable,"checkedAt":now(),"latencyMs":if reachable {json!(started.elapsed().as_millis() as u64)}else{Value::Null},"error":ping.err().map(|e|e.code)}))
                        })
                    }).collect::<Vec<_>>();
                    probes
                        .into_iter()
                        .map(|probe| {
                            probe.join().map_err(|_| {
                                IcError::new("STATUS_FAILED", "Node health probe failed")
                            })?
                        })
                        .collect::<Result<Vec<Value>>>()
                })?;
                for id in masters {
                    if nodes.iter().any(|n| n["id"] == id) {
                        continue;
                    }
                    let incoming = connected.contains(&id);
                    nodes.push(json!({"id":id,"name":names[&id],"relationship":"master","relationships":["master"],"online":if incoming {json!(true)}else{Value::Null},"incomingConnected":incoming,"status":if incoming {"online"}else{"unknown"},"reason":if incoming {Value::Null}else{json!("No live connection or outgoing endpoint")}}));
                }
                let selected = c["peerId"].as_str();
                if let Some(id) = selected {
                    nodes.retain(|n| n["id"] == id);
                }
                Ok(
                    json!({"self":{"id":config.id,"name":crate::node_store::read_section(&directory,"self")?.unwrap_or(Value::Null)["name"],"online":true},"nodes":nodes,"bindings":self.workspaces.command(&json!({"command":"listWorkspaceBindings"}))?}),
                )
            }
            "nodesRename" => {
                let id = c["peerId"].as_str().unwrap_or(&config.id);
                let name = string(c, "name")?;
                if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                    return Err(IcError::new(
                        "INVALID_NODE_NAME",
                        "Display name must contain 1..128 printable bytes",
                    ));
                }
                if id == config.id {
                    let identity = crate::node_store::rename_self(&directory, name)?;
                    self.config.write().unwrap().raw["name"] = json!(name);
                    return Ok(identity);
                }
                if !self
                    .pairing
                    .lock()
                    .unwrap()
                    .peers()
                    .iter()
                    .any(|p| p["identity"]["nodeId"] == id)
                    && !config.raw["peers"]
                        .as_array()
                        .is_some_and(|p| p.iter().any(|p| p["id"] == id))
                {
                    return Err(IcError::new("UNKNOWN_PEER", "Unknown node identity"));
                }
                let _guard = self.ensures.lock().unwrap();
                let mut names = crate::node_store::read_section(&directory, "displayNames")?
                    .unwrap_or_else(|| json!({}));
                names[id] = json!(name);
                crate::node_store::write_section(&directory, "displayNames", &names)?;
                Ok(json!({"id":id,"name":name}))
            }
            "nodesBind" | "nodesUnbind" => {
                let peer = string(c, "peerId")?;
                let path = std::fs::canonicalize(string(c, "localPath")?)?;
                let local = self
                    .workspaces
                    .command(&json!({"command":"listLocalWorkspaces"}))?;
                let existing = local["roots"]
                    .as_array()
                    .and_then(|roots| roots.iter().find(|r| r["path"] == json!(path)));
                let logical = existing
                    .and_then(|r| r["logicalWorkspaceId"].as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                if c["command"] == "nodesUnbind" || c["type"] == "nodesUnbind" {
                    return self.workspaces.command(&json!({"command":"unbindWorkspace","peerId":peer,"logicalWorkspaceId":logical}));
                }
                let workspace = string(c, "workspaceId")?;
                let catalog = self.remote_catalog(peer)?;
                if !catalog["workspaces"].as_array().is_some_and(|a| {
                    a.iter()
                        .any(|w| w["id"] == workspace && w["state"] == "ready")
                }) {
                    return Err(IcError::new(
                        "WORKSPACE_DENIED",
                        "Target workspace is not approved",
                    ));
                }
                if existing.is_none() {
                    self.workspaces.command(&json!({"command":"bindLocalWorkspace","logicalWorkspaceId":logical,"path":path,"expectedRevision":local["revision"]}))?;
                }
                self.workspaces.command(&json!({"command":"bindWorkspace","peerId":peer,"logicalWorkspaceId":logical,"workspaceId":workspace}))
            }
            _ => Err(IcError::new("INVALID_COMMAND", "Unknown nodes command")),
        }
    }
}
