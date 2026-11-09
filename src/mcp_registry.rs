//! Owner-managed MCP aggregation and per-caller visibility.
use crate::{
    IcError, Result,
    resources::{MCP_PROTOCOL_VERSION, StdioClient},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

pub struct McpRegistry {
    path: PathBuf,
    state: Mutex<Value>,
}
fn invalid(message: &str) -> IcError {
    IcError::new("INVALID_MCP_CONFIG", message)
}
fn denied() -> IcError {
    IcError::new(
        "MCP_TOOL_DENIED",
        "Tool is disabled or not visible to this caller",
    )
}
fn masters_valid(v: &Value) -> bool {
    v == "all"
        || v.as_array().is_some_and(|a| {
            a.len() <= 256
                && a.iter()
                    .all(|v| v.as_str().is_some_and(crate::policy::valid_id))
        })
}
fn master_allowed(v: &Value, master: &str) -> bool {
    v == "all" || v.as_array().is_some_and(|a| a.iter().any(|v| v == master))
}
fn visibility(value: Option<&Value>) -> Result<Value> {
    let value = value.cloned().unwrap_or(json!({"local":true,"masters":[]}));
    if !value.is_object()
        || !value["local"].is_boolean()
        || !masters_valid(&value["masters"])
        || value
            .as_object()
            .unwrap()
            .keys()
            .any(|k| k != "local" && k != "masters")
    {
        return Err(invalid(
            "Visibility requires local boolean and masters array or 'all'",
        ));
    }
    Ok(value)
}
fn visible(entry: &Value, caller: Option<&str>) -> bool {
    entry["enabled"] == true
        && entry["visibility"]["local"] == true
        && caller.is_none_or(|id| master_allowed(&entry["visibility"]["masters"], id))
}
fn public_name(server: &Value, tool: &str) -> String {
    format!(
        "mcp__{}__{tool}",
        server["id"].as_str().unwrap().replace('-', "")
    )
}
fn tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn check_deadline(until: Instant) -> Result<()> {
    if Instant::now() >= until {
        Err(IcError::new("MCP_TIMEOUT", "MCP request deadline exceeded"))
    } else {
        Ok(())
    }
}
fn connect(server: &Value, cwd: &Path, check: &dyn Fn() -> Result<()>) -> Result<StdioClient> {
    let mut client = StdioClient::open(server, cwd)?;
    let init = client.request("initialize", json!({"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"intelligent-cells","version":env!("CARGO_PKG_VERSION")}}), check)?;
    if init["protocolVersion"] != MCP_PROTOCOL_VERSION
        || !init["capabilities"]["tools"].is_object()
        || !init["serverInfo"].is_object()
    {
        return Err(IcError::new(
            "MCP_NEGOTIATION_FAILED",
            "Upstream must support the tools protocol",
        ));
    }
    client.send(
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        check,
    )?;
    Ok(client)
}
fn catalog(client: &mut StdioClient, check: &dyn Fn() -> Result<()>) -> Result<Vec<Value>> {
    let mut cursor: Option<String> = None;
    let mut cursors = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut tools = Vec::new();
    loop {
        let params = cursor.as_ref().map_or(json!({}), |c| json!({"cursor":c}));
        let result = client.request("tools/list", params, check)?;
        let page = result["tools"]
            .as_array()
            .ok_or_else(|| invalid("Upstream returned an invalid tools catalog"))?;
        for tool in page {
            let name = tool["name"]
                .as_str()
                .filter(|n| tool_name(n))
                .ok_or_else(|| invalid("Upstream tool name is invalid"))?;
            if !names.insert(name.to_string()) || tools.len() >= 128 {
                return Err(invalid("Upstream catalog is duplicated or too large"));
            }
            tools.push(tool.clone());
        }
        match result.get("nextCursor") {
            None | Some(Value::Null) => return Ok(tools),
            Some(Value::String(next))
                if !next.is_empty()
                    && next.len() <= 1024
                    && cursors.len() < 16
                    && cursors.insert(next.clone()) =>
            {
                cursor = Some(next.clone())
            }
            _ => return Err(invalid("Upstream catalog cursor is invalid")),
        }
    }
}
fn prepare(mut server: Value, id: &str, approve_code: bool) -> Result<Value> {
    if !server.is_object()
        || server.as_object().unwrap().keys().any(|k| {
            ![
                "id",
                "name",
                "file",
                "args",
                "launchMode",
                "cwd",
                "tools",
                "enabled",
                "visibility",
                "maxOutputBytes",
                "codeFiles",
                "codeSnapshots",
            ]
            .contains(&k.as_str())
        })
    {
        return Err(invalid("Unknown MCP server setting"));
    }
    let name = server["name"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
        .ok_or_else(|| invalid("MCP display name is required"))?
        .to_string();
    let cwd = server["cwd"]
        .as_str()
        .ok_or_else(|| invalid("MCP discovery cwd is required"))?;
    let cwd = PathBuf::from(cwd);
    if !cwd.is_absolute() || std::fs::canonicalize(&cwd)? != cwd {
        return Err(invalid("MCP cwd must be canonical and absolute"));
    }
    crate::files::inspect_root(&cwd)?;
    if server.get("enabled").is_some_and(|v| !v.is_boolean()) {
        return Err(invalid("enabled must be a boolean"));
    }
    server["enabled"] = server.get("enabled").cloned().unwrap_or(json!(true));
    server["visibility"] = visibility(server.get("visibility"))?;
    let max = server
        .get("maxOutputBytes")
        .and_then(Value::as_u64)
        .unwrap_or(65536);
    if !(256..=1048576).contains(&max) {
        return Err(invalid("maxOutputBytes must be 256..1048576"));
    }
    server["maxOutputBytes"] = json!(max);
    server["id"] = json!(id);
    server["name"] = json!(name);
    let discovered = if approve_code {
        server = crate::policy::compile_approved_code(&server, "UNSAFE_MCP_POLICY")?;
        let until = Instant::now() + Duration::from_secs(10);
        let check = || check_deadline(until);
        Some(catalog(&mut connect(&server, &cwd, &check)?, &check)?)
    } else {
        None
    };
    let mut bindings = if let Some(tools) = server.get("tools") {
        tools
            .as_object()
            .cloned()
            .ok_or_else(|| invalid("tools must be an object"))?
    } else {
        discovered.as_ref().ok_or_else(|| invalid("Tools are required for metadata update"))?.iter().map(|t| (t["name"].as_str().unwrap().to_string(), json!({"inputSchema":t["inputSchema"],"description":t.get("description").cloned().unwrap_or(json!(t["name"])),"readOnly":false}))).collect()
    };
    if bindings.len() > 128 {
        return Err(invalid("Too many approved MCP tools"));
    }
    for (name, binding) in &mut bindings {
        if !tool_name(name)
            || !binding.is_object()
            || discovered
                .as_ref()
                .is_some_and(|tools| !tools.iter().any(|t| t["name"] == *name))
        {
            return Err(invalid("Approved tool is absent from upstream catalog"));
        }
        if binding.as_object().unwrap().keys().any(|k| {
            ![
                "inputSchema",
                "readOnly",
                "description",
                "enabled",
                "visibility",
            ]
            .contains(&k.as_str())
        }) {
            return Err(invalid("Unknown tool setting"));
        }
        crate::resources::validate_schema(&binding["inputSchema"], 0)?;
        if binding["inputSchema"]["type"] != "object"
            || binding.get("readOnly").is_some_and(|v| !v.is_boolean())
            || binding.get("enabled").is_some_and(|v| !v.is_boolean())
        {
            return Err(invalid("Invalid MCP tool schema or flags"));
        }
        binding["readOnly"] = binding.get("readOnly").cloned().unwrap_or(json!(false));
        binding["enabled"] = binding.get("enabled").cloned().unwrap_or(json!(true));
        binding["visibility"] = match binding.get("visibility") {
            Some(v) => visibility(Some(v))?,
            None => json!({"local":true,"masters":"all"}),
        };
        if binding
            .get("description")
            .is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 4096))
        {
            return Err(invalid("Invalid tool description"));
        }
    }
    server["tools"] = Value::Object(bindings);
    Ok(server)
}
fn merge(target: &mut Value, patch: &Value) {
    if let (Some(target), Some(patch)) = (target.as_object_mut(), patch.as_object()) {
        for (key, value) in patch {
            if value.is_object() && target.get(key).is_some_and(Value::is_object) {
                merge(target.get_mut(key).unwrap(), value);
            } else {
                target.insert(key.clone(), value.clone());
            }
        }
    }
}
impl McpRegistry {
    pub fn open(path: &Path) -> Result<Self> {
        let state = if path.exists() {
            crate::durable::read_checked(path)?
        } else {
            let empty = json!({"version":1,"servers":{},"builtins":{}});
            crate::durable::write_checked(path, &empty)?;
            empty
        };
        if state["version"] != 1 || !state["servers"].is_object() || !state["builtins"].is_object()
        {
            return Err(invalid("Invalid MCP registry file"));
        }
        for (id, server) in state["servers"].as_object().unwrap() {
            if uuid::Uuid::parse_str(id).is_err()
                || server["id"] != *id
                || !server["tools"].is_object()
            {
                return Err(invalid("Invalid persisted MCP server"));
            }
        }
        Ok(Self {
            path: path.into(),
            state: Mutex::new(state),
        })
    }
    pub fn command(&self, command: &Value) -> Result<Value> {
        let mut state = self.state.lock().unwrap();
        let mut next = state.clone();
        let result = match command["command"].as_str() {
            Some("list") => {
                let builtins = crate::tools::names()
                    .iter()
                    .map(|name| {
                        let mut entry = state["builtins"]
                            .get(*name)
                            .cloned()
                            .unwrap_or(json!({"enabled":true,"masters":"all"}));
                        entry["origin"] = json!("ic");
                        entry["local"] = json!(false);
                        (name.to_string(), entry)
                    })
                    .collect::<serde_json::Map<_, _>>();
                let servers = state["servers"]
                    .as_object()
                    .unwrap()
                    .values()
                    .map(|server| {
                        let mut entry = server.clone();
                        entry["origin"] = json!("aggregated");
                        entry
                    })
                    .collect::<Vec<_>>();
                return Ok(json!({"servers":servers,"builtins":builtins}));
            }
            Some("add") => {
                let id = uuid::Uuid::new_v4().to_string();
                let server = prepare(command["server"].clone(), &id, true)?;
                next["servers"][&id] = server.clone();
                json!({"server":server})
            }
            Some("update") => {
                let id = command["id"]
                    .as_str()
                    .ok_or_else(|| invalid("Server id is required"))?;
                let mut server = state["servers"]
                    .get(id)
                    .cloned()
                    .ok_or_else(|| invalid("Unknown MCP server id"))?;
                let patch = &command["patch"];
                if !patch.is_object()
                    || patch.get("id").is_some()
                    || patch.get("codeSnapshots").is_some()
                    || patch.get("codeFiles").is_some()
                {
                    return Err(invalid("Invalid server patch"));
                }
                let code_change = ["file", "args", "launchMode"]
                    .iter()
                    .any(|key| patch.get(key).is_some());
                merge(&mut server, patch);
                let server = prepare(server, id, code_change)?;
                next["servers"][id] = server.clone();
                json!({"server":server})
            }
            Some("remove") => {
                let id = command["id"]
                    .as_str()
                    .ok_or_else(|| invalid("Server id is required"))?;
                if next["servers"]
                    .as_object_mut()
                    .unwrap()
                    .remove(id)
                    .is_none()
                {
                    return Err(invalid("Unknown MCP server id"));
                }
                json!({"removed":id})
            }
            Some("updateBuiltin") => {
                let name = command["tool"]
                    .as_str()
                    .filter(|t| crate::tools::names().contains(t))
                    .ok_or_else(|| invalid("Unknown IC built-in tool"))?;
                if command.get("local").is_some() || command.get("visibility").is_some() {
                    return Err(invalid("IC built-in tools are never visible locally"));
                }
                let mut entry = next["builtins"]
                    .get(name)
                    .cloned()
                    .unwrap_or(json!({"enabled":true,"masters":"all"}));
                if let Some(enabled) = command.get("enabled") {
                    if !enabled.is_boolean() {
                        return Err(invalid("enabled must be a boolean"));
                    }
                    entry["enabled"] = enabled.clone();
                }
                if let Some(masters) = command.get("masters") {
                    if !masters_valid(masters) {
                        return Err(invalid("Invalid masters selector"));
                    }
                    entry["masters"] = masters.clone();
                }
                next["builtins"][name] = entry.clone();
                json!({"tool":name,"origin":"ic","local":false,"settings":entry})
            }
            _ => return Err(invalid("Unknown MCP management command")),
        };
        crate::durable::write_checked(&self.path, &next)?;
        *state = next;
        Ok(result)
    }
    /// Rebuild MCP grants from the separate registry; never grant a built-in capability.
    pub fn augment_grant(&self, grant: &mut crate::Grant) -> Result<()> {
        let state = self.state.lock().unwrap();
        grant.tools.retain(|tool| {
            state["builtins"].get(tool).is_none_or(|b| {
                b["enabled"] == true && master_allowed(&b["masters"], &grant.master_id)
            })
        });
        let mut servers = serde_json::Map::new();
        for (id, server) in state["servers"].as_object().unwrap() {
            if !visible(server, Some(&grant.master_id)) {
                continue;
            }
            let mut approved = server.clone();
            let bindings = server["tools"]
                .as_object()
                .unwrap()
                .iter()
                .filter(|(_, binding)| visible(binding, Some(&grant.master_id)))
                .map(|(name, binding)| {
                    let mut binding = binding.clone();
                    binding["name"] = json!(name);
                    if binding.get("description").is_none() {
                        binding["description"] = json!(name);
                    }
                    (name.clone(), binding)
                })
                .collect::<serde_json::Map<_, _>>();
            if bindings.is_empty() {
                continue;
            }
            approved["alias"] = json!(id);
            approved["tools"] = Value::Object(bindings);
            approved["maxOutputBytes"] = json!(
                approved["maxOutputBytes"]
                    .as_u64()
                    .unwrap_or(65536)
                    .min(grant.limit("maxMcpBytes", 32768))
            );
            servers.insert(id.clone(), approved);
        }
        grant.raw["mcpServers"] = Value::Object(servers);
        Ok(())
    }
    pub fn builtin_allowed(&self, caller: Option<&str>, tool: &str) -> bool {
        let Some(master) = caller else {
            return false;
        };
        if !crate::tools::names().contains(&tool) {
            return false;
        }
        let state = self.state.lock().unwrap();
        state["builtins"]
            .get(tool)
            .is_none_or(|b| b["enabled"] == true && master_allowed(&b["masters"], master))
    }
    pub fn tools(&self, caller: Option<&str>) -> Result<Vec<Value>> {
        let state = self.state.lock().unwrap();
        let mut out = Vec::new();
        let until = Instant::now() + Duration::from_secs(10);
        for server in state["servers"]
            .as_object()
            .unwrap()
            .values()
            .filter(|s| visible(s, caller))
        {
            let check = || check_deadline(until);
            let cwd = Path::new(
                server["cwd"]
                    .as_str()
                    .ok_or_else(|| invalid("Missing MCP cwd"))?,
            );
            let available = catalog(&mut connect(server, cwd, &check)?, &check)?;
            for (name, binding) in server["tools"].as_object().unwrap() {
                if !visible(binding, caller) || !available.iter().any(|t| t["name"] == *name) {
                    continue;
                }
                out.push(json!({"name":public_name(server,name),"description":binding.get("description").cloned().unwrap_or(json!(name)),"inputSchema":binding["inputSchema"],"annotations":{"readOnlyHint":binding["readOnly"]},"_meta":{"origin":"aggregated","serverId":server["id"],"serverName":server["name"],"upstreamTool":name}}));
            }
        }
        Ok(out)
    }
    pub fn call(
        &self,
        caller: Option<&str>,
        name: &str,
        args: &Value,
        cwd: &Path,
    ) -> Result<Value> {
        let state = self.state.lock().unwrap();
        let found = state["servers"]
            .as_object()
            .unwrap()
            .values()
            .find_map(|server| {
                server["tools"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .find(|(tool, _)| public_name(server, tool) == name)
                    .map(|(tool, binding)| (server, tool, binding))
            });
        let (server, tool, binding) = found.ok_or_else(denied)?;
        if !visible(server, caller) || !visible(binding, caller) {
            return Err(denied());
        }
        if !crate::resources::matches_schema(args, &binding["inputSchema"]) {
            return Err(IcError::new(
                "INVALID_ARGS",
                "Arguments violate approved MCP schema",
            ));
        }
        let until = Instant::now() + Duration::from_secs(60);
        let check = || check_deadline(until);
        let mut client = connect(server, cwd, &check)?;
        if !catalog(&mut client, &check)?
            .iter()
            .any(|t| t["name"] == *tool)
        {
            return Err(IcError::new(
                "MCP_TOOL_UNAVAILABLE",
                "Approved upstream tool is unavailable",
            ));
        }
        let result = client
            .request("tools/call", json!({"name":tool,"arguments":args}), &check)
            .and_then(|v| {
                if !v.is_object()
                    || v["content"].as_array().is_none_or(|a| {
                        a.len() > 64 || a.iter().any(|b| !b.is_object() || !b["type"].is_string())
                    })
                    || v.get("isError").is_some_and(|v| !v.is_boolean())
                {
                    Err(IcError::new(
                        "MCP_PROTOCOL_ERROR",
                        "Invalid MCP tool result",
                    ))
                } else {
                    Ok(v)
                }
            });
        match result {
            Err(e)
                if client.call_sent && binding["readOnly"] != true && e.code != "MCP_RPC_ERROR" =>
            {
                Err(
                    IcError::new("OUTCOME_UNKNOWN", "MCP call sent without confirmed outcome")
                        .unknown(),
                )
            }
            other => other,
        }
    }
}
