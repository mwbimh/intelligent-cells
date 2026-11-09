use crate::{Grant, IcError, Result, context::ToolContext};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

pub fn names() -> &'static [&'static str] {
    &[
        "syncInventory",
        "syncUpload",
        "syncTransfer",
        "syncApply",
        "syncExec",
        "workspaceList",
        "workspaceCreate",
        "echo",
        "wait",
        "capabilities",
        "readFile",
        "writeFile",
        "editFile",
        "listDirectory",
        "searchFiles",
        "mkdir",
        "readChunk",
        "writeChunk",
        "exec",
        "jobStatus",
        "jobOutput",
        "jobCancel",
        "jobStdin",
        "resourceList",
        "resourceRead",
        "mcpList",
        "mcpCall",
    ]
}
pub fn side_effect(task: &Value, grant: Option<&Grant>) -> bool {
    match task["tool"].as_str().unwrap_or("") {
        "echo" | "wait" | "capabilities" | "readFile" | "readChunk" | "listDirectory"
        | "searchFiles" | "jobStatus" | "jobOutput" | "jobCancel" | "resourceList"
        | "resourceRead" | "mcpList" | "workspaceList" | "syncInventory" => false,
        "mcpCall" => crate::resources::side_effect(task, grant),
        _ => true,
    }
}
fn fields(tool: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match tool {
        "echo" => (&["text"], &["text"]),
        "wait" => (&["ms"], &["ms"]),
        "capabilities" | "resourceList" => (&[], &[]),
        "workspaceList" => (&["offset", "limit"], &[]),
        "workspaceCreate" => (
            &["rootId", "name", "requestId"],
            &["rootId", "name", "requestId"],
        ),
        "readFile" | "readChunk" => (&["path", "offset", "length"], &["path"]),
        "writeFile" => (&["path", "text", "overwrite"], &["path", "text"]),
        "editFile" => (
            &["path", "oldText", "newText"],
            &["path", "oldText", "newText"],
        ),
        "mkdir" => (&["path"], &["path"]),
        "writeChunk" => (
            &["path", "base64", "offset", "overwrite"],
            &["path", "base64"],
        ),
        "listDirectory" => (&["path", "offset", "limit"], &[]),
        "searchFiles" => (&["path", "query", "maxResults"], &["query"]),
        "exec" => (
            &["command", "args", "background", "stdin", "durationMs"],
            &["command", "args"],
        ),
        "jobStatus" | "jobCancel" => (&["jobId"], &["jobId"]),
        "jobOutput" => (&["jobId", "offset", "limit", "stream"], &["jobId"]),
        "jobStdin" => (&["jobId", "text", "eof"], &["jobId", "text"]),
        "resourceRead" => (&["resource"], &["resource"]),
        "mcpList" => (&["server"], &["server"]),
        "mcpCall" => (
            &["server", "tool", "arguments"],
            &["server", "tool", "arguments"],
        ),
        "syncInventory" => (&["scope"], &["scope"]),
        "syncUpload" => (
            &["sha256", "offset", "base64", "totalBytes"],
            &["sha256", "offset", "base64", "totalBytes"],
        ),
        "syncApply" => (&["scope", "manifest"], &["scope", "manifest"]),
        "syncTransfer" => (&["scope", "manifest"], &["scope", "manifest"]),
        "syncExec" => (
            &[
                "scope",
                "manifest",
                "command",
                "args",
                "stdin",
                "durationMs",
            ],
            &["scope", "manifest", "command", "args"],
        ),
        _ => (&[], &[]),
    }
}
pub fn validate(task: &Value, grant: &Grant) -> Result<()> {
    let tool = task["tool"]
        .as_str()
        .ok_or_else(|| IcError::new("INVALID_TASK", "A standard tool name is required"))?;
    if !names().contains(&tool) || !grant.tools.contains(tool) {
        return Err(IcError::new(
            "TOOL_DENIED",
            "Tool is not granted to this master/workspace",
        ));
    }
    let args = task["args"]
        .as_object()
        .ok_or_else(|| IcError::new("INVALID_ARGS", "Tool arguments must be an object"))?;
    let (allowed, required) = fields(tool);
    if args.keys().any(|key| !allowed.contains(&key.as_str()))
        || required.iter().any(|key| !args.contains_key(*key))
    {
        return Err(IcError::new(
            "INVALID_ARGS",
            "Unexpected or missing tool argument",
        ));
    }
    for name in [
        "path",
        "text",
        "oldText",
        "newText",
        "base64",
        "command",
        "stdin",
        "jobId",
        "stream",
        "resource",
        "server",
        "tool",
        "query",
        "rootId",
        "name",
        "requestId",
        "sha256",
    ] {
        if let Some(value) = args.get(name)
            && value.as_str().is_none()
        {
            return Err(IcError::new(
                "INVALID_ARGS",
                format!("{name} must be a string"),
            ));
        }
    }
    for name in [
        "ms",
        "offset",
        "length",
        "limit",
        "maxResults",
        "durationMs",
        "totalBytes",
    ] {
        if let Some(value) = args.get(name)
            && value.as_u64().is_none()
        {
            return Err(IcError::new(
                "INVALID_ARGS",
                format!("{name} must be a non-negative integer"),
            ));
        }
    }
    for name in ["background", "overwrite", "eof"] {
        if let Some(value) = args.get(name)
            && value.as_bool().is_none()
        {
            return Err(IcError::new(
                "INVALID_ARGS",
                format!("{name} must be boolean"),
            ));
        }
    }
    if let Some(argv) = args.get("args")
        && !argv.as_array().is_some_and(|a| {
            a.len() <= 32
                && a.iter().all(|v| {
                    v.as_str()
                        .is_some_and(|s| s.len() <= 4096 && !s.contains('\0'))
                })
        })
    {
        return Err(IcError::new(
            "INVALID_ARGS",
            "Arguments require bounded literal strings",
        ));
    }
    if tool == "exec" {
        crate::jobs::validate_exec(task, grant)?;
    }
    if ["resourceList", "resourceRead", "mcpList", "mcpCall"].contains(&tool) {
        crate::resources::validate(task, grant)?;
    }
    Ok(())
}
fn property(name: &str) -> Value {
    match name {
        "ms" | "offset" | "length" | "limit" | "maxResults" | "durationMs" | "totalBytes" => {
            json!({"type":"integer","minimum":0})
        }
        "background" | "overwrite" | "eof" => json!({"type":"boolean"}),
        "args" => json!({"type":"array","items":{"type":"string"},"maxItems":32}),
        "manifest" => json!({"type":"array","items":{"type":"object"},"maxItems":256}),
        "scope" => {
            json!({"type":"object","properties":{"paths":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"string"}}},"required":["paths"],"additionalProperties":false})
        }
        "arguments" => json!({"type":"object"}),
        _ => json!({"type":"string"}),
    }
}
pub fn schema(tool: &str) -> Value {
    let (allowed, required) = fields(tool);
    let properties: serde_json::Map<String, Value> = allowed
        .iter()
        .map(|name| (name.to_string(), property(name)))
        .collect();
    json!({"name":tool,"description":format!("Servant-authorized {tool} in the selected workspace"),"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false}})
}
pub fn capabilities(grant: &Grant) -> Value {
    let limit_names = [
        "maxConcurrent",
        "maxTimeoutMs",
        "maxWaitMs",
        "maxReadBytes",
        "maxWriteBytes",
        "maxOutputBytes",
        "maxJobTimeoutMs",
        "maxJobs",
        "maxOutputPageBytes",
        "maxSearchFiles",
        "maxSearchBytes",
        "maxDirectoryEntries",
        "maxTransferBytes",
        "maxTasksPerMinute",
        "maxResourceBytes",
        "maxResourceTotalBytes",
        "maxMcpBytes",
    ];
    let limits: serde_json::Map<String, Value> = limit_names
        .iter()
        .filter_map(|name| {
            grant
                .raw
                .get(*name)
                .filter(|v| v.as_u64().is_some())
                .map(|v| ((*name).to_owned(), v.clone()))
        })
        .collect();
    let directories = grant
        .raw
        .get("directories")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .map(|rule| json!({"path":rule["path"],"read":rule["read"],"write":rule["write"]}))
                .collect::<Vec<_>>()
        });
    let builtin_tools = names()
        .iter()
        .filter(|name| grant.tools.contains(**name))
        .map(|name| {
            let mut tool = schema(name);
            tool["_meta"] = json!({"origin":"ic"});
            tool
        })
        .collect::<Vec<_>>();
    let mcp_servers = if grant.tools.contains("mcpList") || grant.tools.contains("mcpCall") {
        grant.raw.get("mcpServers").and_then(Value::as_object).map(|servers| servers.iter().map(|(id,server)| {
            let tools = server["tools"].as_object().map(|bindings| bindings.iter().map(|(name,binding)| {
                json!({"name":name,"description":binding.get("description").cloned().unwrap_or(json!(name)),"inputSchema":binding["inputSchema"],"annotations":{"readOnlyHint":binding["readOnly"]},"_meta":{"origin":"aggregated","serverId":id}})
            }).collect::<Vec<_>>()).unwrap_or_default();
            json!({"id":id,"name":server.get("name").cloned().unwrap_or(json!(id)),"origin":"aggregated","tools":tools})
        }).collect::<Vec<_>>()).unwrap_or_default()
    } else {
        Vec::new()
    };
    let exec_commands = if grant.tools.contains("exec") || grant.tools.contains("syncExec") {
        grant
            .raw
            .get("execCommands")
            .and_then(Value::as_object)
            .map(|v| v.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    json!({"tools":builtin_tools,"mcpServers":mcp_servers,"execCommands":exec_commands,"limits":limits,"directoryPolicy":{"processSandboxed":false,"directories":directories}})
}
pub fn run(task: &Value, grant: &Grant, ctx: &ToolContext) -> Result<Value> {
    ctx.check()?;
    validate(task, grant)?;
    if side_effect(task, Some(grant)) {
        ctx.jobs.assert_can_write(&ctx.master_id)?;
    }
    let tool = task["tool"].as_str().unwrap();
    if tool.starts_with("sync") {
        return ctx.sync.run(task, grant, ctx);
    }
    if [
        "writeFile",
        "editFile",
        "mkdir",
        "writeChunk",
        "exec",
        "mcpList",
        "mcpCall",
    ]
    .contains(&tool)
        && ctx.workspace_lock.is_none()
    {
        let lock = Arc::new(crate::sync::WorkspaceLock::acquire(&grant.root)?);
        let mut locked = ctx.clone();
        locked.workspace_lock = Some(lock);
        return run_unlocked(task, grant, &locked);
    }
    run_unlocked(task, grant, ctx)
}
pub fn run_unlocked(task: &Value, grant: &Grant, ctx: &ToolContext) -> Result<Value> {
    ctx.check()?;
    match task["tool"].as_str().unwrap_or("") {
        "echo" => Ok(json!({"text":task["args"]["text"]})),
        "wait" => {
            let ms = task["args"]["ms"].as_u64().unwrap();
            if ms > grant.limit("maxWaitMs", 5000) {
                return Err(IcError::new("INVALID_ARGS", "Wait exceeds grant limit"));
            }
            let end = std::time::Instant::now() + Duration::from_millis(ms);
            while std::time::Instant::now() < end {
                ctx.check()?;
                std::thread::sleep(
                    Duration::from_millis(10)
                        .min(end.saturating_duration_since(std::time::Instant::now())),
                );
            }
            Ok(json!({"waitedMs":ms}))
        }
        "capabilities" => Ok(capabilities(grant)),
        "workspaceList" => {
            ctx.workspaces
                .catalog(&ctx.master_id, &ctx.policy, ctx.policy_epoch, &task["args"])
        }
        "workspaceCreate" => {
            ctx.workspaces
                .create(&ctx.master_id, &ctx.policy, ctx.policy_epoch, &task["args"])
        }
        "exec" => ctx.jobs.run(task, grant, ctx),
        "jobStatus" | "jobOutput" | "jobCancel" | "jobStdin" => {
            ctx.jobs.run_control(task, grant, ctx)
        }
        "resourceList" | "resourceRead" | "mcpList" | "mcpCall" => {
            crate::resources::run(task, grant, ctx)
        }
        "readFile" | "writeFile" | "editFile" | "listDirectory" | "searchFiles" | "mkdir"
        | "readChunk" | "writeChunk" => crate::files::run(task, grant, ctx),
        _ => Err(IcError::new("TOOL_DENIED", "Unsupported standard tool")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;
    fn grant() -> Grant {
        Grant {
            root: std::env::temp_dir(),
            tools: BTreeSet::from(["readFile".into(), "syncApply".into()]),
            raw: json!({}),
            master_id: "master".into(),
            workspace_id: "dev".into(),
            epoch: 1,
        }
    }
    #[test]
    fn tool_surface_is_standard_and_manual_sync_is_side_effecting() {
        assert_eq!(names().len(), 27);
        assert!(names().contains(&"syncTransfer"));
        assert!(names().contains(&"syncApply"));
        assert!(side_effect(&json!({"tool":"syncApply"}), None));
        assert!(!side_effect(&json!({"tool":"syncInventory"}), None));
        assert!(!names().iter().any(|name| name.contains("proxy")));
    }
    #[test]
    fn grant_and_argument_schema_do_not_accept_injected_roots() {
        assert_eq!(
            validate(
                &json!({"tool":"exec","args":{"command":"build","args":[]}}),
                &grant()
            )
            .unwrap_err()
            .code,
            "TOOL_DENIED"
        );
        assert_eq!(
            validate(
                &json!({"tool":"readFile","args":{"path":"a","root":"/"}}),
                &grant()
            )
            .unwrap_err()
            .code,
            "INVALID_ARGS"
        );
        validate(
            &json!({"tool":"syncApply","args":{"scope":{"paths":["src"]},"manifest":[]}}),
            &grant(),
        )
        .unwrap();
    }
    #[test]
    fn capability_discovery_exposes_only_granted_tools() {
        let value = capabilities(&grant());
        let listed = value["tools"].as_array().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|item| item["name"] == "syncApply"));
        assert!(!listed.iter().any(|item| item["name"] == "exec"));
    }
    #[test]
    fn workspace_creation_schema_uses_registry_request_id() {
        let mut g = grant();
        g.tools.insert("workspaceCreate".into());
        validate(&json!({"tool":"workspaceCreate","args":{"rootId":"projects","name":"demo","requestId":"req_1"}}),&g).unwrap();
        assert_eq!(
            schema("workspaceCreate")["inputSchema"]["required"],
            json!(["rootId", "name", "requestId"])
        );
    }
}
