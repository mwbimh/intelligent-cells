use super::*;

impl Node {
    /// Scope selection and mirroring use the same pinned directory as session execution.
    pub(super) fn session_sync_call(
        &self,
        session: &Value,
        name: &str,
        args: &Value,
    ) -> Result<Value> {
        if session["localSync"] != true || session["cwd"].as_str().is_none() {
            return Err(IcError::new(
                "TOOL_DENIED",
                "Local synchronization requires a session with an explicit directory",
            ));
        }
        let peer = self.session_peer(session, args)?;
        let task = json!({
            "taskId":uuid::Uuid::new_v4().to_string(),
            "tool":"syncApply",
            "args":{},
            "timeoutMs":args["timeoutMs"].as_u64().unwrap_or(10000)
        });
        match name {
            "ic_workspace" => {
                let mapped = self.session_task(session, &peer, &task)?;
                self.workspaces.command(&json!({
                    "command":"setWorkspaceSyncScope",
                    "peerId":peer,
                    "logicalWorkspaceId":string(&mapped,"logicalWorkspaceId")?,
                    "scope":args["scope"]
                }))
            }
            "ic_sync" => {
                let result = self.session_dispatch(string(session, "sessionId")?, &peer, &task)?;
                if result["status"] == "error" {
                    return Err(IcError::new(
                        result["error"]["code"].as_str().unwrap_or("REMOTE_ERROR"),
                        result["error"]["message"]
                            .as_str()
                            .unwrap_or("Remote synchronization failed"),
                    ));
                }
                Ok(result["result"].clone())
            }
            _ => Err(IcError::new("TOOL_DENIED", "Unknown synchronization tool")),
        }
    }
}
