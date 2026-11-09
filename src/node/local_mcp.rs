use super::*;
use std::path::Path;

impl Node {
    pub(super) fn local_mcp_call(
        &self,
        session_id: &str,
        name: &str,
        args: &Value,
        cwd: &Path,
    ) -> Result<Value> {
        // Keep admission, the durable start record, execution and final outcome in
        // one critical section. A second session must observe an uncertain effect.
        let _admission = self.local_mcp_admission.lock().unwrap();
        // Registry edits use this lock too: the approved effect classification must
        // remain unchanged until the call finishes.
        let _registry = self.pairing_mutation.lock().unwrap();
        if self.sessions.local_directory(
            session_id,
            self.config().raw["sessions"]["allowTemporary"] != false,
        )? != cwd
        {
            return Err(IcError::new(
                "WORKSPACE_CHANGED",
                "Session directory changed",
            ));
        }
        let catalog = self.mcp.tools(None)?;
        let tool = catalog
            .iter()
            .find(|tool| tool["name"] == name)
            .ok_or_else(|| IcError::new("TOOL_DENIED", "Tool is unknown or disabled"))?;
        let side_effect = tool["annotations"]["readOnlyHint"] != true;
        let node_id = self.config().id;
        if side_effect {
            let sessions = self.sessions.list()?;
            if sessions.as_array().unwrap().iter().any(|session| {
                session["tasks"].as_array().unwrap().iter().any(|task| {
                    task["peerId"] == node_id
                        && task["origin"] == "aggregated"
                        && task["sideEffect"] != false
                        && (task["state"] == "running" || task["state"] == "unknown")
                })
            }) {
                return Err(IcError::new(
                    "LOCAL_MCP_OUTCOME_UNKNOWN",
                    "Inspect and reconcile the previous local MCP effect before another mutation",
                ));
            }
        }
        let task = json!({"taskId":uuid::Uuid::new_v4().to_string(),"tool":name,"origin":"aggregated","sideEffect":side_effect});
        self.sessions.record_start(session_id, &node_id, &task)?;
        let result = self.mcp.call(None, name, args, cwd);
        self.sessions
            .record_finish(session_id, string(&task, "taskId")?, &result)?;
        result
    }

    pub(super) fn local_mcp_reconcile(&self, command: &Value) -> Result<Value> {
        let _admission = self.local_mcp_admission.lock().unwrap();
        self.sessions.reconcile_local_mcp(
            string(command, "sessionId")?,
            string(command, "taskId")?,
            &self.config().id,
            string(command, "note")?,
        )
    }
}
