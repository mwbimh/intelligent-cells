use crate::{
    IcError, Result,
    jobs::JobManager,
    sync::{SyncManager, WorkspaceLock},
    workspaces::WorkspaceRegistry,
};
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
pub type EventSink = Arc<dyn Fn(Value) + Send + Sync>;
#[derive(Clone)]
pub struct ToolContext {
    pub state_dir: PathBuf,
    pub master_id: String,
    pub workspace_id: String,
    pub run_id: String,
    pub policy_epoch: u64,
    pub policy: Value,
    pub cancel: Arc<AtomicBool>,
    pub deadline: Instant,
    pub event_sink: Option<EventSink>,
    pub jobs: Arc<JobManager>,
    pub sync: Arc<SyncManager>,
    pub workspaces: Arc<WorkspaceRegistry>,
    pub workspace_lock: Option<Arc<WorkspaceLock>>,
}
impl ToolContext {
    pub fn check(&self) -> Result<()> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(IcError::new("CANCELLED", "Operation cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(IcError::new("TASK_TIMEOUT", "Task deadline exceeded"));
        }
        Ok(())
    }
    pub fn emit(&self, event: Value) {
        if let Some(sink) = &self.event_sink {
            sink(event);
        }
    }
}
