use serde_json::Value;
use std::{collections::BTreeSet, path::PathBuf};
#[derive(Clone, Debug)]
pub struct Config {
    pub raw: Value,
    pub id: String,
    pub host: String,
    pub port: u16,
    pub path: PathBuf,
    pub state_dir: PathBuf,
}
#[derive(Clone, Debug)]
pub struct Grant {
    pub root: PathBuf,
    pub tools: BTreeSet<String>,
    pub raw: Value,
    pub master_id: String,
    pub workspace_id: String,
    pub epoch: u64,
}
impl Grant {
    pub fn limit(&self, name: &str, default: u64) -> u64 {
        self.raw
            .get(name)
            .and_then(Value::as_u64)
            .unwrap_or(default)
    }
}
