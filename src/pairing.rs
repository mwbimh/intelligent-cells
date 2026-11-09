use crate::error::{IcError, Result};
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn denied(message: &str) -> IcError {
    IcError::new("PAIRING_DENIED", message)
}
fn shape(v: &Value, fields: &[&str]) -> Result<()> {
    let o = v.as_object().ok_or_else(|| denied("Object required"))?;
    if o.len() != fields.len() || fields.iter().any(|f| !o.contains_key(*f)) {
        return Err(denied("Unexpected or missing fields"));
    }
    Ok(())
}
fn identity(v: &Value, own: &str) -> Result<()> {
    shape(v, &["nodeId", "certificatePem", "caPem", "fingerprint256"])?;
    let id = v["nodeId"].as_str().unwrap_or("");
    if !crate::policy::valid_id(id) || id == own {
        return Err(denied("Invalid peer identity"));
    }
    for key in ["certificatePem", "caPem"] {
        let s = v[key].as_str().unwrap_or("");
        if s.is_empty() || s.len() > 32768 {
            return Err(denied("Invalid identity bundle"));
        }
    }
    let pin = v["fingerprint256"].as_str().unwrap_or("");
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(denied("Invalid fingerprint"));
    }
    Ok(())
}
fn endpoint(v: &Value) -> Result<()> {
    shape(v, &["host", "port"])?;
    let ip: IpAddr = v["host"]
        .as_str()
        .unwrap_or("")
        .parse()
        .map_err(|_| denied("IP address required"))?;
    if ip.is_unspecified() || ip.is_multicast() || !matches!(v["port"].as_u64(), Some(1..=65535)) {
        return Err(denied("Invalid endpoint"));
    }
    Ok(())
}
/// Durable owner-controlled pairing state. The caller must cryptographically verify
/// identity bundles before submit/record_peer and authenticate complete requests.
pub struct Registry {
    path: PathBuf,
    node_id: String,
    state: Value,
}
impl Registry {
    pub fn open(state_dir: &Path, node_id: &str) -> Result<Self> {
        if !crate::policy::valid_id(node_id) {
            return Err(denied("Invalid local node ID"));
        }
        let path = state_dir.to_path_buf();
        let state = crate::node_store::read_section(&path, "pairing")?
            .unwrap_or_else(|| json!({"nodeId":node_id,"requests":[],"peers":[]}));
        shape(&state, &["nodeId", "requests", "peers"])?;
        if state["nodeId"] != node_id || !state["requests"].is_array() || !state["peers"].is_array()
        {
            return Err(denied("Invalid pairing state"));
        }
        let mut ids = std::collections::BTreeSet::new();
        if state["requests"].as_array().unwrap().len() > 32
            || state["peers"].as_array().unwrap().len() > 32
        {
            return Err(denied("Pairing state exceeds limits"));
        }
        for r in state["requests"].as_array().unwrap() {
            shape(r, &["request", "status", "confirmation"])?;
            let q = &r["request"];
            shape(q, &["requestId", "identity", "endpoint", "expiresAt"])?;
            let id = q["requestId"]
                .as_str()
                .ok_or_else(|| denied("Invalid request ID"))?;
            uuid::Uuid::parse_str(id).map_err(|_| denied("Invalid request UUID"))?;
            if !ids.insert(id)
                || q["expiresAt"].as_u64().is_none()
                || !matches!(
                    r["status"].as_str(),
                    Some("pending" | "approved" | "paired" | "rejected")
                )
            {
                return Err(denied("Invalid request state"));
            }
            uuid::Uuid::parse_str(r["confirmation"].as_str().unwrap_or(""))
                .map_err(|_| denied("Invalid confirmation"))?;
            identity(&q["identity"], node_id)?;
            endpoint(&q["endpoint"])?;
        }
        ids.clear();
        for p in state["peers"].as_array().unwrap() {
            shape(p, &["identity", "endpoint"])?;
            identity(&p["identity"], node_id)?;
            if !p["endpoint"].is_null() {
                endpoint(&p["endpoint"])?;
            }
            if !ids.insert(p["identity"]["nodeId"].as_str().unwrap()) {
                return Err(denied("Duplicate peer"));
            }
        }
        Ok(Self {
            path,
            node_id: node_id.into(),
            state,
        })
    }
    fn save(&mut self, state: Value) -> Result<()> {
        crate::node_store::write_section(&self.path, "pairing", &state)?;
        self.state = state;
        Ok(())
    }
    fn index(&self, id: &str) -> Result<usize> {
        self.state["requests"]
            .as_array()
            .unwrap()
            .iter()
            .position(|r| r["request"]["requestId"] == id)
            .ok_or_else(|| denied("Unknown pairing request"))
    }
    fn live(&self, index: usize) -> Result<()> {
        if self.state["requests"][index]["request"]["expiresAt"]
            .as_u64()
            .unwrap_or(0)
            <= now()
        {
            return Err(denied("Pairing request expired"));
        }
        Ok(())
    }
    fn check_conflict(&self, identity: &Value, endpoint: Option<&Value>) -> Result<()> {
        for p in self.state["peers"].as_array().unwrap().iter().chain(
            self.state["requests"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| {
                    r["status"] != "rejected"
                        && r["request"]["expiresAt"].as_u64().unwrap_or(0) > now()
                })
                .map(|r| &r["request"]),
        ) {
            if p["identity"]["nodeId"] == identity["nodeId"]
                && (p["identity"] != *identity
                    || endpoint.is_some_and(|e| !p["endpoint"].is_null() && p["endpoint"] != *e))
            {
                return Err(denied("Existing identity or endpoint differs"));
            }
        }
        Ok(())
    }
    pub fn submit(&mut self, request: &Value) -> Result<Value> {
        shape(request, &["requestId", "identity", "endpoint", "expiresAt"])?;
        let id = request["requestId"]
            .as_str()
            .ok_or_else(|| denied("Request ID required"))?;
        uuid::Uuid::parse_str(id).map_err(|_| denied("UUID required"))?;
        identity(&request["identity"], &self.node_id)?;
        endpoint(&request["endpoint"])?;
        let expires = request["expiresAt"]
            .as_u64()
            .ok_or_else(|| denied("Expiry required"))?;
        let time = now();
        if expires <= time || expires > time.saturating_add(600_000) {
            return Err(denied("Expiry must be within ten minutes"));
        }
        if let Ok(i) = self.index(id) {
            let r = &self.state["requests"][i];
            if r["request"] != *request
                || matches!(r["status"].as_str(), Some("rejected" | "paired"))
            {
                return Err(denied("Request replay differs or was rejected"));
            }
            return Ok(r.clone());
        }
        self.check_conflict(&request["identity"], Some(&request["endpoint"]))?;
        let mut state = self.state.clone();
        let requests = state["requests"].as_array_mut().unwrap();
        requests.retain(|r| r["request"]["expiresAt"].as_u64().unwrap_or(0) > time);
        if requests.len() >= 32 {
            return Err(denied("Pending request limit"));
        }
        let record = json!({"request":request,"status":"pending","confirmation":uuid::Uuid::new_v4().to_string()});
        requests.push(record.clone());
        self.save(state)?;
        Ok(record)
    }
    pub fn list(&self) -> Value {
        json!({"requests": self.state["requests"].as_array().unwrap().iter().map(|r| json!({"requestId":r["request"]["requestId"],"nodeId":r["request"]["identity"]["nodeId"],"fingerprint256":r["request"]["identity"]["fingerprint256"],"endpoint":r["request"]["endpoint"],"expiresAt":r["request"]["expiresAt"],"status":r["status"],"confirmation":r["confirmation"]})).collect::<Vec<_>>()})
    }
    pub fn approve(&mut self, request_id: &str, expected_fingerprint: &str) -> Result<Value> {
        let i = self.index(request_id)?;
        self.live(i)?;
        let r = &self.state["requests"][i];
        if r["request"]["identity"]["fingerprint256"] != expected_fingerprint
            || !matches!(r["status"].as_str(), Some("pending" | "approved"))
        {
            return Err(denied("Fingerprint or request state mismatch"));
        }
        let mut state = self.state.clone();
        state["requests"][i]["status"] = json!("approved");
        let result = state["requests"][i].clone();
        self.save(state)?;
        Ok(result)
    }
    pub fn reject(&mut self, request_id: &str) -> Result<Value> {
        let i = self.index(request_id)?;
        if self.state["requests"][i]["status"] == "paired" {
            return Err(denied("Revoke paired peer explicitly"));
        }
        let mut state = self.state.clone();
        state["requests"][i]["status"] = json!("rejected");
        let result = state["requests"][i].clone();
        self.save(state)?;
        Ok(result)
    }
    pub fn complete(&self, request_id: &str, identity: &Value) -> Result<Value> {
        let i = self.index(request_id)?;
        let r = &self.state["requests"][i];
        if r["status"] != "paired" {
            self.live(i)?;
        }
        if !matches!(r["status"].as_str(), Some("approved" | "paired"))
            || r["request"]["identity"] != *identity
        {
            return Err(denied("Request not approved for this identity"));
        }
        Ok(r.clone())
    }
    /// Commit the outgoing relationship and completion marker in one durable write.
    pub fn activate(&mut self, request_id: &str, peer_identity: &Value) -> Result<Value> {
        let record = self.complete(request_id, peer_identity)?;
        let i = self.index(request_id)?;
        let endpoint = &record["request"]["endpoint"];
        self.check_conflict(peer_identity, Some(endpoint))?;
        let peer = json!({"identity":peer_identity,"endpoint":endpoint});
        let mut state = self.state.clone();
        let peers = state["peers"].as_array_mut().unwrap();
        if let Some(old) = peers
            .iter()
            .find(|p| p["identity"]["nodeId"] == peer_identity["nodeId"])
        {
            if old != &peer {
                return Err(denied("Existing peer differs"));
            }
            if record["status"] == "paired" {
                return Ok(record);
            }
        } else {
            if record["status"] == "paired" {
                return Err(denied("Completed pairing has no active peer"));
            }
            if peers.len() >= 32 {
                return Err(denied("Peer limit"));
            }
            peers.push(peer);
        }
        state["requests"][i]["status"] = json!("paired");
        let result = state["requests"][i].clone();
        self.save(state)?;
        Ok(result)
    }
    pub fn mark_completed(&mut self, request_id: &str) -> Result<()> {
        let i = self.index(request_id)?;
        if self.state["requests"][i]["status"] == "paired" {
            return Ok(());
        }
        self.live(i)?;
        if !matches!(
            self.state["requests"][i]["status"].as_str(),
            Some("approved" | "paired")
        ) {
            return Err(denied("Request not approved"));
        }
        let mut state = self.state.clone();
        state["requests"][i]["status"] = json!("paired");
        self.save(state)
    }
    pub fn record_peer(
        &mut self,
        peer_identity: &Value,
        peer_endpoint: Option<&Value>,
    ) -> Result<()> {
        identity(peer_identity, &self.node_id)?;
        if let Some(e) = peer_endpoint {
            endpoint(e)?;
        }
        self.check_conflict(peer_identity, peer_endpoint)?;
        let mut state = self.state.clone();
        let peers = state["peers"].as_array_mut().unwrap();
        if let Some(p) = peers
            .iter_mut()
            .find(|p| p["identity"]["nodeId"] == peer_identity["nodeId"])
        {
            if p["endpoint"] != peer_endpoint.cloned().unwrap_or(Value::Null) {
                return Err(denied("Existing peer endpoint differs"));
            }
        } else {
            if peers.len() >= 32 {
                return Err(denied("Peer limit"));
            }
            peers.push(json!({"identity":peer_identity,"endpoint":peer_endpoint}));
        }
        self.save(state)
    }
    pub fn peers(&self) -> Vec<Value> {
        self.state["peers"].as_array().unwrap().clone()
    }
    pub fn remove_peer(&mut self, id: &str) -> Result<()> {
        let mut state = self.state.clone();
        state["peers"]
            .as_array_mut()
            .unwrap()
            .retain(|p| p["identity"]["nodeId"] != id);
        for r in state["requests"].as_array_mut().unwrap() {
            if r["request"]["identity"]["nodeId"] == id {
                r["status"] = json!("rejected");
            }
        }
        self.save(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Value {
        json!({"requestId":uuid::Uuid::new_v4().to_string(),"identity":{"nodeId":"servant","certificatePem":"cert","caPem":"ca","fingerprint256":"a".repeat(64)},"endpoint":{"host":"100.64.0.2","port":18433},"expiresAt":now()+60_000})
    }
    #[test]
    fn approval_and_confirmation_are_separate_and_persistent() {
        let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let mut r = Registry::open(d.path(), "master").unwrap();
        let q = request();
        let id = q["requestId"].as_str().unwrap();
        r.submit(&q).unwrap();
        assert!(r.complete(id, &q["identity"]).is_err());
        assert!(r.approve(id, &"b".repeat(64)).is_err());
        r.approve(id, &"a".repeat(64)).unwrap();
        r.complete(id, &q["identity"]).unwrap();
        assert!(r.peers().is_empty());
        r.record_peer(&q["identity"], Some(&q["endpoint"])).unwrap();
        r.mark_completed(id).unwrap();
        let r = Registry::open(d.path(), "master").unwrap();
        assert_eq!(r.peers().len(), 1);
        assert!(d.path().join("nodes.json").is_file());
        assert!(!d.path().join("pairing.json").exists());
        assert_eq!(r.list()["requests"][0]["status"], "paired");
        assert!(!r.list().to_string().contains("certificatePem"));
    }
    #[test]
    fn rejects_replay_mutation_identity_collision_and_expiry() {
        let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let mut r = Registry::open(d.path(), "master").unwrap();
        let q = request();
        r.submit(&q).unwrap();
        r.submit(&q).unwrap();
        let mut changed = q.clone();
        changed["endpoint"]["port"] = json!(1);
        assert!(r.submit(&changed).is_err());
        changed = request();
        changed["identity"]["fingerprint256"] = json!("b".repeat(64));
        assert!(r.submit(&changed).is_err());
        changed = request();
        changed["expiresAt"] = json!(now() - 1);
        assert!(r.submit(&changed).is_err());
        r.reject(q["requestId"].as_str().unwrap()).unwrap();
        assert!(r.submit(&q).is_err());
    }
    #[test]
    fn activation_write_failure_leaves_approval_and_peers_unchanged() {
        let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let mut r = Registry::open(d.path(), "master").unwrap();
        let q = request();
        let id = q["requestId"].as_str().unwrap();
        r.submit(&q).unwrap();
        r.approve(id, &"a".repeat(64)).unwrap();
        let before = r.state.clone();
        let path = r.path.clone();
        std::fs::write(d.path().join("blocked"), "file").unwrap();
        r.path = d.path().join("blocked/pairing.json");
        assert!(r.activate(id, &q["identity"]).is_err());
        assert_eq!(r.state, before);
        assert_eq!(Registry::open(d.path(), "master").unwrap().state, before);
        r.path = path;
        r.activate(id, &q["identity"]).unwrap();
        let restored = Registry::open(d.path(), "master").unwrap();
        assert_eq!(restored.peers().len(), 1);
        assert_eq!(restored.list()["requests"][0]["status"], "paired");
    }
    #[test]
    fn activated_request_retries_after_expiry_but_never_after_revocation() {
        let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let mut r = Registry::open(d.path(), "master").unwrap();
        let q = request();
        let id = q["requestId"].as_str().unwrap();
        r.submit(&q).unwrap();
        r.approve(id, &"a".repeat(64)).unwrap();
        let mut expired = r.state.clone();
        expired["requests"][0]["request"]["expiresAt"] = json!(now() - 1);
        r.save(expired).unwrap();
        assert!(r.activate(id, &q["identity"]).is_err());
        let mut live = r.state.clone();
        live["requests"][0]["request"]["expiresAt"] = q["expiresAt"].clone();
        r.save(live).unwrap();
        r.activate(id, &q["identity"]).unwrap();
        let mut expired = r.state.clone();
        expired["requests"][0]["request"]["expiresAt"] = json!(now() - 1);
        r.save(expired).unwrap();
        assert!(r.complete(id, &q["identity"]).is_ok());
        assert!(r.activate(id, &q["identity"]).is_ok());
        assert!(r.approve(id, &"a".repeat(64)).is_err());
        r.remove_peer("servant").unwrap();
        assert!(r.activate(id, &q["identity"]).is_err());
        assert!(r.peers().is_empty());
    }
    #[test]
    fn validates_endpoints_and_does_not_mutate_after_failed_write() {
        let d = tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let mut r = Registry::open(d.path(), "master").unwrap();
        for host in ["0.0.0.0", "::", "224.0.0.1", "hostname"] {
            let mut q = request();
            q["endpoint"]["host"] = json!(host);
            assert!(r.submit(&q).is_err());
        }
        let q = request();
        r.submit(&q).unwrap();
        let before = r.list();
        r.path = d.path().join("missing/invalid/pairing.json");
        std::fs::write(d.path().join("missing"), "file").unwrap();
        assert!(
            r.approve(q["requestId"].as_str().unwrap(), &"a".repeat(64))
                .is_err()
        );
        assert_eq!(before, r.list());
    }
}
