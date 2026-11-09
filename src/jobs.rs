#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt;
    fn grant() -> Grant {
        Grant {
            root: std::env::temp_dir(),
            tools: BTreeSet::from(["exec".into()]),
            raw: json!({"execCommands":{"ok":{"file":"/bin/echo","args":[],"argsAllowed":true,"maxArgs":2,"allowedArgs":["yes"],"stdinAllowed":false}}}),
            master_id: "alice".into(),
            workspace_id: "dev".into(),
            epoch: 2,
        }
    }
    #[test]
    fn denied_alias_and_unapproved_argv() {
        let g = grant();
        assert_eq!(
            validate_exec(&json!({"args":{"command":"bad","args":[]}}), &g)
                .unwrap_err()
                .code,
            "COMMAND_DENIED"
        );
        assert_eq!(
            validate_exec(&json!({"args":{"command":"ok","args":["no"]}}), &g)
                .unwrap_err()
                .code,
            "INVALID_ARGS"
        );
        assert_eq!(
            validate_exec(
                &json!({"args":{"command":"ok","args":["yes"],"stdin":"x"}}),
                &g
            )
            .unwrap_err()
            .code,
            "STDIN_DENIED"
        );
    }
    #[test]
    fn restarted_running_job_requires_owner_reconciliation() {
        let dir = tempfile::tempdir().unwrap();
        let manager = JobManager::new(dir.path(), 1).unwrap();
        let job = json!({"version":1,"jobId":"test","masterId":"alice","workspaceId":"dev","policyEpoch":2,"state":"running","root":"/tmp","maxOutputBytes":1024});
        for stream in ["stdout", "stderr", "combined"] {
            private_file(&manager.path("test", stream)).unwrap();
        }
        crate::durable::write_checked(&manager.path("test", "json"), &job).unwrap();
        drop(manager);
        let manager = JobManager::new(dir.path(), 1).unwrap();
        assert_eq!(
            manager.assert_can_write("alice").unwrap_err().code,
            "OUTCOME_UNKNOWN"
        );
        assert_eq!(manager.command(&json!({"command":"reconcileJob","masterId":"alice","jobId":"test","resolution":"no-effects","note":"Inspected process and workspace"})).unwrap()["state"],"reconciled");
        manager.assert_can_write("alice").unwrap();
    }
    #[test]
    fn rejects_linked_spool() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::write(&outside, "x").unwrap();
        let jobs = dir.path().join("jobs");
        std::fs::create_dir(&jobs).unwrap();
        std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&outside, jobs.join("test.stdout")).unwrap();
        assert!(JobManager::new(dir.path(), 1).is_err());
    }
}
use crate::{IcError, Result, context::ToolContext, model::Grant};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::os::unix::{
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    io::AsRawFd,
    process::CommandExt,
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{ChildStdin, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn err(code: &str, message: &str) -> IcError {
    IcError::new(code, message)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn private_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?)
}
fn safe(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(err(
            "JOB_STORE_UNSAFE",
            "Spool must be private regular unlinked file",
        ));
    }
    Ok(())
}
fn command_spec<'a>(task: &Value, grant: &'a Grant) -> Result<&'a Value> {
    grant
        .raw
        .get("execCommands")
        .and_then(|c| c.get(task["args"]["command"].as_str().unwrap_or("")))
        .ok_or_else(|| err("COMMAND_DENIED", "Command alias is not approved"))
}
pub fn validate_exec(task: &Value, grant: &Grant) -> Result<()> {
    if !grant.tools.contains("exec") {
        return Err(err("TOOL_DENIED", "exec is not granted"));
    }
    let cmd = command_spec(task, grant)?;
    let args = task["args"]["args"]
        .as_array()
        .ok_or_else(|| err("INVALID_ARGS", "args must be an array"))?;
    if args.len() > cmd["maxArgs"].as_u64().unwrap_or(0) as usize
        || (!args.is_empty() && cmd["argsAllowed"] != true)
    {
        return Err(err("INVALID_ARGS", "Arguments exceed configured allowance"));
    }
    let mut total = 0;
    for arg in args {
        let arg = arg
            .as_str()
            .ok_or_else(|| err("INVALID_ARGS", "Argument must be string"))?;
        total += arg.len();
        if arg.contains('\0')
            || arg.len() > 4096
            || total > 16384
            || cmd["allowedArgs"]
                .as_array()
                .is_some_and(|a| !a.iter().any(|v| v.as_str() == Some(arg)))
        {
            return Err(err("INVALID_ARGS", "Argument is not allowed"));
        }
    }
    if let Some(stdin) = task["args"].get("stdin") {
        let text = stdin
            .as_str()
            .ok_or_else(|| err("INVALID_ARGS", "stdin must be text"))?;
        if cmd["stdinAllowed"] != true {
            return Err(err("STDIN_DENIED", "stdin is not granted"));
        }
        if text.len() > cmd["maxStdinBytes"].as_u64().unwrap_or(65536) as usize {
            return Err(err("STDIN_TOO_LARGE", "stdin exceeds lifetime limit"));
        }
    }
    if let Some(d) = task["args"].get("durationMs")
        && d.as_u64().is_none_or(|d| {
            d < 10 || d > grant.limit("maxJobTimeoutMs", grant.limit("maxTimeoutMs", 3600000))
        })
    {
        return Err(err("INVALID_ARGS", "Invalid durationMs"));
    }
    Ok(())
}
fn public_job(data: &Value) -> Value {
    let mut value = data.clone();
    if let Some(fields) = value.as_object_mut() {
        for key in [
            "version",
            "root",
            "maxOutputBytes",
            "maxStdinBytes",
            "stdinAllowed",
        ] {
            fields.remove(key);
        }
    }
    value
}
struct Job {
    data: Value,
    stdin: Option<ChildStdin>,
    stop: Arc<AtomicBool>,
    closed: bool,
    result: Option<Result<Value>>,
}
struct Entry {
    job: Mutex<Job>,
    done: Condvar,
    stdin_gate: Mutex<()>,
}
#[derive(PartialEq, Eq)]
struct ReservationIdentity {
    master_id: String,
    root: PathBuf,
    workspace_id: String,
    run_id: String,
    task_id: String,
}
impl ReservationIdentity {
    fn new(task: &Value, grant: &Grant, ctx: &ToolContext) -> Self {
        Self {
            master_id: ctx.master_id.clone(),
            root: grant.root.clone(),
            workspace_id: ctx.workspace_id.clone(),
            run_id: ctx.run_id.clone(),
            task_id: task["taskId"].as_str().unwrap_or("").into(),
        }
    }
}
struct Execution {
    task: Value,
    grant: Grant,
    ctx: ToolContext,
    background: bool,
}
struct Inner {
    dir: PathBuf,
    jobs: Mutex<BTreeMap<String, Arc<Entry>>>,
    max_concurrent: usize,
    stopping: AtomicBool,
    reservations: Mutex<BTreeMap<String, ReservationIdentity>>,
}
pub struct Reservation {
    inner: Arc<Inner>,
    token: String,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.inner.reservations.lock().unwrap().remove(&self.token);
    }
}
#[derive(Clone)]
pub struct JobManager {
    inner: Arc<Inner>,
}
impl JobManager {
    pub fn new(state_dir: &Path, max_concurrent: usize) -> Result<Self> {
        if max_concurrent == 0 || max_concurrent > 256 {
            return Err(err("INVALID_POLICY", "Invalid process capacity"));
        }
        let dir = state_dir.join("jobs");
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)?;
        }
        let m = fs::symlink_metadata(&dir)?;
        if !m.is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
            || fs::canonicalize(&dir)? != dir
        {
            return Err(err(
                "JOB_STORE_UNSAFE",
                "Job directory is not canonical and private",
            ));
        }
        let manager = Self {
            inner: Arc::new(Inner {
                dir,
                jobs: Mutex::new(BTreeMap::new()),
                max_concurrent,
                stopping: AtomicBool::new(false),
                reservations: Mutex::new(BTreeMap::new()),
            }),
        };
        let entries = fs::read_dir(&manager.inner.dir)?.collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() > 1040 {
            return Err(err("JOB_STORE_FULL", "Too many spool entries"));
        }
        for entry in &entries {
            safe(&entry.path())?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            let id = name.trim_end_matches(".json");
            if !crate::policy::valid_id(id) {
                return Err(err("JOB_STORE_CORRUPT", "Invalid job ID"));
            }
            let mut data = crate::durable::read_checked(&entry.path())?;
            if data["jobId"] != id
                || data["version"] != 1
                || !crate::policy::valid_id(data["masterId"].as_str().unwrap_or(""))
            {
                return Err(err("JOB_STORE_CORRUPT", "Invalid job record"));
            }
            if !crate::policy::valid_id(data["runId"].as_str().unwrap_or("default"))
                || data
                    .get("workspaceId")
                    .is_some_and(|v| !crate::policy::valid_id(v.as_str().unwrap_or("")))
                || !matches!(
                    data["state"].as_str(),
                    Some(
                        "starting"
                            | "running"
                            | "succeeded"
                            | "failed"
                            | "cancelled"
                            | "timed_out"
                            | "unknown"
                            | "reconciled"
                    )
                )
            {
                return Err(err("JOB_STORE_CORRUPT", "Invalid job ownership or state"));
            }
            let cap = data["maxOutputBytes"]
                .as_u64()
                .filter(|x| *x > 0 && *x <= 16777216)
                .ok_or_else(|| err("JOB_STORE_CORRUPT", "Invalid output cap"))?;
            for stream in ["combined", "stdout", "stderr"] {
                let p = manager.path(id, stream);
                safe(&p)?;
                let n = fs::metadata(p)?.len();
                if n > cap {
                    return Err(err("JOB_STORE_CORRUPT", "Output exceeds cap"));
                }
                data[if stream == "combined" {
                    "outputBytes"
                } else if stream == "stdout" {
                    "stdoutBytes"
                } else {
                    "stderrBytes"
                }] = json!(n);
            }
            if matches!(
                data["state"].as_str(),
                Some("succeeded" | "failed" | "cancelled" | "timed_out")
            ) && data["stdoutBytes"].as_u64().unwrap_or(0)
                + data["stderrBytes"].as_u64().unwrap_or(0)
                != data["outputBytes"].as_u64().unwrap_or(0)
            {
                return Err(err("JOB_STORE_CORRUPT", "Inconsistent durable output"));
            }
            if matches!(data["state"].as_str(), Some("starting" | "running")) {
                data["state"] = json!("unknown");
                data["outcomeUnknown"] = json!(true);
                data["error"] = json!({"code":"OUTCOME_UNKNOWN","message":"Node restarted before process close; inspect effects locally"});
                manager.save(&data)?;
            }
            manager.inner.jobs.lock().unwrap().insert(
                id.into(),
                Arc::new(Entry {
                    job: Mutex::new(Job {
                        data,
                        stdin: None,
                        stop: Arc::new(AtomicBool::new(false)),
                        closed: true,
                        result: None,
                    }),
                    done: Condvar::new(),
                    stdin_gate: Mutex::new(()),
                }),
            );
        }
        Ok(manager)
    }
    fn path(&self, id: &str, suffix: &str) -> PathBuf {
        self.inner.dir.join(format!("{id}.{suffix}"))
    }
    fn save(&self, data: &Value) -> Result<()> {
        crate::durable::write_checked(&self.path(data["jobId"].as_str().unwrap(), "json"), data)
    }
    fn get(&self, id: &str) -> Result<Arc<Entry>> {
        self.inner
            .jobs
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| err("JOB_NOT_FOUND", "No accessible job"))
    }
    pub fn has_active(&self, root: &Path) -> bool {
        self.inner.jobs.lock().unwrap().values().any(|e| {
            let j = e.job.lock().unwrap();
            !j.closed && {
                let job_root = Path::new(j.data["root"].as_str().unwrap_or(""));
                root.starts_with(job_root) || job_root.starts_with(root)
            }
        })
    }
    pub fn assert_can_write(&self, master: &str) -> Result<()> {
        if self.inner.jobs.lock().unwrap().values().any(|e| {
            let j = e.job.lock().unwrap();
            j.data["masterId"] == master
                && (j.data["outcomeUnknown"] == true || j.data["state"] == "unknown")
        }) {
            return Err(err(
                "OUTCOME_UNKNOWN",
                "Prior job requires local owner reconciliation",
            ));
        }
        Ok(())
    }
    pub fn reserve(&self, task: &Value, grant: &Grant, ctx: &ToolContext) -> Result<Reservation> {
        ctx.check()?;
        if ctx.master_id != grant.master_id
            || ctx.workspace_id != grant.workspace_id
            || ctx.policy_epoch != grant.epoch
        {
            return Err(err(
                "TASK_POLICY_CHANGED",
                "Execution context does not match authenticated grant",
            ));
        }
        if !crate::policy::valid_id(&ctx.master_id) || !crate::policy::valid_id(&ctx.run_id) {
            return Err(err("INVALID_TASK", "Invalid job owner or run identity"));
        }
        validate_exec(task, grant)?;
        self.assert_can_write(&ctx.master_id)?;
        crate::policy::verify_approved_code(command_spec(task, grant)?, "EXEC_CODE_CHANGED")?;
        let mut jobs = self.inner.jobs.lock().unwrap();
        if jobs.values().any(|e| {
            let j = e.job.lock().unwrap();
            j.data["masterId"] == ctx.master_id
                && (j.data["outcomeUnknown"] == true || j.data["state"] == "unknown")
        }) {
            return Err(err(
                "OUTCOME_UNKNOWN",
                "Prior job requires local inspection",
            ));
        }
        let mut reservations = self.inner.reservations.lock().unwrap();
        if self.inner.stopping.load(Ordering::Acquire) {
            return Err(err("SHUTTING_DOWN", "Job manager stopping"));
        }
        let peer_reserved = reservations
            .values()
            .filter(|r| r.master_id == ctx.master_id)
            .count();
        let retain = grant.limit("maxJobs", 32).min(256) as usize;
        while jobs.len() + reservations.len() >= 256
            || jobs
                .values()
                .filter(|e| e.job.lock().unwrap().data["masterId"] == ctx.master_id)
                .count()
                + peer_reserved
                >= retain
        {
            let global = jobs.len() + reservations.len() >= 256;
            let victim = jobs
                .iter()
                .filter(|(_, e)| {
                    let j = e.job.lock().unwrap();
                    j.closed
                        && j.data["outcomeUnknown"] != true
                        && (global || j.data["masterId"] == ctx.master_id)
                })
                .min_by_key(|(_, e)| {
                    e.job.lock().unwrap().data["startedAt"]
                        .as_u64()
                        .unwrap_or(0)
                })
                .map(|(id, _)| id.clone())
                .ok_or_else(|| err("JOB_STORE_FULL", "No terminal job can retire"))?;
            fs::remove_file(self.path(&victim, "json"))?;
            for stream in ["combined", "stdout", "stderr"] {
                fs::remove_file(self.path(&victim, stream))?;
            }
            jobs.remove(&victim);
        }
        let active = jobs
            .values()
            .filter(|e| !e.job.lock().unwrap().closed)
            .count();
        let peer_active = jobs
            .values()
            .filter(|e| {
                let j = e.job.lock().unwrap();
                !j.closed && j.data["masterId"] == ctx.master_id
            })
            .count();
        if active + reservations.len() >= self.inner.max_concurrent
            || peer_active + peer_reserved >= grant.limit("maxConcurrent", 1) as usize
        {
            return Err(err("BUSY", "Process capacity is reserved"));
        }
        let token = uuid::Uuid::new_v4().to_string();
        reservations.insert(token.clone(), ReservationIdentity::new(task, grant, ctx));

        Ok(Reservation {
            inner: self.inner.clone(),
            token,
        })
    }
    pub fn run(&self, task: &Value, grant: &Grant, ctx: &ToolContext) -> Result<Value> {
        let reservation = self.reserve(task, grant, ctx)?;
        self.run_reserved(task, grant, ctx, reservation)
    }
    pub fn run_reserved(
        &self,
        task: &Value,
        grant: &Grant,
        ctx: &ToolContext,
        reservation: Reservation,
    ) -> Result<Value> {
        ctx.check()?;
        if ctx.master_id != grant.master_id
            || ctx.workspace_id != grant.workspace_id
            || ctx.policy_epoch != grant.epoch
        {
            return Err(err(
                "TASK_POLICY_CHANGED",
                "Execution context does not match authenticated grant",
            ));
        }
        if !crate::policy::valid_id(&ctx.master_id) || !crate::policy::valid_id(&ctx.run_id) {
            return Err(err("INVALID_TASK", "Invalid job owner or run identity"));
        }
        validate_exec(task, grant)?;
        self.assert_can_write(&ctx.master_id)?;
        let spec = command_spec(task, grant)?.clone();
        crate::policy::verify_approved_code(&spec, "EXEC_CODE_CHANGED")?;
        crate::files::inspect_root(&grant.root)?;
        let workspace = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&grant.root)?;
        let metadata = workspace.metadata()?;
        if grant.raw["workspaceIdentity"]["ino"]
            .as_str()
            .is_some_and(|ino| ino != metadata.ino().to_string())
            || grant.raw["workspaceIdentity"]["dev"]
                .as_str()
                .is_some_and(|dev| dev != metadata.dev().to_string())
        {
            return Err(err(
                "WORKSPACE_DENIED",
                "Workspace directory identity changed",
            ));
        }

        let id = uuid::Uuid::new_v4().to_string();
        let cap = grant.limit("maxOutputBytes", 65536).min(16777216);
        let background = task["args"]["background"] == true;
        let data = json!({"version":1,"jobId":id,"masterId":ctx.master_id,"workspaceId":ctx.workspace_id,"policyEpoch":ctx.policy_epoch,"runId":ctx.run_id,"taskId":task["taskId"],"command":task["args"]["command"],"root":grant.root,"state":"starting","startedAt":now(),"finishedAt":null,"outcomeUnknown":false,"outputBytes":0,"stdoutBytes":0,"stderrBytes":0,"stdinBytes":0,"maxOutputBytes":cap,"stdinAllowed":spec["stdinAllowed"]==true,"maxStdinBytes":spec["maxStdinBytes"].as_u64().unwrap_or(65536)});
        let entry = Arc::new(Entry {
            job: Mutex::new(Job {
                data,
                stdin: None,
                stop: Arc::new(AtomicBool::new(false)),
                closed: false,
                result: None,
            }),
            done: Condvar::new(),
            stdin_gate: Mutex::new(()),
        });
        let mut files = BTreeMap::new();
        {
            let mut jobs = self.inner.jobs.lock().unwrap();
            if jobs.values().any(|e| {
                let j = e.job.lock().unwrap();
                j.data["masterId"] == ctx.master_id
                    && (j.data["outcomeUnknown"] == true || j.data["state"] == "unknown")
            }) {
                return Err(err(
                    "OUTCOME_UNKNOWN",
                    "Prior job requires local inspection",
                ));
            }
            let mut reservations = self.inner.reservations.lock().unwrap();
            if !Arc::ptr_eq(&reservation.inner, &self.inner)
                || reservations.get(&reservation.token)
                    != Some(&ReservationIdentity::new(task, grant, ctx))
            {
                return Err(err(
                    "INVALID_JOB_RESERVATION",
                    "Reservation does not match execution",
                ));
            }
            if self.inner.stopping.load(Ordering::Acquire) {
                return Err(err("SHUTTING_DOWN", "Job manager stopping"));
            }
            let active = jobs
                .values()
                .filter(|e| !e.job.lock().unwrap().closed)
                .count();
            let peer_active = jobs
                .values()
                .filter(|e| {
                    let j = e.job.lock().unwrap();
                    !j.closed && j.data["masterId"] == ctx.master_id
                })
                .count();
            if active >= self.inner.max_concurrent
                || peer_active >= grant.limit("maxConcurrent", 1) as usize
            {
                return Err(err("BUSY", "Live process quota reached"));
            }
            let retain = grant.limit("maxJobs", 32).min(256) as usize;
            while jobs.len() >= 256
                || jobs
                    .values()
                    .filter(|e| e.job.lock().unwrap().data["masterId"] == ctx.master_id)
                    .count()
                    >= retain
            {
                let victim = jobs
                    .iter()
                    .filter(|(_, e)| {
                        let j = e.job.lock().unwrap();
                        j.closed
                            && j.data["outcomeUnknown"] != true
                            && (jobs.len() >= 256 || j.data["masterId"] == ctx.master_id)
                    })
                    .min_by_key(|(_, e)| {
                        e.job.lock().unwrap().data["startedAt"]
                            .as_u64()
                            .unwrap_or(0)
                    })
                    .map(|(id, _)| id.clone())
                    .ok_or_else(|| err("JOB_STORE_FULL", "No terminal job can be retired"))?;
                fs::remove_file(self.path(&victim, "json"))?;
                for stream in ["combined", "stdout", "stderr"] {
                    fs::remove_file(self.path(&victim, stream))?;
                }
                jobs.remove(&victim);
            }
            for stream in ["combined", "stdout", "stderr"] {
                files.insert(stream, private_file(&self.path(&id, stream))?);
            }
            self.save(&entry.job.lock().unwrap().data)?;
            jobs.insert(id.clone(), entry.clone());
            reservations.remove(&reservation.token);
        }
        let mut command = Command::new(
            spec["file"]
                .as_str()
                .ok_or_else(|| err("INVALID_POLICY", "Missing executable"))?,
        );
        command.args(
            spec["args"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        );
        command.args(
            task["args"]["args"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str),
        );
        command.env_clear();
        if let Some(env) = spec["env"].as_object() {
            for (k, v) in env {
                command.env(k, v.as_str().unwrap_or(""));
            }
        }
        command
            .stdin(if spec["stdinAllowed"] == true {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::fchdir(workspace.as_raw_fd()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                let error = err("EXEC_FAILED", &e.to_string());
                let mut j = entry.job.lock().unwrap();
                j.data["state"] = json!("failed");
                j.data["error"] = json!(error);
                j.closed = true;
                j.result = Some(Err(error.clone()));
                self.save(&j.data)?;
                entry.done.notify_all();
                return Err(error);
            }
        };
        let manager = self.clone();
        let ctx = ctx.clone();
        let task = task.clone();
        let grant = grant.clone();
        let worker_entry = entry.clone();
        thread::spawn(move || {
            manager.supervise(
                child,
                files,
                worker_entry,
                Execution {
                    task,
                    grant,
                    ctx,
                    background,
                },
            )
        });
        let mut j = entry.job.lock().unwrap();
        if background {
            while j.data["state"] == "starting" && !j.closed {
                j = entry.done.wait(j).unwrap();
            }
            if j.closed {
                return j
                    .result
                    .clone()
                    .unwrap_or_else(|| Err(err("EXEC_FAILED", "Job could not start")));
            }
            let mut public = public_job(&j.data);
            public["background"] = json!(true);
            return Ok(public);
        }
        while !j.closed {
            j = entry.done.wait(j).unwrap();
        }
        j.result
            .clone()
            .unwrap_or_else(|| Err(err("EXEC_FAILED", "Missing completion")))
    }
    fn write_stdin_bounded(
        &self,
        entry: &Entry,
        text: &str,
        eof: bool,
        limit: u64,
        ctx: &ToolContext,
    ) -> Result<Value> {
        let _queue = loop {
            ctx.check()?;
            match entry.stdin_gate.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(5)),
                Err(_) => return Err(err("STDIN_FAILED", "stdin queue poisoned")),
            }
        };
        let (mut stdin, stop, total, id) = {
            let mut j = entry.job.lock().unwrap();
            if j.closed || j.stdin.is_none() {
                return Err(err("JOB_NOT_RUNNING", "stdin unavailable"));
            }
            let total = j.data["stdinBytes"].as_u64().unwrap_or(0) + text.len() as u64;
            if total > limit.min(j.data["maxStdinBytes"].as_u64().unwrap_or(65536)) {
                return Err(err("STDIN_TOO_LARGE", "Lifetime stdin exceeded"));
            }
            j.data["stdinBytes"] = json!(total);
            self.save(&j.data)?;
            (
                j.stdin.take().unwrap(),
                j.stop.clone(),
                total,
                j.data["jobId"].clone(),
            )
        };
        let mut written = 0;
        let operation = (|| -> Result<()> {
            while written < text.len() {
                ctx.check()?;
                if stop.load(Ordering::Acquire) {
                    return Err(err("CANCELLED", "stdin cancelled"));
                }
                match stdin.write(&text.as_bytes()[written..]) {
                    Ok(0) => return Err(err("STDIN_FAILED", "stdin closed")),
                    Ok(n) => written += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(err("STDIN_FAILED", "stdin write failed")),
                }
            }
            Ok(())
        })();
        let mut j = entry.job.lock().unwrap();
        match operation {
            Ok(()) => {
                if !eof && !j.closed {
                    j.stdin = Some(stdin);
                }
                Ok(json!({"jobId":id,"bytes":written,"stdinBytes":total,"eof":eof}))
            }
            Err(e) => {
                stop.store(true, Ordering::Release);
                Err(e.unknown())
            }
        }
    }
    fn append_output(
        &self,
        entry: &Entry,
        files: &mut BTreeMap<&str, File>,
        stream: &str,
        bytes: &[u8],
        ctx: &ToolContext,
        seq: &mut u64,
    ) -> Result<()> {
        let mut j = entry.job.lock().unwrap();
        let offset = j.data["outputBytes"].as_u64().unwrap_or(0);
        let cap = j.data["maxOutputBytes"].as_u64().unwrap_or(0);
        if offset + bytes.len() as u64 > cap || *seq >= 4096 {
            return Err(err("OUTPUT_TOO_LARGE", "Combined output budget exceeded"));
        }
        let combined = files.get_mut("combined").unwrap();
        combined.write_all(bytes)?;
        combined.sync_data()?;
        let output = files.get_mut(stream).unwrap();
        output.write_all(bytes)?;
        output.sync_data()?;
        let key = if stream == "stdout" {
            "stdoutBytes"
        } else {
            "stderrBytes"
        };
        j.data["outputBytes"] = json!(offset + bytes.len() as u64);
        j.data[key] = json!(j.data[key].as_u64().unwrap_or(0) + bytes.len() as u64);
        ctx.emit(json!({"type":"job_output","jobId":j.data["jobId"],"masterId":ctx.master_id,"runId":ctx.run_id,"seq":*seq,"stream":stream,"offset":offset,"bytes":bytes.len(),"base64":STANDARD.encode(bytes),"text":String::from_utf8_lossy(bytes)}));
        *seq += 1;
        Ok(())
    }
    fn supervise(
        &self,
        mut child: std::process::Child,
        mut files: BTreeMap<&str, File>,
        entry: Arc<Entry>,
        execution: Execution,
    ) {
        let Execution {
            task,
            grant,
            ctx,
            background,
        } = execution;
        let pid = child.id() as i32;
        let mut pipes: Vec<(&str, Box<dyn Read + Send>, i32)> = vec![];
        if let Some(p) = child.stdout.take() {
            let fd = p.as_raw_fd();
            unsafe {
                libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
            }
            pipes.push(("stdout", Box::new(p), fd));
        }
        if let Some(p) = child.stderr.take() {
            let fd = p.as_raw_fd();
            unsafe {
                libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK);
            }
            pipes.push(("stderr", Box::new(p), fd));
        }
        let mut error = None;
        {
            let mut j = entry.job.lock().unwrap();
            j.data["pid"] = json!(pid);
            j.data["state"] = json!(if task["args"].get("stdin").is_some() {
                "starting"
            } else {
                "running"
            });
            j.stdin = child.stdin.take();
            if let Some(stdin) = &j.stdin {
                unsafe {
                    libc::fcntl(stdin.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK);
                }
            }
            if let Err(e) = self.save(&j.data) {
                error = Some(e);
            }
            ctx.emit(json!({"type":"job_state","job":public_job(&j.data)}));
            entry.done.notify_all();
        }
        if let Some(text) = task["args"]["stdin"].as_str() {
            let manager = self.clone();
            let entry = entry.clone();
            let text = text.to_owned();
            let mut ctx = ctx.clone();
            ctx.workspace_lock = None;
            let limit=grant.raw["execCommands"][task["args"]["command"].as_str().unwrap_or("")]["maxStdinBytes"].as_u64().unwrap_or(65536);
            thread::spawn(move || {
                if manager
                    .write_stdin_bounded(&entry, &text, true, limit, &ctx)
                    .is_err()
                {
                    entry
                        .job
                        .lock()
                        .unwrap()
                        .stop
                        .store(true, Ordering::Release);
                } else {
                    let mut j = entry.job.lock().unwrap();
                    if !j.closed {
                        j.data["state"] = json!("running");
                        if manager.save(&j.data).is_err() {
                            j.stop.store(true, Ordering::Release);
                        }
                        ctx.emit(json!({"type":"job_state","job":public_job(&j.data)}));
                        entry.done.notify_all();
                    }
                }
            });
        }
        let duration = task["args"]["durationMs"]
            .as_u64()
            .unwrap_or(if background {
                grant.limit("maxJobTimeoutMs", grant.limit("maxTimeoutMs", 3600000))
            } else {
                task["timeoutMs"]
                    .as_u64()
                    .unwrap_or(grant.limit("maxTimeoutMs", 30000))
            });
        let until = Instant::now() + Duration::from_millis(duration);
        let mut seq = 0;
        let mut status = None;
        while status.is_none() {
            if error.is_none() {
                let j = entry.job.lock().unwrap();
                if j.stop.load(Ordering::Acquire) {
                    error = Some(err("CANCELLED", "Job cancelled"));
                } else if Instant::now() >= until {
                    error = Some(err("TASK_TIMEOUT", "Process duration exceeded"));
                } else if !background && let Err(e) = ctx.check() {
                    error = Some(e);
                }
            }
            if error.is_some() {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
                let _ = child.kill();
            }
            for (stream, pipe, _) in &mut pipes {
                let mut buffer = [0u8; 4096];
                loop {
                    match pipe.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            if error.is_some() {
                                break;
                            }
                            if let Err(e) = self.append_output(
                                &entry,
                                &mut files,
                                stream,
                                &buffer[..n],
                                &ctx,
                                &mut seq,
                            ) {
                                error = Some(e);
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            error = Some(e.into());
                            break;
                        }
                    }
                }
            }
            match child.try_wait() {
                Ok(s) => status = s,
                Err(e) => {
                    error = Some(e.into());
                    break;
                }
            }
            if status.is_none() {
                thread::sleep(Duration::from_millis(5));
            }
        }
        // Root close is authoritative; kill ordinary remaining descendants, then drain bounded pipes.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        if status.is_none() {
            status = child.wait().ok();
        }
        for (stream, pipe, _) in &mut pipes {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if error.is_some() {
                    break;
                }
                if let Err(e) =
                    self.append_output(&entry, &mut files, stream, &buffer[..n], &ctx, &mut seq)
                {
                    error = Some(e);
                    break;
                }
            }
        }
        for file in files.values() {
            if let Err(e) = file.sync_all() {
                error.get_or_insert(e.into());
            }
        }
        drop(files);
        drop(pipes);
        let _stdin_closed = entry.stdin_gate.lock().unwrap();
        let mut j = entry.job.lock().unwrap();
        j.stdin.take();
        let code = status.and_then(|s| s.code());
        j.data["exitCode"] = json!(code);
        j.data["finishedAt"] = json!(now());
        j.data["outcomeUnknown"] = json!(error.is_some() || code.is_none());
        j.data["state"] = json!(match error.as_ref().map(|e| e.code.as_str()) {
            Some("TASK_TIMEOUT") => "timed_out",
            Some("CANCELLED" | "SHUTTING_DOWN") => "cancelled",
            Some(_) => "failed",
            None if code == Some(0) => "succeeded",
            None => "failed",
        });
        if let Some(e) = &error {
            j.data["error"] = json!(e);
        }
        if let Err(e) = self.save(&j.data) {
            j.data["state"] = json!("unknown");
            j.data["outcomeUnknown"] = json!(true);
            error = Some(e.unknown());
            let _ = self.save(&j.data);
        }
        let id = j.data["jobId"].as_str().unwrap().to_owned();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Ok(f) = File::open(self.path(&id, "stdout")) {
            let _ = f.take(8192).read_to_end(&mut stdout);
        }
        if let Ok(f) = File::open(self.path(&id, "stderr")) {
            let _ = f.take(8192).read_to_end(&mut stderr);
        }
        j.result = Some(match error {
            Some(e) => Err(e.unknown()),
            None => Ok(
                json!({"jobId":id,"state":j.data["state"],"stdout":String::from_utf8_lossy(&stdout),"stderr":String::from_utf8_lossy(&stderr),"exitCode":code,"outcomeUnknown":j.data["outcomeUnknown"],"outputBytes":j.data["outputBytes"],"outputTruncated":j.data["stdoutBytes"].as_u64().unwrap_or(0)>8192||j.data["stderrBytes"].as_u64().unwrap_or(0)>8192}),
            ),
        });
        ctx.emit(json!({"type":"job_state","job":public_job(&j.data)}));
        // The cloned context owns the physical lock until actual process/pipes close.
        drop(ctx);
        j.closed = true;
        entry.done.notify_all();
    }
    fn output(&self, entry: &Entry, args: &Value, max_page: u64) -> Result<Value> {
        let j = entry.job.lock().unwrap();
        let id = j.data["jobId"].as_str().unwrap();
        let stream = args["stream"].as_str().unwrap_or("combined");
        if !["combined", "stdout", "stderr"].contains(&stream) {
            return Err(err("INVALID_ARGS", "Invalid output stream"));
        }
        let offset = args["offset"].as_u64().unwrap_or(0);
        let limit = args["limit"].as_u64().unwrap_or(16384);
        if limit == 0 || limit > max_page {
            return Err(err("INVALID_ARGS", "Invalid output page"));
        }
        let path = self.path(id, stream);
        safe(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.len() > j.data["maxOutputBytes"].as_u64().unwrap_or(0)
        {
            return Err(err(
                "JOB_STORE_UNSAFE",
                "Opened spool failed identity safety checks",
            ));
        }
        let total = metadata.len();
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![];
        file.take(limit).read_to_end(&mut bytes)?;
        Ok(
            json!({"jobId":id,"stream":stream,"offset":offset,"bytes":bytes.len(),"base64":STANDARD.encode(&bytes),"text":String::from_utf8_lossy(&bytes),"nextOffset":offset+bytes.len() as u64,"totalBytes":total,"eof":offset+bytes.len() as u64>=total,"state":j.data["state"],"outcomeUnknown":j.data["outcomeUnknown"]}),
        )
    }
    fn cancel(&self, entry: &Entry) -> Result<Value> {
        let mut j = entry.job.lock().unwrap();
        let accepted = !j.closed;
        if accepted {
            j.stop.store(true, Ordering::Release);
            while !j.closed {
                j = entry.done.wait(j).unwrap();
            }
        }
        Ok(
            json!({"jobId":j.data["jobId"],"accepted":accepted,"state":j.data["state"],"outcomeUnknown":j.data["outcomeUnknown"]}),
        )
    }
    pub fn run_control(&self, task: &Value, grant: &Grant, ctx: &ToolContext) -> Result<Value> {
        ctx.check()?;
        let args = &task["args"];
        let entry = self.get(
            args["jobId"]
                .as_str()
                .ok_or_else(|| err("INVALID_ARGS", "jobId required"))?,
        )?;
        {
            let j = entry.job.lock().unwrap();
            if j.data["masterId"] != ctx.master_id || j.data["workspaceId"] != ctx.workspace_id {
                return Err(err("JOB_NOT_FOUND", "No accessible job"));
            }
            if j.data["policyEpoch"] != ctx.policy_epoch {
                return Err(err(
                    "TASK_POLICY_CHANGED",
                    "Job belongs to earlier policy epoch",
                ));
            }
        }
        match task["tool"].as_str().unwrap_or("") {
            "jobStatus" => {
                let mut value = public_job(&entry.job.lock().unwrap().data);
                value.as_object_mut().unwrap().remove("reconciliationNote");
                Ok(value)
            }
            "jobOutput" => self.output(&entry, args, grant.limit("maxOutputPageBytes", 16384)),
            "jobCancel" => self.cancel(&entry),
            "jobStdin" => {
                let spec = grant.raw["execCommands"][entry.job.lock().unwrap().data["command"]
                    .as_str()
                    .unwrap_or("")]
                .clone();
                let text = args["text"]
                    .as_str()
                    .ok_or_else(|| err("INVALID_ARGS", "text required"))?;
                {
                    let j = entry.job.lock().unwrap();
                    if spec["stdinAllowed"] != true || j.data["stdinAllowed"] != true {
                        return Err(err("STDIN_DENIED", "stdin denied"));
                    }
                }
                self.write_stdin_bounded(
                    &entry,
                    text,
                    args["eof"] == true,
                    spec["maxStdinBytes"].as_u64().unwrap_or(65536),
                    ctx,
                )
            }
            _ => Err(err("UNKNOWN_TOOL", "Unknown job control")),
        }
    }
    pub fn command(&self, command: &Value) -> Result<Value> {
        let name = command["command"]
            .as_str()
            .or(command["type"].as_str())
            .unwrap_or("");
        if name == "listJobs" {
            return Ok(
                json!({"jobs":self.inner.jobs.lock().unwrap().values().map(|e|e.job.lock().unwrap().data.clone()).collect::<Vec<_>>()}),
            );
        }
        let entry = self.get(
            command["jobId"]
                .as_str()
                .ok_or_else(|| err("INVALID_ARGS", "jobId required"))?,
        )?;
        match name {
            "jobStatus" | "getJob" => Ok(public_job(&entry.job.lock().unwrap().data)),
            "jobOutput" => self.output(&entry, command, 16384),
            "cancelJob" | "jobCancel" => self.cancel(&entry),
            "reconcileJob" => {
                let note = command["note"]
                    .as_str()
                    .filter(|n| !n.trim().is_empty() && n.len() <= 2000)
                    .ok_or_else(|| err("INVALID_ARGS", "Bounded evidence note required"))?;
                let resolution = command["resolution"]
                    .as_str()
                    .filter(|r| {
                        [
                            "completed",
                            "not_applied",
                            "effects-confirmed",
                            "no-effects",
                            "effects-inspected",
                        ]
                        .contains(r)
                    })
                    .ok_or_else(|| err("INVALID_ARGS", "Explicit inspected resolution required"))?;
                let mut j = entry.job.lock().unwrap();
                if !j.closed || j.data["outcomeUnknown"] != true {
                    return Err(err(
                        "JOB_NOT_UNKNOWN",
                        "Only closed unknown jobs can reconcile",
                    ));
                }
                j.data["state"] = json!("reconciled");
                j.data["outcomeUnknown"] = json!(false);
                j.data["resolution"] = json!(resolution);
                j.data["reconciliationNote"] = json!(note);
                self.save(&j.data)?;
                Ok(public_job(&j.data))
            }
            _ => Err(err("UNKNOWN_COMMAND", "Unknown job command")),
        }
    }
    pub fn cancel_master(&self, master: &str) -> Result<()> {
        let entries = self
            .inner
            .jobs
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.job.lock().unwrap().data["masterId"] == master)
            .cloned()
            .collect::<Vec<_>>();
        for entry in entries {
            self.cancel(&entry)?;
        }
        Ok(())
    }
    pub fn cancel_all(&self) -> Result<()> {
        let entries = self
            .inner
            .jobs
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for entry in entries {
            self.cancel(&entry)?;
        }
        Ok(())
    }
    pub fn shutdown(&self) -> Result<()> {
        self.inner.stopping.store(true, Ordering::Release);
        let entries = self
            .inner
            .jobs
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for e in &entries {
            e.job.lock().unwrap().stop.store(true, Ordering::Release);
        }
        for e in entries {
            let mut j = e.job.lock().unwrap();
            while !j.closed {
                j = e.done.wait(j).unwrap();
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod execution_tests {
    use super::*;
    use crate::{model::Config, sync::SyncManager, workspaces::WorkspaceRegistry};
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt;
    fn fixture(binary: &str, args: &[&str], cap: u64) -> (tempfile::TempDir, Grant, ToolContext) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir(&root).unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let config = Config {
            raw: json!({"masters":[],"peers":[]}),
            id: "local".into(),
            host: "127.0.0.1".into(),
            port: 0,
            path: dir.path().join("config.json"),
            state_dir: state.clone(),
        };
        let file = fs::canonicalize(binary).unwrap();
        let mut spec = crate::policy::compile_approved_code(
            &json!({"file":file,"launchMode":"native","args":args}),
            "UNSAFE_EXEC_POLICY",
        )
        .unwrap();
        spec["maxArgs"] = json!(0);
        spec["env"] = json!({});
        let grant = Grant {
            root,
            tools: BTreeSet::from(["exec".into()]),
            raw: json!({"execCommands":{"approved":spec},"maxOutputBytes":cap,"maxConcurrent":1}),
            master_id: "alice".into(),
            workspace_id: "dev".into(),
            epoch: 1,
        };
        let ctx = ToolContext {
            state_dir: state.clone(),
            master_id: "alice".into(),
            workspace_id: "dev".into(),
            run_id: "test".into(),
            policy_epoch: 1,
            policy: json!({}),
            cancel: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(5),
            event_sink: None,
            jobs: Arc::new(JobManager::new(&state, 2).unwrap()),
            sync: Arc::new(SyncManager::new(&state).unwrap()),
            workspaces: Arc::new(WorkspaceRegistry::new(&state, &config).unwrap()),
            workspace_lock: None,
        };
        (dir, grant, ctx)
    }
    #[test]
    fn foreground_spools_and_control_isolates_owner_workspace_epoch() {
        let (_d, g, ctx) = fixture("/bin/echo", &["hello"], 1024);
        let result = ctx
            .jobs
            .run(
                &json!({"taskId":"one","tool":"exec","args":{"command":"approved","args":[]}}),
                &g,
                &ctx,
            )
            .unwrap();
        assert_eq!(result["stdout"], "hello\n");
        let control = json!({"tool":"jobOutput","args":{"jobId":result["jobId"],"stream":"stdout","offset":0,"limit":100}});
        assert_eq!(
            ctx.jobs.run_control(&control, &g, &ctx).unwrap()["text"],
            "hello\n"
        );
        let mut wrong = ctx.clone();
        wrong.workspace_id = "other".into();
        assert_eq!(
            ctx.jobs.run_control(&control, &g, &wrong).unwrap_err().code,
            "JOB_NOT_FOUND"
        );
        wrong.workspace_id = ctx.workspace_id.clone();
        wrong.policy_epoch = 2;
        assert_eq!(
            ctx.jobs.run_control(&control, &g, &wrong).unwrap_err().code,
            "TASK_POLICY_CHANGED"
        );
    }
    #[test]
    fn background_capacity_cancel_and_unknown_gate() {
        let (_d, g, ctx) = fixture("/bin/sleep", &["5"], 1024);
        let task = json!({"taskId":"one","tool":"exec","args":{"command":"approved","args":[],"background":true}});
        let result = ctx.jobs.run(&task, &g, &ctx).unwrap();
        assert_eq!(result["background"], true);
        assert!(result.get("root").is_none());
        assert!(result.get("maxStdinBytes").is_none());
        assert!(ctx.jobs.has_active(&g.root));
        assert_eq!(ctx.jobs.run(&task, &g, &ctx).unwrap_err().code, "BUSY");
        ctx.jobs
            .run_control(
                &json!({"tool":"jobCancel","args":{"jobId":result["jobId"]}}),
                &g,
                &ctx,
            )
            .unwrap();
        assert!(!ctx.jobs.has_active(&g.root));
        assert_eq!(
            ctx.jobs.assert_can_write("alice").unwrap_err().code,
            "OUTCOME_UNKNOWN"
        );
        ctx.jobs.shutdown().unwrap();
    }
    #[test]
    fn combined_output_overflow_kills_then_quarantines() {
        let (_d, g, ctx) = fixture("/bin/echo", &["too much output"], 2);
        let error = ctx
            .jobs
            .run(
                &json!({"tool":"exec","args":{"command":"approved","args":[]}}),
                &g,
                &ctx,
            )
            .unwrap_err();
        assert_eq!(error.code, "OUTPUT_TOO_LARGE");
        assert!(error.outcome_unknown);
        assert!(!ctx.jobs.has_active(&g.root));
        ctx.jobs.assert_can_write("alice").unwrap_err();
    }
    #[test]
    fn reservation_prevents_parallel_admission_and_releases_on_drop() {
        let (_d, g, ctx) = fixture("/bin/echo", &["hello"], 1024);
        let task = json!({"taskId":"one","tool":"exec","args":{"command":"approved","args":[]}});
        let reservation = ctx.jobs.reserve(&task, &g, &ctx).unwrap();
        assert_eq!(ctx.jobs.run(&task, &g, &ctx).unwrap_err().code, "BUSY");
        drop(reservation);
        assert_eq!(ctx.jobs.run(&task, &g, &ctx).unwrap()["stdout"], "hello\n");
    }
    #[test]
    fn background_retains_physical_lock_until_cancelled_real_close() {
        let (_d, g, mut ctx) = fixture("/bin/sleep", &["5"], 1024);
        ctx.workspace_lock = Some(Arc::new(
            crate::sync::WorkspaceLock::acquire(&g.root).unwrap(),
        ));
        let task = json!({"taskId":"one","tool":"exec","args":{"command":"approved","args":[],"background":true}});
        let result = ctx.jobs.run(&task, &g, &ctx).unwrap();
        ctx.workspace_lock.take();
        assert!(crate::sync::WorkspaceLock::acquire(&g.root).is_err());
        ctx.jobs
            .run_control(
                &json!({"tool":"jobCancel","args":{"jobId":result["jobId"]}}),
                &g,
                &ctx,
            )
            .unwrap();
        crate::sync::WorkspaceLock::acquire(&g.root).unwrap();
    }
    #[test]
    fn timeout_closes_before_releasing_active_slot() {
        let (_d, g, ctx) = fixture("/bin/sleep", &["5"], 1024);
        let error = ctx
            .jobs
            .run(
                &json!({"tool":"exec","args":{"command":"approved","args":[],"durationMs":10}}),
                &g,
                &ctx,
            )
            .unwrap_err();
        assert_eq!(error.code, "TASK_TIMEOUT");
        assert!(error.outcome_unknown);
        assert!(!ctx.jobs.has_active(&g.root));
    }
    #[test]
    fn approved_binary_change_refused_before_creating_job() {
        let code = tempfile::tempdir().unwrap();
        let binary = code.path().join("approved-binary");
        fs::copy("/bin/echo", &binary).unwrap();
        let (_d, g, ctx) = fixture(binary.to_str().unwrap(), &["hello"], 1024);
        OpenOptions::new()
            .append(true)
            .open(&binary)
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        let error = ctx
            .jobs
            .run(
                &json!({"tool":"exec","args":{"command":"approved","args":[]}}),
                &g,
                &ctx,
            )
            .unwrap_err();
        assert_eq!(error.code, "EXEC_CODE_CHANGED");
        assert_eq!(
            ctx.jobs.command(&json!({"command":"listJobs"})).unwrap()["jobs"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
    #[test]
    fn replaced_workspace_root_is_refused_before_process_spawn() {
        let (_d, mut g, ctx) = fixture("/bin/echo", &["hello"], 1024);
        let metadata = fs::metadata(&g.root).unwrap();
        g.raw["workspaceIdentity"] =
            json!({"dev":metadata.dev().to_string(),"ino":metadata.ino().to_string()});
        fs::rename(&g.root, g.root.with_extension("old")).unwrap();
        fs::create_dir(&g.root).unwrap();
        assert_eq!(
            ctx.jobs
                .run(
                    &json!({"tool":"exec","args":{"command":"approved","args":[]}}),
                    &g,
                    &ctx
                )
                .unwrap_err()
                .code,
            "WORKSPACE_DENIED"
        );
        assert_eq!(
            ctx.jobs.command(&json!({"command":"listJobs"})).unwrap()["jobs"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
    #[test]
    fn stdin_larger_than_pipe_buffer_obeys_backpressure_and_lifetime_quota() {
        let (_d, mut g, ctx) = fixture("/usr/bin/wc", &["-c"], 1024);
        // Exercise transport with a trusted grant. Production policy separately restricts native stdin.
        g.raw["execCommands"]["approved"]["stdinAllowed"] = json!(true);
        g.raw["execCommands"]["approved"]["maxStdinBytes"] = json!(65536);
        let text = "x".repeat(64000);
        let result = ctx
            .jobs
            .run(
                &json!({"tool":"exec","args":{"command":"approved","args":[],"stdin":text}}),
                &g,
                &ctx,
            )
            .unwrap();
        assert_eq!(result["stdout"].as_str().unwrap().trim(), "64000");
        let error=ctx.jobs.run(&json!({"tool":"exec","args":{"command":"approved","args":[],"stdin":"x".repeat(65537)}}),&g,&ctx).unwrap_err();
        assert_eq!(error.code, "STDIN_TOO_LARGE");
    }
}
