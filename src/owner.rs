//! Private, same-UID owner IPC for an already-running node.
use crate::{Config, IcError, Result, node::Node, wire};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufReader, Read},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
const TIMEOUT: Duration = Duration::from_secs(10);

// Transport framing remains short-lived. Only the response to a recognized
// bounded operation gets its execution budget plus room for IPC delivery.
fn response_timeout(command: &Value) -> Duration {
    let (requested, minimum) = match command["command"].as_str() {
        Some("nodesList" | "nodesStatus") => return Duration::from_secs(45),
        Some("sessionDispatch" | "dispatch") => (command["task"]["timeoutMs"].as_u64(), 10_000),
        Some("mcpCallTool") => (command["arguments"]["timeoutMs"].as_u64(), 60_000),
        Some("sessionMcp") => match command["request"]["method"].as_str() {
            Some("tools/call") => (
                command["request"]["params"]["arguments"]["timeoutMs"].as_u64(),
                60_000,
            ),
            Some("tools/list") => (None, 10_000),
            _ => return TIMEOUT,
        },
        Some("mcpListTools") => (None, 10_000),
        _ => return TIMEOUT,
    };
    let milliseconds = requested
        .unwrap_or(minimum)
        .max(minimum)
        .saturating_add(TIMEOUT.as_millis() as u64)
        .min(86_400_000);
    Duration::from_millis(milliseconds)
}

fn same_user(stream: &UnixStream) -> Result<()> {
    #[cfg(target_os = "linux")]
    let uid = unsafe {
        let mut credentials: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut len,
        ) != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        credentials.uid
    };
    #[cfg(not(target_os = "linux"))]
    let uid = unsafe {
        let mut uid = 0;
        let mut gid = 0;
        if libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        uid
    };
    if uid != unsafe { libc::geteuid() } {
        return Err(IcError::new(
            "OWNER_DENIED",
            "Owner socket requires same UID",
        ));
    }
    Ok(())
}
struct DeadlineReader {
    stream: UnixStream,
    until: Instant,
}
impl Read for DeadlineReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .until
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Owner frame timed out")
            })?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(bytes)
    }
}
pub struct Handle {
    path: PathBuf,
    inode: u64,
    stop: Arc<AtomicBool>,
    listener: Option<thread::JoinHandle<()>>,
}
impl Handle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.stop();
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && m.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
// Node holds the exclusive state lock before this endpoint is created. Only
// an owned, private socket that conclusively refuses connections is recoverable.
fn recover_stale_socket(path: &std::path::Path) -> Result<()> {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let safe = |metadata: &fs::Metadata| {
        metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.nlink() == 1
    };
    if !safe(&metadata) {
        return Err(IcError::new(
            "UNSAFE_OWNER_SOCKET",
            "Existing owner path is not a private owned single-link socket",
        ));
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(IcError::new(
            "UNSAFE_OWNER_SOCKET",
            "Owner socket path is invalid",
        ));
    }
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    #[cfg(not(target_os = "linux"))]
    {
        address.sun_len = std::mem::size_of::<libc::sockaddr_un>() as u8;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let probe = unsafe { UnixStream::from_raw_fd(fd) };
    if unsafe { libc::fcntl(probe.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    probe.set_nonblocking(true)?;
    // Any successful or pending connection means the socket must be preserved.
    let connected = unsafe {
        libc::connect(
            probe.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if connected == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ECONNREFUSED)
    {
        return Err(IcError::new(
            "OWNER_SOCKET_IN_USE",
            "Owner socket is live or could not be safely classified",
        ));
    }
    let current = fs::symlink_metadata(path)?;
    if !safe(&current) || current.dev() != metadata.dev() || current.ino() != metadata.ino() {
        return Err(IcError::new(
            "UNSAFE_OWNER_SOCKET",
            "Owner socket changed during recovery",
        ));
    }
    fs::remove_file(path)?;
    Ok(())
}

pub fn start(node: Arc<Node>) -> Result<Handle> {
    let directory = node.config().state_dir;
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || fs::canonicalize(&directory)? != directory
    {
        return Err(IcError::new(
            "UNSAFE_OWNER_DIRECTORY",
            "Owner state directory must be private and owned",
        ));
    }
    let path = directory.join("owner.sock");
    recover_stale_socket(&path)?;
    let listener = UnixListener::bind(&path)?;
    let mut handle = Handle {
        inode: fs::symlink_metadata(&path)?.ino(),
        path,
        stop: Arc::new(AtomicBool::new(false)),
        listener: None,
    };
    fs::set_permissions(&handle.path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let stop = handle.stop.clone();
    let active = Arc::new(AtomicUsize::new(0));
    handle.listener = Some(thread::spawn(move || {
        let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
        while !stop.load(Ordering::Acquire) {
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let _ = workers.swap_remove(i).join();
                } else {
                    i += 1;
                }
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if active.load(Ordering::Acquire) >= 16
                        || stream.set_nonblocking(false).is_err()
                        || same_user(&stream).is_err()
                    {
                        continue;
                    }
                    active.fetch_add(1, Ordering::AcqRel);
                    let active = active.clone();
                    let node = node.clone();
                    let stop = stop.clone();
                    workers.push(thread::spawn(move || {
                        let result = (|| -> Result<Value> {
                            stream.set_write_timeout(Some(TIMEOUT))?;
                            let mut reader = BufReader::new(DeadlineReader {
                                stream: stream.try_clone()?,
                                until: Instant::now() + TIMEOUT,
                            });
                            let command = wire::read_frame(&mut reader)?.ok_or_else(|| {
                                IcError::new("INVALID_FRAME", "Owner command required")
                            })?;
                            if stop.load(Ordering::Acquire) {
                                return Err(IcError::new("STOPPING", "Owner endpoint is stopping"));
                            }
                            node.owner_request(&command)
                        })();
                        let response = match result {
                            Ok(result) => json!({"ok":true,"result":result}),
                            Err(error) => json!({"ok":false,"error":error}),
                        };
                        let _ = wire::write_frame(&mut stream, &response);
                        active.fetch_sub(1, Ordering::AcqRel);
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(_) => break,
            }
        }
        for worker in workers {
            let _ = worker.join();
        }
    }));
    Ok(handle)
}
pub fn request(config: &Config, command: &Value) -> Result<Value> {
    if !command.is_object() || command["command"].as_str().is_none_or(str::is_empty) {
        return Err(IcError::new(
            "INVALID_ARGS",
            "Owner command requires a command string",
        ));
    }
    let path = config.state_dir.join("owner.sock");
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(IcError::new(
            "UNSAFE_OWNER_SOCKET",
            "Owner socket must be private and owned",
        ));
    }
    let mut stream = UnixStream::connect(path)?;
    same_user(&stream)?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    wire::write_frame(&mut stream, command)?;
    let mut reader = BufReader::new(DeadlineReader {
        stream,
        until: Instant::now() + response_timeout(command),
    });
    let response = wire::read_frame(&mut reader)?
        .ok_or_else(|| IcError::new("INVALID_FRAME", "Missing owner response"))?;
    if response["ok"] == true {
        Ok(response["result"].clone())
    } else {
        let mut error = IcError::new(
            response["error"]["code"].as_str().unwrap_or("OWNER_ERROR"),
            response["error"]["message"]
                .as_str()
                .unwrap_or("Owner command failed"),
        );
        error.outcome_unknown = response["error"]["outcomeUnknown"] == true;
        Err(error)
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[test]
    fn response_budget_tracks_only_execution_timeouts_and_remains_bounded() {
        assert_eq!(
            response_timeout(
                &json!({"command":"sessionMcp","request":{"method":"tools/call","params":{"arguments":{"timeoutMs":60000}}}})
            ),
            Duration::from_secs(70)
        );
        assert_eq!(
            response_timeout(&json!({"command":"sessionDispatch","task":{"timeoutMs":60000}})),
            Duration::from_secs(70)
        );
        assert_eq!(
            response_timeout(&json!({"command":"mcpCallTool","arguments":{"timeoutMs":60000}})),
            Duration::from_secs(70)
        );
        assert_eq!(
            response_timeout(
                &json!({"command":"sessionMcp","request":{"method":"tools/call","params":{"arguments":{"timeoutMs":u64::MAX}}}})
            ),
            Duration::from_secs(86400)
        );
        assert_eq!(
            response_timeout(&json!({"command":"sessionMcp","request":{"method":"tools/call"}})),
            Duration::from_secs(70)
        );
        assert_eq!(
            response_timeout(&json!({"command":"status","timeoutMs":u64::MAX})),
            TIMEOUT
        );
        assert_eq!(
            response_timeout(
                &json!({"command":"sessionMcp","request":{"method":"ping","params":{"arguments":{"timeoutMs":u64::MAX}}}})
            ),
            TIMEOUT
        );
    }

    #[test]
    fn node_health_response_has_a_fixed_bounded_probe_budget() {
        for command in ["nodesList", "nodesStatus"] {
            assert_eq!(
                response_timeout(&json!({"command":command})),
                Duration::from_secs(45)
            );
            assert_eq!(
                response_timeout(&json!({"command":command,"timeoutMs":u64::MAX})),
                Duration::from_secs(45)
            );
        }
    }

    #[test]
    fn owner_peer_credentials_accept_same_uid() {
        let (one, two) = UnixStream::pair().unwrap();
        same_user(&one).unwrap();
        same_user(&two).unwrap();
    }
}
