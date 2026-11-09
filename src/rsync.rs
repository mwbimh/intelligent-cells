//! Fixed, pinned rsync subprocesses transported only through IC's authenticated session.
use crate::{IcError, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use openssl::ssl::SslStream;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHUNK: usize = 16384;
const MAX_WIRE: u64 = 256 * 1024 * 1024;
const MAX_STDERR: usize = 65536;
fn fail(message: impl Into<String>) -> IcError {
    IcError::new("RSYNC_FAILED", message)
}
#[derive(Clone, Debug)]
pub struct Settings {
    pub file: PathBuf,
    pub sha256: String,
}
impl Settings {
    pub fn parse(raw: &Value) -> Result<Option<Self>> {
        let invalid = |message: &str| IcError::new("INVALID_CONFIG", message);
        let Some(sync) = raw.get("sync") else {
            return Ok(None);
        };
        let obj = sync
            .as_object()
            .ok_or_else(|| invalid("sync must be an object"))?;
        if obj.keys().any(|k| k != "backend" && k != "rsync") {
            return Err(invalid("Unknown sync setting"));
        }
        match sync["backend"].as_str() {
            Some("native") if obj.len() == 1 => Ok(None),
            Some("rsync") => {
                let r = sync["rsync"]
                    .as_object()
                    .ok_or_else(|| invalid("rsync executable pin required"))?;
                if r.len() != 2 || r.keys().any(|k| k != "file" && k != "sha256") {
                    return Err(invalid("Only rsync file and sha256 are allowed"));
                }
                let file = sync["rsync"]["file"]
                    .as_str()
                    .filter(|s| !s.contains('\0') && Path::new(s).is_absolute())
                    .ok_or_else(|| invalid("rsync file must be absolute"))?;
                let pin = sync["rsync"]["sha256"]
                    .as_str()
                    .filter(|s| {
                        s.len() == 64
                            && s.bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                    .ok_or_else(|| invalid("Canonical SHA-256 pin required"))?;
                Ok(Some(Self {
                    file: file.into(),
                    sha256: pin.into(),
                }))
            }
            _ => Err(invalid("sync backend must be native or rsync")),
        }
    }
    fn validate_file(&self) -> Result<()> {
        if fs::canonicalize(&self.file)? != self.file {
            return Err(fail("Noncanonical rsync executable"));
        }
        let mut f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.file)?;
        let m = f.metadata()?;
        let euid = unsafe { libc::geteuid() };
        if !m.is_file()
            || m.nlink() != 1
            || m.mode() & 0o022 != 0
            || m.mode() & 0o111 == 0
            || (m.uid() != 0 && m.uid() != euid)
            || m.len() > 64 * 1024 * 1024
        {
            return Err(fail("Unsafe rsync executable identity"));
        }
        let mut h = Sha256::new();
        let mut buf = [0u8; 16384];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        let after = f.metadata()?;
        let path = fs::symlink_metadata(&self.file)?;
        let identity = |m: &fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
                m.mode(),
                m.nlink(),
            )
        };
        if identity(&m) != identity(&after)
            || identity(&m) != identity(&path)
            || hex::encode(h.finalize()) != self.sha256
        {
            return Err(fail("rsync executable changed or SHA-256 pin mismatch"));
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_file()?;
        let mut c = command(self);
        c.arg("--version");
        let mut child = c.spawn()?;
        let result = version_output(&mut child);
        if result.is_err() {
            terminate(&mut child)
        }
        let output = result?;
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        if !version_supported(&output) {
            return Err(fail("rsync >= 3.4.1 required"));
        }
        Ok(())
    }
}
fn command(settings: &Settings) -> Command {
    let mut c = Command::new(&settings.file);
    c.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Enforce the existing snapshot single-file bound in the operating system,
    // including bytes written by the receiver before stage verification.
    unsafe {
        c.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 64 * 1024 * 1024,
                rlim_max: 64 * 1024 * 1024,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn terminate(c: &mut Child) {
    unsafe {
        libc::kill(-(c.id() as i32), libc::SIGKILL);
    }
    let _ = c.kill();
    let _ = c.wait();
}
fn version_supported(output: &str) -> bool {
    let words: Vec<_> = output
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    if words.first() != Some(&"rsync") {
        return false;
    }
    let Some(i) = words.iter().position(|w| *w == "version") else {
        return false;
    };
    let Some(v) = words.get(i + 1) else {
        return false;
    };
    let parts: Vec<_> = v.split('.').map(str::parse::<u32>).collect();
    if parts.len() != 3 {
        return false;
    }
    match (&parts[0], &parts[1], &parts[2]) {
        (Ok(a), Ok(b), Ok(c)) => (*a, *b, *c) >= (3, 4, 1),
        _ => false,
    }
}
fn version_output(c: &mut Child) -> Result<String> {
    drop(c.stdin.take());
    let mut out = c.stdout.take().unwrap();
    let mut err = c.stderr.take().unwrap();
    nonblocking(out.as_raw_fd())?;
    nonblocking(err.as_raw_fd())?;
    let end = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::new();
    let mut stderr = Vec::new();
    let mut oe = false;
    let mut ee = false;
    loop {
        drain(&mut out, &mut bytes, &mut oe, 16384)?;
        drain(&mut err, &mut stderr, &mut ee, 16384)?;
        if let Some(status) = c.try_wait()?
            && oe
            && ee
        {
            if !status.success() {
                return Err(fail("rsync --version failed"));
            }
            return String::from_utf8(bytes).map_err(|_| fail("Invalid version output"));
        }
        if Instant::now() >= end {
            return Err(fail("rsync version check timeout"));
        }
        thread::sleep(Duration::from_millis(2));
    }
}
fn drain(input: &mut impl Read, dst: &mut Vec<u8>, eof: &mut bool, max: usize) -> Result<()> {
    if *eof {
        return Ok(());
    }
    let mut buf = [0; 4096];
    loop {
        match input.read(&mut buf) {
            Ok(0) => {
                *eof = true;
                break;
            }
            Ok(n) => {
                if dst.len() + n > max {
                    return Err(fail("rsync output limit exceeded"));
                }
                dst.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
/// Only immutable, owner-private staging directories may be passed here.
pub struct Process {
    child: Child,
    socket: Option<UnixStream>,
    finished: bool,
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.finished {
            terminate(&mut self.child);
        }
    }
}
fn helper_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let mut parent = exe
        .parent()
        .ok_or_else(|| fail("Missing IC binary directory"))?;
    if parent.file_name().is_some_and(|v| v == "deps") {
        parent = parent
            .parent()
            .ok_or_else(|| fail("Missing IC binary directory"))?;
    }
    let helper = parent.join("ic-rsync-stdio");
    let m = fs::symlink_metadata(&helper)?;
    if fs::canonicalize(&helper)? != helper
        || !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o022 != 0
        || m.mode() & 0o111 == 0
        || (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() })
    {
        return Err(fail("Unsafe IC rsync stdio companion"));
    }
    Ok(helper)
}
pub fn spawn(settings: &Settings, stage: &Path, sender: bool) -> Result<Process> {
    settings.validate_file()?;
    let m = fs::symlink_metadata(stage)?;
    if fs::canonicalize(stage)? != stage
        || !m.is_dir()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        return Err(fail("Unsafe rsync stage"));
    }
    let mut c = command(settings);
    c.current_dir(stage);
    let mut socket = None;
    if sender {
        let helper = helper_binary()?;
        let helper = helper
            .to_str()
            .filter(|v| !v.contains(['"', '\\', '\n', '\r']))
            .ok_or_else(|| fail("Unsupported companion path"))?;
        let (parent, remote) = UnixStream::pair()?;
        let inherited = remote.as_raw_fd();
        unsafe {
            c.pre_exec(move || {
                if inherited != 3 && libc::dup2(inherited, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        c.arg(format!("--rsh=\"{helper}\" --fd 3"));
        c.args([
            "-r",
            "--checksum",
            "--compress",
            "--compress-choice=zlib",
            "--no-whole-file",
            "--chmod=F600",
            "./",
            "ic-peer:./",
        ]);
        let child = c.spawn()?;
        drop(remote);
        socket = Some(parent);
        return Ok(Process {
            child,
            socket,
            finished: false,
        });
    }
    c.arg("--server");
    c.args([
        "-r",
        "--checksum",
        "--compress",
        "--compress-choice=zlib",
        "--no-whole-file",
        "--chmod=F600",
        ".",
        "./",
    ]);
    Ok(Process {
        child: c.spawn()?,
        socket,
        finished: false,
    })
}
fn bridge_args_valid(args: &[String]) -> bool {
    args.len() >= 7
        && args.len() <= 32
        && args[0] == "--fd"
        && args[1] == "3"
        && args[2] == "ic-peer"
        && args[3] == "rsync"
        && args[4] == "--server"
        && args.iter().all(|v| v.len() <= 256 && !v.contains('\0'))
        && args[5..args.len() - 2]
            .iter()
            .all(|v| v.starts_with('-') && v != "--sender")
        && args[args.len() - 2] == "."
        && args[args.len() - 1] == "./"
}
/// Invoked only by rsync's fixed remote-shell argv; never executes its remote command arguments.
pub fn stdio_bridge(args: &[String]) -> Result<()> {
    if !bridge_args_valid(args) {
        return Err(fail("Invalid IC rsync stdio invocation"));
    }
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            3,
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    } != 0
        || address.ss_family as i32 != libc::AF_UNIX
    {
        return Err(fail("Inherited local rsync socket required"));
    }
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, 3] {
        nonblocking(fd)?;
    }
    let mut socket = unsafe { UnixStream::from_raw_fd(3) };
    let mut stdin = unsafe { fs::File::from_raw_fd(libc::STDIN_FILENO) };
    let mut stdout = unsafe { fs::File::from_raw_fd(libc::STDOUT_FILENO) };
    let mut to_socket = Vec::new();
    let mut socket_offset = 0;
    let mut to_stdout = Vec::new();
    let mut stdout_offset = 0;
    let mut stdin_eof = false;
    let mut remote_eof = false;
    let mut write_closed = false;
    let mut total = 0u64;
    loop {
        if !remote_eof && to_stdout.is_empty() {
            let mut b = [0; CHUNK];
            match socket.read(&mut b) {
                Ok(0) => remote_eof = true,
                Ok(n) => {
                    to_stdout.extend_from_slice(&b[..n]);
                    total += n as u64;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !to_stdout.is_empty() {
            match stdout.write(&to_stdout[stdout_offset..]) {
                Ok(0) => return Err(fail("rsync client stdout closed")),
                Ok(n) => stdout_offset += n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
            if stdout_offset == to_stdout.len() {
                to_stdout.clear();
                stdout_offset = 0;
            }
        }
        // Remote EOF means the receiver has ended its protocol. The client
        // waits for this helper to exit before closing its inherited fd 3.
        if remote_eof && to_stdout.is_empty() {
            return Ok(());
        }
        if !stdin_eof && to_socket.is_empty() {
            let mut b = [0; CHUNK];
            match stdin.read(&mut b) {
                Ok(0) => stdin_eof = true,
                Ok(n) => {
                    to_socket.extend_from_slice(&b[..n]);
                    total += n as u64;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !to_socket.is_empty() {
            match socket.write(&to_socket[socket_offset..]) {
                Ok(0) => return Err(fail("rsync protocol socket closed")),
                Ok(n) => socket_offset += n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
            if socket_offset == to_socket.len() {
                to_socket.clear();
                socket_offset = 0;
            }
        }
        if stdin_eof && to_socket.is_empty() && !write_closed {
            socket.shutdown(Shutdown::Write)?;
            write_closed = true;
        }
        if total > MAX_WIRE {
            return Err(fail("rsync stdio wire limit exceeded"));
        }
        thread::sleep(Duration::from_millis(1));
    }
}
enum Input {
    Pipe(ChildStdin),
    Socket(UnixStream),
}
impl AsRawFd for Input {
    fn as_raw_fd(&self) -> i32 {
        match self {
            Self::Pipe(v) => v.as_raw_fd(),
            Self::Socket(v) => v.as_raw_fd(),
        }
    }
}
impl Write for Input {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Pipe(v) => v.write(b),
            Self::Socket(v) => v.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Input {
    fn close(self) {
        if let Self::Socket(v) = self {
            let _ = v.shutdown(Shutdown::Write);
        }
    }
}
enum Output {
    Pipe(ChildStdout),
    Socket(UnixStream),
}
impl AsRawFd for Output {
    fn as_raw_fd(&self) -> i32 {
        match self {
            Self::Pipe(v) => v.as_raw_fd(),
            Self::Socket(v) => v.as_raw_fd(),
        }
    }
}
impl Read for Output {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Pipe(v) => v.read(b),
            Self::Socket(v) => v.read(b),
        }
    }
}
#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub transmitted_bytes: u64,
    pub received_bytes: u64,
}
fn decode_frame(frame: &Value, task_id: &str) -> Result<Option<Vec<u8>>> {
    let o = frame
        .as_object()
        .ok_or_else(|| fail("Invalid rsync frame"))?;
    if frame["taskId"] != task_id {
        return Err(fail("rsync task identity mismatch"));
    }
    match frame["type"].as_str() {
        Some("rsync_eof") if o.len() == 2 => Ok(None),
        Some("rsync_data") if o.len() == 3 => {
            let s = frame["base64"]
                .as_str()
                .filter(|s| s.len() <= 4 * CHUNK.div_ceil(3))
                .ok_or_else(|| fail("Invalid rsync data size"))?;
            let bytes = STANDARD
                .decode(s)
                .map_err(|_| fail("Invalid rsync base64"))?;
            if bytes.is_empty() || bytes.len() > CHUNK || STANDARD.encode(&bytes) != s {
                return Err(fail("Invalid rsync data"));
            }
            Ok(Some(bytes))
        }
        _ => {
            let mut detail = frame.to_string();
            if detail.len() > 2048 {
                let mut end = 2048;
                while !detail.is_char_boundary(end) {
                    end -= 1;
                }
                detail.truncate(end);
            }
            Err(fail(format!("Unexpected rsync stream frame: {detail}")))
        }
    }
}
pub fn transfer(
    reader: &mut BufReader<SslStream<TcpStream>>,
    mut process: Process,
    task_id: &str,
    check: &dyn Fn() -> Result<()>,
) -> Result<Stats> {
    let setup = reader.get_ref().get_ref().set_nonblocking(true);
    let result = setup
        .map_err(IcError::from)
        .and_then(|_| pump(reader, &mut process, task_id, check));
    if result.is_err() {
        terminate(&mut process.child)
    }
    process.finished = true;
    let restored = reader.get_ref().get_ref().set_nonblocking(false);
    result.and_then(|stats| {
        restored?;
        Ok(stats)
    })
}
fn pump(
    reader: &mut BufReader<SslStream<TcpStream>>,
    process: &mut Process,
    task_id: &str,
    check: &dyn Fn() -> Result<()>,
) -> Result<Stats> {
    let child = &mut process.child;
    let mut diagnostics = None;
    let (input, mut output) = if let Some(socket) = process.socket.take() {
        drop(child.stdin.take());
        diagnostics = child.stdout.take();
        (Input::Socket(socket.try_clone()?), Output::Socket(socket))
    } else {
        (
            Input::Pipe(
                child
                    .stdin
                    .take()
                    .ok_or_else(|| fail("Missing rsync stdin"))?,
            ),
            Output::Pipe(
                child
                    .stdout
                    .take()
                    .ok_or_else(|| fail("Missing rsync stdout"))?,
            ),
        )
    };
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| fail("Missing rsync stderr"))?;
    nonblocking(input.as_raw_fd())?;
    nonblocking(output.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    if let Some(v) = &diagnostics {
        nonblocking(v.as_raw_fd())?;
    }
    let mut input = Some(input);
    let mut outbound = Vec::new();
    let mut sent = 0usize;
    let mut inbound = Vec::new();
    let mut delivered = 0usize;
    let mut frame = Vec::new();
    let mut errors = Vec::new();
    let mut err_eof = false;
    let mut diag_eof = diagnostics.is_none();
    let mut diag_bytes = Vec::new();
    let mut out_eof = false;
    let mut eof_sent = false;
    let mut peer_eof = false;
    let mut status = None;
    let mut stats = Stats::default();
    let mut wire_bytes = 0u64;
    loop {
        if let Err(mut error) = check() {
            error.message = format!(
                "{}; rsync tx={} rx={} stdoutEof={} peerEof={} eofSent={} childExited={} stderrBytes={} pendingInput={} pendingOutput={}",
                error.message,
                stats.transmitted_bytes,
                stats.received_bytes,
                out_eof,
                peer_eof,
                eof_sent,
                status.is_some(),
                errors.len(),
                inbound.len().saturating_sub(delivered),
                outbound.len().saturating_sub(sent)
            );
            return Err(error);
        }
        drain(&mut stderr, &mut errors, &mut err_eof, MAX_STDERR)?;
        if let Some(v) = &mut diagnostics {
            drain(v, &mut diag_bytes, &mut diag_eof, MAX_STDERR)?;
        }
        if delivered < inbound.len() {
            let writer = input
                .as_mut()
                .ok_or_else(|| fail("Data after rsync stdin EOF"))?;
            match writer.write(&inbound[delivered..]) {
                Ok(0) => return Err(fail("rsync stdin closed")),
                Ok(n) => delivered += n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
            if delivered == inbound.len() {
                inbound.clear();
                delivered = 0;
            }
        }
        if peer_eof
            && inbound.is_empty()
            && let Some(v) = input.take()
        {
            v.close();
        }
        if outbound.is_empty() && !out_eof {
            let mut buf = [0; CHUNK];
            match output.read(&mut buf) {
                Ok(0) => {
                    out_eof = true;
                    outbound = serde_json::to_vec(&json!({"type":"rsync_eof","taskId":task_id}))?;
                    outbound.push(b'\n');
                }
                Ok(n) => {
                    stats.transmitted_bytes += n as u64;
                    outbound = serde_json::to_vec(
                        &json!({"type":"rsync_data","taskId":task_id,"base64":STANDARD.encode(&buf[..n])}),
                    )?;
                    outbound.push(b'\n');
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !outbound.is_empty() {
            match reader.get_mut().write(&outbound[sent..]) {
                Ok(0) => return Err(fail("rsync TLS stream closed")),
                Ok(n) => {
                    sent += n;
                    wire_bytes += n as u64;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
            if sent == outbound.len() {
                outbound.clear();
                sent = 0;
                if out_eof {
                    eof_sent = true;
                }
            }
        }
        // BufReader may already hold a following ordinary task result; never consume it after EOF.
        if !peer_eof && inbound.is_empty() {
            loop {
                let data = match reader.fill_buf() {
                    Ok([]) => return Err(fail("Truncated rsync stream")),
                    Ok(b) => b,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::Interrupted =>
                    {
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };
                let n = data
                    .iter()
                    .position(|b| *b == b'\n')
                    .map(|n| n + 1)
                    .unwrap_or(data.len());
                if frame.len() + n > 32768 {
                    return Err(fail("rsync frame limit exceeded"));
                }
                frame.extend_from_slice(&data[..n]);
                reader.consume(n);
                wire_bytes += n as u64;
                if frame.last() == Some(&b'\n') {
                    let v = crate::wire::read_frame(&mut std::io::Cursor::new(&frame))?
                        .ok_or_else(|| fail("Empty rsync stream frame"))?;
                    frame.clear();
                    match decode_frame(&v, task_id)? {
                        Some(data) => {
                            stats.received_bytes += data.len() as u64;
                            inbound = data;
                        }
                        None => peer_eof = true,
                    };
                    break;
                }
            }
        }
        if wire_bytes > MAX_WIRE {
            return Err(fail("rsync wire limit exceeded"));
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        if let Some(s) = status {
            if !s.success() {
                return Err(fail(format!(
                    "rsync exited {s}: {}",
                    String::from_utf8_lossy(&errors[..errors.len().min(2048)])
                )));
            }
            if eof_sent && peer_eof && inbound.is_empty() && err_eof && diag_eof {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                return Ok(stats);
            }
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn stdio_companion_accepts_only_fixed_remote_shell_shape() {
        let args: Vec<String> = [
            "--fd",
            "3",
            "ic-peer",
            "rsync",
            "--server",
            "-rze.iLsfxCIvu",
            "--compress-choice=zlib",
            "--chmod=F600",
            ".",
            "./",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        assert!(bridge_args_valid(&args));
        for (index, value) in [
            (1, "4"),
            (2, "other"),
            (3, "sh"),
            (4, "--sender"),
            (5, "/tmp/command"),
            (9, "/tmp/workspace"),
        ] {
            let mut bad = args.clone();
            bad[index] = value.into();
            assert!(!bridge_args_valid(&bad));
        }
    }
    #[test]
    fn strict_backend_settings() {
        assert!(Settings::parse(&json!({})).unwrap().is_none());
        assert!(
            Settings::parse(&json!({"sync":{"backend":"native"}}))
                .unwrap()
                .is_none()
        );
        for sync in [
            json!({}),
            json!({"backend":"other"}),
            json!({"backend":"native","rsync":{}}),
            json!({"backend":"rsync"}),
            json!({"backend":"rsync","rsync":{"file":"rsync","sha256":"a".repeat(64)}}),
            json!({"backend":"rsync","rsync":{"file":"/bin/rsync","sha256":"X".repeat(64)}}),
            json!({"backend":"native","unknown":1}),
        ] {
            assert!(Settings::parse(&json!({"sync":sync})).is_err(), "{sync}");
        }
        assert!(Settings::parse(&json!({"sync":{"backend":"rsync","rsync":{"file":"/bin/rsync","sha256":"a".repeat(64)}}})).unwrap().is_some());
    }
    #[test]
    fn minimum_version_is_checked_numerically() {
        for v in [
            "rsync  version 3.4.1  protocol version 32",
            "rsync version 3.10.0 protocol version 32",
        ] {
            assert!(version_supported(v));
        }
        for v in [
            "rsync version 3.4.0",
            "rsync version 2.6.9",
            "other version 9.9.9",
            "rsync version x",
        ] {
            assert!(!version_supported(v));
        }
    }
    #[test]
    fn wire_frames_bind_task_and_bound_content() {
        assert_eq!(
            decode_frame(
                &json!({"type":"rsync_data","taskId":"a","base64":"YQ=="}),
                "a"
            )
            .unwrap(),
            Some(vec![b'a'])
        );
        for v in [
            json!({"type":"rsync_data","taskId":"b","base64":"YQ=="}),
            json!({"type":"rsync_data","taskId":"a","base64":"YQ"}),
            json!({"type":"rsync_eof","taskId":"a","extra":1}),
            json!({"type":"result","taskId":"a"}),
        ] {
            assert!(decode_frame(&v, "a").is_err());
        }
        let b64 = STANDARD.encode(vec![0; CHUNK + 1]);
        assert!(
            decode_frame(&json!({"type":"rsync_data","taskId":"a","base64":b64}), "a").is_err()
        );
    }
    #[test]
    fn executable_identity_rejects_links_before_launch() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("rsync");
        std::fs::write(&p, b"no process").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pin = hex::encode(Sha256::digest(b"no process"));
        std::fs::hard_link(&p, d.path().join("link")).unwrap();
        assert!(
            Settings {
                file: p,
                sha256: pin
            }
            .validate()
            .is_err()
        );
    }
}
