use crate::{Grant, IcError, Result, context::ToolContext, policy};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    ffi::{CStr, CString},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};

fn denied(message: &str) -> IcError {
    IcError::new("PATH_DENIED", message)
}
fn cstring(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| denied("NUL in path"))
}
fn fd_open(parent: i32, name: &CStr, flags: i32, mode: u32) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) {
            return Err(denied("Path contains a link or non-directory"));
        }
        return Err(e.into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub fn inspect_root(root: &Path) -> Result<()> {
    if !root.is_absolute() {
        return Err(denied("Workspace must be absolute"));
    }
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || fs::canonicalize(root)? != root {
        return Err(denied("Workspace is not a canonical directory"));
    }
    Ok(())
}
fn root_fd(root: &Path) -> Result<File> {
    inspect_root(root)?;
    let expected = fs::symlink_metadata(root)?;
    let mut file = fd_open(
        libc::AT_FDCWD,
        &cstring(b"/")?,
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    for component in root.components() {
        if let std::path::Component::Normal(name) = component {
            file = fd_open(
                file.as_raw_fd(),
                &cstring(name.as_bytes())?,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
        }
    }
    let actual = file.metadata()?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err(denied("Workspace changed"));
    }
    inspect_root(root)?;
    Ok(file)
}
fn directory_fd(root: &Path, name: &str) -> Result<File> {
    let mut dir = root_fd(root)?;
    if !name.is_empty() {
        policy::relative_path(name)?;
        for component in name.split('/') {
            dir = fd_open(
                dir.as_raw_fd(),
                &cstring(component.as_bytes())?,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
        }
    }
    Ok(dir)
}
type DirectoryIdentity = (PathBuf, u64, u64);
type DirectorySnapshot = Vec<DirectoryIdentity>;

struct Target {
    parent: File,
    name: CString,
    original: Option<libc::stat>,
    directories: DirectorySnapshot,
}
fn directory_snapshot(root: &Path, name: &str) -> Result<DirectorySnapshot> {
    inspect_root(root)?;
    let mut path = root.to_path_buf();
    let mut output = Vec::new();
    let meta = fs::symlink_metadata(&path)?;
    output.push((path.clone(), meta.dev(), meta.ino()));
    if !name.is_empty() {
        for part in name.split('/') {
            path.push(part);
            let meta = fs::symlink_metadata(&path)?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(denied("Parent is not a real directory"));
            }
            output.push((path.clone(), meta.dev(), meta.ino()));
        }
    }
    Ok(output)
}
fn verify_directories(snapshot: &[DirectoryIdentity]) -> Result<()> {
    for (path, dev, ino) in snapshot {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.dev() != *dev
            || meta.ino() != *ino
            || fs::canonicalize(path)? != *path
        {
            return Err(denied("Parent directory changed during operation"));
        }
    }
    Ok(())
}
fn pinned_directory(root: &Path, name: &str) -> Result<(File, DirectorySnapshot)> {
    if !name.is_empty() {
        policy::relative_path(name)?
    }
    let snapshot = directory_snapshot(root, name)?;
    let dir = directory_fd(root, name)?;
    verify_directories(&snapshot)?;
    let meta = dir.metadata()?;
    let (_, dev, ino) = snapshot.last().unwrap();
    if meta.dev() != *dev || meta.ino() != *ino {
        return Err(denied("Directory changed while opening"));
    }
    Ok((dir, snapshot))
}
fn stat_at(parent: &File, name: &CStr) -> Result<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(e.into());
    }
    Ok(Some(unsafe { stat.assume_init() }))
}
fn regular(stat: &libc::stat) -> Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
        Err(denied("Only regular non-linked files are allowed"))
    } else {
        Ok(())
    }
}
fn target(root: &Path, name: &str, allow_missing: bool) -> Result<Target> {
    policy::relative_path(name)?;
    let (parent, leaf) = name.rsplit_once('/').unwrap_or(("", name));
    let directories = directory_snapshot(root, parent)?;
    let parent = directory_fd(root, parent)?;
    verify_directories(&directories)?;
    let actual = parent.metadata()?;
    let (_, dev, ino) = directories.last().unwrap();
    if actual.dev() != *dev || actual.ino() != *ino {
        return Err(denied("Parent directory changed while opening"));
    }
    let leaf = cstring(leaf.as_bytes())?;
    let original = stat_at(&parent, &leaf)?;
    if original.is_none() && !allow_missing {
        return Err(IcError::new("ENOENT", "File does not exist"));
    }
    if let Some(stat) = &original {
        regular(stat)?
    }
    Ok(Target {
        parent,
        name: leaf,
        original,
        directories,
    })
}
pub fn checked_path(root: &Path, relative: &str, allow_missing: bool) -> Result<PathBuf> {
    if relative.is_empty() {
        inspect_root(root)?;
        return Ok(root.to_path_buf());
    }
    policy::relative_path(relative)?;
    let (parent, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
    let dir = directory_fd(root, parent)?;
    match stat_at(&dir, &cstring(leaf.as_bytes())?)? {
        None if !allow_missing => return Err(IcError::new("ENOENT", "Path does not exist")),
        Some(s) if s.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
        Some(s) => regular(&s)?,
        _ => {}
    }
    Ok(root.join(relative))
}
fn verify(t: &Target) -> Result<()> {
    verify_directories(&t.directories)?;
    let now = stat_at(&t.parent, &t.name)?;
    match (&t.original, now) {
        (None, None) => Ok(()),
        (Some(a), Some(b))
            if a.st_dev == b.st_dev
                && a.st_ino == b.st_ino
                && a.st_size == b.st_size
                && a.st_mtime == b.st_mtime
                && a.st_mtime_nsec == b.st_mtime_nsec
                && a.st_ctime == b.st_ctime
                && a.st_ctime_nsec == b.st_ctime_nsec =>
        {
            regular(&b)
        }
        _ => Err(denied("File changed during operation")),
    }
}
fn read_target(t: &Target, max: u64, check: &dyn Fn() -> Result<()>) -> Result<Vec<u8>> {
    check()?;
    let mut file = fd_open(t.parent.as_raw_fd(), &t.name, libc::O_RDONLY, 0)?;
    let meta = file.metadata()?;
    let old = t
        .original
        .as_ref()
        .ok_or_else(|| IcError::new("ENOENT", "Missing file"))?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.dev() != old.st_dev as u64
        || meta.ino() != old.st_ino
    {
        return Err(denied("File changed while opening"));
    }
    if meta.len() > max {
        return Err(IcError::new(
            "FILE_TOO_LARGE",
            "File exceeds local byte limit",
        ));
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    let mut buffer = [0; 65536];
    loop {
        check()?;
        let bytes = file.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        if data.len() as u64 + bytes as u64 > max {
            return Err(IcError::new(
                "FILE_TOO_LARGE",
                "File exceeds local byte limit",
            ));
        }
        data.extend_from_slice(&buffer[..bytes]);
    }
    check()?;
    verify(t)?;
    Ok(data)
}
pub fn safe_read(root: &Path, relative: &str, max_bytes: u64) -> Result<Vec<u8>> {
    read_target(&target(root, relative, false)?, max_bytes, &|| Ok(()))
}
fn atomic_write(t: &Target, data: &[u8], check: &dyn Fn() -> Result<()>) -> Result<()> {
    atomic_write_mode(t, data, 0o600, check)
}
fn atomic_write_mode(
    t: &Target,
    data: &[u8],
    mode: u32,
    check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    check()?;
    verify(t)?;
    let name = cstring(format!(".intelligent-cells-{}.tmp", uuid::Uuid::new_v4()).as_bytes())?;
    let mut created = false;
    let result = (|| -> Result<()> {
        let mut file = fd_open(
            t.parent.as_raw_fd(),
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        created = true;
        for chunk in data.chunks(65536) {
            check()?;
            file.write_all(chunk)?;
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), (mode & 0o777) as libc::mode_t) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        file.sync_all()?;
        let staged = file.metadata()?;
        let now = stat_at(&t.parent, &name)?.ok_or_else(|| denied("Staged file disappeared"))?;
        regular(&now)?;
        if staged.dev() != now.st_dev as u64 || staged.ino() != now.st_ino as u64 {
            return Err(denied("Staged file changed"));
        }
        verify(t)?;
        check()?;
        if unsafe {
            libc::renameat(
                t.parent.as_raw_fd(),
                name.as_ptr(),
                t.parent.as_raw_fd(),
                t.name.as_ptr(),
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        created = false;
        t.parent
            .sync_all()
            .map_err(|e| IcError::from(e).unknown())?;
        Ok(())
    })();
    if created {
        unsafe { libc::unlinkat(t.parent.as_raw_fd(), name.as_ptr(), 0) };
    }
    result
}
/// An absent expected identity means creation only, never overwrite.
pub fn atomic_write_bytes(
    root: &Path,
    relative: &str,
    bytes: &[u8],
    mode: u32,
    expected: Option<(u64, u64)>,
) -> Result<()> {
    let t = target(root, relative, true)?;
    let identity = t.original.as_ref().map(|s| (s.st_dev as u64, s.st_ino));
    if identity != expected {
        return Err(denied("Target identity changed before mirror write"));
    }
    atomic_write_mode(&t, bytes, mode, &|| Ok(()))
}
/// Deletes one non-linked file or an empty directory with its preflight identity.
pub fn remove_checked(
    root: &Path,
    relative: &str,
    is_directory: bool,
    expected: Option<(u64, u64)>,
) -> Result<()> {
    policy::relative_path(relative)?;
    let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
    let (dir, snapshot) = pinned_directory(root, parent)?;
    let leaf = cstring(name.as_bytes())?;
    let original =
        stat_at(&dir, &leaf)?.ok_or_else(|| denied("Mirror deletion target disappeared"))?;
    if expected != Some((original.st_dev as u64, original.st_ino as u64)) {
        return Err(denied("Mirror deletion target changed"));
    }
    if is_directory {
        if original.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(denied("Mirror target is not directory"));
        }
    } else {
        regular(&original)?
    }
    verify_directories(&snapshot)?;
    let now = stat_at(&dir, &leaf)?.ok_or_else(|| denied("Mirror deletion target disappeared"))?;
    if now.st_dev != original.st_dev
        || now.st_ino != original.st_ino
        || now.st_mode != original.st_mode
    {
        return Err(denied("Mirror deletion target changed"));
    }
    if unsafe {
        libc::unlinkat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            if is_directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    dir.sync_all().map_err(|e| IcError::from(e).unknown())?;
    Ok(())
}
pub fn mkdir_checked(root: &Path, relative: &str, mode: u32) -> Result<()> {
    policy::relative_path(relative)?;
    let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
    let (dir, snapshot) = pinned_directory(root, parent)?;
    let leaf = cstring(name.as_bytes())?;
    verify_directories(&snapshot)?;
    if unsafe {
        libc::mkdirat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            (mode & 0o777) as libc::mode_t,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    dir.sync_all().map_err(|e| IcError::from(e).unknown())?;
    Ok(())
}
fn text<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args[key]
        .as_str()
        .ok_or_else(|| IcError::new("INVALID_ARGS", format!("{key} must be a string")))
}
fn number(args: &Value, key: &str, default: u64, max: u64, min: u64) -> Result<u64> {
    let value = match args.get(key) {
        None => default,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| IcError::new("INVALID_ARGS", format!("Invalid {key}")))?,
    };
    if value < min || value > max {
        return Err(IcError::new("INVALID_ARGS", format!("Invalid {key} bound")));
    }
    Ok(value)
}
fn boolean(args: &Value, key: &str) -> Result<bool> {
    match args.get(key) {
        None => Ok(false),
        Some(v) => v
            .as_bool()
            .ok_or_else(|| IcError::new("INVALID_ARGS", format!("{key} must be boolean"))),
    }
}
fn keys(args: &Value, allowed: &[&str]) -> Result<()> {
    let obj = args
        .as_object()
        .ok_or_else(|| IcError::new("INVALID_ARGS", "args must be an object"))?;
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(IcError::new("INVALID_ARGS", "Unexpected argument"));
    }
    Ok(())
}
fn accessible(grant: &Grant, name: &str, write: bool, directory: bool) -> bool {
    policy::check_directory(grant, name, write, directory).is_ok()
}
struct Entry {
    name: String,
    valid_utf8: bool,
    stat: libc::stat,
}
fn entries(
    dir: &File,
    max: u64,
    truncate: bool,
    check: &dyn Fn() -> Result<()>,
) -> Result<Vec<Entry>> {
    let fd = unsafe { libc::dup(dir.as_raw_fd()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| {
        let mut output = Vec::new();
        let mut scanned = 0;
        loop {
            check()?;
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if raw.to_bytes() == b"." || raw.to_bytes() == b".." {
                continue;
            }
            if scanned >= max {
                if truncate {
                    break;
                }
                return Err(IcError::new(
                    "DIRECTORY_TOO_LARGE",
                    "Directory exceeds entry limit",
                ));
            }
            scanned += 1;
            let valid_utf8 = std::str::from_utf8(raw.to_bytes()).is_ok();
            let name = String::from_utf8_lossy(raw.to_bytes()).into_owned();
            if let Some(stat) = stat_at(dir, raw)? {
                output.push(Entry {
                    name,
                    valid_utf8,
                    stat,
                });
            }
        }
        output.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(output)
    })();
    unsafe { libc::closedir(stream) };
    result
}
pub fn run(task: &Value, grant: &Grant, ctx: &ToolContext) -> Result<Value> {
    execute(task, grant, &|| ctx.check())
}
fn execute(task: &Value, grant: &Grant, check: &dyn Fn() -> Result<()>) -> Result<Value> {
    check()?;
    let tool = text(task, "tool")?;
    if !grant.tools.contains(tool) {
        return Err(IcError::new("TOOL_DENIED", "Tool not granted"));
    }
    let args = &task["args"];
    let name = args
        .get("path")
        .map(|_| text(args, "path"))
        .transpose()?
        .unwrap_or("");
    let read_max = grant.limit("maxReadBytes", 65536);
    let write_max = grant.limit("maxWriteBytes", 65536);
    if read_max == 0 || write_max == 0 || read_max > 16777216 || write_max > 16777216 {
        return Err(IcError::new("INVALID_POLICY", "Invalid file byte budget"));
    }
    match tool {
        "readFile" | "readChunk" => {
            keys(args, &["path", "offset", "length"])?;
            policy::check_directory(grant, name, false, false)?;
            let t = target(&grant.root, name, false)?;
            if tool == "readFile" && args.get("offset").is_none() && args.get("length").is_none() {
                let data = read_target(&t, read_max, check)?;
                return Ok(json!({"text":String::from_utf8_lossy(&data),"bytes":data.len()}));
            }
            let offset = number(args, "offset", 0, 9007199254740991 - read_max, 0)?;
            let length = number(args, "length", read_max, read_max, 1)?;
            let mut file = fd_open(t.parent.as_raw_fd(), &t.name, libc::O_RDONLY, 0)?;
            let meta = file.metadata()?;
            let old = t.original.as_ref().unwrap();
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.dev() != old.st_dev as u64
                || meta.ino() != old.st_ino as u64
            {
                return Err(denied("File changed while opening"));
            }
            file.seek(SeekFrom::Start(offset))?;
            let mut data = Vec::new();
            let mut remaining = length;
            let mut buffer = [0; 65536];
            while remaining > 0 {
                check()?;
                let wanted = (remaining as usize).min(buffer.len());
                let count = file.read(&mut buffer[..wanted])?;
                if count == 0 {
                    break;
                }
                data.extend_from_slice(&buffer[..count]);
                remaining -= count as u64;
            }
            check()?;
            verify(&t)?;
            let mut result = json!({"path":name,"offset":offset,"bytes":data.len(),"nextOffset":offset+data.len() as u64,"totalBytes":meta.len(),"eof":offset+data.len() as u64>=meta.len()});
            if tool == "readChunk" {
                result["base64"] = json!(STANDARD.encode(&data));
                result["sha256"] = json!(hex::encode(Sha256::digest(&data)));
            } else {
                result["text"] = json!(String::from_utf8_lossy(&data));
            }
            Ok(result)
        }
        "writeFile" | "editFile" | "writeChunk" => {
            keys(
                args,
                match tool {
                    "writeFile" => &["path", "text", "overwrite"],
                    "editFile" => &["path", "oldText", "newText"],
                    _ => &["path", "base64", "offset", "overwrite"],
                },
            )?;
            if tool != "editFile" {
                boolean(args, "overwrite")?;
            }
            policy::check_directory(grant, name, true, false)?;
            if tool == "editFile" {
                policy::check_directory(grant, name, false, false)?
            }
            let t = target(&grant.root, name, tool != "editFile")?;
            let mut offset = 0;

            let data = match tool {
                "writeFile" => {
                    if t.original.is_some() && !boolean(args, "overwrite")? {
                        return Err(IcError::new(
                            "FILE_EXISTS",
                            "Existing file requires overwrite",
                        ));
                    }
                    text(args, "text")?.as_bytes().to_vec()
                }
                "editFile" => {
                    let old = text(args, "oldText")?;
                    let new = text(args, "newText")?;
                    if old.is_empty() {
                        return Err(IcError::new("INVALID_ARGS", "oldText must be nonempty"));
                    }
                    if old.len() as u64 > read_max || new.len() as u64 > write_max {
                        return Err(IcError::new("FILE_TOO_LARGE", "Edit text exceeds limit"));
                    }
                    let data = read_target(&t, read_max, check)?;
                    let source = String::from_utf8(data).map_err(|_| {
                        IcError::new("INVALID_ENCODING", "editFile requires valid UTF-8")
                    })?;
                    let found = source.find(old).ok_or_else(|| {
                        IcError::new("EDIT_MATCH_COUNT", "oldText must occur exactly once")
                    })?;
                    let next = source[found + source[found..].chars().next().unwrap().len_utf8()..]
                        .find(old);
                    if next.is_some() {
                        return Err(IcError::new(
                            "EDIT_MATCH_COUNT",
                            "oldText must occur exactly once",
                        ));
                    }
                    source.replacen(old, new, 1).into_bytes()
                }
                _ => {
                    let encoded = text(args, "base64")?;
                    if encoded.len() as u64 > write_max.div_ceil(3) * 4 {
                        return Err(IcError::new("FILE_TOO_LARGE", "Chunk exceeds limit"));
                    }
                    let chunk = STANDARD
                        .decode(encoded)
                        .map_err(|_| IcError::new("INVALID_ARGS", "Invalid base64"))?;
                    if STANDARD.encode(&chunk) != encoded {
                        return Err(IcError::new("INVALID_ARGS", "Noncanonical base64"));
                    }
                    if chunk.len() as u64 > write_max {
                        return Err(IcError::new("FILE_TOO_LARGE", "Chunk exceeds limit"));
                    }
                    let transfer = grant.limit("maxTransferBytes", 67108864);
                    offset = number(args, "offset", 0, transfer, 0)?;
                    if offset + chunk.len() as u64 > transfer {
                        return Err(IcError::new(
                            "FILE_TOO_LARGE",
                            "Transfer exceeds total limit",
                        ));
                    }
                    if offset == 0 {
                        if t.original.is_some() && !boolean(args, "overwrite")? {
                            return Err(IcError::new(
                                "FILE_EXISTS",
                                "Existing file requires overwrite",
                            ));
                        }
                        chunk
                    } else {
                        if t.original.as_ref().map(|s| s.st_size as u64) != Some(offset) {
                            return Err(IcError::new(
                                "OFFSET_MISMATCH",
                                "Append offset must equal file size",
                            ));
                        }
                        let mut source = read_target(&t, transfer, check)?;
                        source.extend_from_slice(&chunk);
                        source
                    }
                }
            };
            let bytes = data.len() as u64 - offset;
            if tool != "writeChunk" && data.len() as u64 > write_max {
                return Err(IcError::new("FILE_TOO_LARGE", "Write exceeds local limit"));
            }
            atomic_write(&t, &data, check)?;
            let mut result = json!({"path":name,"bytes":bytes});
            if tool == "writeChunk" {
                result["offset"] = json!(offset);
                result["nextOffset"] = json!(offset + bytes);
            }
            Ok(result)
        }
        "mkdir" => {
            keys(args, &["path"])?;
            policy::relative_path(name)?;
            policy::check_directory(grant, name, true, true)?;
            let (parent, leaf) = name.rsplit_once('/').unwrap_or(("", name));
            let (dir, snapshot) = pinned_directory(&grant.root, parent)?;
            let leaf = cstring(leaf.as_bytes())?;
            verify_directories(&snapshot)?;
            check()?;
            if unsafe { libc::mkdirat(dir.as_raw_fd(), leaf.as_ptr(), 0o700) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            dir.sync_all().map_err(|e| IcError::from(e).unknown())?;
            Ok(json!({"path":name,"created":true}))
        }
        "listDirectory" => {
            keys(args, &["path", "offset", "limit"])?;
            policy::check_directory(grant, name, false, true)?;
            let max = grant.limit("maxDirectoryEntries", 1000);
            let offset = number(args, "offset", 0, max, 0)?;
            let limit = number(args, "limit", 100.min(max), 100.min(max), 1)?;
            let (dir, snapshot) = pinned_directory(&grant.root, name)?;
            let mut output = Vec::new();
            let mut skipped = 0;
            for entry in entries(&dir, max, false, check)? {
                if !entry.valid_utf8 || policy::relative_path(&entry.name).is_err() {
                    skipped += 1;
                    continue;
                }
                let rel = if name.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{name}/{}", entry.name)
                };
                let kind = entry.stat.st_mode & libc::S_IFMT;
                if !accessible(grant, &rel, false, kind == libc::S_IFDIR) {
                    continue;
                }
                let ty = match kind {
                    libc::S_IFDIR => "directory",
                    libc::S_IFREG if entry.stat.st_nlink == 1 => "file",
                    libc::S_IFLNK | libc::S_IFREG => "blocked-link",
                    _ => "blocked-special",
                };
                let mut value = json!({"name":entry.name,"type":ty});
                if ty == "file" {
                    value["bytes"] = json!(entry.stat.st_size)
                }
                output.push(value);
            }
            verify_directories(&snapshot)?;
            let total = output.len();
            let page: Vec<_> = output
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            let next = offset + page.len() as u64;
            check()?;
            Ok(
                json!({"path":name,"entries":page,"skippedEntries":skipped,"offset":offset,"nextOffset":next,"total":total,"eof":next>=total as u64}),
            )
        }
        "searchFiles" => search(grant, args, name, check),
        _ => Err(IcError::new("TOOL_DENIED", "Unknown file tool")),
    }
}
fn search(
    grant: &Grant,
    args: &Value,
    name: &str,
    check: &dyn Fn() -> Result<()>,
) -> Result<Value> {
    keys(args, &["path", "query", "maxResults"])?;
    policy::check_directory(grant, name, false, true)?;
    let query = text(args, "query")?;
    if query.is_empty() || query.len() > 256 || query.contains('\n') {
        return Err(IcError::new(
            "INVALID_ARGS",
            "Search requires a bounded single-line literal",
        ));
    }
    let max_results = number(args, "maxResults", 50, 50, 1)?;
    let max_files = grant.limit("maxSearchFiles", 1000);
    let max_bytes = grant.limit("maxSearchBytes", 1048576);
    let read_max = grant.limit("maxReadBytes", 65536);
    let mut queue = VecDeque::from([name.to_string()]);
    let mut matches = Vec::new();
    let mut visited = 0;
    let mut scanned = 0;
    let mut skipped = 0;
    let mut reason: Option<&str> = None;
    'outer: while let Some(name) = queue.pop_front() {
        let (dir, snapshot) = pinned_directory(&grant.root, &name)?;
        for entry in entries(&dir, max_files - visited + 1, true, check)? {
            visited += 1;
            if visited > max_files {
                reason = Some("maxSearchFiles");
                break 'outer;
            }
            let rel = if name.is_empty() {
                entry.name
            } else {
                format!("{name}/{}", entry.name)
            };
            if !entry.valid_utf8 || policy::relative_path(&rel).is_err() {
                skipped += 1;
                continue;
            }
            let kind = entry.stat.st_mode & libc::S_IFMT;
            if !accessible(grant, &rel, false, kind == libc::S_IFDIR) {
                continue;
            }
            if kind == libc::S_IFDIR {
                queue.push_back(rel);
                continue;
            }
            if kind != libc::S_IFREG
                || entry.stat.st_nlink != 1
                || entry.stat.st_size as u64 > read_max
            {
                skipped += 1;
                continue;
            }
            if scanned + entry.stat.st_size as u64 > max_bytes {
                reason = Some("maxSearchBytes");
                break 'outer;
            }
            let data = read_target(&target(&grant.root, &rel, false)?, read_max, check)?;
            scanned += data.len() as u64;
            let text = String::from_utf8_lossy(&data);
            for (line, content) in text.split('\n').enumerate() {
                if let Some(column) = content.find(query) {
                    let character_column = content[..column].chars().count();
                    let preview: String = content
                        .chars()
                        .skip(character_column.saturating_sub(80))
                        .take(160)
                        .collect();
                    matches.push(json!({"path":rel,"line":line+1,"column":character_column+1,"preview":preview}));
                    if matches.len() as u64 >= max_results {
                        reason = Some("maxResults");
                        break 'outer;
                    }
                }
            }
        }
        verify_directories(&snapshot)?;
    }
    check()?;
    Ok(
        json!({"matches":matches,"scannedEntries":visited.min(max_files),"scannedBytes":scanned,"skippedFiles":skipped,"truncated":reason.is_some(),"reason":reason}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::symlink;
    fn fixture() -> (tempfile::TempDir, Grant) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let grant = Grant {
            root,
            tools: [
                "readFile",
                "writeFile",
                "editFile",
                "readChunk",
                "writeChunk",
                "listDirectory",
                "searchFiles",
                "mkdir",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            raw: json!({"maxReadBytes":1024,"maxWriteBytes":1024}),
            master_id: "master".into(),
            workspace_id: "dev".into(),
            epoch: 0,
        };
        (dir, grant)
    }
    fn invoke(g: &Grant, tool: &str, args: Value) -> Result<Value> {
        execute(&json!({"tool":tool,"args":args}), g, &|| Ok(()))
    }
    #[test]
    fn files_paths_reject_escape_alias_and_link() {
        let (_d, g) = fixture();
        for p in [
            "../x", "/x", "a//b", "a/../b", "a\\b", "nul.txt", "a.", "a/",
        ] {
            assert!(checked_path(&g.root, p, true).is_err(), "{p}");
        }
        std::fs::write(g.root.join("file"), b"secret").unwrap();
        symlink("file", g.root.join("link")).unwrap();
        std::fs::hard_link(g.root.join("file"), g.root.join("hard")).unwrap();
        for p in ["file", "link", "hard"] {
            assert_eq!(safe_read(&g.root, p, 100).unwrap_err().code, "PATH_DENIED");
        }
        symlink(&g.root, g.root.join("alias")).unwrap();
        assert!(checked_path(&g.root, "alias/new", true).is_err());
    }
    #[test]
    fn files_atomic_write_edit_and_utf8_protection() {
        let (_d, g) = fixture();
        invoke(&g, "writeFile", json!({"path":"a","text":"你好 world"})).unwrap();
        assert_eq!(
            invoke(&g, "writeFile", json!({"path":"a","text":"bad"}))
                .unwrap_err()
                .code,
            "FILE_EXISTS"
        );
        invoke(
            &g,
            "editFile",
            json!({"path":"a","oldText":"world","newText":"Rust"}),
        )
        .unwrap();
        assert_eq!(
            invoke(&g, "readFile", json!({"path":"a"})).unwrap()["text"],
            "你好 Rust"
        );
        assert_eq!(
            invoke(
                &g,
                "editFile",
                json!({"path":"a","oldText":"missing","newText":"x"})
            )
            .unwrap_err()
            .code,
            "EDIT_MATCH_COUNT"
        );
        std::fs::write(g.root.join("binary"), [0xff, b'a']).unwrap();
        assert_eq!(
            invoke(
                &g,
                "editFile",
                json!({"path":"binary","oldText":"a","newText":"b"})
            )
            .unwrap_err()
            .code,
            "INVALID_ENCODING"
        );
        assert_eq!(std::fs::read(g.root.join("binary")).unwrap(), [0xff, b'a']);
    }
    #[test]
    fn files_chunks_binary_offset_and_limits() {
        let (_d, g) = fixture();
        invoke(&g, "writeChunk", json!({"path":"b","base64":"AP8="})).unwrap();
        assert_eq!(
            invoke(
                &g,
                "writeChunk",
                json!({"path":"b","base64":"YQ==","offset":1})
            )
            .unwrap_err()
            .code,
            "OFFSET_MISMATCH"
        );
        invoke(
            &g,
            "writeChunk",
            json!({"path":"b","base64":"YQ==","offset":2}),
        )
        .unwrap();
        let page = invoke(&g, "readChunk", json!({"path":"b","offset":1,"length":2})).unwrap();
        assert_eq!(page["base64"], "/2E=");
        assert_eq!(page["nextOffset"], 3);
        assert_eq!(page["eof"], true);
        assert!(
            invoke(
                &g,
                "writeChunk",
                json!({"path":"b","base64":"YR==","overwrite":true})
            )
            .is_err()
        );
        assert_eq!(
            invoke(&g, "readChunk", json!({"path":"b","length":1025}))
                .unwrap_err()
                .code,
            "INVALID_ARGS"
        );
    }
    #[test]
    fn files_acl_intersection_and_pruned_listing_search() {
        let (_d, mut g) = fixture();
        std::fs::create_dir(g.root.join("secret")).unwrap();
        std::fs::write(g.root.join("secret/a"), "needle").unwrap();
        std::fs::write(g.root.join("public"), "needle\nneedle").unwrap();
        g.raw["directories"] = json!([{"path":"","read":true,"write":true},{"path":"secret","read":false,"write":true}]);
        assert_eq!(
            invoke(
                &g,
                "editFile",
                json!({"path":"secret/a","oldText":"needle","newText":"x"})
            )
            .unwrap_err()
            .code,
            "DIRECTORY_DENIED"
        );
        let list = invoke(&g, "listDirectory", json!({"limit":1})).unwrap();
        assert_eq!(list["entries"][0]["name"], "public");
        assert_eq!(list["total"], 1);
        let search = invoke(&g, "searchFiles", json!({"query":"needle"})).unwrap();
        assert_eq!(search["matches"].as_array().unwrap().len(), 2);
        g.raw["maxSearchFiles"] = json!(1);
        assert_eq!(
            invoke(&g, "searchFiles", json!({"query":"needle"})).unwrap()["truncated"],
            true
        );
    }
    #[test]
    fn files_cancel_before_write_has_no_effect() {
        let (_d, g) = fixture();
        let result = execute(
            &json!({"tool":"writeFile","args":{"path":"a","text":"x"}}),
            &g,
            &|| Err(IcError::new("CANCELLED", "cancelled")),
        );
        assert_eq!(result.unwrap_err().code, "CANCELLED");
        assert!(!g.root.join("a").exists());
    }
    #[test]
    fn files_budget_mkdir_and_overlapping_edit() {
        let (_d, mut g) = fixture();
        invoke(&g, "mkdir", json!({"path":"sub"})).unwrap();
        assert!(invoke(&g, "mkdir", json!({"path":"missing/child"})).is_err());
        invoke(&g, "writeFile", json!({"path":"sub/a","text":"aaa"})).unwrap();
        assert_eq!(
            invoke(
                &g,
                "editFile",
                json!({"path":"sub/a","oldText":"aa","newText":"b"})
            )
            .unwrap_err()
            .code,
            "EDIT_MATCH_COUNT"
        );
        assert_eq!(
            std::fs::read_to_string(g.root.join("sub/a")).unwrap(),
            "aaa"
        );
        g.raw["maxReadBytes"] = json!(2);
        assert_eq!(
            invoke(&g, "readFile", json!({"path":"sub/a"}))
                .unwrap_err()
                .code,
            "FILE_TOO_LARGE"
        );
        assert_eq!(
            invoke(&g, "readFile", json!({"path":"sub/a","length":2})).unwrap()["text"],
            "aa"
        );
        g.raw["maxDirectoryEntries"] = json!(1);
        std::fs::write(g.root.join("sub/b"), "b").unwrap();
        assert_eq!(
            invoke(&g, "listDirectory", json!({"path":"sub"}))
                .unwrap_err()
                .code,
            "DIRECTORY_TOO_LARGE"
        );
    }
    #[test]
    fn files_cancel_after_staging_preserves_existing_file() {
        use std::cell::Cell;
        let (_d, g) = fixture();
        std::fs::write(g.root.join("a"), "before").unwrap();
        let calls = Cell::new(0);
        let result = execute(
            &json!({"tool":"writeFile","args":{"path":"a","text":"after","overwrite":true}}),
            &g,
            &|| {
                let n = calls.get() + 1;
                calls.set(n);
                if n >= 3 {
                    Err(IcError::new("CANCELLED", "cancelled"))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.unwrap_err().code, "CANCELLED");
        assert_eq!(std::fs::read_to_string(g.root.join("a")).unwrap(), "before");
        assert_eq!(std::fs::read_dir(&g.root).unwrap().count(), 1);
    }
    #[test]
    fn files_parent_replacement_detected_before_commit() {
        use std::cell::Cell;
        let (_d, g) = fixture();
        std::fs::create_dir(g.root.join("sub")).unwrap();
        std::fs::write(g.root.join("sub/a"), "before").unwrap();
        let calls = Cell::new(0);
        let result = execute(
            &json!({"tool":"writeFile","args":{"path":"sub/a","text":"after","overwrite":true}}),
            &g,
            &|| {
                let n = calls.get() + 1;
                calls.set(n);
                if n == 3 {
                    std::fs::rename(g.root.join("sub"), g.root.join("old")).unwrap();
                    std::fs::create_dir(g.root.join("sub")).unwrap();
                }
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err().code, "PATH_DENIED");
        assert_eq!(
            std::fs::read_to_string(g.root.join("old/a")).unwrap(),
            "before"
        );
        assert!(!g.root.join("sub/a").exists());
    }
    #[test]
    fn files_sync_helpers_pin_identity_and_preserve_modes() {
        let (_d, g) = fixture();
        mkdir_checked(&g.root, "sub", 0o700).unwrap();
        atomic_write_bytes(&g.root, "sub/a", b"one", 0o751, None).unwrap();
        let meta = std::fs::symlink_metadata(g.root.join("sub/a")).unwrap();
        let identity = Some((meta.dev(), meta.ino()));
        assert_eq!(meta.mode() & 0o777, 0o751);
        assert_eq!(
            atomic_write_bytes(&g.root, "sub/a", b"two", 0o640, None)
                .unwrap_err()
                .code,
            "PATH_DENIED"
        );
        atomic_write_bytes(&g.root, "sub/a", b"two", 0o640, identity).unwrap();
        assert_eq!(
            remove_checked(&g.root, "sub/a", false, identity)
                .unwrap_err()
                .code,
            "PATH_DENIED"
        );
        let meta = std::fs::symlink_metadata(g.root.join("sub/a")).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o640);
        remove_checked(&g.root, "sub/a", false, Some((meta.dev(), meta.ino()))).unwrap();
        let meta = std::fs::symlink_metadata(g.root.join("sub")).unwrap();
        remove_checked(&g.root, "sub", true, Some((meta.dev(), meta.ino()))).unwrap();
        assert!(!g.root.join("sub").exists());
    }
}
