#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    #[test]
    fn sync_scope_rejects_overlap_glob_and_escape() {
        for value in [
            json!({"paths":["a","a/b"]}),
            json!({"paths":["../x"]}),
            json!({"paths":["a*"]}),
            json!({"paths":[]}),
        ] {
            assert!(normalize_scope(&value).is_err());
        }
        assert_eq!(
            normalize_scope(&json!({"paths":["z","a"]})).unwrap(),
            json!({"paths":["a","z"]})
        );
    }
    #[test]
    fn sync_capture_binary_emptydirs_and_all_exec_masks() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("empty")).unwrap();
        for mask in [0, 1, 8, 9, 64, 65, 72, 73] {
            let p = tmp.path().join(format!("f{mask}"));
            fs::write(&p, [0, 255, 128]).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600 | mask)).unwrap();
        }
        let snap = capture(tmp.path(), &json!({"paths":[""]})).unwrap();
        assert_eq!(snap.manifest.as_array().unwrap().len(), 9);
        assert_eq!(snap.blobs.len(), 1);
        for entry in snap
            .manifest
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["type"] == "file")
        {
            assert_eq!(
                entry["executable"],
                entry["path"].as_str().unwrap()[1..].parse::<u32>().unwrap()
            );
        }
    }
    #[test]
    fn sync_capture_refuses_links() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("a"), b"a").unwrap();
        fs::hard_link(tmp.path().join("a"), tmp.path().join("b")).unwrap();
        assert!(capture(tmp.path(), &json!({"paths":[""]})).is_err());
        fs::remove_file(tmp.path().join("b")).unwrap();
        std::os::unix::fs::symlink("a", tmp.path().join("b")).unwrap();
        assert!(capture(tmp.path(), &json!({"paths":[""]})).is_err());
    }
    #[test]
    fn sync_strict_mirror_preserves_unchanged_inode_and_scope_boundary() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir(src.path().join("src")).unwrap();
        fs::create_dir(dst.path().join("src")).unwrap();
        fs::write(src.path().join("src/a"), b"same").unwrap();
        fs::write(dst.path().join("src/a"), b"same").unwrap();
        fs::write(dst.path().join("src/extra"), b"delete").unwrap();
        fs::write(dst.path().join("outside"), b"keep").unwrap();
        fs::create_dir(src.path().join("src/empty")).unwrap();
        let scope = json!({"paths":["src"]});
        let snap = capture(src.path(), &scope).unwrap();
        let before = fs::metadata(dst.path().join("src/a")).unwrap();
        apply_snapshot(
            dst.path(),
            &scope,
            &snap.manifest,
            &snap.blobs,
            None,
            &|| Ok(()),
        )
        .unwrap();
        let after = fs::metadata(dst.path().join("src/a")).unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.mtime_nsec(), after.mtime_nsec());
        assert!(!dst.path().join("src/extra").exists());
        assert!(dst.path().join("src/empty").is_dir());
        assert!(dst.path().join("outside").exists());
    }
    #[test]
    fn sync_preflight_missing_blob_changes_nothing() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a"), b"new").unwrap();
        fs::write(dst.path().join("old"), b"old").unwrap();
        let scope = json!({"paths":[""]});
        let snap = capture(src.path(), &scope).unwrap();
        assert!(
            apply_snapshot(
                dst.path(),
                &scope,
                &snap.manifest,
                &BTreeMap::new(),
                None,
                &|| Ok(())
            )
            .is_err()
        );
        assert!(dst.path().join("old").exists());
    }
    #[test]
    fn sync_physical_locks_cover_descendants() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("child")).unwrap();
        let lock = WorkspaceLock::acquire(dir.path()).unwrap();
        assert!(WorkspaceLock::acquire(&dir.path().join("child")).is_err());
        assert!(WorkspaceLock::acquire(dir.path()).is_err());
        drop(lock);
        assert!(WorkspaceLock::acquire(dir.path()).is_ok());
    }
    #[test]
    fn sync_manifest_requires_ancestors_and_bounds() {
        assert!(
            validate_manifest(
                &json!({"paths":[""]}),
                &json!([{"path":"a/b","type":"directory"}])
            )
            .is_err()
        );
        assert!(
            validate_manifest(
                &json!({"paths":["src"]}),
                &json!([{"path":"other","type":"directory"}])
            )
            .is_err()
        );
    }
    #[test]
    fn sync_manifest_bounds_hash_and_modes() {
        let hash = digest(b"a");
        for entry in [
            json!({"path":"a","type":"file","size":u64::MAX,"sha256":hash,"executable":0}),
            json!({"path":"a","type":"file","size":1,"sha256":hash,"executable":2}),
            json!({"path":"a","type":"file","size":1,"sha256":"invalid","executable":0}),
        ] {
            assert!(validate_manifest(&json!({"paths":[""]}), &json!([entry])).is_err());
        }
    }
    #[test]
    fn sync_preflight_acl_refuses_delete_without_side_effect() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir(dst.path().join("private")).unwrap();
        fs::write(dst.path().join("private/secret"), b"secret").unwrap();
        let scope = json!({"paths":[""]});
        let snap = capture(src.path(), &scope).unwrap();
        let grant = Grant {
            root: dst.path().into(),
            tools: Default::default(),
            master_id: "m".into(),
            workspace_id: "w".into(),
            epoch: 1,
            raw: json!({"directories":[{"path":"","read":true,"write":true},{"path":"private","read":true,"write":false}]}),
        };
        assert!(
            apply_snapshot(
                dst.path(),
                &scope,
                &snap.manifest,
                &snap.blobs,
                Some(&grant),
                &|| Ok(())
            )
            .is_err()
        );
        assert_eq!(
            fs::read(dst.path().join("private/secret")).unwrap(),
            b"secret"
        );
    }
    #[test]
    fn sync_mirror_converts_files_and_dirs_and_exec_masks() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        fs::create_dir(src.path().join("a")).unwrap();
        fs::write(src.path().join("a/x"), [0, 255]).unwrap();
        fs::write(src.path().join("b"), b"file").unwrap();
        fs::set_permissions(src.path().join("b"), fs::Permissions::from_mode(0o751)).unwrap();
        fs::write(dst.path().join("a"), b"old").unwrap();
        fs::create_dir(dst.path().join("b")).unwrap();
        fs::write(dst.path().join("b/child"), b"old").unwrap();
        let scope = json!({"paths":[""]});
        let snap = capture(src.path(), &scope).unwrap();
        apply_snapshot(
            dst.path(),
            &scope,
            &snap.manifest,
            &snap.blobs,
            None,
            &|| Ok(()),
        )
        .unwrap();
        assert_eq!(fs::read(dst.path().join("a/x")).unwrap(), [0, 255]);
        assert_eq!(
            fs::metadata(dst.path().join("b")).unwrap().mode() & 0o111,
            0o111
        );
    }
    #[test]
    fn sync_live_lock_recovery_requires_note_and_never_steals() {
        let dir = tempfile::tempdir().unwrap();
        let lock = WorkspaceLock::acquire(dir.path()).unwrap();
        assert_eq!(
            recover(dir.path(), "short").unwrap_err().code,
            "SYNC_RECOVERY_NOTE_REQUIRED"
        );
        assert_eq!(
            recover(dir.path(), "owner checked all side effects")
                .unwrap_err()
                .code,
            "SYNC_LOCK_RECOVERY_DENIED"
        );
        drop(lock);
        assert!(WorkspaceLock::acquire(dir.path()).is_ok());
    }
    #[test]
    fn sync_staging_restart_deletes_partials_and_verifies_content() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let manager = SyncManager::new(dir.path()).unwrap();
        let partition = manager.directory.join(digest(b"partition"));
        private_dir(&partition).unwrap();
        let hash = digest(b"blob");
        let path = partition.join(format!("{hash}.part"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"partial").unwrap();
        drop(file);
        let blob = partition.join(format!("{hash}.blob"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&blob)
            .unwrap();
        file.write_all(b"blob").unwrap();
        drop(file);
        drop(manager);
        let recovered = SyncManager::new(dir.path()).unwrap();
        assert!(!path.exists());
        assert_eq!(recovered.staging.lock().unwrap().records.len(), 1);
        fs::write(&blob, b"changed").unwrap();
        assert!(SyncManager::new(dir.path()).is_err());
    }

    #[test]
    fn sync_upload_enforces_chunks_offsets_partitions_and_full_hash() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let manager = SyncManager::new(dir.path()).unwrap();
        let partition = digest(b"m/w/root");
        let hash = digest(b"abcd");
        let args = json!({"sha256":hash,"offset":0,"base64":STANDARD.encode(b"ab"),"totalBytes":4});
        let ack = manager.upload(&args, &partition, &|| Ok(())).unwrap();
        assert_eq!(ack["received"], 2);
        assert_eq!(ack["complete"], false);
        assert_eq!(
            manager
                .upload(&args, &partition, &|| Ok(()))
                .unwrap_err()
                .code,
            "SYNC_OFFSET_MISMATCH"
        );
        let final_args =
            json!({"sha256":hash,"offset":2,"base64":STANDARD.encode(b"cd"),"totalBytes":4});
        assert_eq!(
            manager.upload(&final_args, &partition, &|| Ok(())).unwrap()["complete"],
            true
        );
        assert_eq!(
            manager.upload(&args, &partition, &|| Ok(())).unwrap()["received"],
            4
        );
        assert_eq!(manager.staging.lock().unwrap().records.len(), 1);
        assert_eq!(
            manager
                .upload(&final_args, &digest(b"other"), &|| Ok(()))
                .unwrap_err()
                .code,
            "SYNC_OFFSET_MISMATCH"
        );
        let oversized = json!({"sha256":hash,"offset":0,"base64":STANDARD.encode(vec![0;16385]),"totalBytes":16385});
        assert!(manager.upload(&oversized, &partition, &|| Ok(())).is_err());
        let bad = json!({"sha256":digest(b"wrong"),"offset":0,"base64":STANDARD.encode(b"bad"),"totalBytes":3});
        assert_eq!(
            manager
                .upload(&bad, &partition, &|| Ok(()))
                .unwrap_err()
                .code,
            "SYNC_HASH_MISMATCH"
        );
        assert_eq!(manager.staging.lock().unwrap().records.len(), 1);
    }

    fn manager_fixture() -> (tempfile::TempDir, Grant, ToolContext) {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
        let root = d.path().join("workspace");
        fs::create_dir(&root).unwrap();
        let config = crate::model::Config {
            raw: json!({}),
            id: "test".into(),
            host: "127.0.0.1".into(),
            port: 0,
            path: d.path().join("config.json"),
            state_dir: state.clone(),
        };
        let sync = Arc::new(SyncManager::new(&state).unwrap());
        let jobs = Arc::new(crate::jobs::JobManager::new(&state, 1).unwrap());
        let workspaces =
            Arc::new(crate::workspaces::WorkspaceRegistry::new(&state, &config).unwrap());
        let grant = Grant {
            root,
            tools: ["syncInventory", "syncUpload", "syncApply", "syncExec"]
                .into_iter()
                .map(String::from)
                .collect(),
            raw: json!({}),
            master_id: "master".into(),
            workspace_id: "dev".into(),
            epoch: 1,
        };
        let ctx = ToolContext {
            state_dir: state,
            master_id: "master".into(),
            workspace_id: "dev".into(),
            run_id: "run".into(),
            policy_epoch: 1,
            policy: json!({}),
            cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
            event_sink: None,
            jobs,
            sync,
            workspaces,
            workspace_lock: None,
        };
        (d, grant, ctx)
    }
    #[test]
    fn sync_manual_apply_needs_no_exec_and_partition_blocks_other_master() {
        let (_d, g, ctx) = manager_fixture();
        fs::write(g.root.join("extra"), b"remove").unwrap();
        let hash = digest(b"bytes");
        ctx.sync.run(&json!({"tool":"syncUpload","args":{"sha256":hash,"offset":0,"base64":STANDARD.encode(b"bytes"),"totalBytes":5}}),&g,&ctx).unwrap();
        let manifest = json!([{"path":"a","type":"file","size":5,"sha256":hash,"executable":0}]);
        let task = json!({"tool":"syncApply","args":{"scope":{"paths":[""]},"manifest":manifest}});
        let mut other_g = g.clone();
        other_g.master_id = "other".into();
        let mut other_ctx = ctx.clone();
        other_ctx.master_id = "other".into();
        assert_eq!(
            ctx.sync.run(&task, &other_g, &other_ctx).unwrap_err().code,
            "SYNC_BLOB_MISSING"
        );
        assert!(g.root.join("extra").exists());
        let result = ctx.sync.run(&task, &g, &ctx).unwrap();
        assert_eq!(result["synced"], true);
        assert_eq!(fs::read(g.root.join("a")).unwrap(), b"bytes");
        assert!(!g.root.join("extra").exists());
    }
    fn transfer_grant(mut grant: Grant) -> Grant {
        grant.tools.insert("syncTransfer".into());
        grant.raw["allowUnsandboxedProcesses"] = json!(true);
        grant
    }
    fn transfer_task(bytes: &[u8]) -> Value {
        json!({"tool":"syncTransfer","args":{"scope":{"paths":[""]},"manifest":[{"path":"a","type":"file","size":bytes.len(),"sha256":digest(bytes),"executable":0}]}})
    }
    #[test]
    fn rsync_source_is_private_flat_verified_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        fs::create_dir(source.path().join("nested")).unwrap();
        fs::write(source.path().join("nested/a"), b"content").unwrap();
        let snap = capture(source.path(), &json!({"paths":[""]})).unwrap();
        let stage = materialize_rsync_source(dir.path(), &snap).unwrap();
        let path = stage.path().to_owned();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::read(path.join(digest(b"nested/a"))).unwrap(),
            b"content"
        );
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
        drop(stage);
        assert!(!path.exists());
        let mut bad = snap;
        bad.blobs.values_mut().next().unwrap().push(1);
        assert!(materialize_rsync_source(dir.path(), &bad).is_err());
    }
    #[test]
    fn rsync_transfer_uses_path_basis_and_publishes_without_applying() {
        let (_dir, grant, ctx) = manager_fixture();
        let grant = transfer_grant(grant);
        fs::write(grant.root.join("a"), b"basis").unwrap();
        let task = transfer_task(b"new");
        let mut stage_path = PathBuf::new();
        let result = ctx
            .sync
            .transfer(&task, &grant, &ctx, |stage, check| {
                stage_path = stage.to_owned();
                assert_eq!(fs::read(stage.join(digest(b"a")))?, b"basis");
                check()?;
                fs::write(stage.join(digest(b"a")), b"new")?;
                Ok(json!({"bytes":3}))
            })
            .unwrap();
        assert_eq!(result["transferred"], true);
        assert!(!stage_path.exists());
        assert_eq!(fs::read(grant.root.join("a")).unwrap(), b"basis");
        let apply = json!({"tool":"syncApply","args":task["args"]});
        ctx.sync.run(&apply, &grant, &ctx).unwrap();
        assert_eq!(fs::read(grant.root.join("a")).unwrap(), b"new");
    }
    #[test]
    fn rsync_transfer_rejects_bad_tree_before_any_blob_publication() {
        for attack in [
            "wrong",
            "extra",
            "directory",
            "symlink",
            "hardlink",
            "missing",
        ] {
            let (_dir, grant, ctx) = manager_fixture();
            let grant = transfer_grant(grant);
            let result = ctx
                .sync
                .transfer(&transfer_task(b"new"), &grant, &ctx, |stage, _| {
                    let file = stage.join(digest(b"a"));
                    match attack {
                        "wrong" => fs::write(&file, b"bad")?,
                        "extra" => {
                            fs::write(&file, b"new")?;
                            fs::write(stage.join("extra"), b"x")?;
                        }
                        "directory" => fs::create_dir(&file)?,
                        "symlink" => std::os::unix::fs::symlink(grant.root.join("a"), &file)?,
                        "hardlink" => {
                            fs::write(grant.root.join("outside"), b"new")?;
                            fs::hard_link(grant.root.join("outside"), &file)?;
                        }
                        _ => (),
                    }
                    Ok(json!({}))
                });
            assert!(result.is_err(), "{attack}");
            assert!(ctx.sync.staging.lock().unwrap().records.is_empty());
            assert!(!grant.root.join("a").exists());
        }
    }
    #[test]
    fn rsync_stale_stages_are_removed_on_restart() {
        let state = tempfile::tempdir().unwrap();
        let stage = RsyncStage::create(state.path()).unwrap();
        stage.write("a", b"partial").unwrap();
        let path = stage.path().to_owned();
        std::mem::forget(stage);
        SyncManager::new(state.path()).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn rsync_transfer_missing_basis_and_cancellation_keep_workspace_unchanged() {
        let (_dir, grant, ctx) = manager_fixture();
        let grant = transfer_grant(grant);
        let task = transfer_task(b"new");
        let mut stage_path = PathBuf::new();
        let error = ctx
            .sync
            .transfer(&task, &grant, &ctx, |stage, check| {
                assert_eq!(fs::read_dir(stage)?.count(), 0);
                stage_path = stage.to_owned();
                ctx.cancel.store(true, std::sync::atomic::Ordering::Release);
                check()?;
                Ok(json!({}))
            })
            .unwrap_err();
        assert_eq!(error.code, "CANCELLED");
        assert!(!stage_path.exists());
        assert!(ctx.sync.staging.lock().unwrap().records.is_empty());
        ctx.cancel
            .store(false, std::sync::atomic::Ordering::Release);
        ctx.sync
            .transfer(&task, &grant, &ctx, |stage, _| {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(stage.join(digest(b"a")))?;
                file.write_all(b"new")?;
                Ok(json!({}))
            })
            .unwrap();
        assert!(!grant.root.join("a").exists());
        assert_eq!(ctx.sync.staging.lock().unwrap().records.len(), 1);
    }
    #[test]
    fn rsync_transfer_bounds_live_staging_before_publication() {
        let (_dir, grant, ctx) = manager_fixture();
        let grant = transfer_grant(grant);
        let error = ctx
            .sync
            .transfer(&transfer_task(b"new"), &grant, &ctx, |stage, check| {
                for index in 0..513 {
                    let file = stage.join(format!("part{index}"));
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(file)?;
                }
                // The callback checks growth while the child is still running.
                check()?;
                Ok(json!({}))
            })
            .unwrap_err();
        assert_eq!(error.code, "SYNC_STAGING_LIMIT");
        assert!(ctx.sync.staging.lock().unwrap().records.is_empty());
        assert!(!grant.root.join("a").exists());
    }
    #[test]
    fn rsync_transfer_requires_explicit_process_permission_and_stream() {
        let (_dir, mut grant, ctx) = manager_fixture();
        grant.tools.insert("syncTransfer".into());
        assert_eq!(
            ctx.sync
                .transfer(&transfer_task(b"new"), &grant, &ctx, |_, _| panic!(
                    "must not start"
                ))
                .unwrap_err()
                .code,
            "UNSANDBOXED_PROCESS_DENIED"
        );
        assert_eq!(
            ctx.sync
                .run(&transfer_task(b"new"), &grant, &ctx)
                .unwrap_err()
                .code,
            "RSYNC_TRANSPORT_REQUIRED"
        );
    }
    #[test]
    fn sync_exec_denied_before_mirror() {
        let (_d, g, ctx) = manager_fixture();
        fs::write(g.root.join("extra"), b"keep").unwrap();
        let task = json!({"tool":"syncExec","taskId":"test","args":{"scope":{"paths":[""]},"manifest":[],"command":"bad","args":[]}});
        assert_eq!(
            ctx.sync.run(&task, &g, &ctx).unwrap_err().code,
            "TOOL_DENIED"
        );
        assert!(g.root.join("extra").exists());
        let mut g = g;
        g.tools.insert("exec".into());
        assert_eq!(
            ctx.sync.run(&task, &g, &ctx).unwrap_err().code,
            "COMMAND_DENIED"
        );
        assert!(g.root.join("extra").exists());
    }
    #[test]
    fn sync_source_and_target_changes_are_detected_before_effects() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("a"), b"original").unwrap();
        let scope = json!({"paths":[""]});
        let count = std::cell::Cell::new(0);
        let source_change = || -> Result<()> {
            count.set(count.get() + 1);
            if count.get() == 3 {
                fs::write(src.path().join("a"), b"changed")?;
            }
            Ok(())
        };
        assert_eq!(
            capture_checked(src.path(), &scope, None, &source_change)
                .unwrap_err()
                .code,
            "SYNC_SOURCE_CHANGED"
        );
        let dst = tempfile::tempdir().unwrap();
        fs::write(dst.path().join("a"), b"old").unwrap();
        let desired = capture(src.path(), &scope).unwrap();
        let count = std::cell::Cell::new(0);
        let target_change = || -> Result<()> {
            count.set(count.get() + 1);
            if count.get() == 3 {
                fs::write(dst.path().join("a"), b"external")?;
            }
            Ok(())
        };
        let error = apply_snapshot(
            dst.path(),
            &scope,
            &desired.manifest,
            &desired.blobs,
            None,
            &target_change,
        )
        .unwrap_err();
        assert_eq!(error.code, "SYNC_TARGET_CHANGED");
        assert!(!error.outcome_unknown);
        assert_eq!(fs::read(dst.path().join("a")).unwrap(), b"external");
    }
}

use crate::{IcError, Result, context::ToolContext, model::Grant};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 256;
fn fail(code: &str, msg: &str) -> IcError {
    IcError::new(code, msg)
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn inside(name: &str, prefix: &str) -> bool {
    prefix.is_empty() || name == prefix || name.starts_with(&format!("{prefix}/"))
}
fn only(value: &Value, names: &[&str]) -> Result<()> {
    let obj = value
        .as_object()
        .ok_or_else(|| fail("INVALID_ARGS", "Expected object"))?;
    if obj.keys().any(|k| !names.contains(&k.as_str())) {
        return Err(fail("INVALID_ARGS", "Unexpected sync argument"));
    }
    Ok(())
}
pub fn normalize_scope(value: &Value) -> Result<Value> {
    only(value, &["paths"]).map_err(|_| fail("SYNC_SCOPE_INVALID", "Expected explicit paths"))?;
    let entries = value["paths"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 32)
        .ok_or_else(|| fail("SYNC_SCOPE_INVALID", "Sync requires 1..32 paths"))?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .as_str()
            .ok_or_else(|| fail("SYNC_SCOPE_INVALID", "Path must be a string"))?;
        if !path.is_empty() {
            crate::policy::relative_path(path)?;
        }
        if path.chars().any(|c| "*?[]{}".contains(c)) {
            return Err(fail("SYNC_SCOPE_INVALID", "Globs are unsupported"));
        }
        paths.push(path.to_owned());
    }
    paths.sort();
    for (i, path) in paths.iter().enumerate() {
        if paths[..i].iter().any(|prefix| inside(path, prefix)) {
            return Err(fail("SYNC_SCOPE_INVALID", "Scope paths overlap"));
        }
    }
    Ok(json!({"paths":paths}))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn validate_manifest(scope: &Value, manifest: &Value) -> Result<Value> {
    let scope = normalize_scope(scope)?;
    let scopes: Vec<&str> = scope["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let entries = manifest
        .as_array()
        .ok_or_else(|| fail("SYNC_MANIFEST_INVALID", "Manifest must be an array"))?;
    if entries.len() > MAX_ENTRIES || serde_json::to_vec(manifest)?.len() > 60000 {
        return Err(fail("SYNC_LIMIT_EXCEEDED", "Manifest limit exceeded"));
    }
    let mut by_path = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    let mut total = 0;
    for entry in entries {
        let path = entry["path"]
            .as_str()
            .ok_or_else(|| fail("SYNC_MANIFEST_INVALID", "Missing path"))?;
        crate::policy::relative_path(path)?;
        if !scopes.iter().any(|prefix| inside(path, prefix)) || by_path.contains_key(path) {
            return Err(fail(
                "SYNC_MANIFEST_INVALID",
                "Duplicate or out of scope entry",
            ));
        }
        let canonical = match entry["type"].as_str() {
            Some("directory") => {
                only(entry, &["path", "type"])?;
                json!({"path":path,"type":"directory"})
            }
            Some("file") => {
                only(entry, &["path", "type", "size", "sha256", "executable"])?;
                let size = entry["size"]
                    .as_u64()
                    .ok_or_else(|| fail("SYNC_MANIFEST_INVALID", "Invalid size"))?;
                let hash = entry["sha256"]
                    .as_str()
                    .filter(|s| valid_hash(s))
                    .ok_or_else(|| fail("SYNC_MANIFEST_INVALID", "Invalid hash"))?;
                let mode = entry["executable"]
                    .as_u64()
                    .filter(|m| m & !0o111 == 0)
                    .ok_or_else(|| fail("SYNC_MANIFEST_INVALID", "Invalid executable mask"))?;
                if hashes
                    .insert(hash.to_owned(), size)
                    .is_some_and(|previous| previous != size)
                {
                    return Err(fail("SYNC_MANIFEST_INVALID", "Conflicting blob sizes"));
                }
                if size > MAX_BYTES {
                    return Err(fail("SYNC_LIMIT_EXCEEDED", "Byte limit exceeded"));
                }
                total += size;
                if total > MAX_BYTES {
                    return Err(fail("SYNC_LIMIT_EXCEEDED", "Byte limit exceeded"));
                }
                json!({"path":path,"type":"file","size":size,"sha256":hash,"executable":mode})
            }
            _ => return Err(fail("SYNC_MANIFEST_INVALID", "Invalid type")),
        };
        by_path.insert(path.to_owned(), canonical);
    }
    for path in by_path.keys() {
        let prefix = scopes.iter().find(|prefix| inside(path, prefix)).unwrap();
        let mut parent = Path::new(path).parent();
        while let Some(p) = parent {
            let name = p.to_str().unwrap_or("");
            if name.is_empty() || !inside(name, prefix) {
                break;
            }
            if by_path.get(name).is_none_or(|v| v["type"] != "directory") {
                return Err(fail("SYNC_MANIFEST_INVALID", "Missing directory ancestor"));
            }
            parent = p.parent();
        }
    }
    Ok(Value::Array(by_path.into_values().collect()))
}
pub fn manifest_hash(manifest: &Value) -> String {
    digest(&serde_json::to_vec(manifest).unwrap_or_default())
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub manifest: Value,
    pub blobs: BTreeMap<String, Vec<u8>>,
    pub hash: String,
}
/// Private, flattened rsync working directory. Never points at a real workspace.
pub struct RsyncStage {
    path: PathBuf,
}
impl RsyncStage {
    fn create(state_dir: &Path) -> Result<Self> {
        private_dir(state_dir)?;
        let parent = state_dir.join("rsync-staging");
        private_dir(&parent)?;
        let path = parent.join(uuid::Uuid::new_v4().to_string());
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self { path })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn check_budget(&self) -> Result<()> {
        fs::symlink_metadata(&self.path)?;
        private_dir(&self.path)?;
        let mut count = 0usize;
        let mut bytes = 0u64;
        for entry in fs::read_dir(&self.path)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            checked_file(&metadata)?;
            count += 1;
            bytes = bytes.saturating_add(metadata.len());
            if count > 512 || metadata.len() > MAX_BYTES || bytes > MAX_BYTES * 2 {
                return Err(fail(
                    "SYNC_STAGING_LIMIT",
                    "Live rsync staging budget exceeded",
                ));
            }
        }
        Ok(())
    }
    fn write(&self, relative: &str, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path.join(digest(relative.as_bytes())))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
}
impl Drop for RsyncStage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
/// Materialize a captured snapshot without exposing source paths to rsync.
pub fn materialize_rsync_source(state_dir: &Path, snapshot: &Snapshot) -> Result<RsyncStage> {
    let scope = json!({"paths":[""]});
    let manifest = validate_manifest(&scope, &snapshot.manifest)?;
    if manifest_hash(&manifest) != snapshot.hash {
        return Err(fail("SYNC_HASH_MISMATCH", "Snapshot manifest changed"));
    }
    let stage = RsyncStage::create(state_dir)?;
    for entry in manifest
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["type"] == "file")
    {
        let hash = entry["sha256"].as_str().unwrap();
        let bytes = snapshot
            .blobs
            .get(hash)
            .ok_or_else(|| fail("SYNC_BLOB_MISSING", "Snapshot content missing"))?;
        if bytes.len() as u64 != entry["size"].as_u64().unwrap() || digest(bytes) != hash {
            return Err(fail("SYNC_HASH_MISMATCH", "Snapshot content changed"));
        }
        stage.write(entry["path"].as_str().unwrap(), bytes)?;
    }
    Ok(stage)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode(),
        nlink: m.nlink(),
        size: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
fn checked_root(root: &Path) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(root)?;
    if !root.is_absolute()
        || !m.is_dir()
        || m.file_type().is_symlink()
        || fs::canonicalize(root)? != root
    {
        return Err(fail(
            "PATH_DENIED",
            "Root must be a canonical real directory",
        ));
    }
    Ok(m)
}
fn checked_file(m: &fs::Metadata) -> Result<()> {
    if !m.is_file() || m.file_type().is_symlink() || m.nlink() != 1 {
        return Err(fail("PATH_DENIED", "Sync refuses links and special files"));
    }
    Ok(())
}
fn secure_read(path: &Path, expected: Option<&Identity>, private: bool) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    checked_file(&m)?;
    if m.len() > MAX_BYTES {
        return Err(fail("SYNC_LIMIT_EXCEEDED", "File exceeds byte budget"));
    }
    if private && (m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o600) {
        return Err(fail("UNSAFE_SYNC_STATE", "Blob must be owner-only"));
    }
    let key = identity(&m);
    if expected.is_some_and(|e| *e != key) {
        return Err(fail("SYNC_SOURCE_CHANGED", "File identity changed"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != m.len()
        || identity(&f.metadata()?) != key
        || identity(&fs::symlink_metadata(path)?) != key
    {
        return Err(fail("SYNC_SOURCE_CHANGED", "File changed during read"));
    }
    Ok(bytes)
}
fn access(grant: Option<&Grant>, path: &str, write: bool, is_dir: bool) -> Result<()> {
    if let Some(g) = grant {
        crate::policy::check_directory(g, path, false, is_dir)?;
        if write {
            crate::policy::check_directory(g, path, true, is_dir)?;
        }
    }
    Ok(())
}
struct Scan {
    snapshot: Snapshot,
    state: BTreeMap<String, Option<Identity>>,
}
fn scan(
    root: &Path,
    scope: &Value,
    grant: Option<&Grant>,
    check: &dyn Fn() -> Result<()>,
) -> Result<Scan> {
    check()?;
    let rm = checked_root(root)?;
    let mut out = Scan {
        snapshot: Snapshot {
            manifest: json!([]),
            blobs: BTreeMap::new(),
            hash: String::new(),
        },
        state: BTreeMap::from([(String::new(), Some(identity(&rm)))]),
    };
    let mut entries = Vec::new();
    let mut total = 0u64;
    fn visit(
        root: &Path,
        name: &str,
        out: &mut Scan,
        entries: &mut Vec<Value>,
        total: &mut u64,
        grant: Option<&Grant>,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        check()?;
        let path = root.join(name);
        let m = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                out.state.insert(name.to_owned(), None);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };
        if m.file_type().is_symlink() {
            return Err(fail("PATH_DENIED", "Sync refuses symbolic links"));
        }
        out.state.insert(name.to_owned(), Some(identity(&m)));
        if entries.len() >= MAX_ENTRIES {
            return Err(fail("SYNC_LIMIT_EXCEEDED", "Entry limit exceeded"));
        }
        if m.is_dir() {
            if fs::canonicalize(&path)? != path {
                return Err(fail("PATH_DENIED", "Directory alias"));
            }
            access(grant, name, false, true)?;
            entries.push(json!({"path":name,"type":"directory"}));
            let mut children = fs::read_dir(path)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            children.sort();
            for child in children {
                let child = child
                    .to_str()
                    .ok_or_else(|| fail("PATH_DENIED", "Non UTF-8 path"))?;
                crate::policy::relative_path(child)?;
                visit(
                    root,
                    &format!("{name}/{child}"),
                    out,
                    entries,
                    total,
                    grant,
                    check,
                )?;
            }
        } else {
            checked_file(&m)?;
            access(grant, name, false, false)?;
            *total += m.len();
            if *total > MAX_BYTES {
                return Err(fail("SYNC_LIMIT_EXCEEDED", "Total byte limit exceeded"));
            }
            let bytes = crate::files::safe_read(root, name, MAX_BYTES)?;
            if bytes.len() as u64 != m.len()
                || identity(&fs::symlink_metadata(&path)?) != identity(&m)
            {
                return Err(fail(
                    "SYNC_SOURCE_CHANGED",
                    "File changed during secure capture",
                ));
            }
            let sha = digest(&bytes);
            entries.push(json!({"path":name,"type":"file","size":bytes.len(),"sha256":sha,"executable":m.mode()&0o111}));
            out.snapshot.blobs.entry(sha).or_insert(bytes);
        }
        Ok(())
    }
    for prefix in scope["paths"].as_array().unwrap() {
        let prefix = prefix.as_str().unwrap();
        if prefix.is_empty() {
            access(grant, "", false, true)?;
            let mut children = fs::read_dir(root)?
                .map(|e| e.map(|e| e.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            children.sort();
            for child in children {
                let name = child
                    .to_str()
                    .ok_or_else(|| fail("PATH_DENIED", "Non UTF-8 path"))?;
                crate::policy::relative_path(name)?;
                visit(root, name, &mut out, &mut entries, &mut total, grant, check)?;
            }
        } else {
            let mut missing = false;
            let mut partial = PathBuf::new();
            for part in Path::new(prefix).parent().unwrap().components() {
                partial.push(part);
                let name = partial.to_str().unwrap();
                let path = root.join(&partial);
                match fs::symlink_metadata(&path) {
                    Ok(m) => {
                        if !m.is_dir()
                            || m.file_type().is_symlink()
                            || fs::canonicalize(&path)? != path
                        {
                            return Err(fail(
                                "PATH_DENIED",
                                "Scope ancestor is not a real directory",
                            ));
                        }
                        out.state.insert(name.to_owned(), Some(identity(&m)));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        out.state.insert(name.to_owned(), None);
                        missing = true;
                        break;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            if !missing {
                visit(
                    root,
                    prefix,
                    &mut out,
                    &mut entries,
                    &mut total,
                    grant,
                    check,
                )?;
            }
            if !entries.iter().any(|e| e["path"] == prefix) {
                access(grant, prefix, false, true)?;
            }
        }
    }
    out.snapshot.manifest = validate_manifest(scope, &Value::Array(entries))?;
    out.snapshot.hash = manifest_hash(&out.snapshot.manifest);
    Ok(out)
}
fn verify_state(
    root: &Path,
    state: &BTreeMap<String, Option<Identity>>,
    code: &str,
    check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    for (name, expected) in state {
        check()?;
        let actual = match fs::symlink_metadata(root.join(name)) {
            Ok(m) => Some(identity(&m)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if actual != *expected {
            return Err(fail(code, "Tree changed after inspection"));
        }
    }
    Ok(())
}
pub fn capture(root: &Path, scope: &Value) -> Result<Snapshot> {
    capture_checked(root, scope, None, &|| Ok(()))
}
fn capture_checked(
    root: &Path,
    scope: &Value,
    grant: Option<&Grant>,
    check: &dyn Fn() -> Result<()>,
) -> Result<Snapshot> {
    let scope = normalize_scope(scope)?;
    let first = scan(root, &scope, grant, check)?;
    let second = scan(root, &scope, grant, check)?;
    if first.snapshot.hash != second.snapshot.hash || first.state != second.state {
        return Err(fail("SYNC_SOURCE_CHANGED", "Tree changed during capture"));
    }
    verify_state(root, &second.state, "SYNC_SOURCE_CHANGED", check)?;
    Ok(first.snapshot)
}
fn ensure_parents(
    root: &Path,
    name: &str,
    grant: Option<&Grant>,
    check: &dyn Fn() -> Result<()>,
) -> Result<()> {
    let mut part = PathBuf::new();
    for c in Path::new(name).parent().unwrap().components() {
        check()?;
        part.push(c);
        let p = root.join(&part);
        match fs::symlink_metadata(&p) {
            Ok(m) => {
                if !m.is_dir() || m.file_type().is_symlink() {
                    return Err(fail("PATH_DENIED", "Parent is not a real directory"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                access(grant, part.to_str().unwrap(), true, true)?;
                crate::files::mkdir_checked(root, part.to_str().unwrap(), 0o700)?;
            }
            Err(e) => return Err(e.into()),
        }
        if fs::canonicalize(&p)? != p {
            return Err(fail("PATH_DENIED", "Parent changed"));
        }
    }
    Ok(())
}
use std::os::unix::fs::DirBuilderExt;
pub fn apply_snapshot(
    root: &Path,
    scope: &Value,
    manifest: &Value,
    blobs: &BTreeMap<String, Vec<u8>>,
    grant: Option<&Grant>,
    check: &dyn Fn() -> Result<()>,
) -> Result<Snapshot> {
    let scope = normalize_scope(scope)?;
    let desired = validate_manifest(&scope, manifest)?;
    let before = scan(root, &scope, grant, check)?;
    let desired_entries = desired.as_array().unwrap();
    let old_entries = before.snapshot.manifest.as_array().unwrap();
    let index: BTreeMap<&str, &Value> = desired_entries
        .iter()
        .map(|v| (v["path"].as_str().unwrap(), v))
        .collect();
    for entry in old_entries.iter().chain(desired_entries) {
        access(
            grant,
            entry["path"].as_str().unwrap(),
            true,
            entry["type"] == "directory",
        )?;
    }
    for prefix in scope["paths"].as_array().unwrap() {
        let name = prefix.as_str().unwrap();
        let kind = index
            .get(name)
            .copied()
            .or_else(|| old_entries.iter().find(|v| v["path"] == name))
            .is_none_or(|v| v["type"] == "directory");
        access(grant, name, true, kind)?;
    }
    for entry in desired_entries {
        let name = entry["path"].as_str().unwrap();
        let mut parent = Path::new(name).parent();
        while let Some(p) = parent {
            let n = p.to_str().unwrap();
            if n.is_empty() {
                break;
            }
            if !index.contains_key(n) && before.state.get(n).is_none_or(|s| s.is_none()) {
                access(grant, n, true, true)?;
            }
            parent = p.parent();
        }
        if entry["type"] == "file" {
            let hash = entry["sha256"].as_str().unwrap();
            let b = blobs
                .get(hash)
                .ok_or_else(|| fail("SYNC_BLOB_MISSING", "Required blob missing"))?;
            if b.len() as u64 != entry["size"].as_u64().unwrap() || digest(b) != hash {
                return Err(fail("SYNC_HASH_MISMATCH", "Blob identity mismatch"));
            }
        }
    }
    let checked = scan(root, &scope, grant, check)?;
    if before.snapshot.hash != checked.snapshot.hash || before.state != checked.state {
        return Err(fail(
            "SYNC_TARGET_CHANGED",
            "Target changed during preflight",
        ));
    }
    verify_state(root, &checked.state, "SYNC_TARGET_CHANGED", check)?;
    let root_id = identity(&checked_root(root)?);
    let check_root = || -> Result<()> {
        check()?;
        let m = checked_root(root)?;
        if m.dev() != root_id.dev || m.ino() != root_id.ino {
            return Err(fail("SYNC_TARGET_CHANGED", "Root replaced"));
        }
        Ok(())
    };
    let effect = || -> Result<Snapshot> {
        let mut remove: Vec<&Value> = old_entries
            .iter()
            .filter(|v| {
                index
                    .get(v["path"].as_str().unwrap())
                    .is_none_or(|e| e["type"] != v["type"])
            })
            .collect();
        remove.sort_by_key(|v| std::cmp::Reverse(v["path"].as_str().unwrap().split('/').count()));
        for entry in remove {
            check_root()?;
            let name = entry["path"].as_str().unwrap();
            let p = root.join(name);
            crate::files::checked_path(root, name, false)?;
            let m = fs::symlink_metadata(&p)?;
            if entry["type"] == "directory" {
                if !m.is_dir() || m.file_type().is_symlink() {
                    return Err(fail("PATH_DENIED", "Deletion directory changed"));
                }
                if before
                    .state
                    .get(name)
                    .and_then(|v| v.as_ref())
                    .is_none_or(|old| old.dev != m.dev() || old.ino != m.ino())
                {
                    return Err(fail(
                        "SYNC_TARGET_CHANGED",
                        "Deletion directory identity changed",
                    ));
                }
                crate::files::remove_checked(root, name, true, Some((m.dev(), m.ino())))?;
            } else {
                checked_file(&m)?;
                if before.state.get(name) != Some(&Some(identity(&m))) {
                    return Err(fail("SYNC_TARGET_CHANGED", "Deletion file changed"));
                }
                crate::files::remove_checked(root, name, false, Some((m.dev(), m.ino())))?;
            }
        }
        let mut dirs: Vec<&Value> = desired_entries
            .iter()
            .filter(|v| v["type"] == "directory")
            .collect();
        dirs.sort_by_key(|v| v["path"].as_str().unwrap().split('/').count());
        for e in dirs {
            check_root()?;
            let name = e["path"].as_str().unwrap();
            ensure_parents(root, name, grant, check)?;
            let path = root.join(name);
            match crate::files::mkdir_checked(root, name, 0o700) {
                Ok(()) => (),
                Err(e) if e.code == "EEXIST" => {
                    let m = fs::symlink_metadata(&path)?;
                    if !m.is_dir() || m.file_type().is_symlink() {
                        return Err(fail("PATH_DENIED", "Directory target changed"));
                    }
                }
                Err(e) => return Err(e),
            }
        }
        for e in desired_entries.iter().filter(|v| v["type"] == "file") {
            let name = e["path"].as_str().unwrap();
            let previous = old_entries
                .iter()
                .find(|v| v["path"] == name && v["type"] == "file");
            if previous.is_some_and(|old| old == e) {
                continue;
            }
            check_root()?;
            ensure_parents(root, name, grant, check)?;
            let target = root.join(name);
            crate::files::checked_path(root, name, true)?;
            let initial = match fs::symlink_metadata(&target) {
                Ok(m) => {
                    checked_file(&m)?;
                    Some(m)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            };
            let expected = if previous.is_some() {
                before.state.get(name).cloned().flatten()
            } else {
                None
            };
            if initial.as_ref().map(identity) != expected {
                return Err(fail("SYNC_TARGET_CHANGED", "Target changed before staging"));
            }
            let mode = initial.as_ref().map_or(0o600, |m| m.mode() & 0o666)
                | e["executable"].as_u64().unwrap() as u32;
            crate::files::atomic_write_bytes(
                root,
                name,
                &blobs[e["sha256"].as_str().unwrap()],
                mode,
                initial.as_ref().map(|m| (m.dev(), m.ino())),
            )?;
        }
        let result = capture_checked(root, &scope, grant, check)?;
        if result.hash != manifest_hash(&desired) {
            return Err(fail(
                "SYNC_HASH_MISMATCH",
                "Final tree differs from manifest",
            ));
        }
        Ok(result)
    };
    effect().map_err(IcError::unknown)
}

fn private_dir(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o700
        || fs::canonicalize(path)? != path
    {
        return Err(fail(
            "UNSAFE_SYNC_STATE",
            "State directory must be owner-only and real",
        ));
    }
    Ok(())
}
fn lock_base() -> Result<PathBuf> {
    let base = fs::canonicalize(std::env::temp_dir())?
        .join(format!("ic-workspace-locks-{}", unsafe { libc::geteuid() }));
    private_dir(&base)?;
    Ok(base)
}
fn lock_key(root: &Path, m: &fs::Metadata) -> String {
    digest(&serde_json::to_vec(&json!([root, m.dev(), m.ino()])).unwrap())
}
struct Admission {
    path: PathBuf,
    nonce: String,
    identity: Identity,
}
impl Admission {
    fn acquire(base: &Path) -> Result<Self> {
        let path = base.join(".admission");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => break,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if std::time::Instant::now() >= deadline {
                        return Err(fail(
                            "SYNC_WORKSPACE_LOCKED",
                            "Admission occupied; explicit owner recovery required",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(e.into()),
            }
        }
        private_dir(&path)?;
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.join("owner.json"))?;
        f.write_all(&serde_json::to_vec(
            &json!({"pid":std::process::id(),"nonce":nonce}),
        )?)?;
        f.sync_all()?;
        let identity = identity(&fs::symlink_metadata(&path)?);
        Ok(Self {
            path,
            nonce,
            identity,
        })
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        let result = || -> Result<()> {
            let m = fs::symlink_metadata(&self.path)?;
            if m.dev() != self.identity.dev || m.ino() != self.identity.ino {
                return Err(fail("SYNC_LOCK_CHANGED", "Admission identity changed"));
            }
            let owner: Value =
                serde_json::from_slice(&secure_read(&self.path.join("owner.json"), None, true)?)?;
            if owner["nonce"] != self.nonce || owner["pid"] != std::process::id() {
                return Err(fail("SYNC_LOCK_CHANGED", "Admission owner changed"));
            }
            fs::remove_file(self.path.join("owner.json"))?;
            fs::remove_dir(&self.path)?;
            Ok(())
        };
        if let Err(e) = result() {
            eprintln!("{e}");
        }
    }
}
fn overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn read_owner(path: &Path, key: &str) -> Result<Value> {
    fs::symlink_metadata(path)?;
    private_dir(path)?;
    let entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
    if entries.len() != 1 || entries[0].file_name() != "owner.json" {
        return Err(fail("UNSAFE_SYNC_STATE", "Unknown lock metadata"));
    }
    let bytes = secure_read(&path.join("owner.json"), None, true)?;
    if bytes.len() > 4096 {
        return Err(fail("UNSAFE_SYNC_STATE", "Oversized lock metadata"));
    }
    let o: Value = serde_json::from_slice(&bytes)
        .map_err(|_| fail("UNSAFE_SYNC_STATE", "Invalid lock metadata"))?;
    only(&o, &["pid", "nonce", "root", "dev", "ino"])?;
    let root = o["root"]
        .as_str()
        .ok_or_else(|| fail("UNSAFE_SYNC_STATE", "Missing lock root"))?;
    if !Path::new(root).is_absolute()
        || Path::new(root).components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || Path::new(root).components().collect::<PathBuf>().to_str() != Some(root)
        || o["pid"]
            .as_u64()
            .is_none_or(|v| v == 0 || v > i32::MAX as u64)
        || o["dev"].as_u64().is_none()
        || o["ino"].as_u64().is_none()
        || o["nonce"]
            .as_str()
            .and_then(|n| uuid::Uuid::parse_str(n).ok())
            .is_none()
        || digest(&serde_json::to_vec(&json!([root, o["dev"], o["ino"]]))?) != key
    {
        return Err(fail("UNSAFE_SYNC_STATE", "Invalid lock identity"));
    }
    Ok(o)
}
#[derive(Debug)]
pub struct WorkspaceLock {
    base: PathBuf,
    path: PathBuf,
    key: String,
    nonce: String,
    dev: u64,
    ino: u64,
}
impl WorkspaceLock {
    pub fn acquire(root: &Path) -> Result<Self> {
        let m = checked_root(root)?;
        let base = lock_base()?;
        if overlap(root, &base) {
            return Err(fail(
                "UNSAFE_SYNC_STATE",
                "Workspace overlaps lock directory",
            ));
        }
        let _admission = Admission::acquire(&base)?;
        let entries = fs::read_dir(&base)?.collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() > 1024 {
            return Err(fail("SYNC_LOCK_LIMIT", "Lock capacity exhausted"));
        }
        for e in entries {
            if e.file_name() == ".admission" {
                continue;
            }
            let key = e
                .file_name()
                .to_str()
                .ok_or_else(|| fail("UNSAFE_SYNC_STATE", "Invalid lock filename"))?
                .to_owned();
            if !valid_hash(&key) {
                return Err(fail("UNSAFE_SYNC_STATE", "Unknown physical lock"));
            }
            let owner = read_owner(&e.path(), &key)?;
            if overlap(root, Path::new(owner["root"].as_str().unwrap())) {
                return Err(fail(
                    "SYNC_WORKSPACE_BUSY",
                    "Equal, ancestor or descendant workspace locked",
                ));
            }
        }
        let key = lock_key(root, &m);
        let path = base.join(&key);
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let nonce = uuid::Uuid::new_v4().to_string();
        let owner =
            json!({"pid":std::process::id(),"nonce":nonce,"root":root,"dev":m.dev(),"ino":m.ino()});
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.join("owner.json"))?;
        f.write_all(&serde_json::to_vec(&owner)?)?;
        f.sync_all()?;
        File::open(&path)?.sync_all()?;
        let current = checked_root(root)?;
        if current.dev() != m.dev() || current.ino() != m.ino() {
            return Err(fail(
                "SYNC_WORKSPACE_CHANGED",
                "Workspace identity changed while locking",
            ));
        }
        let lm = fs::symlink_metadata(&path)?;
        Ok(Self {
            base,
            path,
            key,
            nonce,
            dev: lm.dev(),
            ino: lm.ino(),
        })
    }
    pub fn recover(root: &Path, note: &str) -> Result<Value> {
        recover(root, note)
    }
}
impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let cleanup = || -> Result<()> {
            let _gate = Admission::acquire(&self.base)?;
            let m = fs::symlink_metadata(&self.path)?;
            let owner = read_owner(&self.path, &self.key)?;
            if m.dev() != self.dev
                || m.ino() != self.ino
                || owner["pid"] != std::process::id()
                || owner["nonce"] != self.nonce
            {
                return Err(fail(
                    "SYNC_LOCK_CHANGED",
                    "Lock ownership changed; retained for recovery",
                ));
            }
            fs::remove_file(self.path.join("owner.json"))?;
            fs::remove_dir(&self.path)?;
            File::open(&self.base)?.sync_all()?;
            Ok(())
        };
        if let Err(e) = cleanup() {
            eprintln!("{e}");
        }
    }
}
pub fn recover(root: &Path, note: &str) -> Result<Value> {
    if note.trim().chars().count() < 8 || note.len() > 4096 {
        return Err(fail(
            "SYNC_RECOVERY_NOTE_REQUIRED",
            "Recovery requires an owner reconciliation note",
        ));
    }
    let m = checked_root(root)?;
    let base = lock_base()?;
    let _gate = Admission::acquire(&base)?;
    let key = lock_key(root, &m);
    let path = base.join(&key);
    let owner = read_owner(&path, &key)?;
    let pid = owner["pid"].as_i64().unwrap() as libc::pid_t;
    let alive = unsafe { libc::kill(pid, 0) };
    if alive == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(fail(
            "SYNC_LOCK_RECOVERY_DENIED",
            "Owner process is alive or cannot be verified",
        ));
    }
    fs::remove_file(path.join("owner.json"))?;
    fs::remove_dir(&path)?;
    File::open(&base)?.sync_all()?;
    Ok(json!({"recovered":true,"root":root,"note":note.trim(),"previousOwner":owner}))
}

#[derive(Clone)]
struct Blob {
    path: PathBuf,
    total: u64,
    received: u64,
    complete: bool,
}
struct Staging {
    records: BTreeMap<String, Blob>,
    bytes: u64,
}
pub struct SyncManager {
    directory: PathBuf,
    staging: Mutex<Staging>,
}
impl SyncManager {
    pub fn new(state_dir: &Path) -> Result<Self> {
        fs::symlink_metadata(state_dir)?;
        private_dir(state_dir)?;
        let rsync_directory = state_dir.join("rsync-staging");
        private_dir(&rsync_directory)?;
        // Node state is exclusive: a stage left here belongs to a prior process.
        for entry in fs::read_dir(&rsync_directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| fail("UNSAFE_SYNC_STATE", "Invalid rsync stage name"))?;
            let id = uuid::Uuid::parse_str(&name)
                .map_err(|_| fail("UNSAFE_SYNC_STATE", "Unknown rsync staging content"))?;
            if id.to_string() != name {
                return Err(fail("UNSAFE_SYNC_STATE", "Noncanonical rsync stage name"));
            }
            private_dir(&entry.path())?;
            fs::remove_dir_all(entry.path())?;
        }
        File::open(&rsync_directory)?.sync_all()?;
        let directory = state_dir.join("sync-blobs");
        private_dir(&directory)?;
        let mut records = BTreeMap::new();
        let mut bytes = 0;
        for partition in fs::read_dir(&directory)? {
            let partition = partition?;
            let name = partition
                .file_name()
                .to_str()
                .ok_or_else(|| fail("UNSAFE_SYNC_STATE", "Invalid partition"))?
                .to_owned();
            if !valid_hash(&name) {
                return Err(fail("UNSAFE_SYNC_STATE", "Unknown staging partition"));
            }
            private_dir(&partition.path())?;
            for file in fs::read_dir(partition.path())? {
                let file = file?;
                let filename = file
                    .file_name()
                    .to_str()
                    .ok_or_else(|| fail("UNSAFE_SYNC_STATE", "Invalid blob filename"))?
                    .to_owned();
                let (hash, extension) = filename
                    .rsplit_once('.')
                    .ok_or_else(|| fail("UNSAFE_SYNC_STATE", "Invalid blob name"))?;
                if !valid_hash(hash) || !matches!(extension, "part" | "blob") {
                    return Err(fail("UNSAFE_SYNC_STATE", "Unknown staging content"));
                }
                let data = secure_read(&file.path(), None, true)?;
                if extension == "part" {
                    fs::remove_file(file.path())?;
                    continue;
                }
                if digest(&data) != hash {
                    return Err(fail("SYNC_HASH_MISMATCH", "Completed blob modified"));
                }
                bytes += data.len() as u64;
                if bytes > MAX_BYTES || records.len() >= 1024 {
                    return Err(fail("SYNC_STAGING_LIMIT", "Staging capacity exceeded"));
                }
                records.insert(
                    format!("{name}/{hash}"),
                    Blob {
                        path: file.path(),
                        total: data.len() as u64,
                        received: data.len() as u64,
                        complete: true,
                    },
                );
            }
        }
        Ok(Self {
            directory,
            staging: Mutex::new(Staging { records, bytes }),
        })
    }
    fn partition(&self, grant: &Grant, ctx: &ToolContext) -> Result<String> {
        if ctx.master_id.is_empty()
            || ctx.workspace_id.is_empty()
            || ctx.master_id != grant.master_id
            || ctx.workspace_id != grant.workspace_id
        {
            return Err(fail(
                "SYNC_IDENTITY_REQUIRED",
                "Authenticated master and explicit workspace required",
            ));
        }
        let m = checked_root(&grant.root)?;
        Ok(digest(&serde_json::to_vec(&json!([
            ctx.master_id,
            ctx.workspace_id,
            grant.root,
            m.dev(),
            m.ino()
        ]))?))
    }
    pub fn transfer<F>(
        &self,
        task: &Value,
        grant: &Grant,
        ctx: &ToolContext,
        bridge: F,
    ) -> Result<Value>
    where
        F: FnOnce(&Path, &dyn Fn() -> Result<()>) -> Result<Value>,
    {
        ctx.check()?;
        if task["tool"] != "syncTransfer" || !grant.tools.contains("syncTransfer") {
            return Err(fail("TOOL_DENIED", "syncTransfer not granted"));
        }
        if grant.raw["allowUnsandboxedProcesses"] != true {
            return Err(fail(
                "UNSANDBOXED_PROCESS_DENIED",
                "rsync requires explicit process permission",
            ));
        }
        only(&task["args"], &["scope", "manifest"])?;
        let scope = normalize_scope(&task["args"]["scope"])?;
        let desired = validate_manifest(&scope, &task["args"]["manifest"])?;
        let partition = self.partition(grant, ctx)?;
        ctx.jobs.assert_can_write(&ctx.master_id)?;
        let _lock = match &ctx.workspace_lock {
            Some(lock) => lock.clone(),
            None => Arc::new(WorkspaceLock::acquire(&grant.root)?),
        };
        if ctx.jobs.has_active(&grant.root) {
            return Err(fail(
                "SYNC_WORKSPACE_BUSY",
                "Workspace has active or unknown job",
            ));
        }
        let current = capture_checked(&grant.root, &scope, Some(grant), &|| ctx.check())?;
        for entry in desired.as_array().unwrap() {
            ctx.check()?;
            access(
                Some(grant),
                entry["path"].as_str().unwrap(),
                true,
                entry["type"] == "directory",
            )?;
        }
        let stage = RsyncStage::create(&ctx.state_dir)?;
        let current_entries: BTreeMap<&str, &Value> = current
            .manifest
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| (entry["path"].as_str().unwrap(), entry))
            .collect();
        let mut expected = BTreeMap::new();
        for entry in desired
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["type"] == "file")
        {
            ctx.check()?;
            let path = entry["path"].as_str().unwrap();
            expected.insert(digest(path.as_bytes()), entry);
            if let Some(basis) = current_entries
                .get(path)
                .filter(|entry| entry["type"] == "file")
            {
                stage.write(path, &current.blobs[basis["sha256"].as_str().unwrap()])?;
            }
        }
        let last_budget_check = std::cell::Cell::new(None);
        let check_transfer = || -> Result<()> {
            ctx.check()?;
            let now = std::time::Instant::now();
            if last_budget_check
                .get()
                .is_none_or(|previous: std::time::Instant| {
                    now.duration_since(previous) >= std::time::Duration::from_millis(25)
                })
            {
                stage.check_budget()?;
                last_budget_check.set(Some(now));
            }
            Ok(())
        };
        let transport = bridge(stage.path(), &check_transfer)?;
        ctx.check()?;
        stage.check_budget()?;
        let mut verified = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for entry in fs::read_dir(stage.path())? {
            ctx.check()?;
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| fail("SYNC_MANIFEST_INVALID", "Invalid rsync filename"))?;
            let wanted = expected
                .get(&name)
                .ok_or_else(|| fail("SYNC_MANIFEST_INVALID", "Unexpected rsync content"))?;
            let metadata = fs::symlink_metadata(entry.path())?;
            checked_file(&metadata)?;
            if metadata.len() != wanted["size"].as_u64().unwrap() {
                return Err(fail("SYNC_HASH_MISMATCH", "Transferred file size mismatch"));
            }
            let bytes = secure_read(&entry.path(), None, true)?;
            let hash = wanted["sha256"].as_str().unwrap();
            if digest(&bytes) != hash {
                return Err(fail("SYNC_HASH_MISMATCH", "Transferred file hash mismatch"));
            }
            seen.insert(name);
            verified.insert(hash.to_owned(), bytes);
        }
        if seen.len() != expected.len() {
            return Err(fail("SYNC_BLOB_MISSING", "rsync omitted expected content"));
        }
        // No cache publication happens until the complete transferred tree is verified.
        ctx.check()?;
        self.publish_verified(&partition, &verified, &|| ctx.check())?;
        Ok(
            json!({"transferred":true,"hash":manifest_hash(&desired),"entries":desired.as_array().unwrap().len(),"blobs":verified.len(),"transferStats":transport}),
        )
    }
    fn publish_verified(
        &self,
        partition: &str,
        blobs: &BTreeMap<String, Vec<u8>>,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        let mut state = self
            .staging
            .lock()
            .map_err(|_| fail("SYNC_STAGING_FAILED", "Staging mutex poisoned"))?;
        let mut needed = 0;
        let mut count = 0;
        for (hash, bytes) in blobs {
            check()?;
            let key = format!("{partition}/{hash}");
            if let Some(existing) = state.records.get(&key) {
                if !existing.complete {
                    return Err(fail(
                        "SYNC_STAGING_FAILED",
                        "Another upload has incomplete content",
                    ));
                }
                let prior = secure_read(&existing.path, None, true)?;
                if prior != *bytes {
                    return Err(fail("SYNC_HASH_MISMATCH", "Cached blob changed"));
                }
            } else {
                needed += bytes.len() as u64;
                count += 1;
            }
        }
        if state.bytes + needed > MAX_BYTES || state.records.len() + count > 1024 {
            return Err(fail(
                "SYNC_STAGING_LIMIT",
                "Content staging capacity exhausted",
            ));
        }
        let directory = self.directory.join(partition);
        private_dir(&directory)?;
        for (hash, bytes) in blobs {
            let key = format!("{partition}/{hash}");
            if state.records.contains_key(&key) {
                continue;
            }
            check()?;
            let partial = directory.join(format!("{hash}.part"));
            let target = directory.join(format!("{hash}.blob"));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&partial)?;
            let write = (|| -> Result<()> {
                file.write_all(bytes)?;
                file.sync_all()?;
                check()?;
                fs::rename(&partial, &target)?;
                File::open(&directory)?.sync_all()?;
                Ok(())
            })();
            if write.is_err() {
                let _ = fs::remove_file(&partial);
            }
            write?;
            state.bytes += bytes.len() as u64;
            state.records.insert(
                key,
                Blob {
                    path: target,
                    total: bytes.len() as u64,
                    received: bytes.len() as u64,
                    complete: true,
                },
            );
        }
        Ok(())
    }

    pub fn run(&self, task: &Value, grant: &Grant, ctx: &ToolContext) -> Result<Value> {
        ctx.check()?;
        let tool = task["tool"].as_str().unwrap_or("");
        if !grant.tools.contains(tool) {
            return Err(fail("TOOL_DENIED", "Sync tool not granted"));
        }
        if tool == "syncTransfer" {
            return Err(fail(
                "RSYNC_TRANSPORT_REQUIRED",
                "syncTransfer requires a controlled rsync stream",
            ));
        }
        if tool != "syncInventory" {
            ctx.jobs.assert_can_write(&ctx.master_id)?;
        }
        let partition = self.partition(grant, ctx)?;
        let args = &task["args"];
        if tool == "syncUpload" {
            return self.upload(args, &partition, &|| ctx.check());
        }
        let allowed = if tool == "syncInventory" {
            vec!["scope"]
        } else if tool == "syncApply" {
            vec!["scope", "manifest"]
        } else if tool == "syncExec" {
            vec![
                "scope",
                "manifest",
                "command",
                "args",
                "stdin",
                "durationMs",
            ]
        } else {
            return Err(fail("UNKNOWN_TOOL", "Unknown sync tool"));
        };
        only(args, &allowed)?;
        let scope = normalize_scope(&args["scope"])?;
        let mut exec = task.clone();
        exec["tool"] = json!("exec");
        if let Some(a) = exec["args"].as_object_mut() {
            a.remove("scope");
            a.remove("manifest");
        }
        if tool == "syncExec" {
            if !grant.tools.contains("exec") {
                return Err(fail("TOOL_DENIED", "syncExec requires exec permission"));
            }
            if task["background"] == true {
                return Err(fail(
                    "SYNC_BACKGROUND_UNSUPPORTED",
                    "Local sync requires foreground execution",
                ));
            }
            crate::jobs::validate_exec(&exec, grant)?;
        }
        if tool != "syncInventory" {
            validate_manifest(&scope, &args["manifest"])?;
        }
        let reservation = if tool == "syncExec" {
            Some(ctx.jobs.reserve(&exec, grant, ctx)?)
        } else {
            None
        };
        let lock = if let Some(lock) = &ctx.workspace_lock {
            lock.clone()
        } else {
            Arc::new(WorkspaceLock::acquire(&grant.root)?)
        };
        if ctx.jobs.has_active(&grant.root) {
            return Err(fail(
                "SYNC_WORKSPACE_BUSY",
                "Workspace has active or unknown job",
            ));
        }
        ctx.check()?;
        let current = capture_checked(&grant.root, &scope, Some(grant), &|| ctx.check())?;
        if tool == "syncInventory" {
            let mut hashes: BTreeSet<String> = current.blobs.keys().cloned().collect();
            let state = self
                .staging
                .lock()
                .map_err(|_| fail("SYNC_STAGING_FAILED", "Staging mutex poisoned"))?;
            for (key, record) in &state.records {
                if record.complete && key.starts_with(&format!("{partition}/")) {
                    let data = secure_read(&record.path, None, true)?;
                    let hash = key.rsplit('/').next().unwrap();
                    if digest(&data) != hash {
                        return Err(fail("SYNC_HASH_MISMATCH", "Stored blob changed"));
                    }
                    hashes.insert(hash.to_owned());
                }
            }
            return Ok(json!({"manifest":current.manifest,"hash":current.hash,"blobs":hashes}));
        }
        let desired = validate_manifest(&scope, &args["manifest"])?;
        let mut blobs = current.blobs;
        {
            let state = self
                .staging
                .lock()
                .map_err(|_| fail("SYNC_STAGING_FAILED", "Staging mutex poisoned"))?;
            for entry in desired
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["type"] == "file")
            {
                let hash = entry["sha256"].as_str().unwrap();
                if !blobs.contains_key(hash) {
                    let record = state
                        .records
                        .get(&format!("{partition}/{hash}"))
                        .filter(|r| r.complete)
                        .ok_or_else(|| {
                            fail("SYNC_BLOB_MISSING", "Blob not uploaded by this identity")
                        })?;
                    let data = secure_read(&record.path, None, true)?;
                    if data.len() as u64 != entry["size"].as_u64().unwrap() || digest(&data) != hash
                    {
                        return Err(fail(
                            "SYNC_HASH_MISMATCH",
                            "Staged content identity mismatch",
                        ));
                    }
                    blobs.insert(hash.to_owned(), data);
                }
            }
        }
        let applied = apply_snapshot(&grant.root, &scope, &desired, &blobs, Some(grant), &|| {
            ctx.check()
        })?;
        if tool == "syncApply" {
            return Ok(
                json!({"synced":true,"hash":applied.hash,"entries":desired.as_array().unwrap().len()}),
            );
        }
        let mut locked_ctx = ctx.clone();
        locked_ctx.workspace_lock = Some(lock);
        ctx.check().map_err(IcError::unknown)?;
        ctx.jobs
            .run_reserved(&exec, grant, &locked_ctx, reservation.unwrap())
            .map_err(IcError::unknown)
    }
    fn upload(
        &self,
        args: &Value,
        partition: &str,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Value> {
        only(args, &["sha256", "offset", "base64", "totalBytes"])?;
        let hash = args["sha256"]
            .as_str()
            .filter(|s| valid_hash(s))
            .ok_or_else(|| fail("INVALID_ARGS", "Invalid hash"))?;
        let offset = args["offset"]
            .as_u64()
            .ok_or_else(|| fail("INVALID_ARGS", "Invalid offset"))?;
        let total = args["totalBytes"]
            .as_u64()
            .filter(|n| *n <= MAX_BYTES)
            .ok_or_else(|| fail("INVALID_ARGS", "Invalid total size"))?;
        let b64 = args["base64"]
            .as_str()
            .ok_or_else(|| fail("INVALID_ARGS", "Missing base64"))?;
        if b64.len() > 4 * 16384usize.div_ceil(3) {
            return Err(fail("SYNC_CHUNK_TOO_LARGE", "Chunk limit 16384 bytes"));
        }
        let data = STANDARD
            .decode(b64)
            .map_err(|_| fail("INVALID_ARGS", "Invalid base64"))?;
        if STANDARD.encode(&data) != b64
            || data.len() > 16384
            || offset
                .checked_add(data.len() as u64)
                .is_none_or(|v| v > total)
        {
            return Err(fail(
                "INVALID_ARGS",
                "Chunk is not canonical or exceeds total",
            ));
        }
        let mut state = self
            .staging
            .lock()
            .map_err(|_| fail("SYNC_STAGING_FAILED", "Staging mutex poisoned"))?;
        let key = format!("{partition}/{hash}");
        if let Some(prior) = state.records.get(&key)
            && prior.complete
        {
            let existing = secure_read(&prior.path, None, true)?;
            if prior.total != total
                || digest(&existing) != hash
                || existing.get(offset as usize..offset as usize + data.len())
                    != Some(data.as_slice())
            {
                return Err(fail(
                    "SYNC_HASH_MISMATCH",
                    "Chunk differs from completed content",
                ));
            }
            return Ok(json!({"sha256":hash,"received":prior.received,"complete":true}));
        }
        if !state.records.contains_key(&key) {
            if offset != 0 {
                return Err(fail("SYNC_OFFSET_MISMATCH", "Upload must begin at zero"));
            }
            if state.records.len() >= 1024 || state.bytes + total > MAX_BYTES {
                return Err(fail(
                    "SYNC_STAGING_LIMIT",
                    "Content staging capacity exhausted",
                ));
            }
            let directory = self.directory.join(partition);
            private_dir(&directory)?;
            let path = directory.join(format!("{hash}.part"));
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?;
            f.sync_all()?;
            state.records.insert(
                key.clone(),
                Blob {
                    path,
                    total,
                    received: 0,
                    complete: false,
                },
            );
            state.bytes += total;
        }
        let record = state.records.get_mut(&key).unwrap();
        if record.total != total || record.received != offset {
            return Err(fail(
                "SYNC_OFFSET_MISMATCH",
                "Sequential stable-size chunks required",
            ));
        }
        check()?;
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&record.path)?;
        let m = f.metadata()?;
        checked_file(&m)?;
        if m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o777 != 0o600
            || m.len() != record.received
        {
            return Err(fail("UNSAFE_SYNC_STATE", "Partial blob changed"));
        }
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(&data)?;
        f.sync_all()?;
        record.received += data.len() as u64;
        check()?;
        if record.received == record.total {
            if digest(&secure_read(&record.path, None, true)?) != hash {
                let path = record.path.clone();
                fs::remove_file(path)?;
                state.records.remove(&key);
                state.bytes -= total;
                return Err(fail("SYNC_HASH_MISMATCH", "Full blob hash mismatch"));
            }
            let target = record.path.with_extension("blob");
            fs::rename(&record.path, &target)?;
            File::open(target.parent().unwrap())?.sync_all()?;
            record.path = target;
            record.complete = true;
        }
        Ok(json!({"sha256":hash,"received":record.received,"complete":record.complete}))
    }
}
