# Rust implementation contract

This file coordinates the rewrite; it is not an alternative implementation.

- Runtime source is `src/*.rs`, binary `ic`, library `intelligent_cells`.
- `error::{IcError,Result}` and `model::{Config,Grant}` are shared. JSON API/protocol names remain camelCase. Internal Rust names use snake_case.
- `ToolContext` is in `src/context.rs`; use `ctx.check()` for cancellation/deadlines and `ctx.emit(Value)` for bounded task events.
- Root alone edits Cargo.toml, lib.rs, model.rs, error.rs, context.rs and integrates shared API changes.
- Write meaningful tests before implementation. Root runs builds/tests in Herdr pane `w1:pM`; send requested test filters and resolve compiler errors. Do not run separate invisible build/test terminals.
- Read existing Rust code and maintained English docs for behavior. No JS/TS runtime, shim or parallel old implementation remains when complete. `ui/` is retained. External harnesses can still require their own runtime.
- Preserve mTLS TLS1.3 CA/CN/pins, authenticated incoming master grants, path/link safety, explicit workspaces, durable IDs/unknown gates, approved execution code, background jobs, MCP/resources, local-sync and manual sync, owner-only management.

## APIs

### policy.rs
`load_config(path:&Path)->Result<Config>`; `validate_policy(raw:&Value,base:&Path)->Result<Value>` returns normalized absolute roots/approved-code metadata in raw JSON; `resolve_grant(policy:&Value,master:&str,workspace:Option<&str>,epoch:u64)->Result<Grant>`; `valid_id(&str)->bool`; `check_directory(grant:&Grant,path:&str,write:bool,is_directory:bool)->Result<()>`; `relative_path(&str)->Result<()>`.

### durable.rs
`write_checked(path:&Path,value:&Value)->Result<()>`; `read_checked(path:&Path)->Result<Value>`; `StateLock::acquire(dir:&Path)->Result<StateLock>` (RAII); `DurableStore::open(dir:&Path,max_records:usize,max_bytes:u64)->Result<DurableStore>`; `get(&str)->Option<Value>`; `put(&mut self,key:&str,value:Value)->Result<()>`; `values()->Vec<Value>`; `retired(&str)->bool`; `info()->Value`.

### workspaces.rs
`WorkspaceRegistry::new(state_dir:&Path,config:&Config)->Result<WorkspaceRegistry>`; node-store persistence and internal synchronization; `command(&self,command:&Value)->Result<Value>` for local/binding owner commands; `binding(peer:&str,logical:&str)->Result<Option<String>>`; `local_root(logical:&str)->Result<PathBuf>`; `sync_mapping(peer:&str,logical:&str)->Result<(PathBuf,String,Value)>`; `catalog(master:&str,policy:&Value,epoch:u64,args:&Value)->Result<Value>`; `create(master:&str,policy:&Value,epoch:u64,args:&Value)->Result<Value>`; `resolve(policy:&Value,master:&str,workspace:Option<&str>,epoch:u64)->Result<Grant>` includes provisioned grants. `sync_mapping` pins revisions/identity and `check_mapping(peer,logical,root,workspace,scope)->Result<()>` revalidates.

### tls.rs / wire.rs
Runtime composition provisions certificate paths before `tls::Security::load(raw:&Value,base:&Path,node_id:&str)->Result<Security>`; `acceptor()->Result<SslAcceptor>`; `connect(host:&str,port:u16,expected_id:&str)->Result<SslStream<TcpStream>>`; `authenticate(cert:&X509Ref,expected:Option<&str>)->Result<String>`; `certificate_identity(pem:&[u8])->Result<Value>`; mandatory CA/TLS1.3/CN/pins. `wire::{read_frame(&mut impl BufRead)->Result<Option<Value>>,write_frame(&mut impl Write,&Value)->Result<()>,fingerprint(&Value)->String}`; max 128KiB/depth32/valid UTF8/object.

### files.rs
`run(task:&Value,grant:&Grant,ctx:&ToolContext)->Result<Value>` handles readFile/writeFile/editFile/listDirectory/searchFiles/mkdir/readChunk/writeChunk. `inspect_root(&Path)->Result<()>`; `checked_path(root:&Path,relative:&str,allow_missing:bool)->Result<PathBuf>` reusable secure path resolution. Byte budgets, ACLs, O_NOFOLLOW/hardlink protection, atomic fsync writes.

### jobs.rs
`JobManager::new(state_dir:&Path,max_concurrent:usize)->Result<JobManager>`; `run(task:&Value,grant:&Grant,ctx:&ToolContext)->Result<Value>`; `command(command:&Value)->Result<Value>` handles owner list/status/output/cancel/reconcile; `run_control(task:&Value,grant:&Grant,ctx:&ToolContext)->Result<Value>` authenticated/epoch/workspace checks; `has_active(root:&Path)->bool`; `assert_can_write(master:&str)->Result<()>`; `shutdown()->Result<()>`. Process-group termination, bounded spooled streaming output/stdin, persisted unknown, jobs hold `ctx.workspace_lock` through real close. `validate_exec(task,grant)->Result<()>` checks command/code/argv before mirror effects.

### sync.rs
`SyncManager::new(state_dir:&Path)->Result<SyncManager>`; `run(task:&Value,grant:&Grant,ctx:&ToolContext)->Result<Value>` handles syncInventory/syncUpload/syncApply/syncExec. `WorkspaceLock::acquire(root:&Path)->Result<WorkspaceLock>` RAII physical root/ancestor locks; `recover(root,note)->Result<Value>`. `normalize_scope(&Value)->Result<Value>`; `capture(root:&Path,scope:&Value)->Result<Snapshot>` (manifest Value, blobs BTreeMap<String,Vec<u8>>, hash String). Local dispatch preparation in node reuses capture/inventory/uploads; frozen hash/mapping recheck, manual syncApply no job, syncExec mirror+approved execute same lock.

### resources.rs
`run(task:&Value,grant:&Grant,ctx:&ToolContext)->Result<Value>` resources/MCP, compile schema/grants validation helper if needed. Approved code, server alias/workdir/workspace relocation, list capability subset, strict UTF8/frame/output budgets, no arbitrary server/model commands.

### tools.rs (root)
`names()->&'static [&'static str]`; `side_effect(task:&Value,grant:Option<&Grant>)->bool`; `validate(task:&Value,grant:&Grant)->Result<()>`; `capabilities(grant:&Grant)->Value`; `run(task:&Value,grant:&Grant,ctx:&ToolContext)->Result<Value>` routes files/jobs/sync/resources/workspaces, holds physical lock for mutations/exec/MCP. `run_unlocked` avoids nested locking in syncExec.

### node.rs
`Node::new(Config)->Result<Arc<Node>>`; `start(self:&Arc<Self>)->Result<()>`; `shutdown(&self)->Result<()>`; `command(&self,&Value)->Result<Value>`; `dispatch(&self,peer_id:&str,task:&Value)->Result<Value>`; `port()->u16`; `config()->Config`. Incoming/outgoing persistent tasks, pending/cancel/query, reconnect; emit English field-colored stderr events or explicit JSON; reserve stdout for protocols. `command` owner alone changes permissions/root mappings; remote protocol cannot invoke owner commands. Node policy epoch persisted in nodes.json. TLS network workers may use std threads. Local-sync dispatch routes logical workspace and rewrites exec→syncExec and syncApply→frozen scope+manifest via authenticated inventory/upload.

### operator.rs
`start(node:Arc<Node>)->Result<OperatorHandle>`; `OperatorHandle::info()->Value`, `shutdown()`; retain UI HTTP/API routes/auth/local-only/CSRF/session/bootstrap and protected owner access. Node/CLI start operator after start when config operator enabled.

### settings.rs / node_store.rs
`settings::{home_dir,selected_config_path,select_config,load_selected,check_config,initialize,set_config,compose_raw}` own selected runtime settings and composition. Only `config` accepts an explicit settings path. Runtime settings exclude identity, peers, grants and certificate paths. `nodes.json` stores UUID identity plus display name, relationships, trust, control policy and directory bindings. `mcp.json` separately stores aggregation settings. Identity material is automatically provisioned per UUID; no manual identity CLI remains. Root integrates shared Config/model/context fields and cross-module APIs; coordinate changes instead of independently altering shared fields.

### sessions.rs / mcp_registry.rs
The resident node owns sessions and execution records. MCP clients attach over local IPC. An explicit agent cwd resolves through node directory bindings; no cwd selects a target session-specific temporary root only when permitted. Persist session identity and mappings; do not infer the agent cwd from the bridge process. Aggregation enforces provider/tool enablement and local/master visibility. Hidden local external tools remain hidden remotely. Built-in IC tools are always hidden locally and tagged separately from external providers.

### harness.rs / main.rs
Commands are `serve`, `config`, `nodes`, `pair`, `mcp`, `install`, `mock-model`. Remove call/launch/check-config/owner/mock-server/identity-fixture aliases. MCP CRUD and `give` manage providers and native harness configuration; `connect` attaches a persistent session to the existing service. `give` supports Claude Code and Codex, preserving existing native configuration; unsupported harnesses fail explicitly. Pure servants never invoke models. Test real installed harnesses with deterministic loopback model mocks, never real models.

### Documentation and verification
Maintained project text is English. Cross-host acceptance for this redesign uses tky, not cal. Historical logs remain historical and must not be represented as current validation. Record exact executed commands, failures, skips and evidence. Do not claim automatic certificate renewal, compatibility migration, harness support or completed testing without implementation and evidence.
