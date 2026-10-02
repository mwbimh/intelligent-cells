# 守护运行、持久化与人工核对

本版本的验收范围是单机回环网络上的独立进程模拟。没有进行真实 VPS、跨设备公网组网或 Windows 服务实机验收。TLS 1.3、CA 验证、节点 CN 和逐 peer 证书指纹固定继续强制执行；不存在明文传输或本机执行回退。

## 启动模式

- `node src/main.mjs --config node.json` 保留开发用 stdin JSONL 命令接口；stdin 关闭会干净停机
- `node src/main.mjs --config node.json --daemon` 不读取 stdin，也不因 stdin 关闭而退出；用 SIGTERM/SIGINT 或已启用的本机操作台关闭
- `--operator` 或配置 `operator.enabled:true` 启用独立的本机操作台。HTTP 只绑定 `127.0.0.1`；身份验证、同源、CSRF 检查由操作台实现
- 后台模式不打印任何登录秘密。临时 owner 文件或受保护 Unix socket 的本机助手创建一次性会话；TTY 交互启动可以显示一次性引导地址

示例配置增量：

```json
{
  "stateDir": ".unified-node-state/example",
  "operator": {"enabled": true, "host": "127.0.0.1", "port": 0}
}
```

默认状态目录是配置文件旁 `.unified-node-state/<nodeId>`，更名后仍保留该路径，避免丢失既有账本。新部署可显式设置 `stateDir`；已有部署迁移见 [兼容说明](migration.md)。该目录必须为当前用户所有、规范真实路径、POSIX 0700，不接受符号链接。独占 PID 锁禁止两个进程共享状态；进程异常退出后死 PID 锁可安全接管。锁恢复中异常退出会保留恢复锁，需要主人检查后处理，不能通过删除所有状态“修复”。

## 两侧持久记录

- Master：发送网络请求之前，先将 operation ledger 的 `dispatching` 状态完成临时文件写入、文件 fsync、原子 rename 与父目录 fsync
- Servant：调用任何工具之前，先按同样流程记录 `running`
- 每个记录以 SHA-256 校验封装写入。结果、输出事件、reconcile 结论也使用原子写入
- 控制状态独立记录已激活的 policy、policy epoch 与 revoke；重启不会因旧配置仍存在而悄悄恢复授权。显式 `reloadPolicy` 或 `setPolicy` 才激活新 policy
- 本地审计只持久化元数据，过滤参数、结果、提示词、环境变量和错误消息，并有文件轮换。任务结果/工作内容保存在私有状态目录，因此该目录仍属于敏感数据

上述 fsync 是本地文件系统崩溃恢复措施，并不是跨远程副作用的事务。不保证恶意本机用户、管理员、失效存储或手工删除/回滚状态后的正确性。

## Unknown、查询与核对

收到结果前断线或 Master 重启，已发送操作变为 unknown。Servant 在运行期间重启，可能有副作用的任务变为 unknown；只读任务变为 interrupted，保留已消费 ID。

写入、编辑、执行命令、分块写入、进程 stdin 和非本地声明只读的 MCP 调用都按副作用处理。超时、取消、输出溢出、进程或结果落盘故障可能发生在效果已经产生之后，因此保留 unknown。`FILE_EXISTS`、明确参数/路径拒绝等确认在效果之前失败的情形仍可标为普通失败。

前台程序自发收到信号、后台作业后续超时/取消、`jobStatus`/输出/取消返回的未知作业，以及 Servant 准入时报告的既有未知副作用，都向 Master 保留顶层 `outcomeUnknown`。后台启动成功只代表已启动：原任务记录在作业运行期间仍为 `running`，不能被历史保留淘汰；启动响应返回后仍继续持久化和传递作业终态事件。活跃后台作业的事件连接丢失也保守记为 unknown。

只要某 Master 仍有 unknown 副作用，Master ledger 拒绝向所有 peer 发送新的副作用，Servant journal 和 job manager 拒绝来自该 Master 的新副作用。新 taskId 或新 runId 均不能绕过。只读检查、状态查询和取消仍可用。门禁属于执行代码，不依赖模型遵守提示词。

本机 JSONL/API 命令：

```json
{"command":"operationStatus","peerId":"servant","taskId":"op1"}
{"command":"query","peerId":"servant","taskId":"op1"}
{"command":"taskStatus","masterId":"master","taskId":"op1"}
{"command":"taskEvents","masterId":"master","taskId":"op1","after":0}
{"command":"listTasks","kind":"outgoing","limit":100}
{"command":"reconcile","peerId":"servant","taskId":"op1","resolution":"completed","note":"主人已核对目标文件哈希与实际状态"}
{"command":"reconcile","masterId":"master","taskId":"op1","resolution":"not_applied","note":"主人已核对目标没有变化且原进程已经结束"}
```

`query` 只读、不重放；远端确认的终态结果可以解除 Master 的 unknown。`not_found`/`expired` 不能证明写入未发生，不会清除 unknown。明确重新提交只读请求且远端返回 not_found 时才允许重发只读操作。旧副作用 ID 永远不会重新执行。

`reconcile` 仅通过本机主人接口开放，必须提供结论和证据说明；网络协议不能要求 reconcile。正在等待底层工具退出的任务不能在 Servant 提前核对。`not_applied` 仍然消费旧 ID；检查后要重新操作必须使用新 ID。已丢失结果不伪造成原始结果；未给出 result 时仅返回人工核对标记。

进程型长任务还有 `listJobs`、`jobStatus`、`jobOutput`、`jobCancel` 和 `reconcileJob`。后台进程的 job 与启动任务是不同记录。异常结束后的恢复顺序：先由 Servant 主人核对原进程和外部效果，执行 `reconcileJob`，再对原始启动 `taskId` 执行 incoming `reconcile`；最后由 Master 对该原始任务执行只读 `query`。仅核对 job 不会提前清除任务门禁。与同一个 peer/原始 taskId 关联的 `jobStatus` 或准入拒绝观察记录随源任务核对解除，不需要把每个观察 ID 当成一次新副作用逐个重放；它们的 ID 仍永久消费。Master 即使仅保留观察记录，也能查询源任务完成这一步。干净 Master 单独 `query` 到未知效果时，同样持久记录不可重放的观察并阻止新副作用；仅查询过的旧 ID 不能借 dispatch 执行，观察记录淘汰后仍受 tombstone 保护。核对说明仍是本机主人数据，不通过任务状态接口公开。

升级时，对于仍保留的旧版后台启动响应、自发信号 exec 结果和嵌套未知 job 状态，先补齐关联并恢复保守门禁，不丢弃已消费 ID；已被旧版淘汰的历史不能凭空恢复。

远程 jobStatus/jobOutput/jobStdin/jobCancel 绑定作业创建时的 policy epoch。任何权限重载或撤销后，旧作业的输出和控制请求返回 `TASK_POLICY_CHANGED`；缺少 epoch 的旧版作业同样拒绝远程访问。本地主人仍可检查输出、停止及核对。重新授予相同工具不会重新开放旧输出。

## 有界保留与永不盲目重放

默认保留最多 4096 个完整任务记录；达到数量/字节界限时优先淘汰最旧已完成记录，每次约四分之一。运行中、后台活跃和 unknown 记录不淘汰。既有记录从小型运行状态增长到大型结果时也执行安全淘汰；当前正在更新的记录永不作为淘汰候选。淘汰前先持久化 bounded Bloom tombstone，再删除完整结果，避免崩溃窗口丢失已消费 ID。

- 固定 256 KiB 位图，最多 200000 个已淘汰 ID；误命中只会保守拒绝新 ID，不会允许旧 ID 重放
- 淘汰后同一 ID 返回 `TASK_HISTORY_EXPIRED`；不再保留原始结果
- 历史摘要满或 unresolved 记录占满时返回 `TASK_STORE_FULL`，不会以不安全清空换取容量；容量拒绝本身不会把存储标为 I/O 故障，真实文件写入/fsync/rename 故障则 fail closed
- `setPolicy`/`reloadPolicy` 的 `maxTaskRecords`、`maxJournalBytes` 在控制状态提交前同时检查 incoming/outgoing 当前保留量。低于任一侧保留量返回 `JOURNAL_CAPACITY`，epoch、磁盘 policy 和两侧生效限额都不变；允许的调整同步作用于两侧运行实例并持久化，避免重启才发现限额不匹配
- 降低限额不会隐式删除历史；请选择不低于当前保留量的值。`status.incoming/outgoing` 显示记录、字节、当前数量和字节上限
- 不提供“忘掉 unknown 并重试”按钮。不能删除状态目录、恢复旧快照或更换节点 ID 作为常规重试方式
- 包含超过 4096 次记录写入与重启后旧 ID 拒绝的自动化回归测试

## 输出与长任务

任务事件为有界、带递增 seq 的持久尾部，最多 64 条/16 KiB；查询返回 `truncated` 标志，不承诺永久完整流。后台命令使用独立有界输出文件，支持分页 stdout/stderr/combined。同步结果也受编码后的传输上限约束。

任务 deadline 最大 24 小时，但 Servant 本地 grant 再收紧。超时不会立即释放并发位，须等底层 I/O/进程清理后释放。POSIX 正常进程组可一起结束；主动逃逸进程组的程序仍不是该应用能约束的 OS 沙箱。真实 Windows taskkill 和系统服务模板尚未实机验收。

## 损坏与恢复界限

不完整 `.tmp` 文件从不提升为正式记录。已提交记录校验失败、元数据缺失、非私有目录、符号链接和未知格式会阻止启动，明确要求人工检查。不会自动回退旧备份，因为旧备份可能缺少已经执行的操作。应保全原状态，核对外部效果，使用完整一致的受控备份恢复；不要自行丢弃损坏记录后盲目执行。

对 DNS 主机名的配置支持只有显式 `security.allowExternal:true` 时开启；此开关没有绕过 CA/CN/指纹固定。测试使用 `127.0.0.1`，没有设置真实网络、防火墙、VPN 或生产身份。
