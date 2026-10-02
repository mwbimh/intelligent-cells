# 远程开发工具

这些工具运行在 servant 本地授予的工作区中。master 只能提出请求；工具、路径、命令、配额和资源的最终权限来自 servant 的对应 peer grant。`capabilities` 返回当前 grant 的 JSON Schema、限额和命令别名，不暴露本地执行文件路径或环境变量。

## 文件操作

- `listDirectory {path?,offset?,limit?}`：空路径表示工作区根。按名称排序，一页最多 100 项；整个目录超过 `maxDirectoryEntries` 时拒绝，避免为了第一页读取无限目录。软链接、硬链接和特殊文件显示为 blocked 类型，不读取目标。不能用普通路径规则访问的文件名被跳过并计入 `skippedEntries`。不同页之间不保证目录快照不变。
- `searchFiles {path?,query,maxResults?}`：递归字面文本搜索，不接受正则表达式。受 `maxSearchFiles`、`maxSearchBytes` 和最多 50 条结果约束；超过单文件 `maxReadBytes` 的文件跳过。返回 `skippedFiles`、`truncated` 和明确的限额原因。软链接、硬链接和特殊文件不扫描。
- `readFile {path,offset?,length?}`：未指定范围时保留 v0.2 行为，超出 `maxReadBytes` 拒绝；指定范围时按字节读取，不把整个大文件载入内存。UTF-8 切在字符中间可能显示替换字符；要求字节精确时用 `readChunk`。
- `mkdir {path}`：创建一个目录，父目录必须已存在，不递归、不覆盖。
- `writeFile {path,text,overwrite?}` 和 `editFile {path,oldText,newText}`：有界原子替换；已有文件的覆盖需要 `overwrite:true`，编辑必须只有一个字面匹配。无损编辑要求有效 UTF-8。
- `readChunk {path,offset?,length?}`：按字节分块下载，返回规范 base64、块 SHA-256、`nextOffset`、总大小和 EOF。
- `writeChunk {path,base64,offset?,overwrite?}`：分块上传。第一块 offset 为 0，已有文件需明确覆盖；后续块只能在“当前文件大小恰好等于 offset”时追加。单块受 `maxWriteBytes`、总文件受 `maxTransferBytes` 限制。每一块以临时文件原子提交，追加复制用固定 64 KiB 缓冲区。已经提交的先前块不会因下一块失败而回滚；整次上传并非一个事务。大量小块追加的磁盘复制成本较高。

所有文件工具拒绝绝对路径、`..`、Windows 设备名、反斜线/ADS 别名、软链接和多链接普通文件，并重新核对文件/父目录身份。Node 路径 API 不是 `openat` 安全沙箱：工作区不得由恶意本地写入者并发替换目录。

## 命令与后台作业

`exec {command,args,background?,stdin?,durationMs?}` 的 command 是本地配置的别名，不能传可执行文件路径或 shell 语句。执行使用 `shell:false` 和独立的显式环境；没有 master 本地回退。

- 默认不允许远程附加 argv。`argsAllowed:true` 才允许，并受 `maxArgs`、每个参数 4096 字节、总参数 16384 字节限制；推荐设置 `allowedArgs` 为逐值白名单。参数始终按字面传递，但被批准的程序自身如何解释这些参数仍由程序决定。
- `maxTimeoutMs` 和 `maxJobTimeoutMs` 可配置到 24 小时；后台默认时限为 `maxJobTimeoutMs`（默认 1 小时），durationMs 只可缩短或被本地上限截断。请求的 transport/task deadline 和后台进程自己的时限是不同层级。
- 非后台调用等待进程退出。运行节点返回 `jobId`、状态、退出码、信号及短 stdout/stderr 摘要。每个流摘要最多 8 KiB；超出时设置 `outputTruncated`，完整保留部分可用 `jobOutput` 读取。
- 后台调用在进程成功启动且开始状态已持久化后返回 `jobId`。后续请求连接丢失不会自动重启或重放进程。
- 输出在进程退出前流式发出，事件含 jobId、递增 seq、stream、字节数和 base64。单事件最多 4096 字节；combined、stdout、stderr 分别持久化，写入并同步后才通知。文本流用 UTF-8 decoder；需要精确重组时用 base64。
- 总输出受 `maxOutputBytes`（最多 16 MiB）和 4096 个事件硬上限约束。超过上限终止进程，不继续积累内存。输出同时存 combined 和各自流，占用约两倍原始输出磁盘空间。
- `jobStatus {jobId}` 返回该 peer 的作业状态。
- `jobOutput {jobId,offset?,limit?,stream?}` 按字节分页，默认 stream 为 combined，支持 stdout/stderr；页最多 16 KiB，返回 base64 和便于浏览的 text。页尾 UTF-8 边界应以 base64 处理。
- `jobStdin {jobId,text,eof?}` 只有原始命令及当前命令配置都允许 `stdinAllowed:true` 才可用。总写入字节受命令的 `maxStdinBytes` 限制。`exec.stdin` 是一次初始输入并发送 EOF；需要持续交互时启动后台作业，再逐次 jobStdin。输入内容不记录进作业元数据。
- `jobCancel {jobId}` 等待清理后回复。POSIX 用独立进程组及负 PID SIGKILL 终止正常继承的子孙；Windows 实现调用绝对系统路径 taskkill.exe `/T /F`，尚未在 Windows 上运行验证。

取消/超时不能撤销已经写入的文件或其他副作用。可信进程若故意 setsid、使用外部服务或修改主机仍可能逃离进程组；这不是恶意进程沙箱。运行不可信项目需操作系统级容器、账户隔离及独立权限。允许构建/测试意味着信任本地批准的 runner 及它会执行的项目代码。

## 持久化、隔离与回收

作业元数据和输出保存在工作区以外的节点私有 stateDir/jobs；元数据原子保存，POSIX 同步目录。重启时 running/starting 一律变为 unknown；不会按旧 PID 盲目终止，也不会自动重跑。unknown 状态，以及已启动后被取消、超时、输出超限或其他强制终止产生的 outcomeUnknown 标记，阻断同一 peer 的后续副作用，即使换 taskId 或 runId 也不能绕过。本地主人必须检查真实效果，通过本地 reconcile 提供 completed/not_applied 决议和证据说明后恢复。

作业控制根据认证 peer 身份隔离。后台进程计入单独的活跃进程配额，不能因为请求已经返回就绕过 maxConcurrent。重新加载/撤销权限会清理相关后台进程。

`maxJobs` 是保留的作业历史上限。达到上限时回收最旧的明确终态作业及其输出；从不回收活动、unknown 或 outcomeUnknown 未核对作业。已回收 jobId 的查询返回 JOB_NOT_FOUND。任务去重和副作用状态由独立 durable task journal 保留，回收输出不授权重放任务。全节点最多保留 256 个作业。

可执行文件和固定脚本必须位于所有远程可写工作区之外，包括其他 peer 共享的工作区；该规则只约束显式入口，不能把会加载项目代码的可信 runner 变成沙箱。

## 验证

`node --test test/tools-v2.test.mjs test/tools-v3.test.mjs test/audit-v03-jobs.test.mjs`

覆盖大文件范围读取、二进制传输、目录/搜索配额、路径/链接攻击、提前流式输出、stdout/stderr 分页、stdin 权限、同组子进程取消、输出洪水、未知结果门禁、终态回收与并发后台 admission。超过 30 秒的时长通过配置及定时器参数验证；不把短 fixture 冒充真实耗时 65 秒的测试。
