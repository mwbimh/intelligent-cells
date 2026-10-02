#.1 本机运维、配对与部署指南

## 范围和验证边界

本版本的实现和验收针对**同一 Linux 模拟环境中的多进程节点**。模型仍固定为 `pi-mock`；这不是接入真实付费模型或生产代理的声明。

- 已实现：不依赖 stdin 的 daemon 模式；带所有者认证的中文本机控制台；持久权限、任务/作业状态及核对；身份配对/轮换/撤销；审计轮换；只生成文本的 Linux/Windows 部署计划
- 已通过：真实本地节点上的 HTTP 控制面、一次性引导/会话失效、CSRF/Origin/Host 防护、所有者文件权限与清理、配对与轮换的拒绝路径、日志脱敏和轮换、部署计划单元测试
- Unix 域套接字尚未完成目标机验收；受限环境可能返回 `EPERM`，该传输**未验证**；不要把跳过测试视为通过
- 云浏览器访问临时本地控制台返回 `net::ERR_BLOCKED_BY_CLIENT`；已验证 HTML/脚本静态交付与 HTTP 行为，**未完成视觉、实际浏览器点击或可访问性验收**
- 真实 VPS 公网链路、真实 Windows 主机、systemd/计划任务注册、主机重启和生产证书轮换**未执行**
- 没有生成生产私钥、开通长期访问、安装 OS 服务、修改防火墙、注册计划任务或发布网站

运行测试：

```bash
npm test
node --test --test-concurrency=1 test/operator-ui.test.mjs test/audit-v03-operator.test.mjs
```

测试证书只能由现有 `scripts/test-identities.mjs` 在 OS 临时目录内带 `.disposable-test-only` 标记的目录生成。不要把这些 CA、证书或私钥用于正式部署。

## 1. 运行方式

```bash
node scripts/check-config.mjs /absolute/path/node.json
node src/main.mjs --config /absolute/path/node.json --daemon --operator
```

`--daemon` 不读取 stdin，关闭终端输入不会关闭节点。没有该参数时保留原有 NDJSON stdin 测试接口。`SIGINT`、`SIGTERM` 或本机控制台“停止此节点”触发正常关闭。

示例配置片段（应合并到已具备真实、独立核验身份的配置中）：

```json
{
  "stateDir": "/var/lib/intelligent-cells/state",
  "logFile": "/var/lib/intelligent-cells/logs/audit.jsonl",
  "operator": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 0,
    "sessionDirectory": "/var/lib/intelligent-cells/operator-access"
  }
}
```

`stateDir`、日志目录和管理访问目录必须为本机运行账号所有、不可经符号链接进入、POSIX 权限 `0700`。管理访问文件和审计文件使用 `0600`。端口 `0` 让 OS 选择空闲端口；`operator_ready` 事件报告实际地址和 `ownerFile` 路径，**不报告秘密内容**。

不要把状态目录、配置、密钥、MCP 程序或固定命令脚本放到任何对端可写的工作区中。控制台只绑定 `127.0.0.1`，不能通过配置改为公网监听。不要给它加公网反向代理或开放管理端口。

## 2. 所有者登录和会话

在节点运行账号的本机终端，从 `operator_ready` 事件取得本次运行的所有者文件路径：

```bash
node scripts/operator.mjs open --session-file /path/from/operator_ready.json
```

把输出地址在**同一主机的浏览器**打开。URL 的 `#token` 是一次性、5 分钟有效的引导令牌；片段不会发送到 HTTP 服务器访问路径。页面读取后立即从地址栏历史当前条目移除，不存入 localStorage/sessionStorage。

- 所有者文件含 256 位随机、仅本次进程有效的访问能力，保存在 `0700` 目录的随机 `0600` 文件中
- 它只能换取短期一次性会话引导，不是生产证书或长期身份
- 正常关闭时删除；进程崩溃留下的文件不能访问后续进程（每次重新生成秘密和文件名）。确认旧进程已停止后由所有者清理旧文件
- 不要把此目录加入源码包、诊断包、日志采集或共享备份。不要把 URL、cookie、CSRF 值贴到工单或聊天
- 会话默认 30 分钟，最多 1 小时；退出立即使 cookie 失效
- `HttpOnly`、`SameSite=Strict` cookie；API 必须匹配准确的 Host，任何跨站 Origin/Fetch-Site 被拒绝。所有修改需要同源 Origin 和随机 CSRF 请求头
- 只有本机页面是公开静态资源；没有会话时不能读取状态、日志或任务，更不能改权限

可信的本机同账号进程/管理员可以读所有者文件；这是明确的本机所有者信任边界，不是多用户 Web 平台。HTTP 被限定在回环地址，无法防御已控制本机内核或同账号的攻击者。

Unix IPC 是可选路径：`operator.socketPath` 必须位于 owner-only 目录。`scripts/operator.mjs open --socket <路径>` 只请求会话，不接受远程工具执行。本环境未验证该传输，默认使用已测试的 HTTP + 所有者文件路径。

Windows 不尝试凭 Node 的 POSIX mode 位假装实现 NTFS ACL。后台 daemon 需要保持 `operator` 关闭；需要控制台时先停止计划任务，使用交互终端 `--operator` 运行并由终端获得每次运行的令牌（Windows 所有者文件/Unix IPC 不受支持）。Windows OS 权限和服务控制仍须在真实目标机审核与验证。

## 3. 控制台功能

### 节点总览

显示当前节点、加密方式、连接状态、活动任务、持久账本、策略 epoch、未知结果计数。未知计数包括 incoming、outgoing 和后台 jobs。页面每 10 秒可见时刷新；手动刷新也可用。

### 执行权限

每个调用方独立授予工具、工作区、并发、超时和固定命令别名。基础工具可勾选；资源、MCP provider 和其他边界在“高级授权边界”JSON 中修改。既有、未编辑字段会保留。所有策略由核心 `loadPolicy` 校验，再存入持久控制状态。

数量/字节限额降低前会同时检查两侧账本，低于当前保留量即返回 `JOURNAL_CAPACITY`，不会保存一个重启后无法加载的策略。通过检查的限额同时应用于运行实例和持久 policy。

保存使用 `expectedEpoch`，另一所有者先改过策略时拒绝过期页面保存，防止覆盖新撤销。撤销列表在显示/保存中扣除；编辑其他调用方不会偷偷重新启用被撤销对象。重新授权需要明确填入对应 ID 并保存。

“从磁盘重新加载”明确采用配置文件的策略，可能恢复配置中仍存在的旧授权，操作前会提示。正常重启使用持久控制状态，不能依靠重启擦除撤销。

撤销工具授权会取消对应当前任务和后台作业。身份撤销另外断开连接并移除持久对端/信任配置。权限保存、撤销和重新加载均有审计元数据，不记录策略正文或环境值。

### 任务、后台作业与核对

- incoming 任务：读取记录/事件、所有者取消、未知状态人工核对
- outgoing 任务：读取本地操作账本、查询远端状态、请求取消、未知状态人工核对
- 后台作业：作业状态、分页输出、停止进程组、未知状态人工核对
- 输出只在已认证控制台中显示，不进入元数据审计日志
- 人工核对需 `completed` 或 `not_applied` 以及独立证据说明。它记录事实判断，不会执行或重放原任务
- 任务 ID 已消耗；即使核对为未执行，也不要以原 ID 再试。确需新工作时由所有者/规划器在完成核对后创建新的业务意图和 ID
- 停止/取消不等于外部效果回滚；文件修改、第三方调用或进程已经产生的效果须另行核实
- 未知后台效果恢复顺序：Servant 主人 `reconcileJob` → incoming 原始启动任务 `reconcile` → Master 查询原始 `taskId`；同源状态/拒绝观察记录联动解除，其他 peer/任务门禁不受影响
- 权限 epoch 变化后，旧作业的远程状态/输出/控制均拒绝；本地主人仍可检查与核对。旧版缺少 epoch 的作业按同一规则拒绝远程读取

当前视图每种任务最多展示 100 条，日志最新 100 条；具体旧任务可按 ID 查询。服务不是 exactly-once 外部事务系统；保留未知结果和拒绝重放是刻意的安全边界。

## 4. 配对、到期、轮换和撤销

### 配对

1. 所有者通过独立渠道取得对端 node ID、公开证书和 SHA-256 指纹；不能把同一未验证连接给出的指纹当作独立证据
2. 控制台填入 ID、证书、预期指纹，先“检查证书”
3. 校验 CN、固定指纹、当前有效期、非 CA 节点证书，以及受当前配置 CA 直接签发。中间 CA 链在本工具中不自动猜测，须事先线下验证和配置
4. 勾选已独立核对并保存；只持久保存信任，可选保存出站 IP/端口。没有默认工具授权
5. 重启使新增信任生效，再单独配置执行授权

仅有证书本身或 TLS CA 信任不会自动配对。不存在“首次看见即信任”。

### 到期检查

```bash
node scripts/identity-lifecycle.mjs inspect /path/to/node.pem
node scripts/identity-lifecycle.mjs rotation-plan /path/to/old.pem /path/to/new.pem INDEPENDENTLY_VERIFIED_NEW_SHA256 /path/to/ca.pem
```

工具只读取公开证书，报告 `valid`、`expiring_soon`、`expired` 或 `not_yet_valid`。30 天内到期提示仅是运维提示，不能延长证书有效期。运行时每次身份认证仍检查当前有效期。

### 无自动信任的轮换

先由所有者在既有 PKI/安全流程中生成并签发新材料。本项目不会代为生成生产私钥或自动授权。

1. 各对端独立核对新指纹，用“保留旧指纹，添加轮换证书”保存；每个身份最多 4 个 pin
2. 重启对端使新 pin 生效，原 pin 可短期共存
3. 本节点停机；所有者替换匹配的新证书/私钥，确认权限，重启
4. 核验双向 mTLS 和许可工具的小范围调用，确认所有关系都使用新证书
5. 通过“移除旧指纹”收缩信任，关闭旧连接。移除操作不会提前激活尚未重启的新增 pin
6. 由所有者按组织保留策略处理旧私钥

### 撤销

“撤销身份”先撤销运行中执行权和对应作业，再断开该身份连接，移除活跃 pin 和出站 peer，最后持久移除配置 pin/peer/grant。磁盘失败会报错，不会把执行权限重新打开；处理磁盘问题并核验配置后才能认为整体撤销完成。

## 5. 审计与保留

`src/operator-audit.mjs` 使用允许字段列表，只持久保存时间、节点/对端/任务标识、事件、工具名、状态、错误 code 等。参数、文件内容、提示、模型输出、完整错误消息、命令环境、secret/token 不写入。

默认单文件约 1 MiB，保留当前文件 + 4 个轮转文件。当前核心使用固定 1 MiB / 4 个归档的边界，未暴露可随意扩大的配置开关。每条 append 同步 fsync；不可写时核心报告 `log_write_error`。日志故障需要所有者处理，不能把缺失日志当作未执行证据。

```bash
node scripts/operator.mjs logs --session-file /path/from/operator_ready.json
```

任务结果/去重账本保留与审计保留彼此独立，不能删审计/删账本来重试任务。原有 stdin 测试协议会把 `command_result` 返回到 stdout；不要把包含真实内容的交互测试 stdout 当作已脱敏审计。daemon 控制台不会记录 API 响应正文。

## 6. Linux 与 Windows 部署计划（仅 dry-run）

以下命令**生成可审阅的文本**；不会调用 systemctl、schtasks、sudo、安装包管理器或任何密钥生成命令。`--write-dir` 仅在指定目录写入新的模板文件，已有文件不覆盖。

```bash
node scripts/service-plan.mjs --platform linux --name intelligent-cells --project /opt/intelligent-cells --config /etc/intelligent-cells/node.json --state-dir /var/lib/intelligent-cells --node /usr/bin/node --user intelligentcells --workspace /srv/intelligent-cells/data --write-dir ./service-plans
```

systemd 模板采用专用非 root 用户、`UMask=0077`、`NoNewPrivileges=yes`、只读系统和显式可写路径、`KillMode=control-group`、`Restart=on-failure`。它不创建系统用户、不修改权限、不配置防火墙，也不是完整恶意代码沙箱。所需证书和目录必须先由所有者建立并核验。参见 [systemd 官方服务语义](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)。

```powershell
node scripts/service-plan.mjs --platform windows --name intelligent-cells --project C:\IntelligentCells --config C:\IntelligentCells\node.json --state-dir C:\IntelligentCells\state --node "C:\Program Files\nodejs\node.exe" --user "DESKTOP\nodeowner" --write-dir .\service-plans
```

Windows 输出的是当前显式用户登录后的计划任务 XML，使用 `InteractiveToken` 和 `LeastPrivilege`；**不是 Windows 服务，不承诺注销后或无人登录时执行**。Windows 运行账号需要用户的实际 DOMAIN\user 或 SID，禁止假定账号身份。真正服务包装器、凭据存储、ACL、开机无人登录场景另行审批验证。参见 [Microsoft LogonType](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-logontype-principaltype-element) 和 [RunLevel](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-runlevel-principaltype-element)。

`manualRegistration` 字段列出所有者取得批准后可自行执行的注册命令。不要直接复制包含占位路径的命令执行。回滚应停止/移除服务注册并保留账本；不要为“干净重试”清空状态。

## 7. 可执行验收与后续目标机清单

针对已经明确授权运行的节点，读操作验收：

```bash
node scripts/service-acceptance.mjs --session-file /path/from/operator_ready.json
```

该命令读取身份、状态、持久账本开启状态和审计配置，检查跨站请求被拒绝，不派发新工作、不改权限。报告对真实 VPS、Windows、服务管理器注册、主机重启、生产证书轮换明确输出 `not_run`。`passed: true` 仅表示已执行的本地检查通过；`productionVerified` 固定为 false。

在将来真实目标机获得明确授权后，仍需逐项留下时间、机器/OS、commit、配置摘要、证据文件及结果：

| 验收项 | 当前验证范围 | 目标机所需证据 |
|---|---|---|
| daemon 在 stdin EOF 后继续运行 | 本地核心测试覆盖 | 目标 OS 服务 stdout/stdin 行为 |
| 本机所有者认证和拒绝跨站 | 本地 HTTP 测试通过 | 本机浏览器实际登录/退出/刷新/重复点击 |
| Unix owner IPC | 受限环境未验证 | owner/non-owner 账户访问测试 |
| 中文 UI 视觉、焦点、取消与返回 | 未完成浏览器验收 | 桌面/窄屏截图和操作记录 |
| VPS ↔ Windows 双向 TLS | 未运行 | 两端连接日志及错误 pin/过期证书拒绝 |
| 重启后的未知任务核对 | 本地核心测试覆盖 | OS 杀进程/主机重启及外部效果核对 |
| 服务持久注册和启动策略 | 仅模板生成测试 | systemctl/schtasks 现场检查、重启行为 |
| 生产证书签发与轮换 | 仅临时证书流程测试 | 所有者授权、独立指纹核对和双端切换 |
| 日志轮转/权限/敏感内容遗漏 | 本地测试通过 | 现场日志采集及磁盘故障演练 |

严禁把未运行项替换成“通过”。真实部署须由目标主机所有者审阅和授权，不能因为已有模板就自动安装、签发或修改持久访问。
