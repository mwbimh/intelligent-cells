# Intelligent Cells

**可控权限、持久任务与远程工具的实验性节点运行时。** 当前版本 0.4.0，包含真实 Pi SDK 与固定 mock 模型，用于可复现的本机开发和安全回归。

同一个 `src/main.mjs` 运行全部节点。master / servant 是**有向关系**：A→B 时 A 是 master；B 同时可以通过自己的 agent 向 C 派发。纯 servant 不需要 agent，任何配置了出站执行关系的节点必须配置 agent。

本版在持久化统一节点基础上增加目录级读写授权、独立工作区绑定、批准根内的系统自动创建与改版中文控制台。守护运行、两侧任务账本、未知副作用门禁、开发工具与长进程、批准的资源/扩展/MCP 保持回归覆盖。**模型保持固定 mock 流程，Pi SDK / AgentSession、TLS 连接、文件变更、构建和测试进程都是真实执行。绝无 master 本机执行兜底。**

已验证的运行范围是 Linux 本机、`127.0.0.1`、一次性身份和多个独立进程。真实 VPS/LAN/Windows 组网、服务安装与真实模型尚未验收。项目不是生产就绪平台；副作用不确定时必须查询/人工核对，不宣称 exactly-once。

- [工作区绑定与系统自动创建](docs/workspace-bindings.md)
- [仆从侧目录读写授权](docs/directory-permissions.md)
- [持久化、daemon 与 unknown 恢复](docs/durability.md)
- [开发工具与进程生命周期](docs/remote-tools.md)
- [Pi 资源、MCP 与固定开发工作流](docs/pi-resources.md)
- [本机操作台基础、身份与服务模板](docs/operations.md)
- [v0.4.0 升级与控制台操作](docs/upgrade-v0.4.md)
- [版本变更](CHANGELOG.md)
- [测试命令、覆盖范围与限制](docs/testing.md)
- [更名兼容说明](docs/migration.md)

## v0.4.0 新增能力

- **目录授权**：servant 本地主人对每个工作区分别配置 read/write；最长完整目录前缀优先，限定模式未匹配默认拒绝。删除规则是恢复继承；撤销要显式保存 false/false
- **工作区映射**：一个 master 逻辑工作区可按 `logicalWorkspaceId + peerId` 分别绑定多个 servant。每个物理工作区拥有独立工具、目录规则和限额，不自动同步文件
- **系统自动创建**：servant 主人先批准创建父目录、固定权限模板和数量额度；master 主人对特定逻辑工作区/servant 启用自动准备。保存规则不创建目录，首次实际选择才由 SYSTEM 路由层准备。重复、并发和重启复用稳定 ID，不重复建目录
- **Pi 会话范围**：每次会话固定一个逻辑工作区（或显式远端 ID），资源加载和所有远程工具使用同一范围。模型不能改选或调用创建工具。缺少/失效的绑定直接报错，不转默认工作区，也不转 master 本机
- **控制台**：清楚区分入站/出站角色；结构化编辑目录、命名工作区、创建根和映射；草稿保留、版本冲突、风险确认、任务筛选、恢复清单、分页输出和结构化日志

文件 API 目录 ACL **不约束 exec/MCP 进程的宿主权限**。配置目录规则并开放这些进程工具时，主人必须显式确认 `allowUnsandboxedProcesses:true`；这不是 OS 沙箱。自动规则“已启用”、映射“已保存”和远端工作区“当前可用”是不同状态，实际执行时仍由 servant 检查权限。

旧配置没有 `directories` 时保留旧整工作区行为；旧任务省略工作区选择器仍使用其原有默认 grant。本版不会自动缩小旧权限。新部署建议明确目录规则并采用独立工作区，迁移步骤见 [升级指南](docs/upgrade-v0.4.md)。

### 沿用 v0.3.1 的安全与兼容修复

修复前台/后台 job 未知效果丢失、Master 跨 peer 门禁遗漏、运行期降低账本限额导致重启失败，以及结果增长时未淘汰可回收历史的三个已复现问题组。补充敏感目录双向隔离、执行入口固定语法/源文件变更校验和旧 epoch job 输出/控制拒绝的防护；部分额外风险来自静态审查，不把它们都宣称为修复前已完成的攻击复现。

默认命令适配器现在为 `launchMode:"node-script"`，只接受批准的 Node 可执行文件加首个绝对脚本路径，拒绝不明确的解释器参数/动态入口。原生 `git`/编译器等主人审阅的固定命令需显式 `launchMode:"native"`，只允许固定 argv，不允许远端参数或 stdin；固定命令及其参数仍属于受信任宿主能力，不构成 OS 沙箱。已有使用不支持语法的配置需要主人审阅后改为支持的适配器，不会静默恢复原权限。

旧版 job 缺少策略 epoch 时，仅本地主人可检查/停止/核对；重新授权不会开放旧 job 的远程输出。

## 一键复现

依赖：Node.js **22.19+**（实测 24.19.0）、npm、OpenSSL CLI **3.x**。测试身份使用系统临时目录中的一次性 P-256 测试 CA/证书，结束后删除；不配置生产身份、不监听外部地址、不改 VPN/防火墙/路由。

```sh
npm ci --ignore-scripts
npm test
npm run demo
npm run demo:pi
npm run demo:dev
```

Pi 的精确版本和传递依赖由 `package-lock.json` 固定。无真实模型 API key、无远程 LLM 费用。`npm ci --ignore-scripts` 从官方 npm registry 安装锁定依赖，并跳过安装脚本。锁文件显式修复上游 shrinkwrap 固定的 brace-expansion 安全问题；复现与说明见 `docs/pi*`。网络离线但依赖已安装时可运行全部测试。

- `demo`：三个独立进程、同一个执行文件，验证双角色、只读工具、拒绝、超时、断连与去重
- `demo:pi`：真实 Pi AgentSession → loopback mock OpenAI-compatible SSE → Pi tool call → 加密传输 → servant 本地工具 → tool result → Pi 最终回复
- `demo:dev`：固定 mock 完成实际 Pi → servant 的列目录/搜索/读取/编辑/真实构建/真实测试/回读闭环
- `npm test`：全部回归，包括目录 ACL、命名/自动工作区、跨工作区 jobs、真实 Pi 路由与控制台控制器/HTTP 的独立负例

在不允许 Unix domain socket 的受限环境，可使用 `node --test --test-concurrency=1 --test-skip-pattern='owner-only Unix IPC' test/*.test.mjs`。被过滤用例未执行，不能算通过。自动测试覆盖控制台 HTTP、模型/控制器和静态交付；浏览器视觉及真实交互尚未验收。

Linux 已实测；未声称 Windows/macOS 真机测试通过。OpenSSL CLI 需自行安装。测试删除仅作用于自己创建的临时目录。

## 架构与信任边界

```text
master 的真实 Pi AgentSession
  → mock 模型（仅 loopback，替代模型网络；harness 本身是真实的）
  → remote_* tools（没有内建本机 bash/read/write）
  → IntelligentCell.dispatch(peerId, task)
  → TLS 1.3：双方证书链 + 有效期 + nodeId 证书 pin
  → servant 自己的 peer grant / workspace / quota
  → 本地 tool → 加密结果 → Pi tool result → 最终回复
```

这里“端到端”指 TLS 的两个端点就是发任务和执行任务的 cell 节点。转发 TCP 字节不能看到任务明文；没有 TLS 终止型 relay，也没有实现应用层 relay E2E。模型、master 和 servant 都是可见任务内容的受信端点；磁盘文件、进程内存及本地 stdout 不受传输加密保护。

### 身份与加密

- 只支持 TLS 1.3，无明文兼容开关，无 TLS 1.2 降级
- `requestCert: true`、`rejectUnauthorized: true`，OpenSSL 验证 CA 链、有效期和 TLS 用途
- 双方在握手及派发/接收任务时检查证书有效期，且同时检查证书 CN 的 nodeId 和本地 SHA-256 证书指纹；CA 签名本身不能自动授予节点身份
- hello 的 nodeId 必须等于客户端已验证的证书身份；不能在 JSON 里冒充别的 master
- 出站连接检查预期 servant nodeId/pin；没有仅凭 IP 地址信任、TOFU 或自动配对
- 每条连接自己握手；不保存/重用客户端 TLS session，不发送 0-RTT 数据
- 默认仅 127.0.0.1；外部地址必须在同一个本地安全配置里明确 `allowExternal: true`，仍强制 mTLS。测试仅使用 loopback listener

实现依赖 [Node TLS/OpenSSL](https://nodejs.org/api/tls.html)、[X509Certificate](https://nodejs.org/api/crypto.html#class-x509certificate)；没有自制加密协议。

## 配置：权限由 servant 决定

`examples/*.json` 是结构模板，证书路径/指纹为占位符，不可直接部署。自动 demo 不使用这些占位配置，会创建并清理独立的临时配置。

```json
{
  "id": "servant-b",
  "host": "127.0.0.1",
  "port": 7312,
  "agent": null,
  "security": {
    "cert": "./identities/servant-b.pem",
    "key": "./identities/servant-b.key",
    "ca": "./identities/ca.pem",
    "trustedPeers": { "master": "<64 hex SHA-256 certificate fingerprint>" },
    "allowExternal": false
  },
  "policy": {
    "maxConcurrent": 4,
    "maxTaskRecords": 4096,
    "maxCacheBytes": 4194304,
    "grants": {
      "master": {
        "tools": ["readFile", "writeFile", "editFile"],
        "workspace": "./workspace",
        "maxConcurrent": 1,
        "maxTimeoutMs": 2000,
        "maxReadBytes": 16384,
        "maxWriteBytes": 16384,
        "maxTasksPerMinute": 120
      }
    }
  }
}
```

不同 master 可以被映射到不同 workspace 和不同工具集合，权限互不继承。上例是兼容默认工作区模式；`grant.workspaces` 可声明独立命名工作区，`grant.workspaceProvisioning.roots` 可批准自动创建根，完整模板见 [工作区绑定](docs/workspace-bindings.md)。`security.trustedPeers` 表示允许验证这个身份；`policy.grants` 表示这个身份可做什么，两者都需要。无 grant 或无工具就是拒绝。master 请求里附带的 policy/grants 不会改变 servant 配置。

出站配置：

```json
{
  "agent": "pi-mock",
  "peers": [{ "id": "servant-b", "host": "127.0.0.1", "port": 7312 }]
}
```

`deterministic-demo` 只用于低层确定性传输演示，不能冒称 Pi。`pi-mock` 使用真实 Pi harness 和 mock 模型。配置解析器拒绝旧的全局 `allowedMasters/tools` 方式；测试 helper 的兼容转换只用于旧回归测试。

### 工具协议

节点共有 22 个内置远程工具。Pi 注册其中 20 个执行工具的 remote_* 适配器；`workspaceList` / `workspaceCreate` 由本地主人或 SYSTEM 生命周期使用，不暴露为模型工具。

| 工具 | 参数 | 限制 |
|---|---|---|
| workspaceList | `{offset?,limit?}` | 当前身份可发现工作区/批准根；每页最多 32 条，不披露物理路径 |
| workspaceCreate | `{rootId,name,requestId}` | servant 批准根/模板、稳定请求 ID、数量额度，不接受权限覆盖 |
| echo | `{text}` | UTF-8 4096 bytes |
| wait | `{ms}` | grant.maxWaitMs、本地超时、可取消 |
| readFile | `{path,offset?,length?}` | 相对路径、普通文件、有界字节范围 |
| writeFile | `{path,text,overwrite?}` | 默认不覆盖；需已存在父目录；写入字节上限 |
| editFile | `{path,oldText,newText}` | oldText 必须准确出现一次；不接受空 oldText |
| exec | `{command,args:[],background?,stdin?,durationMs?}` | command 只能是本地批准的命令别名，shell=false |
| capabilities | `{}` | 当前 peer 工具、schema、命令别名与本地限额 |
| listDirectory / searchFiles | 有界分页 / 字面搜索参数 | 路径、条目、扫描文件数和字节预算 |
| mkdir / readChunk / writeChunk | 相对路径与有界字节参数 | 普通文件、分块偏移/总量控制 |
| jobStatus / jobOutput / jobCancel / jobStdin | jobId 和有界参数 | 认证 peer 隔离；长输出分页；stdin 需显式批准 |
| resourceList / resourceRead | 明确批准的 alias | instruction / skill / prompt 作为数据读取 |
| mcpList / mcpCall | 批准 server + tool + schema | 独立可信 stdio MCP 进程；不接受任意 URL/代码 |

每个普通任务可携带 `workspaceId`；master 本地主人也可用 `logicalWorkspaceId`，路由层在发送前解析为远端 ID，两者互斥。未带选择器的旧任务保留兼容行为；明确选择后的失败绝不退回默认工作区。

路径拒绝绝对路径、`.`/`..`、反斜线、冒号、空组件、符号链接和不适合的文件类型；文件工具检查 hardlink。读写检查每层目录与真实路径，终端打开使用 O_NOFOLLOW。写入使用临时文件/原子提交；并发同目标写操作由实现串行化。不是 OS sandbox：其他本地恶意进程同时替换父目录仍属于未支持的威胁模型。

受限 exec 配置示例（只有操作者审核后可配置可信文件）：

```json
{
  "tools": ["exec"],
  "workspace": "./workspace",
  "maxOutputBytes": 16384,
  "execCommands": {
    "fixture": {
      "file": "/absolute/path/to/node",
      "args": ["/absolute/path/to/approved-fixed-fixture.mjs"],
      "argsAllowed": false,
      "env": {}
    }
  }
}
```

默认 `launchMode: "node-script"`：`file` 必须是批准的 Node 可执行文件，`args[0]` 必须是绝对、canonical、已存在的普通脚本文件。解释器的 inline/eval、preload、module、相对入口和未知运行时 flag 形式均在配置阶段拒绝，不再猜测或跳过 flag 参数。原有 Node + 绝对脚本 fixture 保持兼容。其他解释器需要受审查的固定 Node wrapper。

Git 等原生开发工具仍可显式配置，例如 `{"file":"/usr/bin/git","args":["diff","--","src/math.mjs"],"launchMode":"native","argsAllowed":false}`。native 模式只接受 canonical、非 hardlink 的原生可执行映像和主人批准的固定 argv，禁止远程追加参数和 exec stdin；解释器/通用启动器不能改成 native 模式来省略入口检查。MCP 也支持同样的显式 native 入口。

两种模式都要求批准的 executable / Node 脚本位于所有 peer 可写 workspace 之外；配置时记录文件身份、大小和纳秒修改时间，每次启动前重新核对，变化后须重新审查并加载策略。这里只固定显式入口；Node 脚本后面的参数、native argv、程序配置、imports、plugins 与传递依赖的语义都属于主人批准的宿主能力，必须审查，不能据此宣称全部代码不可变或获得 OS sandbox。

不接受任意 shell 字符串、任意 executable 或请求注入 env/cwd。子进程使用明确环境，不继承主进程凭据。默认不能追加参数；`argsAllowed: true` 是操作者显式授予额外参数能力，必须了解目标程序如何解释选项，尤其解释器可能因此获得广泛权限。固定开发演示编辑合成仓库中的简单函数，再由显式批准的可信 runner 构建/测试；没有任意模型生成 shell。可信 runner 执行目标源码仍属于操作者批准的宿主代码能力，不是 OS sandbox。

所有默认/命名/自动创建 workspace（包括只读 grant）及批准创建根必须与 state、owner session/socket、专用 TLS 和日志目录双向分离：既不能包含敏感目录，也不能位于其中。配置文件本身也受保护；有意与 workspace 同级的配置文件/日志不把整个共享父目录自动变成敏感目录。

exec 输出按合并 stdout+stderr 字节限制，支持流式尾部和有界落盘分页；超限、取消或超时结束正常 POSIX 进程组。强制结束仍可能留下已产生的效果，触发 unknown 核对。非零退出码作为结果返回。主动逃逸进程组的子孙不保证终止；不提供进程/文件/网络 OS 隔离，不能把不受信程序放进此 allowlist。Windows taskkill 代码尚未实机验收。

## 配对/部署身份流程

配对流程分开“检查身份”和“授予能力”。本项目不创建任何生产长期身份，源码包不含私钥。

1. 由双方操作者在各自主机上经过授权的证书流程准备 key、有效 CA-signed cert，证书 CN 等于节点 ID，TLS client/server 用途正确
2. 仅交换公开证书；私钥留在所属主机。通过可信独立渠道核对 SHA-256 指纹
3. 在本地运行只读检查：

```sh
node scripts/pairing.mjs inspect /path/to/peer.pem expected-peer-id
```

4. 命令输出 nodeId、有效期、指纹及待审的 trustFragment，不写配置、不配对、不授予权限
5. 经操作者批准后，在自己节点配置添加该 peer 的 pin 和最小 grant；master 另外配置出站 peer
6. 先用 `node scripts/check-config.mjs config.json` 只读校验配置（不会创建 listener），再启动后检查 `relationship_accepted` / `peer_connected`，先做授权和拒绝负例，再考虑外部绑定

每个身份可暂时配置最多 4 个 pin 以便审核后的证书轮换；修改 TLS trust/key/CA 需要重启节点。无自动 CA 颁发、续期、OCSP/CRL 服务、NAT 穿透或自动发现。创建部署身份、长期信任及实际外部监听须另行审批，不能把自动测试 CA 拿来部署。

## 任务、失败与恢复语义

协议仍采用认证 TLS 中的 newline JSON v2 framing，扩展了 status query 与事件输出；单帧、JSON 深度、连接、并发、速率和磁盘保留都有界。

```json
{"v":2,"type":"task","taskId":"unique_id","runId":"project_fix","tool":"readFile","args":{"path":"hello.txt"},"timeoutMs":1000}
```

- Master 发送前落盘，Servant 调用工具前落盘；atomic rename + fsync 的校验记录跨重启保留
- 已运行但未确认的副作用为 unknown；取消和超时都不能证明“未发生”，不自动重试、不给本地兜底
- 新 taskId/runId 不能绕过 persistent unknown 门禁；只读检查、状态查询、取消可继续
- 只读 `query` 可取得远端保留的终态；not_found/expired 不解除未知写入。主人提供证据后才能本地 reconcile
- 默认 4096 完整记录达到界限后淘汰已完成结果；先落盘有界 tombstone，再删结果。旧 ID 返回 TASK_HISTORY_EXPIRED，不重跑
- unknown/运行中记录不淘汰；tombstone 有限容量耗尽时明确拒绝，避免静默丢失去重历史
- revoke 与已激活 policy/epoch 持久化；重启不恢复旧授权。显式 reloadPolicy/setPolicy 重新批准；epoch 变化后旧结果不披露
- 策略覆盖 state/config/TLS/owner 会话和运行时代码隔离。可远程读取的 workspace 不能包含状态或身份文件；可写 workspace 也不能包含 node 配置/日志或 runtime 代码

工作区本机命令：listWorkspaceBindings、remoteWorkspaces、bindWorkspace、unbindWorkspace、setWorkspaceAutoProvision、ensureWorkspaceBinding、createWorkspace、reconcileWorkspaceCreation。

其他常用本机命令：status、permissions、listTasks、taskStatus、taskEvents、operationStatus、query、cancel/cancelTask、listJobs/jobStatus/jobOutput/jobCancel、reconcile/reconcileJob、revoke、reloadPolicy/setPolicy、agent、dispatch、shutdown。网络 master 无权执行本地主人命令。

开发时使用 stdin JSONL；部署模式显式使用 `--daemon`，不依赖 stdin。`--operator` 开启有认证、同源和 CSRF 保护的 loopback 管理页；后台通过私有临时 owner 文件或 Unix socket 获取会话，不能从日志获取秘密。详细命令、数据状态和故障恢复流程见 [v0.3 持久化说明](docs/durability.md)。

## 日志与可见性

JSONL 事件带 timestamp/nodeId/pid/masterId/taskId，包括身份拒绝、任务拒绝、启动/完成、取消、撤权和重连。

- 开发用 stdout 的 command_result 包含结果，可能有正文或 Pi transcript，只交给可信本地主人
- 持久化 audit 元数据白名单过滤参数、结果、提示词、环境和错误正文；默认在 stateDir，允许显式私有 logFile
- 内置轮转（默认每文件 1 MiB、4 个历史文件）、过滤查询和主人操作台查看；不是防篡改审计系统
- 任务结果和进程输出保存在私有 stateDir，磁盘未加密；不能将其随源码打包或公开分享

## 已实现与延期事项

v0.4.0 包含目录 ACL、独立工作区、系统首次选择自动创建/重复及重启复用、工作区级任务/作业隔离、Pi 会话范围与本机控制台。

沿用能力：统一 executable/双角色、真实 Pi harness + 固定 mock、TLS 1.3 mTLS/pin、per-peer grants、daemon、持久 ledger/journal/revoke、unknown 门禁和主人核对、bounded retention、开发文件工具、长任务/输出/stdin/取消、本地操作台、配置与公开身份检查、批准资源/内建扩展/MCP、日志与服务模板。

延期或未实现：生产模型/provider 会话和费用控制、真实 VPS/LAN/Windows 网络/服务实机验收、生产证书自动颁发续期、relay E2E/NAT 穿透和自动发现、OS sandbox/容器隔离、恶意子孙强隔离、磁盘加密。跨外部副作用的 exactly-once 不作承诺。

详细信息见 [Pi 集成](docs/pi-integration.md)、[资源与 MCP](docs/pi-resources.md)、[工作区路由](docs/workspace-bindings.md) 和 [测试指南](docs/testing.md)。服务模板只生成供审阅的文本，不安装 OS 服务，不修改防火墙或 VPN。

## 许可证

仓库沿用目标项目已有的 [GNU Affero General Public License v3](LICENSE)。第三方依赖保留各自许可证。
