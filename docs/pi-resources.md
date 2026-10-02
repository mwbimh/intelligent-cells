# 受控 Pi 资源、MCP 与真实仓库固定开发流程

## 交付与边界

保留正式发布的 `@earendil-works/pi-coding-agent@0.99.2`；使用原版 SDK 与已固定安全修复的依赖树。模型仍是临时 loopback HTTP/SSE 确定性脚本：真实 provider、真实模型规划质量与持续聊天会话尚未实现。每次运行会建立新的内存 Pi session；节点任务、输出、未知结果等持久性属于节点运行时。

已实现：

- 真正 Pi session 的远程工具调用、schema 校验、模型工具回合与最终回答
- 显式加载 servant 批准的项目指令、技能文本与 prompt；内容有字节上限，可选 SHA-256 固定
- 单个显式批准、随应用审查的 `remote-audit-v1` 原生 Pi extension adapter
- 经过 master→mTLS→servant grant 的 MCP tools 桥接，不在 master 直接启动 MCP 服务
- 真实临时 git 仓库：读目录/搜索/读源码、复现失败测试、精确修复、build、test、git diff、回读及 MCP 校验
- 两节点重启后的持久结果查询；MCP 副作用未知后禁止新 ID 重试；明确核对后才通过操作员 reconcile 解锁

## 执行演示

```sh
node integration/pi/demo-development.mjs
node --test --test-concurrency=1 test/pi-resources.test.mjs test/pi-development.test.mjs
```

演示自动创建临时证书、三个不同进程角色（master、servant、MCP 子进程），只运行本项目写出的受信任小型 fixture，无生产账号、密钥、外部模型或第三方 API 调用，结束后删除临时目录。

预期结果：`version=0.99.2`、`modelRequests=14`、`remoteTaskCount=13`、`masterLocalExecutions=0`；另有三次启动前的远程资源读取。最终 `verified=true` 只有在真实工具结果满足全部条件时才出现：初始 test exit=1、精确修改成功、build exit=0 且输出 BUILD_OK、最终 test exit=0 且输出 TEST_OK、git diff 和回读包含修复、MCP sum=42。不是不论工具结果如何都输出成功。

build/test/git 都是 servant 所有者配置的固定命令别名。fixture 的受信任 runner 位于远程可写 workspace 之外，runner 明确执行 workspace 内的已知测试代码。这种开发权限允许受信任项目代码运行，**不是 OS sandbox**，不能用来安全运行恶意项目。不能把固定 runner 当作隔离边界。

## 资源权限与加载

servant grant 示例（其他必需身份配置省略）：

```json
{
  "tools": ["resourceList", "resourceRead"],
  "workspace": "workspace",
  "maxResourceBytes": 16384,
  "maxResourceTotalBytes": 65536,
  "resources": {
    "project": { "kind": "instruction", "path": "instructions/project.md" },
    "repair": { "kind": "skill", "path": "instructions/skill.md" },
    "task": { "kind": "prompt", "path": "instructions/prompt.md" }
  }
}
```

每个 resource 可另设更小的 `maxBytes` 和已审查内容的十六进制 `sha256`。没有摘要时允许批准路径上的文本随项目改变；这种文本依旧不能授予工具、凭据或执行权限。禁止链接、父目录别名、硬链接、路径越界、非 UTF-8 内容、超限内容与未知 kind。读取使用 O_NOFOLLOW、文件描述符检查及前后路径快照；这不取代 OS 隔离或对恶意同机用户的防护。

master 所有者还必须显式选择要进入 Pi 上下文的资源：

```json
{
  "agent": "pi-mock",
  "pi": {
    "resources": [
      { "peerId": "servant-a", "resource": "project" },
      { "peerId": "servant-a", "resource": "repair" },
      { "peerId": "servant-a", "resource": "task" }
    ],
    "trustedExtensions": [{ "id": "remote-audit-v1", "approved": true }]
  }
}
```

两个 allowlist 都要满足：master 的选择不覆盖 servant 的 grant。每次 Pi run 重新走远程 `resourceRead`；权限撤回、摘要变动或超限使运行在模型启动前失败。Pi 总加载内容最多 65536 bytes。所有 source 都使用 synthetic `remote-resource://peer/alias`，不映射 master 的本地文件。

项目指令放入 `getAgentsFiles()`；技能 metadata 放入 `getSkills()`，技能正文通过 `getAppendSystemPrompt()` 提供；prompt 放入 `getPrompts()`。Pi 0.99.2 的原生 `/skill:` 展开会读本地文件，所以仍禁用自动展开和默认资源扫描。技能在已验证远程上下文中使用；关联材料必须另有 resource alias，不能按远端相对路径偷偷访问 master。

操作员可用 `promptResource: {peerId, resource}` 选择已被 master 允许的 prompt；只做一次纯文本 `$USER_PROMPT` 替换，无 shell、模板脚本、动态 include 或递归替换。没有显式选择的模板不会进入 prompt。

## Extensions 的可信代码界限

默认不启用任何 extension。`remote-audit-v1` 是仓库内审查的代码，构造 Pi 0.99.2 的原生 Extension 注册对象，仅监听 agent_start/tool_call/agent_end 并记录有界 metadata。测试证明真实 Pi 调用了这些 hooks。

它必须在 master 配置中写明 `approved:true`；其他 ID、JS path、URL、代码字段或批准 false 都拒绝。没有恢复 DefaultResourceLoader，没有动态 import 用户/项目 JavaScript，也没有给资源文本执行机会。这是一个有限、可信 adapter 扩展点，**不宣称兼容任意 Pi extension 或可安全运行不可信 JS**。新增 adapter 是需要代码审查与显式配置的应用改动。

## MCP 的实际链路与配置

```text
Pi remote_mcp_call
  → node.dispatch(mcpCall, server alias, tool alias, arguments)
  → TLS 1.3 / 双向证书与 pin
  → servant 当前逐 master grant / 本地输入 schema
  → servant 启动已批准固定 MCP stdio 子进程
  → initialize → notifications/initialized → tools/list → tools/call
  → 校验文本结果 → 节点持久结果 → Pi tool result → 最终模型回答
```

原生 Pi 默认 MCP loader 没有打开；本项目的 remote-only Pi tool 是实际 servant MCP client 的桥接入口。MCP 不只是一个普通工具换名：测试运行独立 MCP 子进程，校验 JSON-RPC 生命周期和真实协议消息。

servant 本地配置：

```json
{
  "tools": ["mcpList", "mcpCall"],
  "workspace": "workspace",
  "mcpServers": {
    "fixture_math": {
      "trusted": true,
      "file": "/absolute/path/to/node",
      "args": ["/owner-approved/path/mock-mcp-server.mjs"],
      "tools": {
        "add": {
          "readOnly": true,
          "description": "Bounded integer addition",
          "inputSchema": {
            "type": "object",
            "properties": {
              "a": { "type": "integer", "minimum": -100, "maximum": 100 },
              "b": { "type": "integer", "minimum": -100, "maximum": 100 }
            },
            "required": ["a", "b"],
            "additionalProperties": false
          }
        }
      }
    }
  }
}
```

默认 `launchMode: "node-script"` 只接受 Node 可执行文件和 `args[0]` 中显式绝对、canonical、已存在的普通脚本；inline/eval、preload、module、相对入口和其他未知运行时 flag 形式拒绝，不再靠跳过 flag 的启发式检查。原生 MCP 服务可通过 `launchMode: "native"` 显式批准固定原生二进制及 argv；解释器/通用启动器不能使用该模式。入口文件都必须位于任一远程可写 grant 之外，且启动前再次核对批准时的文件身份/大小/时间，变化时返回 `MCP_CODE_CHANGED`。

command/env/URL 字段不能由 master 请求提供；子进程环境为空，不继承宿主秘密。脚本后的参数与 native argv 是主人信任的应用数据/行为，不能自动判定其中是否间接引用代码。MCP server 是所有者信任的宿主代码，固定 stdio 命令不是 sandbox；其配置、传递依赖、运行行为及是否实际只读仍需要所有者审查。

`mcpList` 只展示本地批准且服务器确实提供的工具，附本地 schema、readOnly 与 `permissionAuthority=servant-local-grant`。server 描述、annotations、tools/list 返回的新名字都不增加权限。未经批准 server/tool、额外字段和 schema 不匹配在 spawn 前拒绝。

实现是依赖 Node 标准库的**有限 MCP 2025-06-18 stdio tools client**：

- JSON-RPC 2.0、一行一个 UTF-8 JSON、初始化和能力协商、tools/list、tools/call
- 只支持文本 content；不支持图片、资源链接、catalog 分页、HTTP/SSE MCP transport、auth/OAuth、远端 URL、MCP prompts/resources、subscriptions
- 客户端未声明 roots/sampling/elicitation；server 发出的这些请求返回 -32601，不能访问 master 或 servant 的额外能力
- 本地 JSON Schema 子集：object（additionalProperties 必须 false）、array、string、integer、number、boolean、null、scalar enum 与数值/长度界限；不支持 $ref、pattern、组合 schema 或外部解析
- catalog、输入、输出和递归深度有界；服务器错误、版本不兼容、异常 framing 或超限拒绝并结束子进程
- 没有自动工具重试。mutating tools/call 发送后掉线、取消或无法确认结果返回 OUTCOME_UNKNOWN，不能当作“没执行”

stdio 生命周期/工具部分参考 [MCP 2025-06-18 transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)、[lifecycle](https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle)、[tools](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)。此处固定版本是本实现的互操作范围，不声称覆盖 MCP 后续所有版本。

## 重复、取消、未知结果与重启

Pi 每次逻辑 tool call 有固定 taskId；同一个 Pi toolCallId 完成后重复请求复用结果，不生成新的副作用；相同 ID 不同参数返回冲突。不同逻辑调用可以有新 taskId，但 node master/servant 的持久未知副作用门禁才是最终保障，不能更换 taskId 或 runId 绕过。

runId 由本地操作员传入，默认稳定的 `pi-default`，模型不控制它。Pi 单次 run 还有一个保守 unknown latch：一旦遇到未知结果，之后只允许读取/查询类工具，所有 MCP call 都按可能有副作用处理。结果确定的任务仍可显式再次执行；这一层不是跨系统 exactly-once 保证。

持久 e2e 测试让可信 MCP fixture 实际追加一行文件后丢失 response；两个节点都记 unknown。重启两节点、使用全新 Pi session/taskId 后仍拒绝再执行，文件保持一行。只读检查后，servant 操作员明确 `reconcile`，master `query` 已核对结果，才清除 gate；期间从未重放 commit。

Pi AbortSignal 仍取消同一 peer/taskId；shutdown 先中止 Pi 再断开 transport。已有加密端到端测试验证 servant 收到取消及终态。取消只能请求停止，不能撤销已提交文件/外部副作用；节点或进程清理完成也不等于副作用不存在。

## 验证范围

- `test/pi-resources.test.mjs`：真实 Pi 资源上下文、可信 native extension hooks、MCP 子进程协议、拒绝、unknown latch、重复 ID
- `test/pi-development.test.mjs`：真实加密开发完整流程、主从重启/持久结果、真实 MCP 已提交但响应丢失/门禁/核对
- `test/pi-harness.test.mjs`、`test/pi-integration.test.mjs`、`test/audit-pi-isolation.test.mjs`：原工具循环、本地旁路拒绝、加密执行、权限撤回与取消
- 独立审计 `test/audit-v03-resources.test.mjs`、`test/audit-v03-mcp.test.mjs`：链接/摘要/限额、服务器能力诱导、允许列表、无秘密继承与未知副作用

不声称完成真实 provider/持续会话、多主机 NAT/VPN、公网暴露、生产密钥运维、任意不可信代码隔离或全 MCP 协议覆盖。
