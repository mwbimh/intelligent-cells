# 工作区绑定与系统自动创建

一个 master 的逻辑工作区可以分别绑定到多个 servant 的工作区。绑定键是 **`logicalWorkspaceId + peerId`**，不是主控本地绝对路径。工作区选择只决定远端执行范围，不做文件同步、复制、删除，也不会回退到 master 本机执行。

## 三条使用路径

1. **绑定已有工作区**：servant 主人预先配置命名工作区；master 主人从该 servant 的已批准目录中选择绑定
2. **手动创建并绑定**：master 主人选择 servant 已批准的创建根 `rootId` 和安全名称；使用固定 `creationRequestId` 创建，可同时绑定
3. **系统自动创建**：master 主人对某个逻辑工作区/servant 开启自动准备，并选择已批准的 `rootId`。后续普通 `dispatch` 或真实 Pi 运行选择该逻辑工作区时，由路由层先自动创建、保存绑定，再执行原工具。模型不需要先调用 `workspaceCreate`

自动功能默认关闭。绑定已经存在时直接复用；同一个逻辑工作区的并发准备合并为同一操作。不同逻辑工作区独立保存，不会因另一条绑定保存引起无关 revision 冲突。所有普通工具仍受 servant 的并发、速率、超时和字节配额限制，忙时可以返回 `BUSY`；系统不会因此改用默认工作区。

## servant 主人配置

下面的路径仅为示例。根目录必须由主人提前创建并批准；远程 master 不能指定实际父路径或新增工具权限。

```json
{
  "grants": {
    "master": {
      "tools": ["workspaceList", "workspaceCreate"],
      "workspaces": {
        "reference": {
          "workspace": "/srv/reference",
          "tools": ["readFile", "listDirectory"],
          "directories": [{"path":"", "read":true, "write":false}]
        }
      },
      "workspaceProvisioning": {
        "roots": {
          "projects": {
            "path": "/srv/approved-projects",
            "maxWorkspaces": 8,
            "grant": {
              "tools": ["capabilities", "readFile", "writeFile", "editFile", "listDirectory", "mkdir"],
              "directories": [{"path":"", "read":true, "write":true}]
            }
          }
        }
      }
    }
  }
}
```

- 父 grant 不必有默认 `workspace`。管理权限和所选工作区的执行权限相互独立；仅授予 `workspaceCreate` 不会授予文件读写，`mkdir` 也不会授予创建工作区权限
- 旧 `grant.workspace` 保留为 `default`；未带选择器的旧任务行为不变
- 每个命名工作区是完整 grant，必须明确 `workspace` 和 `tools`，不从父 grant 拼接或扩展权限。最多 32 个；ID 为 1..64 个字母、数字、下划线或连字符，保留 `default` 和 `ws_` 前缀
- 每个创建根要求明确 `path`、`maxWorkspaces` 和默认 `grant`。quota 为 1..128，最多 16 个根。默认 grant 必须明确 `tools` 和 `directories`，其余读写/进程限制继续采用既有有界缺省值
- 嵌套 grant 不能含 `workspaceList`/`workspaceCreate`、其他命名工作区或创建根；创建模板也不能含自己的 `workspace`
- 子工作区的目录规则相对于**选中的子工作区**。进程权限仍需独立白名单；与目录 ACL 共存时要求 `allowUnsandboxedProcesses:true`，不构成 OS 沙箱
- 创建根必须是已存在、canonical、由当前运行账户拥有且无组/其他账户写位的目录；不能是链接或别名。所有创建根彼此不重叠，且不能覆盖或落在任何已有默认/命名 workspace、状态、配置、TLS/日志、owner session 或运行代码范围内
- 所有 named/default/provisioning 范围一起参与批准代码隔离检查，不能把批准脚本放进可创建或可写范围。模板中的 MCP 工作目录会重定位到实际创建的子工作区，批准的执行入口不变

## master 主人接口

所有管理命令使用现有本机 owner HTTP session/CSRF，或本地主人 stdin 通道。没有远程 owner 策略编辑能力。

- `listWorkspaceBindings`：返回 `{revision, bindings, autoProvision, creations}`。`GET /api/state` 响应的 `workspaces` 字段提供同样快照；servant 的 `creations` 可显示未完成/未知/已确认状态
- `remoteWorkspaces {peerId}`：返回 `{workspaces, creationRoots}`，只包含该身份可发现的信息，不公开 servant 绝对路径。工作区条目含 `id/name/kind/state/tools/filesystem`；创建根含 `id/maxWorkspaces/used/remaining/tools/filesystem`
- `bindWorkspace {peerId, logicalWorkspaceId, workspaceId, expectedRevision}`：先检查远端条目为 `ready`，再保存本地映射
- `unbindWorkspace {peerId, logicalWorkspaceId, expectedRevision}`：只解除映射，远端文件保留。若自动规则仍开启，下次选择会复用原自动创建的工作区并重新绑定
- `setWorkspaceAutoProvision {peerId, logicalWorkspaceId, rootId, enabled, expectedRevision}`：保存自动规则。启用前查询可用根；关闭已有规则无需 servant 在线。保存规则本身不会创建目录
- `ensureWorkspaceBinding {peerId, logicalWorkspaceId}`：显式触发准备；普通逻辑工作区派发也会自动触发。已有绑定的返回表示映射存在，不替代执行时的远端授权检查
- `createWorkspace {peerId, rootId, name, creationRequestId, logicalWorkspaceId?, expectedRevision?}`：手动创建，可同时绑定；返回 `{workspace, binding?, revision}`

HTTP bind/unbind/set-auto 必须提供当前 revision；手动创建并绑定也必须提供。冲突返回 `WORKSPACE_BINDING_CONFLICT`，要求刷新后检查。创建已经成功但绑定发生冲突时，远端目录和稳定 ID 保留；相同请求可查询/重试绑定，不会再创建一份。

`name` 为 1..64 个字母、数字、下划线或连字符，必须以字母或数字开头，拒绝保留设备名。`creationRequestId` 为 1..100 个字母、数字、下划线或连字符，同一请求重试必须保持不变。自动命名为 `w_<逻辑ID前缀>_<摘要>`，自动请求 ID 从 master 身份、peer、逻辑 ID、root ID 稳定推导，重启或解除/重建绑定均可复用。

## 任务与 Pi 路由

```json
{
  "command":"dispatch",
  "peerId":"servant",
  "task":{
    "taskId":"read_example_1",
    "logicalWorkspaceId":"project_alpha",
    "tool":"readFile",
    "args":{"path":"README.md"},
    "timeoutMs":2000
  }
}
```

master 在网络发送前把逻辑 ID 解析成 servant 的 `workspaceId`。调用者也可明确提供 `task.workspaceId`；两种选择器互斥。所选工作区不存在、不可用或未绑定且自动规则关闭时直接拒绝，不转到 `default`。

真实 Pi adapter 的 `agent` 命令支持 `logicalWorkspaceId` 或 `workspaceId`，选择范围传到资源加载与每个远端工具调用。自动准备按实际使用到的 servant 惰性触发；不会为未使用的 peer 分配目录。运行中既定范围不能被某次模型调用替换为另一工作区。stock 本机工具仍不注册。

wire 增加两个普通、受 grant 限制的工具：

- `workspaceList {offset?, limit?}`：分页返回目录和根，默认 32 条、每页最多 32 条，返回 `nextOffset`；编码预算有界。master 的 `remoteWorkspaces` 自动合并页面
- `workspaceCreate {rootId, name, requestId}`：只能使用 servant 当前批准的根和固定模板；不接受绝对路径、权限覆盖或工作区选择器

正常任务指纹、两侧账本和作业记录均保留选中的 workspace ID。一个 workspace 的远程 job 输出、stdin 或取消不能从另一 workspace 的授权取得，重启后仍适用。旧版没有 workspace ID 的任务和 job 视为默认工作区。

## 持久化、重复、崩溃与未知结果

本地绑定/自动规则与 servant 创建登记写入现有 node state 下的校验和、原子替换文件，并受原有独占 state lock 保护。登记最多 1024 条创建历史、1024 条绑定和 1024 条自动规则，满后明确拒绝，不丢弃请求 ID。

创建顺序是：持久化 intent → 排他 `mkdir` → 父目录 fsync → 持久化新目录 inode/dev → 再校验并提交 ready。已有目录从不自动接管，即使它是空目录；不提供删除/回滚用户目录功能。

- 已 ready 的同一 requestId 返回相同 ID；即使 quota 已满也复用。相同 requestId 携带不同根或名称会被拒绝
- quota 按 peer/root 计算，pending/unknown 也占用；根物理范围全局互不重叠
- 重启时，已提交的目录身份若仍一致，可以完成 `created → ready`。只有 intent、无法证明新目录身份的记录保持 `unknown`，不自动重放、接管或删除
- 对已证明 ready 的创建，可从登记安全恢复同一 incoming 创建任务的终态；一般文件/进程的未知效果机制不变
- `reconcileWorkspaceCreation {masterId, workspaceId, resolution:"completed"|"not_created", note}` 仅供 servant 本地主人检查后操作。completed 是主人明确认领已检查目录；not_created 还会验证目录确实不存在。匹配的未知创建任务一起核对；master 再 query 原任务可解除其对应未知门禁
- 失败/已确认未创建的请求 ID 仍被消耗，不会被重用执行；要创建新的操作需新 ID。未知工作区不能绑定或执行，控制台必须显示待主人检查

这不是 filesystem 与 journal 的单一事务，不声称 exactly-once。进程拥有宿主账户权限，无法防御有同等本地权限的恶意 owner；对本地管理员改名/替换创建父目录的并发操作仍采用身份校验、拒绝和人工恢复。

## 修改权限与错误

移除 `workspaceCreate` 工具只停止新创建；已有已批准工作区仍可使用。移除创建根、撤销 peer 或改变该根的原始默认 grant，会让旧 provisioned ID 不可用，不能悄悄套用较宽模板。恢复完全相同的已批准模板可以恢复访问，quota 计数仍保留。对象键顺序不影响摘要，但工具/目录数组顺序以及显式/缺省字段差异会改变摘要；修改前应核对现存项目。

已有 named workspace 由本地主人显式配置的稳定别名标识。更换 named workspace 路径属于主人重新配置该别名；策略 epoch 更新后，旧缓存任务/作业仍受既有 epoch 限制。

常见拒绝：`WORKSPACE_DENIED`、`WORKSPACE_BINDING_NOT_FOUND`、`WORKSPACE_BINDING_CONFLICT`、`WORKSPACE_CREATE_DENIED`、`WORKSPACE_QUOTA`、`WORKSPACE_NAME_CONFLICT`、`WORKSPACE_REQUEST_CONFLICT`、`WORKSPACE_CREATE_UNKNOWN`。非未知的配置、目录拒绝和 quota 错误不应误报已经发生文件效果；未知创建则保持门禁并请求主人核对。

## 验证边界

- `test/workspaces.test.mjs`：配置范围、模板独立权限、代码/状态隔离、稳定 ID、quota、登记重启、intent 未知/身份恢复、人工核对、改权失效、并发独立绑定、MCP 子目录重定位
- `test/acceptance-workspace-bindings.test.mjs`：独立多进程 mTLS/owner HTTP 生命周期、绑定/解除/重启、自动首次选择、重复/并发、拒绝/缺省禁止回退
- `test/workspace-jobs.test.mjs`：真实批准的只输出进程，以及跨工作区 job 输出/控制和重启持久性
- `test/pi-workspaces.test.mjs` 与 `test/pi-workspace-integration.test.mjs`：真实 Pi SDK/AgentSession 的工作区选择，以及双逻辑工作区自动创建、隔离文件操作、双方重启和取消顺序测试；模型仍为本机确定性 mock

测试只使用临时合成数据和一次性本机证书。生产凭证、实际运行实例、既有真实 workspace、浏览器视觉与 Unix IPC 不在已验证范围内。
