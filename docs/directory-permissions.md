# 仆从侧目录授权

目录授权由**接收任务的仆从节点的本地主人**管理。远程 master 只能使用已授予的工具，不能提交策略来给自己加权。统一节点与「master 只派发远程工具」架构不变。

## 配置与兼容

每个 peer 可有兼容的默认 `workspace`、多个命名工作区，以及经主人批准自动创建的子工作区。每个被选中的工作区内可有多个独立目录规则：

```json
{
  "grants": {
    "master": {
      "workspace": "./workspace",
      "tools": ["capabilities", "readFile", "readChunk", "listDirectory", "searchFiles", "writeFile", "editFile", "mkdir", "writeChunk"],
      "directories": [
        { "path": "docs", "read": true, "write": false },
        { "path": "work", "read": true, "write": true },
        { "path": "work/private", "read": false, "write": false },
        { "path": "incoming", "read": false, "write": true }
      ]
    }
  }
}
```

- `path` 相对于本 peer 的 workspace；`""` 专门表示 workspace 根目录，不能用 `"."` 代替
- 每条规则必须明确写出 `read` 和 `write` 两个布尔值，最多 128 条，路径最多 500 UTF-8 字节，不允许重复路径或额外字段
- 不允许绝对路径、`..`、空路径段、反斜线、控制字符或不安全的跨平台名称；已有路径段必须是真目录，不能是文件、符号链接或路径别名
- 可以预先批准尚未创建的目录；实际 `mkdir` 仍要求父目录存在，且自己有写授权
- 同一个 peer 可配置多个分离的命名工作区/创建根；规则始终相对于当前选中的工作区，不把多个根挂载到同一个文件命名空间。配置、绑定与自动创建见 [工作区绑定](workspace-bindings.md)
- **字段完全缺省**保留原有整 workspace 权限，再由工具白名单限制；这不会自动转为新的拒绝策略
- **显式 `directories: []`**拒绝全部目录文件访问；`null` 或格式错误不等于缺省，保存会失败
- 开启限定模式后，未命中任何规则的路径默认拒绝；启用新模式不会自动创建根目录读写授权

## 继承、优先级与撤销

规则递归覆盖其目录子树，**最长的完整目录段前缀优先**，与数组顺序无关。例如 `docs` 不会命中 `docs-old`。最具体规则同时替换读写两项，不会分别从父目录拼接权限。

规则描述目录；文件读写采用其所在目录的规则。已有文件不能被配置为目录规则。

如果 `work` 可读写，而 `work/private` 两项都是 false，则 private 子树被拒绝；可再为更深的已知目录设置明确规则。要撤销一个子目录，应保存该目录的 `read:false, write:false`。

**删除规则表示恢复继承，不等同于撤销。** 删除拒绝规则可能恢复较宽的父目录授权。控制台应在保存前显示这一区别。

## 工具与目录权限取交集

| 工具 | 目录条件 | 其他约束 |
| --- | --- | --- |
| `readFile`、`readChunk` | 文件所在目录 read | 读字节限额、普通非链接文件、路径快照 |
| `listDirectory` | 起点目录 read | 分页与目录条目上限，隐藏不可读的子目录 |
| `searchFiles` | 起点目录 read；访问的目录/文件可读 | 字面文本搜索，扫描文件/字节/结果限额 |
| `writeFile`、`writeChunk` | 文件所在目录 write | 字节限额、覆盖须明确、原子写入、分块偏移/总量限制 |
| `mkdir` | 新目录路径 write | 只创建一层，父目录必须存在 |
| `editFile` | 文件所在目录 read **且** write | 合法 UTF-8、oldText 唯一匹配、原子替换 |
| `resourceRead` | 配置资源文件所在目录 read | 同时满足资源别名清单、大小与可选 SHA-256 |
| `resourceList` | 每个资源文件所在目录 read | 隐藏不可读资源；capabilities 的资源目录同样过滤 |

即使目录 read/write 是 true，没有对应工具也不能调用。write 不会自动赋予 read；尤其 edit 的匹配反馈可能透露内容，因此 write-only 不允许 edit。分块追加需要 write，允许上传者继续自己的写入；文件存在/偏移不匹配等写入错误仍会暴露有限元数据，**write-only 不是隐藏文件存在性或大小的隐私边界**。

### 列表和搜索的边界

起点目录不可读就返回 `DIRECTORY_DENIED`。例如只授予 `docs`，省略 path 的 workspace 根目录列表/搜索仍拒绝；应直接请求 `path:"docs"`。

在可读起点下，列表隐藏不可读的子目录，递归搜索剪除拒绝子树，不会穿过拒绝目录去发现更深的重新授权路径。master 若已知一个更深的明确授权路径，可以直接访问它。物理扫描预算仍然有界；拒绝子树不会返回名称、内容或资源描述，搜索的扫描预算/截断信息不是隐藏物理目录规模的保证。

### 这不是操作系统沙箱

`exec`、`mcpList`、`mcpCall` 会启动本机批准的进程。它们仍按各自的命令/入口代码、参数、工具白名单和配额执行，**不受这里的文件 API 目录 ACL 约束**；进程可使用运行节点账户本来具有的系统权限。`mcpList` 虽是发现操作，也会启动 MCP provider。

当 `directories` 存在且工具清单含以上任一工具时，必须额外配置：

```json
{ "allowUnsandboxedProcesses": true }
```

这表示本地主人明确理解并批准两类权限共存。没有明确 true，配置失败；不能把它理解为已实现进程隔离。旧版完全没有 directories 的 grant 保持兼容。批准代码的隔离/完整性检查、无 shell 启动、固定别名、参数/stdin 限额仍独立生效。强 OS 隔离需另行部署合适的低权限账户/容器；此版本不声称已经完成生产沙箱验收。

## 本地主人接口与撤销生效

控制台继续使用已有接口，不新增远程管理能力：

- `GET /api/state` 的 `permissions.effectivePolicy` 是当前有效原始策略，已排除被撤销的 peer
- `permissions.directoryPolicies[peerId]` 提供编译后的目录模式、继承规则和进程隔离说明；远程 `capabilities.filesystem` 提供同样的相对路径摘要，不公开物理 workspace 路径
- `POST /api/command`：`{command:"setPolicy", expectedEpoch, policy}` 通过本机 owner session、CSRF 与策略 epoch 检查后整体保存
- stale epoch 返回 `POLICY_CONFLICT`，要求刷新后检查差异再保存，不能默默覆盖别人的新策略
- 有效更新先完整验证策略/隔离/配额，再持久化并增加 epoch；旧活动任务和作业会取消，旧 epoch 的缓存结果、事件和远程作业控制不可继续使用。已经产生的文件副作用不会倒退，未知结果仍须本地主人核对
- 保存后的有效策略写入 durable control，重启后继续生效；不会自动改写启动配置文件。`reloadPolicy` 是明确从启动配置重新加载，若该文件还是旧规则，它会替换当前有效授权
- `revoke`/`revokePeer` 继续负责整个 peer 的授权/身份撤销；目录级撤销用明确 false/false 规则

ACL 拒绝为 `DIRECTORY_DENIED`，非法任务路径为 `PATH_DENIED`，策略格式或未确认进程共存为 `INVALID_CONFIG`。ACL 拒绝按确定未产生副作用处理，不会把未执行的写入误报成未知结果。

## 已实现的权限层次

1. 身份：TLS 1.3 双向证书认证、指定 peer pin；身份可信与工具授权分开
2. peer/工作区：仆从独立 per-peer grants、默认/命名/批准创建的 workspace、工具集合、并发/速率/超时/字节与持久记录配额
3. 目录：上述 read/write 规则及工具交集；路径/链接/快照校验继续生效
4. 进程：exec 命令别名、批准的入口代码、参数白名单、环境与 stdin 限制；长期作业属于 peer 和选中的 workspace，且受 epoch 限制
5. 资源/MCP：资源别名/类型/摘要/大小；MCP 本地主人批准的 provider 与工具、只读标记；不会从外部内容推导授权
6. 主人控制面：本机环回 HTTP、短时单次 bootstrap、HttpOnly session、Host/Origin/CSRF、串行策略更新、并发 epoch 校验、审计

没有通用 shell、远程 owner 命令、任意文件删除/重命名/chmod 工具，也没有将上述 ACL 等同于完整 OS 沙箱。

## 验证

`test/directory-policy.test.mjs` 覆盖配置边界、兼容/拒绝默认、重叠优先级、read/write 交集、write-only edit 拒绝、目录/资源发现过滤和进程权限确认。`test/acceptance-directory-permissions.test.mjs` 独立覆盖文件操作、跨 peer、mTLS + 本机 HTTP 更新、冲突、失败不生效、重启与撤销。

测试只使用临时模拟数据，未扩大现有运行实例、真实 workspace 或生产凭证的授权。
