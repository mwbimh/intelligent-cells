# v0.4.0 升级与控制台操作

基线为 v0.3.1。此指南用于已获主人批准的本机节点；示例是配置/命令说明，不会为现有运行实例自动授权。没有生产迁移、服务安装或外网验证。

## 1. 保留现有数据并检查配置

1. 停止派发新任务，先查询/核对未知任务和作业，再正常停止节点。取消不是回滚
2. 由节点主人私下保存启动配置、身份材料和完整 stateDir 的备份。备份含秘密与任务正文，不能随源码发布；升级时不要删除账本、撤销记录或旧请求 ID
3. 使用独立的 v0.4.0 源码目录并安装锁定依赖。Node.js 需要 22.19+，测试还需要 OpenSSL CLI 3.x

```sh
npm ci --ignore-scripts
node scripts/check-config.mjs /absolute/path/to/node.json
```

配置检查不启动 listener。例子中的证书/指纹是占位符，不能直接部署。采用原有私有 stateDir 启动时，会为工作区登记增加校验文件；既有账本、控制策略和撤销信息继续使用。不要在运行中拷贝/替换部分状态文件，也不要通过旧快照回滚消除未知效果。降级到 v0.3.1 不能理解新工作区功能，不能作为盲目恢复手段。

- 旧 `workspace` 成为兼容默认工作区，未带选择器的旧任务不变
- `directories` 缺省保留整工作区旧行为；明确 `[]` 拒绝文件路径。升级不自动收窄旧权限
- 新命名工作区必须自己列出工具/路径；新创建根必须自己列出工具、目录模板与额度，不继承父级执行权限
- v0.3.1 的固定 Node 入口/显式 native 适配器和旧 job epoch 限制继续生效

## 2. 打开本机控制台

```sh
node src/main.mjs --config /absolute/path/to/node.json --daemon --operator
```

在同一节点主机、同一运行账号的新终端中，从 `operator_ready.ownerFile` 取到本次运行的私有访问文件路径，然后：

```sh
OWNER_FILE=/absolute/path/from/operator_ready.json
node scripts/operator.mjs open --session-file "$OWNER_FILE"
```

在同一主机浏览器打开输出 URL。输出含短期一次性秘密，不要贴到聊天、日志或工单。详细认证、退出及 Windows 限制见 [操作台指南](operations.md)。本次发布的自动验收覆盖 owner HTTP/控制器；未完成浏览器视觉验收。

## 3. servant 主人先批准范围

在“目录与权限”选择调用方节点：

- 默认目录授权的每条规则同时写出 read/write。空路径代表工作区根；最长完整目录前缀优先。未命中默认拒绝，不会为了浏览已授权子目录而开放父目录
- 删除子规则恢复父规则继承；要撤销一个目录，保存该目录 false/false。保存前核对控制台风险说明
- 可以增加“已存在的命名工作区”，每个独立配置路径、工具、目录规则和限额
- 若需要系统首次选择自动创建，先由主人在合适的位置准备专用父目录，再在“允许创建工作区的父目录”加入别名、路径、额度与固定模板，并明确开放 workspaceList/workspaceCreate
- 父目录必须已有、canonical、由运行账号拥有且无其他账号写位，与其他工作区、状态、身份、运行代码等受保护路径分离。远程 master 只能选择别名，不能传入实际路径或提升模板

最小“仅管理独立工作区”的 policy 示例：

```json
{
  "grants": {
    "master": {
      "tools": ["workspaceList", "workspaceCreate"],
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

这是 node 配置中 `policy` 的值，不是完整节点配置。`/srv/approved-projects` 只是路径示例，必须由对应主机主人审阅并提前准备。目录 ACL 不限制 exec/MCP 实际可读写的宿主范围；开放进程工具须审查固定命令/provider，并在相关 grant 明确设置 `allowUnsandboxedProcesses:true`。

## 4. master 主人绑定或启用自动准备

“工作区映射”先选择逻辑工作区 ID 和 servant，再刷新远端目录。逻辑 ID 是稳定项目标识，不能填写本机绝对路径。

- 绑定已有 ready 工作区：只保存映射，不复制文件
- 手动创建：选择批准根、安全名称和稳定创建请求 ID，可同时绑定。重复请求必须使用相同根/名称/请求 ID
- 自动准备：为这一逻辑工作区与 servant 选择批准根并开启。保存规则不会创建目录；“准备/复用”或后续真正选择该逻辑工作区时，SYSTEM 才创建/复用并保存映射

命令行查询也走相同的认证 HTTP 通道：

```sh
node scripts/operator.mjs command --session-file "$OWNER_FILE" '{"command":"remoteWorkspaces","peerId":"servant"}'
node scripts/operator.mjs command --session-file "$OWNER_FILE" '{"command":"listWorkspaceBindings"}'
```

下面的 Node 片段先读取当前 revision 再提交规则；运行前替换文件路径、peer、逻辑 ID 与已批准根别名。它不绕过并发冲突检查，另一编辑者先提交时会拒绝而不是自动覆盖：

```sh
node --input-type=module - "$OWNER_FILE" <<'JS'
import { connectOperator } from './scripts/operator.mjs';
const client = await connectOperator(process.argv[2], { sessionFile: true });
try {
  const snapshot = (await client.request('/api/command', { command: 'listWorkspaceBindings' })).result;
  const result = await client.request('/api/command', {
    command: 'setWorkspaceAutoProvision', peerId: 'servant', logicalWorkspaceId: 'project_alpha',
    rootId: 'projects', enabled: true, expectedRevision: snapshot.revision,
  });
  console.log(JSON.stringify(result, null, 2));
} finally { await client.request('/api/logout', {}); }
JS

node scripts/operator.mjs command --session-file "$OWNER_FILE" '{"command":"ensureWorkspaceBinding","peerId":"servant","logicalWorkspaceId":"project_alpha"}'
```

这是 master 的 owner 文件；在 servant 上运行不能修改另一节点的映射。映射已保存只证明本地选择，实际文件/进程任务仍由 servant 按当前批准范围校验。第一次创建得到空目录，不会同步 master 源码，也不会自动复制资源文件。

Pi 的本地主人 stdin 命令例子如下，发送给非 daemon 的 master 实例；`agent` 不在 HTTP owner API 的命令白名单中：

```json
{"command":"agent","logicalWorkspaceId":"project_alpha","prompt":"Read hello.txt in this remote project"}
```

每次 Pi 会话只固定一个逻辑工作区（或一个显式 `workspaceId`），两者互斥。资源和所有模型工具沿用该范围。首次使用才为实际选中的 servant 准备，未使用 servant 不分配目录；同一次会话不能由模型参数切换项目。mock 默认读取 hello.txt，新空工作区必须先通过批准路径准备这个文件，读取不存在文件会按正常规则失败。

## 5. 复用、撤销与异常恢复

- 并发/重复选择和正常重启复用持久绑定及稳定创建 ID。创建根额度满时，已成功的同一请求仍可复用
- 解除绑定不删除目录。若自动规则仍开着，下次会重新绑定原自动创建的工作区；要停止自动准备，也需关闭该规则
- 仅关闭 workspaceCreate 停止新建，已有授权仍有效。删除批准根/修改原始模板/撤销 peer 会使旧创建 ID 失效；数据保留，不能自动迁移或套用新权限
- 创建中断、未知结果或名字冲突不自动重放/接管已有目录。servant 主人检查后用 reconcileWorkspaceCreation 记录 completed/not_created 与证据，再由 master 查询原任务。不要换请求 ID 盲目绕过 unknown
- 目录拒绝、失效工作区、quota、离线、版本冲突和任务失败均不得转默认工作区或 master 本机执行
- 策略保存使用 expectedEpoch；映射保存使用 expectedRevision。冲突后刷新并审阅差异，不能静默覆盖。运行时策略持久保存但不改写原启动文件，reloadPolicy 会明确采用磁盘内容

完整命令、状态机及限制见 [工作区绑定](workspace-bindings.md)。

## 6. 回归验证

升级后，先在一次性环境中运行 [测试指南](testing.md) 中的完整测试和三个 demo，再按 [操作台指南](operations.md) 校验目标节点。

升级不替代真实目标机验收。Unix IPC 与浏览器视觉未完成验证；受限环境中被过滤的测试不计为通过。Intelligent Cells 更名的状态目录和 API 兼容说明见 [迁移指南](migration.md)。
