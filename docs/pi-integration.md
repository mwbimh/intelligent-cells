# Pi SDK 与确定性 mock 模型

Intelligent Cells 使用固定版本 `@earendil-works/pi-coding-agent@0.99.2`。Pi AgentSession、HTTP/SSE provider、工具解析、mTLS 传输、文件变更、构建和测试都真实执行；只有模型响应是确定性测试脚本。它不理解任意自然语言任务，也不验证真实 LLM 的规划能力。

## 运行

```sh
npm ci --ignore-scripts
npm run test:pi
npm run demo:pi
npm run demo:dev
```

依赖 Node.js 22.19+、npm 和 OpenSSL 3.x。演示创建临时 loopback listener、一次性证书和合成工作区，结束时清理。无需真实模型 API key 或付费模型请求。

`demo:pi` 验证 read → write → edit → exec → readback，随后验证路径越界拒绝；`demo:dev` 验证临时 Git 仓库中的实际测试失败、修复、build/test、diff 和 MCP 校验。预期 `masterLocalExecutions` 为 0。完整工作流与限制见 [资源、MCP 与开发演示](pi-resources.md)。

## 执行链路与范围

1. master 创建内存 Pi AgentSession，调用 `session.prompt()`
2. 本机 `intelligent-cells-local-mock/intelligent-cells-mock` 返回指定 scenario 的工具调用
3. Pi 校验并执行 `remote_*` 工具，经 `IntelligentCell.dispatch()` 发送
4. servant 通过自己的身份、工具、工作区、目录与配额授权后执行，结果经 mTLS 返回 Pi

Pi 仅注册 20 个远程执行工具；`workspaceList` 和 `workspaceCreate` 由本地主人/SYSTEM 管理，不向模型开放。每次会话绑定一个逻辑或显式远程工作区，模型不能切换执行位置，失败不回退默认工作区或 master 本机。

`remote_*` 名称和允许列表由 `integration/pi/remote-tools.mjs` 定义。原生本机 read/bash/write/edit/ls/grep/find/powershell 不在可调用 registry 中。每次会话都验证可用工具集合。

已有完整身份/授权配置的 master 可设 `"agent": "pi-mock"`，通过本机 stdin JSONL 调用：

```json
{"requestId":"example","command":"agent","prompt":"Run the approved fixture workflow","scenario":"workflow"}
```

此片段不替代 TLS 配置和 servant grant。scenario 决定固定测试流程，prompt 不会改变它为通用智能编程代理。

## 隔离、重试与取消

- 默认不发现用户/项目配置、skills、AGENTS.md 或 JavaScript extensions；仅加载两端显式批准的远程资源及仓库内已批准 adapter
- 不读取 `~/.pi/auth.json`、环境 API key 或 models.json；凭据接口为空，mock token 为非秘密测试值
- settings/session 使用内存；不启用 compaction、重试、cache warming、analytics 或安装遥测
- 同一 Pi toolCallId 的重复调用复用任务 ID 和结果；不同参数发生冲突。未知副作用由持久任务门禁阻止重放
- AbortSignal 请求取消同一远程任务；取消不能撤销已经提交的文件或外部副作用
- 每个 run 在 finally 中清理 listener、socket 和订阅，一次 master 仅允许一个 Pi run
- 资源文本和 MCP tool 描述不能增加权限；受信任 exec/MCP 进程仍有宿主权限，不构成 OS 沙箱

## 安全依赖修复：保留真实 Pi，固定兼容传递依赖

Pi 0.99.2 的公开 npm tarball 自带 `npm-shrinkwrap.json`，将依赖链固定为：

`@earendil-works/pi-coding-agent@0.99.2 → minimatch@10.2.6 → brace-expansion@5.0.9`

5.0.9 命中三个 DoS advisory，其中两个 high。官方补丁版 5.0.12 满足 minimatch 声明的 `^5.0.8`。npm 11.9 的 override 和 `npm audit fix` 没有修正这个嵌套 shrinkwrap。

本项目提交明确的 root-lock 修复：

1. Pi 自身 npm tarball URL、版本、SHA512 不变，未改上游源码或重打包
2. root `package-lock.json` 中将对应 brace-expansion 条目固定到官方 5.0.12 URL 和 npm registry 提供的 SHA512
3. 仅删除该 root lock 中 Pi 条目的 `hasShrinkwrap: true` 标记，让 `npm ci` 使用本项目已完整锁定的依赖树，避免再次导入上游旧 resolution

如维护者用 `npm install` 更新 lock 后再次引入旧 shrinkwrap，可显式运行：

```sh
npm run harden:pi-lock
npm ci --ignore-scripts
npm test
npm audit --omit=dev
```

`harden:pi-lock` 是本项目可审查的维护脚本，不是自动安装 hook；上游版本不符时拒绝修改。它只修改 root lock，硬编码并检查已审阅的版本/官方 integrity。测试同时检查锁文件与**实际安装**的 brace-expansion 版本，防止仅在 lock 中“看起来已修补”。

运行 `npm audit --omit=dev` 检查当前已知 advisory；审计结果随时间变化，不代表无漏洞。更换 npm/Pi 版本后必须重做 clean-install、全量测试和 audit。

## 未验证范围

真实模型/provider、付费请求、多主机组网、VPN/NAT、Windows/macOS、生产身份运维和恶意代码强隔离尚未验证。mock HTTP listener 仅用于同一可信主机的 loopback；跨节点任务使用 mTLS。

实现以已固定 SDK 的导出和源码为准；上游在线文档可能变化。参考 [Pi 官方仓库](https://github.com/earendil-works/pi) 和 [0.99.2 npm 发布包](https://www.npmjs.com/package/@earendil-works/pi-coding-agent/v/0.99.2)。
