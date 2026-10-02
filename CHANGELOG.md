# Changelog

## Intelligent Cells publication

- 项目、npm package、本机控制台、演示模型和服务模板统一更名为 Intelligent Cells / `intelligent-cells`
- 以 0.4.0 运行时为基线，整理当前使用文档，移除重复的历史报告和生成日志
- 旧状态目录、持久协议和 `UnifiedNode` 导出保留兼容；见 [更名迁移说明](docs/migration.md)
- 保留仓库原有 LICENSE；npm package 仍为 private，不发布 npm 包

## 0.4.0 — 2026-10-01 UTC

### 新增

- 每个默认/命名/创建工作区独立的目录 read/write ACL：最长完整目录前缀、显式拒绝、列表/搜索/资源过滤、write-only 与 edit 交集
- servant 主人批准的命名工作区与创建根；固定权限模板、配额、稳定请求 ID、崩溃登记与本地人工核对
- master 逻辑工作区到每个 servant 的持久映射；SYSTEM 首次实际选择自动准备，重复/并发与重启复用，不做同步或默认/本机回退
- Pi 会话固定的逻辑/显式工作区选择；资源和工具使用同一范围，模型不能改选或创建工作区
- 任务指纹、账本、jobs 与工作区 ID 绑定；跨工作区作业输出/控制拒绝
- 中文控制台关系总览、结构化授权/映射编辑器、草稿与版本冲突保护、恢复清单、任务筛选、输出分页和结构化日志

### 兼容与边界

- 旧 grant 不含 directories 时保持整工作区兼容；旧任务未带 workspace 选择器时仍使用默认 grant
- 目录 ACL 只限制内建文件/资源 API；与 exec/MCP 共存须明确 allowUnsandboxedProcesses:true，不构成进程沙箱
- 保存自动规则不等于目录已经创建；映射存在不等于远端授权仍有效
- 改变创建模板或删除批准根使已有创建工作区失效，文件保留；仅移除 workspaceCreate 停止新建并保留已有授权
- Linux loopback + 一次性测试身份 + 真实 Pi SDK/固定 mock；真实网络/Windows/模型未验收。浏览器视觉和 Unix IPC 未完成验收

见 [升级指南](docs/upgrade-v0.4.md)、[目录授权](docs/directory-permissions.md)、[工作区协议](docs/workspace-bindings.md) 与 [测试指南](docs/testing.md)。

## 0.3.1 — 2026-10-01 UTC

未知进程效果向 Master 门禁传播、跨 peer/重启隔离、在线 journal 限额预检和结果增长安全淘汰；敏感路径双向隔离、批准执行入口复核、旧 epoch job 访问拒绝。

## 0.3.0

持久化 daemon、两侧账本、未知结果核对、开发工具/长进程、本机操作台、资源/MCP 与部署模板。

## 0.2.0

TLS 1.3 mTLS/证书 pin、per-peer grants、真实 Pi harness 与本机 mock 模型。

## 0.1.0

统一节点可执行程序、双角色关系、loopback 工具派发与确定性演示。
