# Intelligent Cells 更名与兼容性

本次发布以原 Unified Node Lab 0.4.0 运行时为基线，更名和整理文档，不改动任务协议或权限语义。

## 已更名

- 项目与 npm package：`intelligent-cells`，npm package 仍为 private
- 控制台标题：Intelligent Cells；服务模板默认名称：`intelligent-cells`
- 主要运行时导出：`IntelligentCell`；源码入口仍为 `src/main.mjs`
- 演示模型：`intelligent-cells-local-mock/intelligent-cells-mock`
- 演示/测试临时目录、文件写入暂存前缀和 MCP clientInfo 名称

## 保留的兼容标识

- `UnifiedNode` 仍作为 `IntelligentCell` 的同一构造器别名导出，旧代码可继续导入
- 未显式设置 `stateDir` 时，继续使用配置旁的 `.unified-node-state/<nodeId>`。不能仅因更名切换为空目录，否则会失去既有去重、授权撤销与未知任务记录
- newline JSON v2 framing、持久账本与工作区 schema、节点/peer ID、任务与工具名称保持原样
- `master` / `servant` 保留为有向关系与配置术语；同一 cell 可同时扮演两种角色

新部署可以显式选择 `.intelligent-cells-state/<nodeId>` 作为 `stateDir`。已有部署优先继续使用旧路径；确需迁移时，先停止节点、保留完整账本和输出、按现有所有者权限迁移并更新绝对路径配置，再验证未知任务、撤权和去重记录。不要清空状态后重试不确定任务。

服务计划默认名称已更改。已有服务应明确传入原 `--name`，避免把新名称误当成需要第二份服务注册；脚本只生成模板，不安装服务。

源码树不包含依赖目录、运行时状态、身份私钥、历史日志、旧发布包或本地 Git 历史。仓库已有 LICENSE 保持不变。测试方法与未验证项见 [测试指南](testing.md)。
