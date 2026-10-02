# 测试与验证范围

## 环境与命令

要求 Node.js 22.19+、npm、OpenSSL CLI 3.x，以及允许 loopback TCP 的 Linux 环境。测试创建一次性证书、临时工作区和本机独立进程，不需要真实模型 API key。依赖通过已提交的 lockfile 固定。

```sh
npm ci --ignore-scripts
npm test
npm run demo
npm run demo:pi
npm run demo:dev
npm audit --omit=dev
```

单独运行 Pi 回归可用 `npm run test:pi`。测试进程按文件顺序执行；不要把多个测试运行器指向同一固定网络端口并行运行。

若环境不允许 Unix domain socket，预先排除该项：

```sh
node --test --test-concurrency=1 --test-skip-pattern='owner-only Unix IPC' test/*.test.mjs
```

该命令不运行 owner-only Unix IPC 测试。Node 可能不将被过滤的用例计入 skip；`0 skip` 不代表此项通过。不能用更宽泛的权限绕过环境拒绝。

## 回归范围

- mTLS、CA/CN/指纹固定、逐 peer 授权、帧与请求限额、去重、取消和断连
- 持久账本、未知效果门禁、重启恢复、容量边界与历史淘汰
- 文件工具路径/链接保护、目录 ACL、读写交集、撤权与权限 epoch
- 命名工作区、批准根自动创建、稳定请求 ID、并发/重启复用、绑定与跨工作区作业隔离
- 固定执行入口、作业输出/取消/stdin、MCP schema/能力限制与未知副作用恢复
- 真实 Pi SDK、固定 mock provider、远程-only 工具集、资源加载和真实开发演示
- 控制台 owner HTTP、认证/同源/CSRF、静态元素、模型及确定性 DOM 控制器测试
- 产品名称、包/锁文件一致、旧构造器别名与状态路径兼容

## 必须独立验证的范围

以下不由上述自动回归证明，不能宣称生产就绪：

- Unix owner IPC 的 owner/non-owner 账户访问
- 真实浏览器渲染、焦点、键盘/鼠标、历史导航与可访问性
- VPS/LAN/公网、多设备网络、Windows/macOS、OS 服务注册与主机重启
- 生产身份签发/轮换、真实模型/provider、费用和持续会话
- 恶意代码的 OS 隔离、任意进程树强制终止、磁盘加密和跨外部系统 exactly-once

目录 ACL 仅限制内建文件/资源 API，已批准 exec/MCP 进程拥有宿主账户权限。真实部署前应按 [操作台指南](operations.md) 在目标机器逐项验收。

历史报告和机器生成的测试日志不随源码发布。测试结果应关联实际验证的提交和环境；依赖审计只是运行时点的已知 advisory，不是安全证明。
