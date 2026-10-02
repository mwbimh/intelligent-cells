// Generates reviewable deployment text ONLY. Never runs systemctl, schtasks,
// privilege changes, firewall changes, key generation or persistent grants.
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
function checked(value, label) { if (typeof value !== 'string' || !value || /[\r\n\0]/.test(value)) throw new Error(`Invalid ${label}`); return value; }
const systemd = value => '"' + checked(value, 'systemd argument').replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('%', '%%') + '"';
const xml = value => checked(value, 'XML value').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&apos;');
export function servicePlan({ platform, project, config, node = process.execPath, name = 'intelligent-cells', user, stateDir, writableWorkspace }) {
  if (!['linux', 'windows'].includes(platform) || !/^[a-zA-Z0-9_-]{1,64}$/.test(name)) throw new Error('Platform must be linux/windows and service name must be an identifier');
  for (const [label, value] of Object.entries({ project, config, node, stateDir })) { checked(value, label); if (!(platform === 'windows' ? path.win32 : path.posix).isAbsolute(value)) throw new Error(`${label} must be an absolute ${platform} path`); }
  const entrypoint = (platform === 'windows' ? path.win32 : path.posix).join(project, 'src', 'main.mjs');
  const common = { dryRun: true, registered: false, installed: false, networkTested: false, identityGenerated: false, grantsCreated: false, platform, name, preflight: ['由所有者预先提供并核对正式 CA、节点证书、私钥及对端指纹', '配置 stateDir、logFile 与最小授权工作区；数据目录不得与可执行代码重叠', '先在交互终端运行配置检查和服务验收；确认运行身份只拥有必要目录权限', '取得所有者对持久服务安装、网络监听与身份访问的明确批准后，手动执行安装'], rollback: ['停止服务/计划任务', '禁用或移除服务注册（保留配置、密钥和账本）', '恢复已核验的旧程序版本和配置；不可清空账本后重试不确定任务'] };
  if (platform === 'linux') {
    if (!user || !/^[a-z_][a-z0-9_-]{0,31}$/.test(user) || user === 'root') throw new Error('Linux plan requires an existing non-root --user');
    if (writableWorkspace && !path.posix.isAbsolute(writableWorkspace)) throw new Error('Linux workspace must be absolute');
    const writable = [stateDir, path.dirname(config), ...(writableWorkspace ? [checked(writableWorkspace, 'workspace')] : [])];
    return { ...common, filename: `${name}.service`, contents: `[Unit]\nDescription=Intelligent Cells execution node (${name})\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=${user}\nWorkingDirectory=${systemd(project)}\nExecStart=${systemd(node)} ${systemd(entrypoint)} --config ${systemd(config)} --daemon\nRestart=on-failure\nRestartSec=3\nTimeoutStopSec=45\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=${writable.map(systemd).join(' ')}\nPrivateTmp=yes\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target\n`,
      manualRegistration: [`sudo install -m 0644 ${name}.service /etc/systemd/system/${name}.service`, 'sudo systemctl daemon-reload', `sudo systemctl enable --now ${name}.service`], verification: [`systemctl status ${name}.service`, `journalctl -u ${name}.service --since today`, `node scripts/service-acceptance.mjs --socket <stateDir/operator.sock>`], note: 'systemd 模板仅生成，不执行。项目与密钥权限应预先配置；命令沙箱不是 OS 级容器。' };
  }
  checked(user, 'Windows owner --user');
  if (['SYSTEM', 'LOCALSERVICE', 'NETWORKSERVICE'].includes(user.toUpperCase())) throw new Error('Windows plan requires a real interactive owner identity');
  if (/["%\r\n]/.test(config + entrypoint)) throw new Error('Windows arguments cannot contain quote or environment expansion characters');
  return { ...common, filename: `${name}.task.xml`, contents: `<?xml version="1.0" encoding="UTF-8"?>\n<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n <RegistrationInfo><Description>Intelligent Cells: owner-reviewed, non-elevated task</Description></RegistrationInfo>\n <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>${xml(user)}</UserId></LogonTrigger></Triggers>\n <Principals><Principal id="Author"><UserId>${xml(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\n <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>\n <Actions Context="Author"><Exec><Command>${xml(node)}</Command><Arguments>${xml(`"${entrypoint}" --config "${config}" --daemon`)}</Arguments><WorkingDirectory>${xml(project)}</WorkingDirectory></Exec></Actions>\n</Task>\n`,
    manualRegistration: [`schtasks.exe /Create /TN ${name} /XML ${name}.task.xml`, `schtasks.exe /Run /TN ${name}`], verification: [`schtasks.exe /Query /TN ${name} /V /FO LIST`, 'Get-Content <stateDir>\\audit.jsonl -Tail 50'], note: '仅提供登录后、当前用户、非提升的计划任务模板；不是 Windows 服务，也不宣称注销后运行。真正服务包装器及无人登录凭据配置待所有者审批与目标机验证。Windows 后台不启用 Unix 管理套接字；需要 UI 时先停止计划任务再在交互终端运行。' };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const flags = {}; const args = process.argv.slice(2);
    for (let i = 0; i < args.length; i += 2) { if (!/^--[a-z-]+$/.test(args[i]) || !args[i + 1]) throw new Error('All options need values'); flags[args[i].slice(2)] = args[i + 1]; }
    const plan = servicePlan({ platform: flags.platform, project: flags.project, config: flags.config, node: flags.node ?? process.execPath, name: flags.name, user: flags.user, stateDir: flags['state-dir'], writableWorkspace: flags.workspace });
    if (flags['write-dir']) { const dir = path.resolve(flags['write-dir']); await fs.mkdir(dir, { recursive: true }); await fs.writeFile(path.join(dir, plan.filename), plan.contents, { flag: 'wx', mode: 0o600 }); }
    console.log(JSON.stringify(plan, null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
