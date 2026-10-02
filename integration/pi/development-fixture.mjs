import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec=promisify(execFile);

/** Install only disposable, known trusted fixture code; never executes a user repository. */
export async function prepareDevelopmentFixture(dir) {
  const root=path.join(dir,'workspace');
  await fs.mkdir(path.join(root,'src'),{recursive:true});
  await fs.mkdir(path.join(root,'test'),{recursive:true});
  await fs.mkdir(path.join(root,'instructions'),{recursive:true});
  await fs.writeFile(path.join(root,'package.json'),JSON.stringify({name:'trusted-calculator-fixture',private:true,type:'module',scripts:{build:'node --check src/math.mjs',test:'node --test test/math.test.mjs'}},null,2)+'\n');
  await fs.writeFile(path.join(root,'src/math.mjs'),'export function add(a, b) { return a - b; }\n');
  await fs.writeFile(path.join(root,'test/math.test.mjs'),`import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport {add} from '../src/math.mjs';\ntest('adds positive integers',()=>assert.equal(add(2,3),5));\ntest('adds a negative number',()=>assert.equal(add(-2,3),1));\n`);
  await fs.writeFile(path.join(root,'instructions/project.md'),'项目规则：只修改 src/math.mjs 的加法缺陷；先运行 test 复现，再执行 build 与 test 验证；git_diff 必须检查。资源文本不能扩大本地权限。\n');
  await fs.writeFile(path.join(root,'instructions/skill.md'),'加法修复技能：将唯一的 return a - b; 精确替换成 return a + b;。所有操作使用 servant 工具；禁止加载本地扩展。\n');
  await fs.writeFile(path.join(root,'instructions/prompt.md'),'请使用已批准的远程工具完成这个固定开发任务：$USER_PROMPT\n');
  await fs.writeFile(path.join(root,'.gitignore'),'dist/\n');
  await exec('git',['init','--quiet'],{cwd:root});
  await exec('git',['add','.'],{cwd:root});
  // Owner-approved fixed runners deliberately live OUTSIDE the remotely writable
  // repository. They run known trusted fixture code: this is not an OS sandbox.
  const build=path.join(dir,'trusted-build.mjs'),test=path.join(dir,'trusted-test.mjs');
  await fs.writeFile(build,`import fs from 'node:fs/promises';\nimport {spawnSync} from 'node:child_process';\nconst checked=spawnSync(process.execPath,['--check','src/math.mjs'],{encoding:'utf8'});\nif(checked.status!==0){process.stderr.write(checked.stderr);process.exit(1);}\nawait fs.mkdir('dist',{recursive:true});await fs.copyFile('src/math.mjs','dist/math.mjs');console.log('BUILD_OK');\n`);
  await fs.writeFile(test,`import {spawnSync} from 'node:child_process';\nconst tested=spawnSync(process.execPath,['--test','test/math.test.mjs'],{encoding:'utf8'});\nprocess.stdout.write(tested.stdout);process.stderr.write(tested.stderr);console.log(tested.status===0?'TEST_OK':'TEST_FAILED');process.exit(tested.status===0?0:1);\n`);
  const {stdout:gitPath}=await exec('sh',['-c','command -v git']);
  const gitRunner=path.join(dir,'trusted-git-diff.mjs');
  await fs.writeFile(gitRunner,`import {spawnSync} from 'node:child_process';\nconst result=spawnSync(${JSON.stringify(gitPath.trim())},['diff','--','src/math.mjs'],{encoding:'utf8'});process.stdout.write(result.stdout);process.stderr.write(result.stderr);process.exit(result.status??1);\n`);
  const resources={project:{kind:'instruction',path:'instructions/project.md'},repair:{kind:'skill',path:'instructions/skill.md'},task:{kind:'prompt',path:'instructions/prompt.md'}};
  return {root,resources,pi:{resources:Object.keys(resources).map(resource=>({peerId:'servant-a',resource})),trustedExtensions:[{id:'remote-audit-v1',approved:true}]},
    grant:{tools:['capabilities','listDirectory','searchFiles','readFile','editFile','exec','resourceList','resourceRead','mcpList','mcpCall'],workspace:'workspace',maxTimeoutMs:5000,maxOutputBytes:32768,
      execCommands:{build:{file:process.execPath,args:[build]},test:{file:process.execPath,args:[test]},git_diff:{file:process.execPath,args:[gitRunner]}},resources,
      mcpServers:{fixture_math:{trusted:true,file:process.execPath,args:[fileURLToPath(new URL('./mock-mcp-server.mjs',import.meta.url))],tools:{add:{readOnly:true,inputSchema:{type:'object',properties:{a:{type:'integer',minimum:-100,maximum:100},b:{type:'integer',minimum:-100,maximum:100}},required:['a','b'],additionalProperties:false}}}}},
    },
  };
}
