import { loadConfig } from './config.mjs';
import { IntelligentCell } from './node.mjs';
import { errorData, NodeError } from './errors.mjs';
import { receiveFrames } from './wire.mjs';

let node;
try {
  const args = process.argv.slice(2), configIndex = args.indexOf('--config');
  const daemon = args.includes('--daemon'), operatorRequested = args.includes('--operator');
  if (configIndex < 0 || !args[configIndex+1] || args.some((arg,index) => index !== configIndex+1 && !['--config','--daemon','--operator'].includes(arg)) || args.filter(arg=>arg==='--config').length !== 1) throw new Error('Usage: node src/main.mjs --config config.json [--daemon] [--operator]');
  const config = await loadConfig(args[configIndex+1]);
  node = new IntelligentCell(config); await node.start();
  if (operatorRequested || config.operator?.enabled === true) {
    const { startOperator } = await import('./operator.mjs');
    node.operator = await startOperator(node, config.operator ?? (process.platform === 'win32' ? {} : {sessionDirectory: `${config.stateDir}/operator-access`}));
    node.log('operator_ready', { url: node.operator.url, socketPath: node.operator.socketPath, ownerFile: node.operator.ownerFile });
    // Never place owner-session secrets in daemon logs/journald/audit files.
    if (process.stderr.isTTY) process.stderr.write(`Local owner UI: ${node.operator.url}/#token=${node.operator.bootstrapToken}\n`);
  }
  const stop = () => { if (!daemon) process.stdin.destroy(); void node.shutdown().catch(error => {process.stderr.write(JSON.stringify({event:'shutdown_error',error:errorData(error)})+'\n');process.exitCode=1;}); };
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
  if (!daemon) {
    let commandsInFlight = 0;
    receiveFrames(process.stdin, command => {
      const requestId = typeof command.requestId === 'string' && /^[a-zA-Z0-9_-]{1,100}$/.test(command.requestId) ? command.requestId : null;
      const name = typeof command.command === 'string' && command.command.length <= 32 ? command.command : null;
      void (async () => {
        try {
          if(command.requestId!==undefined&&requestId===null)throw new NodeError('INVALID_COMMAND','requestId must be 1..100 letters, digits, _ or -');
          if(name===null)throw new NodeError('INVALID_COMMAND','Invalid command name');
          if(commandsInFlight>=32)throw new NodeError('BUSY','Too many concurrent operator commands');
          commandsInFlight++;
          try { const result=await node.command(command);node.log('command_result',{requestId,command:name,ok:true,result});if(name==='shutdown')process.stdin.destroy(); }
          finally {commandsInFlight--;}
        } catch(error){node.log('command_result',{requestId,command:name,ok:false,error:errorData(error)});}
      })();
    },reason=>node.log('command_result',{requestId:null,command:null,ok:false,error:{code:'INVALID_FRAME',message:reason}}));
    process.stdin.once('end',stop);process.stdin.once('close',stop);
  }
  node.log('runtime_mode',{mode:daemon?'daemon':'stdio',stdinDependent:!daemon});
} catch(error) {
  process.stderr.write(JSON.stringify({event:'fatal',error:errorData(error)})+'\n');
  if(node)await node.shutdown();process.exitCode=1;
}
