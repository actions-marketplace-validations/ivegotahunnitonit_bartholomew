/**
 * Bartholomew Process Shim (Runtime Subprocess Interceptor)
 * Path: packages/npm_package/process_shim.js
 * 
 * Provides transparent, runtime interception of Node.js child_process methods:
 * - child_process.spawn
 * - child_process.exec
 * - child_process.execFile
 * - child_process.fork
 * 
 * Can be pre-loaded in uninstrumented agent runtimes via:
 *   NODE_OPTIONS="-r @bartholomew/btp-guard/process_shim" node agent.js
 */

import childProcess from 'child_process';
import { EventEmitter } from 'events';
import { enforceToolBoundary } from './agent_core.js';

const originalSpawn = childProcess.spawn;
const originalExec = childProcess.exec;
const originalExecFile = childProcess.execFile;
const originalFork = childProcess.fork;

class BlockedChildProcess extends EventEmitter {
  constructor(reason, code = 126) {
    super();
    this.pid = -1;
    this.killed = true;
    this.exitCode = code;
    this.signalCode = null;
    this.stdin = null;
    this.stdout = new EventEmitter();
    this.stderr = new EventEmitter();
    
    process.nextTick(() => {
      const err = new Error(`[BTP-PROCESS-SHIM] Subprocess execution blocked by Bartholomew Trust Protocol: ${reason}`);
      err.code = 'EPERM';
      this.emit('error', err);
      this.stderr.emit('data', Buffer.from(`[BTP] Blocked: ${reason}\n`));
      this.emit('close', code, null);
      this.emit('exit', code, null);
    });
  }

  kill() {
    return false;
  }
}

export function patchChildProcess(options = {}) {
  // Patch spawn
  childProcess.spawn = function(command, args, opts) {
    const fullCmd = Array.isArray(args) ? `${command} ${args.join(' ')}` : command;
    const gateDecision = enforceToolBoundary('run_command', { command: fullCmd }, options);
    
    if (!gateDecision.allowed) {
      return new BlockedChildProcess(gateDecision.reason || gateDecision.verdict, 126);
    }
    return originalSpawn.apply(this, arguments);
  };

  // Patch exec
  childProcess.exec = function(command, opts, callback) {
    let cb = typeof opts === 'function' ? opts : callback;
    const gateDecision = enforceToolBoundary('run_command', { command }, options);
    
    if (!gateDecision.allowed) {
      const blockedProc = new BlockedChildProcess(gateDecision.reason || gateDecision.verdict, 126);
      if (typeof cb === 'function') {
        blockedProc.on('error', () => {});
        process.nextTick(() => {
          const err = new Error(`[BTP-PROCESS-SHIM] Command blocked: ${gateDecision.reason || gateDecision.verdict}`);
          err.code = 126;
          cb(err, '', `[BTP] Blocked: ${gateDecision.reason || gateDecision.verdict}\n`);
        });
      }
      return blockedProc;
    }
    return originalExec.apply(this, arguments);
  };

  // Patch execFile
  childProcess.execFile = function(file, args, opts, callback) {
    let cb = typeof opts === 'function' ? opts : (typeof args === 'function' ? args : callback);
    const fullCmd = Array.isArray(args) ? `${file} ${args.join(' ')}` : file;
    const gateDecision = enforceToolBoundary('run_command', { command: fullCmd }, options);
    
    if (!gateDecision.allowed) {
      const blockedProc = new BlockedChildProcess(gateDecision.reason || gateDecision.verdict, 126);
      if (typeof cb === 'function') {
        blockedProc.on('error', () => {});
        process.nextTick(() => {
          const err = new Error(`[BTP-PROCESS-SHIM] ExecFile blocked: ${gateDecision.reason || gateDecision.verdict}`);
          err.code = 126;
          cb(err, '', `[BTP] Blocked: ${gateDecision.reason || gateDecision.verdict}\n`);
        });
      }
      return blockedProc;
    }
    return originalExecFile.apply(this, arguments);
  };

  // Patch fork
  childProcess.fork = function(modulePath, args, opts) {
    const fullCmd = Array.isArray(args) ? `node ${modulePath} ${args.join(' ')}` : `node ${modulePath}`;
    const gateDecision = enforceToolBoundary('run_command', { command: fullCmd }, options);
    
    if (!gateDecision.allowed) {
      return new BlockedChildProcess(gateDecision.reason || gateDecision.verdict, 126);
    }
    return originalFork.apply(this, arguments);
  };

  return {
    unpatch: () => {
      childProcess.spawn = originalSpawn;
      childProcess.exec = originalExec;
      childProcess.execFile = originalExecFile;
      childProcess.fork = originalFork;
    }
  };
}

// Auto-patch on require/import if BTP_AUTO_SHIM is enabled or when imported
if (process.env.BTP_AUTO_SHIM === 'true' || process.env.BTP_AUTO_SHIM === '1') {
  patchChildProcess();
}

export default {
  patchChildProcess,
  BlockedChildProcess
};
