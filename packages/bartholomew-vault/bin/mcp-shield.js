#!/usr/bin/env node

/**
 * Bartholomew MCP Shield CLI (BTP v6.5.5)
 * =======================================
 * Transparent in-process proxy wrapper for Model Context Protocol (MCP) servers.
 * Intercepts stdio JSON-RPC tool calls in <35µs:
 * - Invariant Gating: Blocks destructive shell breakouts, SQL drops, path traversals
 * - Inbound / Outbound: Tokenizes sensitive parameters and JIT detokenizes for verified execution
 *
 * Usage:
 *   npx @bartholomew/mcp-shield -- <mcp-server-command> [args...]
 * Example:
 *   mcp-shield -- npx -y @modelcontextprotocol/server-postgres postgresql://...
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { VaultEngine } = require('../dist/vault_engine');
const { KeystoneVerifier } = require('../dist/keystone_verifier');

const engine = new VaultEngine();
const keystoneVerifier = new KeystoneVerifier({
  strictMode: process.env.BTP_ENFORCE_KEYSTONE !== '0'
});
const rawArgs = process.argv.slice(2);

function getMcpConfigPaths() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const appData = process.env.APPDATA || '';
  const paths = [];

  // Claude Desktop configurations
  if (process.platform === 'win32' && appData) {
    paths.push({ client: 'Claude Desktop (Windows)', path: path.join(appData, 'Claude', 'claude_desktop_config.json') });
  } else if (process.platform === 'darwin' && home) {
    paths.push({ client: 'Claude Desktop (macOS)', path: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') });
  } else if (home) {
    paths.push({ client: 'Claude Desktop (Linux)', path: path.join(home, '.config', 'Claude', 'claude_desktop_config.json') });
  }

  // Cursor configurations
  if (home) {
    paths.push({ client: 'Cursor IDE', path: path.join(home, '.cursor', 'mcp.json') });
  }

  // Workspace-local configuration
  const cwdCursor = path.join(process.cwd(), '.cursor', 'mcp.json');
  if (fs.existsSync(cwdCursor)) {
    paths.push({ client: 'Workspace Cursor (.cursor/mcp.json)', path: cwdCursor });
  }

  return paths;
}

function handleInstall() {
  process.stdout.write('\n============================================================\n');
  process.stdout.write('  BARTHOLOMEW MCP AUTO-SHIELD HARDENING WIZARD (BTP v6.5.5)\n');
  process.stdout.write('============================================================\n');

  const configs = getMcpConfigPaths();
  let totalShielded = 0;
  let configsFound = 0;

  for (const cfg of configs) {
    if (!fs.existsSync(cfg.path)) continue;
    configsFound++;
    process.stdout.write(`[*] Found ${cfg.client}: ${cfg.path}\n`);

    try {
      const content = fs.readFileSync(cfg.path, 'utf-8');
      const parsed = JSON.parse(content);
      const servers = parsed.mcpServers || {};
      let modified = false;

      for (const [serverName, serverCfg] of Object.entries(servers)) {
        if (!serverCfg || typeof serverCfg !== 'object') continue;
        const cmd = serverCfg.command || '';
        const args = serverCfg.args || [];

        // Check if already shielded
        if (cmd === 'mcp-shield' || (args && args.includes('mcp-shield'))) {
          process.stdout.write(`    [i] Server '${serverName}' is already shielded.\n`);
          continue;
        }

        // Backup original configuration
        const backupPath = cfg.path + '.bak';
        if (!fs.existsSync(backupPath)) {
          fs.writeFileSync(backupPath, content, 'utf-8');
          process.stdout.write(`    [+] Backup created: ${backupPath}\n`);
        }

        // Shield server: wrap command with mcp-shield
        const originalCmd = serverCfg.command;
        const originalArgs = serverCfg.args || [];
        serverCfg.command = 'mcp-shield';
        serverCfg.args = ['--', originalCmd, ...originalArgs];
        modified = true;
        totalShielded++;
        process.stdout.write(`    [+] Shielded '${serverName}' -> in-process <35us AST & PII gating active.\n`);
      }

      if (modified) {
        fs.writeFileSync(cfg.path, JSON.stringify(parsed, null, 2), 'utf-8');
        process.stdout.write(`[OK] Successfully hardened ${cfg.client} configuration.\n\n`);
      } else {
        process.stdout.write(`[i] No unshielded servers found in ${cfg.client}.\n\n`);
      }
    } catch (err) {
      process.stderr.write(`[!] Error processing ${cfg.path}: ${err.message}\n`);
    }
  }

  if (configsFound === 0) {
    process.stdout.write('[-] No standard Claude Desktop or Cursor configuration files found in default paths.\n');
    process.stdout.write('    You can run servers directly: mcp-shield -- <mcp-server-cmd> [args...]\n\n');
  } else {
    process.stdout.write(`[SUMMARY] Hardened ${totalShielded} MCP server(s) across ${configsFound} configuration(s).\n`);
    process.stdout.write('Zero configuration overhead. In-process <35us protection is now active.\n\n');
  }
}

function handleAudit() {
  process.stdout.write('\n============================================================\n');
  process.stdout.write('  BARTHOLOMEW MCP SECURITY AUDITOR (BTP v6.5.5)\n');
  process.stdout.write('============================================================\n');

  const configs = getMcpConfigPaths();
  let totalServers = 0;

  for (const cfg of configs) {
    if (!fs.existsSync(cfg.path)) continue;
    try {
      const content = fs.readFileSync(cfg.path, 'utf-8');
      const audit = engine.auditMcpConfiguration(content, cfg.path);
      process.stdout.write(`\nTarget: ${cfg.client} (${cfg.path})\n`);
      process.stdout.write(`- Audit Score: ${audit.overallScore} / 100\n`);
      process.stdout.write(`- Server Count: ${audit.serverCount}\n`);
      process.stdout.write(`- Unvaulted Secrets Detected: ${audit.totalUnvaultedSecrets}\n`);

      for (const s of audit.servers) {
        process.stdout.write(`  * Server '${s.serverName}': score ${s.securityScore}/100, unvaulted secrets: ${s.unvaultedSecretsDetected}\n`);
        for (const rec of s.recommendations) {
          process.stdout.write(`    - [RECOMMENDATION] ${rec}\n`);
        }
      }
      totalServers += audit.serverCount;
    } catch (err) {
      process.stderr.write(`[!] Audit error on ${cfg.path}: ${err.message}\n`);
    }
  }
  process.stdout.write(`\n[+] Audit completed across ${totalServers} MCP server definitions.\n\n`);
}

// Subcommand Router
if (rawArgs.includes('--install') || rawArgs.includes('-i')) {
  handleInstall();
  process.exit(0);
}

if (rawArgs.includes('--audit') || rawArgs.includes('-a')) {
  handleAudit();
  process.exit(0);
}

if (rawArgs.includes('--help') || rawArgs.includes('-h') || rawArgs.length === 0) {
  process.stdout.write('\nBartholomew MCP Shield CLI (BTP v6.5.5)\n');
  process.stdout.write('=======================================\n');
  process.stdout.write('Sub-35us in-process invariant proxy wrapper for Model Context Protocol servers.\n\n');
  process.stdout.write('Usage:\n');
  process.stdout.write('  mcp-shield --install              Automatically detect & shield Claude Desktop and Cursor MCP configs\n');
  process.stdout.write('  mcp-shield --audit                Audit active MCP configs for exposed credentials & secrets\n');
  process.stdout.write('  mcp-shield -- <command> [args...] Wrap an individual MCP server command as transparent stdio proxy\n\n');
  process.stdout.write('Examples:\n');
  process.stdout.write('  npx mcp-shield --install\n');
  process.stdout.write('  mcp-shield -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb\n\n');
  process.exit(0);
}

// Parse target command after '--'
const separatorIndex = rawArgs.indexOf('--');
const targetArgs = separatorIndex !== -1 ? rawArgs.slice(separatorIndex + 1) : rawArgs;

if (targetArgs.length === 0) {
  process.stderr.write('[Bartholomew MCP Shield] Error: No target MCP server specified.\n');
  process.stderr.write('Usage: mcp-shield -- <command> [args...]\n');
  process.exit(1);
}

const childCmd = targetArgs[0];
const childCmdArgs = targetArgs.slice(1);

// Sanitize environment passed to untrusted child MCP server
// Never leak signing keys, verification secrets, or internal auth flags
const childEnv = { ...process.env };
delete childEnv.BTP_KEYSTONE_SECRET;
delete childEnv.BTP_WORKSPACE_SECRET;
delete childEnv.BTP_ENFORCE_KEYSTONE;

// Spawn target MCP server child process with pipe stdio
const needsShell = process.platform === 'win32' && (childCmd.endsWith('.cmd') || childCmd.endsWith('.bat'));
const child = spawn(childCmd, childCmdArgs, {
  stdio: ['pipe', 'pipe', 'inherit'],
  shell: needsShell,
  env: childEnv
});

child.on('error', (err) => {
  process.stderr.write(`[Bartholomew MCP Shield] Failed to start server ${childCmd}: ${err.message}\n`);
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code || 0);
});

// Setup JSON-RPC line readers
const rlIn = readline.createInterface({ input: process.stdin, terminal: false });
const rlOut = readline.createInterface({ input: child.stdout, terminal: false });

// Intercept Client -> MCP Server (tools/call requests)
rlIn.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const msg = JSON.parse(trimmed);
    
    // Check if message is a batch request (JSON-RPC 2.0 array)
    if (Array.isArray(msg)) {
      const blockedResponses = [];
      const sanitizedBatch = [];
      let anyBlocked = false;

      for (const item of msg) {
        if (!item || typeof item !== 'object') {
          anyBlocked = true;
          blockedResponses.push({
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32600,
              message: 'Invalid Request: batch element must be a valid JSON-RPC object.'
            }
          });
          continue;
        }

        if (item.method === 'tools/call') {
          if (!item.params || typeof item.params !== 'object') {
            anyBlocked = true;
            blockedResponses.push({
              jsonrpc: '2.0',
              id: item.id !== undefined ? item.id : null,
              error: {
                code: -32602,
                message: 'Invalid params: tools/call requires a valid params object.'
              }
            });
            continue;
          }

          const toolName = item.params.name || 'unknown_tool';
          const toolArgs = item.params.arguments || {};
          const rawPasskey = (item.params._meta && item.params._meta.btp_passkey)
            || item.params._btp_passkey
            || (toolArgs && toolArgs._btp_passkey);

          const authCheck = keystoneVerifier.verifyToolCall(toolName, toolArgs, rawPasskey);
          if (!authCheck.allowed) {
            anyBlocked = true;
            blockedResponses.push({
              jsonrpc: '2.0',
              id: item.id,
              error: {
                code: authCheck.code,
                message: `[Bartholomew Keystone Authorization Failed]: ${authCheck.reason} (${authCheck.rule_id})`,
                data: { rule_id: authCheck.rule_id, verdict: 'DENY', tool: toolName }
              }
            });
            continue;
          }

          if (toolArgs._btp_passkey) delete toolArgs._btp_passkey;
          if (item.params._btp_passkey) delete item.params._btp_passkey;
          if (item.params._meta && item.params._meta.btp_passkey) delete item.params._meta.btp_passkey;

          const check = engine.interceptMcpToolCall(toolName, toolArgs, {
            serverName: childCmd,
            isAuthorizedDestination: true
          });

          if (!check.allowed) {
            anyBlocked = true;
            blockedResponses.push({
              jsonrpc: '2.0',
              id: item.id,
              error: {
                code: -32000,
                message: `[Bartholomew Keystone Invariant Blocked]: ${check.reason} (${check.rule_id})`,
                data: {
                  rule_id: check.rule_id,
                  verdict: check.verdict,
                  latency_us: check.latencyUs,
                  merkle_leaf: check.merkleLeaf
                }
              }
            });
            continue;
          }

          item.params.arguments = check.sanitizedArgs;
          sanitizedBatch.push(item);
        } else {
          sanitizedBatch.push(item);
        }
      }

      if (anyBlocked) {
        process.stdout.write(JSON.stringify(blockedResponses) + '\n');
        return;
      }

      child.stdin.write(JSON.stringify(sanitizedBatch) + '\n');
      return;
    }

    // Check if message is a single tools/call request
    if (msg.method === 'tools/call') {
      if (!msg.params || typeof msg.params !== 'object') {
        const errResponse = {
          jsonrpc: '2.0',
          id: msg.id !== undefined ? msg.id : null,
          error: {
            code: -32602,
            message: 'Invalid params: tools/call requires a valid params object.'
          }
        };
        process.stdout.write(JSON.stringify(errResponse) + '\n');
        return;
      }

      const toolName = msg.params.name || 'unknown_tool';
      const toolArgs = msg.params.arguments || {};

      // 1. Mandatory Keystone Authorization Gate (Phase 2 & Phase 4)
      const rawPasskey = (msg.params._meta && msg.params._meta.btp_passkey)
        || msg.params._btp_passkey
        || (toolArgs && toolArgs._btp_passkey);

      const authCheck = keystoneVerifier.verifyToolCall(toolName, toolArgs, rawPasskey);
      if (!authCheck.allowed) {
        process.stderr.write(`[Bartholomew MCP Shield] UNAUTHORIZED tool call '${toolName}' (${authCheck.rule_id}): ${authCheck.reason}\n`);
        const errResponse = {
          jsonrpc: '2.0',
          id: msg.id,
          error: {
            code: authCheck.code,
            message: `[Bartholomew Keystone Authorization Failed]: ${authCheck.reason} (${authCheck.rule_id})`,
            data: {
              rule_id: authCheck.rule_id,
              verdict: 'DENY',
              tool: toolName
            }
          }
        };
        process.stdout.write(JSON.stringify(errResponse) + '\n');
        return;
      }

      // Remove internal security token from arguments and parameters so child MCP server gets clean parameters
      if (toolArgs._btp_passkey) {
        delete toolArgs._btp_passkey;
      }
      if (msg.params._btp_passkey) {
        delete msg.params._btp_passkey;
      }
      if (msg.params._meta && msg.params._meta.btp_passkey) {
        delete msg.params._meta.btp_passkey;
      }

      // 2. Invariant & AST Execution Gating
      const check = engine.interceptMcpToolCall(toolName, toolArgs, {
        serverName: childCmd,
        isAuthorizedDestination: true
      });

      if (!check.allowed) {
        // Block request and return JSON-RPC error response immediately
        process.stderr.write(`[Bartholomew MCP Shield] BLOCKED tool call '${toolName}' (${check.rule_id}): ${check.reason} [<35µs]\n`);
        
        const errResponse = {
          jsonrpc: '2.0',
          id: msg.id,
          error: {
            code: -32000,
            message: `[Bartholomew Keystone Invariant Blocked]: ${check.reason} (${check.rule_id})`,
            data: {
              rule_id: check.rule_id,
              verdict: check.verdict,
              latency_us: check.latencyUs,
              merkle_leaf: check.merkleLeaf
            }
          }
        };
        process.stdout.write(JSON.stringify(errResponse) + '\n');
        return;
      }

      // 3. Child server availability check
      if (!child.stdin || child.stdin.destroyed || !child.stdin.writable) {
        const errResponse = {
          jsonrpc: '2.0',
          id: msg.id,
          error: {
            code: -32002,
            message: '[Bartholomew MCP Shield Error]: Target MCP child process is unavailable or terminated.',
            data: { rule_id: 'BTP-MCP-CHILD-UNAVAILABLE' }
          }
        };
        process.stdout.write(JSON.stringify(errResponse) + '\n');
        return;
      }

      // If allowed, use sanitized / JIT detokenized arguments
      msg.params.arguments = check.sanitizedArgs;
      child.stdin.write(JSON.stringify(msg) + '\n');
      return;
    }
  } catch {
    // If not valid JSON, forward raw
  }

  child.stdin.write(line + '\n');
});

// Intercept MCP Server -> Client (Tokenize sensitive outputs returning to LLM)
rlOut.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const msg = JSON.parse(trimmed);
    
    // If response contains content/text, tokenize sensitive credentials before sending to LLM context
    if (msg.result && Array.isArray(msg.result.content)) {
      for (const item of msg.result.content) {
        if (item.type === 'text' && typeof item.text === 'string') {
          const tok = engine.tokenize(item.text);
          if (tok.tokenCount > 0) {
            item.text = tok.sanitized;
            process.stderr.write(`[Bartholomew MCP Shield] Sanitized ${tok.tokenCount} sensitive token(s) from tool result before LLM context dispatch.\n`);
          }
        }
      }
      process.stdout.write(JSON.stringify(msg) + '\n');
      return;
    }
  } catch {}

  process.stdout.write(line + '\n');
});
