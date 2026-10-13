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

const engine = new VaultEngine();
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

// Spawn target MCP server child process with pipe stdio
const child = spawn(childCmd, childCmdArgs, {
  stdio: ['pipe', 'pipe', 'inherit'],
  shell: process.platform === 'win32'
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
    
    // Check if message is a tools/call request
    if (msg.method === 'tools/call' && msg.params) {
      const toolName = msg.params.name || 'unknown_tool';
      const toolArgs = msg.params.arguments || {};
      
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
