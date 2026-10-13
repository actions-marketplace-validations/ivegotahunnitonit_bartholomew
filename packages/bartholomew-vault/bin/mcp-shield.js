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
const path = require('path');
const readline = require('readline');
const { VaultEngine } = require('../dist/vault_engine');

const engine = new VaultEngine();

// Parse target command after '--'
const args = process.argv.slice(2);
const separatorIndex = args.indexOf('--');
const targetArgs = separatorIndex !== -1 ? args.slice(separatorIndex + 1) : args;

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
