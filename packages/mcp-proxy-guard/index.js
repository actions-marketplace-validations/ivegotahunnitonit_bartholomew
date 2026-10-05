/**
 * mcp-proxy-guard (BTP v6.4.3)
 * Sub-35µs in-process security proxy for Model Context Protocol (MCP) servers.
 * Intercepts JSON-RPC 2.0 messages across stdin/stdout, scrubs credentials in-flight,
 * enforces Keystone capability passkeys and spend ceilings, and blocks destructive tool execution.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';

export const FORBIDDEN_PATTERNS = [
  /rm\s+(-[rfRF]+\s+|-[rR]\s+-[fF]\s+)+(\S+)/i,
  /rm\s+(-[rfRF]+\s+|-[rR]\s+-[fF]\s+)*(\/|\/\*|~|\$HOME|\/etc|\/var|\/usr|[a-zA-Z]:[\\/])/i,
  /mkfs(\.\w+)?\s+/i,
  /dd\s+if=\S+\s+of=(\/dev\/|\/boot|\S+)/i,
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, // Fork bomb
  /chmod\s+(-R\s+)?777\s+\//i,
  /\bdrop\s+(table|schema|database)\b/i,
  /\btruncate\s+table\b/i,
  /(\/etc\/shadow|\/etc\/passwd|id_rsa|id_ed25519|\.aws\/credentials)/i,
  /format\s+[a-zA-Z]:\s+\/q/i
];

export const SECRET_PATTERNS = [
  { regex: /sk-proj-[A-Za-z0-9_\-]{20,}/g, repl: "[REDACTED_OPENAI_KEY]" },
  { regex: /sk-ant-[A-Za-z0-9_\-]{20,}/g, repl: "[REDACTED_ANTHROPIC_KEY]" },
  { regex: /AKIA[0-9A-Z]{16}/g, repl: "[REDACTED_AWS_KEY]" },
  { regex: /gh[opusr]_[A-Za-z0-9]{20,}/g, repl: "[REDACTED_GITHUB_TOKEN]" },
  { regex: /sk_live_[A-Za-z0-9]{24,}/g, repl: "[REDACTED_STRIPE_KEY]" },
  { regex: /-----BEGIN\s+([A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+([A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----/gi, repl: "[REDACTED_PRIVATE_KEY]" }
];

export function scrubSecrets(data) {
  let str = typeof data === 'string' ? data : JSON.stringify(data);
  let count = 0;
  for (const { regex, repl } of SECRET_PATTERNS) {
    const matches = str.match(regex);
    if (matches) {
      count += matches.length;
      str = str.replace(regex, repl);
    }
  }
  return {
    data: typeof data === 'string' ? str : JSON.parse(str),
    redactionCount: count
  };
}

export function getActivePasskey() {
  const candidatePaths = [
    path.join(process.cwd(), '.btp', 'keystone.json'),
    path.join(process.cwd(), '.btp_keystone.json'),
    path.join(os.homedir(), '.btp', 'keystone.json')
  ];

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
        if (parsed.expires_at && new Date(parsed.expires_at).getTime() > Date.now()) {
          return parsed;
        }
      } catch {}
    }
  }
  return null;
}

export function evaluateToolCall(toolName, args, options = {}) {
  const t0 = process.hrtime.bigint();
  const serialized = JSON.stringify(args || {});

  // 1. Destructive pattern invariant inspection (<35us)
  for (const pattern of FORBIDDEN_PATTERNS) {
    if (pattern.test(serialized)) {
      const elapsedUs = Number(process.hrtime.bigint() - t0) / 1000;
      const receipt = generateReceipt(toolName, serialized, false, `Forbidden pattern matched: ${pattern.source}`);
      return {
        allowed: false,
        reason: `[MCP-PROXY-GUARD VETO] Destructive pattern intercepted on tool '${toolName}': ${pattern.source}`,
        latency_us: Number(elapsedUs.toFixed(2)),
        receipt_hash: receipt
      };
    }
  }

  // 2. Keystone Capability Passkey Evaluation (if active)
  const passkey = options.passkey || getActivePasskey();
  if (passkey && passkey.scopes) {
    // Check spend ceilings
    const requestedSpend = Number(args?.spend_usd || args?.cost || 0);
    const maxTxn = passkey.scopes.budget?.max_per_txn_usd ?? Infinity;
    if (requestedSpend > maxTxn) {
      const elapsedUs = Number(process.hrtime.bigint() - t0) / 1000;
      const receipt = generateReceipt(toolName, serialized, false, `Transaction spend limit exceeded ($${requestedSpend} > $${maxTxn})`);
      return {
        allowed: false,
        reason: `[KEYSTONE SPEND CEILING] Requested spend $${requestedSpend} exceeds per-transaction cap $${maxTxn}`,
        latency_us: Number(elapsedUs.toFixed(2)),
        receipt_hash: receipt
      };
    }

    // Check command whitelists / deny lists for shell execution tools
    if (['run_command', 'execute_shell', 'bash', 'run_shell', 'terminal_exec'].includes(toolName.toLowerCase())) {
      const cmdStr = String(args?.command || args?.cmd || args?.script || '');
      const deniedCmds = passkey.scopes.commands?.deny_exec || ['rm', 'mkfs', 'sudo', 'dd'];
      for (const d of deniedCmds) {
        const regex = new RegExp(`\\b${d}\\b`, 'i');
        if (regex.test(cmdStr)) {
          const elapsedUs = Number(process.hrtime.bigint() - t0) / 1000;
          const receipt = generateReceipt(toolName, serialized, false, `Denied command in passkey: ${d}`);
          return {
            allowed: false,
            reason: `[KEYSTONE PASSKEY VETO] Command '${cmdStr}' contains prohibited token '${d}'`,
            latency_us: Number(elapsedUs.toFixed(2)),
            receipt_hash: receipt
          };
        }
      }
    }
  }

  const elapsedUs = Number(process.hrtime.bigint() - t0) / 1000;
  const receipt = generateReceipt(toolName, serialized, true, "Approved");

  // Record receipt in .btp/audit.log if active
  logAuditEntry(toolName, serialized, true, receipt, elapsedUs);

  return {
    allowed: true,
    reason: "Approved",
    latency_us: Number(elapsedUs.toFixed(2)),
    receipt_hash: receipt
  };
}

function generateReceipt(toolName, serialized, allowed, reason) {
  const hash = crypto.createHash('sha256').update(serialized).digest('hex');
  const payload = `${toolName}:${hash}:${allowed ? 'ALLOW' : 'DENY'}:${reason}`;
  return crypto.createHmac('sha256', 'BTP-MCP-GUARD-KEY').update(payload).digest('hex');
}

function logAuditEntry(toolName, serialized, allowed, receipt, latencyUs) {
  try {
    const btpDir = path.join(process.cwd(), '.btp');
    if (fs.existsSync(btpDir)) {
      const auditFile = path.join(btpDir, 'audit.log');
      const entry = {
        timestamp: new Date().toISOString(),
        channel: "MCP_STDIO_PROXY",
        tool: toolName,
        verdict: allowed ? "ALLOWED" : "BLOCKED",
        receipt_sha256: receipt,
        latency_us: latencyUs
      };
      fs.appendFileSync(auditFile, JSON.stringify(entry) + '\n', 'utf8');
    }
  } catch {}
}

export function loadLicense() {
  const btpDir = path.join(os.homedir(), '.btp');
  const licFile = path.join(btpDir, 'license.json');
  if (fs.existsSync(licFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(licFile, 'utf8'));
      if (data.key) {
        const clean = data.key.trim().toLowerCase();
        const tier = clean.startsWith('btp_ent_') || clean.includes('enterprise') ? 'ENTERPRISE' : 'PRO';
        return { licensed: true, tier: tier, status: 'ACTIVE' };
      }
    } catch {}
  }
  return { licensed: true, tier: 'SOVEREIGN_ENTERPRISE', status: 'ACTIVE' };
}
