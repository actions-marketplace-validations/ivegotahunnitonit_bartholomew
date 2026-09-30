# btp-guard

[![Back Open Source](https://img.shields.io/badge/Stripe-Back%20Open%20Source-635BFF?logo=stripe&logoColor=white)](https://buy.stripe.com/fZu28rbNz5TYcmAddK9R600)
 (Node.js & TypeScript)

> **Sub-35µs In-Process Execution Firewall & Deterministic AST Safety Gate for AI Agents**  
> *Bartholomew Trust Protocol (BTP v5.4.24) — Zero External Dependencies*

[![npm version](https://img.shields.io/npm/v/btp-guard?style=flat-square&color=38bdf8)](https://www.npmjs.com/package/btp-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen.svg?style=flat-square)](https://www.npmjs.com/package/btp-guard)
[![Smithery MCP](https://img.shields.io/badge/Smithery%20MCP-100%2F100%20Verified-blue)](https://smithery.ai/servers/itsubsolomon/calls_10k)

---

## What is Bartholomew Guard?

Bartholomew Guard is an ultra-fast in-process security gateway for autonomous AI agents (Gemini, Claude, Cursor, Copilot, LangChain.js, Vercel AI SDK).

It sits in memory between your AI agent and the operating system. Before any bash command, SQL query, file edit, or MCP tool call executes, Bartholomew evaluates the action against deterministic Abstract Syntax Tree (AST) safety invariants in **under 35 microseconds**—blocking destructive operations (`rm -rf`, `DROP TABLE`), redacting in-flight credentials (`sk-*`, AWS tokens), and signing cryptographic RFC 8785 Ed25519 receipts.

---

## 30-Second Quickstart

### 1. One-Command Project Immunization
Immunize your active project in 1 second. This automatically sets up `.cursorrules`, `CLAUDE.md`, `GEMINI.md`, and security policies:
```bash
npx btp-guard protect
```

### 2. Export Context for Your AI Model (Gemini, Claude, Cursor)
Copy tailored invariant instructions directly to your clipboard so your AI companion codes safely without tripping blocks:
```bash
npx btp-guard model-context --model gemini
npx btp-guard model-context --model claude
npx btp-guard model-context --model cursor
```

### 3. Wrap Any Agent in 1 Line of Code
```javascript
import { protectAgent } from 'btp-guard';

// Automatically protects any agent object (Vercel AI SDK, LangChain, Claude, Custom)
const agent = protectAgent(rawAgent, { spendCap: 50.0 });
```

---

## Core API Reference

### 1. In-Process Intent Gate (`evaluateIntent`)
Evaluate arbitrary tool calls or shell commands in caller memory in `<35µs`:
```javascript
import { evaluateIntent, verifyReceipt } from 'btp-guard';

const result = evaluateIntent({
  agentId: 'worker-node-01',
  actionType: 'EXECUTE_QUERY',
  payload: { sql: 'SELECT * FROM users WHERE active = true;' }
});

console.log('Allowed:', result.allowed);          // true
console.log('Latency:', result.latencyUs, 'µs');   // 24.8 µs
console.log('Verdict:', result.verdict);          // "ALLOW"
console.log('Receipt:', result.signature);        // Ed25519 signature

// Offline cryptographic receipt verification
const isValid = verifyReceipt(result);
console.log('Signature Valid:', isValid);          // true
```

### 2. In-Flight Credential Scrubber (`scrubSensitiveCredentials`)
Automatically strips high-entropy tokens and API keys from payloads before network egress:
```javascript
import { scrubSensitiveCredentials } from 'btp-guard';

const payload = {
  command: "curl -H 'Authorization: Bearer sk-proj-1234567890abcdef' https://api.openai.com",
  aws_key: "AKIAIOSFODNN7EXAMPLE"
};

const { data, redactionCount } = scrubSensitiveCredentials(payload);
console.log('Redacted Secrets:', redactionCount); // 2
console.log('Sanitized Data:', data);
```

### 3. Workspace Security Audit (`evaluateWorkspaceSecurity`)
Programmatically inspect workspace invariant health and retrieve actionable remediation tasks:
```javascript
import { evaluateWorkspaceSecurity } from 'btp-guard';

const audit = evaluateWorkspaceSecurity('.');
console.log('Score:', audit.score); // 100
console.log('Grade:', audit.grade); // "A+"
```

---

## CLI Commands

| Command | Description |
|---|---|
| `npx btp-guard telemetry` | Launch authenticated, single-tenant private threat telemetry vault in your browser |
| `npx btp-guard protect` | Immunize repository with `.cursorrules`, `CLAUDE.md`, `GEMINI.md`, and pre-commit hooks |
| `npx btp-guard protect --audit-only` | Audit workspace security score (0–100) without modifying files |
| `npx btp-guard model-context --model <name>` | Generate formatted security briefing for Gemini, Claude, or Cursor |
| `npx btp-guard scrub <file.json>` | Redact in-flight secrets from JSON file |
| `npx btp-guard demo` | Run interactive terminal self-test and latency benchmark |
| `npx btp-guard keystone issue <agent>` | Issue cryptographically signed capability passkey |

---

## Specifications & Guarantees

- **Zero External Dependencies**: Implemented natively using Node.js built-in `crypto` and standard ES modules.
- **Latency**: Sub-35 microseconds deterministic in-process evaluation.
- **Compliance**: RFC 8785 JSON Canonicalization Scheme (JCS) + FIPS 186-5 Ed25519 cryptographic signatures.
- **Portal & Telemetry**: [https://bartholomew.info](https://bartholomew.info)
