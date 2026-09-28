# Bartholomew Guard — AI Agent Safety & Guardrails (Cursor, Claude, Copilot)

> **Zero-trust firewall & execution guardrails for AI agents in Cursor, Claude Desktop, and VS Code.**  
> *Sub-35µs In-Process AST Safety, Tamper-Evident Action Ledger, and Direct Model Context Bridge.*

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/itsubsolomon.bartholomew-guard-vscode?color=blue&logo=visualstudiocode&label=VS%20Code%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=itsubsolomon.bartholomew-guard-vscode)
[![Open VSX](https://img.shields.io/badge/Open%20VSX-v5.4.24-blue)](https://open-vsx.org/extension/itsubsolomon/bartholomew-guard-vscode)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/Tests-3%2C000%20passed-brightgreen)](https://bartholomew.info)

---

## What It Does

Bartholomew Guard sits in-process between your AI coding companions (Cursor, Copilot, Claude Code, Gemini, Windsurf) and your operating system. Every time an agent proposes a command, tool call, or file edit, Guard validates it in **under 35 microseconds** before execution:

- **Destructive Command Blocking**: Prohibits `rm -rf`, `DROP TABLE`, and raw disk overwrites.
- **In-Flight Secret Redaction**: Intercepts and scrubs API keys (`sk-*`, AWS credentials) before they reach logs or network.
- **Pipe-to-Shell Gate**: Vetoes unverified `curl | bash` remote execution scripts.
- **Keystone Passkeys**: Limits agent file writes to workspace paths and enforces spend caps.

---

## Proof of Protection & AI Model Bridge

Once installed, Bartholomew Guard provides immediate transparency in your IDE:

### 1. Proof It's Working
- **Status Bar Indicator**: Live status pill `$(shield) BTP: ARMED (<25µs)`. Clicking it opens the full dashboard.
- **Activity Bar View (`bartholomew.proofView`)**: Click the Bartholomew Shield icon in your left sidebar to view real-time metrics:
  * Invariant Status: `ARMED & MONITORING`
  * Total Actions Audited
  * Blocked Threats & Neutralized Injections
  * Evaluation Latency: `<24.8 µs`
  * Cryptographic Merkle Root Hash

### 2. What It's Worked On (Live Intercepted Action Ledger)
An interactive feed streaming directly from `.btp/audit.log`:
- View recent tool invocations and terminal commands.
- Inspect verdicts (`ALLOWED`, `BLOCKED`, `SANITIZED`) and rule IDs (`BTP-AST-001`, `BTP-SEC-001`).
- Copy cryptographic RFC 8785 Ed25519 receipts with one click.

### 3. How to Improve (Workspace Health Score & 1-Click Fixes)
The extension automatically audits your workspace against 5 security baselines (scoring **0–100, Grade A+**):
- Git Pre-Commit AST Gate `[Install Pre-Commit Hook]`
- AI Model Invariants (`GEMINI.md`, `CLAUDE.md`, `.cursorrules`) `[Inject AI Rules]`
- Declarative Security Policy `[1-Click Immunize]`
- Keystone Capability Passkey `[Issue Passkey]`
- CI/CD Continuous Guard Workflow `[Enable GitHub Actions]`

### 4. Straight-On Path to AI Models (Gemini, Claude, Cursor)
Pairing with an AI model? Click any button to copy instant, structured prompt context directly into your chat or composer:
- `[📋 Copy Context for Gemini]` — Formatted for Gemini & Google AI Studio / Antigravity IDE.
- `[📋 Copy Context for Claude]` — Formatted for Anthropic Claude Code & API.
- `[📋 Copy Context for Cursor]` — Formatted for Cursor Composer & Chat.
- `[📄 View .btp/model-context.md]` — Opens the persistent workspace briefing file.

---

## 1-Command Project Immunization

You can also immunize any repository in 1 second from your terminal:
```bash
# Via Python:
pip install btp-guard && btp-guard protect

# Via Node.js / npx:
npx btp-guard protect
```

---

## Commands

Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) and type `Bartholomew`:

| Command | Description |
|---|---|
| `Bartholomew: Open Proof of Protection & AI Bridge` | Open full interactive telemetry & activity dashboard |
| `Bartholomew: Copy AI Context (Gemini, Claude, Cursor)` | Select and copy model invariant prompt to clipboard |
| `Bartholomew: Immunize Project (btp-guard protect)` | 1-click generate AI rules, policy, and git hooks |
| `Bartholomew: Install Git Pre-Commit AST Hook` | Block uncommitted secrets and destructive AST code |
| `Bartholomew: Inject AI Model Rules` | Generate GEMINI.md, CLAUDE.md, and .cursorrules |
| `Keystone: Issue Agent Capability Passkey` | Issue cryptographic capability token with spend ceiling |
| `Bartholomew: Generate SOC 2 / ISO 27001 Evidence Pack` | Export auditor-ready compliance dossier |

---

## Open Source & Sovereign

Bartholomew Guard is **100% open source (MIT license)** and runs entirely local to your machine. No telemetry sent to third parties, zero cloud latency.

- **Website**: [https://bartholomew.info](https://bartholomew.info)
- **PyPI Package**: `pip install btp-guard`
- **NPM Package**: `npm install btp-guard`
