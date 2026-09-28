# Bartholomew Keystone - Cryptographic Agent Capability Passkeys

Issue tamper-evident, cryptographically signed permission slips for autonomous AI agents. Define deterministic boundaries for file modifications, command executions, external network calls, and financial spend.

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v5.4.23-blue)](https://open-vsx.org/extension/itsubsolomon/bartholomew-keystone)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Works With](https://img.shields.io/badge/Works%20With-Bartholomew%20Guard-blue)](https://open-vsx.org/extension/itsubsolomon/bartholomew-guard-vscode)

---

## The Problem Keystone Solves

Autonomous AI coding agents (such as Cursor Agent, Claude Code, Cline, Windsurf, Devin, GitHub Copilot Workspace, and MCP tool runners) operate with broad system privileges. If an agent receives instructions containing an indirect prompt injection, or hallucinates during an automated refactoring loop, it can:

1. **Destroy files or git history** (`rm -rf`, destructive resets, overwriting production configs).
2. **Exfiltrate secrets and credentials** (reading `.env`, `.ssh/id_rsa`, AWS/GCP keys and transmitting via `curl`).
3. **Run out-of-scope system commands** (modifying permissions, installing malware, spawning unauthorized processes).
4. **Trigger unchecked financial costs** (calling billable APIs or Cloud services without budget boundaries).

System prompt instructions ("Please do not touch `.env`") are easily ignored or circumvented by prompt injections. **Bartholomew Keystone** enforces hard, deterministic cryptographic clearance boundaries at the tool execution seam.

---

## Guard vs. Keystone - How They Work Together

| Layer | Bartholomew Guard | Bartholomew Keystone (This Extension) |
|---|---|---|
| **Primary Role** | Invariant & Leak Detection | Cryptographic Capability Scoping |
| **How It Operates** | AST static analysis & runtime leak scanning | Issues and verifies signed capability passkeys |
| **Protection Focus** | Zero-leak credential guard, prompt-injection AST gate | Defines exact file globs, commands, domains, and budget limits |
| **Speed** | Sub-25 microseconds in-process verification | Sub-15 microseconds HMAC-SHA256 signature and scope check |
| **Installation** | Companion extension (`itsubsolomon.bartholomew-guard-vscode`) | You are here |

---

## Core Clearance Scopes

When a Keystone Passkey is issued, the agent receives an ephemeral `.btp_keystone.json` token signed by the local authority. Every proposed action is evaluated against these scopes:

### 1. Filesystem Containment (`files`)
- **`allow_read`**: Globs the agent may inspect (e.g. `["src/**", "tests/**"]`).
- **`allow_write`**: Globs the agent is authorized to modify. Any write outside these paths is rejected instantly.
- **`deny`**: Blacklisted patterns strictly blocked from reading or writing (e.g. `.env*`, `secrets*`, `id_rsa*`, `.git/hooks/**`).
- **`max_file_size_kb`**: Maximum permissible file write payload to prevent repository bloat or disk exhaustion.

### 2. Command Sandboxing (`commands`)
- **`allow_exec`**: Safe execution whitelist (e.g. `npm test`, `pytest`, `cargo check`, `git status`).
- **`deny_exec`**: Destructive and dangerous commands blocked unconditionally (e.g. `rm`, `sudo`, `curl`, `wget`, `chmod`, `dd`, `mkfs`).
- **`deny_shell_operators`**: Prevents command chaining injections (`&&`, `||`, `;`, `|`, `` ` ``, `$()`).

### 3. Network and API Gating (`network`)
- **`allow_domains`**: Whitelist of permitted external egress destinations (e.g. `api.github.com`, `registry.npmjs.org`, `pypi.org`).
- **`deny_domains`**: Prohibited exfiltration endpoints.
- **`allow_search`**: Controls whether web search tool capabilities are enabled.

### 4. Financial and Velocity Ceilings (`budget`)
- **`max_spend_usd`**: Cumulative session ceiling for paid tool calls, inference APIs, or cloud resources.
- **`max_per_txn_usd`**: Hard cap on any single transaction (default: $10.00).
- **`max_tokens`**: Token velocity limiter preventing runaway infinite loops.

### 5. Temporal Validity and Non-Repudiation (`temporal` & `receipts`)
- **TTL Expiry**: Automatic invalidation after session duration (default: 120 minutes).
- **Audit Receipts**: Every evaluation produces a deterministic SHA-256 receipt hash for SOC 2 and audit log traceability.

---

## Quick Start

### Installation

```bash
# Via VS Code / Cursor Extensions Terminal
code --install-extension itsubsolomon.bartholomew-keystone

# Open VSX Registry
# https://open-vsx.org/extension/itsubsolomon/bartholomew-keystone
```

### Issuing a Passkey

1. Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS).
2. Select **`Keystone: Issue Agent Capability Passkey`**.
3. Choose a clearance preset:
   - **Developer Sandbox**: Read all workspace, write `src/` & `tests/`, test commands, $25 ceiling, 2h TTL.
   - **Read-Only Auditor**: Read-only clearance, no write permissions, no command execution.
   - **Custom Autonomous Clearance**: Interactively configure your own exact boundaries.
4. Keystone generates `.btp_keystone.json` and arms the status bar.

---

## Extension Commands

| Command | Identifier | Description |
|---|---|---|
| Issue Passkey | `keystone.issuePasskey` | Issue a signed agent capability passkey with presets |
| Inspect Clearance | `keystone.inspectClearance` | View active agent privileges, expiration, and spend limits |
| Revoke Passkey | `keystone.revokePasskey` | Instantly strip agent privileges and delete active passkey |
| Validate Action | `keystone.validateAction` | Test a proposed command or file path against current clearance |
| Audit Receipts | `keystone.auditReceipts` | View recent cryptographic clearance decision receipts |

---

## Open Source and Compliance

Bartholomew Keystone is **MIT licensed** and designed to comply with zero-trust agentic security architectures.

- Documentation: [bartholomew.info](https://bartholomew.info)
- Guard Extension: [Open VSX Registry](https://open-vsx.org/extension/itsubsolomon/bartholomew-guard-vscode)
- Python Package: `pip install btp-guard`
- NPM Package: `npm install btp-guard`
