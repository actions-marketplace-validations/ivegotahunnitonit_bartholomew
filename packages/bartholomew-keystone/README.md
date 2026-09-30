<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/keystone_logo.png" width="96" height="96" alt="Bartholomew Keystone Crest Logo" />
</p>

# Bartholomew Keystone - Cryptographic Agent Capability Passkeys

> **Issue tamper-evident, cryptographically signed permission slips for autonomous AI agents.**  
> *Define deterministic boundaries for file modifications, command executions, external network calls, and financial spend in Cursor, Claude Desktop, Windsurf, and VS Code.*

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v5.4.34-blue)](https://open-vsx.org/extension/Bartholomew/bartholomew-keystone)
[![Works With](https://img.shields.io/badge/Works%20With-Bartholomew%20Guard-blue)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
[![PyPI](https://img.shields.io/badge/PyPI-btp--guard%20v6.0.0-blue)](https://pypi.org/project/btp-guard/)
[![npm](https://img.shields.io/badge/npm-btp--guard%20v6.0.0-cb3837)](https://www.npmjs.com/package/btp-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## The Problem Keystone Solves

Autonomous AI coding agents (such as Cursor Agent, Claude Code, Cline, Windsurf, Devin, GitHub Copilot Workspace, and MCP tool runners) operate with broad system privileges. If an agent receives instructions containing an indirect prompt injection, or hallucinates during an automated refactoring loop, it can:

1. **Destroy files or git history** (`rm -rf`, destructive resets, overwriting production configs).
2. **Exfiltrate secrets and credentials** (reading `.env`, `.ssh/id_rsa`, AWS/GCP keys and transmitting via `curl`).
3. **Run out-of-scope system commands** (modifying permissions, installing malware, spawning unauthorized processes).
4. **Trigger unchecked financial costs** (calling billable APIs or Cloud services without budget boundaries).

System prompt instructions ("Please do not touch `.env`") are easily ignored or circumvented by prompt injections. **Bartholomew Keystone** enforces hard, deterministic cryptographic clearance boundaries at the tool execution seam.

---

## Keystone Core Visual

### Active Cryptographic Clearance and Scopes
Visualizing active capability boundaries: $25.00 session spend ceiling, $5.00 max per transaction, filesystem write restrictions, command sandboxing whitelists, and network egress controls.

<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/keystone_passkey_core.png" width="100%" alt="Bartholomew Keystone Passkey Core" />
</p>

---

## Guard vs. Keystone - How They Work Together

| Layer | Bartholomew Guard | Bartholomew Keystone (This Extension) |
|---|---|---|
| **Primary Role** | Invariant and Leak Detection | Cryptographic Capability Scoping |
| **How It Operates** | AST static analysis and runtime leak scanning | Issues and verifies signed capability passkeys |
| **Protection Focus** | Zero-leak credential guard, prompt-injection AST gate | Defines exact file globs, commands, domains, and budget limits |
| **Speed** | Sub-25 microseconds in-process verification | Sub-15 microseconds HMAC-SHA256 signature and scope check |
| **Installation** | Companion extension (`Bartholomew.bartholomew-guard-vscode`) | You are here (`Bartholomew.bartholomew-keystone`) |

---

## Core Clearance Scopes

When a Keystone Passkey is issued, the agent receives an ephemeral `.btp_keystone.json` token signed by the local authority. Every proposed action is evaluated against these scopes:

### 1. Filesystem Containment (`files`)
- **`allow_read`**: Globs the agent may inspect (e.g. `["src/**", "tests/**", "docs/**"]`).
- **`allow_write`**: Globs the agent is authorized to modify. Any write outside these paths is rejected instantly.
- **`deny`**: Blacklisted patterns strictly blocked from reading or writing (e.g. `.env*`, `secrets*`, `id_rsa*`, `.git/hooks/**`).
- **`max_file_size_kb`**: Maximum permissible file write payload to prevent repository bloat or disk exhaustion.

### 2. Command Sandboxing (`commands`)
- **`allow`**: Safe command whitelists allowed to execute without human intervention (e.g. `npm test`, `git status`, `pytest`).
- **`deny`**: Hard forbidden commands (e.g. `rm -rf`, `git push --force`, `curl | sh`, `chmod 777`).

### 3. Financial Spend Budget (`budget`)
- **`max_total_spend_usd`**: Cumulative session ceiling (default: `$25.00`). If autonomous loops exceed this limit, all further tool calls halt immediately.
- **`max_per_txn_usd`**: Per-action cost ceiling (default: `$5.00`) preventing runaway API or model inference spikes.

---

## How-To Guide: Step-by-Step Instructions

### Step 1: Issue an Autonomous Agent Passkey

Open your command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and choose:
```text
Keystone: Issue Agent Capability Passkey
```
Select a clearance profile:
- **Autonomous Dev Agent** (Standard workspace write access, $25 spend cap)
- **Read-Only Auditor** (File inspection only, zero writes, zero shell execution)
- **High-Trust Lead** (Extended permissions with per-transaction receipts)

### Step 2: Inspect Clearance Status

Run:
```text
Keystone: Inspect Active Agent Clearance
```
Or view the interactive Keystone status card in your sidebar.

### Step 3: Instant Revocation

If an agent exhibits erratic behavior:
1. Open the command palette.
2. Run **`Keystone: Revoke Current Agent Passkey`**.
3. The cryptographic passkey is permanently destroyed, disarming agent write and execution capabilities instantly.

---

## Open Source and Compliance

Bartholomew Keystone is **MIT licensed** and engineered for zero-trust agentic enterprise architectures.

- Documentation: [https://bartholomew.info](https://bartholomew.info)
- Guard Extension: [Open VSX Registry](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
- Python Package: `pip install btp-guard`
- NPM Package: `npm install btp-guard`
