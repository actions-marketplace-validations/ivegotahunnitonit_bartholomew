# Bartholomew Guard - AI Agent Safety & Guardrails (Cursor, Claude, Copilot)

> **Zero-trust firewall & execution guardrails for autonomous AI agents in Cursor, Claude Desktop, Windsurf, and VS Code.**  
> *Sub-35us In-Process AST Safety, 15 Enterprise Invariant Pillars, 40 Native MCP Tools, Tamper-Evident Action Forensics, and Direct AI Model Context Bridge.*

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/itsubsolomon.bartholomew-guard-vscode?color=blue&logo=visualstudiocode&label=VS%20Code%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=itsubsolomon.bartholomew-guard-vscode)
[![Open VSX](https://img.shields.io/badge/Open%20VSX-v5.4.31-blue)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
[![PyPI](https://img.shields.io/badge/PyPI-btp--guard%20v6.0.0-blue)](https://pypi.org/project/btp-guard/)
[![npm](https://img.shields.io/badge/npm-btp--guard%20v6.0.0-cb3837)](https://www.npmjs.com/package/btp-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Audit Score](https://img.shields.io/badge/Audit%20Score-100%2F100%20(A%2B)-success)](https://bartholomew.info)
[![Security Gates](https://img.shields.io/badge/Security%20Invariants-15%20Pillars%20Active-brightgreen)](https://bartholomew.info)

---

## Extension Overview

Bartholomew Guard operates in-process between autonomous AI coding assistants (Cursor Composer, Claude Code, GitHub Copilot, Gemini Antigravity, Windsurf, Roo Code, Cline) and your operating system. Every proposed command, file write, script execution, or network invocation is intercepted and verified against deterministic invariants in **under 35 microseconds** before execution:

- **Destructive Command Interception**: Blocks destructive operations such as `rm -rf`, `mkfs`, raw block overwrites, and unauthorized branch deletions.
- **In-Flight Secret & Credential Redaction**: Intercepts high-entropy API keys (`sk-*`, AWS keys, JWTs, OAuth tokens) and replaces them with cryptographically verified redaction masks before transmission.
- **Pipe-to-Shell Quarantine**: Halts and isolates unvetted remote scripts (`curl | bash`, `wget | sh`) before shell evaluation.
- **Keystone Agent Capabilities**: Constrains agent writes to permitted paths, sandboxes system commands, and enforces hard session spend limits ($25.00 ceiling, $10.00 single-action cap).
- **Universal Extension Mesh**: Automatically discovers installed agent toolchains (Cursor, Copilot, Claude Desktop, Cline, Python) and coordinates unified protection policies.

---

## Important Extension Cores (Visual Walkthrough)

### 1. Proof of Protection Dashboard Core
Real-time telemetry showing your workspace security score (100/100, Grade A+), active invariant status, evaluation latency (<24.8us), and the live action forensics ledger.

<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/dashboard_core.png" width="100%" alt="Bartholomew Guard Telemetry Dashboard" />
</p>

---

### 2. Plain-English Analysis Core
Instant diagnostic clarity across four structured panels detailing exactly what your agents are doing, what risks exist, what remediations are required, and how Bartholomew is actively safeguarding the workspace.

<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/breakdown_core.png" width="100%" alt="Bartholomew Plain-English Breakdown Core" />
</p>

---

### 3. Direct AI Model Context Bridge Core
One-click context injection buttons formatted specifically for Google Gemini / Antigravity, Anthropic Claude Code, Cursor Composer, and GitHub Copilot. Copy invariant rules directly into your prompt or composer.

<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/model_bridge_core.png" width="100%" alt="Bartholomew Direct AI Model Context Bridge" />
</p>

---

## Plain-English Analysis Breakdown

Whenever Bartholomew Guard audits your workspace or intercepts an agent operation, it surfaces a transparent four-stage breakdown:

| Stage | Focus | Description |
|---|---|---|
| **What's Going On** | Current Execution Posture | Live status of the workspace, agent activity levels, active invariant monitors, and background telemetry. |
| **What's Wrong** | Identified Hazards | Concrete misconfigurations, unshielded pre-commit hooks, missing agent policy files, or high-risk tool calls. |
| **What Needs Fixing** | Clear Next Steps | Actionable remediations to achieve a perfect 100/100 (A+) security rating. |
| **How We're Helping** | Active Invariant Guardrails | Sub-35us AST gates, in-flight secret masking, pipe-to-shell blocking, and Keystone capability passkeys actively defending the system. |

---

## How-To Guide: Step-by-Step Instructions

### Step 1: Installation

#### In VS Code, Cursor, or Windsurf
1. Open the Extensions pane (`Ctrl+Shift+X` or `Cmd+Shift+X`).
2. Search for **`Bartholomew AI Agent Guard`**.
3. Click **Install**.

#### Via Extensions CLI
```bash
# In VS Code:
code --install-extension itsubsolomon.bartholomew-guard-vscode

# In Cursor:
cursor --install-extension Bartholomew.bartholomew-guard-vscode

# Via Open VSX Registry:
# https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode
```

---

### Step 2: Open Proof of Protection & AI Bridge

Once installed, Bartholomew Guard immediately activates in your workspace. You can open the interactive dashboard in three ways:

1. **Activity Bar**: Click the **Bartholomew Shield** icon in the primary side bar (left).
2. **Status Bar**: Click the status indicator at the bottom: `[STATUS: ARMED (<25us)]`.
3. **Command Palette**: Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS) and run:
   ```text
   Bartholomew: Open Proof of Protection & AI Bridge
   ```

---

### Step 3: Inject Context into Your AI Companion

To bridge your active security invariants into your AI assistant:

1. In the Bartholomew dashboard, scroll to the **Straight-On Path to AI Models** card.
2. Click the button matching your assistant:
   - **`[Copy Context for Gemini]`**: Formatted for Google Gemini & Antigravity IDE.
   - **`[Copy Context for Claude]`**: Formatted for Anthropic Claude Code & Claude Desktop.
   - **`[Copy Context for Cursor]`**: Formatted for Cursor Composer & Chat.
   - **`[Copy Context for Copilot]`**: Formatted for GitHub Copilot Workspace.
3. Paste the copied snippet into your agent chat or system prompt.
4. Alternatively, click **`[View .btp/model-context.md]`** to view the auto-generated workspace briefing file.

---

### Step 4: 1-Click Immunize Any Repository

You can achieve a 100/100 (Grade A+) security posture in under two seconds:

1. Open the Command Palette (`Ctrl+Shift+P`).
2. Execute **`Bartholomew: Immunize Project (btp-guard protect)`**.
3. Bartholomew will:
   - Generate root invariant files (`GEMINI.md`, `CLAUDE.md`, `.cursorrules`).
   - Create the declarative invariant policy (`.btp/policy.yaml`).
   - Install the Git pre-commit AST safety hook (`.git/hooks/pre-commit`).
   - Issue a default Keystone agent capability passkey (`.btp/keystone.json`).

From the terminal:
```bash
# Using Python:
pip install btp-guard && btp-guard protect

# Using Node / npx:
npx btp-guard protect
```

---

### Step 5: Install Git Pre-Commit AST Barrier

Prevent uncommitted secrets and destructive syntax trees from ever entering version control:

1. Open the Command Palette (`Ctrl+Shift+P`).
2. Execute **`Bartholomew: Install Git Pre-Commit AST Hook`**.
3. The hook automatically runs `btp-guard check` on staged files prior to each git commit.

---

### Step 6: Review Live Forensics & Cryptographic Receipts

All agent actions are logged to `.btp/audit.log` with RFC 8785 Ed25519 deterministic hashes:

1. In the Bartholomew dashboard, inspect the **Live Action Forensics Ledger**.
2. Click any **SHA-256 Receipt** to copy its cryptographic proof for compliance audits (SOC 2, ISO 27001).
3. Export an auditor-ready evidence dossier at any time:
   ```text
   Bartholomew: Generate SOC 2 / ISO 27001 Evidence Pack
   ```

---

## Extension Commands Reference

| Command | Identifier | Description |
|---|---|---|
| `Bartholomew: Open Proof of Protection & AI Bridge` | `bartholomew.openProofOfProtection` | Opens full interactive telemetry, health score, and model bridge |
| `Bartholomew: Copy AI Context (Gemini, Claude, Cursor)` | `bartholomew.copyAiContext` | Interactive selector to copy structured prompt invariants |
| `Bartholomew: Immunize Project (btp-guard protect)` | `bartholomew.protectWorkspace` | 1-click generation of AI rules, policy, and git hooks |
| `Bartholomew: Install Git Pre-Commit AST Hook` | `bartholomew.installPreCommit` | Installs local AST barrier preventing unvetted commits |
| `Bartholomew: Inject AI Model Rules` | `bartholomew.injectAiRules` | Synchronizes GEMINI.md, CLAUDE.md, and .cursorrules |
| `Bartholomew: Generate SOC 2 / ISO 27001 Evidence Pack` | `bartholomew.generateEvidencePack` | Exports signed compliance dossier to .btp/evidence_pack.json |
| `Keystone: Issue Agent Capability Passkey` | `bartholomew.issueKeystonePasskey` | Issues cryptographic capability token with spend ceiling |

---

## Sovereign Architecture & Privacy

- **Zero Cloud Latency**: All invariant evaluations execute locally in CPython and V8.
- **Zero Third-Party Telemetry**: Code, terminal commands, and secrets never leave your workstation.
- **Open Standards**: Fully compatible with the Model Context Protocol (MCP), Open VSX, and standard Git toolchains.

- **Website**: [https://bartholomew.info](https://bartholomew.info)
- **PyPI**: [btp-guard on PyPI](https://pypi.org/project/btp-guard/)
- **npm**: [btp-guard on npm](https://www.npmjs.com/package/btp-guard)
- **License**: MIT
