# Bartholomew Guard - AI Agent Safety & Guardrails (Cursor, Claude, Copilot)

> **Zero-trust firewall & execution guardrails for autonomous AI agents in Cursor, Claude Desktop, Windsurf, and VS Code.**  
> *Sub-35us In-Process AST Safety, 15 Enterprise Invariant Pillars, 40 Native MCP Tools, Tamper-Evident Action Forensics, and Direct AI Model Context Bridge.*

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/itsubsolomon.bartholomew-guard-vscode?color=blue&logo=visualstudiocode&label=VS%20Code%20Marketplace)](https://marketplace.visualstudio.com/items?itemName=itsubsolomon.bartholomew-guard-vscode)
[![Open VSX](https://img.shields.io/badge/Open%20VSX-v5.4.32-blue)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
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
- **Keystone Agent Capabilities**: Constrains agent writes to permitted paths, sandboxes system commands, and enforces hard session spend limits ($25.00 ceiling, $5.00 single-action cap).
- **Universal Extension Mesh**: Automatically discovers installed agent toolchains (Cursor, Copilot, Claude Desktop, Cline, Python) and coordinates unified protection policies.

---

## Important Extension Cores (Visual Walkthrough)

### 1. Proof of Protection Dashboard Core
Real-time telemetry showing your workspace security score (100/100, Grade A+), active invariant status, evaluation latency (<24.8us), and the live action forensics ledger.

<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/dashboard_core.png" width="100%" alt="Bartholomew Guard Telemetry Dashboard" />
</p>

---

### 2. Live Threat Sandbox & Plain-English Analysis Core
Interactive real-time threat simulator and four structured diagnostic panels. Test arbitrary shell commands, tool calls, and spend requests against the live AST barrier with zero-delay cryptographic receipts.

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
| **1. Active Protection Status** | Current Execution Posture | Live status of the workspace, agent activity levels, active invariant monitors, and background telemetry. |
| **2. Invariants & Integrity** | Identified Hazards | Concrete misconfigurations, unshielded pre-commit hooks, missing agent policy files, or high-risk tool calls. |
| **3. Recommended Operation** | Clear Next Steps | Actionable remediations to achieve a perfect 100/100 (A+) security rating. |
| **4. Core Active Capabilities** | Active Invariant Guardrails | Sub-35us AST gates, in-flight secret masking, pipe-to-shell blocking, and Keystone capability passkeys actively defending the system. |

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

### Step 2: Initialize Workspace Invariants

Open your command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and execute:
```text
Bartholomew: 1-Click Immunize Workspace
```
This generates `.btp/policy.yaml` and installs the Git AST pre-commit barrier to ensure no raw secrets or toxic commands ever exit your workstation.

### Step 3: Test Interactive Threat Sandbox

1. Click the **Bartholomew Shield icon** in your activity bar.
2. Select the **Threat Sandbox** tab.
3. Choose a preset attack scenario (e.g. `Blocked Wipe (rm -rf /)` or `Secret Leak`).
4. Click **Test Gate** to verify real-time sub-35us AST interception and review the generated SHA-256 cryptographic proof receipt.

### Step 4: Bridge into AI Coding Companions

Select the **AI Companions** tab to get customized system instructions for:
- **Anthropic Claude Desktop**: Automatically injects MCP security invariants.
- **Cursor IDE**: Direct `.cursorrules` enforcement snippet.
- **Google Gemini / Antigravity**: Scoped context prompt with Keystone token verification.
- **GitHub Copilot**: Real-time workspace guardrail instructions.

---

## Open Source and Enterprise Verification

Bartholomew Guard is open-source software under the **MIT License**.

- Documentation & Live Telemetry: [https://bartholomew.info](https://bartholomew.info)
- Source Repository: [GitHub](https://github.com/ivegotahunnitonit/bartholomew)
- Python Package: `pip install btp-guard`
- NPM Package: `npm install btp-guard`
