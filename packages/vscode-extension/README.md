<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/logo.png" width="80" height="80" alt="Bartholomew Guard Logo" />
</p>

# Bartholomew Guard - Agentic Runtime Protection (Cursor, Claude Code, Windsurf, VS Code)

> **The in-process execution firewall for autonomous coding agents.**  
> Intercepts destructive commands, prevents API key leaks, and caps agent spend in **under 35 microseconds** before code touches your operating system.

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v6.5.3-purple?logo=eclipseide)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
[![Companion](https://img.shields.io/badge/Companion-Bartholomew%20Keystone-blue)](https://open-vsx.org/extension/Bartholomew/bartholomew-keystone)
[![Companion](https://img.shields.io/badge/Companion-Bartholomew%20Vault-0ea5e9)](https://open-vsx.org/extension/Bartholomew/bartholomew-vault)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Enterprise](https://img.shields.io/badge/Enterprise-Audit%20%26%20SLAs-10b981)](https://bartholomew.info)

---

## The Bartholomew Extension Trinity Overview

Bartholomew operates as a unified, three-tier developer runtime security suite across Cursor, Windsurf, Claude Code, Copilot, and VS Code:

```
[ Phase 1: Context Input ]       [ Phase 2: Authorization Scope ]       [ Phase 3: Runtime Execution ]
   Bartholomew Vault                 Bartholomew Keystone                    Bartholomew Guard
   In-Process PII & Secret           Cryptographic Clearance Passkeys        Sub-35µs In-Process AST
   Tokenization (<35µs)              & Spend Ceiling Governor                Invariant Gate & Sentinel
```

1. **Bartholomew Vault** (`Bartholomew.bartholomew-vault`): Zero-latency PII, HIPAA PHI, and credential tokenization. Replaces live keys, emails, and SSNs with format-preserving surrogates before cloud LLM transmission, detokenizing just-in-time for local test runs.
2. **Bartholomew Keystone** (`Bartholomew.bartholomew-keystone`): Signed Non-Human Identity (NHI) clearance passkeys. Enforces authorized filesystem directories, whitelisted CLI tools, and hard $25/day session spend caps.
3. **Bartholomew Guard** (`Bartholomew.bartholomew-guard-vscode` - This Extension): Deterministic in-process AST execution gateway. Evaluates bash, python, and MCP tool payloads fail-closed in under 35 microseconds to block destructive operations (`rm -rf`, `DROP TABLE`, reverse shells).

### 1-Click Terminal Installation for the Full Trinity

```bash
# In Cursor:
cursor --install-extension Bartholomew.bartholomew-guard-vscode
cursor --install-extension Bartholomew.bartholomew-keystone
cursor --install-extension Bartholomew.bartholomew-vault

# In VS Code:
code --install-extension Bartholomew.bartholomew-guard-vscode
code --install-extension Bartholomew.bartholomew-keystone
code --install-extension Bartholomew.bartholomew-vault
```

---

## The One Job Bartholomew Does

When autonomous agents (Cursor Composer, Claude Code, Windsurf, Cline, Copilot) suggest terminal commands, file writes, or API tool calls, Bartholomew acts as a **local, deterministic execution gate**.

Every action is verified against policy with **sub-millisecond execution overhead**. If an agent attempts an unauthorized or destructive action, it is blocked fail-closed before execution, and an immutable cryptographic receipt is generated.

---

## Verified Enforcement Boundaries (Explicit Architectural Scope)

Bartholomew enforces deterministic security invariants along 4 concrete, verified boundaries:

1. **Git Version Control Barrier (Fail-Closed Pre-Commit)**: Blocks unverified commits, secret leaks, and destructive code patterns before they can enter git history or be pushed to team remotes. Chained and non-destructive.
2. **Model Context Protocol (MCP) Tool Proxy (`btp_execute_command`, `btp_write_file`, etc.)**: When AI coding companions (Cursor MCP, Claude Desktop, Cline) invoke tools via MCP JSON-RPC stdio, payloads are gated and sanitized in-process before execution.
3. **Process Shim Sandbox (`ProcessShimSandbox` / `btp run`)**: Commands executed within the shimmed environment or launched via `btp run <cmd>` have their PATH wrapped with protective AST filters.
4. **Direct Static & Policy Verification (`btp check`, `btp audit`)**: Evaluates command strings, staged diffs, and workspace files against `.btp/policy.yaml`.

---

## What Bartholomew Does NOT Claim to Intercept (Explicit Boundary)

To build genuine trust, we state clearly what is **outside the enforcement boundary**:

- **Unshimmed Arbitrary IDE Terminals**: Manual terminal keystrokes and third-party IDE child processes that do NOT route through the Git hook, MCP server, or `ProcessShimSandbox` wrapper run directly on your shell without Bartholomew interception.
- **Semantic Code Correctness**: Bartholomew does not judge whether an agent wrote optimal algorithms or inefficient loops. Use your test suite (`npm test`, `pytest`).
- **Prompt Hallucinations / Pure Chat**: Bartholomew does not filter conversational chat text that does not execute tools, touch files, or make network calls.

---

## How to Verify It Is Active (In 5 Seconds)

### Option A: From VS Code / Cursor Sidebar
1. Click the **Bartholomew Shield** icon in your activity bar.
2. Click **`[ Run 60-Second Live Security Probe ]`**.
3. Watch as a test payload is generated, evaluated, and blocked fail-closed in under 35 microseconds with a signed cryptographic audit receipt.

### Option B: From the Terminal
```bash
# Verify security policy
python -m btp_guard.cli check

# Run an agent tool under the deterministic sandbox
python -m btp_guard.cli run -- npm test
```

---

## Enterprise Support & Trust Center

- **Repository**: [https://github.com/ivegotahunnitonit/bartholomew](https://github.com/ivegotahunnitonit/bartholomew)
- **Live Trust Center**: [https://bartholomew.info](https://bartholomew.info)
- **Security Contact**: `help@bartholomew.info`
