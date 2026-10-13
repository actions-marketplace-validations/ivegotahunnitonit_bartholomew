<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/vault_logo.png" width="80" height="80" alt="Bartholomew Vault Logo" />
</p>

# Bartholomew Vault - In-Process Data, Credential & MCP Safety Shield for AI Coding Agents

> **Sub-millisecond in-process credential, PHI, PII tokenization and Model Context Protocol (MCP) tool call gating for Cursor, Claude Code, Windsurf, Copilot, and VS Code.**  
> Enables developers and autonomous agents to inspect production databases, logs, and sensitive payloads with zero raw secret exfiltration and zero malicious MCP tool exploits.

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v6.5.5-purple?logo=eclipseide)](https://open-vsx.org/extension/Bartholomew/bartholomew-vault)
[![Companion](https://img.shields.io/badge/Companion-Bartholomew%20Guard-brightgreen)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
[![Keystone](https://img.shields.io/badge/Companion-Bartholomew%20Keystone-blue)](https://open-vsx.org/extension/Bartholomew/bartholomew-keystone)
[![Compliance](https://img.shields.io/badge/Compliance-HIPAA%20%7C%20PCI--DSS%20%7C%20SOC%202-blue?style=flat-square)](https://bartholomew.info)
[![Latency](https://img.shields.io/badge/Latency-Sub--35%C2%B5s%20In--Process-brightgreen?style=flat-square)](https://bartholomew.info)
[![License](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE.md)

---

## The Bartholomew Extension Trinity Overview

Bartholomew operates as a unified, three-tier developer runtime security suite across Cursor, Windsurf, Claude Code, Copilot, and VS Code:

```
[ Phase 1: Context & MCP Input ]    [ Phase 2: Authorization Scope ]       [ Phase 3: Runtime Execution ]
   Bartholomew Vault                     Bartholomew Keystone                    Bartholomew Guard
   In-Process PII, Secret & MCP          Cryptographic Clearance Passkeys        Sub-35µs In-Process AST
   Shield Tokenization (<35µs)           & Spend Ceiling Governor                Invariant Gate & Sentinel
```

1. **Bartholomew Vault** (`Bartholomew.bartholomew-vault` - This Extension): Zero-latency PII, HIPAA PHI, credential tokenization, and in-process MCP tool call interception. Replaces live keys, emails, and SSNs with format-preserving surrogates before cloud LLM transmission, detokenizing just-in-time for local test runs.
2. **Bartholomew Keystone** (`Bartholomew.bartholomew-keystone`): Signed Non-Human Identity (NHI) clearance passkeys. Enforces authorized filesystem directories, whitelisted CLI tools, and hard $25/day session spend caps.
3. **Bartholomew Guard** (`Bartholomew.bartholomew-guard-vscode`): Deterministic in-process AST execution gateway. Evaluates bash, python, and tool payloads fail-closed in under 35 microseconds to block destructive operations (`rm -rf`, `DROP TABLE`, reverse shells).

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

## What Bartholomew Vault Does

When developers and autonomous agents inspect production logs, query live databases, execute MCP server tools, or review configuration files, **Bartholomew Vault acts as an in-process, zero-latency privacy and tool safety gateway**.

It deterministically converts live credentials, patient PHI, and customer PII into format-preserving surrogate tokens before prompts leave the IDE. When the agent dispatches a test command or integration script locally, Vault detokenizes values just-in-time in process memory - ensuring local commands succeed while cloud LLMs never see plaintext secrets.

Furthermore, with built-in **MCP Safety Shielding**, Vault intercepts Model Context Protocol `tools/call` JSON-RPC messages and MCP configuration files (`claude_desktop_config.json`, `cursor_mcp.json`) in <35 microseconds. Any high-risk operation (`DROP TABLE`, shell escapes, unredacted secrets in arguments) is blocked fail-closed before dispatch.

---

## The Problem: Why Simple Redaction Breaks AI Coding

1. **Simple Redaction Breaks Code Logic**: Traditional DLP tools replace sensitive fields with `[REDACTED]`. The moment an agent tries to reason about variables, trace dependencies, or run `curl -H "Authorization: Bearer [REDACTED]"`, the code crashes.
2. **Format-Preserving Surrogates Keep Code Functional**: Bartholomew Vault replaces real secrets with valid synthetic equivalents:
   - Real API Key: Replaced with `sk_live_vault_surrogate_...`
   - Real Patient Email: `sarah.jenkins@hospital.org` -> Vault Token: `patient_anon_88192@vault.local`
   - Real Credit Card: Valid Luhn 16-digit surrogate generated on the fly.
3. **Just-In-Time Detokenization**: When the agent issues a local test run via terminal or subprocess, Vault's local bridge detokenizes the surrogate back to the live value in-memory, executes the call, and re-tokenizes the output before displaying it.

---

## Model Context Protocol (MCP) Safety Shield

Vault provides native interception for MCP tools and configurations:

- **JSON-RPC Interception (`mcp-shield` CLI & Extension API)**: Intercepts `tools/call` messages in sub-35µs, stripping PII and validating SQL/system command arguments against destructive invariants.
- **MCP Config Hardening**: Scans MCP JSON configurations to ensure raw API keys are replaced with environment variable references.
- **Standalone CLI Wrapper**:
  ```bash
  # Wrap any standard MCP server transparently:
  npx mcp-shield --server "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb"
  ```

---

## Features & Capabilities

- **Integrated Activity Bar View**: Dedicated cybernetic Vault icon and real-time inspector in the IDE sidebar with zero clutter.
- **Zero-Latency In-Process Tokenization**: Evaluates buffer changes and selection edits in <35 microseconds without network calls.
- **MCP Tool Interception & Auditing**: Audits MCP configurations and enforces sub-35µs guardrails on tool arguments.
- **HIPAA, PCI-DSS & SOC 2 Compliance**: Keeps raw patient health information (PHI) and cardholder data off model training datasets and LLM provider log servers.
- **Bi-Directional Mapping**: Seamless detokenization for authorized developers via the command palette.
- **Drata & Vanta Compliance Proof Export**: 1-click generation of cryptographic JSON audit reports proving zero plaintext PII was transmitted during agent sessions.
- **Compatible with the Bartholomew Trinity**: Works hand-in-hand with Bartholomew Guard (AST Gate) and Bartholomew Keystone (Capability Passkeys).

---

## Commands

- `Vault: Tokenize Selected Text / PII (In-Process)`: Manually tokenizes high-sensitivity text.
- `Vault: Detokenize Selection (Authorized View)`: Restores original values in active document.
- `Vault: Inspect Active In-Memory Token Mappings`: Opens a secure read-only viewer of current surrogate bindings.
- `Vault: Flush In-Memory Surrogates`: Clears current session lookup tables immediately.
- `Vault: Audit MCP Servers Configuration`: Audits active MCP configs for plaintext secrets.
- `Vault: Shield MCP Configuration File`: Replaces raw tokens in MCP server configs with environment variables.
- `Vault: Intercept MCP Tool Call`: In-process invariant validation for MCP tool payloads.
- `Vault: Export Drata / Vanta HIPAA & SOC 2 Proof Dossier`: Generates verifiable JSON proof of zero-leakage compliance.

---

## Architecture & Enterprise Support

- **Repository**: [https://github.com/ivegotahunnitonit/bartholomew](https://github.com/ivegotahunnitonit/bartholomew)
- **Documentation & Trust Center**: [https://bartholomew.info](https://bartholomew.info)
- **Support**: `help@bartholomew.info`