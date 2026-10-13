<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/logo.png" width="80" height="80" alt="Bartholomew Logo" />
</p>

# Bartholomew Trinity - Complete AI Agent Security Suite

> **1-Click installation of the entire Bartholomew runtime security pipeline for Cursor, Claude Code, Windsurf, Copilot, and VS Code.**  
> Protects filesystems, blocks destructive commands, tokenizes sensitive data, and enforces spend ceilings across autonomous coding agents.

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v6.5.5-purple?logo=eclipseide)](https://open-vsx.org/extension/Bartholomew/bartholomew-trinity)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](LICENSE.md)
[![Compliance](https://img.shields.io/badge/Compliance-HIPAA%20%7C%20PCI--DSS%20%7C%20SOC%202-blue)](https://bartholomew.info)
[![Latency](https://img.shields.io/badge/Latency-Sub--35%C2%B5s%20In--Process-brightgreen)](https://bartholomew.info)

---

## 1-Click Terminal Installation

Install the entire Trinity with a single command:

```bash
# In Cursor:
cursor --install-extension Bartholomew.bartholomew-trinity

# In VS Code:
code --install-extension Bartholomew.bartholomew-trinity

# In Windsurf:
windsurf --install-extension Bartholomew.bartholomew-trinity
```

---

## Included Extensions

This extension pack installs and configures all three components of the Bartholomew Trinity:

```
[ Phase 1: Context & MCP Input ]    [ Phase 2: Authorization Scope ]       [ Phase 3: Runtime Execution ]
   Bartholomew Vault                     Bartholomew Keystone                    Bartholomew Guard
   In-Process PII, Secret & MCP          Cryptographic Clearance Passkeys        Sub-35µs In-Process AST
   Shield Tokenization (<35µs)           & Spend Ceiling Governor                Invariant Gate & Sentinel
```

### 1. [Bartholomew Vault](https://open-vsx.org/extension/Bartholomew/bartholomew-vault)
- Sub-35µs in-process credential, API key, and PII tokenization.
- Format-preserving surrogates prevent raw secrets from reaching cloud LLMs.
- JIT (Just-In-Time) RAM detokenization ensures local test commands execute normally.
- In-process Model Context Protocol (MCP) Safety Shielding for tool calls.

### 2. [Bartholomew Keystone](https://open-vsx.org/extension/Bartholomew/bartholomew-keystone)
- Ephemeral HMAC-SHA256 Non-Human Identity (NHI) clearance passkeys.
- Enforces strict write-path boundaries (e.g. `src/**`), allowed CLI tools, and network domains.
- Hard $25/day session budget ceiling prevents runaway autonomous spending.

### 3. [Bartholomew Guard](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
- Deterministic polyglot AST execution firewall.
- Intercepts destructive commands (`rm -rf`, `DROP TABLE`, reverse shells) in under 35 microseconds.
- Fail-closed git pre-commit sentinel blocks unauthorized repository changes.

---

## Architecture & Enterprise Support

- **Repository**: [https://github.com/ivegotahunnitonit/bartholomew](https://github.com/ivegotahunnitonit/bartholomew)
- **Documentation & Trust Center**: [https://bartholomew.info](https://bartholomew.info)
- **Support**: `help@bartholomew.info`
