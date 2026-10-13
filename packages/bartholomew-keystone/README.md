<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/keystone_logo.png" width="80" height="80" alt="Bartholomew Keystone Logo" />
</p>

# Bartholomew Keystone - Cryptographic Agent Passkeys & Spend Governor

> **Issue deterministic, signed capability passkeys for autonomous AI coding agents in Cursor, Claude Code, Windsurf, and VS Code.**  
> Restricts file writes, system commands, and financial spend to explicit policy bounds in **under 15 microseconds**.

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v6.5.5-purple?logo=eclipseide)](https://open-vsx.org/extension/Bartholomew/bartholomew-keystone)
[![Companion](https://img.shields.io/badge/Companion-Bartholomew%20Guard-brightgreen)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
[![Companion](https://img.shields.io/badge/Companion-Bartholomew%20Vault-0ea5e9)](https://open-vsx.org/extension/Bartholomew/bartholomew-vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Team Pilot](https://img.shields.io/badge/Team%20Pilot-%24199%2Fmo-10b981)](https://buy.stripe.com/3cI6oHbNz3LQ4U84He9R605)

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
2. **Bartholomew Keystone** (`Bartholomew.bartholomew-keystone` - This Extension): Signed Non-Human Identity (NHI) clearance passkeys. Enforces authorized filesystem directories, whitelisted CLI tools, and hard $25/day session spend caps.
3. **Bartholomew Guard** (`Bartholomew.bartholomew-guard-vscode`): Deterministic in-process AST execution gateway. Evaluates bash, python, and MCP tool payloads fail-closed in under 35 microseconds to block destructive operations (`rm -rf`, `DROP TABLE`, reverse shells).

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

## The One Job Keystone Does

Prompt instructions like *"Please do not modify files outside `src/`"* are routinely bypassed by prompt injection or model hallucination.

**Keystone solves this with local cryptographic capability passkeys**:
Before an agent writes a file, executes a terminal command, or triggers a billable tool call, Keystone evaluates the action against a cryptographically signed capability passkey in **<15 microseconds**.

---

## What Keystone Protects

1. **Filesystem Boundaries**: Whitelists write paths (e.g. `src/**`, `tests/**`) while blocking modifications to production configs, `.env` files, or `.git/hooks`.
2. **Command Whitelisting**: Whitelists build/test commands (`npm test`, `pytest`, `cargo check`) while denying destructive actions (`rm`, `sudo`, `mkfs`, `format C:`).
3. **Spend & Micro-Billing Ceilings**: Enforces hard budget ceilings ($25 session cap, $10 single transaction ceiling) to stop rogue recursive API loops.
4. **Verifiable Audit Receipts**: Generates signed HMAC-SHA256 Merkle receipts for every clearance evaluation.

---

## What Keystone Does NOT Protect (Explicit Scope Boundary)

- **Code Quality**: Keystone does not evaluate whether code written inside allowed paths is optimal or bug-free.
- **Prompt Accuracy**: Keystone does not police general conversation text.
- **Manual Human Actions**: Keystone enforces bounds on autonomous agents operating through IDE tools or MCP protocols.

---

## Commands

- `Keystone: Issue Agent Capability Passkey`: Generates signed non-human identity clearance tokens for agent sessions.
- `Keystone: Inspect Active Clearance`: View authorized directories, spend ceilings, and whitelisted tools.
- `Keystone: Revoke Session Passkey`: Instantly invalidates all active clearance tokens.
- `Keystone: Validate Action Against Active Passkey`: Evaluates test payloads against active policy in <15 microseconds.
- `Keystone: View Cryptographic Audit Receipts`: Displays immutable HMAC receipts of evaluated actions.

---

## Enterprise Support & Trust Center

- **Repository**: [https://github.com/ivegotahunnitonit/bartholomew](https://github.com/ivegotahunnitonit/bartholomew)
- **Live Trust Center**: [https://bartholomew.info](https://bartholomew.info)
- **Security Contact**: `help@bartholomew.info`
