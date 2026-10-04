<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/keystone_logo.png" width="80" height="80" alt="Bartholomew Keystone Logo" />
</p>

# Bartholomew Keystone — Cryptographic Agent Passkeys & Spend Governor

> **Issue deterministic, signed capability passkeys for autonomous AI coding agents in Cursor, Claude Code, Windsurf, and VS Code.**  
> Restricts file writes, system commands, and financial spend to explicit policy bounds in **under 15 microseconds**.

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v6.4.3-purple?logo=eclipseide)](https://open-vsx.org/extension/Bartholomew/bartholomew-keystone)
[![Companion](https://img.shields.io/badge/Companion-Bartholomew%20Guard-brightgreen)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Team Pilot](https://img.shields.io/badge/Team%20Pilot-%24199%2Fmo%20--%2030%20Days-10b981)](https://buy.stripe.com/3cI6oHbNz3LQ4U84He9R605)

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

- - **Code Quality**: Keystone does not evaluate whether code written inside allowed paths is optimal or bug-free.
- - **Prompt Accuracy**: Keystone does not police general conversation text.
- - **Manual Human Actions**: Keystone enforces bounds on autonomous agents operating through IDE tools or MCP protocols.

---

## How to Verify It Is Active (In 5 Seconds)

1. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
2. Run: **`Keystone: Open Passkey Dashboard & Capability Monitor`**.
3. In the interactive probe box, test any command (`rm -rf /`, `cat .env`, `npm test`) and see the sub-15µs verdict and receipt hash.

---

## Pricing: Free for Developers, Built for Teams

| Tier | Price | What You Get |
| :--- | :--- | :--- |
| **Developer Edition** | **Free Forever** (MIT) | Local capability passkeys, interactive dashboard, spend capping, tamper-evident logs. |
| **30-Day Team Pilot** | **$199 / month** *(or $950 one-time)* | Up to 10 engineers. Centralized passkey policy sync, multi-seat key rings, weekly CISO/SOC2 compliance dossier, 30-min onboarding kickoff, 100% money-back guarantee. |

-> **[Start a 30-Day Team Pilot ($199/mo)](https://buy.stripe.com/3cI6oHbNz3LQ4U84He9R605)** or learn more at [bartholomew.info](https://bartholomew.info/#pricing) or email `founders@bartholomew.info`.

---

## Quickstart

```bash
# 1. Install companion CLI
pip install btp-guard

# 2. Issue a Developer Sandbox passkey in your workspace
btp-guard keystone issue --preset developer

# 3. Verify active passkey
btp-guard keystone verify
```

Website: [https://bartholomew.info](https://bartholomew.info)  
Full Guide: [Reproducible Trust Boundary Demo](https://github.com/ivegotahunnitonit/bartholomew/blob/main/docs/REPRODUCIBLE_DEMO.md)
