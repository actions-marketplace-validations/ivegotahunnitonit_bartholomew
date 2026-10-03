<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/logo.png" width="80" height="80" alt="Bartholomew Logo" />
</p>

# Bartholomew Guard — Agentic Runtime Protection (Cursor, Claude Code, Windsurf, VS Code)

> **The in-process execution firewall for autonomous coding agents.**  
> Intercepts destructive commands, prevents API key leaks, and caps agent spend in **under 35 microseconds** before code touches your operating system.

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v6.4.0-purple?logo=eclipseide)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
[![PyPI](https://img.shields.io/badge/PyPI-btp--guard%20v6.4.0-blue)](https://pypi.org/project/btp-guard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Team Pilot](https://img.shields.io/badge/Team%20Pilot-%24199%2Fmo%20--%2030%20Days-10b981)](https://bartholomew.info/#pricing)

---

## The One Job Bartholomew Does

When autonomous agents (Cursor Composer, Claude Code, Windsurf, Cline, Copilot) suggest terminal commands, file writes, or API tool calls, Bartholomew acts as a **local, deterministic execution gate**.

Every action is verified against policy in **<35 microseconds**. If an agent attempts an unauthorized or destructive action, it is blocked fail-closed before execution, and an immutable cryptographic receipt is generated.

---

## What Bartholomew Protects

1. **Destructive Terminal Operations**: Blocks `rm -rf`, disk wipes (`format C:`, `del /s`), raw partition writes (`dd`, `mkfs`), and pipe-to-shell payloads (`curl | bash`).
2. **In-Flight API Secret Leaks**: Intercepts high-entropy credentials (`.env`, `sk-*`, AWS keys, bearer tokens) and replaces them with redaction masks before external transmission.
3. **Agent Spend & Budget Ceilings**: Enforces hard caps on agentic transactions ($25 session ceiling, $5 single-transaction cap) to prevent accidental infinite loops and runaway API billing.
4. **Git Pre-Commit Protection**: Enforces pre-commit invariants so no toxic commands or raw secrets enter your team's repository branches.

---

## What Bartholomew Does NOT Protect (Explicit Scope Boundary)

To build genuine trust, we state clearly what is **out of scope**:

- ❌ **Semantic Code Quality**: Bartholomew does not judge whether the agent wrote good algorithms or poor $O(N^3)$ loops. Use your standard test suite (`npm test`, `pytest`).
- ❌ **Prompt Hallucinations / Factual Errors**: Bartholomew does not filter chat text that does not touch files, terminal commands, or network sockets.
- ❌ **Manual Human Actions**: Bartholomew inspects agentic tool proposals, not manual terminal actions initiated directly by human developers.

---

## How to Verify It Is Active (In 5 Seconds)

### Option A: From VS Code / Cursor Sidebar
1. Click the **Bartholomew Shield** icon in your activity bar.
2. Click **`[⚡ Run 60-Second Live Security Probe]`**.
3. Watch the animated in-process probe test safe vs. blocked execution in <35µs with SHA-256 receipts.

### Option B: From Any Terminal
```bash
python -m btp_guard.cli prove
# Or run the trust boundary demo:
python -m btp_guard.demo_trust_boundary
```

---

## Pricing: Free for Developers, Built for Teams

| Tier | Price | What You Get |
| :--- | :--- | :--- |
| **Developer Edition** | **Free Forever** (MIT) | Personal AST invariant gate, secret scrubber, local tamper-evident ledger, VS Code / Cursor sidebar. |
| **30-Day Team Pilot** | **$199 / month** *(or $950 one-time)* | Up to 10 engineers. Centralized repository policy sync (`.btp/policy.yaml`), team-wide pre-commit hooks, CISO/SOC2-ready PDF compliance dossier, 30-min setup call, 100% money-back guarantee. |

👉 **[Start a 30-Day Team Pilot](https://bartholomew.info/#pricing)** or email `founders@bartholomew.info`.

---

## Supported Autonomous Runtimes

- **Cursor**
- **Claude Code**
- **Windsurf**
- **Cline**
- **Aider**
- **OpenHands**
- **Smolagents**
- **CrewAI & AutoGen**
- **Ollama / vLLM local harnesses**

---

## Quickstart

```bash
# 1. Install CLI
pip install btp-guard

# 2. Immunize your workspace (creates .btp/policy.yaml and git hook)
btp-guard immunize

# 3. Verify protection
btp-guard prove
```

Website: [https://bartholomew.info](https://bartholomew.info)  
Documentation: [Reproducible Trust Boundary Demo](https://github.com/ivegotahunnitonit/bartholomew/blob/main/docs/REPRODUCIBLE_DEMO.md)
