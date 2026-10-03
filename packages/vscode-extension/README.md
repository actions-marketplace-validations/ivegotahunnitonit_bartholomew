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

## Verified Enforcement Boundaries (Explicit Architectural Scope)

Bartholomew enforces deterministic security invariants along 4 concrete, verified boundaries:

1. **Git Version Control Barrier (Fail-Closed Pre-Commit)**: Blocks unverified commits, secret leaks, and destructive code patterns before they can enter git history or be pushed to team remotes. Chained and non-destructive.
2. **Model Context Protocol (MCP) Tool Proxy (`btp_execute_command`, `btp_write_file`, etc.)**: When AI coding companions (Cursor MCP, Claude Desktop, Cline) invoke tools via MCP JSON-RPC stdio, payloads are gated and sanitized in-process (<35µs) before execution.
3. **Process Shim Sandbox (`ProcessShimSandbox` / `btp run`)**: Commands executed within the shimmed environment or launched via `btp run <cmd>` have their PATH wrapped with protective AST filters.
4. **Direct Static & Policy Verification (`btp check`, `btp audit`)**: Evaluates command strings, staged diffs, and workspace files against `.btp/policy.yaml`.

---

## What Bartholomew Does NOT Claim to Intercept (Explicit Boundary)

To build genuine trust, we state clearly what is **outside the enforcement boundary**:

- ❌ **Unshimmed Arbitrary IDE Terminals**: Manual terminal keystrokes and third-party IDE child processes that do NOT route through the Git hook, MCP server, or `ProcessShimSandbox` wrapper run directly on your shell without Bartholomew interception.
- ❌ **Semantic Code Correctness**: Bartholomew does not judge whether an agent wrote optimal algorithms or inefficient loops. Use your test suite (`npm test`, `pytest`).
- ❌ **Prompt Hallucinations / Pure Chat**: Bartholomew does not filter conversational chat text that does not execute tools, touch files, or make network calls.

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
