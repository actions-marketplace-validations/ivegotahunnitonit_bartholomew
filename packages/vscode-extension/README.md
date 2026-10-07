<p align="center">
  <img src="https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/images/logo.png" width="80" height="80" alt="Bartholomew Logo" />
</p>

# Bartholomew Guard — Agentic Runtime Protection (Cursor, Claude Code, Windsurf, VS Code)

> **The in-process execution firewall for autonomous coding agents.**  
> Intercepts destructive commands, prevents API key leaks, and caps agent spend in **under 35 microseconds** before code touches your operating system.

[![Open VSX](https://img.shields.io/badge/Open%20VSX-v6.4.3-purple?logo=eclipseide)](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
[![PyPI](https://img.shields.io/badge/PyPI-btp--guard%20v6.4.3-blue)](https://pypi.org/project/btp-guard/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Enterprise Support](https://img.shields.io/badge/Enterprise-Audit%20%26%20SLAs-10b981)](https://bartholomew.info/enterprise)

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
2. Click **`[ Run 60-Second Live Security Probe]`**.
3. Watch the animated in-process probe test safe vs. blocked execution with SHA-256 receipts.

### Option B: From Any Terminal
```bash
python -m btp_guard.cli prove
# Or run the trust boundary demo:
python -m btp_guard.demo_trust_boundary
```

---

## Editions & Licensing

| Tier | Deployment | Features |
| :--- | :--- | :--- |
| **Community Edition** | Open Source (Apache-2.0) | Local deterministic AST invariant gate, secret scrubber, tamper-evident audit ledger, VS Code / Cursor extension. |
| **Enterprise Edition** | Commercial / Managed | Centralized policy distribution, SIEM/telemetry streaming, multi-agent identity verification, enterprise SLA and compliance evidence packs. |

-> **[Request Enterprise Security Audit & Licensing](https://bartholomew.info/enterprise)** or contact `security@bartholomew.info`.

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
