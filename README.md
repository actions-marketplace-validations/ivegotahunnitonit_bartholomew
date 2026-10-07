<p align="center">
  <img src="packages/vscode-extension/icon.png" width="130" alt="Bartholomew Shield Logo" />
</p>

# Bartholomew Guard — In-Process Agentic Execution Gateway

> **Deterministic AST Policy Invariants, In-Flight Secret Masking, and Cryptographic Telemetry for Autonomous Agents & Tool Runtimes.**  
> Intercepts destructive commands, prevents secret exfiltration, and enforces budget invariants in **sub-millisecond execution overhead (< 0.1 ms - < 1 ms)** before tool calls execute.

<!-- BTP Status Badges -->
[![Security Score](https://img.shields.io/badge/Security%20Audit-100%2F100%20A%2B-brightgreen?style=flat-square)](docs/mcp_tool_registry_v6.json)
[![Tests](https://img.shields.io/badge/Tests-147%20v6%20%7C%203%2C199%20Total-brightgreen?style=flat-square)](tests/)
[![MCP Tools](https://img.shields.io/badge/MCP%20Tools-40%20Native-blue?style=flat-square)](docs/mcp_tool_registry_v6.json)
[![CI](https://github.com/ivegotahunnitonit/bartholomew/actions/workflows/ci.yml/badge.svg)](https://github.com/ivegotahunnitonit/bartholomew/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/btp-guard?logo=pypi&logoColor=white)](https://pypi.org/project/btp-guard/)
[![npm](https://img.shields.io/badge/npm-btp--guard%20v6.4.4-cb3837?logo=npm&logoColor=white)](https://www.npmjs.com/package/btp-guard)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Enterprise Support](https://img.shields.io/badge/Enterprise-Audit%20%26%20SLAs-10b981)](https://bartholomew.info/enterprise)

---

## Architectural Overview

When autonomous agents (Claude Code, Cursor, Copilot, CrewAI, AutoGen, LangChain) suggest terminal commands, file modifications, or external tool invocations, Bartholomew acts as an **in-process deterministic execution gateway**.

Every proposed action is statically evaluated against enterprise policy with **sub-millisecond overhead**. If an action violates security invariants (e.g., destructive filesystem commands, SQL table drops, secret exfiltration, budget overruns), execution is vetoed fail-closed before process dispatch, and an immutable cryptographic audit receipt is logged.

```
                    [ Autonomous Agent / LLM Orchestrator ]
                                       │
                                       ▼ (Proposes Tool Call / Bash / SQL)
   ┌────────────────────────────────────────────────────────────────────────┐
   │             Bartholomew In-Process Runtime Gateway                     │
   │                                                                        │
   │   [ Polyglot AST Invariant Gate ]     Sub-millisecond syntax validation│
   │   [ In-Flight Secret Vault ]          Zero-allocation credential mask  │
   │   [ Declarative Policy Engine ]       Spend caps & command allowlists  │
   │   [ Tamper-Evident Audit Ledger ]     RFC 8785 Canonical JSON Digests  │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
                 [ ALLOWED ]                       [ DENIED ]
                      │                                 │
             [ Target System / OS ]       [ Execution Veto + Audit Telemetry ]
```

---

## Verified Enforcement Boundaries

Bartholomew enforces deterministic security invariants across four verified boundaries:

1. **Git Version Control Barrier (Fail-Closed Pre-Commit)**: Blocks unverified commits, API key leaks, and destructive code patterns before entering git history.
2. **Model Context Protocol (MCP) Tool Proxy**: Intercepts JSON-RPC stdio tool calls (`execute_command`, `write_file`) and enforces AST invariants in-process prior to execution.
3. **Process Shim Sandbox (`btp run`)**: Wraps execution environments with protective AST filtering on OS process dispatch.
4. **Static & Policy Verification (`btp check`, `btp audit`)**: Evaluates command strings, staged diffs, and workspace files against `.btp/policy.yaml`.

### Explicit Non-Interception Scope
To establish rigorous security boundaries, the following are explicitly outside the scope of AST gating:
- **Unshimmed Host Terminals**: Manual terminal interactions executed outside wrapped MCP, Git hooks, or `btp run` shims run directly on the underlying operating system.
- **Semantic Code Quality**: Bartholomew validates security invariants, not algorithmic efficiency or business logic correctness.
- **Pure Conversational Text**: Chat outputs that do not trigger system tools, filesystem writes, or network requests are not evaluated by execution gates.

---

## Quickstart

### Installation

```bash
# Python SDK & CLI
pip install btp-guard

# Node.js / TypeScript SDK
npm install btp-guard
```

### Local Workspace Policy Initialization

Initialize workspace security policies and pre-commit AST verification:

```bash
# Initialize local repository invariants
btp-guard arm

# Verify workspace files and policies
btp-guard check --all
```

This configures:
- `.btp/policy.yaml`: Declarative workspace execution invariants and spend limits.
- Git Pre-Commit Hook: Prevents credential leaks and destructive commands prior to git commits.
- Machine-readable context files for local IDE agent integration.

---

## SDK Integration

### Python (LangChain, CrewAI, AutoGen, Semantic Kernel, OpenAI SDK)

```python
from btp_guard import Guard, protect_agent

# Initialize execution guard
guard = Guard(strict=True)

# 1. Deterministic AST invariant evaluation
verdict = guard.check("rm -rf /var/data")
print(verdict)
# {'allowed': False, 'verdict': 'DENY', 'rule_id': 'BTP-AST-001', 'overhead_ms': 0.08}

# 2. In-flight secret sanitization with placeholder anonymization
clean_text = guard.scrub("Authorization: Bearer sk-proj-SAMPLE_KEY_FOR_TESTING_PURPOSES")
print(clean_text)
# "Authorization: Bearer [REDACTED_API_KEY_BTP_SEC_001]"

# 3. Universal agent wrapper with spend ceiling
# protected_agent = protect_agent(agent, spend_cap=50.0)
```

### Node.js / TypeScript (LangChain.js, Vercel AI SDK, MCP Servers)

```typescript
import { evaluateIntent, protectAgent } from 'btp-guard';

// Sub-millisecond in-process check
const result = evaluateIntent({
  agentId: 'service-worker-1',
  actionType: 'EXEC_COMMAND',
  payload: { cmd: 'cat .env' }
});

if (!result.allowed) {
  console.error(`Blocked by invariant rule: ${result.ruleId}`);
}
```

---

## Framework Compatibility

Bartholomew provides validated runtime adapters across enterprise agent orchestrators:

| Framework | Adapter Integration | Reference Documentation |
| :--- | :--- | :--- |
| **OpenAI Agents SDK** | Dynamic Tool Gating & Schema Invariant Interceptor | [`docs/FRAMEWORK_GUIDE.md`](docs/FRAMEWORK_GUIDE.md) |
| **Anthropic Claude** | `ClaudeToolGuard` Pre-Execution Filter | [`docs/CLAUDE_CODE_INTEGRATION_GUIDE.md`](docs/CLAUDE_CODE_INTEGRATION_GUIDE.md) |
| **CrewAI** | `@btp_crewai_tool` Boundary & Invariant Gate | [`docs/FRAMEWORK_GUIDE.md`](docs/FRAMEWORK_GUIDE.md) |
| **LangChain / LangGraph** | `BTPGuardTool` Node Interceptor | [`docs/FRAMEWORK_GUIDE.md`](docs/FRAMEWORK_GUIDE.md) |
| **Microsoft AutoGen** | Swarm Consensus & Execution Filter | [`examples/future_swarms/autogen_swarm_consensus.py`](examples/future_swarms/autogen_swarm_consensus.py) |
| **Semantic Kernel** | Native Kernel Filter Pipeline | [`docs/FRAMEWORK_GUIDE.md`](docs/FRAMEWORK_GUIDE.md) |
| **Agno / Phidata** | Agent Pre-Execution Hook | [`docs/FRAMEWORK_GUIDE.md`](docs/FRAMEWORK_GUIDE.md) |
| **Haystack** | Component-Level Tool Validator | [`docs/FRAMEWORK_GUIDE.md`](docs/FRAMEWORK_GUIDE.md) |

---

## Architectural Benchmarking & Performance

Traditional safety approaches rely on secondary language model calls (LLM-as-a-judge), which introduce substantial latency, high operational costs, and non-deterministic behavior. Bartholomew evaluates tool arguments at the compiler AST level in-process.

### Comparative Defense Evaluation

Evaluated against the **OWASP Top 10 for Agentic AI Applications** and standard adversarial evaluation benchmarks:

| Defense Architecture | Evaluation Latency | Compute / Memory Footprint | Determinism | Invariant Enforcement Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Bartholomew (`btp-guard`)** | **< 0.1 ms - < 1 ms** | **In-Process CPU (< 15 MB RAM)** | **100% Deterministic** | **Static AST & Lexical Invariant Engine** |
| Secondary LLM Judge | 800 ms - 2,500 ms | Cloud API or 16-80 GB VRAM | Probabilistic | Prompt Evaluation / Semantic Classifier |
| Regex Filter Rules | < 0.1 ms | In-Process (< 5 MB RAM) | Deterministic | Literal String Matching (No AST Context) |
| Container Sandboxing | 150 ms - 400 ms | OS-Level Virtualization | Deterministic | Syscall Gating (Post-Dispatch) |

### Key Architectural Differentiators

1. **Sub-Millisecond Execution Overhead**: Static AST parsing operates entirely in-process without network hops or secondary model inference latency.
2. **Zero GPU / VRAM Overhead**: Runs entirely on CPU worker threads, eliminating GPU resource contention with primary models.
3. **Deterministic Jailbreak Immunity**: A destructive payload such as `DROP TABLE` or `rm -rf` has identical AST structure regardless of how persuasively prompt text is framed.

---

## Model Context Protocol (MCP) Integration

Bartholomew provides drop-in security proxying for Model Context Protocol hosts:

```json
{
  "mcpServers": {
    "bartholomew": {
      "command": "python",
      "args": ["-m", "btp_guard.mcp_server"]
    }
  }
}
```

When client tools request operations through Bartholomew's MCP server, all arguments are audited and validated prior to forwarding to OS runtimes.

---

## CI/CD Pipeline Audit (GitHub Actions)

Incorporate agentic safety verification into your continuous integration workflow:

```yaml
name: Agent Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run Bartholomew Audit
        run: |
          pip install btp-guard
          btp-guard check --all
          btp-guard audit --summary
```

---

## Monorepo Architecture

Bartholomew is structured as a unified multi-language monorepo:

| Directory | Component | Runtime / Tooling | Target Distribution |
| :--- | :--- | :--- | :--- |
| `btp_guard/` | **Canonical Python In-Process Engine** | Python 3.10+ | PyPI (`btp-guard`) |
| `packages/npm_package/` | **Node.js / TypeScript SDK** | TypeScript, Node 18+ | npm (`btp-guard`) |
| `packages/mcp-proxy-guard/` | **MCP Security Gateway Proxy** | Node.js stdio / SSE | npm (`mcp-proxy-guard`) |
| `packages/vscode-extension/` | **IDE Guard Extension** | VS Code API | VS Code / Cursor / Open VSX |
| `packages/sdk_go/` | **Go In-Process Verifier & CLI** | Go 1.22+ (`cmd/`) | Go Modules (`pkg/btp`) |
| `packages/sdk_rust/` | **Rust High-Performance Crate** | Rust / Cargo | crates.io |
| `deploy/` | **Infrastructure & Containers** | Docker, Helm, Cloud Run | Datacenter & Kubernetes |
| `policies/` | **Declarative Security Presets** | YAML Invariants | SOC 2 / Multi-Agent Rules |
| `tests/` | **Deterministic Invariant Test Suite** | Pytest, Node Test | CI Automation |

---

## Auditable Telemetry & Control Log Exporter

Bartholomew provides automated control-mapping exporters to generate structured telemetry and evidence logs for independent CPA examination (mapping directly to AICPA SOC 2 CC6.1, CC6.6, CC7.1 and ISO/IEC 27001:2022 controls):

```bash
# Export structured control logs & cryptographic telemetry
python scripts/generate_soc2_compliance_evidence.py
```

Output: `audit_evidence/soc2_compliance_evidence_pack.json` containing SHA-256 Merkle tree hashes and RFC 8785 canonical JSON audit receipts ready for direct ingestion into your SIEM, GRC platform, or third-party CPA auditor review.

---

## Enterprise Edition & Support

| Feature | Community Edition (Apache-2.0) | Enterprise Edition |
| :--- | :--- | :--- |
| **Deterministic AST Invariant Gate** | Included | Included |
| **In-Flight Secret Redaction** | Included | Included |
| **Local Pre-Commit & MCP Gate** | Included | Included |
| **Centralized Policy Distribution** | Manual / Git-based | Centralized Management Portal |
| **Telemetry & SIEM Streaming** | Local JSON Export | Datadog, Splunk, OpenTelemetry Native Exporters |
| **Multi-Agent Identity & Passkeys** | Local File (`.btp/`) | Centralized KMS / HashiCorp Vault Integration |
| **Commercial SLA & Support** | Community | Dedicated 24/7 Enterprise SLA & Security Advisory |

For enterprise licensing, deployment assistance, and compliance audits:
- **Security Portal**: [https://bartholomew.info/enterprise](https://bartholomew.info/enterprise)
- **Contact**: `security@bartholomew.info`

---

## License

Bartholomew core libraries and CLI tools are open source and licensed under the [Apache License 2.0](LICENSE).  
Enterprise extensions, centralized telemetry collectors, and managed audit services are licensed under the Bartholomew Commercial License Agreement.
