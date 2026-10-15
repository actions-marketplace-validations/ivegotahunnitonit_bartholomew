# Bartholomew: Enterprise Pilot Proposal & CISO Hand-Off Memo

**Date**: October 13, 2026  
**Document Classification**: Commercial Confidential / Pilot Evaluator Brief  
**Protocol Version**: Bartholomew Trust Protocol (BTP v6.5.5)  
**Distribution Channel**: [Bartholomew Namespace on Open VSX](https://open-vsx.org/namespace/Bartholomew) | [Bartholomew Portal](https://bartholomew.info)  

---

## 1. Executive Summary: The AI Agent Compliance Impasse

Enterprises, FinTechs, and Healthcare organizations face an urgent security and compliance blocker:
- **Engineering Demand**: Developers are adopting autonomous coding assistants (Cursor, Claude Code, Windsurf, Copilot, Cline) to accelerate development.
- **CISO & Compliance Veto**: Security officers, risk councils, and compliance teams are blocking or restricting adoption due to three unmitigated failure modes:
  1. **Direct Data Egress (SOC 2 CC6.7 / HIPAA § 164.312)**: Developers inadvertently piping customer PII, HIPAA PHI, or production API keys into cloud LLM context windows.
  2. **Indirect Prompt Injection & Tool Poisoning (OWASP LLM01 / LLM02)**: Malicious open-source dependencies or adversarial prompts instructing agents to invoke database or terminal tools with catastrophic arguments (`DROP TABLE`, `rm -rf`, reverse shells).
  3. **Non-Human Identity (NHI) Credential Sprawl**: Autonomous agents operating with unconstrained host credentials and zero cryptographic clearance boundaries.

**Bartholomew resolves this impasse** without slowing down developers or requiring cloud proxy microservices.

---

## 2. Technical Architecture & Defense Model

Bartholomew operates entirely in-process on the developer's workstation or build runner, providing sub-35-microsecond deterministic protection at three critical boundaries:

```
+-----------------------------------------------------------------------------------------------+
|                                    BARTHOLOMEW TRINITY (v6.5.5)                               |
+------------------------------+--------------------------------+-------------------------------+
| 1. CONTEXT INGRESS           | 2. IDENTITY & CLEARANCE        | 3. EXECUTION EGRESS           |
| Bartholomew Vault            | Bartholomew Keystone           | Bartholomew Guard             |
| In-Process PII, Secret,      | Ephemeral HMAC-SHA256          | Sub-35us Polyglot AST         |
| & MCP Tool Interceptor       | Capability Passkeys & Spend Cap| Execution Firewall            |
+------------------------------+--------------------------------+-------------------------------+
```

### Deterministic In-Process Invariants vs. Cloud LLM Moderation

| Feature | Bartholomew (BTP v6.5.5) | Cloud LLM Moderation Proxies | Prompt Guardrails (NeMo, etc.) |
| :--- | :--- | :--- | :--- |
| **Enforcement Layer** | Local RAM / Stdio JSON-RPC / Kernel Pipe | Cloud HTTP Reverse Proxy | Cloud Prompt Wrappers |
| **Interception Latency** | **< 35 Microseconds** | 250 ms – 1,500 ms | 150 ms – 800 ms |
| **Jailbreak Resistance** | **Mathematical AST Invariant** (deterministic) | Probabilistic (easily bypassed) | Probabilistic (prompt manipulation) |
| **Model Agnostic** | 100% Agnostic (Claude, GPT-4o, DeepSeek, Local) | Coupled to cloud provider API | Coupled to prompt framework |
| **Offline / Air-Gapped** | Fully operational offline | Fails when disconnected | Fails when disconnected |
| **Compliance Proof** | Cryptographic SHA-256 Merkle Dossier | Cloud text logs | Text logs |

---

## 3. The 30-Day "Air-Gapped Agent Compliance Pilot"

We propose a structured, 30-day enterprise validation pilot designed to give CISOs mathematical certainty of zero plaintext egress and zero unauthorized tool execution across a defined developer cohort.

### Cohort Specification
- **Seats**: Up to 25 developer workstations (macOS, Windows, Linux).
- **Supported IDEs**: Cursor, Claude Code, Windsurf, VS Code.
- **Infrastructure Impact**: Zero cloud dependencies; zero network routing changes.
- **Pilot Setup Time**: Under 15 minutes per developer seat (`npx mcp-shield doctor --fix`).

### Pilot Deliverables & Milestones

| Week | Milestone | Deliverable |
| :--- | :--- | :--- |
| **Week 1** | **Baseline Assessment & Automated Shielding** | Run `npx mcp-shield doctor` across cohort. Audit all active MCP servers (Postgres, SQLite, GitHub, Filesystem). Automatically inject in-process protection. |
| **Week 2** | **Zero-Egress Data & PII Tokenization** | Activate Bartholomew Vault format-preserving surrogates. Verify that production API keys and customer records are replaced in RAM before LLM dispatch. |
| **Week 3** | **Capability Scoping & Nonce Replay Enforcement** | Deploy ephemeral Keystone passkeys with $25/day spending caps and single-use atomic SQLite replay verification (`.btp/consumed_nonces.db`). |
| **Week 4** | **Executive Audit Dossier & CISO Sign-Off** | Generate automated sovereign cryptographic compliance dossiers (`npx mcp-shield export-compliance`) signed with SHA-256 Merkle roots and direct auditor clearance. |

---

## 4. Verification & SLAs

Under the pilot agreement, Bartholomew guarantees the following empirical invariants:

1. **Zero Credential Egress Guarantee**: No raw API key matching known patterns (Stripe, AWS, GitHub, OpenAI, PostgreSQL) will leave the developer workstation in plaintext LLM prompts.
2. **Sub-35µs Latency SLA**: In-process AST invariant inspection will not introduce more than 35 microseconds of computational latency to tool dispatches.
3. **Fail-Closed Execution**: If an MCP tool payload contains a forbidden structural mutation (such as destructive SQL schema modification) or an invalid capability passkey, the proxy immediately terminates execution and returns JSON-RPC `-32000` / `-32001`.
4. **Tamper-Evident Receipts**: Every intercepted and permitted action is cryptographically signed and hash-chained in the host audit ledger.

---

## 5. Instant Reproduction for Security Reviewers

Enterprise security teams can verify all claims in under 10 seconds on any workstation without root permissions or external internet access:

```bash
# 1. Clone verified pilot baseline
git clone https://github.com/ivegotahunnitonit/bartholomew.git
cd bartholomew

# 2. Run the 10-Second Live Interception Challenge
node examples/demo_mcp_shield_live.js

# 3. Diagnose local workstation MCP posture
node packages/bartholomew-vault/bin/mcp-shield.js doctor

# 4. Generate a cryptographic compliance dossier
node packages/bartholomew-vault/bin/mcp-shield.js export-compliance
```

---

## 6. Pilot Commercial Terms & Contact

- **Pilot Investment**: $3,500 fixed setup (includes dedicated deployment engineering, custom regex token rules, and CISO compliance audit sign-off).
- **Post-Pilot Options**: Annual enterprise license ($45/seat/month) or full open-core self-managed deployment.
- **Point of Contact**:  
  - Website: [https://bartholomew.info/](https://bartholomew.info/)  
  - Email: `contact@bartholomew.info`  
  - Repository: [https://github.com/ivegotahunnitonit/bartholomew](https://github.com/ivegotahunnitonit/bartholomew)
