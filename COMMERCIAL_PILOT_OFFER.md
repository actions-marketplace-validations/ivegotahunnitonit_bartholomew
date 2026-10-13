# Bartholomew AI Agent Execution Boundary: Commercial Offer & Assessment

## Executive Summary

Engineering teams deploying autonomous AI coding agents (Cursor, Windsurf, Claude Code, custom MCP tooling) face an operational bottleneck: **giving agents direct access to databases, terminal shells, and sensitive infrastructure introduces catastrophic execution risk.** Native agent controls rely on prompt instructions that fail under adversarial injection, tool chaining, or context hallucinations.

Bartholomew provides an **in-process execution boundary** (<35µs latency) that deterministically intercepts agent actions, blocks destructive schema mutations and shell commands, enforces single-use capability passkeys, and generates cryptographically signed audit evidence.

---

## 1. The Two Fixed-Scope Commercial Engagements

### Engagement A: AI Agent Security Boundary Assessment
**Fee:** $1,000 (Flat Fee)  
**Timeline:** 3 Business Days  
**Objective:** Identify unconstrained execution paths and verify native guardrails before production incident.

#### Deliverables:
1. **Agent Architecture & Threat Model Review**: Mapping trust boundaries across 1 active agent workflow (IDE, terminal, or MCP server).
2. **Adversarial Boundary Testing**: 50 targeted attack vectors executed against your agent tools (SQL schema drops, privilege escalation, credential replay, homoglyph evasions, prompt injection escapes).
3. **Findings & Evidence Report**: Prioritized vulnerabilities with reproducible proof-of-concept payloads.
4. **Remediation Specification**: Exact deterministic rules and passkey scopes required to close identified bypasses.

---

### Engagement B: Paid Implementation Pilot (In-Process MCP Boundary)
**Fee:** $3,500 (Flat Fee)  
**Timeline:** 14 Calendar Days  
**Scope:** Up to 15 developer seats / 2 agent workflows.  
**Objective:** Deploy and validate Bartholomew MCP Shield across sensitive local and staging tools.

#### Deliverables:
1. **Working BTP Integration**: In-process stdio proxy configured on high-risk tools (databases, deployment scripts, or internal APIs).
2. **Agreed Security Invariants**: Deterministic blocking of destructive commands (DROP TABLE, unconstrained DELETE, rm -rf, unauthorized egress).
3. **Atomic Replay Defense**: SQLite-backed single-use passkey invalidation eliminating token reuse.
4. **Performance Validation**: High-resolution latency profiling (<35µs AST evaluation, <250µs stdio roundtrip).
5. **Customer Acceptance Test Suite**: Self-contained script runnable by your team to independently verify all enforcement boundaries.
6. **Reproducible Results & Audit Dossier**: Signed RFC 8785 Merkle receipts suitable for SOC 2 / internal security review.

---

## 2. Explicit Acceptance Criteria (What You Receive)

Every paid pilot must pass four objective, customer-reproducible acceptance criteria:

| Scenario | Proposed Agent Action | Expected Verdict | Acceptance Standard |
| :--- | :--- | :--- | :--- |
| **1. Legitimate Query** | `SELECT id, name FROM users WHERE id = 10` | **PERMIT** | Passes transparently with zero developer friction (<250µs stdio). |
| **2. Schema Mutation** | `DROP TABLE users;` or `ALTER DATABASE` | **DENY** | Blocked fail-closed in <35µs. Backend database never receives payload. |
| **3. Passkey Replay** | Reusing an intercepted single-use passkey ID | **DENY** | Rejected by atomic replay cache. Double-spend prevented. |
| **4. Live Credential Injection** | Raw API key passed in tool arguments | **CONTAINED** | Tokenized into format-preserving surrogate before backend egress. |

---

## 3. Scope & Known Boundaries (What BTP Does Not Claim)

To maintain technical integrity, Bartholomew explicitly defines what is protected and what is out of scope:
- **Protected**: Tool invocations, database queries, and shell commands passing through the Bartholomew in-process proxy or AST gate.
- **Out of Scope**: Direct network calls or out-of-band processes executed outside the protected proxy boundary.
- **Semantic Leaks**: Vault tokenizes recognizable secrets and structured PII; semantic paraphrasing by models remains an active research direction and is not guaranteed as 100% prevented.

---

## 4. How to Verify in 10 Seconds (Reproducible Demo)

Your engineering team can independently verify the enforcement boundary right now:

```bash
# Clone the repository
git clone https://github.com/ivegotahunnitonit/bartholomew.git
cd bartholomew

# Run the self-contained live interception challenge
node examples/demo_mcp_shield_live.js
```

**Expected Result**: All 4 scenarios execute locally in <500ms, proving fail-closed blocking, replay invalidation, and credential tokenization without external cloud dependencies.

---

## 5. Contact & Booking

- **Organization**: Bartholomew Sovereign Trust Authority
- **Technical Lead**: Itsub Alemayehu
- **Email**: help@bartholomew.info
- **Direct Engagement Booking**: https://bartholomew.info/audit
