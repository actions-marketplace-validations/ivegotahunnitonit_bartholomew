# BTP v6.5.6 Baseline Audit and System Verification

**Document Identifier**: `docs/audit/btp-baseline.md`  
**Protocol Specification**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Evaluation Date**: 2026-10-13  
**Auditor Mode**: In-Process AST Execution Boundary and Discovery Audit  

---

## 1. Verified Tool and Environment Baseline

Execution baseline verified on host system prior to changes:

| Tool / Runtime | Proposed Minimum | Detected Version | Requirement Source | Verification Result |
|---|---|---|---|---|
| Node.js | 20.19.0 | v24.18.0 | `package.json` engines | VERIFIED |
| npm | 10.8.2 | 11.16.0 | Node ecosystem | VERIFIED |
| Python | 3.11.0 | 3.14.6 | `pyproject.toml` | VERIFIED |
| pip | 23.2.1 | 26.1.2 | Python environment | VERIFIED |
| Git | 2.40.0 | 2.55.0.windows.3 | Version control | VERIFIED |
| curl | 8.0.0 | 8.21.0 | Network & manifests | VERIFIED |
| OpenSSL CLI | 3.0.0 | Built-in node:crypto / hashlib | Cryptographic engines | VERIFIED (in-process) |

---

## 2. Package and Release Version Alignment Matrix

Audit of active packages, registry releases, and public manifests:

| Component / File | Prior Declared Version | Synchronized Version | Status |
|---|---|---|---|
| `packages/npm_package/package.json` | 6.5.6 | 6.5.6 | Published on npm (`btp-guard@6.5.6`) |
| `packages/vscode-extension/package.json` | 6.5.5 | 6.5.5 | Published on Open VSX (15,401 downloads) |
| `packages/bartholomew-vault/package.json` | 6.5.6 | 6.5.6 | Published on npm (`bartholomew-vault@6.5.6`) |
| `site/.well-known/agent-manifest.json` | 6.4.4 (outdated) | 6.5.6 | SYNCHRONIZED |
| `site/agent-manifest.json` | 6.4.4 (outdated) | 6.5.6 | SYNCHRONIZED |
| `site/.well-known/mcp.json` | 6.5.5 (outdated) | 6.5.6 | SYNCHRONIZED |
| `site/llms.txt` | 6.4.7 (outdated) | 6.5.6 | SYNCHRONIZED |
| `site/llms-full.txt` | 6.4.4 (outdated) | 6.5.6 | SYNCHRONIZED |
| `site/mcp-catalog.json` | 6.4.4 (outdated) | 6.5.6 | SYNCHRONIZED |
| `site/tools.json` | 6.4.4 (outdated) | 6.5.6 | SYNCHRONIZED |

---

## 3. Implementation Status and Reproducible Test Evidence

### A. Implemented and Verified Functionality

1. **Deterministic Execution Barrier**:
   - In-process AST inspection and pattern validation for shell, SQL, and filesystem tools.
   - Microsecond latency budget: 80µs to 210µs steady-state on Node.js; 15µs to 180µs steady-state on Python.
   - Non-fatal self-healing envelopes (`safe_alternative` and `remediation_hint`) preserving agent execution context without process abortion.

2. **Agent-to-Agent Capability Discovery**:
   - `BTP_CAPABILITY_MANIFEST` machine-readable schema.
   - `auditToolBoundary()` (`audit_tool_boundary()` in Python): automatically flags unshielded bash, database, file, and network tools with categorized threat models.
   - `enforceToolBoundary()` (`enforce_tool_boundary()` in Python): handles `ALLOW`, `DENY`, and `HOLD_FOR_APPROVAL` decisions with Ed25519 merkle receipts.

3. **Obfuscation Defense**:
   - Interception and automatic pre-decoding of base64-piped commands (`echo '...' | base64 -d | sh`) preventing evasion of AST safety gates.

4. **Cryptographic Attestations**:
   - RFC 8785 Canonical JSON hashing.
   - Ed25519 signature generation and Merkle turn receipts.

### B. Reproducible Test Results

- `node tests/test_agent_discovery_and_enforcement.js`:
  - 11 / 11 scenarios passed (100.00%).
- `python -m pytest tests/test_agent_discovery_python.py`:
  - 10 / 10 scenarios passed (100.00%).
- `node tests/test_mcp_shield_in_process.js`:
  - 6 / 6 passed (100.00%).
- `node packages/bartholomew-keystone/test_keystone.js`:
  - 10 / 10 passed (100.00%).
- `node tests/test_adversarial_keystone_mcp_regression.js`:
  - 14 / 14 passed (100.00%).

---

## 4. Known Security Seams and Architectural Boundaries

1. **Direct Subprocess Bypass**:
   - Uninstrumented child processes launched directly via OS primitives (e.g., bare `child_process.spawn` or `subprocess.Popen`) bypass MCP proxy layers unless wrapped by SDK middleware (`protect_agent()`) or OS sandbox boundaries (Landlock / Seccomp / AppContainer).

2. **Environment Secret Inheritance**:
   - Subprocesses inherit environment variables (`process.env`) unless explicitly scrubbed by the execution runner.

3. **Local Audit Log Immutability**:
   - Local `.btp/audit.log` and SQLite stores reside on writable host storage. True immutability requires external Merkle root anchoring or append-only ledger streaming.
