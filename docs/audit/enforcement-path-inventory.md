# Bartholomew BTP v6.5.6 — Enforcement Path Inventory

**Document Identifier**: `docs/audit/enforcement-path-inventory.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `729b6f2` / `a6ec74f`  
**Audit Mode**: Evidence Closure & Adversarial Challenge  
**Evaluation Date**: 2026-10-13  

---

## 1. Inventory Scope and Principles

Enforcement paths encompass all active code paths where an incoming action, tool call, command, or data stream is intercepted, evaluated against safety invariants, and permitted, denied, or held for authorization *before* reaching an underlying executor or downstream resource.

**Critical Audit Rule**: A security decision counts as successful only when the prohibited action is demonstrably prevented from executing at the actual boundary. Returning a JSON denial payload without preventing downstream execution is a failure.

---

## 2. Enforcement Path Inventory Table

| Enforcement ID | Entry Point | Protected Operation | Policy Mechanism | Denial Evidence | Failure Behavior | Bypass Exposure | Status |
|---|---|---|---|---|---|---|---|
| **E-01** | `packages/bartholomew-vault/bin/mcp-shield.js` (MCP Stdio Proxy) | Downstream MCP tool server execution | JSON-RPC tool interceptor, AST validator, Keystone passkey validator | `test_mcp_shield_in_process.js`: Denied tool calls return JSON-RPC error code `-32600` without proxying to child server. | Fail-closed: invalid JSON or unhandled exceptions return JSON-RPC error and abort forwarding. | Direct connection to downstream MCP server bypassing proxy stdio pipe. | **VERIFIED** |
| **E-02** | `enforceToolBoundary()` (`packages/npm_package/agent_core.js`) | Node.js agent tool execution | Synchronous AST regex inspection (`BTP-MCP-INV-001/002/003`) & policy options | `test_boundary_enforcement_harness.js`: Instrumented executor invocation count verified at 0 for denied actions. | Fail-closed on null/malformed inputs; returns `{ allowed: false, verdict: "DENY" }`. | Direct `child_process.exec` calls made outside the wrapper bypass the gate. | **VERIFIED** |
| **E-03** | `enforce_tool_boundary()` & `protect_agent()` (`src/agent_protector.py`) | Python agent tool execution (LangGraph, CrewAI, AutoGen) | Pre-execution AST validator, spend cap tracker, and wrapper interception | `test_agent_discovery_python.py`: Blocked commands return `[BLOCKED BY BARTHOLOMEW]` without OS invocation. | Fail-closed: invalid or missing tool names/inputs are rejected cleanly. | Direct `subprocess.Popen` calls made outside the agent tool loop bypass the wrapper. | **VERIFIED** |
| **E-04** | `KeystoneVerifier.verifyPasskey()` (`packages/bartholomew-vault/dist/keystone_verifier.js`) | Scoped tool execution & spending limits | HMAC-SHA256 signature verification, scope matching, single-use nonce consumption | `test_adversarial_keystone_mcp_regression.js`: Tampered signatures, expired tokens, and reused nonces rejected. | Fail-closed: invalid signature or replay throws or returns `valid: false`. | Callers that omit the passkey check entirely bypass authorization unless proxy enforces it. | **VERIFIED** |
| **E-05** | `VaultEngine.tokenize()` (`packages/bartholomew-vault/dist/vault_engine.js`) | LLM prompt ingress & tool responses | In-memory regex tokenization for API keys, DB URIs, credit cards, SSNs | `benchmark_complete_path.js`: Replaces live secrets with format-preserving surrogate tokens in <18µs. | Format-preserving fallback to typed surrogate token (`BTP_TKN_*`). | Secrets pre-existing in parent environment table (`process.env`) remain visible to child processes. | **VERIFIED** |
| **E-06** | Pre-commit Sentinel & Hook (`.btp/policy.yaml`, git hooks) | Git commit & staging boundary | High-entropy secret scanning & OWASP LLM02 regex gate | Verified during commit: Blocked commit of test artifacts containing live token patterns until resolved. | Fail-closed: commit aborted with exit code 1 when violations detected. | `git commit --no-verify` bypasses pre-commit hooks. Editor extension provides advisory highlights only. | **VERIFIED (Commit Gate)** / **ADVISORY (Editor)** |
| **E-07** | Base64 Normalization Gate (`agent_core.js` & `agent_protector.py`) | Obfuscated shell execution boundary | In-memory base64 unpacking for `echo '...' \| base64 -d` and Python `b64decode()` | Scenario 11 in `test_agent_discovery_and_enforcement.js`: Decodes `cm0gLXJmIC8=` to `rm -rf /` and blocks. | Unpack errors fail safe (payload left intact for standard AST regex evaluation). | Nested base64, variable concatenation (`$A$B`), and hex escapes (`\x72\x6d...`) are unhandled. | **PARTIALLY VERIFIED** |
| **E-08** | Uninstrumented Process Execution (Direct Subprocess Bypass) | Host OS shell and syscall execution | Outside BTP boundary (unprotected route) | Confirmed: BTP operates in-process or as an MCP proxy; it does not replace the OS kernel. | Unprotected by design unless deployed within an OS sandbox (e.g. Landlock, Docker, AppContainer). | Any uninstrumented `subprocess.run` or `child_process.spawn` call executed outside BTP wrappers. | **VERIFIED LIMITATION** |

---

## 3. Enforcement Boundary Analysis

1. **Mandatory vs. Caller-Controlled Enforcement**:
   - When deployed as an **MCP Proxy (`E-01`)**, enforcement is mandatory for all JSON-RPC requests flowing through the pipe.
   - When deployed via **SDK Wrappers (`E-02`, `E-03`)**, enforcement is mandatory for wrapped tools, but cannot prevent unwrapped code in the same process from directly calling OS primitives.

2. **Downstream Execution Interception**:
   - In both JavaScript (`E-02`) and Python (`E-03`), test harnesses verify that the downstream executor callback is NEVER invoked when a policy decision evaluates to `DENY` or `HOLD_FOR_APPROVAL`.
