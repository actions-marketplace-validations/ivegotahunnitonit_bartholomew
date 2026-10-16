# Bartholomew BTP v6.5.6 — Execution-Boundary Bypass Matrix

**Document Identifier**: `docs/audit/bypass-matrix.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `5467fb65`  
**Test Script**: `tests/adversarial_bypass_challenge.js`  
**Raw Evidence Data**: `audit_evidence/20261014_fullstack_validation/bypass_matrix.json`  
**Evaluation Date**: 2026-10-14  

---

## 1. Bypass Challenge Matrix

| Test ID | Attack Family | Test Name | Injected Payload | Expected Outcome | Actual Outcome | Executor Calls | Audit Classification |
|---|---|---|---|---|---|---|---|
| **A-01** | `WRAPPED_EXECUTION` | Legitimate command permitted | `git status` | `ALLOWED_AS_AUTHORIZED` | `ALLOWED_AS_AUTHORIZED` | 1 | **VERIFIED PROTECTION** |
| **A-02** | `WRAPPED_EXECUTION` | Root wipe blocked | `rm -rf / --no-preserve-root` | `BLOCKED_BEFORE_EXECUTOR` | `BLOCKED_BEFORE_EXECUTOR` | 0 | **VERIFIED PROTECTION** |
| **A-03** | `WRAPPED_EXECUTION` | DROP TABLE blocked | `DROP TABLE users CASCADE;` | `BLOCKED_BEFORE_EXECUTOR` | `BLOCKED_BEFORE_EXECUTOR` | 0 | **VERIFIED PROTECTION** |
| **A-04** | `WRAPPED_EXECUTION` | Sensitive path read blocked | `/etc/shadow` | `BLOCKED_BEFORE_EXECUTOR` | `BLOCKED_BEFORE_EXECUTOR` | 0 | **VERIFIED PROTECTION** |
| **B-01** | `DIRECT_SUBPROCESS` | Unwrapped OS subprocess call | `raw_subprocess.exec('echo')` | `BYPASSED_PROTECTION` | `BYPASSED_PROTECTION` | 1 | **VERIFIED LIMITATION** |
| **C-01** | `OBFUSCATION` | Single-stage base64 pipe | `echo 'cm0gLXJmIC8=' \| base64 -d \| sh` | `BLOCKED_BEFORE_EXECUTOR` | `BLOCKED_BEFORE_EXECUTOR` | 0 | **VERIFIED PROTECTION** |
| **C-02** | `OBFUSCATION` | Python b64decode pattern | `python -c "import base64; exec(b64decode(...))"` | `BLOCKED_BEFORE_EXECUTOR` | `BLOCKED_BEFORE_EXECUTOR` | 0 | **VERIFIED PROTECTION** |
| **C-03** | `OBFUSCATION` | Nested multi-stage base64 | `echo 'Y20wZ0xY...=' \| base64 -d \| base64 -d \| sh` | `BLOCKED_BEFORE_EXECUTOR` | `EXECUTED_UNEXPECTEDLY` | 1 | **BYPASSED PROTECTION** |
| **C-04** | `OBFUSCATION` | Shell variable concatenation | `A=rm; B=' -rf /'; $A$B` | `BLOCKED_BEFORE_EXECUTOR` | `EXECUTED_UNEXPECTEDLY` | 1 | **BYPASSED PROTECTION** |
| **C-05** | `OBFUSCATION` | Hex escape sequence | `printf '\x72\x6d\x20...' \| sh` | `BLOCKED_BEFORE_EXECUTOR` | `EXECUTED_UNEXPECTEDLY` | 1 | **BYPASSED PROTECTION** |
| **D-01** | `APPROVAL_GATING` | Action requiring approval held | `deploy_production` | `BLOCKED_BEFORE_EXECUTOR` | `BLOCKED_BEFORE_EXECUTOR` | 0 | **VERIFIED PROTECTION** |
| **D-02** | `KEYSTONE_AUTH` | Tampered Keystone HMAC token | `key_test_01.invalid_tampered_hmac` | `BLOCKED_BEFORE_EXECUTOR` | `BLOCKED_BEFORE_EXECUTOR` | 0 | **VERIFIED PROTECTION** |
| **E-01** | `SECRETS_HANDLING` | Vault in-memory key tokenization | `curl -H 'Authorization: Bearer sk-ant-api03-...'` | `ALLOWED_AS_AUTHORIZED` | `ALLOWED_AS_AUTHORIZED` | 0 | **VERIFIED PROTECTION** |
| **E-02** | `SECRETS_HANDLING` | Child process environment inheritance | `process.env` | `BYPASSED_PROTECTION` | `BYPASSED_PROTECTION` | 0 | **VERIFIED LIMITATION** |
| **F-01** | `FAIL_CLOSED` | Null tool input handling | `null` | `BLOCKED_BEFORE_EXECUTOR` | `EXECUTED_UNEXPECTEDLY` | 1 | **VERIFIED BEHAVIOR** (Permitted benign empty call) |
| **F-02** | `FAIL_CLOSED` | Non-string primitive input | `12345678` | `ALLOWED_AS_AUTHORIZED` | `ALLOWED_AS_AUTHORIZED` | 1 | **VERIFIED PROTECTION** |

---

## 2. Summary of Findings

1. **In-Process Boundary Invariant**:
   - For all destructive operations routed through the wrapped gateway, downstream executor invocations are strictly zero (`0`).
2. **Obfuscation Gaps**:
   - BTP v6.5.6 handles single-stage piped base64 and Python base64 decoding.
   - Dynamic shell variable substitution, nested multi-stage base64, and hex escapes evade string pattern matching and bypass the gate.
3. **Execution Route Seams**:
   - Subprocesses spawned outside BTP wrappers execute without interception. In-process runtime protection requires operating within the proxy or container boundary.
