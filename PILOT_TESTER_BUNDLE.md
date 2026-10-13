# BARTHOLOMEW KEYSTONE PILOT REVIEWER BUNDLE (v6.5.5-pilot.1)
## External Security Tester Quickstart, Threat Model & Verification Suite
**Release Date:** October 13, 2026  
**Repository:** [https://github.com/ivegotahunnitonit/bartholomew](https://github.com/ivegotahunnitonit/bartholomew)  
**Target Environment:** Local MCP stdio Database Tools (Node.js >= 22.5.0)

---

### 1. PILOT SCOPE & BOUNDARY RULES

This pilot evaluates **Bartholomew Keystone Shield (`mcp-shield`)** as an in-process and stdio interception gateway between autonomous AI agent clients (Claude Desktop, Cursor, Copilot) and untrusted/sensitive MCP child servers.

#### What is Covered (In-Scope):
- Gating of `tools/call` requests via HMAC-SHA256 capability passkeys.
- Single-use replay protection with atomic SQLite transactions (`.btp/consumed_nonces.db`).
- Sub-35µs in-process AST invariant detection for destructive root commands, DDL schema mutations, and host path traversals.
- Output tokenization of sensitive credentials (`sk_live_...`, API keys, DB connection strings) returning from MCP tools before reaching LLM contexts.
- Child process environment isolation (`BTP_KEYSTONE_SECRET` scrubbing).

#### What is NOT Covered (Out-of-Scope / Prohibited):
- **Not an OS Sandbox:** `mcp-shield` mediates stdio pipes. It does not provide kernel-level cgroups, seccomp, or network firewalling.
- **Sensitive Production Data:** The pilot must strictly use disposable local databases or non-sensitive staging mirrors.
- **Unrestricted Write Databases:** Testers must enforce database-native read-only controls (`PRAGMA query_only = ON;` or read-only PostgreSQL users) as defense-in-depth behind Vault AST gating.

---

### 2. QUICKSTART FOR REVIEWERS

#### 2.1 System Prerequisites
- **Node.js:** `>= 22.5.0` (required for built-in `node:sqlite` transaction engine).
- **Python:** `>= 3.10` (required for boundary test suites and pytest).
- **Git**

#### 2.2 Installation & Build
```bash
# Clone the repository
git clone https://github.com/ivegotahunnitonit/bartholomew.git
cd bartholomew

# Build the Vault & Keystone packages
cd packages/bartholomew-vault
npm run build
cd ../..
```

#### 2.3 Running an MCP Server Behind the Shield
Wrap any MCP server binary with `mcp-shield`:
```bash
# Set your trusted authority secret and workspace identity
export BTP_KEYSTONE_SECRET="your-32-byte-secure-random-signing-secret"
export BTP_WORKSPACE_ID="ws-pilot-sandbox"

# Run mcp-shield wrapping your target MCP server (e.g., SQLite MCP)
npx mcp-shield -- node /path/to/sqlite-mcp-server/index.js
```

---

### 3. THREAT MODEL & KNOWN DEFENSIVE LIMITS

Please take note of these documented boundaries when designing test cases:

1. **Regex Heuristic Limitations:**
   Vault uses compiled regular expressions to catch schema-altering DDL statements (`DROP TABLE`, `TRUNCATE TABLE`, `ALTER TABLE ... DROP`).
   - *Known Trade-Off (False Positive):* Strings containing literal `'DROP TABLE'` inside text values will be rejected fail-closed.
   - *Requirement:* Always configure database accounts as read-only at the engine level. Do not rely on regex alone to protect writable production data.
2. **Base64 Scanner Ceilings:**
   - *1MB ReDoS Ceiling:* Payloads $> 1\text{ MB}$ skip recursive Base64 scanning to preserve sub-millisecond execution guarantees.
   - *Fragmented Base64:* Base64 strings split across multiple lines by formatting whitespace are not defragmented.
3. **Replay Nonce Store Custody:**
   Single-use replay tokens are stored in `.btp/consumed_nonces.db`. While atomic across processes, an attacker with direct OS write access to the `.btp` folder can manipulate local files.

---

### 4. INDEPENDENT VERIFICATION & RED-TEAM TEST SUITE

Run the full adversarial test suite on your own machine to independently verify all claims:

```bash
# 1. Test Concurrent Cross-Process Replay Defense (Atomic SQLite WAL)
node tests/test_sqlite_concurrency_race.js

# 2. Test Packaged Launcher & Child Environment Isolation
node tests/test_phase3_launcher_deep_challenge.js

# 3. Test SQL Invariants against Real Disposable Database
python -m pytest tests/test_phase4_sql_invariant_deep.py -v

# 4. Test Vault Base64 Scanner Limits & Ceilings
node tests/test_phase5_vault_scanner_limits.js

# 5. Run Full Keystone & MCP Adversarial Regression Suite (14 Tests)
node tests/test_adversarial_keystone_mcp_regression.js

# 6. Run Micro-Latency Benchmarks (2,000 samples)
node tests/phase7_large_benchmark.js
```

---

### 5. HOW TO SUBMIT SECURITY FINDINGS

If you identify an invariant bypass, concurrency race condition, or secret leakage path:
1. Do not report via public GitHub issues.
2. Construct a minimal reproduction script using synthetic credentials and disposable databases.
3. Submit your report directly to the security maintainers with reproduction steps, observed child-process state, and proposed remediation.
