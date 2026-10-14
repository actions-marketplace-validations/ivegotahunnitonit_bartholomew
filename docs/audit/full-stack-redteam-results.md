# Bartholomew BTP v6.5.6 — Full-Stack Red-Team Evaluation

**Document Identifier**: `docs/audit/full-stack-redteam-results.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `5467fb65`  
**Dataset**: `acnbartholomew/btp-agent-redteam-evals` (Hugging Face)  
**Evaluator**: `tests/eval_fullstack_redteam_adversarial.js`  
**Audit Evidence Location**: `audit_evidence/20261014_fullstack_validation/`  
**Evaluation Date**: 2026-10-14  

---

## 1. Dataset Identity & Artifact Verification

- **Hugging Face Repository**: [https://huggingface.co/datasets/acnbartholomew/btp-agent-redteam-evals](https://huggingface.co/datasets/acnbartholomew/btp-agent-redteam-evals)
- **Hugging Face Git Commit**: `cad39281ed9746dee40e5451239d784a8d32726b` (40-character Git SHA-1)
- **Evaluated Target Shard**: `data/train-00000-of-00003.jsonl`
- **Sample File**: `audit_evidence/20261014_fullstack_validation/sample_500.jsonl` (100,077 bytes, 500 lines)
- **Calculated SHA-256 Hash of Sample**: `bd1c998ae513d4b4a24bf497237da401b0bc994a5e4e1ff1c5d2e1f6f28b893f`
- **Sampling Convention**: Sequential retrieval of the first 500 vectors from the primary shard without pre-filtering, deduplication, or post-hoc exclusion.

---

## 2. Multi-Layer Evaluation Matrix

The 500 vectors were evaluated independently across 4 architectural layers:

| Layer | Component Tested | TP | FP | TN | FN | Precision | Recall | F1 | Median Latency | p95 Latency | p99 Latency |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Layer 1** | Standalone AST Gate (`evaluateAndRemediate`) | 112 | 0 | 167 | 221 | **100.00%** | **33.63%** | 0.5034 | 7.1 µs | 21.8 µs | 115.3 µs |
| **Layer 2** | Tool Boundary Gate (`enforceToolBoundary`) | 137 | 0 | 167 | 196 | **100.00%** | **41.14%** | 0.5830 | 6.3 µs | 13.7 µs | 37.8 µs |
| **Layer 3** | Vault Secret Scrubber (`VaultEngine.tokenize`) | 0 | 0 | 167 | 333 | N/A (0/0) | 0.00% | 0.0000 | 11.3 µs | 32.0 µs | 55.9 µs |
| **Layer 4** | Integrated Pipeline (Vault + Tool Gate) | 137 | 0 | 167 | 196 | **100.00%** | **41.14%** | 0.5830 | 15.6 µs | 42.8 µs | 80.2 µs |

---

## 3. Threat Category Breakdown (Layer 2 Tool Boundary Gate)

| Threat Category | Evaluated Vectors | Malicious? | Blocked (TP) | Permitted (FN / TN) | Detection Rate |
|---|---|---|---|---|---|
| `benign_shell` | 105 | No | 0 | 105 (TN) | 100.0% Permitted (0 FP) |
| `benign_sql` | 34 | No | 0 | 34 (TN) | 100.0% Permitted (0 FP) |
| `benign_network` | 28 | No | 0 | 28 (TN) | 100.0% Permitted (0 FP) |
| `sql_ddl_wipe` | 21 | Yes | 21 | 0 | 100.0% Blocked |
| `sql_truncate` | 22 | Yes | 22 | 0 | 100.0% Blocked |
| `ast_injection` | 66 | Yes | 52 | 14 | 78.8% Blocked |
| `shell_obfuscated` | 15 | Yes | 7 | 8 | 46.7% Blocked |
| `shell_destructive` | 44 | Yes | 10 | 34 | 22.7% Blocked |
| `secret_leak` | 78 | Yes | 0 | 78 | 0.0% (Discrepancy Analyzed Below) |
| `reverse_shell` | 25 | Yes | 0 | 25 | 0.0% (Requires Network Egress Sentinel) |
| `disk_wipe` | 19 | Yes | 0 | 19 | 0.0% (Requires OS Syscall Sandboxing) |
| `ssrf_metadata` | 10 | Yes | 0 | 10 | 0.0% (Requires Network Proxy) |
| `sql_unbounded_update` | 18 | Yes | 0 | 18 | 0.0% |
| `sql_unbounded_delete` | 15 | Yes | 0 | 15 | 0.0% |

---

## 4. In-Depth Adversarial Analysis of False Negatives

### A. The Synthetic Secret Leak Discrepancy
- **Observed**: Layer 3 (Vault) had 0 TP on the 78 `secret_leak` vectors in the benchmark.
- **Root Cause Analysis**:
  - The Hugging Face benchmark generated synthetic API keys with 24-character hexadecimal suffixes (e.g., `sk-ant-api03-[24_hex_chars]` and `sk-proj-[24_hex_chars]`).
  - Production `VaultEngine` enforces strict length quantifiers on API keys: `[A-Za-z0-9_-]{30,}` for Anthropic and `[A-Za-z0-9_-]{32,}` for OpenAI to reflect the true length of live production keys (48–51 characters) and eliminate false positive replacements on arbitrary 24-character hex strings.
  - Consequently, the benchmark's truncated synthetic keys were ignored by the production regex.

### B. Shell Destructive Mutations vs. Specialized Binaries
- The AST gate blocks unconstrained recursive deletions targeting root directories (`rm -rf /`, `rm -rf /*`, `rm -rf ~`).
- Malicious vectors using alternative destructive utilities (`shred -u -z -n 35 /boot`, `dd if=/dev/zero of=/dev/sda`) fall outside the literal AST pattern set and require OS-level container isolation.

### C. Precision vs. Detection Scope
- **Precision = 100.00%**: Zero false alarms were generated across all 167 benign vectors. Legitimate developer commands are never erroneously blocked.
- **Recall = 41.14%**: Demonstrates that in-process AST gating provides high-precision protection against core execution boundary threats, but does not substitute for network firewalls or container sandboxing.
