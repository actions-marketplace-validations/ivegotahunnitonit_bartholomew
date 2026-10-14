# Bartholomew Red-Team Dataset Evaluation Report

**Document Identifier**: `docs/audit/red-team-results.md`  
**Dataset**: `acnbartholomew/btp-agent-redteam-evals`  
**Dataset URL**: [https://huggingface.co/datasets/acnbartholomew/btp-agent-redteam-evals](https://huggingface.co/datasets/acnbartholomew/btp-agent-redteam-evals)  
**Dataset Revision (SHA)**: `cad39281ed9746dee40e5451239d784a8d32726b`  
**Total Vectors in Dataset**: 105,000  
**Evaluator Command**: `node tests/eval_redteam_dataset.js`  
**Evaluation Environment**: Node.js v24.18.0, Windows x64  
**Date**: 2026-10-13  

---

## 1. Evaluation Methodology

The Hugging Face dataset provides 105,000 ground-truth labeled evaluation samples of agent tool executions across shell commands, SQL statements, secrets, and network requests.

Evaluation was performed against a sequential live slice of 500 vectors drawn directly from the remote repository shard `data/train-00000-of-00003.jsonl`. Each payload was fed into the in-process AST gate (`evaluateAndRemediate`) without pre-training or prior calibration on this dataset.

---

## 2. Confusion Matrix & Key Metrics

| Metric | Measured Value | Analysis |
|---|---|---|
| **Total Samples Evaluated** | 500 | Live dataset slice |
| **True Positives (TP)** | 112 | Malicious attacks successfully blocked |
| **False Positives (FP)** | 0 | Benign operations incorrectly blocked |
| **True Negatives (TN)** | 167 | Benign operations successfully permitted |
| **False Negatives (FN)** | 221 | Attacks not blocked by standalone AST rules |
| **Precision** | **100.00%** | Zero false alarms on benign commands |
| **Recall** | **33.63%** | Selective coverage by standalone in-process rules |
| **F1 Score** | **0.5034** | Harmonic mean of precision and recall |

---

## 3. Results by Threat Category

| Threat Category | Total Tested | Blocked (TP) | Allowed (FN / TN) | Category Precision |
|---|---|---|---|---|
| `benign_shell` | 105 | 0 | 105 (TN) | 100.0% (Zero FP) |
| `benign_sql` | 34 | 0 | 34 (TN) | 100.0% (Zero FP) |
| `benign_network` | 28 | 0 | 28 (TN) | 100.0% (Zero FP) |
| `sql_ddl_wipe` | 21 | 21 | 0 | 100.0% |
| `sql_truncate` | 22 | 22 | 0 | 100.0% |
| `ast_injection` | 66 | 52 | 14 | 78.8% |
| `shell_obfuscated` | 15 | 7 | 8 | 46.7% |
| `shell_destructive` | 44 | 10 | 34 | 22.7% |
| `secret_leak` | 78 | 0 | 78 | 0.0% (Requires Vault Scrubber) |
| `reverse_shell` | 25 | 0 | 25 | 0.0% (Requires Network Gate) |
| `disk_wipe` | 19 | 0 | 19 | 0.0% |
| `ssrf_metadata` | 10 | 0 | 10 | 0.0% (Requires Network Gate) |
| `sql_unbounded_update` | 18 | 0 | 18 | 0.0% |
| `sql_unbounded_delete` | 15 | 0 | 15 | 0.0% |

---

## 4. Latency Distribution Under Evaluation Load

- **Median (p50)**: `8.2 µs`
- **95th Percentile (p95)**: `28.8 µs`
- **99th Percentile (p99)**: `108.2 µs`

The steady-state in-process evaluation latency complies with the stated target (<35µs median, <250µs SLA).

---

## 5. False Negative Analysis & Architectural Boundaries

1. **Secret Leaks (`secret_leak`)**:
   - The standalone AST parser checks command syntax, whereas secret scrubbing is handled by the regex/entropy vault in `VaultEngine.scrubSecrets()`. In an isolated tool evaluator where the vault scrubber is disabled, secret strings pass through.
2. **Reverse Shells & SSRF (`reverse_shell`, `ssrf_metadata`)**:
   - Commands using non-standard IP notations or esoteric socket syntaxes require integration with `BTP Network Egress Sentinel` rather than purely syntactic shell regexes.
3. **Distinction from Self-Authored Tests**:
   - The 105,000 vector Hugging Face dataset was authored independently by red-team contributors and contains attack variations not present in local test fixtures.
