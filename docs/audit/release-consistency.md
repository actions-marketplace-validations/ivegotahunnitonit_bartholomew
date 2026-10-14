# Bartholomew BTP v6.5.6 — Release & Artifact Reconciliation Report

**Document Identifier**: `docs/audit/release-consistency.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `5467fb65`  
**Evaluation Date**: 2026-10-14  

---

## 1. Reconciliation Inventory

| Artifact / Registry Target | Expected Identifier / Version | Observed State | Classification | Evidence & Details |
|---|---|---|---|---|
| **Git Repository HEAD** | `5467fb65` | `5467fb65b26045f2f323da433df414ae125566a7` | **LOCAL_VERIFIED** | Clean working tree; tracks `origin/main` |
| **npm Package** | `btp-guard@6.5.6` | `btp-guard@6.5.6` | **EXTERNALLY_VERIFIED** | Published on npm registry; version 6.5.6 |
| **VS Code Extension (VSIX)** | `bartholomew-guard-vscode-6.5.6.vsix` | File present (1,402,123 bytes) | **LOCAL_VERIFIED** | Compiled package with publisher `itsubsolomon` |
| **Vault Extension (VSIX)** | `bartholomew-vault-6.5.6.vsix` | File present (1,980,105 bytes) | **LOCAL_VERIFIED** | Compiled package with publisher `itsubsolomon` |
| **Open VSX Extension (Guard)** | `itsubsolomon/bartholomew-guard-vscode@6.5.6` | Published v6.5.6 | **EXTERNALLY_VERIFIED** | Verified active on open-vsx.org |
| **Open VSX Extension (Vault)** | `itsubsolomon/bartholomew-vault@6.5.6` | VSIX ready; pending token | **LOCAL_VERIFIED** | Package built; awaiting user publish token |
| **Hugging Face Dataset Commit** | `cad39281ed9746dee40e5451239d784a8d32726b` | HF Git Commit SHA-1 | **EXTERNALLY_VERIFIED** | Verified commit hash of the HF repository |
| **Dataset Shard File SHA-256** | `cad39281ed...` (previously reported as SHA-256) | `bd1c998ae513d4b4a24bf497237da401b0bc994a5e4e1ff1c5d2e1f6f28b893f` | **MISMATCH** | Historical report confused Git commit hash with data file SHA-256 |
| **Web Landing Page** | `https://bartholomew.info` | Reachable | **EXTERNALLY_VERIFIED** | Active public endpoint |

---

## 2. Discrepancy Analysis

### A. The Hugging Face Hash Discrepancy
- **Claimed**: Previous audit reports listed `cad39281ed9746dee40e5451239d784a8d32726b` as the SHA-256 hash of the dataset shard.
- **Verification**: `cad39281ed9746dee40e5451239d784a8d32726b` is exactly 40 hexadecimal characters, which corresponds to a Git SHA-1 commit hash on Hugging Face, not a 64-character SHA-256 hash.
- **Deterministic Calculation**: The actual SHA-256 of the 500-vector sequential sample retrieved from `data/train-00000-of-00003.jsonl` is `bd1c998ae513d4b4a24bf497237da401b0bc994a5e4e1ff1c5d2e1f6f28b893f`.
- **Classification**: `MISMATCH` on hashing convention documentation; `EXTERNALLY_VERIFIED` on repository data identity.

### B. Extension Publisher Alignment
- **Historical Defect**: Prior commits referenced publisher ID `bartholomew` in the extension manifest, whereas the Open VSX registered namespace is `itsubsolomon`.
- **Current State**: Reconciled and fixed in commits `54b9981` and `a6ec74f`. Both local manifests and VSIX packages reflect `itsubsolomon`.
