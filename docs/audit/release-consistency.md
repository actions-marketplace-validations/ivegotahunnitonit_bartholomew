# Bartholomew BTP v6.5.6 — Release & Artifact Reconciliation Report

**Document Identifier**: `docs/audit/release-consistency.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `5467fb65`  
**Evaluation Date**: 2026-10-14  

---

## 1. Reconciliation Inventory

| Artifact / Registry Target | Expected Identifier / Version | Observed State | Classification | Evidence & Details |
|---|---|---|---|---|
| **Git Repository HEAD** | Current main | Working tree clean | **LOCAL_VERIFIED** | Tracks `origin/main` |
| **npm Package** | `btp-guard@6.5.6` | `btp-guard@6.5.6` | **EXTERNALLY_VERIFIED** | Published on npm registry; version 6.5.6 |
| **VS Code Extension (Guard)** | `bartholomew-guard-vscode-6.5.6` | Manifest v6.5.6 | **LOCAL_VERIFIED** | Aligned with verified Open VSX publisher `bartholomew` |
| **VS Code Extension (Vault)** | `bartholomew-vault-6.5.6` | Manifest v6.5.6 | **LOCAL_VERIFIED** | Aligned with verified Open VSX publisher `bartholomew` |
| **Open VSX Extension (Guard)** | `Bartholomew/bartholomew-guard-vscode` | Published v6.5.5 | **EXTERNALLY_VERIFIED** | Verified active on open-vsx.org under namespace `Bartholomew` |
| **Open VSX Extension (Vault)** | `Bartholomew/bartholomew-vault` | Published v6.5.5 | **EXTERNALLY_VERIFIED** | Verified active on open-vsx.org under namespace `Bartholomew` |
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
- **Historical Defect**: Prior commits mistakenly changed the publisher ID to `itsubsolomon` in `packages/vscode-extension/package.json` and `packages/bartholomew-vault/package.json`.
- **Live Registry Truth**: Live inspection of the Open VSX registry API confirms that `https://open-vsx.org/api/itsubsolomon` returns 404, while the verified publisher namespace is `Bartholomew` (`publisher: "bartholomew"`), which actively hosts `Bartholomew/bartholomew-guard-vscode` and `Bartholomew/bartholomew-vault`. (Note: `itsubsolomon` is the publisher namespace for the Azure DevOps extension, not Open VSX).
- **Current State**: Reconciled and restored publisher ID to `bartholomew` in both extension manifests to align with Open VSX.
- **Release Status**: Open VSX currently hosts v6.5.5. Publication of the local v6.5.6 updates requires human release authorization with an Open VSX personal access token.
