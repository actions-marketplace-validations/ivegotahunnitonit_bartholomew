# Bartholomew BTP v6.5.6 — Escalation Ownership & Decision Authority Report

**Document Identifier**: `docs/audit/escalation-and-decision-authority.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `5467fb65b26045f2f323da433df414ae125566a7`  
**Machine-Readable Escalation Ledger**: `docs/audit/escalation-manifest.json`  
**Evaluation Date**: 2026-10-14  

---

## 1. Governance & Role Assignment Inventory (Section 14.1 & 14.2)

In accordance with Section 14.2 rules, no human owners were pre-configured in repository manifests. Default provisional assignments are established as follows:

| Role | Assigned Identity | Role Type | Authority & Boundary Constraints |
|---|---|---|---|
| **Audit Lead** | Autonomous Security Validation Agent | `PROVISIONAL_OPERATOR` | Accountable for audit execution, test coordination, deliverable status aggregation, and final report. *Cannot waive stop conditions or approve mandatory exclusions.* |
| **Evidence Custodian** | Autonomous Security Validation Agent | `PROVISIONAL_OPERATOR` | Responsible for generating cryptographic hashes, maintaining `audit_evidence/`, and indexing evidence manifests. |
| **Security Decision Owner** | **UNASSIGNED** | `AUTHORIZED_HUMAN_REVIEWER` | Authorized human reviewer responsible for accepting security risk, approving mandatory-criterion exclusions, and authorizing post-stop resumption. |
| **Release Owner** | **UNASSIGNED** | `AUTHORIZED_HUMAN_AUTHORITY` | Responsible for authorizing package publication, tag pushes, and registry updates (e.g., Open VSX publishing token). |
| **Implementation Owner** | **UNASSIGNED** | `ENGINEERING_TEAM` | Responsible for investigating and patching codebase defects. *Cannot independently verify its own fixes or approve its own exclusions.* |

### Autonomous Agent Boundary Rule (Section 14.2)
The Autonomous IDE Agent executes authorized tests, preserves evidence, calculates metrics, and documents findings. **It is not a human authority.** It cannot:
- Independently approve a security-risk exception.
- Approve its own mandatory-criterion exclusions.
- Authorize production changes or external releases.
- Waive any stop condition that requires human authorization.

---

## 2. Escalation Severity Classifications (Section 14.3)

| Severity | Definition | Examples from BTP v6.5.6 Audit | Mandatory Routing Actions |
|---|---|---|---|
| **SEV-1 (Critical / Active Exposure)** | Prohibited action executes on an advertised protected path, credentials leaked, runner compromised | **ESC-BTP-20261014-001**: Nested base64, shell variables, and hex escapes bypassed AST regex on `run_command` and executed (`executorCalls = 1`) | Stop affected execution immediately; preserve minimal evidence; notify Audit Lead & Security Decision Owner; do not resume until human authorization is recorded |
| **SEV-2 (High / Material Security Gap)** | Reproducible bypass on advertised path, approval/replay failure, material full-stack gap | **ESC-BTP-20261014-002**: Direct uninstrumented `child_process.spawn` bypasses in-process gate | Preserve evidence; document architectural boundary; notify Audit Lead and Security Decision Owner |
| **SEV-3 (Moderate / Verification Defect)** | Supporting criterion incomplete, reproducibility metadata missing, noncritical test blocked | **ESC-BTP-20261014-003**: Dataset shard hash discrepancy (`cad39281ed...` Git SHA-1 vs `bd1c998ae...` file SHA-256) | Record issue; preserve raw data; maintain dual tracking in evidence manifests |
| **SEV-4 (Low / Hygiene / Pending Config)** | Nonmaterial documentation gap, pending publication token | **ESC-BTP-20261014-004**: Vault VSIX compiled locally but awaiting Open VSX API publish token | Record state as `LOCAL_VERIFIED_PENDING_PUBLISH`; await human release token |

---

## 3. Decision Authority Matrix (Section 14.4)

| Decision Item | Required Authority | Current Audit Status |
|---|---|---|
| Preserve evidence and stop unsafe test | Any operator or automated runner | **EXECUTED** (Tests stopped on C-03..C-05) |
| Continue independent, demonstrably safe tests | Audit Lead | **EXECUTED** (Safe suites completed across D1..D8) |
| Resume a security-critical stopped test group | Security Decision Owner + Audit Lead | **STOPPED / PENDING HUMAN DECISION** |
| Change mandatory acceptance criteria | Authorized specification owner | **FAIL CLOSED** (Criteria strictly preserved) |
| Approve a mandatory `NOT APPLICABLE` exclusion | Independent authorized human reviewer | **NONE GRANTED** (Zero unapproved exclusions) |
| Accept residual security risk | Explicitly authorized human Security Decision Owner | **PENDING HUMAN REVIEW** |
| Modify security enforcement code | Authorized Implementation Owner | **FROZEN** (Codebase preserved unmodified) |
| Independently verify a security fix | Reviewer other than the implementer | **PENDING REMEDIATION** |
| Publish a package or modify a release | Authorized Release Owner | **FROZEN** (No releases published during pass) |
| Close a material security finding | Audit Lead after required verification & approvals | **OPEN** (Findings logged in manifest) |
| Mark audit complete | Audit Lead, provided all evidence & reporting are satisfied | **COMPLETE WITH FINDINGS** |

---

## 4. Active Escalation Records (Section 14.5)

### Record 1: ESC-BTP-20261014-001 (SEV-1 / Active Execution Bypass)
- **Finding ID**: `FIND-BTP-OBFUSCATION-BYPASS`
- **Trigger**: Execution-Boundary Bypass Challenge uncovered 3 unexpected executions (`executorCalls = 1`) on `run_command` via nested base64 (C-03), variable concatenation (C-04), and hex escapes (C-05).
- **Affected Deliverables**: Deliverable D3 (Enforcement Verification).
- **Mandatory Criterion Affected**: `D3-C6` marked **`UNSATISFIED`**. Deliverable D3 rated **`FAIL`**.
- **Current State**: `STOPPED_AFFECTED_ROUTE`. Repeated testing on those obfuscation forms halted.
- **Assigned Audit Lead**: Autonomous Security Validation Agent.
- **Security Decision Owner**: **`UNASSIGNED`**.
- **Required Decision**: Authorized human reviewer must review the vulnerability report, authorize an iterative AST normalization patch, and accept residual risk for pre-fix versions.
- **Closure Status**: **`OPEN`**.

### Record 2: ESC-BTP-20261014-002 (SEV-2 / Architectural Execution Boundary)
- **Finding ID**: `FIND-BTP-SUBPROCESS-BYPASS`
- **Trigger**: Raw `child_process.spawn` outside BTP wrappers executes directly on the host operating system.
- **Affected Deliverables**: Deliverable D3.
- **Current State**: `DOCUMENTED_ARCHITECTURAL_LIMITATION`.
- **Assigned Audit Lead**: Autonomous Security Validation Agent.
- **Security Decision Owner**: **`UNASSIGNED`**.
- **Required Decision**: Formally approve deployment guidelines requiring OS-level sandboxing (e.g., Docker, seccomp, gVisor) for universal containment.
- **Closure Status**: **`OPEN`**.

### Record 3: ESC-BTP-20261014-003 (SEV-3 / Dataset Hash Discrepancy)
- **Finding ID**: `FIND-BTP-DATASET-HASH-MISMATCH`
- **Trigger**: Reported hash `cad39281ed...` corresponds to Hugging Face Git commit SHA-1; true sample file SHA-256 is `bd1c998ae513d4b4a24bf497237da401b0bc994a5e4e1ff1c5d2e1f6f28b893f`.
- **Affected Deliverables**: D4, D6.
- **Current State**: `RESOLVED_LOCAL_TRACKING`.
- **Assigned Evidence Custodian**: Autonomous Security Validation Agent.
- **Decision**: Documented both hashes in release consistency and evidence manifests; resolved locally without modifying upstream repository.
- **Closure Status**: **`PROVISIONALLY_RESOLVED`**.

### Record 4: ESC-BTP-20261014-004 (SEV-4 / Pending Open VSX Publish)
- **Finding ID**: `FIND-BTP-OPENVSX-VAULT-PUBLISH`
- **Trigger**: `packages/bartholomew-vault/bartholomew-vault-6.5.6.vsix` compiled and verified with publisher `itsubsolomon`, but awaiting human operator API token.
- **Affected Deliverables**: D6.
- **Current State**: `LOCAL_VERIFIED_PENDING_PUBLISH`.
- **Release Owner**: **`UNASSIGNED`**.
- **Closure Status**: **`OPEN`**.

---

## 5. Fail-Closed Enforcement & Human Resumption Rules (Section 14.6 - 14.8)

In accordance with Section 14.8, the audit runner strictly **fails closed**:
1. In the absence of an assigned human Security Decision Owner, no security waivers, criterion downgrades, or risk exceptions have been granted.
2. The demonstrated obfuscation bypasses remain explicitly documented as **`UNSATISFIED`** under Deliverable D3, yielding **`FAIL`** for that deliverable.
3. Resumption of execution testing against the stopped obfuscation routes remains blocked until an authorized human reviewer provides explicit authorization on a newly tracked test run.
