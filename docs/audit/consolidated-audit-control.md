# Bartholomew BTP v6.5.6 — Consolidated Audit Control & Sign-Off Documentation

**Document Identifier**: `docs/audit/consolidated-audit-control.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Authoritative Control Manifest**: `docs/audit/audit-control-manifest.json`  
**Validator Implementation**: `packages/npm_package/audit_control_validator.js` (re-exported via `src/audit_control_validator.js`)  
**Automated Test Suite**: `tests/test_audit_control_validator.js` (14 / 14 tests passing)  
**Evaluation Date**: 2026-10-14  

---

## 1. Single Source of Truth Architecture

To eliminate overlapping frameworks and duplicate tracking, this repository establishes **one authoritative machine-readable audit control manifest**:

```
docs/audit/audit-control-manifest.json
```

All audit controls, stop conditions, active escalations, governance roles, and sign-off states are stored and validated through this single manifest. Other audit documents (`docs/audit/deliverable-status.json`, `docs/audit/evidence-manifest.json`, `docs/audit/bypass-matrix.md`) are directly referenced as child artifacts rather than having their contents duplicated.

---

## 2. Ownership Roles & Invariants (Section 14 Compliance)

The schema defines five formal governance roles:

1. **Audit Lead**: Accountable for audit scope, test coordination, deliverable status aggregation, and final reporting. Assigned provisionally to the Autonomous Validation Agent.
2. **Evidence Custodian**: Responsible for maintaining cryptographic hashes and audit evidence records. Assigned provisionally to the Autonomous Validation Agent.
3. **Security Decision Owner**: **UNASSIGNED**. Authorized human reviewer responsible for accepting security risk, approving mandatory-criterion exclusions, and authorizing post-stop resumption.
4. **Release Owner**: **UNASSIGNED**. Authorized human authority responsible for confirming source-to-package consistency and authorizing registry publication.
5. **Implementation Owner**: **UNASSIGNED**. Engineering team responsible for patching code defects. *Cannot independently verify its own fixes or approve its own exclusions.*

### Automated Agent Boundary Invariant
An AI/IDE agent is strictly prohibited from:
- Simulating human approval or setting Boolean flags to bypass human review.
- Accepting security risk on behalf of the project.
- Approving its own mandatory-criterion exclusions.
- Authorizing package publication or external release changes.
- Waiving any stop condition requiring human authorization.

---

## 3. Finite State Machine: Controlled States & Transitions

The validator strictly enforces controlled states across all entities:

### Controlled State Enums
- **Finding Severity**: `SEV-1`, `SEV-2`, `SEV-3`, `SEV-4`
- **Test State**: `NOT_STARTED`, `RUNNING`, `STOPPED`, `BLOCKED`, `COMPLETED`
- **Escalation State**: `OPEN`, `PENDING_DECISION`, `AUTHORIZED_TO_RESUME`, `CLOSED`
- **Sign-Off State**: `PENDING`, `APPROVED`, `REJECTED`
- **Audit Closure State**: `INCOMPLETE`, `COMPLETE_WITH_FINDINGS`, `COMPLETE`
- **Security Acceptance State**: `NOT_ACCEPTED`, `PENDING_SECURITY_OWNER_DECISION`, `ACCEPTED`
- **Deliverable Status**: `PASS`, `PARTIAL`, `FAIL`, `BLOCKED`, `NOT TESTED`

### State Transition Invariants
1. **`STOPPED` -> `RUNNING` for SEV-1 / SEV-2**:
   - Requires decision `AUTHORIZED_TO_RESUME`.
   - Requires explicit authorization by an assigned human `Security Decision Owner` (`is_human: true`).
   - Requires all recorded `resume_conditions` to be fulfilled.
   - Any attempt by an AI agent or unauthorized actor to resume is rejected.
2. **`OPEN` -> `CLOSED`**:
   - Requires `verification_refs` populated with reproducible test runs on a new run ID.
   - Requires independent human review for security-critical findings.
   - Commits, notifications, or documentation edits alone cannot close an escalation.

---

## 4. Consolidated Decision & Stop Rules

All decision and stop logic is implemented in `packages/npm_package/audit_control_validator.js` and enforced across the repository:

1. **Prohibited Execution is a Security Finding**: A prohibited action reaching a protected executor halts the affected route immediately. Evidence is preserved before any further testing.
2. **Isolation Threat Termination**: Any uncontrolled external execution or environment isolation failure terminates immediately.
3. **Fail-Closed on Human Approval**: Missing human approval blocks only the dependent action; independent safe tests continue.
4. **Agent Cannot Simulate Human Authority**: The IDE agent collects evidence and calculates metrics, but cannot authorize waivers or accept risk.
5. **Fixes Retain Original Failure**: A fix commit does not erase the original failure. Post-fix runs have a new run ID and link to the original finding.
6. **Mandatory Failure Precedence**: Mandatory `FAIL` takes precedence over `BLOCKED`. Unresolved mandatory tests prevent `PASS`.
7. **Invalid Exclusions Rejected**: Unsupported `NOT APPLICABLE` exclusions fail validation.
8. **Independent Verification Mandatory**: A ticket, commit, or doc edit is not evidence of closure.

---

## 5. Closure Semantics: Audit Completion vs. Security Acceptance

The validator explicitly separates **Audit Completion** from **Security Acceptance**:

- **`audit_closure_state`: `COMPLETE_WITH_FINDINGS`**:
  - The audit work, evaluations, raw evidence preservation, and honest reporting are 100% complete.
  - Material findings (e.g., ESC-BTP-20261014-001 SEV-1 obfuscation bypass) remain open and documented.
  - Deliverable D3 is correctly rated `FAIL` without green-status inflation.
  - This status indicates that the **investigation is complete and transparent**, but does **NOT** indicate security approval.
- **`security_acceptance_state`: `PENDING_SECURITY_OWNER_DECISION`**:
  - Because `security_decision_owner` is currently `UNASSIGNED`, residual security risk cannot be accepted.
  - Security acceptance remains pending until an authorized human reviewer reviews the findings and signs off.

---

## 6. Migration Note (Consolidation of Previous Sections)

The implementation of `audit-control-manifest.json` and `AuditControlValidator` consolidates previously disparate audit artifacts:
1. **Section 13 (Stop Conditions & Escalation Rules)**: Merged into the central state machine and verified via `validateStateTransition()`.
2. **Section 14 (Ownership & Authority Matrix)**: Merged into `governance_roles` and checked via fail-closed role validation.
3. **Deliverable Aggregation (Section 7)**: Child evaluation linked to `docs/audit/deliverable-status.json` and verified in `evaluateSignOffGate()`.
4. **Evidence Indexing (Section 8)**: Unified under `evidence_catalog` with automated on-disk existence and SHA-256 integrity verification.

All previous unique technical requirements, historical findings, and raw evidence files remain intact.

---

## 7. Remaining Manual Steps Requiring an Authorized Human

The automated validation suite has passed 100% of its verifiable checks. The following manual steps remain strictly blocked pending human decision:

1. **Assign Human Security Decision Owner**:
   - An authorized human must be designated in `governance_roles.security_decision_owner`.
2. **Review & Authorize Remediation Plan for ESC-BTP-20261014-001 (SEV-1)**:
   - Review demonstrated bypasses on multi-stage nested base64, shell variables, and hex escapes.
   - Authorize implementation of iterative AST unescaping and accept residual risk for pre-fix releases.
3. **Supply Open VSX Publication Token for ESC-BTP-20261014-004 (SEV-4)**:
   - Provide an Open VSX API token to publish `itsubsolomon.bartholomew-vault@6.5.6`.
