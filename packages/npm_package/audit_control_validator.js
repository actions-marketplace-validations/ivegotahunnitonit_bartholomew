/**
 * Bartholomew BTP v6.5.6 — Consolidated Audit Control Validator & Sign-Off Gate
 * Path: packages/npm_package/audit_control_validator.js
 * 
 * Provides:
 * 1. Single-source-of-truth schema validation for audit-control-manifest.json
 * 2. 22-field escalation record enforcement
 * 3. Formal state-machine transitions and stop-condition enforcement
 * 4. Sign-off and closure gate evaluating audit completeness separately from human security acceptance
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export const CONTROLLED_STATES = {
  finding_severity: ['SEV-1', 'SEV-2', 'SEV-3', 'SEV-4'],
  test_state: ['NOT_STARTED', 'RUNNING', 'STOPPED', 'BLOCKED', 'COMPLETED'],
  escalation_state: ['OPEN', 'PENDING_DECISION', 'AUTHORIZED_TO_RESUME', 'CLOSED'],
  signoff_state: ['PENDING', 'APPROVED', 'REJECTED'],
  audit_closure_state: ['INCOMPLETE', 'COMPLETE_WITH_FINDINGS', 'COMPLETE'],
  deliverable_status: ['PASS', 'PARTIAL', 'FAIL', 'BLOCKED', 'NOT TESTED'],
  notification_status: ['NOT_NOTIFIED', 'NOTIFIED', 'PENDING_HUMAN_REVIEW'],
  escalation_decision: ['PENDING', 'AUTHORIZED_TO_RESUME', 'REMEDIATION_REQUIRED', 'REJECTED', 'ACCEPTED_RISK', 'RESOLVED_PROVISIONALLY'],
  security_acceptance_state: ['NOT_ACCEPTED', 'PENDING_SECURITY_OWNER_DECISION', 'ACCEPTED']
};

export const REQUIRED_ESCALATION_FIELDS = [
  'escalation_id',
  'finding_id',
  'severity',
  'triggering_condition',
  'affected_deliverables',
  'affected_execution_paths',
  'repository_commit',
  'created_at_utc',
  'owner_role',
  'assigned_owner',
  'security_decision_owner',
  'notification_status',
  'test_state',
  'required_decision',
  'decision',
  'decision_maker',
  'decision_at_utc',
  'evidence_refs',
  'resume_conditions',
  'remediation_owner',
  'verification_refs',
  'closure_status'
];

export class AuditControlValidator {
  constructor(options = {}) {
    this.rootDir = options.rootDir || process.cwd();
    this.errors = [];
    this.warnings = [];
  }

  /**
   * Validate the complete audit control manifest
   * @param {Object} manifest 
   * @param {Object} options 
   * @returns {Object} Validation outcome
   */
  validateManifest(manifest, options = {}) {
    this.errors = [];
    this.warnings = [];

    if (!manifest || typeof manifest !== 'object') {
      this.errors.push('Manifest must be a non-null object');
      return { valid: false, errors: this.errors, warnings: this.warnings };
    }

    // 1. Header & Metadata
    this._validateHeader(manifest);

    // 2. Governance Roles
    this._validateGovernanceRoles(manifest);

    // 3. Deliverables Status
    this._validateDeliverables(manifest);

    // 4. Findings
    this._validateFindings(manifest);

    // 5. Stop Conditions
    this._validateStopConditions(manifest);

    // 6. Escalations (22 required fields per record)
    this._validateEscalations(manifest);

    // 7. Evidence Catalog & Path Existence
    if (options.checkEvidenceFiles !== false) {
      this._validateEvidenceFiles(manifest);
    }

    return {
      valid: this.errors.length === 0,
      errors: this.errors,
      warnings: this.warnings
    };
  }

  _validateHeader(m) {
    if (!m.audit_run_id || typeof m.audit_run_id !== 'string') {
      this.errors.push('Missing or invalid audit_run_id');
    }
    if (!m.repository_commit || typeof m.repository_commit !== 'string') {
      this.errors.push('Missing or invalid repository_commit');
    }
    if (!m.created_at_utc || isNaN(Date.parse(m.created_at_utc))) {
      this.errors.push('Missing or invalid created_at_utc ISO timestamp');
    }
    if (!m.updated_at_utc || isNaN(Date.parse(m.updated_at_utc))) {
      this.errors.push('Missing or invalid updated_at_utc ISO timestamp');
    }
  }

  _validateGovernanceRoles(m) {
    const roles = m.governance_roles;
    if (!roles || typeof roles !== 'object') {
      this.errors.push('Missing governance_roles object in manifest');
      return;
    }
    const requiredRoles = ['audit_lead', 'evidence_custodian', 'security_decision_owner', 'release_owner', 'implementation_owner'];
    for (const r of requiredRoles) {
      if (!roles[r]) {
        this.errors.push(`Missing required governance role definition: ${r}`);
      } else {
        if (typeof roles[r].assigned !== 'boolean') {
          this.errors.push(`Role ${r} must specify boolean 'assigned'`);
        }
        if (typeof roles[r].is_human !== 'boolean') {
          this.errors.push(`Role ${r} must specify boolean 'is_human'`);
        }
      }
    }
  }

  _validateDeliverables(m) {
    const d = m.deliverable_statuses;
    if (!d || typeof d !== 'object') {
      this.errors.push('Missing deliverable_statuses object in manifest');
      return;
    }
    const requiredD = ['D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8'];
    for (const k of requiredD) {
      if (!d[k]) {
        this.errors.push(`Missing deliverable status for ${k}`);
      } else if (!CONTROLLED_STATES.deliverable_status.includes(d[k])) {
        this.errors.push(`Invalid deliverable status '${d[k]}' for ${k}`);
      }
    }
  }

  _validateFindings(m) {
    if (!Array.isArray(m.findings)) {
      this.errors.push('Manifest must contain a findings array');
      return;
    }
    for (const f of m.findings) {
      if (!f.finding_id) this.errors.push('Finding missing finding_id');
      if (!CONTROLLED_STATES.finding_severity.includes(f.severity)) {
        this.errors.push(`Finding ${f.finding_id || 'unknown'} has invalid severity '${f.severity}'`);
      }
    }
  }

  _validateStopConditions(m) {
    if (!Array.isArray(m.stop_conditions)) {
      this.errors.push('Manifest must contain a stop_conditions array');
      return;
    }
    for (const sc of m.stop_conditions) {
      if (!sc.condition_id) this.errors.push('Stop condition missing condition_id');
      if (!CONTROLLED_STATES.test_state.includes(sc.test_state)) {
        this.errors.push(`Stop condition ${sc.condition_id} has invalid test_state '${sc.test_state}'`);
      }
    }
  }

  _validateEscalations(m) {
    if (!Array.isArray(m.escalations)) {
      this.errors.push('Manifest must contain an escalations array');
      return;
    }

    for (const esc of m.escalations) {
      const id = esc.escalation_id || 'UNKNOWN';

      // Verify all 22 required fields exist
      for (const field of REQUIRED_ESCALATION_FIELDS) {
        if (esc[field] === undefined) {
          this.errors.push(`Escalation ${id} missing required field '${field}'`);
        }
      }

      // Check Enum values
      if (esc.severity && !CONTROLLED_STATES.finding_severity.includes(esc.severity)) {
        this.errors.push(`Escalation ${id} invalid severity: '${esc.severity}'`);
      }
      if (esc.notification_status && !CONTROLLED_STATES.notification_status.includes(esc.notification_status)) {
        this.errors.push(`Escalation ${id} invalid notification_status: '${esc.notification_status}'`);
      }
      if (esc.test_state && !CONTROLLED_STATES.test_state.includes(esc.test_state)) {
        this.errors.push(`Escalation ${id} invalid test_state: '${esc.test_state}'`);
      }
      if (esc.decision && !CONTROLLED_STATES.escalation_decision.includes(esc.decision)) {
        this.errors.push(`Escalation ${id} invalid decision: '${esc.decision}'`);
      }
      if (esc.closure_status && !CONTROLLED_STATES.escalation_state.includes(esc.closure_status)) {
        this.errors.push(`Escalation ${id} invalid closure_status: '${esc.closure_status}'`);
      }

      // Arrays
      if (!Array.isArray(esc.affected_deliverables)) {
        this.errors.push(`Escalation ${id} affected_deliverables must be an array`);
      }
      if (!Array.isArray(esc.affected_execution_paths)) {
        this.errors.push(`Escalation ${id} affected_execution_paths must be an array`);
      }
      if (!Array.isArray(esc.evidence_refs)) {
        this.errors.push(`Escalation ${id} evidence_refs must be an array`);
      }
      if (!Array.isArray(esc.verification_refs)) {
        this.errors.push(`Escalation ${id} verification_refs must be an array`);
      }

      // Rule 4 & 12: Autonomous Agent Cannot Approve Human Decision
      if (esc.decision === 'AUTHORIZED_TO_RESUME' || esc.closure_status === 'CLOSED') {
        const secOwner = m.governance_roles && m.governance_roles.security_decision_owner;
        if (!secOwner || !secOwner.assigned || !secOwner.is_human || secOwner.name === 'UNASSIGNED') {
          this.errors.push(`Escalation ${id} cannot be authorized or closed without an assigned human security_decision_owner`);
        }
        if (esc.decision_maker && /agent|bot|ide|automated/i.test(esc.decision_maker)) {
          this.errors.push(`Escalation ${id} invalid decision_maker '${esc.decision_maker}': AI agent cannot approve human authorization`);
        }
      }

      // Rule 8: Closure requires verification_refs
      if (esc.closure_status === 'CLOSED' && (!esc.verification_refs || esc.verification_refs.length === 0)) {
        this.errors.push(`Escalation ${id} marked CLOSED without verification_refs`);
      }
    }
  }

  _validateEvidenceFiles(m) {
    if (m.evidence_catalog && typeof m.evidence_catalog === 'object') {
      for (const [relPath, meta] of Object.entries(m.evidence_catalog)) {
        const fullPath = path.isAbsolute(relPath) ? relPath : path.join(this.rootDir, relPath);
        if (!fs.existsSync(fullPath)) {
          this.errors.push(`Referenced evidence file does not exist on disk: ${relPath}`);
        } else if (meta.sha256 && meta.sha256.length === 64 && !meta.sha256.includes('...')) {
          const buf = fs.readFileSync(fullPath);
          const computedHash = crypto.createHash('sha256').update(buf).digest('hex');
          if (computedHash !== meta.sha256) {
            this.errors.push(`Hash mismatch for evidence file ${relPath}: expected ${meta.sha256}, got ${computedHash}`);
          }
        }
      }
    }
  }

  /**
   * Validate a proposed state transition
   * @param {Object} escalation 
   * @param {string} newState 
   * @param {Object} actor 
   * @returns {Object} Transition validation result
   */
  validateStateTransition(escalation, newState, actor = {}) {
    const currentState = escalation.test_state;
    const severity = escalation.severity;

    // Transition STOPPED -> RUNNING for SEV-1 / SEV-2
    if (currentState === 'STOPPED' && newState === 'RUNNING') {
      if (['SEV-1', 'SEV-2'].includes(severity)) {
        if (escalation.decision !== 'AUTHORIZED_TO_RESUME') {
          return {
            valid: false,
            error: `Cannot transition SEV-1/SEV-2 test_state from STOPPED to RUNNING without decision 'AUTHORIZED_TO_RESUME' (current: '${escalation.decision}')`
          };
        }
        if (!actor.is_human || actor.name === 'UNASSIGNED') {
          return {
            valid: false,
            error: `Cannot transition SEV-1/SEV-2 from STOPPED to RUNNING without authorized human Security Decision Owner`
          };
        }
        if (!escalation.resume_conditions || escalation.resume_conditions === 'PENDING') {
          return {
            valid: false,
            error: `Cannot transition from STOPPED to RUNNING with unfulfilled resume_conditions`
          };
        }
      }
    }

    // Transition OPEN -> CLOSED
    if (newState === 'CLOSED') {
      if (!escalation.verification_refs || escalation.verification_refs.length === 0) {
        return {
          valid: false,
          error: `Cannot transition escalation to CLOSED without verification_refs establishing independent verification`
        };
      }
      if (!actor.is_human && ['SEV-1', 'SEV-2'].includes(severity)) {
        return {
          valid: false,
          error: `Cannot close SEV-1/SEV-2 escalation without authorized human review`
        };
      }
    }

    return { valid: true };
  }

  /**
   * Evaluate the complete audit sign-off gate
   * @param {Object} manifest 
   * @param {Object} deliverableStatus 
   * @returns {Object} Sign-off evaluation
   */
  evaluateSignOffGate(manifest, deliverableStatus = null) {
    const valResult = this.validateManifest(manifest);

    const blockingReasons = [];
    const outstandingFindings = [];
    const unresolvedEscalations = [];
    const requiredApprovals = [];
    const missingEvidence = [];

    // Collect outstanding findings
    if (Array.isArray(manifest.findings)) {
      for (const f of manifest.findings) {
        if (f.status === 'OPEN' && ['SEV-1', 'SEV-2'].includes(f.severity)) {
          outstandingFindings.push(f.finding_id);
          blockingReasons.push(`Open ${f.severity} finding: ${f.finding_id} (${f.description || ''})`);
        }
      }
    }

    // Collect unresolved escalations
    if (Array.isArray(manifest.escalations)) {
      for (const e of manifest.escalations) {
        if (['OPEN', 'PENDING_DECISION'].includes(e.closure_status)) {
          unresolvedEscalations.push(e.escalation_id);
        }
        if (e.decision === 'PENDING') {
          requiredApprovals.push(`${e.escalation_id} requires ${e.required_decision}`);
        }
      }
    }

    // Check deliverable aggregation invariant (Rule 6)
    if (deliverableStatus && deliverableStatus.deliverables) {
      for (const [dKey, dObj] of Object.entries(deliverableStatus.deliverables)) {
        const hasMandatoryFail = Array.isArray(dObj.mandatory_criteria) && 
          dObj.mandatory_criteria.some(c => c.mandatory && c.status === 'UNSATISFIED');
        if (hasMandatoryFail && dObj.aggregate_status === 'PASS') {
          blockingReasons.push(`Deliverable ${dKey} marked PASS despite mandatory criterion failure`);
        }
        // Rule 7: check invalid NOT APPLICABLE exclusions
        if (Array.isArray(dObj.mandatory_criteria)) {
          for (const c of dObj.mandatory_criteria) {
            if (c.status === 'NOT_APPLICABLE' && !c.exclusion_justification) {
              blockingReasons.push(`Deliverable ${dKey} criterion ${c.id} marked NOT_APPLICABLE without valid justification`);
            }
          }
        }
      }
    }

    // Check human ownership assignment
    const secOwner = manifest.governance_roles && manifest.governance_roles.security_decision_owner;
    if (!secOwner || !secOwner.assigned || !secOwner.is_human || secOwner.name === 'UNASSIGNED') {
      requiredApprovals.push('Security Decision Owner is UNASSIGNED (human authority required for security acceptance)');
    }

    // Determine audit closure state
    let auditClosureState = 'INCOMPLETE';
    if (valResult.valid && (!deliverableStatus || !this._hasUnresolvedMandatoryAudit(deliverableStatus))) {
      if (outstandingFindings.length > 0 || unresolvedEscalations.length > 0) {
        auditClosureState = 'COMPLETE_WITH_FINDINGS';
      } else {
        auditClosureState = 'COMPLETE';
      }
    }

    // Separate Security Acceptance State from Audit Closure
    let securityAcceptanceState = 'PENDING_SECURITY_OWNER_DECISION';
    if (!secOwner || !secOwner.assigned || !secOwner.is_human || secOwner.name === 'UNASSIGNED') {
      securityAcceptanceState = 'PENDING_SECURITY_OWNER_DECISION';
    } else if (manifest.signoff && manifest.signoff.security_acceptance_state === 'ACCEPTED') {
      securityAcceptanceState = 'ACCEPTED';
    }

    const signoffStatus = (auditClosureState === 'COMPLETE' && blockingReasons.length === 0) ? 'APPROVED' : 'PENDING';

    return {
      signoff_status: signoffStatus,
      closure_status: auditClosureState,
      security_acceptance_state: securityAcceptanceState,
      blocking_reasons: blockingReasons,
      outstanding_findings: outstandingFindings,
      unresolved_escalations: unresolvedEscalations,
      missing_evidence: missingEvidence,
      required_approvals: requiredApprovals,
      approved_scope: (manifest.signoff && manifest.signoff.approved_scope) || [],
      excluded_scope: (manifest.signoff && manifest.signoff.excluded_scope) || [],
      validated_at_utc: new Date().toISOString()
    };
  }

  _hasUnresolvedMandatoryAudit(deliverableStatus) {
    if (!deliverableStatus.deliverables) return false;
    for (const dObj of Object.values(deliverableStatus.deliverables)) {
      if (dObj.aggregate_status === 'NOT TESTED') return true;
    }
    return false;
  }
}
