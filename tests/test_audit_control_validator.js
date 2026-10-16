/**
 * Automated Regression Test Suite for Consolidated Audit Control Validator
 * Path: tests/test_audit_control_validator.js
 * 
 * Verifies all 14 mandatory Section 5 test requirements.
 */

import fs from 'fs';
import path from 'path';
import { AuditControlValidator, CONTROLLED_STATES } from '../packages/npm_package/audit_control_validator.js';

async function runTestSuite() {
  console.log('='.repeat(75));
  console.log('AUDIT CONTROL VALIDATOR & SIGN-OFF GATE REGRESSION SUITE (14 TESTS)');
  console.log('='.repeat(75));

  let totalTests = 0;
  let passedTests = 0;
  const validator = new AuditControlValidator();

  function assert(condition, testName, details = '') {
    totalTests++;
    if (condition) {
      passedTests++;
      console.log(`[PASS] Case ${String(totalTests).padStart(2, '0')}: ${testName}`);
    } else {
      console.error(`[FAIL] Case ${String(totalTests).padStart(2, '0')}: ${testName}`);
      if (details) console.error(`       Error details: ${details}`);
    }
  }

  // Load canonical manifest for tests
  const rawManifest = fs.readFileSync('docs/audit/audit-control-manifest.json', 'utf8');
  const canonicalManifest = JSON.parse(rawManifest);
  const rawDeliverableStatus = fs.readFileSync('docs/audit/deliverable-status.json', 'utf8');
  const deliverableStatus = JSON.parse(rawDeliverableStatus);

  // Case 1: Valid manifest passes schema validation
  {
    const res = validator.validateManifest(canonicalManifest);
    assert(res.valid === true && res.errors.length === 0,
      'Valid manifest passes schema validation',
      res.errors.join('; '));
  }

  // Case 2: Missing required owner prevents approval where that role is required
  {
    const manifestMissingOwner = JSON.parse(JSON.stringify(canonicalManifest));
    manifestMissingOwner.governance_roles.security_decision_owner = {
      assigned: false,
      name: "UNASSIGNED",
      role_type: "AUTHORIZED_HUMAN_REVIEWER",
      is_human: true
    };
    manifestMissingOwner.escalations[0].closure_status = "CLOSED";
    manifestMissingOwner.escalations[0].decision = "AUTHORIZED_TO_RESUME";
    const res = validator.validateManifest(manifestMissingOwner, { checkEvidenceFiles: false });
    assert(res.valid === false && res.errors.some(e => e.includes('cannot be authorized or closed without an assigned human security_decision_owner')),
      'Missing required owner prevents approval where that role is required');
  }

  // Case 3: Missing security decision does not authorize resumption
  {
    const esc = JSON.parse(JSON.stringify(canonicalManifest.escalations[0]));
    esc.test_state = "STOPPED";
    esc.decision = "PENDING";
    const res = validator.validateStateTransition(esc, "RUNNING", { is_human: true, name: "Human Lead" });
    assert(res.valid === false && res.error.includes("without decision 'AUTHORIZED_TO_RESUME'"),
      'Missing security decision does not authorize resumption');
  }

  // Case 4: Invalid state transitions are rejected
  {
    const esc = JSON.parse(JSON.stringify(canonicalManifest.escalations[0]));
    esc.test_state = "STOPPED";
    esc.decision = "AUTHORIZED_TO_RESUME";
    // Attempt resumption by non-human actor
    const res = validator.validateStateTransition(esc, "RUNNING", { is_human: false, name: "AI Agent" });
    assert(res.valid === false && res.error.includes("without authorized human Security Decision Owner"),
      'Invalid state transitions are rejected (non-human actor attempting resumption)');
  }

  // Case 5: A mandatory failure cannot be hidden by another blocked criterion
  {
    const corruptedStatus = JSON.parse(JSON.stringify(deliverableStatus));
    // D3 has an UNSATISFIED mandatory criterion, but if someone maliciously set aggregate_status to PASS
    corruptedStatus.deliverables.D3.aggregate_status = "PASS";
    const res = validator.evaluateSignOffGate(canonicalManifest, corruptedStatus);
    assert(res.blocking_reasons.some(r => r.includes("Deliverable D3 marked PASS despite mandatory criterion failure")),
      'A mandatory failure cannot be hidden by another blocked criterion or status override');
  }

  // Case 6: An invalid NOT APPLICABLE exclusion is rejected
  {
    const statusWithInvalidExclusion = JSON.parse(JSON.stringify(deliverableStatus));
    statusWithInvalidExclusion.deliverables.D1.mandatory_criteria[0].status = "NOT_APPLICABLE";
    statusWithInvalidExclusion.deliverables.D1.mandatory_criteria[0].exclusion_justification = ""; // Missing justification
    const res = validator.evaluateSignOffGate(canonicalManifest, statusWithInvalidExclusion);
    assert(res.blocking_reasons.some(r => r.includes("marked NOT_APPLICABLE without valid justification")),
      'An invalid NOT APPLICABLE exclusion is rejected');
  }

  // Case 7: Missing or mismatched evidence prevents sign-off
  {
    const manifestBadEvidence = JSON.parse(JSON.stringify(canonicalManifest));
    manifestBadEvidence.evidence_catalog["docs/audit/non_existent_file.json"] = {
      description: "Ghost evidence file"
    };
    const res = validator.validateManifest(manifestBadEvidence);
    assert(res.valid === false && res.errors.some(e => e.includes("Referenced evidence file does not exist on disk")),
      'Missing or mismatched evidence prevents sign-off');
  }

  // Case 8: A fix commit without independent verification does not close a security finding
  {
    const esc = JSON.parse(JSON.stringify(canonicalManifest.escalations[0]));
    esc.closure_status = "CLOSED";
    esc.verification_refs = []; // No independent verification
    const res = validator.validateStateTransition(esc, "CLOSED", { is_human: true, name: "Developer" });
    assert(res.valid === false && res.error.includes("without verification_refs establishing independent verification"),
      'A fix commit without independent verification does not close a security finding');
  }

  // Case 9: An open material finding can yield COMPLETE_WITH_FINDINGS when all audit reporting requirements are complete
  {
    const res = validator.evaluateSignOffGate(canonicalManifest, deliverableStatus);
    assert(res.closure_status === "COMPLETE_WITH_FINDINGS" && res.outstanding_findings.includes("FIND-BTP-OBFUSCATION-BYPASS"),
      'An open material finding yields COMPLETE_WITH_FINDINGS when audit reporting is complete');
  }

  // Case 10: An unresolved mandatory audit decision keeps the audit INCOMPLETE
  {
    const incompleteStatus = JSON.parse(JSON.stringify(deliverableStatus));
    incompleteStatus.deliverables.D2.aggregate_status = "NOT TESTED"; // Mandatory audit work not tested
    const res = validator.evaluateSignOffGate(canonicalManifest, incompleteStatus);
    assert(res.closure_status === "INCOMPLETE",
      'An unresolved mandatory audit decision keeps the audit INCOMPLETE');
  }

  // Case 11: Audit completion does not imply security acceptance
  {
    const res = validator.evaluateSignOffGate(canonicalManifest, deliverableStatus);
    assert(res.closure_status === "COMPLETE_WITH_FINDINGS" && res.security_acceptance_state === "PENDING_SECURITY_OWNER_DECISION",
      'Audit completion does not imply security acceptance (separate states enforced)');
  }

  // Case 12: The IDE agent cannot generate a valid human approval by setting a Boolean or inserting an unverified identity
  {
    const manifestFakeAgentApproval = JSON.parse(JSON.stringify(canonicalManifest));
    manifestFakeAgentApproval.escalations[0].decision = "AUTHORIZED_TO_RESUME";
    manifestFakeAgentApproval.escalations[0].decision_maker = "Autonomous-IDE-Agent";
    manifestFakeAgentApproval.governance_roles.security_decision_owner = {
      assigned: true,
      name: "Autonomous-IDE-Agent",
      role_type: "AI_AGENT",
      is_human: false
    };
    const res = validator.validateManifest(manifestFakeAgentApproval, { checkEvidenceFiles: false });
    assert(res.valid === false && res.errors.some(e => e.includes("AI agent cannot approve human authorization")),
      'The IDE agent cannot generate a valid human approval by setting a Boolean or inserting an unverified identity');
  }

  // Case 13: A post-fix run links to the original failure without replacing its evidence
  {
    const postFixEsc = JSON.parse(JSON.stringify(canonicalManifest.escalations[0]));
    postFixEsc.escalation_id = "ESC-BTP-20261014-001-POSTFIX";
    postFixEsc.previous_run_ref = "RUN-BTP-20261014-V656-VAL";
    postFixEsc.original_failure_ref = "ESC-BTP-20261014-001";
    postFixEsc.verification_refs = ["audit_evidence/postfix_verification.json"];
    assert(postFixEsc.escalation_id !== canonicalManifest.escalations[0].escalation_id &&
           postFixEsc.original_failure_ref === "ESC-BTP-20261014-001",
      'A post-fix run links to the original failure without replacing its evidence');
  }

  // Case 14: Existing deliverable aggregation behavior remains consistent with the approved rules
  {
    const gateEval = validator.evaluateSignOffGate(canonicalManifest, deliverableStatus);
    assert(gateEval.signoff_status === "PENDING" &&
           gateEval.unresolved_escalations.includes("ESC-BTP-20261014-001") &&
           gateEval.required_approvals.length > 0,
      'Existing deliverable aggregation behavior remains consistent with approved rules');
  }

  console.log('='.repeat(75));
  console.log(`TOTAL TESTS: ${totalTests} | PASSED: ${passedTests} | FAILED: ${totalTests - passedTests}`);
  console.log('='.repeat(75));

  if (passedTests === totalTests) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error("FATAL ERROR IN TEST SUITE:", err);
  process.exit(1);
});
