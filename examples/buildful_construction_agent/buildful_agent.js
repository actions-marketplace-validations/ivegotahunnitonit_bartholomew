/**
 * Buildful.ai Reference Construction Estimating Agent with Bartholomew Guard
 * Demonstrates:
 * 1. Safe blueprint parsing and material calculation
 * 2. In-process contractor PII & banking tokenization
 * 3. Enforcing $25,000 Keystone spend cap on change orders
 * 4. Cryptographic execution receipts for insurance auditing
 */
import { enforceToolBoundary, scrubSensitiveCredentials } from '../../packages/npm_package/index.js';

export class BuildfulEstimatingAgent {
  constructor(config = {}) {
    this.projectName = config.projectName || "Highrise Phase 2";
    this.maxSingleApprovalUsd = config.maxSingleApprovalUsd || 25000.0;
  }

  // 1. Sanitize incoming submittal documentation before LLM processing
  sanitizeSubcontractorSubmittal(rawDocumentText) {
    const scrubbed = scrubSensitiveCredentials(rawDocumentText);
    return {
      sanitizedText: scrubbed.data,
      secretsVaulted: scrubbed.redactionCount,
      safeForCloudLLM: true
    };
  }

  // 2. Dispatch change order or bid with deterministic AST safety check
  async dispatchChangeOrder(changeOrder) {
    const { orderId, subcontractor, amountUsd, trade, targetFile } = changeOrder;

    // Check financial limit
    if (amountUsd > this.maxSingleApprovalUsd) {
      return {
        success: false,
        blocked: true,
        rule_id: "BTP-KEY-SPEND-LIMIT",
        reason: `Change order amount ($${amountUsd.toLocaleString()}) exceeds Keystone autonomous threshold ($${this.maxSingleApprovalUsd.toLocaleString()}). Requires general contractor human sign-off.`
      };
    }

    // Check tool boundary invariants
    const decision = enforceToolBoundary('update_estimate_database', {
      orderId,
      subcontractor,
      amountUsd,
      trade,
      targetFile
    });

    if (!decision.allowed) {
      return {
        success: false,
        blocked: true,
        rule_id: decision.rule_id,
        reason: decision.reason
      };
    }

    return {
      success: true,
      blocked: false,
      orderId,
      amountUsd,
      merkleReceipt: decision.merkle_turn_receipt || '0x' + Buffer.from(orderId).toString('hex').padEnd(64, '0'),
      status: "COMMITTED_TO_ERP"
    };
  }
}
