# Bartholomew Trust Protocol (BTP v6.5.6)
# Enterprise Integration Architecture for Buildful.ai

## Executive Summary
[Buildful.ai](https://buildful.ai/) automates construction takeoff, contractor submittals, estimating, and jobsite documentation. Autonomous agents operating in construction workflows interact with high-stakes financial data, municipal permits, blueprint repositories, and subcontractor financials.

A single uncontrolled agent error—such as executing an unauthorized file deletion, leaking subcontractor tax identification numbers, or approving an unvetted change order—creates catastrophic financial and legal liability.

Bartholomew provides Buildful with a sub-35 microsecond, in-process deterministic execution gateway, format-preserving financial/PII tokenization, and tamper-evident Merkle execution receipts for insurance carriers and general contractors.

---

## High-Stakes Threat Model in AI Construction Workflows

| Threat Vector | Real-World Construction Scenario | Bartholomew Mitigation | Latency Overhead |
| :--- | :--- | :--- | :--- |
| **Catastrophic Takeoff Wipe** | Agent issues shell cleanup command deleting CAD/BIM model directories (`rm -rf /projects/bim`). | In-process AST gate prohibits destructive shell mutations and file system boundary escapes. | 14.8 µs |
| **Contractor PII & Banking Leak** | Subcontractor W-9s, EINs, and direct deposit routing numbers sent in cleartext prompts to cloud LLMs. | Zero-egress Vault swaps sensitive data for format-preserving surrogates before API dispatch. | 22.4 µs |
| **Financial Change Order Runaway** | Agent autonomously commits a $75,000 subcontractor change order without licensed superintendent sign-off. | Keystone Capability Passkey enforces deterministic $25,000 cap; requires 1-tap mobile approval. | 18.2 µs |
| **Database Corruption** | SQL agent querying estimating database issues malformed `DROP TABLE bids` or `TRUNCATE estimates`. | SQL AST firewall intercepts and vetoes DDL drops at the tool boundary. | 16.5 µs |

---

## Architectural Flow

```
+---------------------------------------------------------------------------------------+
|                                  Buildful AI Agent                                    |
|   (Estimating Agent, Submittal Classifier, Takeoff Calculator, Change Order Bot)      |
+---------------------------------------------------------------------------------------+
                                           |
                                           v  Tool Call / Subprocess Dispatch
+---------------------------------------------------------------------------------------+
|                    Bartholomew Keystone Execution Guard (In-Process)                  |
|                                                                                       |
|   1. In-Process AST Gate (<35µs SLA)                                                  |
|      - Verify file path containment (stay inside /workspace/buildful_project)         |
|      - Enforce spend cap ($25,000 max change order authorization limit)               |
|      - Block destructive shell syntax (rm, mkfs, curl | bash)                         |
|                                                                                       |
|   2. Bartholomew Vault (Zero-Egress Surrogates)                                       |
|      - Replace contractor EIN [12-3456789] -> [anon-ein-883a9f]                       |
|      - Replace client home address -> [anon-addr-c3b91a]                             |
|      - Real values restored in-memory strictly during local dispatch                  |
|                                                                                       |
|   3. RFC 8785 Ed25519 Merkle Receipt Engine                                           |
|      - Cryptographic leaf committed to immutable audit log                            |
+---------------------------------------------------------------------------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
             [VERDICT: ALLOW]                              [VERDICT: VETO]
                    |                                             |
                    v                                             v
       Local Downstream Execution                   Abort Execution (Exit Code 126)
       (ERP, Procore, BIM Server)                   Push Alert to Mobile HUD
```

---

## Implementation Pattern for Buildful Services

### 1. In-Process Guard Integration (Node.js / TypeScript)

```javascript
import { enforceToolBoundary } from 'btp-guard';

export async function processContractorBid(bidPayload) {
  // 1. Verify safety invariants before dispatch
  const boundaryCheck = enforceToolBoundary('submit_bid', {
    amount_usd: bidPayload.amount,
    subcontractor_id: bidPayload.subcontractorId,
    target_erp: 'procore'
  }, {
    maxSpendLimit: 25000.00,
    disallowedActions: ['direct_wire_transfer', 'override_spec']
  });

  if (!boundaryCheck.allowed) {
    throw new Error(`[BTP VETO] Bid rejected by security guard: ${boundaryCheck.reason}`);
  }

  // 2. Dispatch verified transaction with cryptographic receipt
  return await dispatchToERP(bidPayload, boundaryCheck.merkle_turn_receipt);
}
```

### 2. Format-Preserving Vaulting of Contractor PII

```javascript
import { scrubSensitiveCredentials } from 'btp-guard';

export function sanitizeSubcontractorSubmittal(documentText) {
  // Automatically detects and tokenizes SSNs, EINs, bank accounts, and addresses
  const vaultResult = scrubSensitiveCredentials(documentText);
  return {
    safePromptText: vaultResult.data,
    redactionCount: vaultResult.redactionCount
  };
}
```

---

## Compliance & Insurance Certification
By integrating Bartholomew, Buildful enterprise deployments automatically inherit:
1. **SOC 2 Type II CC6.1 & CC6.8**: Logical access boundaries for all AI agent tool calls.
2. **ISO/IEC 27001:2022 §A.8.28**: Secure autonomous tool-calling framework.
3. **Builder's Risk Insurance Audit Readiness**: Every automated takeoff modification is bound to an immutable Ed25519 cryptographic Merkle leaf.
