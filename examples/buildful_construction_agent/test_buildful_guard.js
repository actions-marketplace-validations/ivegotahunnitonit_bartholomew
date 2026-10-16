/**
 * Test Suite for Buildful Construction Estimating Agent with Bartholomew Guard
 */
import { BuildfulEstimatingAgent } from './buildful_agent.js';

async function runTests() {
  console.log("================================================================================");
  console.log("TESTING BUILDFUL.AI AGENT WITH BARTHOLOMEW KEYSTONE INVARIANTS");
  console.log("================================================================================");

  const agent = new BuildfulEstimatingAgent({
    projectName: "Metropolitan Hospital Expansion",
    maxSingleApprovalUsd: 25000.0
  });

  // Test 1: Subcontractor PII & Tax Data Vaulting
  console.log("\n[1] Subcontractor W-9 & PII Sanitization Test:");
  const rawSubmittal = {
    contractor: "Apex Plumbing LLC",
    ein: "12-3456789",
    account: "routing_123456789_acc_987654321",
    api_key: "sk-proj-9999999999999999999999999999",
    scope: "HVAC chiller piping and valve manifold installation"
  };

  const sanitized = agent.sanitizeSubcontractorSubmittal(rawSubmittal);
  console.log("    Original Payload Keys Vaulted:", sanitized.secretsVaulted);
  if (sanitized.secretsVaulted > 0) {
    console.log("    [PASS] Sensitive financial and secret credentials scrubbed before cloud dispatch.");
  } else {
    throw new Error("Failed to vault sensitive credentials");
  }

  // Test 2: Safe Change Order Under Threshold ($18,500 < $25,000)
  console.log("\n[2] Safe Change Order Dispatch ($18,500):");
  const safeOrder = {
    orderId: "CO-1049",
    subcontractor: "Apex Plumbing LLC",
    amountUsd: 18500.00,
    trade: "Plumbing",
    targetFile: "estimates/phase2_plumbing.json"
  };
  const safeRes = await agent.dispatchChangeOrder(safeOrder);
  console.log("    Outcome:", safeRes.status);
  console.log("    Merkle Receipt:", safeRes.merkleReceipt ? safeRes.merkleReceipt.slice(0, 32) + "..." : "none");
  if (!safeRes.blocked && safeRes.success) {
    console.log("    [PASS] Authorized within Keystone $25k daily limits.");
  } else {
    throw new Error("Safe order should have been allowed");
  }

  // Test 3: Unapproved Financial Overrun ($68,000 > $25,000)
  console.log("\n[3] Financial Runaway Prevention ($68,000 > $25,000 threshold):");
  const overrunOrder = {
    orderId: "CO-1050",
    subcontractor: "Apex Plumbing LLC",
    amountUsd: 68000.00,
    trade: "Plumbing",
    targetFile: "estimates/phase2_plumbing.json"
  };
  const overrunRes = await agent.dispatchChangeOrder(overrunOrder);
  console.log("    Blocked:", overrunRes.blocked);
  console.log("    Rule ID:", overrunRes.rule_id);
  console.log("    Reason :", overrunRes.reason);
  if (overrunRes.blocked && overrunRes.rule_id === "BTP-KEY-SPEND-LIMIT") {
    console.log("    [PASS] Autonomous financial overrun prevented. Escalated to superintendent.");
  } else {
    throw new Error("Excessive change order should have been blocked");
  }

  // Test 4: Destructive Takeoff Attack (rm -rf)
  console.log("\n[4] Destructive File System Attack Interception:");
  const attackOrder = {
    orderId: "CO-1051",
    subcontractor: "Apex Plumbing LLC",
    amountUsd: 5000.00,
    trade: "Plumbing",
    targetFile: "rm -rf /projects/bim_models"
  };
  const attackRes = await agent.dispatchChangeOrder(attackOrder);
  console.log("    Blocked:", attackRes.blocked);
  console.log("    Rule ID:", attackRes.rule_id);
  if (attackRes.blocked) {
    console.log("    [PASS] In-process AST Gate blocked catastrophic CAD/BIM model deletion.");
  } else {
    throw new Error("Destructive file mutation should have been blocked");
  }

  console.log("\n================================================================================");
  console.log("ALL BUILDFUL.AI INTEGRATION TESTS PASSED (100% RELIABILITY)");
  console.log("================================================================================\n");
}

runTests().catch(err => {
  console.error("Test failed:", err);
  process.exit(1);
});
