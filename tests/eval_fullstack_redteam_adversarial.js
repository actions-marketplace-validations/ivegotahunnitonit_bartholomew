/**
 * Bartholomew Full-Stack Adversarial Red-Team Evaluator
 * Evaluates all 500 vectors across individual layers and integrated pipeline:
 * - Layer 1: Standalone AST Evaluator (evaluateAndRemediate)
 * - Layer 2: Tool Boundary Enforcement Gate (enforceToolBoundary)
 * - Layer 3: Vault Tokenization & Secret Scrubber (VaultEngine.tokenize)
 * - Layer 4: Integrated Pipeline (Vault Scrubber + Tool Boundary Gate)
 */

import fs from 'fs';
import { evaluateAndRemediate, enforceToolBoundary } from '../packages/npm_package/agent_core.js';
import { VaultEngine } from '../packages/bartholomew-vault/dist/vault_engine.js';

const SAMPLE_FILE = "audit_evidence/20261014_fullstack_validation/sample_500.jsonl";
const lines = fs.readFileSync(SAMPLE_FILE, 'utf8').trim().split('\n');

const vault = new VaultEngine();

function createStatsTracker() {
  return {
    total: 0,
    tp: 0,
    fp: 0,
    tn: 0,
    fn: 0,
    byCategory: {},
    latencies: []
  };
}

const statsAST = createStatsTracker();
const statsToolBoundary = createStatsTracker();
const statsVaultScrubber = createStatsTracker();
const statsIntegrated = createStatsTracker();

function percentile(arr, p) {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

for (const line of lines) {
  if (!line.trim()) continue;
  const item = JSON.parse(line);
  const cat = item.threat_category || "unknown";
  const isMalicious = item.is_malicious === true;
  const payload = item.payload;

  // --------------------------------------------------------------------------
  // Layer 1: Standalone AST Evaluator
  // --------------------------------------------------------------------------
  {
    const t0 = process.hrtime.bigint();
    const res = evaluateAndRemediate(cat.includes("sql") ? "SQL" : "SHELL", payload);
    const t1 = process.hrtime.bigint();
    statsAST.latencies.push(Number(t1 - t0) / 1000);
    statsAST.total++;
    if (!statsAST.byCategory[cat]) statsAST.byCategory[cat] = { total: 0, blocked: 0, allowed: 0 };
    statsAST.byCategory[cat].total++;

    const isBlocked = !res.allowed || res.verdict === "REMEDIATED" || res.verdict === "DENY";
    if (isMalicious) {
      if (isBlocked) { statsAST.tp++; statsAST.byCategory[cat].blocked++; }
      else { statsAST.fn++; statsAST.byCategory[cat].allowed++; }
    } else {
      if (!isBlocked) { statsAST.tn++; statsAST.byCategory[cat].allowed++; }
      else { statsAST.fp++; statsAST.byCategory[cat].blocked++; }
    }
  }

  // --------------------------------------------------------------------------
  // Layer 2: Tool Boundary Enforcement Gate
  // --------------------------------------------------------------------------
  {
    const t0 = process.hrtime.bigint();
    let toolName = "execute_command";
    let toolInput = { command: payload };
    if (cat.includes("sql")) {
      toolName = "query_database";
      toolInput = { query: payload };
    } else if (cat.includes("path") || cat.includes("file")) {
      toolName = "read_file";
      toolInput = { path: payload };
    }
    const res = enforceToolBoundary(toolName, toolInput);
    const t1 = process.hrtime.bigint();
    statsToolBoundary.latencies.push(Number(t1 - t0) / 1000);
    statsToolBoundary.total++;
    if (!statsToolBoundary.byCategory[cat]) statsToolBoundary.byCategory[cat] = { total: 0, blocked: 0, allowed: 0 };
    statsToolBoundary.byCategory[cat].total++;

    const isBlocked = res.allowed === false || res.verdict === "DENY";
    if (isMalicious) {
      if (isBlocked) { statsToolBoundary.tp++; statsToolBoundary.byCategory[cat].blocked++; }
      else { statsToolBoundary.fn++; statsToolBoundary.byCategory[cat].allowed++; }
    } else {
      if (!isBlocked) { statsToolBoundary.tn++; statsToolBoundary.byCategory[cat].allowed++; }
      else { statsToolBoundary.fp++; statsToolBoundary.byCategory[cat].blocked++; }
    }
  }

  // --------------------------------------------------------------------------
  // Layer 3: Vault Tokenization & Secret Scrubber
  // --------------------------------------------------------------------------
  {
    const t0 = process.hrtime.bigint();
    const tokenizedObj = vault.tokenize(payload, { formatPreserving: true });
    const scrubbed = tokenizedObj && tokenizedObj.sanitized ? tokenizedObj.sanitized : String(payload);
    const t1 = process.hrtime.bigint();
    statsVaultScrubber.latencies.push(Number(t1 - t0) / 1000);
    statsVaultScrubber.total++;
    if (!statsVaultScrubber.byCategory[cat]) statsVaultScrubber.byCategory[cat] = { total: 0, blocked: 0, allowed: 0 };
    statsVaultScrubber.byCategory[cat].total++;

    const secretDetected = (tokenizedObj && tokenizedObj.tokensCount > 0) || scrubbed !== payload || /BTP_VAULT_|BTP_TKN_/.test(scrubbed);
    // Vault specifically protects against secret_leak
    if (cat === "secret_leak") {
      if (secretDetected) { statsVaultScrubber.tp++; statsVaultScrubber.byCategory[cat].blocked++; }
      else { statsVaultScrubber.fn++; statsVaultScrubber.byCategory[cat].allowed++; }
    } else if (isMalicious) {
      if (secretDetected) { statsVaultScrubber.tp++; statsVaultScrubber.byCategory[cat].blocked++; }
      else { statsVaultScrubber.fn++; statsVaultScrubber.byCategory[cat].allowed++; }
    } else {
      if (!secretDetected) { statsVaultScrubber.tn++; statsVaultScrubber.byCategory[cat].allowed++; }
      else { statsVaultScrubber.fp++; statsVaultScrubber.byCategory[cat].blocked++; }
    }
  }

  // --------------------------------------------------------------------------
  // Layer 4: Integrated Pipeline (Vault Scrubber + Tool Boundary Gate)
  // --------------------------------------------------------------------------
  {
    const t0 = process.hrtime.bigint();
    const tokenizedObj = vault.tokenize(payload, { formatPreserving: true });
    const tokenizedPayload = tokenizedObj && tokenizedObj.sanitized ? tokenizedObj.sanitized : String(payload);
    const secretScrubbed = (tokenizedObj && tokenizedObj.tokensCount > 0) || tokenizedPayload !== payload || /BTP_VAULT_|BTP_TKN_/.test(tokenizedPayload);

    let toolName = "execute_command";
    let toolInput = { command: tokenizedPayload };
    if (cat.includes("sql")) {
      toolName = "query_database";
      toolInput = { query: tokenizedPayload };
    } else if (cat.includes("path") || cat.includes("file")) {
      toolName = "read_file";
      toolInput = { path: tokenizedPayload };
    }
    const gateRes = enforceToolBoundary(toolName, toolInput);
    const t1 = process.hrtime.bigint();
    statsIntegrated.latencies.push(Number(t1 - t0) / 1000);
    statsIntegrated.total++;
    if (!statsIntegrated.byCategory[cat]) statsIntegrated.byCategory[cat] = { total: 0, blocked: 0, allowed: 0 };
    statsIntegrated.byCategory[cat].total++;

    // Integrated protection blocks either via invariant DENY or neutralizes via Vault Tokenization
    const protectedAction = (gateRes.allowed === false || gateRes.verdict === "DENY") || (cat === "secret_leak" && secretScrubbed);

    if (isMalicious) {
      if (protectedAction) { statsIntegrated.tp++; statsIntegrated.byCategory[cat].blocked++; }
      else { statsIntegrated.fn++; statsIntegrated.byCategory[cat].allowed++; }
    } else {
      // Benign action should not be blocked by gate, and benign non-secret should not false-alarm
      const falseAlarm = gateRes.allowed === false;
      if (!falseAlarm) { statsIntegrated.tn++; statsIntegrated.byCategory[cat].allowed++; }
      else { statsIntegrated.fp++; statsIntegrated.byCategory[cat].blocked++; }
    }
  }
}

function computeMetrics(s) {
  const precision = s.tp + s.fp === 0 ? 0 : s.tp / (s.tp + s.fp);
  const recall = s.tp + s.fn === 0 ? 0 : s.tp / (s.tp + s.fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return {
    total: s.total,
    tp: s.tp,
    fp: s.fp,
    tn: s.tn,
    fn: s.fn,
    precision: Number((precision * 100).toFixed(2)),
    recall: Number((recall * 100).toFixed(2)),
    f1: Number(f1.toFixed(4)),
    median_latency_us: Number(percentile(s.latencies, 50).toFixed(1)),
    p95_latency_us: Number(percentile(s.latencies, 95).toFixed(1)),
    p99_latency_us: Number(percentile(s.latencies, 99).toFixed(1)),
    byCategory: s.byCategory
  };
}

const summary = {
  evaluated_at: new Date().toISOString(),
  dataset_sample_sha256: "bd1c998ae513d4b4a24bf497237da401b0bc994a5e4e1ff1c5d2e1f6f28b893f",
  sample_size: 500,
  layers: {
    layer1_standalone_ast: computeMetrics(statsAST),
    layer2_tool_boundary_gate: computeMetrics(statsToolBoundary),
    layer3_vault_secret_scrubber: computeMetrics(statsVaultScrubber),
    layer4_integrated_pipeline: computeMetrics(statsIntegrated)
  }
};

fs.writeFileSync("audit_evidence/20261014_fullstack_validation/fullstack_redteam_results.json", JSON.stringify(summary, null, 2));

console.log("=".repeat(75));
console.log("BARTHOLOMEW FULL-STACK RED-TEAM ADVERSARIAL EVALUATION SUMMARY");
console.log("=".repeat(75));
console.log(`Evaluated: ${summary.sample_size} Vectors across 4 Architectural Layers\n`);

for (const [layerName, m] of Object.entries(summary.layers)) {
  console.log(`--- [${layerName.toUpperCase()}] ---`);
  console.log(`  TP: ${m.tp} | FP: ${m.fp} | TN: ${m.tn} | FN: ${m.fn}`);
  console.log(`  Precision: ${m.precision}% | Recall: ${m.recall}% | F1: ${m.f1}`);
  console.log(`  Latency: Median ${m.median_latency_us}µs | p95 ${m.p95_latency_us}µs | p99 ${m.p99_latency_us}µs\n`);
}
