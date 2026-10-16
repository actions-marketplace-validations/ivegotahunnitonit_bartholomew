/**
 * Bartholomew Red-Team Dataset Evaluator
 * Tests BTP enforcement against the 105,000+ vector HuggingFace benchmark
 * Dataset: https://huggingface.co/datasets/acnbartholomew/btp-agent-redteam-evals
 */

import https from 'https';
import readline from 'readline';
import { evaluateAndRemediate } from '../packages/npm_package/agent_core.js';
import fs from 'fs';

const SAMPLE_LIMIT = 500; // Evaluates a live slice of vectors
const DATA_URL = "https://huggingface.co/datasets/acnbartholomew/btp-agent-redteam-evals/raw/main/data/train-00000-of-00003.jsonl";

console.log('='.repeat(75));
console.log('EVALUATING BTP v6.5.6 AGAINST HUGGING FACE RED-TEAM DATASET');
console.log(`Endpoint: ${DATA_URL}`);
console.log(`Sample Batch: First ${SAMPLE_LIMIT} vectors`);
console.log('='.repeat(75));

const stats = {
  total: 0,
  tp: 0, // Malicious correctly blocked
  fp: 0, // Benign incorrectly blocked
  tn: 0, // Benign correctly allowed
  fn: 0, // Malicious incorrectly allowed
  byCategory: {},
  latencies: []
};

function processLine(line) {
  if (!line || !line.trim()) return;
  try {
    const item = JSON.parse(line);
    stats.total++;

    const cat = item.threat_category || "unknown";
    if (!stats.byCategory[cat]) {
      stats.byCategory[cat] = { total: 0, blocked: 0, allowed: 0 };
    }
    stats.byCategory[cat].total++;

    const t0 = process.hrtime.bigint();
    const result = evaluateAndRemediate(cat.includes("sql") ? "SQL" : "SHELL", item.payload);
    const t1 = process.hrtime.bigint();
    const latUs = Number(t1 - t0) / 1000;
    stats.latencies.push(latUs);

    const isBlocked = !result.allowed || result.verdict === "REMEDIATED" || result.verdict === "DENY";

    if (item.is_malicious) {
      if (isBlocked) {
        stats.tp++;
        stats.byCategory[cat].blocked++;
      } else {
        stats.fn++;
        stats.byCategory[cat].allowed++;
      }
    } else {
      if (!isBlocked) {
        stats.tn++;
        stats.byCategory[cat].allowed++;
      } else {
        stats.fp++;
        stats.byCategory[cat].blocked++;
      }
    }
  } catch (err) {
    // Malformed line
  }
}

function calculatePercentile(arr, p) {
  if (arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx].toFixed(1);
}

https.get(DATA_URL, (res) => {
  if (res.statusCode !== 200) {
    console.error(`Failed to download dataset: HTTP ${res.statusCode}`);
    process.exit(1);
  }

  const rl = readline.createInterface({ input: res, crlfDelay: Infinity });

  rl.on('line', (line) => {
    if (stats.total < SAMPLE_LIMIT) {
      processLine(line);
    } else {
      rl.close();
      res.destroy();
    }
  });

  rl.on('close', () => {
    const precision = stats.tp / (stats.tp + stats.fp || 1);
    const recall = stats.tp / (stats.tp + stats.fn || 1);
    const f1 = (2 * precision * recall) / (precision + recall || 1);

    console.log(`\nEVALUATION COMPLETED: ${stats.total} Vectors Tested`);
    console.log(`- True Positives (TP): ${stats.tp}`);
    console.log(`- False Positives (FP): ${stats.fp}`);
    console.log(`- True Negatives (TN): ${stats.tn}`);
    console.log(`- False Negatives (FN): ${stats.fn}`);
    console.log(`- Precision: ${(precision * 100).toFixed(2)}%`);
    console.log(`- Recall:    ${(recall * 100).toFixed(2)}%`);
    console.log(`- F1 Score:  ${f1.toFixed(4)}`);
    console.log(`- Median Latency: ${calculatePercentile(stats.latencies, 50)} µs`);
    console.log(`- p95 Latency:    ${calculatePercentile(stats.latencies, 95)} µs`);
    console.log(`- p99 Latency:    ${calculatePercentile(stats.latencies, 99)} µs`);

    console.log('\nResults by Threat Category:');
    for (const [cat, data] of Object.entries(stats.byCategory)) {
      console.log(`  - ${cat.padEnd(25)}: Total=${data.total}, Blocked=${data.blocked}, Allowed=${data.allowed}`);
    }

    const summaryReport = {
      evaluated_at: new Date().toISOString(),
      sample_size: stats.total,
      confusion_matrix: { tp: stats.tp, fp: stats.fp, tn: stats.tn, fn: stats.fn },
      metrics: {
        precision: Number((precision * 100).toFixed(2)),
        recall: Number((recall * 100).toFixed(2)),
        f1: Number(f1.toFixed(4)),
        median_latency_us: Number(calculatePercentile(stats.latencies, 50)),
        p95_latency_us: Number(calculatePercentile(stats.latencies, 95)),
        p99_latency_us: Number(calculatePercentile(stats.latencies, 99))
      },
      categories: stats.byCategory
    };

    fs.writeFileSync('tests/redteam_eval_summary.json', JSON.stringify(summaryReport, null, 2));
  });
}).on('error', (err) => {
  console.error("Network error fetching dataset:", err);
  process.exit(1);
});
