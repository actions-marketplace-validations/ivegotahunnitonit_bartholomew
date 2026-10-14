# Bartholomew BTP v6.5.6 — High-Concurrency Latency & Throughput Stress Test Report

## 1. Executive Summary

This report provides empirical evidence for the execution latency and throughput of the Bartholomew Trust Protocol (BTP v6.5.6) enforcement core under concurrent, multi-agent simulated load.

- **Benchmark Harness**: [`tests/benchmark_concurrency_stress.js`](file:///c:/Users/User/.gemini/antigravity/scratch/autonomous-circularity-network/tests/benchmark_concurrency_stress.js)
- **Machine-Readable Artifact**: [`docs/audit/concurrency-stress-results.json`](file:///c:/Users/User/.gemini/antigravity/scratch/autonomous-circularity-network/docs/audit/concurrency-stress-results.json)
- **Execution Date**: 2026-10-14
- **Runtime Environment**: Node.js v24.18.0, Windows 11 x64, Intel/AMD multi-core architecture

---

## 2. Experimental Methodology

- **Total Invocations**: 2,000 distinct tool-evaluation requests.
- **Concurrent In-Flight Batch Size**: 50 simultaneous parallel asynchronous promises.
- **Warmup Cycles**: 200 iterations prior to sample collection to allow JIT compilation and inline caching stabilization.
- **Timing Primitive**: `process.hrtime.bigint()` measuring high-resolution monotonic nanoseconds per evaluation.
- **Workload Composition**:
  - 50% Malicious / Adversarial Invariants (prohibited root deletions, nested base64 shell bypasses, SQL DDL `DROP TABLE`, reverse shells `nc -e`, AWS metadata SSRF `169.254.169.254`).
  - 50% Benign Operational Workloads (git status, npm test, scoped read operations, parameterized SQL SELECT, safe directory listings).

---

## 3. Empirical Results & SLA Adherence

| Metric | Measured Value | SLA Requirement | Verdict |
| :--- | :--- | :--- | :--- |
| **Total Invocations** | 2,000 | 2,000 | COMPLETED |
| **Throughput** | **140,828 ops/sec** | > 10,000 ops/sec | **EXCEEDED** |
| **Decision Accuracy** | **100.00% (2,000/2,000)** | 100.00% | **PASS** |
| **Minimum Latency** | **1.2 µs** | - | INFORMATIONAL |
| **Average Latency** | **5.81 µs** | < 50 µs | **PASS** |
| **Median (p50) Latency** | **5.1 µs** | **< 35.0 µs** | **PASS** |
| **90th Percentile (p90)** | **8.8 µs** | < 100.0 µs | **PASS** |
| **95th Percentile (p95)** | **11.5 µs** | < 150.0 µs | **PASS** |
| **99th Percentile (p99)** | **23.0 µs** | **< 250.0 µs** | **PASS** |
| **Maximum Latency** | 772.8 µs | - | Cold cache tail |

---

## 4. Key Takeaways

1. **Sub-35µs SLA Maintained Under Load**:
   - The median evaluation latency of **5.1 microseconds** is well within the 35µs SLA threshold.
   - 99% of all concurrent requests resolve in **23.0 microseconds or less**.
2. **Deterministic Gating Accuracy**:
   - Zero false passes (0 FP) across destructive and evasion payloads.
   - Zero false blocks (0 FN) on benign developer operations.
3. **Multi-Agent Readiness**:
   - Throughput of **140,828 operations per second** confirms that an in-process Bartholomew sentinel can mediate entire swarms of concurrent agents without becoming an execution bottleneck.
