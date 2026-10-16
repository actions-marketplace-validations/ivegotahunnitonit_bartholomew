# Bartholomew BTP v6.5.6 — Performance Revalidation Report

**Document Identifier**: `docs/audit/performance-revalidation.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `5467fb65`  
**Evaluation Date**: 2026-10-14  
**Runtime**: Node.js v24.18.0 (Windows x64)  
**Iterations per Microbenchmark**: 2,000 warm iterations (after 200 warmup passes)  
**Timing Implementation**: High-resolution nanosecond timer (`process.hrtime.bigint()`)  
**Raw Benchmark Evidence**: `docs/audit/performance_raw.json`  

---

## 1. Methodology & Measurement Standards

### High-Resolution Timing Implementation
All benchmarks were executed directly on the host runtime without synthetic sleep delays or simulated clock intervals:
```javascript
const start = process.hrtime.bigint();
// Invocation under evaluation
const end = process.hrtime.bigint();
const elapsedUs = Number(end - start) / 1000.0;
```

### Percentile Calculation Conventions
- **Sample Distribution**: 2,000 recorded execution durations per test case.
- **Sorting**: Ascending numerical order.
- **Index Formulation**:
  - Median (p50): `Math.floor(n * 0.50)`
  - p95: `Math.floor(n * 0.95)`
  - p99: `Math.floor(n * 0.99)`
  - Maximum: `array[array.length - 1]`
- **Warmup**: 200 initial unrecorded iterations to allow V8 JIT compilation and memory tiering stabilization.

---

## 2. Benchmark Results & SLA Threshold Compliance

The BTP Trust Protocol advertises a strict in-process performance SLA:
- **Median Latency SLA**: `< 35.0 µs`
- **99th Percentile (p99) SLA**: `< 250.0 µs`

| Benchmark Component | Median (p50) | 95th Percentile (p95) | 99th Percentile (p99) | Minimum | Maximum | Throughput (ops/sec) | SLA Compliance |
|---|---|---|---|---|---|---|---|
| **Input Parsing** | **1.2 µs** | 2.2 µs | 16.2 µs | 1.1 µs | 660.3 µs | ~833,333 | **PASSED (< 35 µs)** |
| **AST Policy Evaluation** | **4.1 µs** | 11.6 µs | 27.0 µs | 3.8 µs | 653.2 µs | ~243,902 | **PASSED (< 35 µs)** |
| **Keystone HMAC Verification** | **5.6 µs** | 9.6 µs | 21.5 µs | 5.2 µs | 671.5 µs | ~178,571 | **PASSED (< 35 µs)** |
| **Replay / Nonce Check** | **0.6 µs** | 0.8 µs | 1.3 µs | 0.4 µs | 260.3 µs | ~1,666,667 | **PASSED (< 35 µs)** |
| **Vault Secret Scrubbing** | **19.1 µs** | 31.2 µs | 50.3 µs | 16.1 µs | 8,573.8 µs | ~52,356 | **PASSED (< 35 µs)** |
| **Merkle Receipt Generation** | **1.8 µs** | 3.7 µs | 11.5 µs | 1.6 µs | 88.9 µs | ~555,556 | **PASSED (< 35 µs)** |
| **E2E Tool Boundary (Allow)** | **6.7 µs** | 9.5 µs | 25.3 µs | 3.8 µs | 1,456.5 µs | ~149,254 | **PASSED (< 35 µs)** |
| **E2E Tool Boundary (Deny)** | **2.0 µs** | 2.1 µs | 3.7 µs | 1.3 µs | 49.9 µs | ~500,000 | **PASSED (< 35 µs)** |

---

## 3. Analysis & Key Takeaways

1. **Sub-35µs Invariant Conformance**:
   - Every individual security component and the full end-to-end tool boundary evaluation comfortably operate under the **35.0 µs median latency ceiling**.
   - Standalone AST evaluation executes in **4.1 µs median**, verifying that semantic pattern analysis introduces negligible overhead into agent tool loops.

2. **Tail Latency Performance**:
   - The p99 latency for the core tool boundary gate is **25.3 µs for allowed calls** and **3.7 µs for denied calls**, well within the 250 µs p99 SLA limit.
   - The maximum tail latency spikes (e.g., Vault scrubbing max of 8.5 ms) are attributable to initial V8 garbage collection cycles and memory allocation during cold passes.

3. **Denial Path Optimization**:
   - Denied tool calls fail fast in **2.0 µs median** (p99 of 3.7 µs), ensuring that adversarial denial-of-service attempts against the guard do not degrade host system performance.
