# Bartholomew BTP v6.5.6 Performance and Latency Report

**Document Identifier**: `docs/audit/performance.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Benchmarking Script**: `node tests/benchmark_complete_path.js`  
**Raw Data**: `docs/audit/performance_raw.json`  
**Execution Environment**: Node.js v24.18.0, Windows x64 (2,000 iterations per component with 200 warmup cycles)  
**Date**: 2026-10-13  

---

## 1. Executive Summary

Bartholomew provides deterministic, in-process runtime protection for AI agents with near-zero latency overhead. Across all core components:

- **Stated Typical Latency Target**: `< 35.0 µs`
- **Observed Typical Latency (Median)**: `0.6 µs` to `17.1 µs` (**VERIFIED: 100% within target**)
- **Stated Maximum SLA Target**: `< 250.0 µs`
- **Observed 99th Percentile Latency (p99)**: `1.4 µs` to `48.0 µs` (**VERIFIED: 100% within SLA**)

---

## 2. Component-Level Latency Breakdown

| Component | Median (p50) | 95th Percentile (p95) | 99th Percentile (p99) | Throughput (ops/sec) |
|---|---|---|---|---|
| **Input Parsing** (JSON-RPC tool payload) | `1.2 µs` | `2.2 µs` | `2.7 µs` | 833,333 |
| **AST Policy Evaluation** (Destructive regex & AST) | `4.7 µs` | `8.2 µs` | `17.7 µs` | 212,766 |
| **HMAC-SHA256 Verification** (Keystone Passkey) | `5.7 µs` | `8.1 µs` | `16.8 µs` | 175,439 |
| **Persistent Nonce & Replay Check** | `0.6 µs` | `0.8 µs` | `2.0 µs` | 1,666,667 |
| **Secret Tokenization & Scrubbing** (VaultEngine) | `17.1 µs` | `26.7 µs` | `48.0 µs` | 58,480 |
| **Merkle Turn Receipt Generation** (SHA-256 seed) | `2.0 µs` | `2.2 µs` | `7.9 µs` | 500,000 |

---

## 3. End-to-End Execution Boundary Overhead

| Tool Boundary Scenario | Median (p50) | 95th Percentile (p95) | 99th Percentile (p99) | Throughput (ops/sec) |
|---|---|---|---|---|
| **E2E Tool Boundary: Allowed Action** (`git status`) | `4.3 µs` | `8.0 µs` | `22.2 µs` | 232,558 |
| **E2E Tool Boundary: Denied Action** (`rm -rf /`) | `1.1 µs` | `1.2 µs` | `1.4 µs` | 909,091 |

Denied actions fail fast in `1.1 µs` median, immediately halting downstream execution without invoking OS subprocesses. Allowed actions complete evaluation, permission verification, and cryptographic Merkle receipt generation in `4.3 µs` median.

---

## 4. Verification Against Architectural Targets

1. **In-Process vs. External Proxy Distinction**:
   - The measurements above isolate in-process execution gate overhead.
   - Operating in-process avoids IPC context switching and HTTP network hops, ensuring that the security boundary does not introduce noticeable latency into model inference loops.
2. **Deterministic Guarantees**:
   - All evaluation paths are synchronous, non-blocking, and free of external network calls.
