# Bartholomew BTP v6.5.6 — Discovery Path Inventory

**Document Identifier**: `docs/audit/discovery-path-inventory.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `729b6f2` (with extension publisher ID update at `a6ec74f`)  
**Audit Mode**: Evidence Closure & Adversarial Challenge  
**Evaluation Date**: 2026-10-13  

---

## 1. Inventory Scope and Principles

Discovery paths encompass all publicly exposed, machine-readable, or programmatic mechanisms through which an autonomous AI agent, developer, or orchestrator identifies, inspects, and evaluates BTP capabilities.

**Critical Audit Rule**: Discovery is an informational interface. Discovery does NOT enforce execution boundaries by itself. A passing discovery path proves discoverability, not runtime protection.

---

## 2. Discovery Path Inventory Table

| Discovery ID | Entry Point | Purpose | Source Evidence | Verified Behavior | Limitations & Gaps | Status |
|---|---|---|---|---|---|---|
| **D-01** | `site/.well-known/agent-manifest.json` & `site/agent-manifest.json` | Public machine-readable agent capability manifest | `site/.well-known/agent-manifest.json` | Returns schema version `2026-09-30`, `protocol_version: "6.5.6"`, `<35µs` latency target, and structured remediation envelope schema. | Host-local static file. Live website endpoint reflects prior deployment until site sync is completed by hosting provider. | **VERIFIED (Local)** / **PARTIALLY VERIFIED (Live)** |
| **D-02** | `site/.well-known/mcp.json` | MCP capability declaration and tool specification | `site/.well-known/mcp.json` | Valid MCP v1.0 schema declaring `btp_audit_tool_boundary` and `btp_enforce_tool_boundary` with input schemas. | Exposing tool metadata in a catalog does not guarantee that a client agent activates the proxy. | **VERIFIED** |
| **D-03** | `site/llms.txt` & `site/llms-full.txt` | Human- and agent-readable documentation | `site/llms.txt`, `site/llms-full.txt` | Provides BTP v6.5.6 architectural context, token conservation explanations, and integration instructions. | Textual documentation only; requires prompt ingestion by the consumer model. | **VERIFIED** |
| **D-04** | `site/mcp-catalog.json` & `site/tools.json` | Comprehensive MCP tool registry | `site/mcp-catalog.json`, `site/tools.json` | Declares 40 universal tool schemas with `BTP v6.5.6` annotations and latency bounds. | Catalog visibility only; does not provide runtime mediation without an active MCP client proxy. | **VERIFIED** |
| **D-05** | `npx btp-guard discover` (`--json`) | CLI-driven capability discovery | `packages/npm_package/cli.js` | Executes in Node CLI, prints formatted console summary or machine-readable JSON containing supported boundaries and covered threats. | Requires local Node runtime and network or pre-installed package to execute. | **VERIFIED** |
| **D-06** | `tests/discovery/test_unprompted_discovery.js` | Automated unprompted discovery evaluation | `tests/discovery/test_unprompted_discovery.js` | Programmatic simulation where agent filters capabilities by neutral keywords (`boundary`, `in-process`, `threat`) and recommends BTP only for risky tools. | Evaluates a deterministic programmatic harness rather than an open LLM reasoning agent. | **VERIFIED** |

---

## 3. Discovery Limitations & Adversarial Assessment

1. **Unprompted Discovery Limitations**:
   - The test harness in `D-06` uses synthetic keyword filtering across a mock registry array.
   - It proves that BTP's capability metadata is distinct, machine-readable, and correctly categorizes risky versus benign tool sets.
   - It does NOT prove that arbitrary third-party LLMs (e.g., GPT-4o, Claude 3.5, Gemini 1.5) will autonomously query external registries and install BTP without system prompt guidance.

2. **Metadata vs. Enforcement Separation**:
   - Every discovery path from `D-01` to `D-05` provides passive metadata.
   - An agent consuming this metadata must explicitly execute an integration step (e.g., wrapping tools via `protect_agent()` or routing requests through `mcp-shield`) to establish an actual security boundary.
