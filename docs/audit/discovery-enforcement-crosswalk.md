# Bartholomew BTP v6.5.6 — Discovery to Enforcement Crosswalk

**Document Identifier**: `docs/audit/discovery-enforcement-crosswalk.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Audit Baseline Commit**: `729b6f2` / `a6ec74f`  
**Audit Mode**: Evidence Closure & Cross-Domain Verification  
**Evaluation Date**: 2026-10-13  

---

## 1. Cross-Domain Mapping Principles

This crosswalk establishes whether each advertised discovery route maps to an implemented, verified enforcement path, and details the exact integration steps required to translate discovery into actual execution-boundary protection.

**Core Audit Principle**: Discovery advertises; enforcement protects. Discovering an advertised security capability does NOT automatically protect an execution boundary unless the advertised integration mechanism is activated.

---

## 2. Discovery to Enforcement Crosswalk Table

| Discovery Path | Advertised Capability | Enforcement Path | Relationship Verified? | Integration Step Required | Result |
|---|---|---|---|---|---|
| **D-01** (`agent-manifest.json`) | In-process AST invariant gate (<35µs latency), non-violent structured remediation envelopes, RFC 8785 Ed25519 turn receipts. | **E-02** (`agent_core.js`), **E-03** (`agent_protector.py`) | **YES** | Agent must invoke `enforceToolBoundary()` on proposed tool actions or wrap agents via `protect_agent()`. | **PASS** |
| **D-01** (`agent-manifest.json`) | Capability passkey tokens and spending bounds ($5 per-action, $25 daily). | **E-04** (`keystone_verifier.js`) | **YES** | Agent must obtain and submit a Keystone passkey token signed with the shared parent secret. | **PASS** |
| **D-02** (`mcp.json`) | MCP stdio proxy firewall, tool boundary audit, and AST execution gating. | **E-01** (`mcp-shield.js`), **E-02** (`agent_core.js`) | **YES** | Client configuration (e.g. Claude Desktop `claude_desktop_config.json` or Cursor) must configure `mcp-shield` as the proxy wrapper command. | **PASS** |
| **D-03** (`llms.txt`) | OWASP LLM02 secret scrubbing and format-preserving surrogate tokenization. | **E-05** (`vault_engine.js`) | **YES** | Agent pipeline must route prompt context through `VaultEngine.tokenize()` prior to upstream LLM submission. | **PASS** |
| **D-04** (`mcp-catalog.json`) | Universal tool catalog with sub-35µs evaluation annotations. | **E-01** (`mcp-shield.js`) | **PARTIAL** | Catalog exposes schemas; enforcement requires running tools through `mcp-shield` proxy. Direct tool execution remains unprotected. | **PARTIAL** |
| **D-05** (`cli.js discover`) | Supported execution boundaries: `mcp_stdio_proxy`, `universal_js_wrapper`, `python_framework_middleware`. | **E-01**, **E-02**, **E-03** | **YES** | Developer or agent must install `btp-guard` and configure the relevant wrapper in code or environment. | **PASS** |
| **D-06** (`test_unprompted_discovery.js`) | Autonomous tool boundary auditing and automated guard recommendations. | **E-02** (`enforceToolBoundary`) | **YES** | Harness demonstrates direct handoff from `auditToolBoundary()` recommendations to `enforceToolBoundary()`. | **PASS** |

---

## 3. Misleading Claims & Advisory Flags

1. **Automatic vs. Configured Protection**:
   - Manifests and documentation that state Bartholomew "sits between agents and tools" describe the *operational topology*, but enforcement is not magically ubiquitous at the OS level.
   - If an agent process invokes an uninstrumented subprocess directly (`child_process.spawn("rm -rf /")`), BTP does not intercept it unless the process runs inside `mcp-shield` or within an OS container sandbox.
   - **Remediation**: Documentation in `site/docs.html` and `site/llms.txt` accurately identifies that developers and agents must wrap tools or configure the MCP stdio proxy to establish the boundary.

2. **Editor Extension Scope**:
   - The VS Code / Open VSX extension provides pre-commit gates (`E-06`) and editor diagnostics. It does NOT intercept background MCP tool calls made by independent external CLI agents (e.g. Claude Code CLI or Aider) unless those tools run through the configured workspace proxy.
