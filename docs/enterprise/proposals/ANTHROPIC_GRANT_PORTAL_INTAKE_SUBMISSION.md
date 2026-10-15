# Anthropic Grant Portal & Partner Intake Submission
## Application Form Fields, Exact Copy-Paste Responses, and Technical Attestations

**Applicant Organization**: Bartholomew Security / Sovereign Autonomous Circularity Network  
**Project Name**: Bartholomew Keystone Guard (BTP v6.5.7)  
**Primary Contact**: `security@bartholomew.info` / `itsubsolomon`  
**Target Category**: AI Safety & Alignment, Agentic Runtime Infrastructure, Developer Tooling (MCP)  
**Target Program**: Anthropic Ecosystem Developer Grants / Claude Partner Network  
**Requested Amount**: $150,000 USD (Non-Dilutive Grant)  

---

### Field 1: Project Information

* **Project Title**:
  `Bartholomew Keystone: In-Process Agentic Runtime Protection (ARP) Gateway for Model Context Protocol (MCP)`
* **Primary URL / Website**:
  `https://bartholomew.info`
* **GitHub Repository**:
  `https://github.com/ivegotahunnitonit/bartholomew`
* **Package Registries**:
  - NPM Package: `https://www.npmjs.com/package/btp-guard` (v6.5.7 Live)
  - Open VSX Extension: `https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode` (v6.5.6 Live)
  - Open VSX Vault: `https://open-vsx.org/extension/Bartholomew/bartholomew-vault` (v6.5.6 Live)

---

### Field 2: Short Project Description (Elevator Pitch)
*(Under 100 words)*

> Bartholomew provides the first sub-35 microsecond, in-process Agentic Runtime Protection (ARP) gateway built specifically for Claude Desktop, Claude Code, and Model Context Protocol (MCP) agents. It intercepts tool executions at the operating system and process boundary, enforces deterministic AST invariants against destructive commands and prompt injections, redacts credentials before transmission using format-preserving tokenization, and cryptographically signs every agent turn with RFC 8785 Ed25519 Merkle receipts. Bartholomew removes the enterprise CISO barrier to deploying autonomous Claude agents in production.

---

### Field 3: Problem Statement
*(What core obstacle to AI adoption does your project solve?)*

> As Claude expands beyond chat into autonomous computer use and MCP tool orchestration, enterprise deployment is blocked by tool execution risk. CISOs cannot risk agents issuing destructive filesystem operations, running unauthorized SQL mutations (`DROP TABLE`), or transmitting live infrastructure secrets into model context windows.
> 
> Current guardrail solutions fail enterprise requirements:
> 1. **Cloud Moderation APIs (Lakera, NeMo, Azure AI)**: Add 150ms-400ms network round-trip latency to every single tool call and require outbound data egress, violating air-gapped and FedRAMP rules.
> 2. **Blunt Regex Redaction**: Replaces secrets with `[REDACTED]`, destroying referential integrity and breaking agent reasoning loops.
> 3. **Unverifiable Trajectories**: Provide no mathematical proof of compliance when enterprise auditors request proof-of-containment.

---

### Field 4: Technical Architecture & Claude / MCP Integration
*(Describe how your project integrates with Anthropic models and the Model Context Protocol)*

> Bartholomew operates as an invisible, in-process proxy between the Claude client (Claude Desktop, Claude Code, or custom agent runners) and MCP tool servers:
> 
> 1. **Stdio MCP Proxy (`npx btp-guard proxy`)**:
>    Intercepts JSON-RPC 2.0 tool requests over stdio/SSE in <35 microseconds. Incoming arguments are validated against strict AST grammars before reaching the tool.
> 2. **In-Flight Format-Preserving Vault**:
>    Detects PII, database connection strings, and cloud credentials in prompts. Replaces them with syntactically valid surrogates (`TKN_PROD_DB_98`) before payload transmission to Claude API. Real credentials never leave the local environment, resolving enterprise HIPAA/GDPR ingestion compliance.
> 3. **Sub-5 Microsecond Copy-on-Write Rollbacks**:
>    Captures an in-memory byte buffer prior to mutating tool execution. If an unauthorized disk or memory mutation is attempted, pristine state is restored in <5µs with zero orphan residuals.
> 4. **RFC 8785 Ed25519 Merkle Receipts**:
>    Every validated turn produces a deterministic cryptographic Merkle leaf, chaining the agent's prompt, tool inputs, and invariant verdicts into an immutable audit trail exportable directly to Vanta and Drata.

---

### Field 5: Current Traction & Live Artifacts
*(Evidence of technical execution and community distribution)*

* **NPM Registry**: Published as `btp-guard@6.5.7` with 35+ verified releases, supporting one-command deployment (`npx btp-guard auto`, `npx btp-guard hud`, `npx btp-guard test-drive`).
* **Open VSX / Cursor Marketplace**: Live with verified publisher `Bartholomew`, providing native IDE status-bar containment and AST linting.
* **Test Suite & Benchmarks**: 21/21 Node.js test cases passing, 5/5 Vault test cases passing, 14/14 consolidated audit control regression cases passing, and real-time Buildful construction agent integration verified.
* **Open Standard Catalog**: Manifests formatted for Smithery.ai catalog discovery (`smithery.yaml`) and Anthropic Claude Desktop auto-configuration.

---

### Field 6: Grant Funding Allocation & Milestones ($150,000 USD)

* **Milestone 1 ($45,000) — Weeks 1-4**:
  - Release official Anthropic MCP Certified Security Gateway package for TypeScript and Python.
  - Implement 1-click Claude Desktop configuration installer (`npx btp-guard init-claude`).
* **Milestone 2 ($55,000) — Weeks 5-8**:
  - Dedicated CLI containment wrapper for Anthropic `claude code`, providing fail-closed sandboxing for terminal actions and subshell invocations.
  - Expand deterministic AST rulesets for SQL (PostgreSQL, Snowflake, BigQuery), Docker, and Git commands.
* **Milestone 3 ($50,000) — Weeks 9-12**:
  - Enterprise Zero-Exfiltration Compliance Dossier exporter for SOC 2 Type II and HIPAA audits.
  - Public developer test harness and benchmarks validating <35µs latency under 100,000 consecutive MCP tool calls.

---

### Field 7: Applicant Team & Background

* **Core Focus**: High-performance systems security, deterministic compiler/AST validation, cryptographic audit loggers, and agent runtime sandboxing.
* **Contact Email**: `security@bartholomew.info`
* **Physical Location**: Calgary, Alberta, Canada / North America
* **Entity Type**: Independent Software Vendor (ISV) / Developer Tools Publisher
