# Emergent Ventures Grant Application
## Project: Bartholomew Trust Protocol (BTP) & In-Process Agentic Runtime Protection
**Applicant**: Itsub Alemayehu / Bartholomew Security
**Requested Grant Amount**: $30,000 – $50,000 (Non-dilutive grant)
**Repository**: https://github.com/ivegotahunnitonit/bartholomew
**Live Packages**: 
- PyPI: https://pypi.org/project/btp-guard/6.4.3/
- npm (BTP Guard): https://www.npmjs.com/package/btp-guard
- npm (MCP Proxy): https://www.npmjs.com/package/mcp-proxy-guard
- Open-VSX: https://open-vsx.org/extension/bartholomew/bartholomew-guard-vscode

---

### 1. What are you working on? (Brief summary)
We built **Bartholomew Keystone Guard**, a sub-35-microsecond in-process execution firewall, credential scrubber, and cryptographic audit receipt engine for autonomous AI agents (Claude Code, Cursor, Devin, LangChain, AutoGen).

As frontier models transition from conversational chatbots into autonomous agents executing tools (shell commands, SQL queries, file manipulations), prompt-level guardrails fail completely against prompt injection, hallucinations, and multi-step tool breakout. 

Bartholomew intercepts tool invocations in-process across `stdio`, POSIX syscalls (`execve`, `connect`, `openat`), and CI/CD pipelines before arbitrary execution occurs. It vetoes catastrophic actions (`rm -rf /`, `DROP TABLE`, unauthorized exfiltration), scrubs API credentials in-flight, and issues RFC 8785 Canonical JSON Merkle execution receipts for SOC 2 compliance.

---

### 2. What have you already built? (Proof of execution)
This is not an idea or paper; it is fully functioning, battle-tested software:
1. **Sub-35µs AST Invariant Gating**: Pure in-process deterministic evaluation engine running in 13.6µs average latency (<35µs SLA).
2. **Model Context Protocol (MCP) Security Proxy**: `mcp-proxy-guard` running in Claude Desktop and Cursor, scrubbing high-entropy tokens and blocking malicious tool arguments before reaching local filesystems or databases.
3. **Enterprise CI/CD Action**: GitHub Action generating SARIF 2.1.0 alerts and Merkle root audit summaries on pull requests.
4. **Data Centre eBPF & Confidential Enclave Gate**: Remote attestation gateway supporting AMD SEV-SNP and AWS Nitro PCR measurements, paired with a Kubernetes DaemonSet for ring-0 container trajectory gating.
5. **Public Distribution**: Deployed and maintained across PyPI (`btp-guard`), npmjs (`btp-guard`, `mcp-proxy-guard`), and Open-VSX with 100+ passing automated test suites.

---

### 3. Why is this important right now?
The software industry is actively giving autonomous LLM agents direct shell access, database write privileges, and production terminal access. The dominant security paradigm relies on "system prompts" or cloud content filters, which cannot inspect raw OS syscalls or prevent database mutations once an agent hallucinates or suffers prompt injection.

Without deterministic, in-process runtime containment, the autonomous agent economy cannot scale into sensitive industries (finance, healthcare, defense, infrastructure). Bartholomew provides the missing mathematical layer: deterministic invariants enforced at zero-latency cost.

---

### 4. What will this grant fund?
The $30,000–$50,000 grant will fund:
1. **Air-Gapped & Hardware Enclave Verification**: Expanding our hardware attestation to native AMD SEV-SNP and Intel TDX bare-metal test clusters.
2. **Open-Source Tool Maintenance**: Keeping `mcp-proxy-guard` and `btp-guard` 100% free, sovereign, and open-source for researchers, individual developers, and non-profit projects.
3. **Comprehensive Red-Teaming Benchmark**: Packaging our 105,000-sample adversarial tool execution dataset into an open benchmark for evaluating frontier model tool safety.

---

### 5. Why you?
We have shipped production code across the entire stack: compiler-level AST gating, Go/Python eBPF kernel hooks, TypeScript IDE extensions, and cryptographic Merkle tree ledgers. We execute with extreme speed and have already delivered a working, compliant v6.4.3 runtime that any developer can install right now with one line.
