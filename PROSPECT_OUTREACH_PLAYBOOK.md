# Bartholomew 30-Day Prospect Outreach Playbook & Tracker

## Target Profile & Qualification Criteria

We are not contacting random startup founders or general developers. Target exactly **30 technical decision-makers** who meet all three criteria:
1. **Active Coding Agent Usage**: Their engineering team uses Cursor, Windsurf, Claude Code, or custom MCP servers in development/staging.
2. **High-Risk Resource Access**: The agents have access to real databases, bash shells, internal APIs, or deployment repositories.
3. **Economic Buyer**: Holds budget to spend $1,000 to $3,500 without enterprise procurement approval.
   - Title: VP of Engineering, Head of Platform Engineering, Lead Product Security Engineer, or CTO at a Series A/B tech company.

---

## 1. The Outreach Message (Short, Technical, Direct)

Send individually via LinkedIn, direct email, or engineering community channels. Do not use automated mass mailers.

### Subject Line Options:
- Question on your Cursor / Claude Code MCP security boundary
- Guardrailing agent database access in Cursor
- AI coding agent execution boundaries

### Email / Message Body:
```text
Hi [First Name],

Noticed your team is building with [Cursor / Claude Code / MCP tooling].

We built an in-process execution boundary (Bartholomew) that deterministically stops AI coding agents from dropping database tables, chaining dangerous bash commands, or leaking API keys in-process (<35µs latency), and produces signed audit receipts.

Are you currently relying on system prompts to stop agents from executing destructive commands, or do you have an in-process gate between the agent and your databases/APIs?

Happy to share our 10-second open-source demo command if this is on your security radar.

Best,
Itsub Alemayehu
Founder, Bartholomew
https://github.com/ivegotahunnitonit/bartholomew
```

---

## 2. The 6 Discovery Questions (On the Call / Demo)

When a prospect responds, do not pitch features. Ask these 6 questions to identify if they have an urgent, budgeted problem:

1. **Access Scope**: *"What specific tools, databases, or terminal environments do your developers' AI agents have permission to touch today?"*
2. **Current Controls**: *"What prevents an agent with shell or SQL access from executing a destructive query or leaking an API key under prompt injection?"*
3. **Testing Rigor**: *"How do you currently test or verify those controls—manual spot checks, or automated adversarial test cases?"*
4. **Incident History**: *"Have you had any near-misses or incidents yet (e.g. unintended data mutation, runaway loop, or credential committed to Git)?"*
5. **Ownership & Budget**: *"Who owns the security and operational risk for AI developer tooling on your team, and is there budget allocated to lock this down?"*
6. **Required Evidence**: *"What specific evidence would your team require before approving an in-process security boundary?"*

---

## 3. The 30-Prospect Outreach Tracker

| # | Company Name | Contact Title | Stack / Surface | Attack Vector & Exposure | Outreach Hook | Status |
| :- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **E2B** | Head of Platform / Security | Agent sandboxes, MCP stdio | Sandbox breakout, credential persistence across sessions | In-process AST gating and capability passkeys inside E2B agent micro-VMs | Target |
| 2 | **PostHog** | VP Engineering / Infra Lead | Cursor, Claude Code, ClickHouse, Postgres | Agent writing un-scoped SQL or altering schemas via developer IDEs | Hard AST blocking of `DROP TABLE` / destructive queries in local MCP proxy | Target |
| 3 | **Modal Labs** | Head of Security / Staff SecEng | Serverless Python, Agent tool execution | Untrusted agent payloads attempting egress or environment variable dumping | Sub-35µs zero-latency secret tokenization before process execution | Target |
| 4 | **Braintrust** | CTO / Head of Security | LLM Proxy, Agent evals, MCP connectors | Prompt injection breaking through system prompts to trigger privileged tools | Cryptographic Keystone passkeys with SQLite replay prevention | Target |
| 5 | **Supabase** | Head of Platform / DB Security | Official Supabase MCP server, Postgres | Agent connecting via MCP executing destructive DDL (`DROP/TRUNCATE`) | Direct MCP proxy guard on Supabase MCP server stdio channel | Target |
| 6 | **Neon** | VP Engineering / Product Security | Neon MCP Server, Serverless Postgres | Agent branch mutations or data exfiltration across development databases | In-process capabilities gating write operations without cloud latency | Target |
| 7 | **Warp** | Head of Security / VP Engineering | Agentic terminal, autonomous shell execution | Destructive shell command injection (`rm -rf`, piped curls, credential exfiltration) | Kernel/in-process AST gating of shell command execution | Target |
| 8 | **CrewAI** | CTO / Head of Engineering | Multi-agent swarms, autonomous tool dispatch | Cascading tool hallucination and unauthorized file system writes | Scoped capability passkeys passed to subagents with auto-expiration | Target |
| 9 | **LangChain** | Head of Platform / Security | LangGraph, LangSmith, MCP integrations | Autonomous agent executing privileged database or API mutations | Zero-egress AST boundary wrapping standard MCP client stdio | Target |
| 10| **Mintlify** | CTO / VP Engineering | AI documentation agents, GitHub sync bots | Automated PR bots writing unsanitized scripts or leaking workspace secrets | In-process secret masking and integrity attestation on repo edits | Target |
| 11| Replit | Head of Security / Agent Infra | Agent workspaces, cloud containers | Agent privilege escalation in multi-tenant dev environments | Container sandbox AST supervisor | Pending |
| 12| Cognition (Devin) | Head of Platform / Security | Full-stack autonomous software agents | Devin executing unauthorized git force pushes or external network curls | Single-use Keystone passkeys for privileged tool dispatch | Pending |
| 13| Poolside | VP Engineering / SecEng | Local code generation models, internal IDE | Model hallucinations executing destructive system modifications | In-process tokenizer and POSIX AST blocker | Pending |
| 14| Augment Code | Head of Security / Platform Lead | Enterprise code assistant, codebase indexing | Enterprise source code exfiltration or unsanitized AST evaluation | In-memory zero-egress secret tokenization | Pending |
| 15| Sourcegraph (Cody) | VP Engineering / Head of Security | Cody agent, enterprise repo context | Cross-repo data leakage and arbitrary MCP tool invocation | Hard MCP stdio interceptor with capabilities manifest | Pending |
| 16| Continue.dev | Lead Architect / Security Lead | Open source VS Code / JetBrains agent | Local LLM calling unverified CLI tools in developer terminal | Local BTP daemon checking AST in <35 microseconds | Pending |
| 17| Cursor (Anysphere) | Head of Security / Platform | Cursor Composer, MCP server integration | Composer executing destructive commands during long generation loops | In-process proxy blocking schema drops & shell escapes | Pending |
| 18| Factory.ai | CTO / VP Engineering | Autonomous Droids, SDLC automation | Autonomous PR droids deploying vulnerable or malicious code changes | Merkle-signed tamper-evident audit receipts for agent runs | Pending |
| 19| Magic.dev | Head of Platform / SecOps | Ultra-long context coding models, agent VMs | Unconstrained tool invocations during multi-file refactoring | Capabilities matrix with atomic budget controls | Pending |
| 20| Decagon | VP Engineering / Head of Trust | Enterprise customer service agents, live DBs | Agent executing unauthorized CRM/DB mutations under adversarial input | Deterministic schema and action gating before database driver | Pending |
| 21| Sierra | Head of Platform / Staff SecEng | Conversational enterprise agents, API tools | Agent hallucinating API parameter values with administrative privileges | Schema parameter validation with cryptographic attestation | Pending |
| 22| Resend | VP Engineering / Infra | AI email agents, API key infrastructure | Leakage of customer API keys through agent terminal contexts | In-process regex and entropy secret masking | Pending |
| 23| Vercel | Head of Security / AI SDK Lead | Vercel AI SDK, AI tool calling, Serverless | Edge function tool calls executing unauthorized database queries | Zero-latency in-process proxy for AI SDK tool execution | Pending |
| 24| Prisma | VP Engineering / Platform | Prisma ORM, Accelerate, Pulse, AI tools | AI agent modifying schema.prisma or running destructive migrations | AST gating of DDL statements (`DROP`, `ALTER`, `TRUNCATE`) | Pending |
| 25| Drizzle | Lead Maintainer / SecOps | Drizzle ORM, Turso / libSQL MCP | Agent executing unbounded raw SQL queries | AST evaluation of SQL queries before libSQL execution | Pending |
| 26| PlanetScale | VP Engineering / DB Platform | Branching MySQL, AI DB tooling | Accidental schema drops across non-branch development targets | Single-use passkey verification for schema mutation tools | Pending |
| 27| Inngest | CTO / Head of Platform | Durable execution for AI workflows | Agent workflow step replaying sensitive actions without authorization | Atomic SQLite replay protection preventing passkey reuse | Pending |
| 28| Temporal | Head of Developer Experience | Workflow orchestration for AI agents | Runaway agent activities spawning uncontrolled child workers | Keystone passkey scoping with depth and count budgets | Pending |
| 29| Trigger.dev | Founder / Head of Engineering | Background jobs & AI tasks | Long-running background agent leaking environment secrets | Process environment tokenization with zero egress | Pending |
| 30| Daytona | CTO / Head of Platform | Development environment management | Autonomous agent escaping isolated workspace containers | Host-level AST interceptor for agent command lines | Pending |

---

## 4. Objection Handling Matrix

| Prospect Objection | Root Cause | Tactical Response |
| :--- | :--- | :--- |
| **"System prompts are enough to stop the agent."** | False sense of security. | *"Run our 10-second demo (`npx @bartholomew/mcp-shield demo`). We show prompt injection bypassing system prompts to drop tables, while our AST gate stops it in <35µs."* |
| **"We don't have budget for this."** | Low perceived urgency. | *"Understood. If you're open to it, we can run our $1,000 3-day assessment to map your high-risk agent vectors before you allocate tooling budget."* |
| **"Will this slow down our developers?"** | Latency fear. | *"No cloud roundtrip. Bartholomew evaluates in-process in <35 microseconds. Developer workflows see zero perceptible latency."* |
| **"We can't add another vendor right now."** | Procurement block. | *"The core MCP Shield and demo are open source. We can structure this as an assessment with no ongoing vendor dependency."* |
| **"We use Docker containers for isolation."** | Sandbox vs tool boundary confusion. | *"Containers stop host escapes, but they don't stop the agent inside the container from dropping your staging database or exfiltrating your database URL. That requires an in-process tool gate."* |

---

## 5. Day 30 Hard Decision Criteria

At Day 30, evaluate strictly based on signed commitments and payments:
- **Strong Signal**: 2 paid engagements ($2,000+ collected) or 1 paid pilot + recurring commitment. Continue and build what they use.
- **Mixed Signal**: Clear acknowledgment of risk, but procurement or trust is blocked. Consider embedded partnership.
- **Pivot / Shutdown Signal**: 30 qualified approaches and demonstrations yield zero purchases and zero introductions to budget owners. Stop development and pivot to a new project.

---

## 6. Ready-to-Send Outreach Drafts for Top 5 Targets

### Draft 1: To E2B (Head of Platform / Security)
```text
Subject: In-process tool boundary inside E2B agent sandboxes

Hi [Name],

Saw the rapid adoption of E2B for autonomous coding sandboxes.

One pattern we're seeing across teams running agents in sandboxes: while the VM contains host escapes, the agent inside still has unconstrained access to mounted secrets, environment variables, and connected databases.

We built an in-process execution boundary (Bartholomew) that sits on the stdio channel of agent tools. It deterministically blocks destructive commands (DROP TABLE, shell escapes, secret leakage) in under 35 microseconds without leaving the process.

You can verify the 4 core scenarios in 10 seconds right now:
  npx @bartholomew/mcp-shield demo

Would this be interesting to test inside your sandbox execution environments?

Best,
Itsub Alemayehu
Founder, Bartholomew
https://github.com/ivegotahunnitonit/bartholomew
```

### Draft 2: To PostHog (VP of Engineering / Infra Lead)
```text
Subject: Guardrailing Cursor / Claude Code database access

Hi [Name],

Love PostHog's transparency around internal AI engineering adoption.

As more engineers give Cursor or Claude Code direct access to local/staging databases and internal APIs, a common concern is accidental schema mutations or unvetted queries when an agent misinterprets a prompt.

We built an open-source MCP stdio proxy (Bartholomew) that enforces an in-process AST boundary. When an agent attempts a DROP TABLE or destructive DDL, it gets blocked in <35µs and generates a cryptographically signed Merkle audit receipt.

No cloud round-trips, no developer latency. You can run the live test locally:
  npx @bartholomew/mcp-shield demo

Would you be open to seeing our 10-second live test script?

Best,
Itsub Alemayehu
Founder, Bartholomew
https://github.com/ivegotahunnitonit/bartholomew
```

### Draft 3: To Modal Labs (Head of Security / Staff SecEng)
```text
Subject: Zero-latency secret tokenization for agent tool dispatch

Hi [Name],

Modal's execution speed is best-in-class, especially for AI container dispatch.

When developers run agentic tool execution on Modal, one exposure vector is agents attempting environment variable exfiltration or unauthorized file reads when processing untrusted context.

We developed an in-process execution guard that tokenizes environment variables before process launch with zero outbound network egress, coupled with capability passkeys that reject tool replays via atomic SQLite.

Everything runs in-process in <35 microseconds:
  npx @bartholomew/mcp-shield demo

Open to seeing a 10-second CLI demonstration of the boundary in action?

Best,
Itsub Alemayehu
Founder, Bartholomew
https://github.com/ivegotahunnitonit/bartholomew
```

### Draft 4: To Braintrust (CTO / Head of Product Security)
```text
Subject: Enforcing in-process capabilities for agent evaluations

Hi [Name],

Following Braintrust's work on AI evaluation harnesses and LLM proxies.

When evaluating autonomous agents executing live tools (DB queries, bash execution), software teams need deterministic boundaries ensuring an adversarial eval case doesn't execute out-of-scope mutations.

We built Bartholomew Keystone: single-use cryptographic capability passkeys with in-process SQLite replay prevention and AST query gating. If an agent tries to replay an authorized passkey or drop a schema, it is blocked immediately with a signed audit log:
  npx @bartholomew/mcp-shield demo

Would love to share our 4-scenario acceptance test if this aligns with your agent evaluation security roadmap.

Best,
Itsub Alemayehu
Founder, Bartholomew
https://github.com/ivegotahunnitonit/bartholomew
```

### Draft 5: To Supabase (Head of Platform / DB Security)
```text
Subject: Hard boundary on the Supabase MCP Server

Hi [Name],

The new Supabase MCP server is a huge unlock for Cursor and Claude Code users.

However, giving coding agents direct stdio access to Postgres creates immediate risk: prompt injection or hallucinated migrations can fire DROP TABLE or TRUNCATE on connected databases.

We built an open-process MCP shield (`packages/bartholomew-vault/bin/mcp-shield.js`) that wraps standard MCP server stdio streams. It parses SQL AST in-process in <35 microseconds, permitting legitimate queries while deterministically rejecting destructive DDL:
  npx @bartholomew/mcp-shield demo

Happy to send over the GitHub link or run through a 2-minute demo if relevant.

Best,
Itsub Alemayehu
Founder, Bartholomew
https://github.com/ivegotahunnitonit/bartholomew
```

---

## 7. 3-Minute Live Demo Cheat Sheet (For Screening Calls)

When a prospect agrees to a brief Zoom/Huddle or asks for proof:

1. **Minute 1: The Context (Terminal Open)**
   - *"When you give Cursor or Claude Code an MCP tool or database connection, system prompts like 'don't drop tables' fail under adversarial input or complex multi-turn context."*
2. **Minute 2: Run the Live Demo Command**
   - Run: `node packages/bartholomew-vault/bin/mcp-shield.js demo` (or `npx @bartholomew/mcp-shield demo`)
   - Point out the 4 passing scenarios in the terminal output:
     - Scenario 1: Legitimate query `SELECT * FROM users` -> PERMITTED (<35µs).
     - Scenario 2: Adversarial query `DROP TABLE users` -> BLOCKED (<35µs AST intercept).
     - Scenario 3: Unauthorized replay attack with same passkey -> REJECTED (atomic SQLite replay guard).
     - Scenario 4: Credential injection test -> TOKENIZED (zero egress).
3. **Minute 3: The Offer & Close**
   - *"We deliver this as a 3-day fixed-scope boundary assessment for $1,000 where we map all agent tool vectors in your repos and generate a cryptographic audit report, or a 14-day implementation pilot for $3,500 that wraps your staging MCP servers with zero developer latency. Which of those addresses your current risk faster?"*
