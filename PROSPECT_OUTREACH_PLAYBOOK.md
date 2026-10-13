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

Happy to share our 10-second open-source demo script if this is on your security radar.

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

| # | Company Name | Contact Name | Title | Tooling Used | Date Contacted | Status | Primary Objection / Feedback | Next Action |
| :- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Target 1 | | VP Engineering | Cursor + Postgres | | Pending | | |
| 2 | Target 2 | | Head of Platform | Claude Code + AWS | | Pending | | |
| 3 | Target 3 | | Product Security | MCP Tools | | Pending | | |
| 4 | Target 4 | | CTO | Windsurf | | Pending | | |
| 5 | Target 5 | | Staff SecEng | Cursor | | Pending | | |
| 6 | Target 6 | | VP Engineering | Agent Swarms | | Pending | | |
| 7 | Target 7 | | Head of Platform | Custom MCP | | Pending | | |
| 8 | Target 8 | | CTO | LangGraph | | Pending | | |
| 9 | Target 9 | | Product Security | Cursor | | Pending | | |
| 10| Target 10 | | VP Engineering | Claude Code | | Pending | | |
| 11| Target 11 | | CTO | Custom Agents | | Pending | | |
| 12| Target 12 | | Head of Platform | Cursor + DB | | Pending | | |
| 13| Target 13 | | Sec Lead | MCP Stdio | | Pending | | |
| 14| Target 14 | | VP Engineering | Windsurf | | Pending | | |
| 15| Target 15 | | CTO | Cursor | | Pending | | |
| 16| Target 16 | | Head of Platform | Dev Tools | | Pending | | |
| 17| Target 17 | | Product Security | AI Agents | | Pending | | |
| 18| Target 18 | | VP Engineering | Claude Code | | Pending | | |
| 19| Target 19 | | CTO | AutoGen / Crew | | Pending | | |
| 20| Target 20 | | Head of Sec | Cursor | | Pending | | |
| 21| Target 21 | | VP Engineering | MCP Tools | | Pending | | |
| 22| Target 22 | | CTO | Windsurf | | Pending | | |
| 23| Target 23 | | Platform Lead | Staging DBs | | Pending | | |
| 24| Target 24 | | VP Engineering | Cursor | | Pending | | |
| 25| Target 25 | | Product Security | Claude Code | | Pending | | |
| 26| Target 26 | | CTO | Internal Agents | | Pending | | |
| 27| Target 27 | | Head of Platform | AI Infra | | Pending | | |
| 28| Target 28 | | Sec Lead | Dev Environment | | Pending | | |
| 29| Target 29 | | VP Engineering | Cursor | | Pending | | |
| 30| Target 30 | | CTO | Full Agent Stack | | Pending | | |

---

## 4. Objection Handling Matrix

| Prospect Objection | Root Cause | Tactical Response |
| :--- | :--- | :--- |
| **"System prompts are enough to stop the agent."** | False sense of security. | *"Run our 10-second demo (`node examples/demo_mcp_shield_live.js`). We show prompt injection bypassing system prompts to drop tables, while our AST gate stops it in <35µs."* |
| **"We don't have budget for this."** | Low perceived urgency. | *"Understood. If you're open to it, we can run our $1,000 3-day assessment to map your high-risk agent vectors before you allocate tooling budget."* |
| **"Will this slow down our developers?"** | Latency fear. | *"No cloud roundtrip. Bartholomew evaluates in-process in <35 microseconds. Developer workflows see zero perceptible latency."* |
| **"We can't add another vendor right now."** | Procurement block. | *"The core MCP Shield and demo are open source. We can structure this as an assessment with no ongoing vendor dependency."* |

---

## 5. Day 30 Hard Decision Criteria

At Day 30, evaluate strictly based on signed commitments and payments:
- **Strong Signal**: 2 paid engagements ($2,000+ collected) or 1 paid pilot + recurring commitment. Continue and build what they use.
- **Mixed Signal**: Clear acknowledgment of risk, but procurement or trust is blocked. Consider embedded partnership.
- **Pivot / Shutdown Signal**: 30 qualified approaches and demonstrations yield zero purchases and zero introductions to budget owners. Stop development and pivot to a new project.
