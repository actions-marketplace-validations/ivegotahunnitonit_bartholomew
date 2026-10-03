# Bartholomew Protocol — 10-15 User Interview Playbook & Pipeline
**Customer Discovery & Design Partner Sprint (Target: Close 1 Paid Team Pilot)**

---

## 1. Sprint Objective & Iron Rules

1. **Stop Building Breadth**: No new features, speculative protocol extensions, or PRs until **one paying team pilot ($199/mo or $950 one-time)** is closed and funded.
2. **Never Lead with a Demo**: Do not ask *"Do you like the idea?"* or show slides.
3. **Listen for the Real Problem**: Uncover what they currently do instead, what broke, and who owns the budget.
4. **Distinguish the Two Buyer Personas**:
   - **Developer Offer (User)**: *"Protect my own agent workflow with almost no setup."*
   - **Team Offer (Buyer)**: *"Control and audit agent actions across our repositories."*

---

## 2. The 5 Discovery Interview Questions

| # | Question | What We Are Listening For |
| :-: | :--- | :--- |
| **Q1** | *"What specific incident, policy requirement, or fear made you install Bartholomew / look for guardrails?"* | Actual bad experience (e.g. wiped files, leaked API key), company security compliance mandate, or casual curiosity. |
| **Q2** | *"When you tested it, did you run it on a throwaway script or in your team's real production codebase?"* | If throwaway: what made them hesitate? Fear of breaking developer flow? Lack of clarity on what it touches? |
| **Q3** | *"What do you currently do instead to ensure coding agents don't run dangerous commands or leak credentials?"* | If "nothing" or "we just watch the screen", probe the pain. If "we use prompt rules", probe how often prompts fail. |
| **Q4** | *"Who in your organization owns the budget and policy decisions for developer tooling and AI security?"* | Is it the VP of Eng, Head of Platform, Director of AppSec, or do individual devs expense tools? |
| **Q5** | *"If Bartholomew gave your team one shared repo policy (`.btp/policy.yaml`), fail-closed pre-commit hooks, and a CISO-ready audit log for $199/mo, would you start a 30-day pilot next Monday?"* | Tests real willingness to commit budget, a start date, and agreement on a measurable outcome. |

---

## 3. High-Priority Platform Lead Outreach Templates

### Lead 1: OpenHands (All-Hands AI / OpenDevin)
* **Target Role**: Platform & Security Maintainers (Graham Neubig / Robert Brennan / Xingyao Wang)
* **Channel**: Discord `discord.gg/openhands` (`#dev`, `#security`) / GitHub Issues
* **Offer**: Team Offer ($199/mo or $950 setup)
* **Message**:
> "Hi OpenHands team — quick question from a fellow developer building agent tooling:  
> We've seen multiple teams hit issues where autonomous coding agents accidentally run destructive commands (e.g. recursive deletes or modifying root configs in dev containers) or touch sensitive `.env` files.  
> We built a deterministic in-process execution gate that stops prohibited commands in under 35 microseconds before code touches the OS, with zero developer slowdown and signed audit receipts.  
> I'm not trying to sell you anything or do a slide demo. We're interviewing 10 platform teams on how they currently handle agent permission boundaries and who owns that policy. Would you have 10 minutes for a brief chat?"

### Lead 2: Continue.dev
* **Target Role**: Nate Sesti (CTO) / Ty Dunn (CEO/Eng)
* **Channel**: Discord `discord.gg/continue` (`#general`, `#extensions`) / GitHub Discussions
* **Offer**: Team Offer ($199/mo or $950 setup)
* **Message**:
> "Hey Nate & Ty — love what you've built with Continue.dev.  
> I'm reaching out because several teams deploying AI coding assistants in enterprise environments tell us their security/platform leads are hesitating because they lack centralized repository policy controls and tamper-proof audit trails of what the models actually run.  
> We're doing a 2-week research sprint talking with IDE and agent runtime leaders about who owns the budget for AI developer guardrails and what proof teams need to clear enterprise adoption.  
> Would you have 15 minutes this week for a candid conversation? Happy to share our findings."

### Lead 3: CrewAI Enterprise Swarms
* **Target Role**: Lead Platform Engineer / Core Team
* **Channel**: Discord `discord.gg/crewai` (`#crewai-chat`, `#integrations`) / GitHub Discussions
* **Offer**: Team Offer ($199/mo or $950 setup)
* **Message**:
> "Hi CrewAI team —  
> When running autonomous multi-agent crews with tool access, how are your enterprise users capping per-action financial spend and guaranteeing an agent won't execute an out-of-scope terminal command?  
> We're conducting a structured 10-team discovery sprint on agent runtime security: specifically whether teams solve this with prompt instructions vs. deterministic local execution boundaries, and who inside engineering teams typically holds budget for agent governance.  
> Could we borrow 10-15 minutes of your time for a quick research interview? No pitch or product demo."

### Lead 4: E2B (Code Execution Sandboxes)
* **Target Role**: Platform & Security Team (Vasek Mlejnsky's team)
* **Channel**: Discord `discord.gg/e2b` (`#general`, `#sandbox`) / Twitter `@e2b_dev`
* **Offer**: Team Offer ($199/mo or $950 setup)
* **Message**:
> "Hey E2B team —  
> We're seeing strong demand from developers executing untrusted LLM-generated code in sandbox environments who need sub-millisecond guarantees that destructive commands and credential scraping are blocked fail-closed.  
> We're running customer discovery interviews on how infrastructure teams currently draw the line between container isolation and in-process execution inspection. Would someone on your security or platform team have 15 minutes for a quick chat this week?"

### Lead 5: Aider (aider-chat)
* **Target Role**: Paul Gauthier (Creator/Lead)
* **Channel**: Discord `discord.gg/aider` / GitHub Issues
* **Offer**: Developer Offer (Zero-friction safety)
* **Message**:
> "Hi Paul — huge respect for Aider. The git integration is best-in-class.  
> We've been talking to developers using Aider in production repos who worry about agents committing accidentally staged secrets (.env, tokens) or running destructive bash scripts during automated testing.  
> We built a zero-overhead pre-commit and terminal invariant gate. We're interviewing 10 power users on their actual safety practices: what safeguards they currently rely on, and what would make them feel 100% confident letting agents run autonomous loops.  
> Would you have 10 minutes for a brief chat?"

---

## 4. Live Interview & Pilot Pipeline Scorecard

CLI management: `python -m btp_guard.interview_pipeline list`

| Lead ID | Organization | Target Role | Primary Pain Point | Buyer Persona | Current Status | Next Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`inbound-01`** | Series A Fintech (18 devs) | VP Engineering | SOC 2 audit questioning agent repo access | Platform Lead | **CALL_SCHEDULED** | Kickoff call: review custom `.btp/policy.yaml` |
| **`inbound-02`** | Healthcare SaaS (40 devs) | Dir. InfoSec | HIPAA fear: agents reading mock PHI or credentials | Security Lead | **CALL_SCHEDULED** | Scope review: in-flight regex secret masking |
| **`inbound-03`** | AI Agency / Dev Shop (12 devs) | Managing Partner | Contractors wiping client code or leaking keys | Tech Founder | **PILOT_PROPOSED** | Follow up on $199/mo Stripe link commitment |
| **`lead-openhands`** | All-Hands AI (OpenHands) | Core Maintainers | In-container bash jailbreaks, root file deletion | Platform Lead | **MESSAGE_SENT** | Check Discord `#security` response |
| **`lead-continue`** | Continue.dev | CTO / CEO | Enterprise platform adoption friction | Runtime Lead | **MESSAGE_SENT** | Check Discord `#extensions` response |
| **`lead-crewai`** | CrewAI Enterprise | Platform Lead | Runaway loops & unbounded tool spend | Platform Lead | **MESSAGE_SENT** | Check GitHub discussion response |
| **`lead-e2b`** | E2B Sandboxes | Security Team | In-sandbox sub-millisecond execution boundary | Infra Lead | **MESSAGE_SENT** | Check Discord `#sandbox` response |
| **`lead-aider`** | Aider (aider-chat) | Paul Gauthier | Pre-commit secret leakage & destructive commands | Senior Dev | **MESSAGE_SENT** | Monitor GitHub issue thread |

---

## 5. The Closing Seam: Activating the Paid Pilot

When an interviewee says: *"Yes, we need this for our team. How do we start?"*

1. **Send the Agreement / Checkout Link Immediately**:
   - **Monthly Team Pilot ($199/mo)**: [https://bartholomew.info/#pricing](https://bartholomew.info/#pricing)
   - **One-Time Guided Setup ($950)**: Invoice payable via Stripe.
2. **Book the 30-Minute Kickoff**:
   - Deliverable 1: Inspect repo with `python -m btp_guard.cli prove`.
   - Deliverable 2: Commit `.btp/policy.yaml` tailored to their stack.
   - Deliverable 3: Enable team pre-commit hooks.
3. **Weekly Check-In & Non-Repudiation Audit Dossier**:
   - Provide the cryptographic ledger export (`btp-guard audit`) proving zero unauthorized actions occurred.
