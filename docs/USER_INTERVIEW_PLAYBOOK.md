# Bartholomew Protocol — 10-15 User Interview Playbook
**Customer Discovery & Design Partner Sprint (Target: 15 Interviews in 14 Days)**

---

## 1. Sprint Objective

Diagnose why users install Bartholomew but drop off before purchasing. Specifically:
1. Identify the **exact trigger** that motivated installation.
2. Discover the **exact friction point** that blocked activation on a real repository.
3. Validate the **buyer persona** (Engineering Lead vs. Individual Dev vs. Security Lead).
4. Recruit **1–3 Paid Design Partner Pilots ($950 / $199/mo)**.

---

## 2. Outreach Cadence & Templates

### A. Direct Message / Email Outreach
**Subject**: *15-min chat on your AI coding agent guardrails? (Coffee on me)*

> "Hi [Name],
> 
> I noticed you installed the Bartholomew Guard extension / CLI recently. First off—thank you for trying it!
> 
> I'm the creator of Bartholomew. I'm not reaching out to pitch or sell you anything. We are running a focused 2-week research sprint speaking with developers and engineering leads who are adopting AI coding agents (Claude Code, Cursor, Windsurf, Copilot).
> 
> I’d love to ask you 4 or 5 quick questions about how your team manages agent permissions and risks.
> 
> Would you have 15 minutes this week for a brief Zoom or async chat? Happy to send a $25 Amazon card or buy your coffee as a thank you for your time.
> 
> Best,  
> [Your Name]  
> Founder, Bartholomew Protocol"

---

## 3. The 5 Core Discovery Questions

| # | Question | What We Are Listening For |
| :-: | :--- | :--- |
| **Q1** | *"What specific incident, fear, or policy requirement made you look for a tool like Bartholomew in the first place?"* | Was it an actual bad command run by an agent (e.g. wiped files), a company compliance rule, or mere curiosity? |
| **Q2** | *"When you installed it, did you test it on a throwaway script or in your team's real production repo?"* | If throwaway: what made them hesitate to point it at their real codebase? Lack of trust? Fear of breaking builds? |
| **Q3** | *"During your first run, was it immediately obvious what was protected and what was not?"* | Tests the 'Zero-to-Proof' activation gap. Did they feel the product actually worked, or was it a black box? |
| **Q4** | *"If you aren't using it daily right now, what was the primary blocker?"* | Was it false positives, complex configuration, lack of multi-dev sync, or did they forget it existed? |
| **Q5** | *"Who in your organization decides what tools coding agents can touch? If this gave your team one shared policy, fail-closed pre-commit hooks, and a clean audit log for security, would you or your lead expense $199/mo for it?"* | Tests price tolerance, the real economic buyer, and appetite for the Hands-On Paid Pilot. |

---

## 4. The Pivot to Paid Pilot (The Closing Bridge)

If the interviewee expresses active concern about coding agents running uncontrolled in their repositories:

> *"That matches what we're hearing from other engineering leads. In fact, we are onboarding three small engineering teams this month for a hands-on 30-day pilot:*
> * *We personally configure your team's custom security boundaries in a 30-minute kickoff.*
> * *We guarantee zero developer disruption on routine coding commands.*
> * *We deliver a CISO/SOC2-ready cryptographic audit dossier of all agent tool actions.*
> * *It's a flat $950 one-time pilot with a 100% money-back guarantee.*
> 
> *Would your team be open to exploring that as one of our design partners?"*

---

## 5. Interview Tracking Scorecard

| User / Company | Role / Title | Primary Agent Used | Activation Blocker | Would Pay $199/mo? | Pilot Next Step |
| :--- | :--- | :--- | :--- | :--- | :--- |
| *Example 1* | Eng Lead (Series A) | Cursor + Claude Code | Didn't know if hooks worked | Yes (Sec review needed) | Sent Pilot Guide |
| *Example 2* | Solo Dev | Copilot CLI | Too complex config | No (Prefers free) | Disqualified |
| *Example 3* | Platform Lead (50 devs) | Windsurf + Custom | Needs centralized audit log | Yes (Approved budget) | Booked Kickoff Call |
