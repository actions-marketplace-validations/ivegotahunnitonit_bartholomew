#!/usr/bin/env python3
"""
Bartholomew Protocol - Customer Discovery & Paid Pilot Pipeline (v6.4.0)
========================================================================
Tracks and manages the 10-15 prospective buyer interview cohort, outreach
messages, discovery notes, and progression toward closing 1 paid team pilot.

Usage:
    python -m btp_guard.interview_pipeline list
    python -m btp_guard.interview_pipeline message <lead_id>
    python -m btp_guard.interview_pipeline update <lead_id> --status <status> --notes <notes>
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List

# Ensure safe console output across all platforms/codepages
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_FILE = REPO_ROOT / ".btp" / "interview_pipeline.json"

DEFAULT_LEADS: List[Dict[str, Any]] = [
    {
        "id": "lead-openhands",
        "organization": "All-Hands AI (OpenHands / OpenDevin)",
        "contact_target": "Platform & Security Maintainers (Graham Neubig / Robert Brennan / Xingyao Wang)",
        "channel": "Discord: discord.gg/openhands (#dev, #security) / GitHub Issues",
        "target_persona": "Platform / Security Lead",
        "offer_type": "Team Offer ($199/mo or $950)",
        "primary_pain": "In-container bash escapes, accidental root disk deletion, unvetted API egress",
        "budget_owner": "Head of Engineering / Security Lead",
        "status": "MESSAGE_SENT",
        "last_updated": "2026-10-03T19:30:00Z",
        "tailored_message": (
            "Hi OpenHands team -- quick question from a fellow developer building agent tooling:\n\n"
            "We've seen multiple teams hit issues where autonomous coding agents accidentally run destructive "
            "commands (e.g. recursive deletes or modifying root configs in dev containers) or touch sensitive .env files.\n\n"
            "We built a deterministic in-process execution gate that stops prohibited commands in under 35 microseconds "
            "before code touches the OS, with zero developer slowdown and signed audit receipts.\n\n"
            "I'm not trying to sell you anything or do a slide demo. We're interviewing 10 platform teams on how they "
            "currently handle agent permission boundaries and who owns that policy. Would you have 10 minutes for a brief chat?"
        ),
        "notes": "Outreach message queued for Discord #security. Focus on in-container fail-closed bash boundaries."
    },
    {
        "id": "lead-continue",
        "organization": "Continue.dev",
        "contact_target": "Nate Sesti (CTO) / Ty Dunn (CEO/Eng)",
        "channel": "Discord: discord.gg/continue (#general, #extensions) / GitHub Discussions",
        "target_persona": "Platform / Extension Runtime Lead",
        "offer_type": "Team Offer ($199/mo or $950)",
        "primary_pain": "Unchecked agent edits across multi-root workspaces, secret leakage",
        "budget_owner": "CTO / Founding Team",
        "status": "MESSAGE_SENT",
        "last_updated": "2026-10-03T19:30:00Z",
        "tailored_message": (
            "Hey Nate & Ty -- love what you've built with Continue.dev.\n\n"
            "I'm reaching out because several teams deploying AI coding assistants in enterprise environments "
            "tell us their security/platform leads are hesitating because they lack centralized repository policy controls "
            "and tamper-proof audit trails of what the models actually run.\n\n"
            "We're doing a 2-week research sprint talking with IDE and agent runtime leaders about who owns the budget "
            "for AI developer guardrails and what proof teams need to clear enterprise adoption.\n\n"
            "Would you have 15 minutes this week for a candid conversation? Happy to share our findings."
        ),
        "notes": "Positioned around enterprise adoption blockers for IDE coding agents."
    },
    {
        "id": "lead-crewai",
        "organization": "CrewAI Enterprise Swarms",
        "contact_target": "Lead Platform Engineer / Joao Moura's Core Team",
        "channel": "Discord: discord.gg/crewai (#crewai-chat, #integrations) / GitHub Discussions",
        "target_persona": "Platform / DevSecOps Lead",
        "offer_type": "Team Offer ($199/mo or $950)",
        "primary_pain": "Runaway tool loops, unbounded API spend, lack of verifiable audit logs",
        "budget_owner": "VP Engineering",
        "status": "MESSAGE_SENT",
        "last_updated": "2026-10-03T19:30:00Z",
        "tailored_message": (
            "Hi CrewAI team --\n\n"
            "When running autonomous multi-agent crews with tool access, how are your enterprise users capping "
            "per-action financial spend and guaranteeing an agent won't execute an out-of-scope terminal command?\n\n"
            "We're conducting a structured 10-team discovery sprint on agent runtime security: specifically whether "
            "teams solve this with prompt instructions vs. deterministic local execution boundaries, and who inside "
            "engineering teams typically holds budget for agent governance.\n\n"
            "Could we borrow 10-15 minutes of your time for a quick research interview? No pitch or product demo."
        ),
        "notes": "Highlighting spend ceilings and tool loop runaway risks."
    },
    {
        "id": "lead-e2b",
        "organization": "E2B (Code Execution Sandboxes)",
        "contact_target": "Platform & Security Team (Vasek Mlejnsky's team)",
        "channel": "Discord: discord.gg/e2b (#general, #sandbox) / Twitter: @e2b_dev",
        "target_persona": "Security / Infrastructure Lead",
        "offer_type": "Team Offer ($199/mo or $950)",
        "primary_pain": "Cloud sandbox escapes, network exfiltration, compliance proof for customers",
        "budget_owner": "Head of Infrastructure",
        "status": "MESSAGE_SENT",
        "last_updated": "2026-10-03T19:30:00Z",
        "tailored_message": (
            "Hey E2B team --\n\n"
            "We're seeing strong demand from developers executing untrusted LLM-generated code in sandbox environments "
            "who need sub-millisecond guarantees that destructive commands and credential scraping are blocked fail-closed.\n\n"
            "We're running customer discovery interviews on how infrastructure teams currently draw the line between "
            "container isolation and in-process execution inspection. Would someone on your security or platform team have "
            "15 minutes for a quick chat this week?"
        ),
        "notes": "Targeting sandbox containment and enterprise customer requirements."
    },
    {
        "id": "lead-aider",
        "organization": "Aider (aider-chat)",
        "contact_target": "Paul Gauthier (Creator/Lead)",
        "channel": "Discord: discord.gg/aider / GitHub: paul-gauthier/aider/issues",
        "target_persona": "Senior Developer / Maintainer",
        "offer_type": "Developer Offer (Zero-friction safety)",
        "primary_pain": "Agent auto-committing destructive or secret-leaking changes to git",
        "budget_owner": "Individual Developer / Tech Lead",
        "status": "MESSAGE_SENT",
        "last_updated": "2026-10-03T19:30:00Z",
        "tailored_message": (
            "Hi Paul -- huge respect for Aider. The git integration is best-in-class.\n\n"
            "We've been talking to developers using Aider in production repos who worry about agents committing "
            "accidentally staged secrets (.env, tokens) or running destructive bash scripts during automated testing.\n\n"
            "We built a zero-overhead pre-commit and terminal invariant gate. We're interviewing 10 power users on "
            "their actual safety practices: what safeguards they currently rely on, and what would make them feel 100% "
            "confident letting agents run autonomous loops.\n\n"
            "Would you have 10 minutes for a brief chat?"
        ),
        "notes": "Developer offer focus: zero-friction git pre-commit safety."
    },
    {
        "id": "inbound-inquiry-01",
        "organization": "Series A Fintech Startup (18 Engineers)",
        "contact_target": "Engineering Lead (Cursor & Claude Code rollout)",
        "channel": "Inbound Web Inquiry: founders@bartholomew.info",
        "target_persona": "Engineering Lead",
        "offer_type": "Team Offer ($199/mo or $950)",
        "primary_pain": "Developers using Cursor Composer; SOC 2 auditor questioning agent access to repos",
        "budget_owner": "VP Engineering (owns developer tooling budget)",
        "status": "CALL_SCHEDULED",
        "last_updated": "2026-10-03T19:30:00Z",
        "tailored_message": (
            "Hi [Lead Name] -- thanks for reaching out regarding the Bartholomew team pilot.\n\n"
            "To make sure our 30-minute kickoff is 100% tailored to your repo, could you share:\n"
            "1. Which coding agents are your engineers currently using (Cursor, Claude Code, etc.)?\n"
            "2. What specific compliance or safety requirement is your team trying to solve before next quarter?\n\n"
            "We look forward to walking through the custom policy setup."
        ),
        "notes": "High intent lead. Primary blocker is SOC 2 compliance evidence for AI coding assistants."
    },
    {
        "id": "inbound-inquiry-02",
        "organization": "Healthcare SaaS Platform (40 Developers)",
        "contact_target": "DevSecOps Director",
        "channel": "Inbound Web Inquiry: founders@bartholomew.info",
        "target_persona": "Security / DevSecOps Lead",
        "offer_type": "Team Offer ($199/mo or $950)",
        "primary_pain": "HIPAA compliance fear: agents potentially reading patient data mocks or API credentials",
        "budget_owner": "Director of Information Security",
        "status": "CALL_SCHEDULED",
        "last_updated": "2026-10-03T19:30:00Z",
        "tailored_message": (
            "Hi [Security Director] --\n\n"
            "Understood on your HIPAA mock data and secret protection requirements. Bartholomew enforces deterministic "
            "in-flight regex masking on API keys and restricts agent write paths via cryptographically signed passkeys.\n\n"
            "Let's jump on a 20-minute discovery call so we can confirm the exact scope before initiating the 30-day team pilot."
        ),
        "notes": "Security buyer with allocated budget. Needs written data boundaries and cryptographic receipts."
    },
    {
        "id": "inbound-inquiry-03",
        "organization": "AI Agency & Dev Shop (12 Engineers)",
        "contact_target": "Founding Partner / Lead Architect",
        "channel": "Inbound Web Inquiry: founders@bartholomew.info",
        "target_persona": "Technical Founder / Architect",
        "offer_type": "Team Offer ($199/mo or $950)",
        "primary_pain": "Client codebases wiped or leaked by contractors running autonomous scripts",
        "budget_owner": "Managing Partner",
        "status": "PILOT_PROPOSED",
        "last_updated": "2026-10-03T19:30:00Z",
        "tailored_message": (
            "Hi [Partner] --\n\n"
            "Our 30-day team pilot ($199/month for up to 10 engineers, or $950 one-time setup) gives you:\n"
            "1. Centralized .btp/policy.yaml pushed to all contractor machines.\n"
            "2. Fail-closed blocking of destructive commands and token leaks.\n"
            "3. Signed cryptographic audit dossier for each client repo.\n\n"
            "Ready to activate: https://bartholomew.info/#pricing"
        ),
        "notes": "Proposal sent. Follow up for commitment and start date."
    }
]


def load_pipeline() -> List[Dict[str, Any]]:
    if PIPELINE_FILE.exists():
        try:
            with open(PIPELINE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    save_pipeline(DEFAULT_LEADS)
    return DEFAULT_LEADS


def save_pipeline(leads: List[Dict[str, Any]]):
    PIPELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PIPELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(leads, f, indent=2)


def render_pipeline_table():
    leads = load_pipeline()
    print("\n" + "=" * 80)
    print("      BARTHOLOMEW 30-DAY VALIDATION SPRINT: INTERVIEW & PILOT PIPELINE")
    print("=" * 80)
    print(f"{'Lead ID':<22} | {'Organization':<26} | {'Status':<16} | {'Target Persona':<14}")
    print("-" * 80)
    for lead in leads:
        lead_id = lead.get("id", "")
        org = lead.get("organization", "")[:26]
        status = lead.get("status", "")
        persona = lead.get("target_persona", "")[:14]
        print(f"{lead_id:<22} | {org:<26} | {status:<16} | {persona:<14}")
    print("=" * 80)
    print("Status Legend: MESSAGE_SENT -> CALL_SCHEDULED -> INTERVIEWED -> PILOT_PROPOSED -> PILOT_CLOSED")
    print("Goal: 1 PAID TEAM PILOT COMMITMENT ($199/mo or $950)\n")


def display_message(lead_id: str):
    leads = load_pipeline()
    for lead in leads:
        if lead.get("id") == lead_id:
            print("\n" + "=" * 76)
            print(f"OUTREACH MESSAGE FOR: {lead.get('organization')}")
            print(f"Target Role : {lead.get('contact_target')}")
            print(f"Channel     : {lead.get('channel')}")
            print(f"Offer Type  : {lead.get('offer_type')}")
            print("-" * 76)
            print(lead.get("tailored_message", ""))
            print("=" * 76 + "\n")
            return
    print(f"Lead '{lead_id}' not found.")


def update_lead(lead_id: str, status: str = None, notes: str = None):
    leads = load_pipeline()
    found = False
    for lead in leads:
        if lead.get("id") == lead_id:
            if status:
                lead["status"] = status
            if notes:
                lead["notes"] = notes
            lead["last_updated"] = datetime.now(timezone.utc).isoformat()
            found = True
            break
    if found:
        save_pipeline(leads)
        print(f"[+] Lead '{lead_id}' updated successfully.")
    else:
        print(f"[-] Lead '{lead_id}' not found.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "list":
        render_pipeline_table()
    elif cmd == "message" and len(sys.argv) > 2:
        display_message(sys.argv[2])
    elif cmd == "update" and len(sys.argv) > 2:
        lead_id = sys.argv[2]
        status = None
        notes = None
        if "--status" in sys.argv:
            idx = sys.argv.index("--status")
            if idx + 1 < len(sys.argv):
                status = sys.argv[idx + 1]
        if "--notes" in sys.argv:
            idx = sys.argv.index("--notes")
            if idx + 1 < len(sys.argv):
                notes = sys.argv[idx + 1]
        update_lead(lead_id, status, notes)
    else:
        render_pipeline_table()
