import sys
if hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8')
    except Exception: pass
#!/usr/bin/env python3
"""
Bartholomew Protocol - Team Pilot Enrollment & Manager (v6.4.0)
================================================================
Automates 30-day team pilot enrollment, workspace policy synthesis,
passkey generation, and Stripe commercial confirmation.

Usage:
    python -m btp_guard.pilot_manager --enroll
    python -m btp_guard.cli pilot --enroll
"""

import os
import sys
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

REPO_ROOT = Path(__file__).resolve().parent.parent
ENROLLMENT_FILE = REPO_ROOT / ".btp" / "team_pilot_enrollment.json"
POLICY_FILE = REPO_ROOT / ".btp" / "policy.yaml"


def generate_pilot_passkey(team_name: str, email: str) -> str:
    seed = f"{team_name}:{email}:{time.time()}:btp_secret"
    digest = hashlib.sha256(seed.encode()).hexdigest()[:8].upper()
    return f"BTP-PILOT-{digest}"


def enroll_team(
    team_name: str = "Engineering Team",
    email: str = "lead@company.com",
    seats: int = 10,
    billing: str = "monthly"
) -> Dict[str, Any]:
    passkey = generate_pilot_passkey(team_name, email)
    now_utc = datetime.now(timezone.utc)
    expires_unix = int(now_utc.timestamp()) + (30 * 86400)

    # 1. Ensure .btp directory exists
    ENROLLMENT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # 2. Write customized policy.yaml if not present
    if not POLICY_FILE.exists():
        policy_content = f"""# Bartholomew Team Pilot Policy -- {team_name}
# Evaluated in-process (<35us) across Cursor, Claude Code, Windsurf
version: "6.4.0"
team:
  name: "{team_name}"
  lead_email: "{email}"
  authorized_seats: {seats}
  passkey_id: "{passkey}"
  expires_at: "{datetime.fromtimestamp(expires_unix, timezone.utc).isoformat()}"

invariants:
  block_destructive_shell: true
  mask_credentials: true
  quarantine_pipe_to_shell: true
  max_session_spend_usd: 25.00
  max_transaction_spend_usd: 10.00
  fail_closed_precommit: true

runtimes:
  - cursor
  - claude-code
  - windsurf
  - cline
  - aider
  - openhands
"""
        with open(POLICY_FILE, "w", encoding="utf-8") as f:
            f.write(policy_content)

    # 3. Create persistent enrollment record
    record = {
        "status": "AWAITING_PAYMENT",
        "team_name": team_name,
        "lead_email": email,
        "seats": seats,
        "billing": billing,
        "pilot_fee_usd": 199.0 if billing == "monthly" else 950.0,
        "passkey_id": passkey,
        "enrolled_at_iso": now_utc.isoformat(),
        "expires_at_unix": expires_unix,
        "expires_at_iso": datetime.fromtimestamp(expires_unix, timezone.utc).isoformat(),
        "checkout_url": "https://buy.stripe.com/3cI6oHbNz3LQ4U84He9R605",
        "portal_url": "https://bartholomew.info/pilot"
    }

    with open(ENROLLMENT_FILE, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    # 4. Record to funnel metrics
    try:
        from btp_guard.funnel_tracker import record_funnel_step
        record_funnel_step("pilot_enrollment_starts")
    except Exception:
        pass

    return record


def run_pilot_cli(args=None):
    is_enroll = getattr(args, "enroll", False) if args else ("--enroll" in sys.argv)

    if not is_enroll:
        print("\n" + "=" * 74)
        print("   BARTHOLOMEW PROTOCOL -- 30-DAY HANDS-ON TEAM PILOT")
        print("   Verifiable Workspace Guardrails for Teams Adopting AI Coding Agents")
        print("=" * 74)
        print("  * Target Buyer    : Engineering Leads & Platform Teams (up to 10 devs)")
        print("  * Pilot Investment: $199/month (or $950 one-time guided setup)")
        print("  * Core Guarantee  : 100% money back if an unauthorized action isn't caught")
        print("  * Key Outcomes    :")
        print("      1. Sub-35us deterministic execution firewall on coding agent terminal actions.")
        print("      2. Shared team policy (.btp/policy.yaml) across Cursor, Windsurf, VS Code.")
        print("      3. Fail-closed git pre-commit hooks to block bad commits before push.")
        print("      4. CISO/SOC2 cryptographic audit dossier detailing all agent activity.")
        print("-" * 74)
        print("  [+] Enroll Interactively Right Now:")
        print("      Run: python -m btp_guard.cli pilot --enroll")
        print("  [+] Web Portal & Stripe Checkout:")
        print("      URL   : https://bartholomew.info/pilot")
        print("      Email : founders@bartholomew.info")
        print("=" * 74 + "\n")
        return

    # Interactive or Automated Enrollment
    print("\n" + "=" * 74)
    print("   BARTHOLOMEW 30-DAY TEAM PILOT -- WORKSPACE ENROLLMENT")
    print("=" * 74)

    team_name = getattr(args, "team", None) if args else None
    email = getattr(args, "email", None) if args else None
    seats = getattr(args, "seats", 10) if args else 10
    billing = getattr(args, "billing", "monthly") if args else "monthly"

    if not team_name:
        try:
            team_name = input("Enter Team / Company Name (e.g. Acme Engineering): ").strip()
        except Exception:
            team_name = "Team Sandbox"
    if not team_name:
        team_name = "Team Sandbox"

    if not email:
        try:
            email = input("Enter Lead Engineer Email (e.g. you@company.com): ").strip()
        except Exception:
            email = "lead@team.local"
    if not email:
        email = "lead@team.local"

    print("\n[*] Initializing Team Policy & Generating Evaluation Passkey...")
    res = enroll_team(team_name=team_name, email=email, seats=seats, billing=billing)

    print("\n" + "-" * 74)
    print("   [+] 30-DAY TEAM PILOT ENROLLMENT REQUEST RECORDED")
    print("-" * 74)
    print(f"  * Team Name           : {res['team_name']}")
    print(f"  * Lead Email          : {res['lead_email']}")
    print(f"  * Authorized Seats    : {res['seats']} Engineers")
    print(f"  * Evaluation Passkey  : {res['passkey_id']} (Provisioned pending payment confirmation)")
    print(f"  * Enrollment Status   : {res['status']}")
    print(f"  * Policy Configured   : .btp/policy.yaml (local policy draft)")
    print(f"  * Pilot Investment    : ${res['pilot_fee_usd']:,.2f} ({res['billing']})")
    print("-" * 74)
    print("  [+] Complete Payment via Stripe:")
    print(f"      {res['checkout_url']}")
    print("  [+] Manage Online Portal:")
    print(f"      {res['portal_url']}")
    print("=" * 74 + "\n")


if __name__ == "__main__":
    run_pilot_cli()
