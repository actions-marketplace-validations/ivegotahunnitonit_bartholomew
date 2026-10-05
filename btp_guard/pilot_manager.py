#!/usr/bin/env python3
"""
Bartholomew Protocol - Team Pilot Enrollment & Manager (v6.4.3)
================================================================
Automates 30-day team pilot enrollment, workspace policy synthesis,
cryptographic passkey generation, and Stripe commercial confirmation.

Lifecycle States:
  - INQUIRY
  - ENROLLMENT_START
  - PENDING_PAYMENT
  - PAID
  - ACTIVE
  - EXPIRED
  - REFUNDED
"""

import os
import sys
import json
import time
import secrets
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ENROLLMENT_FILE = REPO_ROOT / ".btp" / "team_pilot_enrollment.json"
POLICY_FILE = REPO_ROOT / ".btp" / "policy.yaml"

VALID_STATES = (
    "INQUIRY",
    "ENROLLMENT_START",
    "PENDING_PAYMENT",
    "PAID",
    "ACTIVE",
    "EXPIRED",
    "REFUNDED"
)

CHECKOUT_URL_MONTHLY = "https://buy.stripe.com/fZu14ng3PgyC9ao2z69R601"
CHECKOUT_URL_ONETIME = "https://buy.stripe.com/4gwbJ14d7cimeuE4He9R606"


def generate_secure_pilot_passkey() -> str:
    """Generates a high-entropy, cryptographically secure 192-bit server passkey."""
    token = secrets.token_hex(24).upper()
    return f"BTP-PILOT-{token}"


def get_checkout_url(billing: str, email: str, team_name: str) -> str:
    base = CHECKOUT_URL_MONTHLY if billing == "monthly" else CHECKOUT_URL_ONETIME
    encoded_email = urllib.parse.quote(email.strip().lower())
    team_slug = urllib.parse.quote(team_name.strip()[:30])
    return f"{base}?prefilled_email={encoded_email}&client_reference_id={team_slug}"


def write_policy_yaml(team_name: str, email: str, seats: int, passkey: str, expires_iso: str, status: str = "PENDING_PAYMENT") -> None:
    """Serializes policy.yaml safely through PyYAML without raw string interpolation."""
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    policy_data = {
        "version": "6.4.3",
        "team": {
            "name": team_name,
            "lead_email": email,
            "authorized_seats": int(seats),
            "passkey_id": passkey,
            "expires_at": expires_iso,
            "status": status
        },
        "invariants": {
            "block_destructive_shell": True,
            "mask_credentials": True,
            "quarantine_pipe_to_shell": True,
            "max_session_spend_usd": 25.00,
            "max_transaction_spend_usd": 10.00,
            "fail_closed_precommit": True
        },
        "runtimes": [
            "cursor",
            "claude-code",
            "windsurf",
            "cline",
            "aider",
            "openhands"
        ]
    }
    with open(POLICY_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(policy_data, f, default_flow_style=False, sort_keys=False)


def register_enrollment_intent(
    team_name: str,
    email: str,
    seats: int = 10,
    agent: str = "cursor",
    billing: str = "monthly",
    kickoff_date: Optional[str] = None
) -> Dict[str, Any]:
    """
    Registers a new pilot enrollment in PENDING_PAYMENT state.
    Does NOT issue active credentials before payment confirmation.
    """
    norm_team = team_name.strip()
    norm_email = email.strip().lower()
    seats_num = max(1, min(1000, int(seats)))
    billing_type = "onetime" if billing == "onetime" else "monthly"

    now_utc = datetime.now(timezone.utc)
    expires_unix = int(now_utc.timestamp()) + (30 * 86400)
    expires_iso = datetime.fromtimestamp(expires_unix, timezone.utc).isoformat()

    checkout = get_checkout_url(billing_type, norm_email, norm_team)
    fee_usd = 199.0 if billing_type == "monthly" else 950.0

    record = {
        "status": "PENDING_PAYMENT",
        "team_name": norm_team,
        "lead_email": norm_email,
        "seats": seats_num,
        "agent": agent,
        "billing": billing_type,
        "pilot_fee_usd": fee_usd,
        "passkey_id": None,  # Not issued until payment verified
        "enrolled_at_iso": now_utc.isoformat(),
        "expires_at_unix": expires_unix,
        "expires_at_iso": expires_iso,
        "kickoff_date": kickoff_date,
        "checkout_url": checkout,
        "portal_url": "https://bartholomew.info/pilot"
    }

    ENROLLMENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ENROLLMENT_FILE, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    # Write initial draft policy
    write_policy_yaml(norm_team, norm_email, seats_num, "UNPAID_PENDING_ACTIVATION", expires_iso, "PENDING_PAYMENT")

    # Record funnel step
    try:
        from btp_guard.funnel_tracker import record_funnel_step
        record_funnel_step("pilot_enrollment_starts")
    except Exception:
        pass

    return record


def activate_pilot_after_payment(email: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Called upon verified Stripe payment event to activate pilot enrollment.
    Generates high-entropy passkey, updates policy.yaml, and marks state ACTIVE.
    """
    norm_email = email.strip().lower()
    record = {}
    if ENROLLMENT_FILE.exists():
        try:
            with open(ENROLLMENT_FILE, "r", encoding="utf-8") as f:
                record = json.load(f)
        except Exception:
            record = {}

    if not record:
        record = {
            "team_name": norm_email.split("@")[0].capitalize(),
            "lead_email": norm_email,
            "seats": 10,
            "billing": "monthly",
            "pilot_fee_usd": 199.0
        }

    now_utc = datetime.now(timezone.utc)
    expires_unix = int(now_utc.timestamp()) + (30 * 86400)
    expires_iso = datetime.fromtimestamp(expires_unix, timezone.utc).isoformat()
    passkey = generate_secure_pilot_passkey()

    record["status"] = "ACTIVE"
    record["passkey_id"] = passkey
    record["activated_at_iso"] = now_utc.isoformat()
    record["expires_at_unix"] = expires_unix
    record["expires_at_iso"] = expires_iso
    if api_key:
        record["api_key"] = api_key

    with open(ENROLLMENT_FILE, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    write_policy_yaml(
        record.get("team_name", "Engineering Team"),
        norm_email,
        record.get("seats", 10),
        passkey,
        expires_iso,
        status="ACTIVE"
    )

    return record


def enroll_team(
    team_name: str = "Engineering Team",
    email: str = "lead@company.com",
    seats: int = 10,
    billing: str = "monthly"
) -> Dict[str, Any]:
    return register_enrollment_intent(team_name=team_name, email=email, seats=seats, billing=billing)


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
        print("      1. Sub-35us deterministic execution firewall on coding agent actions.")
        print("      2. Shared team policy (.btp/policy.yaml) across Cursor, Windsurf, VS Code.")
        print("      3. Fail-closed git pre-commit hooks to block bad commits before push.")
        print("      4. Machine-signed audit evidence pack detailing agent activity.")
        print("-" * 74)
        print("  [+] Enroll Interactively Right Now:")
        print("      Run: python -m btp_guard.cli pilot --enroll")
        print("  [+] Web Portal & Stripe Checkout:")
        print("      URL   : https://bartholomew.info/pilot")
        print("      Email : founders@bartholomew.info")
        print("=" * 74 + "\n")
        return

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

    print("\n[*] Initializing Team Policy Intent...")
    res = register_enrollment_intent(team_name=team_name, email=email, seats=seats, billing=billing)

    print("\n" + "-" * 74)
    print("   [+] 30-DAY TEAM PILOT ENROLLMENT INTENT REGISTERED")
    print("-" * 74)
    print(f"  * Team Name           : {res['team_name']}")
    print(f"  * Lead Email          : {res['lead_email']}")
    print(f"  * Authorized Seats    : {res['seats']} Engineers")
    print(f"  * Enrollment Status   : {res['status']}")
    print(f"  * Policy Configured   : .btp/policy.yaml (pending payment)")
    print(f"  * Pilot Investment    : ${res['pilot_fee_usd']:,.2f} ({res['billing']})")
    print("-" * 74)
    print("  [+] Complete Payment via Stripe:")
    print(f"      {res['checkout_url']}")
    print("  [+] Manage Online Portal:")
    print(f"      {res['portal_url']}")
    print("=" * 74 + "\n")


if __name__ == "__main__":
    run_pilot_cli()


def is_pilot_active(email: Optional[str] = None) -> bool:
    """
    Returns True ONLY if a pilot enrollment exists with verified status == 'ACTIVE',
    valid unexpired passkey, and expiration date in the future.
    Strictly rejects PENDING_PAYMENT, INQUIRY, ENROLLMENT_START, or EXPIRED.
    """
    if not ENROLLMENT_FILE.exists():
        return False
    try:
        with open(ENROLLMENT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if email and data.get("lead_email", "").lower() != email.strip().lower():
            return False
        if data.get("status") != "ACTIVE":
            return False
        passkey = data.get("passkey_id")
        if not passkey or passkey == "UNPAID_PENDING_ACTIVATION":
            return False
        exp = data.get("expires_at_unix")
        if exp and int(time.time()) > exp:
            return False
        return True
    except Exception:
        return False
