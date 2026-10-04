#!/usr/bin/env python3
"""
Bartholomew Protocol - Funnel & Conversion Instrumentation (v6.4.1)
===================================================================
Tracks the 5 distinct activation and monetization funnel stages:
  1. Total Downloads & Registries (Public distribution)
  2. Unique Active Installs (Distinct machines & workspaces)
  3. Activated Protection Proofs (First successful probe in real repo)
  4. Repeat Protected Use (Active across 7+ days)
  5. Team Pilot Inquiries & Paid Commitments

Privacy Invariant:
  Only aggregate integer counters and ISO timestamps are tracked.
  Prompts, code, filesystem contents, commands, and secrets are NEVER recorded.
"""

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
FUNNEL_METRICS_PATH = REPO_ROOT / ".btp" / "funnel_metrics.json"
FUNNEL_SCHEMA_VERSION = 2
FUNNEL_FIELDS = (
    "unique_active_installs",
    "first_proof_activations",
    "repeat_active_users_7d",
    "pricing_page_visits",
    "team_pilot_inquiries",
    "paid_commitments",
    "pilot_enrollment_starts",
)
RECORDABLE_FUNNEL_EVENTS = (
    "team_pilot_inquiries",
    "pilot_enrollment_starts",
    "pricing_page_visits",
    "first_proof_activations",
    "paid_commitments",
)


def get_funnel_snapshot() -> Dict[str, Any]:
    census_file = REPO_ROOT / "USER_CENSUS_REPORT.json"
    total_downloads = None
    if census_file.exists():
        try:
            with open(census_file, "r", encoding="utf-8") as f:
                d = json.load(f)
                value = d.get("summary", {}).get("total_verified_distributions")
                if isinstance(value, int) and value >= 0:
                    total_downloads = value
        except Exception:
            pass

    funnel_state = {
        "total_downloads": total_downloads,
        **{field: None for field in FUNNEL_FIELDS},
    }

    if FUNNEL_METRICS_PATH.exists():
        try:
            with open(FUNNEL_METRICS_PATH, "r", encoding="utf-8") as f:
                stored = json.load(f)
            if stored.get("schema_version") == FUNNEL_SCHEMA_VERSION:
                metrics = stored.get("metrics", {})
                for field in FUNNEL_FIELDS:
                    value = metrics.get(field)
                    if isinstance(value, int) and value >= 0:
                        funnel_state[field] = value
                funnel_state["last_updated_utc"] = stored.get("last_updated_utc")
        except Exception:
            pass

    return funnel_state


def record_funnel_step(step_name: str, metadata: Optional[Dict[str, Any]] = None):
    """
    Safely increments a privacy-conscious aggregate funnel counter.
    Prompts, code, shell commands, and secrets are strictly excluded.
    """
    if step_name not in RECORDABLE_FUNNEL_EVENTS:
        raise ValueError(f"Unsupported funnel metric: {step_name}")

    FUNNEL_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    state = get_funnel_snapshot()
    if state[step_name] is None:
        state[step_name] = 0
    state[step_name] += 1
    recorded_at = datetime.now(timezone.utc).isoformat()
    try:
        with open(FUNNEL_METRICS_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "schema_version": FUNNEL_SCHEMA_VERSION,
                "metrics": {field: state[field] for field in FUNNEL_FIELDS},
                "last_updated_utc": recorded_at,
            }, f, indent=2)
    except Exception:
        pass


def render_funnel_report():
    data = get_funnel_snapshot()

    def display_count(value):
        return "NOT INSTRUMENTED" if value is None else f"{value:,}"

    def format_count_and_rate(count, base, label):
        count_str = display_count(count)
        if count is None or base is None or base <= 0:
            return count_str
        rate = (count / base) * 100.0
        return f"{count_str} ({rate:.1f}% {label})"

    downloads = data["total_downloads"]
    installs = data["unique_active_installs"]
    proofs = data["first_proof_activations"]
    repeats = data["repeat_active_users_7d"]
    pricing = data["pricing_page_visits"]
    pilots = data["team_pilot_inquiries"]
    paid = data["paid_commitments"]
    enrollment_starts = data["pilot_enrollment_starts"]

    print("\n" + "=" * 76)
    print("      BARTHOLOMEW CONVERSION FUNNEL & ACTIVATION HEALTH AUDIT")
    print("=" * 76)
    print("Stage 1: Public Distribution Reach")
    print(f"  * Total Verified Downloads     : {display_count(downloads)}")
    print(f"  * Unique Active Installs       : {format_count_and_rate(installs, downloads, 'of downloads')}")
    print("-" * 76)
    print("Stage 2: Workspace Activation (Zero-to-Proof)")
    print(f"  * First Successful Verification : {format_count_and_rate(proofs, installs, 'activation rate')}")
    print(f"  * Repeat Active Users (7d)      : {format_count_and_rate(repeats, installs, '7-day retention')}")
    print("-" * 76)
    print("Stage 3: Commercial Intent & Conversion")
    print(f"  * Pricing / Pilot Page Visits   : {display_count(pricing)}")
    print(f"  * Team Pilot Inquiries          : {display_count(pilots)}")
    print(f"  * Pilot Enrollment Starts       : {display_count(enrollment_starts)}")
    print(f"  * Paid Pilot Commitments        : {display_count(paid)}")
    print("=" * 76)
    if any(value is None for value in (installs, proofs, pricing, pilots, paid)):
        print("\n[DIAGNOSTIC VERDICT]: Funnel instrumentation is partial; missing stages are labeled NOT INSTRUMENTED.")
        print("  * Only verified payments increment paid commitments.")
    elif paid == 0 and pilots and pilots > 0:
        print(f"\n[DIAGNOSTIC VERDICT]: Qualified inbound interest detected ({pilots} inquiries), awaiting payment confirmation.")
    elif paid and paid > 0:
        print(f"\n[DIAGNOSTIC VERDICT]: Active verified commitments: {paid} paid teams.")


if __name__ == "__main__":
    render_funnel_report()
