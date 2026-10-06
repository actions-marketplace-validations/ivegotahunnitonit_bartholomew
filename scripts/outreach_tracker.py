#!/usr/bin/env python3
"""
Bartholomew High-Intent Outreach & Conversion Pipeline Tracker
Tracks outreach status for the 100 high-intent audit prospects.
Prevents duplicate contact, logs timestamps, and manages conversion pipeline.
"""

import os
import sys
import json
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
TRACKER_FILE = ROOT_DIR / ".btp" / "outreach_pipeline.json"

def load_tracker():
    if not TRACKER_FILE.exists():
        TRACKER_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Initialize with baseline pipeline state
        data = {
            "version": "6.4.3",
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "contacts": {}
        }
        with open(TRACKER_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data

    with open(TRACKER_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_tracker(data):
    data["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    with open(TRACKER_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def record_contact(target_id: str, company: str, channel: str, status: str = "CONTACTED", notes: str = ""):
    data = load_tracker()
    contacts = data.setdefault("contacts", {})

    existing = contacts.get(target_id)
    if existing and existing.get("status") in ("CONTACTED", "CALL_SCHEDULED", "AUDIT_PURCHASED"):
        print(f"[!] WARNING: Target #{target_id} ({company}) was ALREADY contacted on {existing.get('contacted_at')}!")
        print(f"    Current Status: {existing.get('status')}")
        return False

    contacts[target_id] = {
        "target_id": target_id,
        "company": company,
        "channel": channel,
        "status": status,
        "contacted_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "notes": notes
    }
    save_tracker(data)
    print(f"[+] Logged outreach for #{target_id} ({company}) via {channel} -> Status: {status}")
    return True

def show_summary():
    data = load_tracker()
    contacts = data.get("contacts", {})
    total = len(contacts)
    status_counts = {}
    for c in contacts.values():
        st = c.get("status", "UNKNOWN")
        status_counts[st] = status_counts.get(st, 0) + 1

    print("=" * 60)
    print(" BARTHOLOMEW 100-PROSPECT CONVERSION PIPELINE")
    print(f" Total Tracked Outreach: {total} / 100")
    print("=" * 60)
    for st, count in status_counts.items():
        print(f"  * {st:<18}: {count}")
    print("=" * 60)

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scripts/outreach_tracker.py status")
        print("  python scripts/outreach_tracker.py log <target_id> <company> <channel> [status] [notes]")
        print("Example:")
        print("  python scripts/outreach_tracker.py log 1 OpenHands Discord CONTACTED 'Sent pitch to Robert Brennan'")
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd == "status":
        show_summary()
    elif cmd == "log":
        if len(sys.argv) < 5:
            print("Error: Missing arguments for log command.")
            sys.exit(1)
        t_id = sys.argv[2]
        comp = sys.argv[3]
        chan = sys.argv[4]
        stat = sys.argv[5] if len(sys.argv) > 5 else "CONTACTED"
        note = " ".join(sys.argv[6:]) if len(sys.argv) > 6 else ""
        record_contact(t_id, comp, chan, stat, note)
    else:
        print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    main()
