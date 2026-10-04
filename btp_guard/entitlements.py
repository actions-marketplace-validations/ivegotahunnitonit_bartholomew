"""
Bartholomew Protocol - Durable Entitlement & Idempotency Store
=============================================================
Manages durable workspace entitlements, Stripe event idempotency,
and license activation records in a persistent atomic store.
"""

import os
import json
import time
import secrets
from pathlib import Path
from typing import Dict, Any, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENTITLEMENTS_FILE = REPO_ROOT / ".btp" / "entitlements.json"

SCHEMA_VERSION = 1

SUPPORTED_PRODUCTS = {
    "TEAM_PILOT_MONTHLY": {
        "amount_usd": 199.0,
        "amount_cents": 19900,
        "tier": "TEAM_PILOT",
        "seats": 10,
        "max_agents": 100,
        "interval": "month"
    },
    "TEAM_PILOT_ONETIME": {
        "amount_usd": 950.0,
        "amount_cents": 95000,
        "tier": "TEAM_PILOT",
        "seats": 10,
        "max_agents": 100,
        "interval": "one_time"
    },
    "PRO_MONTHLY": {
        "amount_usd": 49.0,
        "amount_cents": 4900,
        "tier": "PRO",
        "seats": 1,
        "max_agents": 10,
        "interval": "month"
    },
    "ENTERPRISE": {
        "amount_usd": 199.0,
        "amount_cents": 19900,
        "tier": "ENTERPRISE",
        "seats": 50,
        "max_agents": 1000,
        "interval": "month"
    }
}


class EntitlementStore:
    def __init__(self, file_path: Optional[Path] = None):
        self.file_path = file_path or DEFAULT_ENTITLEMENTS_FILE
        self._load()

    def _load(self) -> None:
        self.data: Dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "processed_event_ids": {},
            "entitlements": {}
        }
        if self.file_path.exists():
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    content = json.load(f)
                    if isinstance(content, dict):
                        self.data["processed_event_ids"] = content.get("processed_event_ids", {})
                        self.data["entitlements"] = content.get("entitlements", {})
            except Exception:
                pass

    def _save(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = self.file_path.with_suffix(".tmp")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            tmp_file.replace(self.file_path)
        except Exception:
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except Exception:
                    pass

    def is_event_processed(self, event_id: str) -> bool:
        if not event_id:
            return False
        return event_id in self.data.get("processed_event_ids", {})

    def record_processed_event(self, event_id: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        if not event_id:
            return
        if "processed_event_ids" not in self.data:
            self.data["processed_event_ids"] = {}
        self.data["processed_event_ids"][event_id] = {
            "processed_at": time.time(),
            "metadata": metadata or {}
        }
        self._save()

    def get_entitlement_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        if not email:
            return None
        norm_email = email.strip().lower()
        return self.data.get("entitlements", {}).get(norm_email)

    def get_entitlement_by_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        if not api_key:
            return None
        for record in self.data.get("entitlements", {}).values():
            if record.get("api_key") == api_key:
                return record
        return None

    def issue_paid_entitlement(
        self,
        email: str,
        tier: str,
        amount_total_cents: int,
        stripe_event_id: str,
        org_name: Optional[str] = None,
        seats: int = 10,
        max_agents: int = 100,
        duration_days: int = 30
    ) -> Dict[str, Any]:
        norm_email = email.strip().lower()
        existing = self.get_entitlement_by_email(norm_email)

        now = time.time()
        expires_at = now + (duration_days * 86400)

        if existing and existing.get("status") == "ACTIVE":
            api_key = existing["api_key"]
            ws_id = existing["workspace_id"]
            existing["tier"] = tier
            existing["seats"] = max(existing.get("seats", seats), seats)
            existing["max_agents"] = max(existing.get("max_agents", max_agents), max_agents)
            existing["expires_at"] = max(existing.get("expires_at", 0), expires_at)
            existing["last_stripe_event_id"] = stripe_event_id
            existing["updated_at"] = now
            self._save()
            return existing

        new_key = f"sk_btp_live_{secrets.token_hex(20)}"
        ws_id = f"ws_{secrets.token_hex(6)}"
        resolved_org = org_name or norm_email.split("@")[0].capitalize()

        record = {
            "email": norm_email,
            "org_name": resolved_org,
            "tier": tier,
            "api_key": new_key,
            "workspace_id": ws_id,
            "seats": seats,
            "max_agents": max_agents,
            "status": "ACTIVE",
            "stripe_event_id": stripe_event_id,
            "amount_paid_usd": amount_total_cents / 100.0,
            "created_at": now,
            "expires_at": expires_at
        }

        if "entitlements" not in self.data:
            self.data["entitlements"] = {}
        self.data["entitlements"][norm_email] = record
        self._save()
        return record


GLOBAL_ENTITLEMENT_STORE = EntitlementStore()
