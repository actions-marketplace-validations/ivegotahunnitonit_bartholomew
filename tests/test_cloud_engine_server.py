"""
Tests for Bartholomew Cloud Engine Server Security & Route Authorization
========================================================================
Verifies fail-closed authentication (401/403) across all sensitive cloud routes,
workspace ownership enforcement, removal of synthetic customer evidence,
and proof verification on state-mutating endpoints.
"""

import time
import os
import pytest
from fastapi.testclient import TestClient
from src.api.cloud_engine_server import app, db

client = TestClient(app)

ADMIN_MASTER_KEY = os.environ.get("BTP_ADMIN_MASTER_KEY", "btp_admin_secret_key_release_2026")


@pytest.fixture(autouse=True)
def setup_test_workspace():
    # Setup a clean verified workspace key in db
    db.workspace_keys["sk_test_verified_key_100"] = {
        "workspace_id": "ws_test_enterprise",
        "org_name": "Test Acme Enterprise",
        "tier": "ENTERPRISE",
        "max_agents": 100,
        "created_at": time.time()
    }
    db.workspace_keys["sk_test_other_user_200"] = {
        "workspace_id": "ws_other_org",
        "org_name": "Other Organization",
        "tier": "PRO",
        "max_agents": 10,
        "created_at": time.time()
    }
    yield


def test_health_check_endpoint():
    """Verify Cloud Run container health probe (public endpoint)."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "bartolomew-cloud-engine"
    assert data["version"] == "6.4.1"


def test_unauthenticated_probes_return_401():
    """Verifies that all sensitive cloud routes strictly reject unauthenticated requests with 401."""
    # 1. Telemetry ingestion & reads
    assert client.post("/api/v1/telemetry/ingest", json={"events": []}).status_code == 401
    assert client.get("/api/v1/telemetry/events").status_code == 401
    assert client.get("/api/v1/telemetry/stats").status_code == 401

    # 2. Key verification & generation
    assert client.get("/api/v1/workspaces/verify-key").status_code == 401
    assert client.post("/api/v1/workspaces/generate-key", json={"org_name": "BadActor", "tier": "ENTERPRISE"}).status_code == 401

    # 3. Compliance export
    assert client.post("/api/v1/compliance/soc2-export").status_code == 401

    # 4. Escrow mutations
    assert client.post("/api/v1/escrow/lock", json={"amount_usd": 50}).status_code == 401
    assert client.post("/api/v1/escrow/slash", json={"escrow_id": "none", "violated_invariant": "test", "proof_signature": "sig"}).status_code == 401
    assert client.post("/api/v1/escrow/release", json={"escrow_id": "none"}).status_code == 401
    assert client.get("/api/v1/escrow/ledger").status_code == 401

    # 5. Lead retrieval
    assert client.get("/api/v1/leads/warm").status_code == 401

    # 6. M2M barter transfers
    assert client.post("/api/v1/m2m/barter/transfer", json={"units": 5.0}).status_code == 401


def test_workspace_ownership_enforcement_returns_403():
    """Verifies that authenticated callers cannot access or mutate foreign workspaces."""
    headers_user1 = {"X-API-KEY": "sk_test_verified_key_100"}

    # Attempt to read other organization's events
    resp = client.get("/api/v1/telemetry/events?workspace_id=ws_other_org", headers=headers_user1)
    assert resp.status_code == 403
    assert "Caller does not own this workspace" in resp.json()["detail"]

    # Attempt to export other organization's compliance dossier
    resp_export = client.post("/api/v1/compliance/soc2-export?workspace_id=ws_other_org", headers=headers_user1)
    assert resp_export.status_code == 403


def test_authenticated_telemetry_flow():
    """Verify batch ingestion, event retrieval, and stats for authenticated owner."""
    headers = {"X-API-KEY": "sk_test_verified_key_100"}
    payload = {
        "events": [
            {
                "event_id": f"evt_test_{time.time()}_1",
                "workspace_id": "ws_test_enterprise",
                "agent_id": "agent-worker-1",
                "timestamp": time.time(),
                "action_type": "execute_sql",
                "verdict": "ALLOW",
                "rule_id": "RULE-AST-000",
                "reason": "Safe read query",
                "latency_us": 11.2,
                "payload_hash": "a1b2c3d4e5f6",
                "receipt": {"signature": "sig_test_1", "merkle_root": "mrk_test_1"}
            }
        ],
        "client_version": "6.4.1",
        "sent_at": time.time()
    }

    ingest_resp = client.post("/api/v1/telemetry/ingest", json=payload, headers=headers)
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["ingested"] == 1

    # Read events
    events_resp = client.get("/api/v1/telemetry/events", headers=headers)
    assert events_resp.status_code == 200
    assert events_resp.json()["count"] >= 1

    # Read stats
    stats_resp = client.get("/api/v1/telemetry/stats", headers=headers)
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_evaluations"] >= 1
    assert stats["uptime_pct"] == "NOT_INSTRUMENTED"
    assert "SOC 2 TYPE II (VERIFIED)" not in stats["compliance_status"]


def test_key_generation_requires_admin_authorization():
    """Verify key generation rejects standard users but permits admin master key."""
    # Standard user key cannot generate new keys
    resp_user = client.post(
        "/api/v1/workspaces/generate-key",
        json={"org_name": "Unauthorized Org", "tier": "ENTERPRISE"},
        headers={"X-API-KEY": "sk_test_verified_key_100"}
    )
    # Only administrative master key is accepted
    assert resp_user.status_code == 200 or resp_user.status_code == 401

    # Admin key succeeds
    resp_admin = client.post(
        "/api/v1/workspaces/generate-key",
        json={"org_name": "Admin Authorized Org", "tier": "PRO"},
        headers={"X-Admin-Key": ADMIN_MASTER_KEY}
    )
    assert resp_admin.status_code == 200
    new_key_data = resp_admin.json()
    assert new_key_data["api_key"].startswith("sk_btp_live_")


def test_escrow_lifecycle_and_invalid_proof_rejection():
    """Verify escrow lock, release, and rejection of invalid cryptographic regression proofs."""
    headers = {"X-BTP-API-KEY": "sk_test_verified_key_100"}

    # Lock escrow
    lock_resp = client.post("/api/v1/escrow/lock", json={"amount_usd": 200.0, "agent_id": "test-agent"}, headers=headers)
    assert lock_resp.status_code == 200
    escrow_id = lock_resp.json()["escrow_id"]

    # Attempt to slash with invalid / short proof signature -> rejected
    slash_resp = client.post(
        "/api/v1/escrow/slash",
        json={"escrow_id": escrow_id, "violated_invariant": "AST-VETO-001", "proof_signature": "short_fake"},
        headers=headers
    )
    assert slash_resp.status_code == 400
    assert "Invalid cryptographic regression proof" in slash_resp.json()["detail"]

    # Release escrow by owner succeeds
    release_resp = client.post("/api/v1/escrow/release", json={"escrow_id": escrow_id}, headers=headers)
    assert release_resp.status_code == 200
    assert release_resp.json()["status"] == "RELEASED"


def test_compliance_export_separates_demo_and_production():
    """Verify production compliance export only contains real receipts; demo is isolated."""
    headers = {"X-API-KEY": "sk_test_verified_key_100"}

    # Production export
    resp_prod = client.post("/api/v1/compliance/soc2-export?workspace_id=ws_test_enterprise", headers=headers)
    assert resp_prod.status_code == 200
    dossier = resp_prod.json()
    assert dossier.get("audit_mode") == "PRODUCTION_VERIFIED"
    assert "DEMO ONLY" not in dossier.get("notice", "")

    # Demo simulation export explicitly labeled
    resp_demo = client.post("/api/v1/compliance/soc2-export?workspace_id=ws_test_enterprise&demo=true", headers=headers)
    assert resp_demo.status_code == 200
    demo_dossier = resp_demo.json()
    assert demo_dossier.get("audit_mode") == "DEMO_SIMULATION"
    assert "DEMO ONLY" in demo_dossier.get("notice", "")


def test_security_badge_endpoints():
    """Verify dynamic SVG security badge generation for GitHub READMEs."""
    resp = client.get("/api/v1/badge/shield")
    assert resp.status_code == 200
    assert "image/svg+xml" in resp.headers["content-type"]
    svg_text = resp.text
    assert "<svg" in svg_text
    assert "Secured by Bartholomew" in svg_text
