"""
Consolidated Security Boundary Verification Suite
Validates the 7 exact boundary conditions required before release:
1. Unauthenticated requests fail (401)
2. Cross-workspace requests fail (403)
3. Valid workspace keys succeed (200)
4. Invalid webhook signatures fail (400) & missing secret fails closed (500)
5. Valid signed webhook + paid event activates entitlement (200 + durable store)
6. Unapproved webview commands are rejected (allowlist drop)
7. Status is not marked "ARMED" without verified runtime proof
"""
import os
import re
import json
import time
import hmac
import hashlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Ensure test secret is configured before importing server
TEST_WEBHOOK_SECRET = "whsec_boundary_test_secret_998877"
os.environ["STRIPE_WEBHOOK_SECRET"] = TEST_WEBHOOK_SECRET

from src.api.cloud_engine_server import app, db
from btp_guard.entitlements import GLOBAL_ENTITLEMENT_STORE
from tests.test_truthful_proof_provider import run_node_telemetry_check

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_workspaces():
    db.workspace_keys["sk_boundary_alpha_key"] = {
        "workspace_id": "ws_boundary_alpha",
        "org_name": "Alpha Corp",
        "tier": "ENTERPRISE",
        "max_agents": 100,
        "created_at": time.time()
    }
    db.workspace_keys["sk_boundary_beta_key"] = {
        "workspace_id": "ws_boundary_beta",
        "org_name": "Beta Corp",
        "tier": "PRO",
        "max_agents": 10,
        "created_at": time.time()
    }
    yield

class TestRealSecurityBoundary:

    def test_1_unauthenticated_requests_fail(self):
        """Proof point 1: Sensitive routes must reject unauthenticated requests."""
        resp = client.get("/api/v1/telemetry/events")
        assert resp.status_code == 401
        assert "Authentication credentials are required" in resp.json()["detail"]

    def test_2_cross_workspace_requests_fail(self):
        """Proof point 2: Requests presenting a key for workspace A cannot access workspace B."""
        headers = {"X-API-KEY": "sk_boundary_alpha_key"}
        # Probing workspace beta using credentials issued for workspace alpha
        resp = client.get("/api/v1/telemetry/events?workspace_id=ws_boundary_beta", headers=headers)
        assert resp.status_code == 403
        assert "Caller does not own this workspace" in resp.json()["detail"]

    def test_3_valid_workspace_keys_succeed(self):
        """Proof point 3: Valid credentials for workspace alpha successfully access workspace alpha."""
        headers = {"X-API-KEY": "sk_boundary_alpha_key"}
        resp = client.get("/api/v1/telemetry/events?workspace_id=ws_boundary_alpha", headers=headers)
        assert resp.status_code == 200
        assert "events" in resp.json()

    def test_4_invalid_webhook_signatures_fail(self, monkeypatch):
        """Proof point 4: Tampered or invalid webhook signatures return 400; missing secret returns 500."""
        # 4a: Missing secret fails closed (500)
        monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
        resp = client.post(
            "/api/v1/billing/stripe-webhook",
            json={"id": "evt_test"},
            headers={"stripe-signature": "t=123,v1=fake"}
        )
        assert resp.status_code == 500

        # 4b: Restored secret with tampered signature returns 400
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
        bad_sig = "t=" + str(int(time.time())) + ",v1=deadbeef00000000000000000000000000000000000000000000000000000000"
        resp2 = client.post(
            "/api/v1/billing/stripe-webhook",
            content=b'{"id": "evt_tampered"}',
            headers={"stripe-signature": bad_sig, "content-type": "application/json"}
        )
        assert resp2.status_code == 400

    def test_5_valid_signed_webhook_activates_entitlement(self, monkeypatch):
        """Proof point 5: Legitimate signed event with paid status creates durable active entitlement."""
        monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", TEST_WEBHOOK_SECRET)
        email = f"boundary_user_{int(time.time())}@enterprise.io"
        event_id = f"evt_boundary_{int(time.time())}"
        payload_dict = {
            "id": event_id,
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": email,
                    "customer_details": {"name": "Boundary Test", "email": email},
                    "payment_status": "paid",
                    "amount_total": 19900
                }
            }
        }
        raw_payload = json.dumps(payload_dict).encode("utf-8")
        now_ts = int(time.time())
        signed_bytes = f"{now_ts}.".encode("utf-8") + raw_payload
        valid_v1 = hmac.new(TEST_WEBHOOK_SECRET.encode("utf-8"), signed_bytes, hashlib.sha256).hexdigest()
        valid_header = f"t={now_ts},v1={valid_v1}"

        resp = client.post(
            "/api/v1/billing/stripe-webhook",
            content=raw_payload,
            headers={"stripe-signature": valid_header, "content-type": "application/json"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["tier"] == "TEAM_PILOT"

        # Verify entitlement is durable
        entitlement = GLOBAL_ENTITLEMENT_STORE.get_entitlement_by_email(email)
        assert entitlement is not None
        assert entitlement["status"] == "ACTIVE"
        assert entitlement["tier"] == "TEAM_PILOT"

    def test_6_unapproved_webview_command_rejected(self):
        """Proof point 6: Webview message handler strictly filters actions against ALLOWED_COMMANDS."""
        ext_ts = (Path(__file__).resolve().parent.parent / "packages" / "vscode-extension" / "src" / "extension.ts").read_text(encoding="utf-8")
        
        # Verify ALLOWED_COMMANDS set is defined and used
        match = re.search(r"const ALLOWED_COMMANDS = new Set\(\[(.*?)\]\);", ext_ts, re.DOTALL)
        assert match is not None
        allowlist_block = match.group(1)
        assert "ALLOWED_COMMANDS.has(message.actionCommand)" in ext_ts
        assert "'bartholomew.armAndLinkWorkspace'" in allowlist_block
        assert "'bartholomew.protectWorkspace'" in allowlist_block
        
        # Verify arbitrary dangerous commands are strictly absent from allowlist
        for cmd in ["workbench.action.terminal.sendSequence", "vscode.open", "eval", "rm -rf /"]:
            assert f"'{cmd}'" not in allowlist_block

    def test_7_status_is_not_armed_without_runtime_proof(self, tmp_path):
        """Proof point 7: Static file presence without active runtime daemon reports DISCONNECTED / not ARMED."""
        # Create valid policy file in workspace
        dot_btp = tmp_path / ".btp"
        dot_btp.mkdir(parents=True, exist_ok=True)
        (dot_btp / "policy.yaml").write_text("version: 1.0\nenforce: true\n", encoding="utf-8")
        
        # When daemon is offline, status must NOT be ARMED
        res = run_node_telemetry_check(str(tmp_path), {"online": False})
        assert res["status"] != "ARMED"
        assert res["status"] in ("DISCONNECTED", "PARTIALLY_ARMED", "UNARMED")
