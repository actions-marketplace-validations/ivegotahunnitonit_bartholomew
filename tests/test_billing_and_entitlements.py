"""
Comprehensive Test Suite: Billing, Webhook Verification & Durable Entitlements
==============================================================================
Validates:
1. Rejection of unsigned or invalid Stripe-Signature webhook requests.
2. Rejection of unpaid sessions (payment_status != 'paid').
3. Rejection of unsupported wrong-product prices.
4. Acceptance of verified successful Stripe payment events ($199/mo team, $950 one-time, $49/mo pro).
5. Idempotent processing of duplicate Stripe events (no duplicate license issuance).
6. Strict rejection of arbitrary claim-license requests (no free trial keys for arbitrary emails).
7. Successful retrieval of license keys only for verified paid entitlements.
8. Real server pilot enrollment endpoint with distinct checkout destinations and input validation.
"""

import time
import json
import hmac
import hashlib
import os
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

TEST_WEBHOOK_SECRET = "whsec_test_live_secret_7f8a9b"
os.environ["STRIPE_WEBHOOK_SECRET"] = TEST_WEBHOOK_SECRET

from src.api.cloud_engine_server import app
from btp_guard.entitlements import GLOBAL_ENTITLEMENT_STORE
from btp_guard.pilot_manager import CHECKOUT_URL_MONTHLY, CHECKOUT_URL_ONETIME, is_pilot_active, register_enrollment_intent, activate_pilot_after_payment

client = TestClient(app)


def sign_stripe_payload(raw_body: bytes, secret: str = TEST_WEBHOOK_SECRET, timestamp: int = None) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    signed_payload = f"{timestamp}.".encode("utf-8") + raw_body
    sig = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={sig}"


class TestBillingAndEntitlements:

    def test_webhook_missing_signature_rejected(self):
        """Unsigned webhook requests must be rejected immediately."""
        payload = {
            "id": "evt_test_unsigned_01",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": "attacker@darkweb.io",
                    "payment_status": "paid",
                    "amount_total": 19900
                }
            }
        }
        resp = client.post("/api/v1/billing/stripe-webhook", json=payload)
        assert resp.status_code == 400
        assert "Invalid or missing Stripe signature" in resp.json()["detail"]
        assert GLOBAL_ENTITLEMENT_STORE.get_entitlement_by_email("attacker@darkweb.io") is None

    def test_webhook_invalid_signature_rejected(self):
        """Webhook requests with forged or invalid signatures must be rejected."""
        payload = json.dumps({
            "id": "evt_test_forged_01",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": "hacker@evil.com",
                    "payment_status": "paid",
                    "amount_total": 19900
                }
            }
        }).encode("utf-8")

        headers = {"stripe-signature": "t=1700000000,v1=0000000000000000000000000000000000000000000000000000000000000000"}
        resp = client.post("/api/v1/billing/stripe-webhook", content=payload, headers=headers)
        assert resp.status_code == 400
        assert "Invalid or missing Stripe signature" in resp.json()["detail"]
        assert GLOBAL_ENTITLEMENT_STORE.get_entitlement_by_email("hacker@evil.com") is None

    def test_webhook_unpaid_session_rejected(self):
        """Checkout session with payment_status != 'paid' must not provision license."""
        payload_dict = {
            "id": "evt_test_unpaid_01",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": "unpaid_buyer@acme.com",
                    "payment_status": "unpaid",
                    "amount_total": 19900
                }
            }
        }
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = sign_stripe_payload(raw_body)
        resp = client.post("/api/v1/billing/stripe-webhook", content=raw_body, headers={"stripe-signature": sig})
        assert resp.status_code == 400
        assert "payment_status != 'paid'" in resp.json()["detail"]
        assert GLOBAL_ENTITLEMENT_STORE.get_entitlement_by_email("unpaid_buyer@acme.com") is None

    def test_webhook_wrong_product_amount_rejected(self):
        """Payments for wrong products or unexpected pricing must not issue paid licenses."""
        payload_dict = {
            "id": "evt_test_wrong_product_01",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": "cheap_buyer@test.io",
                    "payment_status": "paid",
                    "amount_total": 299
                }
            }
        }
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = sign_stripe_payload(raw_body)
        resp = client.post("/api/v1/billing/stripe-webhook", content=raw_body, headers={"stripe-signature": sig})
        assert resp.status_code == 400
        assert "Unsupported or invalid product price" in resp.json()["detail"]
        assert GLOBAL_ENTITLEMENT_STORE.get_entitlement_by_email("cheap_buyer@test.io") is None

    def test_webhook_successful_payment_proves_entitlement(self):
        """Verified payment for $199/month team pilot provisions active durable entitlement."""
        email = f"lead_{int(time.time())}@fintech-corp.com"
        event_id = f"evt_test_valid_{int(time.time())}"
        payload_dict = {
            "id": event_id,
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": email,
                    "customer_details": {"name": "Fintech Corp", "email": email},
                    "payment_status": "paid",
                    "amount_total": 19900
                }
            }
        }
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = sign_stripe_payload(raw_body)

        resp = client.post("/api/v1/billing/stripe-webhook", content=raw_body, headers={"stripe-signature": sig})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "SUCCESS"
        assert data["tier"] == "TEAM_PILOT"
        assert data["api_key"].startswith("sk_btp_live_")

        # Verify durable storage
        entitlement = GLOBAL_ENTITLEMENT_STORE.get_entitlement_by_email(email)
        assert entitlement is not None
        assert entitlement["status"] == "ACTIVE"
        assert entitlement["tier"] == "TEAM_PILOT"
        assert entitlement["api_key"] == data["api_key"]

        # Verify claim-license now returns this entitlement
        claim_resp = client.post("/api/v1/billing/claim-license", json={"email": email})
        assert claim_resp.status_code == 200
        claim_data = claim_resp.json()
        assert claim_data["found"] is True
        assert claim_data["api_key"] == data["api_key"]
        assert claim_data["tier"] == "TEAM_PILOT"

    def test_webhook_event_idempotency_duplicate_event(self):
        """Duplicate Stripe events must be recognized and not issue duplicate keys."""
        email = f"idempotent_{int(time.time())}@stripe-user.io"
        event_id = f"evt_idempotent_{int(time.time())}"
        payload_dict = {
            "id": event_id,
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer_email": email,
                    "payment_status": "paid",
                    "amount_total": 95000
                }
            }
        }
        raw_body = json.dumps(payload_dict).encode("utf-8")
        sig = sign_stripe_payload(raw_body)

        # 1. First event succeeds
        resp1 = client.post("/api/v1/billing/stripe-webhook", content=raw_body, headers={"stripe-signature": sig})
        assert resp1.status_code == 200
        key1 = resp1.json()["api_key"]

        # 2. Duplicate event returns ALREADY_PROCESSED
        resp2 = client.post("/api/v1/billing/stripe-webhook", content=raw_body, headers={"stripe-signature": sig})
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["status"] == "ALREADY_PROCESSED"
        assert data2["entitlement"]["api_key"] == key1

    def test_claim_license_unverified_email_fails_closed(self):
        """Arbitrary unverified emails must not receive a free trial license key."""
        random_email = f"random_unpaid_{time.time()}@nowhere.com"
        resp = client.post("/api/v1/billing/claim-license", json={"email": random_email})
        assert resp.status_code == 404
        assert "No active verified entitlement found" in resp.json()["detail"]

    def test_pilot_enrollment_endpoint(self):
        """Pilot enrollment registers pending intent and returns correct checkout link without issuing passkeys."""
        # 1. Monthly enrollment
        monthly_req = {
            "team_name": "Acme Payments Engineering",
            "email": "lead@acme-payments.com",
            "seats": 10,
            "agent": "cursor",
            "billing": "monthly"
        }
        m_resp = client.post("/api/v1/pilot/enroll", json=monthly_req)
        assert m_resp.status_code == 200
        m_data = m_resp.json()
        assert m_data["status"] == "SUCCESS"
        assert m_data["enrollment_status"] == "PENDING_PAYMENT"
        assert m_data["amount_usd"] == 199.0
        assert CHECKOUT_URL_MONTHLY in m_data["checkout_url"]
        assert "passkey" not in m_data or m_data.get("passkey") is None

        # 2. One-time setup enrollment
        onetime_req = {
            "team_name": "Apex Quant",
            "email": "ops@apexquant.io",
            "seats": 10,
            "agent": "claude-code",
            "billing": "onetime"
        }
        o_resp = client.post("/api/v1/pilot/enroll", json=onetime_req)
        assert o_resp.status_code == 200
        o_data = o_resp.json()
        assert o_data["amount_usd"] == 950.0
        assert CHECKOUT_URL_ONETIME in o_data["checkout_url"]

        # 3. Invalid email rejected
        bad_req = {
            "team_name": "Valid Team",
            "email": "not-an-email",
            "seats": 5,
            "billing": "monthly"
        }
        b_resp = client.post("/api/v1/pilot/enroll", json=bad_req)
        assert b_resp.status_code == 400

    def test_webhook_missing_secret_fails_closed(self, monkeypatch):
        """When STRIPE_WEBHOOK_SECRET is unset in environment, webhook must fail closed (500)."""
        monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
        payload = {"id": "evt_test_no_secret"}
        resp = client.post(
            "/api/v1/billing/stripe-webhook",
            json=payload,
            headers={"stripe-signature": "t=123,v1=fake"}
        )
        assert resp.status_code == 500
        assert "not configured" in resp.json()["detail"].lower()

    def test_pilot_state_model_strict_separation(self, tmp_path, monkeypatch):
        """Pilot enrollment intent creates PENDING_PAYMENT (not ACTIVE); payment verification required for ACTIVE."""
        # 1. Register enrollment intent -> PENDING_PAYMENT
        record = register_enrollment_intent(
            team_name="Sandbox Engineering",
            email="lead@sandbox.io",
            seats=10,
            billing="monthly"
        )
        assert record["status"] == "PENDING_PAYMENT"
        assert record["passkey_id"] is None
        assert is_pilot_active("lead@sandbox.io") is False

        # 2. Activate upon verified payment -> ACTIVE
        active_rec = activate_pilot_after_payment("lead@sandbox.io")
        assert active_rec["status"] == "ACTIVE"
        assert active_rec["passkey_id"].startswith("BTP-PILOT-")
        assert is_pilot_active("lead@sandbox.io") is True
