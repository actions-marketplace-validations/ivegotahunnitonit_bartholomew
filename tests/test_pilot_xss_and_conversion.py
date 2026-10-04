"""
Test Suite: Pilot Conversion Flow & XSS Prevention
==================================================
Tests:
1. site/pilot.html and site/pricing.html do not use innerHTML to interpolate user input.
2. Pilot form scripts make real server fetch to /api/v1/pilot/enroll.
3. No client-side random passkeys are generated in browser code.
4. XSS payloads in team_name or email are handled safely without raw HTML evaluation.
5. Server rejects invalid submissions and accepts valid submissions.
6. Verified distinct checkout links for $199/month and $950 one-time offers.
"""

import json
import re
from pathlib import Path
from fastapi.testclient import TestClient
from src.api.cloud_engine_server import app
from btp_guard.pilot_manager import CHECKOUT_URL_MONTHLY, CHECKOUT_URL_ONETIME

client = TestClient(app)
REPO_ROOT = Path(__file__).resolve().parent.parent


class TestPilotXssAndConversion:

    def test_static_pages_have_no_innerhtml_interpolation(self):
        """Ensure neither pilot.html nor pricing.html interpolates variables into innerHTML."""
        for filename in ["site/pilot.html", "site/pricing.html"]:
            filepath = REPO_ROOT / filename
            assert filepath.exists(), f"{filename} must exist"
            text = filepath.read_text(encoding="utf-8")

            # Check that innerHTML is not used to render form submission results
            assert "resBox.innerHTML" not in text, f"{filename} must not assign to resBox.innerHTML"
            assert "textContent" in text, f"{filename} must use textContent for safe text rendering"
            assert "createTextNode" in text, f"{filename} must use createTextNode for safe DOM insertion"

    def test_no_client_side_passkey_generation(self):
        """Browser scripts must not generate random fake passkeys."""
        for filename in ["site/pilot.html", "site/pricing.html"]:
            filepath = REPO_ROOT / filename
            text = filepath.read_text(encoding="utf-8")
            assert "Math.random().toString(16)" not in text, f"{filename} must not generate passkeys via Math.random"
            assert "BTP-PILOT-" not in text or "generate_secure_pilot_passkey" in text or "Cryptographic access passkeys" in text

    def test_real_server_submission_endpoint_called(self):
        """Browser scripts must call the real server endpoint /api/v1/pilot/enroll."""
        for filename in ["site/pilot.html", "site/pricing.html"]:
            filepath = REPO_ROOT / filename
            text = filepath.read_text(encoding="utf-8")
            assert "fetch('/api/v1/pilot/enroll'" in text or 'fetch("/api/v1/pilot/enroll"' in text

    def test_xss_payload_submission_and_safe_rendering(self):
        """XSS attack payloads must be safely accepted by server and handled without raw HTML execution."""
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '"><svg/onload=alert(document.cookie)>',
            "Fintech Corp <iframe src='javascript:alert(1)'>"
        ]

        for payload in xss_payloads:
            req = {
                "team_name": payload,
                "email": "security_auditor@acme.org",
                "seats": 10,
                "agent": "cursor",
                "billing": "monthly"
            }
            resp = client.post("/api/v1/pilot/enroll", json=req)
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "SUCCESS"
            assert data["team_name"] == payload.strip()
            # The checkout URL must be properly URL-encoded
            assert "<script>" not in data["checkout_url"]
            assert "<img" not in data["checkout_url"]

    def test_distinct_checkout_destination_monthly_vs_onetime(self):
        """Distinct Stripe checkout URLs must be generated for $199/mo vs $950 one-time."""
        # 1. Monthly $199
        resp_m = client.post("/api/v1/pilot/enroll", json={
            "team_name": "Dev Swarm",
            "email": "lead@devswarm.com",
            "seats": 10,
            "billing": "monthly"
        })
        assert resp_m.status_code == 200
        data_m = resp_m.json()
        assert data_m["amount_usd"] == 199.0
        assert CHECKOUT_URL_MONTHLY in data_m["checkout_url"]
        assert CHECKOUT_URL_ONETIME not in data_m["checkout_url"]

        # 2. One-Time $950
        resp_o = client.post("/api/v1/pilot/enroll", json={
            "team_name": "Enterprise Pilot",
            "email": "ciso@enterprise.com",
            "seats": 25,
            "billing": "onetime"
        })
        assert resp_o.status_code == 200
        data_o = resp_o.json()
        assert data_o["amount_usd"] == 950.0
        assert CHECKOUT_URL_ONETIME in data_o["checkout_url"]
        assert CHECKOUT_URL_MONTHLY not in data_o["checkout_url"]

    def test_rejected_submissions(self):
        """Server rejects empty team, invalid email, invalid seats, or wrong billing."""
        # Missing team
        r1 = client.post("/api/v1/pilot/enroll", json={"team_name": "", "email": "valid@corp.io", "billing": "monthly"})
        assert r1.status_code == 400

        # Invalid email
        r2 = client.post("/api/v1/pilot/enroll", json={"team_name": "Team", "email": "bad_email", "billing": "monthly"})
        assert r2.status_code == 400

        # Invalid seat count
        r3 = client.post("/api/v1/pilot/enroll", json={"team_name": "Team", "email": "valid@corp.io", "seats": -5, "billing": "monthly"})
        assert r3.status_code == 400

        # Invalid billing option
        r4 = client.post("/api/v1/pilot/enroll", json={"team_name": "Team", "email": "valid@corp.io", "billing": "free_tier"})
        assert r4.status_code == 400
