"""
Test Suite: The Complete ARP Blueprint (Stripe Connect Split, Agent Passport KYC, HITL Gate, M2M L402)
====================================================================================================
Validates the 4 foundational pillars:
  1. Stripe Connect automated 2.5% platform fee split (`application_fee_amount`).
  2. Cryptographic Corporate Agent Passports (Ed25519/HMAC KYC delegation).
  3. Human-in-the-Loop (HITL) Dual-Control Escalation & Tokenized Approval.
  4. M2M Autonomous Micro-Streaming via HTTP 402 / L402.
"""

import os
import json
import time
import pytest

from btp_guard import (
    BtpUniversalPayGuard,
    PaymentProvider,
    AgentPassport,
    AgentPassportAuthority,
    HITLApprovalGate,
    HITLEscalationRequiredException,
    BtpM2MMicroToll
)


class TestCompleteBlueprintPillars:
    """Verifies all 4 advanced capabilities of the Bartholomew Protocol."""

    def test_pillar_1_stripe_connect_application_fee_split(self, tmp_path):
        ledger = str(tmp_path / "connect_ledger.db")
        guard = BtpUniversalPayGuard(
            max_transaction_usd=500.0,
            platform_stripe_account="acct_btp_treasury_payout",
            ledger_path=ledger
        )

        args = {
            "amount": 10000,  # $100.00
            "currency": "usd",
            "customer": "cus_enterprise_1"
        }

        clearance = guard.secure_clearance(PaymentProvider.STRIPE, "create_charge", args)

        assert clearance["status"] == "CLEARANCE_GRANTED_AND_BILLED"
        # 2.5% of $100.00 = $2.50 + $0.02 = $2.52 -> 252 cents
        assert clearance["protocol_fee_usd"] == 2.52
        assert clearance["application_fee_cents"] == 252
        assert clearance["platform_treasury_account"] == "acct_btp_treasury_payout"
        
        # Verify injected into Stripe arguments
        sanitized = clearance["sanitized_arguments"]
        assert sanitized["application_fee_amount"] == 252
        assert sanitized["on_behalf_of_platform"] == "acct_btp_treasury_payout"

    def test_pillar_2_corporate_agent_passport_kyc(self):
        auth = AgentPassportAuthority()

        # Treasury issues an authorized agent passport for Grok Trader
        passport = auth.issue_passport(
            agent_id="grok-trader-99",
            organization_id="org_citadel_hedge",
            treasury_account="acct_treasury_main",
            spend_cap_usd=750.0,
            authorized_rails=["STRIPE", "VISA_DIRECT"],
            validity_seconds=3600.0
        )

        assert passport.signature_hex is not None

        # 1. Valid invocation within scope and budget
        is_valid, reason = auth.verify_passport(passport, requested_rail="STRIPE", requested_amount_usd=200.0)
        assert is_valid is True
        assert reason == "PASSPORT_VERIFIED_VALID"

        # 2. Invalid rail requested (e.g. unauthorized Apple Pay)
        is_valid, reason = auth.verify_passport(passport, requested_rail="APPLE_PAY", requested_amount_usd=100.0)
        assert is_valid is False
        assert "not in authorized capabilities" in reason

        # 3. Exceeded passport ceiling ($800 > $750)
        is_valid, reason = auth.verify_passport(passport, requested_rail="STRIPE", requested_amount_usd=800.0)
        assert is_valid is False
        assert "exceeds passport authorized ceiling" in reason

    def test_pillar_3_human_in_the_loop_dual_control_gate(self):
        gate = HITLApprovalGate(escalation_threshold_usd=250.0, timeout_seconds=10.0)

        # Action under threshold does NOT escalate
        assert gate.should_escalate("charge_customer", 150.0) is False

        # Action over $250.00 DOES escalate
        assert gate.should_escalate("charge_customer", 350.0) is True

        # Action with destructive keyword escalates regardless of amount
        assert gate.should_escalate("drop_customer_data", 0.0) is True

        # Create challenge
        challenge = gate.create_challenge(
            action_name="large_disbursement",
            amount_usd=400.0,
            agent_id="grok-finance-bot",
            reason="Large wire disbursement requested"
        )

        assert challenge.status == "PENDING"
        assert challenge.token is not None

        # Human resolves with valid cryptographic token
        success, msg = gate.resolve_challenge(challenge.challenge_id, challenge.token, approve=True)
        assert success is True
        assert challenge.status == "APPROVED"

    def test_pillar_4_m2m_autonomous_l402_micro_toll(self):
        m2m = BtpM2MMicroToll()

        # 1. Server issues HTTP 402 challenge
        challenge = m2m.create_402_challenge(
            service_id="llm_eval_microservice",
            amount_satoshis=20,
            fee_usd=0.005,
            agent_id="caller-bot-01"
        )

        assert challenge["status_code"] == 402
        assert "L402 token=" in challenge["www_authenticate"]
        assert challenge["amount_satoshis"] == 20
        assert challenge["fee_usd"] == 0.005

        # 2. Extract macaroon and simulate payment preimage (preimage matching hash)
        token_part = challenge["www_authenticate"].split('token="')[1].split('"')[0]
        
        # Verify invalid scheme rejected
        is_valid, reason, _ = m2m.verify_payment_and_grant("Bearer invalid_token", expected_agent_id="caller-bot-01")
        assert is_valid is False

        # Verify valid scheme accepted
        auth_header = f"L402 {token_part}:{challenge['preimage_hex']}"
        is_valid, reason, receipt = m2m.verify_payment_and_grant(
            auth_header,
            expected_agent_id="caller-bot-01",
            expected_action="llm_eval_microservice"
        )
        assert is_valid is True
        assert receipt["status"] == "M2M_MICROPAYMENT_CLEARED"
        assert receipt["attestation"].startswith("attest_l402_")
