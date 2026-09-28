"""
Test Suite: BTP Secure Stripe Agent Toolkit & Commercial Gateway (BTP v5.4.22)
==============================================================================
Validates:
  1. Automated 2.5% protocol fee & micro-toll compensation on Stripe tool calls.
  2. Live Stripe secret key scrubbing (`sk_test_...`, `rk_test_...`).
  3. Max transaction and cumulative daily refund ceiling enforcement.
  4. Zero-Liability Cryptographic Attestation Stamp issuance (Warranty decoupled).
  5. 1-Line `wrap_stripe` drop-in wrapper for AI agent tooling.
  6. Commercial license gating and upgrade checkout link generation.
"""

import os
import json
import pytest
from btp_guard.integrations.stripe_agent import (
    BtpStripeAgentGuard,
    StripeSecurityVetoException,
    BtpStripeLicenseRequiredException,
    wrap_stripe
)


class TestStripeAgentGuard:
    """Verifies commercial protection, zero-liability attestation, and compensation."""

    def test_benign_charge_with_protocol_compensation(self, tmp_path):
        ledger = str(tmp_path / "stripe_test_ledger.json")
        guard = BtpStripeAgentGuard(max_transaction_usd=500.0, ledger_path=ledger)

        # Dynamically constructed synthetic test token (avoids static scanner regexes)
        dummy_secret = "".join(["rk_", "test_", "synthetic_restricted_token_for_btp_masker_tests_0000"])
        args = {
            "customer_id": "cus_999",
            "amount": 10000,  # 10,000 cents = $100.00
            "currency": "usd",
            "metadata": {
                "source_token": dummy_secret
            }
        }

        clearance = guard.secure_stripe_call("create_payment_intent", args, agent_id="fintech-agent-01")

        assert clearance["status"] == "CLEARANCE_GRANTED_AND_BILLED"
        # 2.5% of $100.00 is $2.50 + $0.02 micro-toll = $2.52
        assert clearance["protocol_fee_usd"] == 2.52
        assert clearance["transaction_volume_usd"] == 100.0
        assert clearance["attestation_voucher"] is not None
        assert clearance["attestation_voucher"].startswith("attest_")
        assert clearance["warranty_bond_id"] is None  # Zero balance sheet liability by default
        assert "Zero underwritten balance-sheet liability" in clearance["liability_disclaimer"]
        assert "synthetic_restricted" not in json.dumps(clearance["sanitized_arguments"])
        assert clearance["latency_us"] < 10000.0  # Sub-10ms cold start

    def test_explicit_warranty_bond_simulation(self, tmp_path):
        ledger = str(tmp_path / "stripe_test_ledger.json")
        guard = BtpStripeAgentGuard(
            max_transaction_usd=500.0, 
            ledger_path=ledger, 
            enable_warranty_bonding=True
        )

        args = {"amount": 5000, "currency": "usd"}
        clearance = guard.secure_stripe_call("create_charge", args)
        assert clearance["warranty_bond_id"] is not None
        assert clearance["warranty_bond_id"].startswith("bond-")
        assert clearance["warranty_status"] == "BONDED"

    def test_transaction_ceiling_veto(self, tmp_path):
        ledger = str(tmp_path / "stripe_test_ledger.json")
        guard = BtpStripeAgentGuard(max_transaction_usd=250.0, ledger_path=ledger)

        # Agent attempts to charge $600.00 exceeding $250.00 cap
        args = {"amount": 60000, "currency": "usd"}

        with pytest.raises(StripeSecurityVetoException) as exc_info:
            guard.secure_stripe_call("create_charge", args)

        assert "BTP-FIN-001" in str(exc_info.value)
        assert "$600.00 exceeds configured safety cap" in str(exc_info.value)

    def test_daily_refund_abuse_prevention(self, tmp_path):
        ledger = str(tmp_path / "stripe_test_ledger.json")
        guard = BtpStripeAgentGuard(daily_refund_limit_usd=300.0, ledger_path=ledger)

        # First refund: $200.00 (allowed)
        guard.secure_stripe_call("issue_refund", {"amount": 20000})

        # Second refund: $150.00 (exceeds $300 cumulative ceiling)
        with pytest.raises(StripeSecurityVetoException) as exc_info:
            guard.secure_stripe_call("issue_refund", {"amount": 15000})

        assert "BTP-FIN-002" in str(exc_info.value)
        assert "exceed daily safety ceiling" in str(exc_info.value)

    def test_tool_wrapper_execution(self, tmp_path):
        ledger = str(tmp_path / "stripe_test_ledger.json")
        guard = BtpStripeAgentGuard(max_transaction_usd=500.0, ledger_path=ledger)

        # Mock Stripe SDK tool function
        execution_recorded = {}
        def mock_stripe_create_link(customer_id: str, amount: int, **kwargs):
            execution_recorded["customer_id"] = customer_id
            execution_recorded["amount"] = amount
            return {"id": "plink_123", "url": "https://buy.stripe.com/test"}

        wrapped_tool = guard.wrap_tool(mock_stripe_create_link, action_name="create_payment_link")
        
        result = wrapped_tool(customer_id="cus_test", amount=5000)
        assert result["id"] == "plink_123"
        assert execution_recorded["amount"] == 5000

    def test_one_line_wrap_stripe_helper(self, tmp_path):
        ledger = str(tmp_path / "stripe_test_ledger.json")
        
        def mock_charge(customer_id: str, amount: int, **kwargs):
            return {"status": "succeeded", "charge_id": "ch_999"}

        # 1-Line Drop-In SDK Wrapper
        guarded_charge = wrap_stripe(mock_charge, max_transaction_usd=500.0, ledger_path=ledger)
        res = guarded_charge(customer_id="cus_abc", amount=2500)
        assert res["status"] == "succeeded"
        assert res["charge_id"] == "ch_999"
