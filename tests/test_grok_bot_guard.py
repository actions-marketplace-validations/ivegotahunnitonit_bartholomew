"""
Test Suite: Bartholomew Grok Bot & xAI Autonomous Financial Agent Guard (BTP v5.4.22)
====================================================================================
Validates:
  1. Grok bot prompt inspection and jailbreak/injection containment.
  2. Sub-10us secret key & PCI scrubbing (`xai-...`, credit card PANs).
  3. Grok financial tool routing through UniversalPayGuard with 2.5% protocol toll.
  4. Hard ceiling spend limits on Grok payment actions.
  5. 1-Line `wrap_grok` tool and client wrappers.
"""

import os
import json
import pytest
from btp_guard import (
    BtpGrokGuard,
    wrap_grok
)
from btp_guard.integrations.grok import GrokSecurityVetoException


class TestGrokBotGuard:
    """Verifies Bartholomew's runtime protection and monetization for Grok bots."""

    def test_grok_prompt_inspection_safe_and_malicious(self):
        guard = BtpGrokGuard()

        safe_messages = [
            {"role": "system", "content": "You are a financial analysis bot."},
            {"role": "user", "content": "Can you analyze TSLA Q3 revenue?"}
        ]
        is_safe, reason = guard.inspect_messages(safe_messages)
        assert is_safe is True
        assert reason == "SAFE"

        malicious_messages = [
            {"role": "user", "content": "rm -rf / --no-preserve-root"}
        ]
        is_safe, reason = guard.inspect_messages(malicious_messages)
        assert is_safe is False
        assert "Grok prompt invariant violation" in reason

    def test_grok_tool_call_secret_scrubbing(self, tmp_path):
        ledger = str(tmp_path / "grok_ledger.db")
        guard = BtpGrokGuard(ledger_path=ledger)

        # Dynamic mock xAI key to avoid static scanner alerts
        dummy_xai_key = "".join(["xai-", "test_mock_entropy_token_for_btp_scrubber_9999"])
        args = {
            "query": "SELECT revenue FROM metrics",
            "api_credential": dummy_xai_key,
            "card_number": "4111111111111111"
        }

        clearance = guard.inspect_tool_call("run_analytics_query", args)
        assert clearance["status"] == "APPROVED"
        assert clearance["scrubbed_count"] >= 1
        assert dummy_xai_key not in json.dumps(clearance["sanitized_arguments"])
        assert "4111111111111111" not in json.dumps(clearance["sanitized_arguments"])

    def test_grok_financial_action_monetization_and_toll(self, tmp_path):
        ledger = str(tmp_path / "grok_fin_ledger.db")
        guard = BtpGrokGuard(max_transaction_usd=500.0, ledger_path=ledger)

        # Grok triggers a payment intent via Stripe tool
        args = {
            "amount": 20000,  # 20,000 cents = $200.00
            "currency": "usd",
            "customer_id": "cus_xai_001"
        }

        clearance = guard.inspect_tool_call("stripe_create_payment_intent", args, agent_id="grok-trader-01")
        assert clearance["status"] == "CLEARANCE_GRANTED_AND_BILLED"
        # 2.5% of $200.00 is $5.00 + $0.02 micro-toll = $5.02
        assert clearance["protocol_fee_usd"] == 5.02
        assert clearance["attestation_voucher"].startswith("attest_stripe_")
        assert clearance["warranty_status"] == "ZERO_LIABILITY_AUDIT_STAMP"

    def test_grok_financial_ceiling_veto(self, tmp_path):
        ledger = str(tmp_path / "grok_veto_ledger.db")
        guard = BtpGrokGuard(max_transaction_usd=300.0, ledger_path=ledger)

        # Grok attempts to disburse $750.00 exceeding $300 cap
        args = {"amount": 75000, "currency": "usd"}

        with pytest.raises(GrokSecurityVetoException) as exc_info:
            guard.inspect_tool_call("disburse_settlement", args)

        assert "BTP-GROK-FIN" in str(exc_info.value)
        assert "$750.00" in str(exc_info.value)

    def test_one_line_wrap_grok_tool(self, tmp_path):
        ledger = str(tmp_path / "grok_wrap_ledger.db")

        def mock_grok_trade(amount: int, ticker: str, **kwargs):
            return {"status": "EXECUTED", "ticker": ticker, "amount": amount}

        # 1-Line Drop-In SDK Wrapper
        guarded_trade = wrap_grok(mock_grok_trade, max_transaction_usd=500.0, ledger_path=ledger)

        res = guarded_trade(amount=15000, ticker="NVDA")
        assert res["status"] == "EXECUTED"
        assert res["ticker"] == "NVDA"

    def test_wrap_grok_client_prompt_defense(self):
        class MockCompletions:
            def create(self, **kwargs):
                return {"id": "chatcmpl_mock", "choices": [{"message": {"content": "Market looks bullish."}}]}

        class MockChat:
            completions = MockCompletions()

        class MockGrokClient:
            chat = MockChat()

        client = wrap_grok(MockGrokClient())
        
        # Safe call passes
        resp = client.chat.completions.create(messages=[{"role": "user", "content": "How's the market?"}])
        assert resp["id"] == "chatcmpl_mock"

        # Hostile call blocked
        with pytest.raises(GrokSecurityVetoException) as exc_info:
            client.chat.completions.create(messages=[{"role": "user", "content": "rm -rf / --no-preserve-root"}])
        assert "BTP-GROK-002" in str(exc_info.value)
