"""
Test Suite: Bartholomew Universal Financial Gateway (Apple Pay, Google Pay, Visa Direct, Stripe)
=================================================================================================
Validates:
  1. Universal 2.5% take-rate + $0.02 micro-toll across disparate payment schemes.
  2. Apple Pay PassKit token & Web Payments schema normalization.
  3. Google Pay PaymentData & transactionInfo normalization.
  4. Visa Direct fast push disbursement ceiling containment.
  5. 1-Line `wrap_payment` SDK drop-in integration.
  6. Zero-liability cryptographic attestation stamps across all providers.
"""

import os
import json
import pytest
from btp_guard import (
    BtpUniversalPayGuard,
    PaymentProvider,
    wrap_payment
)
from btp_guard.integrations.universal_pay import UniversalSecurityVetoException


class TestUniversalPaymentGateway:
    """Tests the Universal Joint for AI Agent Payments."""

    def test_apple_pay_settlement_and_toll(self, tmp_path):
        ledger = str(tmp_path / "apple_pay_ledger.db")
        guard = BtpUniversalPayGuard(max_transaction_usd=500.0, ledger_path=ledger)

        # Standard Apple Pay Web / PassKit payload schema
        apple_pay_args = {
            "countryCode": "US",
            "currencyCode": "USD",
            "total": {
                "label": "Agent Provisioned Cloud Compute",
                "amount": "120.00",
                "type": "final"
            },
            "paymentData": {
                "version": "EC_v1",
                "data": "synthetic_encrypted_payment_blob_for_testing"
            }
        }

        clearance = guard.secure_clearance(
            PaymentProvider.APPLE_PAY,
            "authorize_payment",
            apple_pay_args,
            agent_id="agent-apple-pay-01"
        )

        assert clearance["status"] == "CLEARANCE_GRANTED_AND_BILLED"
        assert clearance["provider"] == "APPLE_PAY"
        assert clearance["transaction_volume_usd"] == 120.00
        # 2.5% of $120.00 is $3.00 + $0.02 micro-toll = $3.02
        assert clearance["protocol_fee_usd"] == 3.02
        assert clearance["attestation_voucher"].startswith("attest_apple_pay_")
        assert clearance["warranty_status"] == "ZERO_LIABILITY_AUDIT_STAMP"
        assert clearance["latency_us"] < 10000.0

    def test_google_pay_settlement_and_toll(self, tmp_path):
        ledger = str(tmp_path / "google_pay_ledger.db")
        guard = BtpUniversalPayGuard(max_transaction_usd=500.0, ledger_path=ledger)

        # Standard Google Pay PaymentData Request payload schema
        google_pay_args = {
            "apiVersion": 2,
            "apiVersionMinor": 0,
            "transactionInfo": {
                "totalPrice": "80.00",
                "totalPriceStatus": "FINAL",
                "currencyCode": "USD"
            }
        }

        clearance = guard.secure_clearance(
            PaymentProvider.GOOGLE_PAY,
            "load_payment_data",
            google_pay_args,
            agent_id="agent-gpay-02"
        )

        assert clearance["status"] == "CLEARANCE_GRANTED_AND_BILLED"
        assert clearance["provider"] == "GOOGLE_PAY"
        assert clearance["transaction_volume_usd"] == 80.00
        # 2.5% of $80.00 is $2.00 + $0.02 micro-toll = $2.02
        assert clearance["protocol_fee_usd"] == 2.02
        assert clearance["attestation_voucher"].startswith("attest_google_pay_")

    def test_visa_direct_push_payment(self, tmp_path):
        ledger = str(tmp_path / "visa_direct_ledger.db")
        guard = BtpUniversalPayGuard(max_transaction_usd=500.0, ledger_path=ledger)

        # Standard Visa Direct original credit transaction (OCT) payload
        visa_args = {
            "transactionAmount": 25000,  # 25,000 cents = $250.00
            "currency": "840",  # USD ISO code
            "recipientPrimaryAccountNumber": "4000001234567890",
            "retrievalReferenceNumber": "ref_987654"
        }

        clearance = guard.secure_clearance(
            PaymentProvider.VISA_DIRECT,
            "push_funds_payout",
            visa_args,
            agent_id="visa-payout-bot"
        )

        assert clearance["status"] == "CLEARANCE_GRANTED_AND_BILLED"
        assert clearance["provider"] == "VISA_DIRECT"
        assert clearance["transaction_volume_usd"] == 250.00
        # 2.5% of $250.00 is $6.25 + $0.02 micro-toll = $6.27
        assert clearance["protocol_fee_usd"] == 6.27
        assert clearance["attestation_voucher"].startswith("attest_visa_direct_")

    def test_universal_spending_ceiling_veto(self, tmp_path):
        ledger = str(tmp_path / "veto_ledger.db")
        guard = BtpUniversalPayGuard(max_transaction_usd=300.0, ledger_path=ledger)

        with pytest.raises(UniversalSecurityVetoException) as exc_info:
            guard.secure_clearance(
                PaymentProvider.VISA_DIRECT,
                "fund_transfer",
                {"transactionAmount": 45000}  # $450.00 > $300.00 cap
            )

        assert "BTP-PAY-001" in str(exc_info.value)
        assert "$450.00 exceeds safety ceiling" in str(exc_info.value)

    def test_one_line_wrap_payment_helper(self, tmp_path):
        ledger = str(tmp_path / "wrap_ledger.db")

        def mock_apple_pay_call(total: dict, **kwargs):
            return {"status": "SUCCESS", "auth_code": "AUTH_APPLE_999"}

        # 1-Line Universal Drop-In
        guarded_apple_pay = wrap_payment(
            PaymentProvider.APPLE_PAY,
            mock_apple_pay_call,
            max_transaction_usd=500.0,
            ledger_path=ledger
        )

        result = guarded_apple_pay(total={"amount": "65.00"})
        assert result["status"] == "SUCCESS"
        assert result["auth_code"] == "AUTH_APPLE_999"
