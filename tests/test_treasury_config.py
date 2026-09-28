import os
import sys
import json
import pytest

from btp_guard.integrations.universal_pay import BtpUniversalPayGuard, _load_treasury_config

def test_load_treasury_config():
    cfg = _load_treasury_config()
    assert isinstance(cfg, dict)
    assert "stripe_connect_account_id" in cfg
    assert cfg["stripe_connect_account_id"] == "acct_1BTP_TREASURY_MAIN"

def test_universal_pay_picks_up_configured_treasury():
    guard = BtpUniversalPayGuard()
    assert guard.platform_stripe_account == "acct_1BTP_TREASURY_MAIN"

def test_universal_pay_override_treasury():
    guard = BtpUniversalPayGuard(platform_stripe_account="acct_custom_override_99")
    assert guard.platform_stripe_account == "acct_custom_override_99"
