"""
Bartholomew Keystone CLI Integration Test Suite
================================================
Verifies bidirectional Keystone-Guard passkey lifecycle:
- Status inspection
- Cryptographic issuance
- Signature verification
- Action scope evaluation (allowed and denied paths)
- Spend budget limit enforcement
"""

import os
import sys
import json
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args):
    cmd = [sys.executable, "-m", "btp_guard.cli"] + list(args)
    p = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def test_keystone_cli_lifecycle():
    # 1. Issue new passkey with $35 budget
    code, stdout, stderr = run_cli("keystone", "issue", "--agent", "test-agent-alpha", "--budget", "35.0")
    assert code == 0, f"Issue failed: {stderr}"
    assert "KEYSTONE CAPABILITY PASSKEY ISSUED" in stdout
    assert "$35.00 USD" in stdout

    # 2. Check status
    code, stdout, stderr = run_cli("keystone", "status")
    assert code == 0, f"Status failed: {stderr}"
    assert "ARMED // VALID" in stdout
    assert "test-agent-alpha" in stdout

    # 3. Verify cryptographic integrity
    code, stdout, stderr = run_cli("keystone", "verify")
    assert code == 0, f"Verify failed: {stderr}"
    assert "VERIFIED (100% valid cryptographic signature" in stdout

    # 4. Evaluate allowed command
    code, stdout, stderr = run_cli("keystone", "evaluate", "--action-type", "command", "--target", "pytest tests/")
    assert code == 0, f"Evaluate allowed failed: {stderr}"
    res = json.loads(stdout)
    assert res["verdict"] == "ALLOW"
    assert res["status"] == "CLEARANCE_GRANTED"

    # 5. Evaluate restricted destructive command (rm)
    code, stdout, stderr = run_cli("keystone", "evaluate", "--action-type", "command", "--target", "rm -rf /etc")
    assert code == 1, "Restricted command should exit with code 1"
    res = json.loads(stdout)
    assert res["verdict"] == "DENY"
    assert res["rule_id"] == "KEYSTONE-CMD-DENIED"

    # 6. Evaluate restricted file write (.env)
    code, stdout, stderr = run_cli("keystone", "evaluate", "--action-type", "file_write", "--target", ".env")
    assert code == 1, "Restricted file write should exit with code 1"
    res = json.loads(stdout)
    assert res["verdict"] == "DENY"
    assert res["rule_id"] == "KEYSTONE-FILE-DENIED"

    # 7. Evaluate budget within limit ($10 < $35)
    code, stdout, stderr = run_cli("keystone", "evaluate", "--action-type", "budget", "--target", "query", "--cost", "10.0")
    assert code == 0, f"Budget within limit failed: {stderr}"
    res = json.loads(stdout)
    assert res["verdict"] == "ALLOW"

    # 8. Evaluate budget exceeding limit ($50 > $35)
    code, stdout, stderr = run_cli("keystone", "evaluate", "--action-type", "budget", "--target", "query", "--cost", "50.0")
    assert code == 1, "Budget exceeding limit should fail"
    res = json.loads(stdout)
    assert res["verdict"] == "DENY"
    assert res["rule_id"] == "KEYSTONE-BUDGET-CAP"


if __name__ == "__main__":
    test_keystone_cli_lifecycle()
    print("[PASS] All Keystone CLI integration tests passed successfully!")
