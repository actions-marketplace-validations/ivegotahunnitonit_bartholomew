"""
Test Suite: Truthful Proof Provider & Status Veracity
=====================================================
Validates that proof_provider.ts:
1. Rejects unverified status (never reports ARMED without verified daemon + valid policy + hook + passkey).
2. Scores checks only when actually executed and verified (not on mere file existence).
3. Detects absent daemon and reports DISCONNECTED or PARTIALLY_ARMED.
4. Detects unrelated local service and rejects daemon identity.
5. Fails check on missing policy.
6. Fails check on malformed/corrupted policy.
7. Fails check on stale or non-fail-closed pre-commit hook.
8. Fails check on expired or invalid Keystone passkey.
9. Accurately reports real audit events and latencies without synthetic floors.
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PROOF_JS = REPO_ROOT / "packages" / "vscode-extension" / "dist" / "proof_provider.js"


def run_node_telemetry_check(workspace_dir: str, daemon_status: dict = None) -> dict:
    """Invokes compiled proof_provider.js via Node.js to evaluate truthful telemetry with mock vscode module."""
    daemon_arg = json.dumps(daemon_status) if daemon_status is not None else "undefined"
    node_code = f"""
    const Module = require('module');
    const origRequire = Module.prototype.require;
    Module.prototype.require = function(mod) {{
      if (mod === 'vscode') {{
        return {{
          workspace: {{ workspaceFolders: [] }},
          Uri: {{ file: (p) => ({{ fsPath: p }}) }}
        }};
      }}
      return origRequire.apply(this, arguments);
    }};

    const {{ loadTelemetry }} = require({json.dumps(str(PROOF_JS).replace(chr(92), '/'))});
    const res = loadTelemetry({json.dumps(str(workspace_dir).replace(chr(92), '/'))}, {daemon_arg});
    console.log(JSON.stringify(res));
    """
    proc = subprocess.run(["node", "-e", node_code], capture_output=True, text=True)
    assert proc.returncode == 0, f"Node script error: {proc.stderr}"
    return json.loads(proc.stdout.strip())


class TestTruthfulProofProvider:

    def test_no_policy_fails_check(self, tmp_path):
        """When policy is absent, policy check must fail and status must not be ARMED."""
        res = run_node_telemetry_check(str(tmp_path), {"online": False})
        assert res["status"] == "DISCONNECTED"
        policy_check = next(c for c in res["checks"] if c["id"] == "policy")
        assert policy_check["passed"] is False

    def test_malformed_policy_fails_check(self, tmp_path):
        """When policy is malformed or corrupt, check must fail."""
        policy_file = tmp_path / ".btp" / "policy.yaml"
        policy_file.parent.mkdir(parents=True, exist_ok=True)
        policy_file.write_text("MALFORMED_POLICY_ERROR: {not: valid yaml", encoding="utf-8")

        res = run_node_telemetry_check(str(tmp_path), {"online": False})
        policy_check = next(c for c in res["checks"] if c["id"] == "policy")
        assert policy_check["passed"] is False

    def test_stale_hook_without_fail_closed_fails_check(self, tmp_path):
        """Pre-commit hook without fail-closed barrier must fail the hook check."""
        hook_file = tmp_path / ".git" / "hooks" / "pre-commit"
        hook_file.parent.mkdir(parents=True, exist_ok=True)
        # Old legacy hook without fail-closed barrier
        hook_file.write_text("#!/bin/sh\necho 'old hook'\nexit 0\n", encoding="utf-8")

        res = run_node_telemetry_check(str(tmp_path), {"online": False})
        hook_check = next(c for c in res["checks"] if c["id"] == "hook")
        assert hook_check["passed"] is False

    def test_expired_passkey_fails_check(self, tmp_path):
        """Expired Keystone passkey must fail the clearance check."""
        keystone_file = tmp_path / ".btp" / "keystone.json"
        keystone_file.parent.mkdir(parents=True, exist_ok=True)
        keystone_file.write_text(json.dumps({
            "passkey_id": "key_expired_123",
            "agent_id": "test_agent",
            "expires_at": "2020-01-01T00:00:00Z"  # Past date
        }), encoding="utf-8")

        res = run_node_telemetry_check(str(tmp_path), {"online": False})
        keystone_check = next(c for c in res["checks"] if c["id"] == "keystone")
        assert keystone_check["passed"] is False
        assert res["keystone"]["armed"] is False

    def test_absent_daemon_never_reports_armed(self, tmp_path):
        """When local daemon is absent, UI must report DISCONNECTED or PARTIALLY_ARMED, never ARMED."""
        policy_file = tmp_path / ".btp" / "policy.yaml"
        policy_file.parent.mkdir(parents=True, exist_ok=True)
        policy_file.write_text("invariants:\n  block_destructive_shell: true\n", encoding="utf-8")

        hook_file = tmp_path / ".git" / "hooks" / "pre-commit"
        hook_file.parent.mkdir(parents=True, exist_ok=True)
        hook_file.write_text("#!/bin/sh\n# FAIL-CLOSED\nbtp-guard check --staged || exit 1\n", encoding="utf-8")

        keystone_file = tmp_path / ".btp" / "keystone.json"
        keystone_file.write_text(json.dumps({
            "passkey_id": "key_valid_123",
            "agent_id": "test_agent",
            "expires_at": "2099-01-01T00:00:00Z"
        }), encoding="utf-8")

        # Daemon offline / undefined
        res_offline = run_node_telemetry_check(str(tmp_path), None)
        assert res_offline["status"] == "PARTIALLY_ARMED"
        assert res_offline["status"] != "ARMED"

    def test_unrelated_local_service_fails_daemon_verification(self, tmp_path):
        """An unrelated service on the local port must be rejected and never report ARMED."""
        policy_file = tmp_path / ".btp" / "policy.yaml"
        policy_file.parent.mkdir(parents=True, exist_ok=True)
        policy_file.write_text("invariants:\n  block_destructive_shell: true\n", encoding="utf-8")

        hook_file = tmp_path / ".git" / "hooks" / "pre-commit"
        hook_file.parent.mkdir(parents=True, exist_ok=True)
        hook_file.write_text("#!/bin/sh\n# FAIL-CLOSED\nbtp-guard check --staged || exit 1\n", encoding="utf-8")

        keystone_file = tmp_path / ".btp" / "keystone.json"
        keystone_file.write_text(json.dumps({
            "passkey_id": "key_valid_123",
            "agent_id": "test_agent",
            "expires_at": "2099-01-01T00:00:00Z"
        }), encoding="utf-8")

        # Unrelated local service identity
        unrelated_status = {
            "online": True,
            "healthy": True,
            "service": "unrelated-custom-web-service",
            "version": "1.0.0"
        }
        res = run_node_telemetry_check(str(tmp_path), unrelated_status)
        assert res["status"] != "ARMED"
        assert res["status"] == "PARTIALLY_ARMED"

    def test_verified_daemon_and_barriers_reports_armed(self, tmp_path):
        """When daemon identity is verified alongside valid policy, hook, and passkey, report ARMED."""
        policy_file = tmp_path / ".btp" / "policy.yaml"
        policy_file.parent.mkdir(parents=True, exist_ok=True)
        policy_file.write_text("invariants:\n  block_destructive_shell: true\n", encoding="utf-8")

        hook_file = tmp_path / ".git" / "hooks" / "pre-commit"
        hook_file.parent.mkdir(parents=True, exist_ok=True)
        hook_file.write_text("#!/bin/sh\n# FAIL-CLOSED\nbtp-guard check --staged || exit 1\n", encoding="utf-8")

        keystone_file = tmp_path / ".btp" / "keystone.json"
        keystone_file.write_text(json.dumps({
            "passkey_id": "key_valid_123",
            "agent_id": "test_agent",
            "expires_at": "2099-01-01T00:00:00Z"
        }), encoding="utf-8")

        verified_daemon = {
            "online": True,
            "healthy": True,
            "service": "bartolomew-cloud-engine",
            "version": "6.4.1"
        }
        res = run_node_telemetry_check(str(tmp_path), verified_daemon)
        assert res["status"] == "ARMED"
        assert res["securityScore"] >= 95
        assert res["grade"] == "A+"

    def test_real_audit_events_and_latencies_truthful(self, tmp_path):
        """Audit counts and average latency must come from actual recorded events, not synthetic floors."""
        audit_file = tmp_path / ".btp" / "audit.log"
        audit_file.parent.mkdir(parents=True, exist_ok=True)

        events = [
            {"timestamp": "2026-10-04T00:00:01Z", "action": "git status", "verdict": "ALLOWED", "latency_us": 12.0},
            {"timestamp": "2026-10-04T00:00:02Z", "action": "rm -rf /", "verdict": "BLOCKED", "latency_us": 24.0},
            {"timestamp": "2026-10-04T00:00:03Z", "action": "cat file.txt", "verdict": "ALLOWED", "latency_us": 18.0}
        ]
        with open(audit_file, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

        res = run_node_telemetry_check(str(tmp_path), None)
        assert res["totalAudited"] == 3
        assert res["totalBlocked"] == 1
        assert res["astLatencyUs"] == 18.0
        assert len(res["recentEvents"]) == 3

    def test_malicious_audit_log_injection_and_csp(self, tmp_path):
        """Proves malicious XSS payloads in audit logs are rendered inertly and strict CSP is enforced."""
        audit_file = tmp_path / ".btp" / "audit.log"
        audit_file.parent.mkdir(parents=True, exist_ok=True)

        malicious_events = [
            {
                "timestamp": "2026-10-04T00:00:01Z",
                "action": "<script>alert('xss_action')</script>",
                "verdict": "BLOCKED",
                "rule_id": "<svg onload=alert(1)>",
                "reason": "<img src=x onerror=fetch('http://evil.com')>",
                "latency_us": 15.0,
                "receipt_sha256": "abcdef1234567890"
            }
        ]
        with open(audit_file, "w", encoding="utf-8") as f:
            for ev in malicious_events:
                f.write(json.dumps(ev) + "\n")

        node_code = f"""
        const Module = require('module');
        const origRequire = Module.prototype.require;
        Module.prototype.require = function(mod) {{
          if (mod === 'vscode') {{
            return {{
              workspace: {{ workspaceFolders: [] }},
              Uri: {{ file: (p) => ({{ fsPath: p }}) }}
            }};
          }}
          return origRequire.apply(this, arguments);
        }};

        const {{ loadTelemetry, getWebviewContent }} = require({json.dumps(str(PROOF_JS).replace(chr(92), '/'))});
        const rootPath = {json.dumps(str(tmp_path).replace(chr(92), '/'))};
        const tel = loadTelemetry(rootPath);
        const html = getWebviewContent(tel, rootPath);
        console.log(html);
        """
        proc = subprocess.run(["node", "-e", node_code], capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert proc.returncode == 0, f"Node script error: {proc.stderr}"
        html_out = proc.stdout

        # Verify strict CSP exists
        assert '<meta http-equiv="Content-Security-Policy"' in html_out
        assert "default-src 'none'" in html_out

        # Verify raw malicious HTML tags are NOT present
        assert "<script>alert('xss_action')</script>" not in html_out
        assert "<img src=x onerror=fetch('http://evil.com')>" not in html_out
        assert "<svg onload=alert(1)>" not in html_out

        # Verify properly escaped entities ARE present
        assert "&lt;script&gt;alert(&#039;xss_action&#039;)&lt;/script&gt;" in html_out
        assert "&lt;img src=x onerror=fetch(&#039;http://evil.com&#039;)&gt;" in html_out
        assert "&lt;svg onload=alert(1)&gt;" in html_out
