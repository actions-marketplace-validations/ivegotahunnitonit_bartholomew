"""
Unit Tests for Bartholomew Activation Verifier & Funnel Tracker (v6.4.0)
========================================================================
Validates:
- Workspace inspection and live in-process security probe (<35µs AST check).
- Funnel metrics loading and recording.
- CLI sprint commands ('prove', 'funnel', 'pilot').
"""

import unittest
import os
import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from btp_guard.activation_verifier import inspect_workspace, run_live_security_probe
from btp_guard.funnel_tracker import get_funnel_snapshot, record_funnel_step
from btp_guard import pilot_manager


class TestActivationAndFunnel(unittest.TestCase):

    def test_inspect_workspace(self):
        ws_info = inspect_workspace(REPO_ROOT)
        self.assertIn("workspace_path", ws_info)
        self.assertTrue(ws_info["git_initialized"])

    def test_run_live_security_probe(self):
        probe = run_live_security_probe()
        self.assertEqual(probe["verdict"], "DENY")
        self.assertTrue(probe["tamper_proof"])
        self.assertIn("receipt_sha256", probe)
        self.assertGreater(len(probe["receipt_sha256"]), 32)

    def test_funnel_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            metrics_path = Path(tmp) / "funnel_metrics.json"
            metrics_path.write_text(json.dumps({
                "unique_active_installs": 48,
                "first_proof_activations": 34,
                "paid_commitments": 0,
            }), encoding="utf-8")

            with patch("btp_guard.funnel_tracker.REPO_ROOT", Path(tmp)), patch(
                "btp_guard.funnel_tracker.FUNNEL_METRICS_PATH", metrics_path
            ):
                snap = get_funnel_snapshot()
                self.assertIsNone(snap["total_downloads"])
                self.assertIsNone(snap["unique_active_installs"])
                self.assertIsNone(snap["first_proof_activations"])
                self.assertIsNone(snap["paid_commitments"])

                record_funnel_step("pilot_enrollment_starts")
                recorded = json.loads(metrics_path.read_text(encoding="utf-8"))
                self.assertEqual(recorded["metrics"]["pilot_enrollment_starts"], 1)
                self.assertIsNone(recorded["metrics"]["team_pilot_inquiries"])
                self.assertIsNone(recorded["metrics"]["paid_commitments"])

                with self.assertRaises(ValueError):
                    record_funnel_step("paid_commitments")

    def test_pilot_enrollment_waits_for_payment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(pilot_manager, "REPO_ROOT", root), patch.object(
                pilot_manager, "ENROLLMENT_FILE", root / ".btp" / "team_pilot_enrollment.json"
            ), patch.object(pilot_manager, "POLICY_FILE", root / ".btp" / "policy.yaml"), patch(
                "btp_guard.funnel_tracker.FUNNEL_METRICS_PATH", root / ".btp" / "funnel_metrics.json"
            ), patch("btp_guard.funnel_tracker.REPO_ROOT", root):
                record = pilot_manager.enroll_team("Test Team", "lead@example.test")

            self.assertEqual(record["status"], "AWAITING_PAYMENT")
            metrics = json.loads((root / ".btp" / "funnel_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(metrics["metrics"]["pilot_enrollment_starts"], 1)
            self.assertIsNone(metrics["metrics"]["paid_commitments"])


if __name__ == "__main__":
    unittest.main()
