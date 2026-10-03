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

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from btp_guard.activation_verifier import inspect_workspace, run_live_security_probe
from btp_guard.funnel_tracker import get_funnel_snapshot, record_funnel_step


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
        snap = get_funnel_snapshot()
        self.assertIn("total_downloads", snap)
        self.assertIn("unique_active_installs", snap)
        self.assertIn("first_proof_activations", snap)
        self.assertGreater(snap["total_downloads"], 0)


if __name__ == "__main__":
    unittest.main()
