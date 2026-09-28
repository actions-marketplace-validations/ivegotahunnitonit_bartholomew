"""
Unit tests for Bartholomew AI Bridge Injector, Process Shim, and Chaos Harness (BTP v5.4.26).
"""

import os
import json
import tempfile
from pathlib import Path
from src.ai_bridge_injector import AIBridgeInjector, run_bridge_injection
from src.process_shim import ProcessShimSandbox, execute_in_sandbox
from src.chaos_harness import ChaosRedTeamHarness


def test_ai_bridge_injector_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Pre-seed a basic .cursorrules
        cr_path = Path(tmpdir) / ".cursorrules"
        cr_path.write_text("// Existing cursor rules\n", encoding="utf-8")

        injector = AIBridgeInjector(workspace_root=tmpdir)
        res = injector.inject_target("cursor")
        assert res["status"] == "SUCCESS"
        assert "BARTHOLOMEW TRUST PROTOCOL" in cr_path.read_text(encoding="utf-8")
        assert "// Existing cursor rules" in cr_path.read_text(encoding="utf-8")

        # Second run should detect already injected
        res2 = injector.inject_target("cursor")
        assert res2["status"] == "ALREADY_INJECTED"


def test_process_shim_environment():
    with tempfile.TemporaryDirectory() as tmpdir:
        sandbox = ProcessShimSandbox(workspace_root=tmpdir)
        shims_dir = Path(tmpdir) / ".btp" / "shims"
        assert shims_dir.exists()
        # Verify shims were created
        shim_files = list(shims_dir.iterdir())
        assert len(shim_files) >= 3

        env = sandbox.get_shimmed_env()
        assert str(shims_dir) in env["PATH"]
        assert env["BTP_SHIM_ACTIVE"] == "1"


def test_chaos_red_team_battery():
    harness = ChaosRedTeamHarness()
    report = harness.run_chaos_battery(iterations=20)
    assert report["total_vectors_tested"] == 20
    assert report["threats_neutralized"] == 20
    assert report["defense_effectiveness_pct"] == "100.0%"
    assert report["total_benchmark_time_ms"] > 0
    assert "latency_distribution_us" in report
    assert "receipt_attestation" in report
    assert Path(".btp/chaos_report.json").exists()
