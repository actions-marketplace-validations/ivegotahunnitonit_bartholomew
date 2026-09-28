"""
Unit tests for Bartholomew Ecosystem Advisor (BTP v5.4.25).
"""

import os
import json
import tempfile
from pathlib import Path
from src.ecosystem_advisor import EcosystemAdvisor, FACT_DATABASE
from btp_guard.mcp_server import BartholomewMCPServer


def test_ecosystem_advisor_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # Create mock package.json with linter and copilot
        (root / "package.json").write_text(json.dumps({
            "dependencies": {"eslint": "^8.0.0", "prettier": "^3.0.0"},
            "devDependencies": {"typescript": "^5.0.0"}
        }), encoding="utf-8")
        (root / ".git").mkdir()

        advisor = EcosystemAdvisor(workspace_root=tmpdir)
        stack = advisor.detect_workspace_stack()

        assert "TypeScript/JavaScript" in stack["languages"]
        assert "GIT_AND_VERSION_CONTROL" in stack["detected_archetypes"]
        assert "LINTERS_AND_FORMATTERS" in stack["detected_archetypes"]


def test_ecosystem_advisor_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("[project]\nname = 'test'\n", encoding="utf-8")
        (root / ".git").mkdir()

        advisor = EcosystemAdvisor(workspace_root=tmpdir)
        report = advisor.generate_optimization_report()

        assert report["title"] == "Bartholomew Ecosystem & Workflow Optimization Matrix"
        assert report["detected_archetypes_count"] > 0
        assert len(report["recommendations"]) > 0

        first_rec = report["recommendations"][0]
        assert "bottlenecks" in first_rec
        assert "facts" in first_rec
        assert "alternative_execution" in first_rec
        assert "workflow_shortcut" in first_rec

        # Verify saved manifest
        manifest = root / ".btp" / "ecosystem_optimization.json"
        assert manifest.exists()


def test_ecosystem_advisor_shortcuts():
    with tempfile.TemporaryDirectory() as tmpdir:
        advisor = EcosystemAdvisor(workspace_root=tmpdir)
        sh_path = advisor.generate_shortcut_script()

        assert Path(sh_path).exists()
        content = Path(sh_path).read_text(encoding="utf-8")
        assert "alias bshield=" in content
        assert "alias bcompress=" in content
        assert "alias bwatch=" in content


def test_mcp_optimize_ecosystem_tool():
    server = BartholomewMCPServer()
    msg = {
        "jsonrpc": "2.0",
        "id": "opt-test-1",
        "method": "tools/call",
        "params": {
            "name": "btp_optimize_ecosystem",
            "arguments": {}
        }
    }
    raw_resp = server.process_message(json.dumps(msg))
    resp = json.loads(raw_resp)
    assert resp["id"] == "opt-test-1"
    res_text = resp["result"]["content"][0]["text"]
    assert "Bartholomew Ecosystem & Workflow Optimization Matrix" in res_text
