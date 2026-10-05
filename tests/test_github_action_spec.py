import pytest
import os
import subprocess
import sys
import yaml
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_YML = REPO_ROOT / "packages" / "github_action" / "action.yml"
ENTRYPOINT_PY = REPO_ROOT / "packages" / "github_action" / "entrypoint.py"

def test_action_yml_syntax_and_schema():
    assert ACTION_YML.exists(), "action.yml must exist"
    with open(ACTION_YML, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert data["name"] == "Bartholomew Agentic Runtime Protection (ARP) CI/CD Action"
    assert "inputs" in data
    inputs = data["inputs"]
    assert "audit-path" in inputs
    assert "fail-on-violation" in inputs
    assert "generate-sarif" in inputs
    assert "export-dossier" in inputs

    assert "outputs" in data
    outputs = data["outputs"]
    assert "compliance-status" in outputs
    assert "audit-receipt-sha256" in outputs
    assert "eval-latency-us" in outputs

def test_entrypoint_clean_run(tmp_path):
    safe_file = tmp_path / "safe_agent.py"
    safe_file.write_text("def run():\n    print('Hello safe agent world')\n", encoding="utf-8")

    cmd = [
        sys.executable,
        str(ENTRYPOINT_PY),
        str(tmp_path),
        "true",  # fail-on-violation
        "true",  # generate-sarif
        "true"   # export-dossier
    ]

    sarif_file = tmp_path / "bartholomew.sarif"
    dossier_file = tmp_path / "btp_dossier.json"

    # Run inside tmp_path
    proc = subprocess.run(cmd, cwd=str(tmp_path), capture_output=True, text=True)
    assert proc.returncode == 0
    assert "SOC2_PASSED" in proc.stdout
    assert "Cryptographic Receipt SHA256" in proc.stdout

    assert sarif_file.exists(), "SARIF file must be generated"
    with open(sarif_file, "r", encoding="utf-8") as f:
        sarif = json.load(f)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0

    assert dossier_file.exists(), "Dossier file must be generated"
    with open(dossier_file, "r", encoding="utf-8") as f:
        dossier = json.load(f)
        assert dossier["status"] == "SOC2_PASSED"
        assert dossier["violations"] == 0

def test_entrypoint_catches_violation(tmp_path):
    bad_file = tmp_path / "rogue_tool.sh"
    bad_file.write_text("#!/bin/bash\nrm -rf / --no-preserve-root\n", encoding="utf-8")

    cmd = [
        sys.executable,
        str(ENTRYPOINT_PY),
        str(tmp_path),
        "true",  # fail-on-violation
        "true",  # generate-sarif
        "false"  # export-dossier
    ]

    proc = subprocess.run(cmd, cwd=str(tmp_path), capture_output=True, text=True)
    assert proc.returncode != 0
    assert "INVARIANT_VIOLATION" in proc.stdout
    assert "BTP Invariant Gate failed" in proc.stdout

    sarif_file = tmp_path / "bartholomew.sarif"
    assert sarif_file.exists()
    with open(sarif_file, "r", encoding="utf-8") as f:
        sarif = json.load(f)
        results = sarif["runs"][0]["results"]
        assert len(results) > 0
        assert results[0]["ruleId"] == "BTP001"
