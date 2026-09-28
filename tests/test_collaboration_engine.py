import os
import json
import pytest
from pathlib import Path
from src.collaboration_engine import (
    detect_workspace_stack,
    calculate_savings_telemetry,
    generate_collaboration_mesh,
    ECOSYSTEM_ARCHETYPES
)

def test_ecosystem_archetypes_coverage():
    assert len(ECOSYSTEM_ARCHETYPES) >= 6
    assert "ai_autonomous_agents" in ECOSYSTEM_ARCHETYPES
    assert "ai_autocomplete_copilots" in ECOSYSTEM_ARCHETYPES
    assert "linters_and_formatters" in ECOSYSTEM_ARCHETYPES
    assert "language_servers_and_lsps" in ECOSYSTEM_ARCHETYPES
    assert "source_control_and_git" in ECOSYSTEM_ARCHETYPES
    assert "cloud_containers_and_iac" in ECOSYSTEM_ARCHETYPES

def test_detect_workspace_stack():
    stack = detect_workspace_stack(".")
    assert "workspace_root" in stack
    assert len(stack["detected_agents"]) >= 1
    assert len(stack["detected_tools"]) >= 1

def test_calculate_savings_telemetry():
    savings = calculate_savings_telemetry(".")
    assert "total_evaluations" in savings
    assert "threats_and_loops_neutralized" in savings
    assert "estimated_tokens_saved" in savings
    assert "estimated_usd_saved" in savings
    assert "developer_hours_saved" in savings

def test_generate_collaboration_mesh(tmp_path):
    res = generate_collaboration_mesh(str(tmp_path))
    assert res["protocol"] == "BTP Collaboration Protocol v5.4"
    assert len(res["ecosystem_matrix"]) >= 6
    assert "public_api" in res
    assert (tmp_path / ".btp" / "collaborate.json").exists()
