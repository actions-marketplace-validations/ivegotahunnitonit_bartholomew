"""
Unit tests for Milestone v6.0 pillars:
  1. Enterprise SIEM Cloud Relay (Splunk, Datadog, CrowdStrike, AWS)
  2. Ring-0 Hardware & eBPF Kernel Guard Controller
  3. Sovereign Swarm Operations TUI
  4. Native MCP Tool Invocation (btp_stream_siem_telemetry, btp_ring0_kernel_guard)
"""

import os
import json
import pytest
from src.siem_relay import SIEMRelay
from src.ring0_controller import Ring0Controller
from src.swarm_ops_tui import SwarmOpsTUI


def test_siem_relay_formatters(tmp_path):
    relay = SIEMRelay(spool_dir=str(tmp_path))
    event = {
        "event_type": "TOOL_INVOCATION",
        "action": "BLOCK",
        "agent_id": "test-agent-42",
        "severity": "HIGH",
        "metadata": {"command": "rm -rf /"}
    }
    
    # Splunk
    splunk_payload = relay.format_for_splunk(event)
    assert splunk_payload["sourcetype"] == "_json"
    assert splunk_payload["event"]["action"] == "BLOCK"
    
    # Datadog
    dd_payload = relay.format_for_datadog(event)
    assert dd_payload["ddsource"] == "bartholomew"
    assert dd_payload["status"] == "error"
    
    # CrowdStrike
    cs_payload = relay.format_for_crowdstrike(event)
    assert cs_payload["detection"]["verdict"] == "BLOCK"
    assert cs_payload["detection"]["mitigated"] is True
    
    # AWS Security Hub
    aws_payload = relay.format_for_aws_security_hub(event)
    assert aws_payload["SchemaVersion"] == "2018-10-08"
    assert aws_payload["Severity"]["Label"] == "HIGH"


def test_siem_relay_spooling_and_export(tmp_path):
    relay = SIEMRelay(spool_dir=str(tmp_path))
    payloads = relay.relay_event(
        event_type="AUTH_CHECK",
        action="ALLOW",
        agent_id="agent-007",
        severity="INFO",
        spool=True
    )
    assert "splunk" in payloads
    assert "datadog" in payloads
    assert os.path.exists(relay.spool_path)
    
    export_out = str(tmp_path / "export_splunk.jsonl")
    count = relay.export_compliance_bundle(export_out, provider="splunk")
    assert count >= 1
    assert os.path.exists(export_out)


def test_ring0_controller_invariants():
    controller = Ring0Controller()
    status = controller.get_status()
    assert "kernel_level" in status
    assert len(status["active_hooks"]) > 0
    assert status["tamper_proof"] is True
    
    verify_res = controller.verify_kernel_invariants()
    assert verify_res["status"] == "PASS"
    assert verify_res["invariants_held"] == 4


def test_swarm_ops_tui_rendering():
    tui = SwarmOpsTUI()
    snapshot = tui.render_snapshot({
        "evaluations": 67000000,
        "neutralized_attacks": 43000000,
        "mcp_tools": 23
    })
    assert "SWARM OPERATIONS CENTER" in snapshot
    assert "67,000,000" in snapshot
    assert "23 native tools" in snapshot


def test_mcp_v6_tool_handlers(tmp_path):
    from btp_guard.mcp_server import BartholomewMCPServer
    server = BartholomewMCPServer(workspace_root=str(tmp_path))
    
    # Check tool count (should be at least 23)
    tool_names = [t["name"] for t in server.tools_schema]
    assert "btp_stream_siem_telemetry" in tool_names
    assert "btp_ring0_kernel_guard" in tool_names
    assert len(tool_names) >= 23
    
    # Test btp_stream_siem_telemetry
    res1 = server.handle_tool_call("btp_stream_siem_telemetry", {"event_type": "TEST_EVENT"})
    assert res1["isError"] is False
    data1 = json.loads(res1["content"][0]["text"])
    assert "splunk" in data1
    
    # Test btp_ring0_kernel_guard
    res2 = server.handle_tool_call("btp_ring0_kernel_guard", {"verify": True})
    assert res2["isError"] is False
    data2 = json.loads(res2["content"][0]["text"])
    assert data2["status"] == "PASS"
