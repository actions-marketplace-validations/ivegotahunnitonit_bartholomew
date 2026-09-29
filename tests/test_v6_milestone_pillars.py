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


def test_jit_self_repair_engine():
    from src.jit_self_repair import JITSelfRepairEngine
    engine = JITSelfRepairEngine()
    
    # 1. ZeroDivisionError
    tb1 = "Traceback (most recent call last):\n  File \"main.py\", line 12, in <module>\nZeroDivisionError: division by zero"
    analysis1 = engine.analyze_traceback(tb1)
    assert analysis1["error_type"] == "ZeroDivisionError"
    repaired1, desc1 = engine.synthesize_repair("val = a / b", analysis1)
    assert "1e-9" in repaired1
    
    # 2. KeyError
    tb2 = "Traceback (most recent call last):\n  File \"agent.py\", line 4\nKeyError: 'api_token'"
    analysis2 = engine.analyze_traceback(tb2)
    assert analysis2["error_type"] == "KeyError"
    repaired2, desc2 = engine.synthesize_repair("tok = config['api_token']", analysis2)
    assert ".get(" in repaired2
    
    # 3. Polyfill injection
    assert engine.inject_in_memory_polyfill("tiktoken") is True
    import tiktoken
    enc = tiktoken.get_encoding("cl100k_base")
    assert enc.encode("hello") == [104, 101, 108, 108, 111]


def test_zk_mesh_attestation_engine():
    from src.zk_mesh_attestation import ZkMeshAttestationEngine
    mesh = ZkMeshAttestationEngine(mesh_id="test-mesh-fleet")
    
    # Generate 4 agent proofs
    for i in range(4):
        mesh.generate_agent_proof(
            agent_id=f"agent-{i}",
            session_hash=f"hash-{i}",
            invariant_root=f"inv-{i}",
            private_action_count=50
        )
    assert len(mesh.attestations) == 4
    
    # Verify peer attestation
    assert mesh.verify_peer_attestation(mesh.attestations[0]) is True
    
    # Aggregate proofs
    agg = mesh.aggregate_mesh_proofs()
    assert agg["status"] == "RECURSIVE_ROOT_VALID"
    assert agg["total_proofs"] == 4
    assert len(agg["aggregated_root"]) == 64
    assert agg["compression_ratio"] == "4:1"


def test_mcp_all_25_tools(tmp_path):
    from btp_guard.mcp_server import BartholomewMCPServer
    server = BartholomewMCPServer(workspace_root=str(tmp_path))
    tool_names = [t["name"] for t in server.tools_schema]
    
    assert "btp_jit_self_repair" in tool_names
    assert "btp_zk_mesh_attestation" in tool_names
    assert len(tool_names) >= 25
    
    # Test btp_jit_self_repair
    res_jit = server.handle_tool_call("btp_jit_self_repair", {
        "traceback": "ZeroDivisionError: division by zero",
        "source_code": "x = a / b"
    })
    assert res_jit["isError"] is False
    data_jit = json.loads(res_jit["content"][0]["text"])
    assert "repaired_code" in data_jit
    
    # Test btp_zk_mesh_attestation
    res_zk = server.handle_tool_call("btp_zk_mesh_attestation", {
        "agent_id": "test-peer-99",
        "session_hash": "sess-alpha"
    })
    assert res_zk["isError"] is False
    data_zk = json.loads(res_zk["content"][0]["text"])
    assert "mesh_root" in data_zk
