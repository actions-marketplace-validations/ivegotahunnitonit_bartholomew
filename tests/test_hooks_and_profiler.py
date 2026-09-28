"""
Unit tests for Bartholomew Hook Installer, Agent Profiler, and MCP Tools (BTP v5.4.25).
"""

import os
import json
import tempfile
from pathlib import Path
from src.hook_installer import install_git_hooks, uninstall_git_hooks
from src.agent_profiler import AgentSessionProfiler
from btp_guard.mcp_server import BartholomewMCPServer, get_registered_tools


def test_hook_installer_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        git_dir = Path(tmpdir) / ".git"
        git_dir.mkdir()

        # 1. Install hooks
        res_inst = install_git_hooks(repo_root=tmpdir)
        assert res_inst["status"] == "SUCCESS"
        assert len(res_inst["hooks_installed"]) == 2
        assert (git_dir / "hooks" / "pre-commit").exists()
        assert (git_dir / "hooks" / "pre-push").exists()

        # 2. Uninstall hooks
        res_uninst = uninstall_git_hooks(repo_root=tmpdir)
        assert res_uninst["status"] == "SUCCESS"
        assert "pre-commit" in res_uninst["hooks_removed"]
        assert "pre-push" in res_uninst["hooks_removed"]
        assert not (git_dir / "hooks" / "pre-commit").exists()
        assert not (git_dir / "hooks" / "pre-push").exists()


def test_agent_profiler_session():
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "src"
        src_dir.mkdir()
        (src_dir / "module.py").write_text(
            "def heavy_calc(x: int) -> int:\n"
            "    '''Heavy calculation docstring'''\n"
            "    res = 0\n"
            "    for i in range(50):\n"
            "        res += i * x\n"
            "    return res\n",
            encoding="utf-8"
        )
        profiler = AgentSessionProfiler(workspace_root=tmpdir)
        report = profiler.profile_workspace_session(agent_name="TestAgent")

        assert "session_id" in report
        assert report["agent_name"] == "TestAgent"
        econ = report["token_economics"]
        assert econ["files_indexed"] == 1
        assert "estimated_usd_saved_per_turn" in econ
        assert (Path(tmpdir) / ".btp" / "sessions" / f"{report['session_id']}.json").exists()


def test_mcp_registered_tools():
    tools = get_registered_tools()
    tool_names = {t["name"] for t in tools}
    assert "btp_compress_context" in tool_names
    assert "btp_auto_heal" in tool_names
    assert "btp_profile_session" in tool_names
    assert "btp_execute_command" in tool_names
    assert "btp_get_manifest" in tool_names


def test_mcp_server_auto_heal_tool():
    server = BartholomewMCPServer()
    msg = {
        "jsonrpc": "2.0",
        "id": "test-123",
        "method": "tools/call",
        "params": {
            "name": "btp_auto_heal",
            "arguments": {
                "payload": "rm -rf /",
                "type": "SHELL"
            }
        }
    }
    raw_resp = server.process_message(json.dumps(msg))
    resp = json.loads(raw_resp)
    assert resp["id"] == "test-123"
    result = resp.get("result", {})
    text_content = result.get("content", [{}])[0].get("text", "")
    assert "repaired_payload" in text_content or "REPAIRED" in text_content or "btp_sandbox" in text_content
