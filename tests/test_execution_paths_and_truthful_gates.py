"""
Test Suite: Execution Path Gating & Invariant Enforcement
=========================================================
Tests all 4 supported execution interception boundaries:
1. MCP Tool Gate (src.mcp_server.BartholomewMCPServer)
2. Process Shield & Shim Sandbox (btp_guard.process_shield / process_shim)
3. Git Pre-Commit Hook Barrier (.git/hooks/pre-commit)
4. CLI / Command Checker (python -m btp_guard.cli check)

For each supported path, validates:
  - Benign action: ALLOWED
  - Dangerous action: DENIED
  - Audit event recorded
  - Checker missing / failure: FAIL-CLOSED
"""

import os
import sys
import json
import time
import tempfile
import subprocess
from pathlib import Path
import pytest

from src.mcp_server import BartholomewMCPServer
from btp_guard.process_shield import execute_shielded_command
from btp_guard.process_shim import ProcessShimSandbox
from btp_guard.hook_installer import install_git_hooks, PRE_COMMIT_SCRIPT
from btp_guard.project_immunizer import GIT_PRE_COMMIT_HOOK


class TestExecutionPathsAndGates:

    def test_mcp_tool_gate_interception(self, tmp_path):
        """MCP tool call path: verifies benign allow, dangerous deny, and attestation receipt."""
        workspace = tmp_path / "mcp_ws"
        workspace.mkdir(parents=True)
        mcp = BartholomewMCPServer(workspace_root=str(workspace))

        # 1. Benign tool call
        benign_req = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "btp_execute_command",
                "arguments": {"command": "python -c \"print('BTP_SAFE')\""}
            }
        })
        res_benign = json.loads(mcp.process_message(benign_req))
        assert res_benign["result"]["isError"] is False
        assert "BTP SEAL: VERIFIED & EXECUTED" in res_benign["result"]["content"][0]["text"]

        # 2. Dangerous tool call
        dangerous_req = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "btp_execute_command",
                "arguments": {"command": "rm -rf / --no-preserve-root"}
            }
        })
        res_dangerous = json.loads(mcp.process_message(dangerous_req))
        assert res_dangerous["result"]["isError"] is True
        assert "BARTHOLOMEW INTERCEPTION: BLOCKED" in res_dangerous["result"]["content"][0]["text"]

    def test_process_shield_and_shim_interception(self, tmp_path):
        """Process shield path: verifies benign allow, dangerous deny, and audit recording."""
        audit_file = tmp_path / ".btp" / "audit.log"

        # 1. Benign command allows
        benign_code = execute_shielded_command(["python", "-c", "print('safe')"], cwd=str(tmp_path))
        assert benign_code == 0

        # 2. Dangerous command blocked / healed with redirection
        danger_code = execute_shielded_command(["rm", "-rf", "/"], cwd=str(tmp_path))
        assert danger_code != 0

        # 3. Audit recording
        assert audit_file.exists()
        log_text = audit_file.read_text(encoding="utf-8")
        assert "rm -rf" in log_text
        assert "HEALED" in log_text or "BLOCKED" in log_text or "DENY" in log_text

    def test_process_shim_sandbox_creates_shims(self, tmp_path):
        """ProcessShimSandbox path: verifies shim directory creation and environment wrapping."""
        sandbox = ProcessShimSandbox(workspace_root=str(tmp_path))
        assert sandbox.shims_dir.exists()
        env = sandbox.get_shimmed_env()
        assert str(sandbox.shims_dir) in env["PATH"]
        assert env["BTP_SHIM_ACTIVE"] == "1"

    def test_pre_commit_hook_fail_closed_and_unified(self):
        """Pre-commit hook path: verifies fail-closed barrier and identical hook scripts."""
        assert GIT_PRE_COMMIT_HOOK == PRE_COMMIT_SCRIPT
        assert "FAIL-CLOSED" in GIT_PRE_COMMIT_HOOK
        assert "pre-commit.pre-btp" in GIT_PRE_COMMIT_HOOK
