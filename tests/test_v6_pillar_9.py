"""
Tests for BTP v6 Pillar 9:
  9. Agent Permission Scope Guard (14 tests)
"""

import pytest


#  PERMISSION SCOPE GUARD 

def test_psg_allows_declared_file_read():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_FILE_READ
    guard = AgentPermissionScopeGuard()
    result = guard.check(ACTION_FILE_READ, "src/auth/login.py")
    assert result["allowed"] is True
    assert result["verdict"] == "ALLOW"


def test_psg_blocks_shell_in_strict_mode():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_SHELL
    guard = AgentPermissionScopeGuard(strict_mode=True)
    result = guard.check(ACTION_SHELL, "rm -rf /")
    assert result["allowed"] is False
    assert result["verdict"] == "DENY"


def test_psg_blocks_file_delete():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_FILE_DELETE
    guard = AgentPermissionScopeGuard()
    result = guard.check(ACTION_FILE_DELETE, "src/auth.py")
    assert result["allowed"] is False


def test_psg_blocks_denied_path():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_FILE_READ
    guard = AgentPermissionScopeGuard()
    result = guard.check(ACTION_FILE_READ, ".env")
    assert result["allowed"] is False
    assert "deny" in result["reason"].lower()


def test_psg_allows_src_path():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_FILE_WRITE
    manifest = {
        "allow_actions": ["file:write"],
        "deny_actions": [],
        "allow_paths": ["src/**"],
        "deny_paths": [],
        "allow_domains": [],
        "deny_domains": [],
        "allow_tools": [],
        "deny_tools": [],
    }
    guard = AgentPermissionScopeGuard(manifest=manifest, strict_mode=False)
    result = guard.check("file:write", "src/mymodule.py")
    assert result["allowed"] is True


def test_psg_blocks_ssh_path():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_FILE_READ
    guard = AgentPermissionScopeGuard()
    result = guard.check(ACTION_FILE_READ, ".ssh/id_rsa")
    assert result["allowed"] is False


def test_psg_allows_mcp_btp_tool():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_MCP_TOOL
    guard = AgentPermissionScopeGuard()
    result = guard.check(ACTION_MCP_TOOL, "btp_evaluate_intent")
    assert result["allowed"] is True


def test_psg_blocks_non_btp_tool_strict():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_MCP_TOOL
    guard = AgentPermissionScopeGuard(strict_mode=True)
    # Default manifest only allows btp_* tools
    result = guard.check(ACTION_MCP_TOOL, "openai_create_completion")
    assert result["allowed"] is False


def test_psg_allows_http_to_openai():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_HTTP
    # Must explicitly allow http:request in the manifest
    manifest = {
        "allow_actions": ["http:request"],
        "deny_actions":  [],
        "allow_paths":   [],
        "deny_paths":    [],
        "allow_domains": ["api.openai.com", "api.anthropic.com"],
        "deny_domains":  [],
        "allow_tools":   [],
        "deny_tools":    [],
    }
    guard = AgentPermissionScopeGuard(manifest=manifest, strict_mode=True)
    result = guard.check(ACTION_HTTP, "https://api.openai.com/v1/chat/completions")
    assert result["allowed"] is True


def test_psg_blocks_http_to_unknown_domain():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_HTTP
    guard = AgentPermissionScopeGuard(strict_mode=True)
    result = guard.check(ACTION_HTTP, "https://evil-exfil.example.com/steal")
    assert result["allowed"] is False


def test_psg_violation_tracking():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_SHELL
    guard = AgentPermissionScopeGuard()
    guard.check(ACTION_SHELL, "dangerous command")
    guard.check(ACTION_SHELL, "another dangerous command")
    summary = guard.get_summary()
    assert summary["total_violations"] >= 2


def test_psg_summary_structure():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_FILE_READ
    guard = AgentPermissionScopeGuard()
    guard.check(ACTION_FILE_READ, "src/main.py")
    summary = guard.get_summary()
    for key in ("session_id", "total_checks", "total_violations", "violation_rate_pct"):
        assert key in summary, f"Missing: {key}"


def test_psg_check_count_increments():
    from src.permission_scope_guard import AgentPermissionScopeGuard, ACTION_FILE_READ
    guard = AgentPermissionScopeGuard()
    for i in range(5):
        guard.check(ACTION_FILE_READ, f"src/file{i}.py")
    assert guard.get_summary()["total_checks"] == 5


def test_psg_session_id_is_hex():
    from src.permission_scope_guard import AgentPermissionScopeGuard
    import re
    guard = AgentPermissionScopeGuard()
    assert re.fullmatch(r"[0-9a-f]+", guard.session_id)
