"""
Bartholomew Agent Permission Scope Guard (BTP v6.0-pre)
=======================================================
Enforces a declared permission manifest against actual agent operations.
Prevents AI agents from performing actions outside their authorized scope.

The fundamental problem: when you give an AI agent access to your computer,
it can do ANYTHING the shell can do. There's no built-in principle of
least privilege. This module fixes that.

You declare what the agent is allowed to do (read files, call APIs, etc.).
Every action is checked against that manifest before execution.
Violations are blocked and logged.

Features:
  1. Declarative permission manifest (YAML-like dict or .btp/permissions.json)
  2. Action-to-permission mapping (file ops, shell, HTTP, MCP tools)
  3. Path-based allow/deny lists (e.g., allow read src/, deny write prod/)
  4. Domain-based HTTP allow/deny lists
  5. Tool-level allow/deny lists (e.g., only allow btp_*, deny openai_*)
  6. Plain-English violation explanations
  7. Audit trail integration (works with ActionReplayLedger)

Zero external deps. Sub-1ms per check. Thread-safe.
"""

import re
import fnmatch
import hashlib
import time
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


#  ACTION CATEGORIES 
ACTION_FILE_READ   = "file:read"
ACTION_FILE_WRITE  = "file:write"
ACTION_FILE_DELETE = "file:delete"
ACTION_SHELL       = "shell:exec"
ACTION_HTTP        = "http:request"
ACTION_MCP_TOOL    = "mcp:tool"
ACTION_ENV_READ    = "env:read"
ACTION_PROCESS     = "process:spawn"

ALL_ACTIONS = {
    ACTION_FILE_READ, ACTION_FILE_WRITE, ACTION_FILE_DELETE,
    ACTION_SHELL, ACTION_HTTP, ACTION_MCP_TOOL, ACTION_ENV_READ, ACTION_PROCESS,
}

#  PERMISSION MANIFEST 
DEFAULT_MANIFEST = {
    "allow_actions": [ACTION_FILE_READ, ACTION_MCP_TOOL],
    "deny_actions":  [ACTION_FILE_DELETE, ACTION_SHELL, ACTION_PROCESS],
    "allow_paths":   ["src/**", "tests/**", "docs/**", "*.md", "*.toml", "*.json"],
    "deny_paths":    [".env", ".env.*", "**/.ssh/**", "**/secrets/**", "**/prod/**"],
    "allow_domains": ["api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"],
    "deny_domains":  [],
    "allow_tools":   ["btp_*"],
    "deny_tools":    [],
}


def _match_glob(pattern: str, value: str) -> bool:
    return fnmatch.fnmatch(value, pattern) or fnmatch.fnmatch(value, f"**/{pattern}")


class AgentPermissionScopeGuard:
    """
    Enforces a permission manifest for AI agent operations.
    Declare what's allowed; everything else is denied by default.
    """

    def __init__(
        self,
        manifest: Optional[Dict[str, Any]] = None,
        workspace_root: str = ".",
        strict_mode: bool = True,
    ):
        self.manifest = manifest or DEFAULT_MANIFEST.copy()
        self.workspace_root = Path(workspace_root).resolve()
        self.strict_mode = strict_mode  # if True, deny anything not explicitly allowed
        self._lock = threading.Lock()
        self.violations: List[Dict[str, Any]] = []
        self.checks_total = 0
        self.session_id = hashlib.sha256(f"perm:{time.time()}".encode()).hexdigest()[:12]

    def _is_action_allowed(self, action_type: str) -> bool:
        allow = self.manifest.get("allow_actions", [])
        deny  = self.manifest.get("deny_actions", [])
        if action_type in deny:
            return False
        if action_type in allow:
            return True
        return not self.strict_mode  # strict: deny by default

    def _is_path_allowed(self, path: str) -> bool:
        # Normalize to relative
        try:
            rel = str(Path(path).resolve().relative_to(self.workspace_root))
        except ValueError:
            rel = path  # outside workspace — extra suspicious
        allow = self.manifest.get("allow_paths", [])
        deny  = self.manifest.get("deny_paths", [])
        for pat in deny:
            if _match_glob(pat, rel) or _match_glob(pat, path):
                return False
        if not allow:
            return not self.strict_mode
        for pat in allow:
            if _match_glob(pat, rel) or _match_glob(pat, path):
                return True
        return not self.strict_mode

    def _is_domain_allowed(self, url: str) -> bool:
        m = re.search(r"https?://([^/]+)", url)
        domain = m.group(1) if m else url
        deny  = self.manifest.get("deny_domains", [])
        allow = self.manifest.get("allow_domains", [])
        for pat in deny:
            if _match_glob(pat, domain):
                return False
        if not allow:
            return not self.strict_mode
        for pat in allow:
            if _match_glob(pat, domain):
                return True
        return not self.strict_mode

    def _is_tool_allowed(self, tool_name: str) -> bool:
        deny  = self.manifest.get("deny_tools", [])
        allow = self.manifest.get("allow_tools", [])
        for pat in deny:
            if _match_glob(pat, tool_name):
                return False
        if not allow:
            return not self.strict_mode
        for pat in allow:
            if _match_glob(pat, tool_name):
                return True
        return not self.strict_mode

    def check(
        self,
        action_type: str,
        target: str = "",
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Check whether an action is within the agent's permission scope.
        Returns verdict dict with allowed, reason, and plain-English explanation.
        """
        with self._lock:
            self.checks_total += 1
            allowed = True
            reason = "Within declared permission scope"

            if not self._is_action_allowed(action_type):
                allowed = False
                reason = (
                    f"Action type '{action_type}' is not in the allow list "
                    f"and/or is explicitly denied."
                )

            elif action_type in (ACTION_FILE_READ, ACTION_FILE_WRITE, ACTION_FILE_DELETE):
                if not self._is_path_allowed(target):
                    allowed = False
                    reason = (
                        f"Path '{target}' is outside the allowed path scope "
                        f"or matches a deny pattern."
                    )

            elif action_type == ACTION_HTTP:
                if not self._is_domain_allowed(target):
                    allowed = False
                    reason = (
                        f"Domain in '{target}' is not in the allowed domain list "
                        f"or is explicitly denied."
                    )

            elif action_type == ACTION_MCP_TOOL:
                if not self._is_tool_allowed(target):
                    allowed = False
                    reason = f"MCP tool '{target}' is not in the allow list."

            result = {
                "allowed": allowed,
                "verdict": "ALLOW" if allowed else "DENY",
                "action_type": action_type,
                "target": target,
                "reason": reason,
                "session_id": self.session_id,
                "check_index": self.checks_total,
            }

            if not allowed:
                self.violations.append({
                    "timestamp": time.time(),
                    **result,
                })

            return result

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "session_id": self.session_id,
                "total_checks": self.checks_total,
                "total_violations": len(self.violations),
                "violation_rate_pct": round(
                    len(self.violations) / max(self.checks_total, 1) * 100, 1
                ),
                "strict_mode": self.strict_mode,
                "recent_violations": self.violations[-5:],
            }

    def load_manifest_file(self, path: str) -> None:
        """Load permission manifest from a JSON file (.btp/permissions.json)."""
        import json
        with open(path, encoding="utf-8") as f:
            self.manifest = json.load(f)
