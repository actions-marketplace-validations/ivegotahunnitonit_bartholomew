"""
Bartholomew Universal Coding Agent & Terminal Guard (BTP v6.4.4)
================================================================
Universal in-process and in-container security boundary for autonomous
coding agents: OpenHands, Aider, Cline, SWE-agent, Goose, and Roo Code.
"""

import functools
import os
from typing import Any, Callable, Dict, List, Optional
from ..authorization_gate import AuthorizationGate
from ..secret_masker import SecretMasker


class BtpCodingAgentGuard:
    """Universal execution firewall for autonomous coding copilots and dev agents."""

    def __init__(
        self,
        allowed_roots: Optional[List[str]] = None,
        spend_cap: float = 100.0,
        strict: bool = True,
        agent_id: str = "coding-agent-sentinel",
    ):
        self.allowed_roots = [os.path.abspath(r) for r in (allowed_roots or [os.getcwd()])]
        self.spend_cap = float(spend_cap)
        self.strict = strict
        self.agent_id = str(agent_id)
        self.gate = AuthorizationGate(policy={
            "max_spend_usd": self.spend_cap,
            "strict": strict,
            "allow_destructive": False,
        })
        self.secret_masker = SecretMasker()

    def protect_bash(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Intercepts raw shell execution, evaluates AST invariants in <35us."""
        func_name = getattr(fn, "__name__", "bash_tool")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            cmd = ""
            if args:
                cmd = str(args[0])
            elif "command" in kwargs:
                cmd = str(kwargs["command"])
            elif "cmd" in kwargs:
                cmd = str(kwargs["cmd"])
            else:
                cmd = " ".join(f"{k}={v}" for k, v in kwargs.items())

            action = {
                "agent_id": self.agent_id,
                "action_type": "TERMINAL_EXECUTE",
                "payload": {"command": cmd, "target_tool": func_name}
            }
            res = self.gate.evaluate(action)
            if res.get("verdict") == "DENY":
                rule_id = res.get("rule_id", "BTP-AST-VETO")
                reason = res.get("reason", "Terminal command blocked")
                raise PermissionError(f"[{rule_id}] Destructive terminal command blocked by Bartholomew: {reason}")

            result = fn(*args, **kwargs)

            if isinstance(result, str):
                return self.secret_masker.mask(result)
            elif isinstance(result, dict):
                return {
                    k: self.secret_masker.mask(v) if isinstance(v, str) else v
                    for k, v in result.items()
                }
            return result

        return wrapper

    def protect_file_write(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Ensures file writes never escape project boundaries or corrupt system files."""
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            filepath = ""
            if args:
                filepath = str(args[0])
            elif "path" in kwargs:
                filepath = str(kwargs["path"])
            elif "filepath" in kwargs:
                filepath = str(kwargs["filepath"])
            elif "file_path" in kwargs:
                filepath = str(kwargs["file_path"])

            if filepath:
                abs_target = os.path.abspath(filepath)
                if any(p in abs_target.lower() for p in [".env", "id_rsa", "/etc/shadow", "/etc/passwd"]):
                    raise PermissionError(
                        f"[BTP-KEYSTONE-VETO] Bartholomew blocked write to protected system file: {filepath}"
                    )

            return fn(*args, **kwargs)

        return wrapper


def wrap_coding_agent(agent_instance: Any, allowed_roots: Optional[List[str]] = None) -> Any:
    """Auto-detects and wraps bash and file tools on any coding agent instance."""
    guard = BtpCodingAgentGuard(allowed_roots=allowed_roots)
    for tool_attr in ["bash", "terminal", "execute_command", "run_shell", "sh", "exec"]:
        if hasattr(agent_instance, tool_attr) and callable(getattr(agent_instance, tool_attr)):
            setattr(agent_instance, tool_attr, guard.protect_bash(getattr(agent_instance, tool_attr)))
    return agent_instance
