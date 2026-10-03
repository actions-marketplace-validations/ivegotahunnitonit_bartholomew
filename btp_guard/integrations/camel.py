"""
Bartholomew Guard for CAMEL-AI (BTP v6.4.0)
==========================================
Sovereign AST execution gate and tool wrapper for CAMEL-AI communicative multi-agent role-playing systems.

Usage:
    from btp_guard.integrations.camel import BtpCamelGuard

    guard = BtpCamelGuard()
    guard.validate_agent_message("Assistant", "Executing: rm -rf /")
"""

from typing import Any, Callable, Dict, Optional
import functools
from ..authorization_gate import AuthorizationGate


class BtpCamelGuard:
    """AST Invariant & Role-Playing message gate for CAMEL-AI."""

    def __init__(
        self,
        strict: bool = True,
        society_name: str = "camel-society",
        ledger_path: Optional[str] = None
    ):
        self.society_name = str(society_name)
        self.gate = AuthorizationGate(
            policy={
                "strict": strict,
                "allow_destructive": False,
            },
            ledger_path=ledger_path
        )

    def validate_agent_message(self, role_name: str, message_content: str) -> bool:
        """Validates agent communication output before delivering to peer agent."""
        action = {
            "agent_id": f"{self.society_name}:{role_name}",
            "action_type": "CAMEL_AGENT_MESSAGE",
            "payload": {"command": message_content}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-CAMEL-VETO]: Message from role '{role_name}' blocked: {res.get('reason')}")

        return True

    def wrap_tool(self, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        """Guards tool calls made by CAMEL agents."""
        tool_name = getattr(tool_fn, "__name__", "camel_tool")

        @functools.wraps(tool_fn)
        def wrapper(*args, **kwargs):
            payload_str = " ".join(str(a) for a in args) + " " + " ".join(f"{k}={v}" for k, v in kwargs.items())
            action = {
                "agent_id": self.society_name,
                "action_type": f"CAMEL_TOOL_{tool_name}",
                "payload": {"command": payload_str}
            }
            res = self.gate.evaluate(action)
            if res.get("verdict") == "DENY":
                raise PermissionError(f"[BTP-CAMEL-VETO]: Tool execution blocked: {res.get('reason')}")
            return tool_fn(*args, **kwargs)

        return wrapper
