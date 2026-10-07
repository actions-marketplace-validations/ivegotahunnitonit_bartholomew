"""
Bartholomew Guard for Haystack (BTP v6.4.0)
==========================================
Deterministic AST execution component & tool interceptor for deepset Haystack 2.x enterprise agent pipelines.

Usage:
    from btp_guard.integrations.haystack import BtpHaystackGuard

    guard = BtpHaystackGuard()
    guard.validate_tool_call("shell_tool", {"command": "rm -rf /tmp"})
"""

from typing import Any, Callable, Dict, Optional, List
import functools
from ..authorization_gate import AuthorizationGate


class BtpHaystackGuard:
    """Enterprise AST & prompt injection gate for Haystack 2.x pipelines."""

    def __init__(
        self,
        strict: bool = True,
        pipeline_name: str = "haystack-enterprise-pipeline",
        ledger_path: Optional[str] = None
    ):
        self.pipeline_name = str(pipeline_name)
        self.gate = AuthorizationGate(
            policy={
                "strict": strict,
                "allow_destructive": False,
            },
            ledger_path=ledger_path
        )

    def validate_tool_call(self, tool_name: str, tool_args: Dict[str, Any]) -> bool:
        """Inspects parameters passed to Haystack Tool Invokers."""
        cmd_str = str(tool_args.get("command") or tool_args.get("query") or tool_args)
        action = {
            "agent_id": self.pipeline_name,
            "action_type": f"HAYSTACK_TOOL_{tool_name.upper()}",
            "payload": {"command": cmd_str}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-HAYSTACK-VETO]: Tool '{tool_name}' blocked: {res.get('reason')}")

        return True

    def run(self, prompt: str, **kwargs: Any) -> Dict[str, Any]:
        """Haystack component run method compatible with Haystack pipeline graph."""
        action = {
            "agent_id": self.pipeline_name,
            "action_type": "HAYSTACK_PIPELINE_PROMPT",
            "payload": {"command": prompt}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-HAYSTACK-VETO]: Prompt blocked by invariant policy: {res.get('reason')}")

        return {"verified_prompt": prompt, "verdict": "ALLOW"}

    def component_tool(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wraps a Haystack component tool with sub-35us invariant validation."""
        func_name = getattr(fn, "__name__", "haystack_tool")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            cmd_str = " ".join(str(a) for a in args) + " " + " ".join(f"{k}={v}" for k, v in kwargs.items())
            action = {
                "agent_id": self.pipeline_name,
                "action_type": f"HAYSTACK_TOOL_{func_name.upper()}",
                "payload": {"command": cmd_str}
            }
            res = self.gate.evaluate(action)
            if res.get("verdict") == "DENY":
                raise PermissionError(f"[BTP-AST-VETO]: Tool '{func_name}' blocked: {res.get('reason')}")
            return fn(*args, **kwargs)

        return wrapper

