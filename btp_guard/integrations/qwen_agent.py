"""
Bartholomew Guard for Qwen-Agent (BTP v6.4.0)
============================================
AST invariant and function call gate for Alibaba Cloud Qwen-Agent multi-modal & code interpreter agents.

Usage:
    from btp_guard.integrations.qwen_agent import BtpQwenAgentGuard

    guard = BtpQwenAgentGuard()
    guard.validate_fn_call("code_interpreter", {"code": "import os; os.remove('/etc/hosts')"})
"""

from typing import Any, Callable, Dict, Optional
import functools
from ..authorization_gate import AuthorizationGate


class BtpQwenAgentGuard:
    """AST Invariant & tool invocation gate for Qwen-Agent."""

    def __init__(
        self,
        strict: bool = True,
        agent_name: str = "qwen-agent",
        ledger_path: Optional[str] = None
    ):
        self.agent_name = str(agent_name)
        self.gate = AuthorizationGate(
            policy={
                "strict": strict,
                "allow_destructive": False,
            },
            ledger_path=ledger_path
        )

    def validate_fn_call(self, fn_name: str, fn_args: Dict[str, Any]) -> bool:
        """Validates function call parameters proposed by Qwen models."""
        cmd_str = str(fn_args.get("code") or fn_args.get("command") or fn_args)

        action = {
            "agent_id": self.agent_name,
            "action_type": f"QWEN_TOOL_{fn_name}",
            "payload": {"command": cmd_str}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-QWEN-VETO]: Tool call '{fn_name}' blocked: {res.get('reason')}")

        return True

    def wrap_tool(self, tool_instance: Any) -> Any:
        """Wraps a Qwen-Agent BaseTool call method."""
        orig_call = getattr(tool_instance, "call", None)
        if not orig_call:
            return tool_instance

        tool_name = getattr(tool_instance, "name", "qwen_tool")

        @functools.wraps(orig_call)
        def guarded_call(params: Any, **kwargs: Any) -> Any:
            params_dict = params if isinstance(params, dict) else {"params": str(params)}
            self.validate_fn_call(tool_name, params_dict)
            return orig_call(params, **kwargs)

        tool_instance.call = guarded_call
        return tool_instance
