"""
Bartholomew Guard for Dify (BTP v6.4.0)
======================================
Security firewall & AST invariant gate for Dify agent workflows, code nodes, and tool providers.

Usage:
    from btp_guard.integrations.dify import BtpDifyGuard

    guard = BtpDifyGuard()
    guard.validate_node_execution("python_code_node", {"code": "import shutil; shutil.rmtree('/')"})
"""

from typing import Any, Callable, Dict, Optional
import functools
from ..authorization_gate import AuthorizationGate


class BtpDifyGuard:
    """AST Invariant & Node execution gate for Dify LLM Application workflows."""

    def __init__(
        self,
        strict: bool = True,
        workflow_id: str = "dify-workflow-sentinel",
        ledger_path: Optional[str] = None
    ):
        self.workflow_id = str(workflow_id)
        self.gate = AuthorizationGate(
            policy={
                "strict": strict,
                "allow_destructive": False,
            },
            ledger_path=ledger_path
        )

    def validate_node_execution(self, node_type: str, inputs: Dict[str, Any]) -> bool:
        """Inspects Dify workflow node execution inputs before node compute."""
        cmd_str = ""
        if isinstance(inputs, dict):
            cmd_str = str(inputs.get("code") or inputs.get("query") or inputs.get("command") or str(inputs))
        else:
            cmd_str = str(inputs)

        action = {
            "agent_id": self.workflow_id,
            "action_type": f"DIFY_{node_type.upper()}",
            "payload": {"command": cmd_str}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-DIFY-VETO]: Workflow node '{node_type}' blocked: {res.get('reason')}")

        return True

    def wrap_tool_provider(self, tool_fn: Callable[..., Any]) -> Callable[..., Any]:
        """Guards external Dify tool provider invocations."""
        tool_name = getattr(tool_fn, "__name__", "dify_tool")

        @functools.wraps(tool_fn)
        def wrapper(*args, **kwargs):
            payload_str = " ".join(str(a) for a in args) + " " + " ".join(f"{k}={v}" for k, v in kwargs.items())
            action = {
                "agent_id": self.workflow_id,
                "action_type": f"DIFY_TOOL_{tool_name}",
                "payload": {"command": payload_str}
            }
            res = self.gate.evaluate(action)
            if res.get("verdict") == "DENY":
                raise PermissionError(f"[BTP-DIFY-VETO]: Tool execution blocked: {res.get('reason')}")
            return tool_fn(*args, **kwargs)

        return wrapper
