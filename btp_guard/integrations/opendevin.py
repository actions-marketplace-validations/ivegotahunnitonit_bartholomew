"""
Bartholomew Guard for OpenDevin / OpenHands (BTP v6.4.0)
=======================================================
AST sandbox firewall & action interceptor for OpenDevin autonomous software development agents.

Usage:
    from btp_guard.integrations.opendevin import BtpOpenDevinGuard

    guard = BtpOpenDevinGuard()
    guard.validate_action("CmdRunAction", {"command": "rm -rf /root"})
"""

from typing import Any, Callable, Dict, Optional
import functools
from ..authorization_gate import AuthorizationGate


class BtpOpenDevinGuard:
    """Action & command execution gate for OpenDevin / OpenHands agents."""

    def __init__(
        self,
        strict: bool = True,
        agent_id: str = "opendevin-agent",
        ledger_path: Optional[str] = None
    ):
        self.agent_id = str(agent_id)
        self.gate = AuthorizationGate(
            policy={
                "strict": strict,
                "allow_destructive": False,
            },
            ledger_path=ledger_path
        )

    def validate_action(self, action_class_name: str, action_args: Dict[str, Any]) -> bool:
        """Inspects OpenDevin action parameters (CmdRunAction, FileWriteAction, IPythonRunCellAction)."""
        cmd_str = str(action_args.get("command") or action_args.get("content") or action_args.get("code") or action_args)

        action = {
            "agent_id": self.agent_id,
            "action_type": f"OPENDEVIN_{action_class_name.upper()}",
            "payload": {"command": cmd_str}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-OPENDEVIN-VETO]: Action '{action_class_name}' blocked: {res.get('reason')}")

        return True

    def wrap_event_stream(self, event_handler_fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wraps OpenDevin event stream action dispatching."""
        @functools.wraps(event_handler_fn)
        def wrapper(event: Any, *args: Any, **kwargs: Any) -> Any:
            event_type = getattr(event, "__class__", type(event)).__name__
            event_dict = getattr(event, "__dict__", {})
            self.validate_action(event_type, event_dict)
            return event_handler_fn(event, *args, **kwargs)

        return wrapper
