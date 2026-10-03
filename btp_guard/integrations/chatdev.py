"""
Bartholomew Guard for ChatDev (BTP v6.4.0)
=========================================
AST execution gate & artifact integrity shield for ChatDev multi-agent software organizations (CEO, CTO, Programmer, Reviewer).

Usage:
    from btp_guard.integrations.chatdev import BtpChatDevGuard

    guard = BtpChatDevGuard()
    guard.validate_phase_output("Coding", "import os; os.system('format C:')")
"""

from typing import Any, Callable, Dict, Optional
import functools
from ..authorization_gate import AuthorizationGate


class BtpChatDevGuard:
    """Artifact integrity & AST execution gate for ChatDev multi-agent organizations."""

    def __init__(
        self,
        strict: bool = True,
        org_name: str = "ChatDev-Org",
        ledger_path: Optional[str] = None
    ):
        self.org_name = str(org_name)
        self.gate = AuthorizationGate(
            policy={
                "strict": strict,
                "allow_destructive": False,
            },
            ledger_path=ledger_path
        )

    def validate_phase_output(self, phase_name: str, code_or_text: str) -> bool:
        """Validates artifacts produced in ChatDev phases (Design, Coding, Testing, Review)."""
        action = {
            "agent_id": self.org_name,
            "action_type": f"CHATDEV_PHASE_{phase_name.upper()}",
            "payload": {"command": code_or_text}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-CHATDEV-VETO]: Phase '{phase_name}' output blocked: {res.get('reason')}")

        return True

    def wrap_chat_turn(self, chat_fn: Callable[..., Any], phase_name: str = "Chat") -> Callable[..., Any]:
        """Wraps ChatDev communication turn between agents."""
        @functools.wraps(chat_fn)
        def wrapper(*args, **kwargs):
            result = chat_fn(*args, **kwargs)
            if isinstance(result, str):
                self.validate_phase_output(phase_name, result)
            return result

        return wrapper
