"""
Bartholomew Guard for Google GenAI & Agent Developer Kit (BTP v6.4.4)
======================================================================
Runtime execution firewall and tool clearance gate for Google GenAI SDK (google-genai),
Vertex AI Search & Conversation, and Gemini Agent Developer Kit (ADK).
"""

import time
import inspect
from typing import Any, Callable, Dict, Optional, List
from ..authorization_gate import AuthorizationGate


class BtpGoogleGenAIGuard:
    """In-process guard for Google GenAI function calls and tool loops."""

    def __init__(
        self,
        spend_cap: float = 100.0,
        strict: bool = True,
        agent_id: str = "google-genai-agent",
    ):
        self.spend_cap = float(spend_cap)
        self.agent_id = str(agent_id)
        self.gate = AuthorizationGate(policy={
            "max_spend_usd": self.spend_cap,
            "strict": strict,
            "allow_destructive": False,
        })

    def tool(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator for Gemini function declaration tools."""
        tool_name = getattr(fn, "__name__", "gemini_tool")

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_dict = {k: str(v) for k, v in kwargs.items()}
            cmd_str = f"{tool_name} " + " ".join(f"{k}={v}" for k, v in call_dict.items())
            action = {
                "agent_id": self.agent_id,
                "action_type": tool_name,
                "payload": {
                    "command": cmd_str,
                    "amount_usd": kwargs.get("amount_usd", 0.0),
                    **call_dict
                }
            }
            res = self.gate.evaluate(action)
            if res.get("verdict") in ("DENY", "BLOCK") or res.get("decision") in ("DENY", "BLOCK"):
                from ..errors import AuthorizationError
                raise AuthorizationError(f"BTP: Blocked Google GenAI tool call: {res.get('reason')}")
            return fn(*args, **kwargs)

        wrapper.__name__ = tool_name
        wrapper.__doc__ = getattr(fn, "__doc__", "")
        return wrapper


def wrap_google_genai_tool(tool_fn: Callable[..., Any], max_spend: float = 50.0) -> Callable[..., Any]:
    """1-Line wrapper for Google GenAI / Gemini tool functions."""
    guard = BtpGoogleGenAIGuard(spend_cap=max_spend)
    return guard.tool(tool_fn)
