"""
Bartholomew Guard for Agno / Phidata (BTP v6.4.4)
=================================================
Runtime security gate, sub-35us AST invariant validator, and
credential scrubber for Agno autonomous agents and toolkits.
"""

import functools
from typing import Any, Callable, Dict, List, Optional
from ..authorization_gate import AuthorizationGate
from ..secret_masker import SecretMasker


class BtpAgnoGuard:
    """Enterprise safety and containment guard for Agno (Phidata) agents."""

    def __init__(
        self,
        spend_cap: float = 100.0,
        strict: bool = True,
        agent_id: str = "agno-agent",
    ):
        self.spend_cap = float(spend_cap)
        self.strict = strict
        self.agent_id = str(agent_id)
        self.gate = AuthorizationGate(policy={
            "max_spend_usd": self.spend_cap,
            "strict": strict,
            "allow_destructive": False,
        })
        self.secret_masker = SecretMasker()

    def tool(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wraps an Agno agent tool function with sub-35us AST validation."""
        func_name = getattr(fn, "__name__", "agno_tool")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_dict = {k: str(v) for k, v in kwargs.items()}
            cmd_str = " ".join(str(a) for a in args) + " " + " ".join(f"{k}={v}" for k, v in call_dict.items())

            action = {
                "agent_id": self.agent_id,
                "action_type": func_name,
                "payload": {
                    "command": cmd_str,
                    "query": cmd_str,
                    "amount_usd": kwargs.get("amount_usd", 0.0),
                    **call_dict
                }
            }
            res = self.gate.evaluate(action)
            if res.get("verdict") == "DENY":
                rule_id = res.get("rule_id", "BTP-AST-VETO")
                reason = res.get("reason", "Action blocked")
                raise PermissionError(f"[{rule_id}] Agno action blocked by Bartholomew: {reason}")

            result = fn(*args, **kwargs)
            if isinstance(result, str):
                return self.secret_masker.mask(result)
            return result

        return wrapper

    def protect_agent(self, agent: Any) -> Any:
        """Instruments an Agno Agent instance, guarding all its tools."""
        if hasattr(agent, "tools") and isinstance(agent.tools, list):
            agent.tools = [self.tool(t) if callable(t) else t for t in agent.tools]
        return agent
