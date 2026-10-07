"""
Bartholomew Guard for Microsoft Semantic Kernel (BTP v6.4.4)
============================================================
In-process runtime execution guard, AST invariant validator,
and credential scrubber for Semantic Kernel plugins and functions.
"""

import functools
from typing import Any, Callable, Dict, Optional
from ..authorization_gate import AuthorizationGate
from ..secret_masker import SecretMasker


class BtpSemanticKernelGuard:
    """Enterprise AST invariant & tool execution guard for Semantic Kernel."""

    def __init__(
        self,
        spend_cap: float = 100.0,
        strict: bool = True,
        agent_id: str = "semantic-kernel-agent",
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

    def kernel_function(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Wraps a Semantic Kernel plugin function with sub-35us AST validation."""
        func_name = getattr(fn, "__name__", "kernel_function")

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
                raise PermissionError(f"[{rule_id}] Semantic Kernel execution blocked by Bartholomew: {reason}")

            result = fn(*args, **kwargs)
            if isinstance(result, str):
                return self.secret_masker.mask(result)
            return result

        return wrapper

    def as_filter(self) -> Dict[str, Any]:
        """Provides filter definition for Semantic Kernel pipeline invocation hooks."""
        return {
            "name": "BtpSemanticKernelGuardFilter",
            "type": "FunctionInvocationFilter",
            "agent_id": self.agent_id,
            "latency_sla_us": 35.0
        }
