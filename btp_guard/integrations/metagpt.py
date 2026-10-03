"""
Bartholomew Guard for MetaGPT (BTP v6.4.0)
=========================================
Deterministic AST execution firewall & sovereign ledger recorder for MetaGPT multi-agent software engineering roles (ProductManager, Architect, Engineer, QAEngineer).

Usage:
    from btp_guard.integrations.metagpt import BtpMetaGPTGuard

    guard = BtpMetaGPTGuard()
    guarded_code = guard.validate_code("import os; os.system('rm -rf /')") # Raises PermissionError
"""

from typing import Any, Callable, Dict, Optional
import functools
from ..authorization_gate import AuthorizationGate


class BtpMetaGPTGuard:
    """AST Execution gate & ledger interceptor for MetaGPT multi-agent software teams."""

    def __init__(
        self,
        strict: bool = True,
        role_name: str = "MetaGPT-Engineer",
        ledger_path: Optional[str] = None
    ):
        self.role_name = str(role_name)
        self.gate = AuthorizationGate(
            policy={
                "strict": strict,
                "allow_destructive": False,
            },
            ledger_path=ledger_path
        )

    def validate_code(self, code_str: str) -> bool:
        """Validates generated code before execution or file emission."""
        try:
            from src.polyglot_ast_validator import PolyglotASTValidator
            is_safe, reason, _ = PolyglotASTValidator.validate_code(code_str, language="python")
            if not is_safe:
                raise PermissionError(f"[BTP-METAGPT-VETO]: Unsafe code execution blocked: {reason}")
        except ImportError:
            pass

        action = {
            "agent_id": self.role_name,
            "action_type": "METAGPT_CODE_EMISSION",
            "payload": {"command": code_str}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-METAGPT-VETO]: Code blocked by security policy: {res.get('reason')}")

        return True

    def validate_command(self, cmd_str: str) -> bool:
        """Validates shell execution commands run by MetaGPT QA or DevOps roles."""
        action = {
            "agent_id": self.role_name,
            "action_type": "METAGPT_SHELL_EXEC",
            "payload": {"command": cmd_str}
        }
        res = self.gate.evaluate(action)
        if res.get("verdict") == "DENY":
            raise PermissionError(f"[BTP-METAGPT-VETO]: Shell command blocked: {res.get('reason')}")
        return True

    def wrap_action(self, action_instance: Any) -> Any:
        """Wraps a MetaGPT Action.run method to intercept execution."""
        orig_run = getattr(action_instance, "run", None)
        if not orig_run:
            return action_instance

        @functools.wraps(orig_run)
        def guarded_run(*args, **kwargs):
            payload_str = " ".join(str(a) for a in args) + " " + json_safe_kwargs(kwargs)
            action = {
                "agent_id": self.role_name,
                "action_type": getattr(action_instance, "name", "MetaGPT_Action"),
                "payload": {"command": payload_str}
            }
            res = self.gate.evaluate(action)
            if res.get("verdict") == "DENY":
                raise PermissionError(f"[BTP-METAGPT-VETO]: Action blocked: {res.get('reason')}")
            result = orig_run(*args, **kwargs)
            if isinstance(result, str):
                self.validate_code(result)
            return result

        action_instance.run = guarded_run
        return action_instance


def json_safe_kwargs(kwargs: Dict[str, Any]) -> str:
    parts = []
    for k, v in kwargs.items():
        try:
            parts.append(f"{k}={v}")
        except Exception:
            pass
    return " ".join(parts)
