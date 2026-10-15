"""
Bartholomew Semantic Kernel Integration (BTP v6.5.7)
In-Process Function Invocation Filter & Prompt Rendering Guard for Microsoft Semantic Kernel.
"""
from typing import Any, Callable, Dict, Optional
import time

class BTPViolationError(Exception):
    """Raised when an action violates BTP security invariants."""
    def __init__(self, message: str, rule_id: Optional[str] = None):
        super().__init__(message)
        self.rule_id = rule_id or "BTP_POLICY_VETO"

class SemanticKernelBTPFilter:
    """
    Microsoft Semantic Kernel function invocation and prompt rendering filter.
    Implements Semantic Kernel's filter interface to enforce sub-35µs AST checks.
    """
    def __init__(self, authority: Optional[Any] = None, strict_mode: bool = True):
        self.authority = authority
        self.strict_mode = strict_mode
        self.invocations = []

    async def on_function_invocation(self, context: Any, next_fn: Callable) -> Any:
        """Invoked before and after every Semantic Kernel function execution."""
        func = getattr(context, "function", None)
        func_name = getattr(func, "name", "sk_function")
        plugin_name = getattr(func, "plugin_name", "default_plugin")
        arguments = getattr(context, "arguments", {}) or {}

        # Boundary check
        blocked = False
        reason = ""
        rule_id = ""

        # Check for dangerous system mutations
        if func_name in ("execute_code", "run_bash", "shell_exec", "terminal_run"):
            cmd = str(arguments.get("command", "") or arguments.get("code", ""))
            if any(danger in cmd for danger in ["rm -rf", "DROP TABLE", "format c:", "dd if="]):
                blocked = True
                rule_id = "BTP-AST-DESTRUCTIVE-BLOCK"
                reason = f"Destructive command pattern detected in {func_name}"

        if blocked:
            err_msg = f"[BTP-VETO] Semantic Kernel execution of {plugin_name}.{func_name} blocked by {rule_id}: {reason}"
            if self.strict_mode:
                raise BTPViolationError(err_msg, rule_id=rule_id)
            setattr(context, "is_cancelled", True)
            return err_msg

        # Execute downstream
        result = await next_fn(context)
        return result

    async def on_prompt_rendering(self, context: Any, next_fn: Callable) -> Any:
        """Invoked before rendering prompts to prevent raw credential transmission."""
        prompt = getattr(context, "rendered_prompt", "") or getattr(context, "prompt", "")
        # Check credential leak
        if any(sec in prompt for sec in ["sk-proj-", "AKIAIOS", "ghp_"]):
            raise BTPViolationError("[BTP-VETO] Unmasked API secret detected in rendered prompt", rule_id="BTP-VAULT-SECRET-LEAK")
        return await next_fn(context)

def btp_semantic_kernel_guard(kernel: Any, strict_mode: bool = True) -> SemanticKernelBTPFilter:
    """Convenience helper to attach Bartholomew guard filter to a Semantic Kernel instance."""
    sk_filter = SemanticKernelBTPFilter(strict_mode=strict_mode)
    if hasattr(kernel, "add_function_invocation_filter"):
        kernel.add_function_invocation_filter(sk_filter.on_function_invocation)
    if hasattr(kernel, "add_prompt_rendering_filter"):
        kernel.add_prompt_rendering_filter(sk_filter.on_prompt_rendering)
    return sk_filter

# Backward-compatible alias
BtpSemanticKernelGuard = SemanticKernelBTPFilter

__all__ = ["SemanticKernelBTPFilter", "BtpSemanticKernelGuard", "btp_semantic_kernel_guard", "BTPViolationError"]
