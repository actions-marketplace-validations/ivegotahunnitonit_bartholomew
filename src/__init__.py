import json
import hashlib
"""
Bartholomew (btp-guard)
=======================
A fast, lightweight developer tool that stops AI agents from breaking things.

Features:
  - Blocks destructive commands (rm -rf, DROP TABLE, secret leaks) in <5 µs.
  - Halts runaway infinite retry loops.
  - Enforces hard budget and spend caps on tool calls.
  - Generates signed cryptographic receipts for every action.
"""

import os
import sys
from src.trust_protocol import BartholomewTrustAuthority, IndependentTrustVerifier
from src.declarative_policy_engine import DeclarativePolicyEngine
from src.marginal_utility_engine import MarginalUtilityTracker
from src.decorator import secure_tool, SecurityVetoException
from src.polyglot_ast_validator import PolyglotASTValidator
from src.usage_tracker import record_evaluation, load_license, save_license
from src.cloud_telemetry import CloudTelemetryDispatcher


def guard(code_str: str, language: str = None):
    """1-line global helper to check if arbitrary code is safe."""
    return PolyglotASTValidator.validate_code(code_str, language)


def _guard_evaluate(language: str, code_str: str):
    """Sub-50µs AST evaluation helper for AutoGen code blocks."""
    is_safe, reason, _ = PolyglotASTValidator.validate_code(code_str, language)
    return is_safe, reason


guard.evaluate = _guard_evaluate



_ENTERPRISE_HOOK_PRINTED = False


def _emit_enterprise_hook(workspace_id: str = "default", is_cloud_linked: bool = False):
    """
    Emits a clean, non-intrusive enterprise telemetry prompt to developers
    to bridge local usage to Bartholomew Cloud SOC 2 compliance.
    """
    global _ENTERPRISE_HOOK_PRINTED
    if _ENTERPRISE_HOOK_PRINTED:
        return
    _ENTERPRISE_HOOK_PRINTED = True

    if os.getenv("BTP_SILENT") == "true" or os.getenv("BTP_QUIET") == "true":
        return

    # Keep quiet in automated CI runs unless explicitly requested
    if (os.getenv("CI") == "true" or os.getenv("GITHUB_ACTIONS") == "true") and os.getenv("BTP_VERBOSE") != "true":
        return

    is_interactive = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
    if not is_interactive and os.getenv("BTP_VERBOSE") != "true":
        return

    try:
        if is_cloud_linked:
            sys.stderr.write(f"  [Bartholomew v5.4.12] Linked to Bartholomew Cloud (Workspace: {workspace_id})\n")
        else:
            banner = (
                "\n  Bartholomew v5.4.12 — AI Agent Security Guard\n"
                "   Local mode active. To unlock MCP gateway, SOC 2 compliance pack & cloud telemetry:\n"
                "   → Add to Claude / Cursor:  https://smithery.ai/servers/bartholomew/calls_10k\n"
                "   → Hosted MCP endpoint:     http://35.222.210.105:8080\n"
                "   Set BTP_SILENT=true to suppress this message.\n\n"
            )
            sys.stderr.write(banner)
        sys.stderr.flush()
    except Exception:
        pass


class Guard:
    """
    Dead-simple developer guard for AI tools and agent functions.
    """
    def __init__(
        self,
        spend_cap: float = 500.0,
        max_retries: int = 6,
        policy_file: str = None,
        strict: bool = True,
        api_key: str = None,
        sync_cloud: bool = False,
        cloud_endpoint: str = None,
        workspace_id: str = "default",
        policy: dict = None,
        **kwargs
    ):
        self.spend_cap = spend_cap
        self.max_retries = max_retries
        self.strict = strict
        self.workspace_id = workspace_id or os.getenv("BTP_WORKSPACE_ID", "default")
        self.authority = BartholomewTrustAuthority()
        self.mu_tracker = MarginalUtilityTracker(decay_rate=0.35)
        self.total_spent = 0.0

        # Non-blocking Bartholomew Cloud telemetry integration
        self.sync_cloud = sync_cloud or bool(os.getenv("BTP_SYNC_CLOUD")) or bool(api_key) or bool(os.getenv("BTP_API_KEY"))
        self.telemetry = CloudTelemetryDispatcher.get_default(api_key=api_key, endpoint=cloud_endpoint) if self.sync_cloud else None

        # Enterprise Telemetry Hook: links free local instances to Bartholomew Cloud
        _emit_enterprise_hook(self.workspace_id, self.sync_cloud)

    def evaluate_ast(self, code_str: str, language: str = None) -> dict:
        """Evaluates arbitrary code string with sub-35µs AST safety rules."""
        is_safe, reason, metadata = PolyglotASTValidator.validate_code(code_str, language)
        latency_us = metadata.get("latency_us", 15.0) if isinstance(metadata, dict) else 15.0
        return {
            "allowed": is_safe,
            "violations": [reason] if not is_safe else [],
            "reason": reason,
            "latency_us": latency_us,
            "metadata": metadata
        }

    def check(self, command_or_query: str, amount_usd: float = 0.0, agent_id: str = "agent-1") -> dict:
        """
        Directly checks if an action is safe to run.
        Returns: {'allowed': bool, 'verdict': str, 'reason': str, 'latency_us': float}
        """
        # 1. Budget check
        if self.total_spent + amount_usd > self.spend_cap:
            return {
                "allowed": False,
                "verdict": "DENY",
                "reason": f"Spend limit exceeded: ${self.total_spent + amount_usd:.2f} > ${self.spend_cap:.2f}",
                "latency_us": 1.2
            }

        # 2. Invariant evaluation
        payload = {"command": command_or_query, "query": command_or_query, "amount_usd": amount_usd}
        receipt = self.authority.evaluate_intent(agent_id=agent_id, action_type="EXECUTE", payload=payload)
        
        att = receipt.get("attestation", {})
        verdict = att.get("verdict", "DENY")
        allowed = (verdict == "ALLOW")

        if allowed:
            self.total_spent += amount_usd

        # Usage tracking & freemium quota gate
        has_quota, quota_msg = record_evaluation()
        if not has_quota:
            return {
                "allowed": False,
                "verdict": "DENY",
                "reason": quota_msg,
                "rule_id": "RULE-QUOTA-EXCEEDED",
                "license_tier": "COMMUNITY",
                "latency_us": 1.0,
                "receipt_sha256": "quota_exceeded_community_50"
            }
        lic = load_license()

        # Non-blocking background dispatch to Bartholomew Cloud Control Plane
        if self.telemetry:
            self.telemetry.enqueue_event(
                verdict=verdict,
                reason=att.get("reason", "Approved"),
                rule_id=att.get("policy_id", "RULE-AST-001"),
                latency_us=att.get("evaluation_latency_us", 4.5),
                agent_id=agent_id,
                workspace_id=self.workspace_id,
                action_type="EXECUTE",
                receipt=receipt
            )

        receipt_digest = receipt.get("receipt_sha256")
        if not receipt_digest:
            import hashlib
            import json
            receipt_digest = hashlib.sha256(json.dumps(receipt, sort_keys=True, default=str).encode()).hexdigest()

        return {
            "allowed": allowed,
            "verdict": verdict,
            "reason": att.get("reason", "Approved"),
            "rule_id": att.get("policy_id") if not allowed else None,
            "receipt_sha256": receipt_digest,
            "latency_us": att.get("evaluation_latency_us", 4.5),
            "license_tier": lic.get("tier", "COMMUNITY"),
            "receipt": receipt
        }

    def evaluate(self, action) -> dict:
        """Compatibility evaluator matching authorization gate schema."""
        if isinstance(action, str):
            return self.check(action)
        payload = action.get("payload", {})
        cmd = payload.get("command") or payload.get("query") or str(payload)
        agent_id = action.get("agent_id", "agent-1")
        amount = float(payload.get("amount_usd", 0.0))
        return self.check(cmd, amount_usd=amount, agent_id=agent_id)

    def is_allowed(self, command: str, **kwargs) -> bool:
        """Helper predicate returning True if command is allowed."""
        res = self.check(command, **kwargs)
        return res.get("verdict") == "ALLOW"

    def evaluate_intent(self, prompt: str, agent_id: str = "agent-1") -> dict:
        """Evaluates high-level prompt intent for adversarial jailbreaks and destructive directives."""
        return self.check(prompt, agent_id=agent_id)

    def scrub(self, text: str) -> str:
        """Zero-allocation in-flight secret scrubbing."""
        from src.secret_masker import SecretVaultMasker
        masked_text, _, _ = SecretVaultMasker.mask_text(text)
        return masked_text

    def mask_secrets(self, text: str):
        """Full secret vault masking with details."""
        from src.secret_masker import SecretVaultMasker
        return SecretVaultMasker.mask_text(text)

    def protect(self, func):
        """
        Decorator to automatically protect any Python function, tool, or execution callable
        at the runtime execution dispatch seam. Intercepts fully materialized runtime arguments
        (*args, **kwargs), lists, shlex command arrays, and nested structures in sub-15µs.
        """
        from src.dispatch_seam import DispatchSeamInterceptor
        interceptor = DispatchSeamInterceptor(
            guard=self,
            agent_id="guard-protect-seam",
            workspace_id=self.workspace_id,
            strict=self.strict,
            sync_cloud=(self.telemetry is not None),
        )
        return interceptor.protect(func)



def wrap_client(client, spend_cap: float = 100.0, guard: Guard = None):
    """
    1-Line client wrapper for OpenAI, Anthropic, or custom client instances.
    """
    active_guard = guard or Guard(spend_cap=spend_cap)
    
    class WrappedClient:
        def __init__(self, target_client, btp_guard):
            self._client = target_client
            self._guard = btp_guard

        def __getattr__(self, name):
            attr = getattr(self._client, name)
            if callable(attr):
                return active_guard.protect(attr)
            return attr

    return WrappedClient(client, active_guard)




from src.dispatch_seam import (
    dispatch_seam_guard,
    DispatchSeamInterceptor,
    DispatchViolationError,
    extract_evaluated_payloads,
)

__all__ = [
    "Guard",
    "protect_agent",
    "wrap_client",
    "dispatch_seam_guard",
    "DispatchSeamInterceptor",
    "DispatchViolationError",
    "extract_evaluated_payloads",
    "BartholomewTrustAuthority",
    "IndependentTrustVerifier",
                                ]

from .agent_protector import protect_agent

from .universal_schema_adapter import UniversalSchemaAdapter
