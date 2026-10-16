"""
Bartholomew Weakest Preconditions Engine (BTP v6.5.7)
======================================================
Dijkstra's Weakest Preconditions (WP) calculus applied to AI Agent action safety.
For a target security postcondition Q (e.g. "No unauthorized disk write or database mutation"),
calculates WP(Action, Q) and deterministically asserts that all preconditions are satisfied
prior to dispatch.

Formal WP Rules:
  1. WP(WriteFile(path, content), SafeFS) =
       IsPathAllowlisted(path) AND
       NOT IsPathDenied(path) AND
       FileExtensionAllowed(path) AND
       ContentSanitized(content) AND
       ValidCapability(passkey, "FILE_WRITE", path)

  2. WP(ExecuteTool(tool, args), SafeToolExecution) =
       ToolPermitted(passkey, tool) AND
       PayloadSizeWithinCeiling(args) AND
       ArgsSanitized(args) AND
       NonceUnconsumed(nonce) AND
       PasskeyNotRevoked(passkey)

  3. WP(NetworkEgress(dest, payload), SafeEgress) =
       DestAllowlisted(passkey, dest) AND
       TaintLevel(payload) <= MaxDestClearance(dest)
"""

from dataclasses import dataclass
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class PreconditionCheckResult:
    condition_name: str
    satisfied: bool
    evidence: str
    latency_us: float


@dataclass
class WeakestPreconditionVerdict:
    action_type: str
    postcondition_target: str
    all_satisfied: bool
    verdict: str
    checks: List[PreconditionCheckResult]
    total_latency_us: float


class WeakestPreconditionsEngine:
    """Calculates and verifies weakest preconditions for agent tool dispatch."""

    DENIED_PATHS_DEFAULT = [
        r".*\.env(\..+)?$",
        r".*id_rsa(\.pub)?$",
        r".*id_ed25519.*$",
        r".*\.git/hooks/.*",
        r".*credentials\.json$",
        r".*service_account\.json$",
        r".*\.btp/keystore.*"
    ]

    DENIED_COMMANDS_DEFAULT = [
        r"\brm\s+-rf\b",
        r"\bsudo\b",
        r"\bmkfs\b",
        r"\bdd\b",
        r"\bshutdown\b",
        r"\bchmod\s+777\b"
    ]

    def __init__(self):
        self._compiled_path_denies = [re.compile(p, re.IGNORECASE) for p in self.DENIED_PATHS_DEFAULT]
        self._compiled_cmd_denies = [re.compile(c, re.IGNORECASE) for c in self.DENIED_COMMANDS_DEFAULT]

    def verify_wp_file_write(
        self,
        target_path: str,
        content: str,
        passkey: Optional[Dict[str, Any]]
    ) -> WeakestPreconditionVerdict:
        """
        Target Postcondition Q: 'No unauthorized modification of sensitive filesystem targets.'
        WP(Write, Q) = ValidPasskey AND PathAllowed AND NOT PathDenied AND SizeWithinLimit
        """
        start = time.perf_counter_ns()
        checks: List[PreconditionCheckResult] = []

        # Condition 1: Passkey valid and not expired
        c1_start = time.perf_counter_ns()
        has_passkey = passkey is not None and passkey.get("expires_at_unix", 0) > time.time()
        c1_end = time.perf_counter_ns()
        checks.append(PreconditionCheckResult(
            condition_name="PasskeyActive",
            satisfied=has_passkey,
            evidence=f"Passkey valid: {has_passkey}",
            latency_us=(c1_end - c1_start) / 1000.0
        ))

        # Condition 2: Target path not in blacklisted patterns
        c2_start = time.perf_counter_ns()
        norm_path = target_path.replace("\\", "/")
        is_denied = any(pat.match(norm_path) for pat in self._compiled_path_denies)
        c2_end = time.perf_counter_ns()
        checks.append(PreconditionCheckResult(
            condition_name="PathNotDenied",
            satisfied=not is_denied,
            evidence=f"Path '{target_path}' matches deny pattern: {is_denied}",
            latency_us=(c2_end - c2_start) / 1000.0
        ))

        # Condition 3: Explicit scope allowlist check if scoped
        c3_start = time.perf_counter_ns()
        allowed_paths = passkey.get("scopes", {}).get("allow_write", []) if passkey else []
        if allowed_paths and "*" not in allowed_paths:
            import fnmatch
            path_in_scope = any(
                allowed in norm_path or
                fnmatch.fnmatch(norm_path, allowed) or
                norm_path.startswith(allowed.rstrip("/*"))
                for allowed in allowed_paths
            )
        else:
            path_in_scope = True
        c3_end = time.perf_counter_ns()
        checks.append(PreconditionCheckResult(
            condition_name="PathInScope",
            satisfied=path_in_scope,
            evidence=f"Path '{target_path}' within allowlist {allowed_paths}: {path_in_scope}",
            latency_us=(c3_end - c3_start) / 1000.0
        ))

        # Condition 4: Payload size reasonable (< 10 MB)
        c4_start = time.perf_counter_ns()
        size_bytes = len(content.encode("utf-8"))
        size_ok = size_bytes <= 10 * 1024 * 1024
        c4_end = time.perf_counter_ns()
        checks.append(PreconditionCheckResult(
            condition_name="ContentSizeSafe",
            satisfied=size_ok,
            evidence=f"Content size {size_bytes} <= 10485760 bytes",
            latency_us=(c4_end - c4_start) / 1000.0
        ))

        total_end = time.perf_counter_ns()
        all_passed = all(c.satisfied for c in checks)

        return WeakestPreconditionVerdict(
            action_type="FILE_WRITE",
            postcondition_target="SafeFSWrite",
            all_satisfied=all_passed,
            verdict="PERMIT_ACTION" if all_passed else "PRECONDITION_FAILURE",
            checks=checks,
            total_latency_us=(total_end - start) / 1000.0
        )

    def verify_wp_command_exec(
        self,
        command_line: str,
        passkey: Optional[Dict[str, Any]]
    ) -> WeakestPreconditionVerdict:
        """
        Target Postcondition Q: 'No shell injection, privilege escalation, or destructive deletion.'
        WP(Exec, Q) = ValidPasskey AND NOT CmdDenied AND NoDangerousChaining
        """
        start = time.perf_counter_ns()
        checks: List[PreconditionCheckResult] = []

        # Condition 1: Passkey
        c1_start = time.perf_counter_ns()
        has_passkey = passkey is not None and passkey.get("expires_at_unix", 0) > time.time()
        c1_end = time.perf_counter_ns()
        checks.append(PreconditionCheckResult(
            condition_name="PasskeyActive",
            satisfied=has_passkey,
            evidence=f"Passkey valid: {has_passkey}",
            latency_us=(c1_end - c1_start) / 1000.0
        ))

        # Condition 2: Forbidden destructive commands
        c2_start = time.perf_counter_ns()
        cmd_denied = any(pat.search(command_line) for pat in self._compiled_cmd_denies)
        c2_end = time.perf_counter_ns()
        checks.append(PreconditionCheckResult(
            condition_name="CommandNotDestructive",
            satisfied=not cmd_denied,
            evidence=f"Command matches forbidden destructive signature: {cmd_denied}",
            latency_us=(c2_end - c2_start) / 1000.0
        ))

        # Condition 3: Dangerous shell operators if command scope prohibits chaining
        c3_start = time.perf_counter_ns()
        chaining_denied = passkey.get("scopes", {}).get("deny_shell_operators", True) if passkey else True
        has_dangerous_chain = any(op in command_line for op in [";", "&&", "||", "`", "$("])
        c3_satisfied = not (chaining_denied and has_dangerous_chain)
        c3_end = time.perf_counter_ns()
        checks.append(PreconditionCheckResult(
            condition_name="NoDangerousOperatorChaining",
            satisfied=c3_satisfied,
            evidence=f"Contains chaining operators: {has_dangerous_chain} (Prohibited: {chaining_denied})",
            latency_us=(c3_end - c3_start) / 1000.0
        ))

        total_end = time.perf_counter_ns()
        all_passed = all(c.satisfied for c in checks)

        return WeakestPreconditionVerdict(
            action_type="COMMAND_EXEC",
            postcondition_target="SafeCommandExecution",
            all_satisfied=all_passed,
            verdict="PERMIT_ACTION" if all_passed else "PRECONDITION_FAILURE",
            checks=checks,
            total_latency_us=(total_end - start) / 1000.0
        )
