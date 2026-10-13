"""
Bartholomew Information-Flow Tracker & Sensitivity Lattice (BTP v6.5.7)
========================================================================
Implements mathematical lattice-based security (Bell-LaPadula inspired)
for Vault data tracking, taint propagation, and deterministic egress verification.

Lattice:
  PUBLIC (rank 0) < INTERNAL (rank 1) < CONFIDENTIAL (rank 2) < SECRET (rank 3)
  Join operator: join(A, B) = max(rank(A), rank(B))
"""

from dataclasses import dataclass, field
from enum import IntEnum
import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class SensitivityLevel(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


@dataclass
class TaintOrigin:
    data_id: str
    level: SensitivityLevel
    source: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DestinationPolicy:
    policy_id: str
    destination_pattern: str
    max_permitted_level: SensitivityLevel
    allowlisted_tools: Optional[List[str]] = None


@dataclass
class FlowVerdict:
    allowed: bool
    verdict: str
    reason: str
    data_id: str
    effective_level: SensitivityLevel
    destination: str
    policy_matched: Optional[str]
    taint_provenance: List[str]


class InformationFlowEngine:
    """Enforces deterministic information-flow policies across MCP tools and egress endpoints."""

    def __init__(self):
        self._taint_store: Dict[str, TaintOrigin] = {}
        self._derivation_dag: Dict[str, List[str]] = {}
        self._policies: List[DestinationPolicy] = [
            DestinationPolicy(
                policy_id="POLICY_SECURE_ENCLAVE",
                destination_pattern=r"(?i).*(hsm|kms|nitro-enclave|vault-isolated).*",
                max_permitted_level=SensitivityLevel.SECRET
            ),
            DestinationPolicy(
                policy_id="POLICY_CONFIDENTIAL_STORAGE",
                destination_pattern=r"(?i).*(encrypted-db|corporate-s3|auth-server).*",
                max_permitted_level=SensitivityLevel.CONFIDENTIAL
            ),
            DestinationPolicy(
                policy_id="POLICY_PUBLIC_EGRESS",
                destination_pattern=r"(?i).*(public|internet|external|webhook\.site|pastebin).*",
                max_permitted_level=SensitivityLevel.PUBLIC
            ),
            DestinationPolicy(
                policy_id="POLICY_INTERNAL_BUS",
                destination_pattern=r"(?i).*(internal|local|mcp://local-.*|127\.0\.0\.1).*",
                max_permitted_level=SensitivityLevel.INTERNAL
            ),
        ]

    def register_policy(self, policy: DestinationPolicy) -> None:
        self._policies.insert(0, policy)

    def tag_source(
        self,
        data_id: str,
        level: SensitivityLevel,
        source_description: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TaintOrigin:
        """Assign an initial sensitivity label to data at its ingestion or origination boundary."""
        origin = TaintOrigin(
            data_id=data_id,
            level=level,
            source=source_description,
            metadata=metadata or {}
        )
        self._taint_store[data_id] = origin
        return origin

    def propagate_transformation(
        self,
        source_data_ids: List[str],
        derived_data_id: str,
        operation_name: str = "derive"
    ) -> TaintOrigin:
        """
        Propagate taint across transformation or synthesis.
        Lattice Join: Level(derived) = sup { Level(s) for s in sources }
        """
        max_level = SensitivityLevel.PUBLIC
        for sid in source_data_ids:
            parent = self._taint_store.get(sid)
            if parent and parent.level > max_level:
                max_level = parent.level

        self._derivation_dag[derived_data_id] = list(source_data_ids)
        derived = TaintOrigin(
            data_id=derived_data_id,
            level=max_level,
            source=f"{operation_name}:{','.join(source_data_ids)}",
            metadata={"parents": source_data_ids, "operator": operation_name}
        )
        self._taint_store[derived_data_id] = derived
        return derived

    def get_provenance_trace(self, data_id: str) -> List[str]:
        """Compute complete transitive dependency graph for a data token."""
        trace = [data_id]
        queue = [data_id]
        visited = {data_id}
        while queue:
            curr = queue.pop(0)
            parents = self._derivation_dag.get(curr, [])
            for p in parents:
                if p not in visited:
                    visited.add(p)
                    trace.append(p)
                    queue.append(p)
        return trace

    def evaluate_egress(
        self,
        data_id: str,
        destination: str,
        tool_name: Optional[str] = None
    ) -> FlowVerdict:
        """
        Deterministically evaluates whether transmitting data_id to destination violates
        information flow boundaries.
        """
        origin = self._taint_store.get(data_id)
        effective_level = origin.level if origin else SensitivityLevel.PUBLIC
        trace = self.get_provenance_trace(data_id)

        for pol in self._policies:
            if re.match(pol.destination_pattern, destination):
                # Check tool allowlist if policy defines one
                if tool_name and pol.allowlisted_tools:
                    if tool_name not in pol.allowlisted_tools and "*" not in pol.allowlisted_tools:
                        return FlowVerdict(
                            allowed=False,
                            verdict="DENY_TOOL_NOT_ALLOWLISTED",
                            reason=f"Tool '{tool_name}' unauthorized under egress policy '{pol.policy_id}'.",
                            data_id=data_id,
                            effective_level=effective_level,
                            destination=destination,
                            policy_matched=pol.policy_id,
                            taint_provenance=trace
                        )

                # Lattice comparison: effective_level <= max_permitted_level
                if effective_level > pol.max_permitted_level:
                    return FlowVerdict(
                        allowed=False,
                        verdict="DENY_SENSITIVITY_EXCEEDED",
                        reason=(
                            f"Information flow violation: Data '{data_id}' labeled {effective_level.name} "
                            f"exceeds destination '{destination}' maximum clearance {pol.max_permitted_level.name} "
                            f"(Enforced by {pol.policy_id})."
                        ),
                        data_id=data_id,
                        effective_level=effective_level,
                        destination=destination,
                        policy_matched=pol.policy_id,
                        taint_provenance=trace
                    )

                return FlowVerdict(
                    allowed=True,
                    verdict="PERMIT_FLOW",
                    reason=f"Flow authorized: {effective_level.name} <= {pol.max_permitted_level.name} under {pol.policy_id}.",
                    data_id=data_id,
                    effective_level=effective_level,
                    destination=destination,
                    policy_matched=pol.policy_id,
                    taint_provenance=trace
                )

        # Default fail-closed for CONFIDENTIAL or SECRET data without explicit policy
        if effective_level >= SensitivityLevel.CONFIDENTIAL:
            return FlowVerdict(
                allowed=False,
                verdict="FAIL_CLOSED_NO_POLICY",
                reason=f"No egress policy permits {effective_level.name} flow to unrecognized destination '{destination}'.",
                data_id=data_id,
                effective_level=effective_level,
                destination=destination,
                policy_matched=None,
                taint_provenance=trace
            )

        return FlowVerdict(
            allowed=True,
            verdict="PERMIT_DEFAULT_LOW_RISK",
            reason=f"Default permit for low-sensitivity data ({effective_level.name}) without conflicting policy.",
            data_id=data_id,
            effective_level=effective_level,
            destination=destination,
            policy_matched=None,
            taint_provenance=trace
        )
