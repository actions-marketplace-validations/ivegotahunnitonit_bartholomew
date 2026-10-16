"""
Bartholomew Temporal Security State Machine Verifier (BTP v6.5.7)
==================================================================
Models agent capability lifecycles and tool authorization sequences as
deterministic state machines and verifies Linear Temporal Logic (LTL)
invariants across execution traces.

LTL Invariants:
  1. [](ActionExecuted(a) -> ActiveCapability(a))
     Always: An action is executed only if an active capability authorizes it.
  2. [](Revoked(c) -> [](!Authorized(c)))
     Always: Once a capability is revoked, it remains permanently unauthorized.
  3. [](NonceConsumed(n) -> [](!AcceptNonce(n)))
     Always: Once a nonce is consumed, it is never accepted in any future state.
  4. [](State in {TERMINAL} -> !(State -> ACTIVE))
     Always: Terminal states (CONSUMED, EXPIRED, REVOKED) cannot re-enter ACTIVE.
"""

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class CapabilityState(str, Enum):
    UNINITIALIZED = "UNINITIALIZED"
    ISSUED = "ISSUED"
    ACTIVE = "ACTIVE"
    DELEGATED = "DELEGATED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


VALID_TRANSITIONS: Dict[CapabilityState, Set[CapabilityState]] = {
    CapabilityState.UNINITIALIZED: {CapabilityState.ISSUED},
    CapabilityState.ISSUED: {CapabilityState.ACTIVE, CapabilityState.DELEGATED, CapabilityState.REVOKED, CapabilityState.EXPIRED},
    CapabilityState.ACTIVE: {CapabilityState.ACTIVE, CapabilityState.CONSUMED, CapabilityState.REVOKED, CapabilityState.EXPIRED},
    CapabilityState.DELEGATED: {CapabilityState.ACTIVE, CapabilityState.REVOKED, CapabilityState.EXPIRED},
    CapabilityState.CONSUMED: set(),  # Terminal state
    CapabilityState.EXPIRED: set(),   # Terminal state
    CapabilityState.REVOKED: set(),   # Terminal state
}


@dataclass
class TemporalEvent:
    event_type: str
    target_id: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StateTransitionViolation:
    capability_id: str
    from_state: CapabilityState
    to_state: CapabilityState
    reason: str
    timestamp: float


class CapabilityLifecycleStateMachine:
    """Formal deterministic state machine managing individual capability token lifecycles."""

    def __init__(self, capability_id: str, max_uses: int = 1):
        self.capability_id = capability_id
        self.max_uses = max_uses
        self.uses_count = 0
        self.state: CapabilityState = CapabilityState.UNINITIALIZED
        self.transition_history: List[Tuple[CapabilityState, CapabilityState, float]] = []

    def transition(self, target_state: CapabilityState, reason: str = "") -> bool:
        """Attempt state transition following formal transition graph."""
        allowed = VALID_TRANSITIONS.get(self.state, set())
        if target_state not in allowed:
            return False

        old = self.state
        self.state = target_state
        self.transition_history.append((old, target_state, time.time()))
        return True

    def record_invocation(self) -> bool:
        """Record an action invocation under this capability."""
        if self.state not in {CapabilityState.ACTIVE, CapabilityState.ISSUED}:
            return False
        
        # Move to active if was issued
        if self.state == CapabilityState.ISSUED:
            self.state = CapabilityState.ACTIVE

        self.uses_count += 1
        if self.uses_count >= self.max_uses:
            self.state = CapabilityState.CONSUMED
        return True


class TemporalSequenceVerifier:
    """Verifies complete multi-step execution traces against LTL temporal properties."""

    def __init__(self):
        self._capabilities: Dict[str, CapabilityLifecycleStateMachine] = {}
        self._consumed_nonces: Set[str] = set()
        self._execution_trace: List[TemporalEvent] = []
        self._violations: List[str] = []

    def register_capability(self, capability_id: str, max_uses: int = 1) -> CapabilityLifecycleStateMachine:
        sm = CapabilityLifecycleStateMachine(capability_id, max_uses)
        sm.transition(CapabilityState.ISSUED, "Minted by authority")
        self._capabilities[capability_id] = sm
        return sm

    def revoke(self, capability_id: str, reason: str = "Admin revocation") -> bool:
        sm = self._capabilities.get(capability_id)
        if not sm:
            return False
        return sm.transition(CapabilityState.REVOKED, reason)

    def expire(self, capability_id: str) -> bool:
        sm = self._capabilities.get(capability_id)
        if not sm:
            return False
        return sm.transition(CapabilityState.EXPIRED, "TTL expired")

    def authorize_step(
        self,
        capability_id: str,
        nonce: str,
        action_name: str,
        session_id: str
    ) -> Tuple[bool, str]:
        """
        Evaluates temporal authorization for an individual step in an execution trace:
        Checks:
          1. Nonce freshness (never seen before in this session/process).
          2. Capability state is valid for invocation.
          3. Atomic consumption.
        """
        # Temporal Check 1: Nonce Replay
        if nonce in self._consumed_nonces:
            v = f"LTL_VIOLATION_NONCE_REPLAY: Nonce '{nonce}' reused in step '{action_name}'"
            self._violations.append(v)
            return False, v

        # Temporal Check 2: Capability State
        sm = self._capabilities.get(capability_id)
        if not sm:
            v = f"LTL_VIOLATION_UNKNOWN_CAPABILITY: '{capability_id}' not found"
            self._violations.append(v)
            return False, v

        if sm.state in {CapabilityState.CONSUMED, CapabilityState.EXPIRED, CapabilityState.REVOKED}:
            v = f"LTL_VIOLATION_TERMINAL_REUSE: Action attempted under {sm.state.value} capability '{capability_id}'"
            self._violations.append(v)
            return False, v

        # Advance state
        success = sm.record_invocation()
        if not success:
            v = f"LTL_VIOLATION_INVOCATION_EXHAUSTED: Capability '{capability_id}' cannot execute further actions"
            self._violations.append(v)
            return False, v

        self._consumed_nonces.add(nonce)
        self._execution_trace.append(TemporalEvent(
            event_type="STEP_AUTHORIZED",
            target_id=action_name,
            metadata={"capability_id": capability_id, "nonce": nonce, "session_id": session_id}
        ))
        return True, "STEP_PERMITTED"

    def get_violations(self) -> List[str]:
        return list(self._violations)

    def is_trace_clean(self) -> bool:
        return len(self._violations) == 0
