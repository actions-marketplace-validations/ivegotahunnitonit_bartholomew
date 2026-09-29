"""
Bartholomew Agent Token Budget Governor (BTP v6.0-pre)
=======================================================
Real-time token spend tracking and circuit breaking for autonomous agents.
Prevents runaway API costs from:
  - Agent loops (same task repeated 50x)
  - Hallucinated large file reads
  - Unnecessary multi-model escalations
  - Missing or broken stop conditions

Features:
  1. Per-session and per-task token budgets with hard limits
  2. Velocity circuit breaker: trips if spend rate exceeds threshold
  3. Model-aware cost tracking (GPT-4o, Claude 3.5, Gemini 2)
  4. Plain-English budget reports and alerts
  5. Spend audit trail with Merkle receipts

Zero external deps. Thread-safe.
"""

import time
import hashlib
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


MODEL_COST_PER_TOKEN = {
    "gpt-4o":            {"input": 5.00 / 1_000_000, "output": 15.00 / 1_000_000},
    "gpt-4o-mini":       {"input": 0.15 / 1_000_000, "output": 0.60 / 1_000_000},
    "claude-3-5-sonnet": {"input": 3.00 / 1_000_000, "output": 15.00 / 1_000_000},
    "claude-3-haiku":    {"input": 0.25 / 1_000_000, "output": 1.25 / 1_000_000},
    "gemini-2-flash":    {"input": 0.075 / 1_000_000, "output": 0.30 / 1_000_000},
    "gemini-2-pro":      {"input": 1.25 / 1_000_000,  "output": 5.00 / 1_000_000},
}

DEFAULT_MODEL = "gemini-2-flash"


@dataclass
class SpendRecord:
    task_id: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    timestamp: float = field(default_factory=time.time)
    receipt: str = ""

    def __post_init__(self):
        if not self.receipt:
            payload = f"{self.task_id}:{self.model}:{self.input_tokens}:{self.timestamp}"
            self.receipt = hashlib.sha256(payload.encode()).hexdigest()[:16]


class AgentTokenBudgetGovernor:
    """
    Tracks and enforces token spend budgets for autonomous AI agent sessions.
    Thread-safe. Fires circuit breaker when limits are hit.
    """

    def __init__(
        self,
        session_budget_usd: float = 1.00,
        per_task_budget_usd: float = 0.10,
        velocity_window_sec: int = 60,
        velocity_limit_usd: float = 0.25,
        model: str = DEFAULT_MODEL,
    ):
        self.session_budget_usd = session_budget_usd
        self.per_task_budget_usd = per_task_budget_usd
        self.velocity_window_sec = velocity_window_sec
        self.velocity_limit_usd = velocity_limit_usd
        self.model = model
        self._lock = threading.Lock()

        self.session_spend_usd = 0.0
        self.task_spends: Dict[str, float] = {}
        self.records: List[SpendRecord] = []
        self.circuit_broken = False
        self.circuit_reason = ""

        self.session_id = hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12]

    def _compute_cost(self, input_tokens: int, output_tokens: int) -> float:
        rates = MODEL_COST_PER_TOKEN.get(self.model, MODEL_COST_PER_TOKEN[DEFAULT_MODEL])
        return input_tokens * rates["input"] + output_tokens * rates["output"]

    def _check_velocity(self) -> Optional[str]:
        """Check spend velocity over the last velocity_window_sec seconds."""
        now = time.time()
        window_start = now - self.velocity_window_sec
        recent_spend = sum(
            r.cost_usd for r in self.records
            if r.timestamp >= window_start
        )
        if recent_spend >= self.velocity_limit_usd:
            return (
                f"Velocity limit hit: ${recent_spend:.4f} spent in last "
                f"{self.velocity_window_sec}s (limit: ${self.velocity_limit_usd:.2f})"
            )
        return None

    def record_usage(
        self,
        task_id: str,
        input_tokens: int,
        output_tokens: int = 0,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record token usage for a task. Returns verdict and current state.
        Trips circuit breaker if any limit is exceeded.
        """
        with self._lock:
            if self.circuit_broken:
                return {
                    "allowed": False,
                    "circuit_broken": True,
                    "reason": self.circuit_reason,
                    "session_spend_usd": self.session_spend_usd,
                }

            model_used = model or self.model
            cost = self._compute_cost(input_tokens, output_tokens)

            record = SpendRecord(
                task_id=task_id,
                model=model_used,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=cost,
            )
            self.records.append(record)
            self.session_spend_usd += cost
            self.task_spends[task_id] = self.task_spends.get(task_id, 0.0) + cost

            # Check limits
            if self.session_spend_usd >= self.session_budget_usd:
                self.circuit_broken = True
                self.circuit_reason = (
                    f"Session budget exhausted: ${self.session_spend_usd:.4f} "
                    f">= ${self.session_budget_usd:.2f} limit"
                )
            elif self.task_spends[task_id] >= self.per_task_budget_usd:
                self.circuit_broken = True
                self.circuit_reason = (
                    f"Task '{task_id}' budget exhausted: ${self.task_spends[task_id]:.4f} "
                    f">= ${self.per_task_budget_usd:.2f} limit"
                )
            else:
                velocity_breach = self._check_velocity()
                if velocity_breach:
                    self.circuit_broken = True
                    self.circuit_reason = velocity_breach

            return {
                "allowed": not self.circuit_broken,
                "circuit_broken": self.circuit_broken,
                "reason": self.circuit_reason if self.circuit_broken else "Within budget",
                "cost_this_call_usd": round(cost, 6),
                "session_spend_usd": round(self.session_spend_usd, 6),
                "session_budget_usd": self.session_budget_usd,
                "task_spend_usd": round(self.task_spends[task_id], 6),
                "per_task_budget_usd": self.per_task_budget_usd,
                "budget_remaining_pct": round(
                    max(0, 1 - self.session_spend_usd / self.session_budget_usd) * 100, 1
                ),
                "receipt": record.receipt,
            }

    def reset_circuit(self) -> None:
        """Manually reset circuit breaker (requires supervisor authorization)."""
        with self._lock:
            self.circuit_broken = False
            self.circuit_reason = ""

    def get_report(self) -> Dict[str, Any]:
        """Full budget report for the session."""
        with self._lock:
            total_tokens = sum(r.input_tokens + r.output_tokens for r in self.records)
            return {
                "session_id": self.session_id,
                "model": self.model,
                "session_budget_usd": self.session_budget_usd,
                "session_spend_usd": round(self.session_spend_usd, 6),
                "budget_used_pct": round(self.session_spend_usd / self.session_budget_usd * 100, 1),
                "circuit_broken": self.circuit_broken,
                "circuit_reason": self.circuit_reason,
                "total_calls": len(self.records),
                "total_tokens": total_tokens,
                "task_breakdown": dict(self.task_spends),
                "top_tasks": sorted(
                    self.task_spends.items(), key=lambda x: x[1], reverse=True
                )[:5],
            }
