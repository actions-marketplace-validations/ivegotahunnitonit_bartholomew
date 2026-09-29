"""
Bartholomew Agent Context Drift Detector (BTP v6.0-pre)
========================================================
Monitors an AI agent's stated objective against its actual tool calls and
file operations to detect when it has drifted from its original intent.

This is the #1 cause of AI agent failures in production:
  - Agent starts task "refactor auth module"
  - Agent starts touching payment code, CI config, SSH keys
  - No one notices until it's too late

Provides:
  1. Objective anchoring: registers the agent's original stated goal
  2. Action alignment scoring: scores each action 0-100 against the objective
  3. Drift detection: flags when cumulative score falls below threshold
  4. Plain-English alerts: tells the user exactly what drifted and why

Zero external dependencies. Sub-1ms per action check.
"""

import re
import time
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


# Semantic categories and their typical legitimate scopes
SCOPE_TAXONOMY = {
    "AUTH":       ["auth", "login", "password", "token", "session", "oauth", "jwt", "credential"],
    "DATABASE":   ["db", "sql", "database", "query", "schema", "migration", "model", "orm"],
    "API":        ["api", "endpoint", "route", "request", "response", "rest", "graphql", "webhook"],
    "FRONTEND":   ["ui", "component", "style", "css", "html", "template", "view", "render"],
    "INFRA":      ["docker", "k8s", "deploy", "ci", "cd", "terraform", "helm", "compose"],
    "PAYMENT":    ["stripe", "payment", "billing", "invoice", "subscription", "price", "charge"],
    "SECURITY":   ["security", "guard", "firewall", "encrypt", "decrypt", "key", "vault", "secret"],
    "TEST":       ["test", "spec", "jest", "pytest", "coverage", "mock", "fixture", "assert"],
    "CONFIG":     ["config", "settings", "env", "dotenv", "yaml", "toml", "json", "ini"],
    "NETWORK":    ["http", "socket", "tcp", "udp", "dns", "proxy", "nginx", "ssl"],
    "SYSTEM":     ["os", "sys", "process", "subprocess", "shell", "bash", "rm", "mv", "cp"],
}


def _classify_text(text: str) -> List[str]:
    """Return scope categories present in text."""
    text_lower = text.lower()
    return [cat for cat, kws in SCOPE_TAXONOMY.items() if any(kw in text_lower for kw in kws)]


@dataclass
class DriftEvent:
    action: str
    alignment_score: int   # 0-100: how well it aligns to objective
    drift_delta: int       # how much this changed the cumulative drift score
    categories: List[str]
    flagged: bool
    timestamp: float = field(default_factory=time.time)


class AgentContextDriftDetector:
    """
    Monitors a single agent session for objective drift.
    Register the original goal, then check each action.
    """

    def __init__(
        self,
        objective: str,
        drift_threshold: int = 40,
        window_size: int = 10,
    ):
        self.objective = objective
        self.drift_threshold = drift_threshold
        self.window_size = window_size

        # Pre-compute objective categories
        self.objective_categories = set(_classify_text(objective))
        self.objective_keywords = set(re.findall(r'\b\w{4,}\b', objective.lower()))

        self.events: List[DriftEvent] = []
        self.session_id = hashlib.sha256(
            f"{objective}:{time.time()}".encode()
        ).hexdigest()[:12]

    def score_action(self, action: str, file_path: str = "") -> int:
        """
        Score how well an action aligns with the stated objective (0-100).
        100 = perfectly aligned, 0 = completely out of scope.
        """
        combined = f"{action} {file_path}".lower()
        action_categories = set(_classify_text(combined))
        action_keywords = set(re.findall(r'\b\w{4,}\b', combined))

        score = 0

        # Category overlap
        cat_overlap = len(self.objective_categories & action_categories)
        cat_total = len(self.objective_categories | action_categories) or 1
        score += int((cat_overlap / cat_total) * 50)

        # Keyword overlap
        kw_overlap = len(self.objective_keywords & action_keywords)
        kw_factor = min(kw_overlap / max(len(self.objective_keywords), 1), 1.0)
        score += int(kw_factor * 40)

        # Bonus if action explicitly mentions a keyword from objective
        if any(kw in combined for kw in list(self.objective_keywords)[:5]):
            score += 10

        return min(score, 100)

    def check_action(self, action: str, file_path: str = "") -> Dict[str, Any]:
        """
        Evaluate a single agent action against the objective.
        Returns verdict and drift analysis.
        """
        score = self.score_action(action, file_path)
        categories = _classify_text(f"{action} {file_path}")
        flagged = score < self.drift_threshold

        # Rolling window drift average
        recent = self.events[-self.window_size:]
        if recent:
            avg_recent = sum(e.alignment_score for e in recent) / len(recent)
            drift_delta = int(avg_recent - score)
        else:
            drift_delta = 0

        event = DriftEvent(
            action=action,
            alignment_score=score,
            drift_delta=drift_delta,
            categories=categories,
            flagged=flagged,
        )
        self.events.append(event)

        # Generate plain explanation
        if flagged:
            explanation = (
                f"Action '{action[:60]}' scored {score}/100 against objective "
                f"'{self.objective[:60]}'. Expected scope: {list(self.objective_categories)}. "
                f"Actual scope detected: {categories}. This action appears outside the stated goal."
            )
        else:
            explanation = (
                f"Action aligned ({score}/100). Scope matches objective: "
                f"{list(self.objective_categories & set(categories)) or 'general match'}."
            )

        return {
            "action": action,
            "file_path": file_path,
            "alignment_score": score,
            "drift_threshold": self.drift_threshold,
            "flagged": flagged,
            "verdict": "DRIFT_DETECTED" if flagged else "ON_TRACK",
            "categories_detected": categories,
            "objective_categories": list(self.objective_categories),
            "drift_delta": drift_delta,
            "explanation": explanation,
            "session_id": self.session_id,
            "event_count": len(self.events),
        }

    def get_session_report(self) -> Dict[str, Any]:
        """Full session summary with drift timeline."""
        if not self.events:
            return {"session_id": self.session_id, "events": 0, "status": "NO_DATA"}

        avg_score = sum(e.alignment_score for e in self.events) / len(self.events)
        flagged_count = sum(1 for e in self.events if e.flagged)
        drift_pct = round(flagged_count / len(self.events) * 100, 1)

        # Identify worst drift point
        worst = min(self.events, key=lambda e: e.alignment_score)

        return {
            "session_id": self.session_id,
            "objective": self.objective,
            "total_actions": len(self.events),
            "avg_alignment_score": round(avg_score, 1),
            "flagged_actions": flagged_count,
            "drift_rate_pct": drift_pct,
            "status": "CRITICAL_DRIFT" if drift_pct > 50 else "MODERATE_DRIFT" if drift_pct > 20 else "ON_TRACK",
            "worst_drift_action": worst.action,
            "worst_score": worst.alignment_score,
            "timeline": [
                {"action": e.action[:40], "score": e.alignment_score, "flagged": e.flagged}
                for e in self.events[-10:]
            ],
        }
