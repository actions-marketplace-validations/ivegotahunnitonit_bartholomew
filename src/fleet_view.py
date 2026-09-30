"""
Bartholomew Multi-workspace Fleet View (BTP v6.0-pre)
=====================================================
Aggregates WorkspaceIntelligence across multiple repositories in one
consolidated fleet-level report. Identifies the weakest workspaces,
highest-priority fixes, and fleet-wide security grade.

Use cases:
  - Engineering manager auditing all team repos at once
  - CI/CD gate that fails if any workspace drops below grade C
  - Weekly fleet health digest

Run: btp-guard fleet [--roots /path/a /path/b ...]
MCP: btp_fleet_view
"""

import os
import time
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from src.workspace_intel import WorkspaceIntelligence
except ImportError:
    from btp_guard.workspace_intel import WorkspaceIntelligence


GRADE_ORDER = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}


class FleetView:
    """
    Aggregates workspace intelligence across multiple repos.
    """

    def __init__(self, workspace_roots: Optional[List[str]] = None):
        if workspace_roots:
            self.roots = [Path(r).resolve() for r in workspace_roots]
        else:
            # Auto-discover: scan the parent of cwd for sibling repos
            cwd = Path.cwd()
            parent = cwd.parent
            self.roots = [
                p for p in parent.iterdir()
                if p.is_dir() and (p / ".git").exists() and p != cwd
            ]
            self.roots.insert(0, cwd)  # always include current workspace

    def generate_fleet_report(self) -> Dict[str, Any]:
        """Generate aggregated fleet report across all workspaces."""
        t0 = time.perf_counter()
        workspace_reports = []

        for root in self.roots[:20]:  # cap at 20 repos for performance
            try:
                intel = WorkspaceIntelligence(str(root))
                report = intel.generate_report()
                workspace_reports.append({
                    "workspace": str(root),
                    "name": root.name,
                    "stack": report["stack"],
                    "security_score": report["security"]["score"],
                    "security_grade": report["security"]["grade"],
                    "ai_tooling_count": len(report["ai_tooling"]),
                    "optimization_count": len(report["optimizations"]),
                    "critical_opts": [
                        o for o in report["optimizations"]
                        if o["impact"] in ("HIGH", "CRITICAL")
                    ],
                    "token_cost_gpt4o": report["token_costs"]["model_costs"].get(
                        "gpt-4o", {}
                    ).get("cost_usd", 0),
                })
            except Exception as e:
                workspace_reports.append({
                    "workspace": str(root),
                    "name": root.name,
                    "error": str(e),
                    "security_score": 0,
                    "security_grade": "F",
                })

        # Fleet-level aggregation
        scores = [w["security_score"] for w in workspace_reports if "error" not in w]
        fleet_avg = round(sum(scores) / len(scores), 1) if scores else 0
        worst = min(workspace_reports, key=lambda w: w.get("security_score", 0))
        best  = max(workspace_reports, key=lambda w: w.get("security_score", 0))

        grade_dist = {}
        for w in workspace_reports:
            g = w.get("security_grade", "F")
            grade_dist[g] = grade_dist.get(g, 0) + 1

        # Fleet grade is based on lowest individual grade
        fleet_grade = min(
            [w.get("security_grade", "F") for w in workspace_reports],
            key=lambda g: GRADE_ORDER.get(g, 0)
        ) if workspace_reports else "F"

        # All critical optimizations across fleet
        all_crits = []
        for w in workspace_reports:
            for opt in w.get("critical_opts", []):
                all_crits.append({
                    "workspace": w["name"],
                    "opt_id": opt["id"],
                    "title": opt["title"],
                    "fix": opt["fix"],
                    "impact": opt["impact"],
                })

        dt_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "fleet_id": hashlib.sha256(
                ",".join(str(r) for r in self.roots).encode()
            ).hexdigest()[:12],
            "workspace_count": len(self.roots),
            "scanned": len(workspace_reports),
            "fleet_avg_score": fleet_avg,
            "fleet_grade": fleet_grade,
            "grade_distribution": grade_dist,
            "worst_workspace": {"name": worst.get("name"), "score": worst.get("security_score", 0), "grade": worst.get("security_grade", "F")},
            "best_workspace":  {"name": best.get("name"),  "score": best.get("security_score", 0),  "grade": best.get("security_grade", "A+")},
            "workspaces": workspace_reports,
            "critical_fleet_opts": all_crits[:20],
            "scan_time_ms": dt_ms,
        }

    def format_plaintext(self, report: Dict[str, Any]) -> str:
        lines = [
            "=" * 78,
            "  BARTHOLOMEW FLEET VIEW — MULTI-WORKSPACE INTELLIGENCE",
            "=" * 78,
            f"  Workspaces Scanned:  {report['scanned']}",
            f"  Fleet Average Score: {report['fleet_avg_score']}/100",
            f"  Fleet Grade:         {report['fleet_grade']}",
            f"  Scan Time:           {report['scan_time_ms']} ms",
            "",
            "  [WORKSPACE BREAKDOWN]",
        ]
        for w in sorted(report["workspaces"], key=lambda x: x.get("security_score", 0)):
            if "error" in w:
                lines.append(f"    [ERR] {w['name']:<30} Error: {w['error'][:40]}")
            else:
                lines.append(
                    f"    [{w['security_grade']:>2}]  {w['name']:<30} "
                    f"{w['security_score']:>3}/100  "
                    f"Stack: {', '.join(w['stack'][:2])}"
                )

        if report["critical_fleet_opts"]:
            lines += ["", "  [CRITICAL FLEET-WIDE FIXES]"]
            for opt in report["critical_fleet_opts"][:8]:
                lines.append(f"    [{opt['impact']}]  {opt['workspace']}: {opt['title'][:50]}")
                lines.append(f"           Run: {opt['fix']}")

        lines.append("=" * 78)
        return "\n".join(lines)
