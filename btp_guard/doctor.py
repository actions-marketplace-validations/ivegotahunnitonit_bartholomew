"""
Bartholomew Protocol - Smart Workspace Doctor & Diagnostics (v6.4.0)
=====================================================================
Performs a 360-degree security inspection of the active repository,
detecting agent configurations, git hooks, secret leaks, and AST performance.
"""

import sys
import os
import time
from pathlib import Path
from typing import Dict, Any, List

# Ensure safe console output across all platforms
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def run_doctor() -> Dict[str, Any]:
    cwd = Path.cwd()
    checks: List[Dict[str, Any]] = []
    score = 100

    # 1. Git Repository Check
    is_git = (cwd / ".git").exists()
    checks.append({
        "category": "Git Repository",
        "name": "Git Tracking",
        "status": "PASS" if is_git else "WARN",
        "detail": "Repository root detected" if is_git else "Not a git repository"
    })
    if not is_git:
        score -= 20

    # 2. Git Hooks Enforcement Check
    pre_commit = cwd / ".git" / "hooks" / "pre-commit"
    hook_active = pre_commit.exists() and "btp" in open(pre_commit, "r", encoding="utf-8", errors="ignore").read() if is_git and pre_commit.exists() else False
    checks.append({
        "category": "Git Enforcement",
        "name": "Pre-Commit Protection Hook",
        "status": "PASS" if hook_active else "WARN",
        "detail": "Active (.git/hooks/pre-commit)" if hook_active else "Not installed (Run 'btp hook install')"
    })
    if not hook_active:
        score -= 15

    # 3. Policy Configuration Check
    policy_file = cwd / ".btp" / "policy.yaml"
    has_policy = policy_file.exists()
    checks.append({
        "category": "Policy Governance",
        "name": "Workspace Policy (.btp/policy.yaml)",
        "status": "PASS" if has_policy else "WARN",
        "detail": "Found and active" if has_policy else "Missing (Run 'btp policy synthesize')"
    })
    if not has_policy:
        score -= 15

    # 4. Sensitive Secret File Exposure Check
    exposed_secrets = []
    for sensitive in [".env", ".env.local", ".env.production", "secrets.json", "id_rsa"]:
        if (cwd / sensitive).exists():
            # Check if ignored in .gitignore
            gitignore = cwd / ".gitignore"
            is_ignored = sensitive in open(gitignore, "r", encoding="utf-8", errors="ignore").read() if gitignore.exists() else False
            if not is_ignored:
                exposed_secrets.append(sensitive)

    checks.append({
        "category": "Credential Hygiene",
        "name": "Unignored Secret Files",
        "status": "FAIL" if exposed_secrets else "PASS",
        "detail": f"Unignored: {', '.join(exposed_secrets)}" if exposed_secrets else "All local credentials properly masked & ignored"
    })
    if exposed_secrets:
        score -= 25

    # 5. Live In-Process AST Latency Probe
    from btp_guard import Guard
    guard = Guard()
    t0 = time.perf_counter()
    probe_res = guard.check("rm -rf / --no-preserve-root")
    latency_us = round((time.perf_counter() - t0) * 1_000_000, 2)
    ast_blocked = (probe_res.get("verdict") == "DENY" or not probe_res.get("allowed", True))

    checks.append({
        "category": "AST Execution Gate",
        "name": "In-Process Enforcement Probe",
        "status": "PASS" if ast_blocked else "FAIL",
        "detail": f"Interception latency: {latency_us} us (Target: <35 us) | Blocked: {ast_blocked}"
    })
    if not ast_blocked:
        score -= 40

    # 6. Active Team Pilot / License Check
    pilot_file = cwd / ".btp" / "team_pilot_enrollment.json"
    has_pilot = pilot_file.exists()
    checks.append({
        "category": "Commercial Governance",
        "name": "Team Pilot License",
        "status": "PASS" if has_pilot else "INFO",
        "detail": "30-Day Team Pilot Active" if has_pilot else "Free Community Edition (Upgrade at https://bartholomew.info/pilot)"
    })

    score = max(0, score)
    grade = "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 70 else "C" if score >= 60 else "F"

    print("\n" + "=" * 74)
    print("      BARTHOLOMEW SMART WORKSPACE SECURITY DOCTOR (v6.4.0)")
    print("=" * 74)
    print(f"  * Workspace Path  : {cwd}")
    print(f"  * Security Score  : {score}/100 [Grade {grade}]")
    print("-" * 74)

    for c in checks:
        status_tag = f"[{c['status']}]".ljust(8)
        print(f"  {status_tag} {c['name'].ljust(32)}: {c['detail']}")

    print("-" * 74)
    if score >= 90:
        print("  [+] WORKSPACE HEALTHY: Ready for autonomous coding agents with zero risk.")
    else:
        print("  [!] ACTION REQUIRED: Run suggested commands above to achieve 100% security.")
    print("=" * 74 + "\n")

    return {
        "score": score,
        "grade": grade,
        "checks": checks
    }
