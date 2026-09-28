"""
Bartholomew Agent Cost & Security Forensics Profiler (BTP v5.4.25)
==================================================================
Profiles autonomous AI agent workspace sessions in real-time.
Quantifies token compression savings, tracks financial ROI in USD,
and audits neutralized security threats across developer agent workflows.
Zero external dependencies -- pure Python standard library.
"""

import os
import sys
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    from src.context_compressor import compress_workspace_context
except ImportError:
    try:
        from btp_guard.context_compressor import compress_workspace_context
    except ImportError:
        compress_workspace_context = None

try:
    from src.sentinel_watcher import run_sentinel
except ImportError:
    try:
        from btp_guard.sentinel_watcher import run_sentinel
    except ImportError:
        run_sentinel = None


class AgentSessionProfiler:
    """
    Forensics and ROI profiler for autonomous coding agents.
    """

    INPUT_TOKEN_RATE_PER_MILLION = 3.00   # Typical Claude 3.7 / GPT-4o input cost
    OUTPUT_TOKEN_RATE_PER_MILLION = 15.00

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = Path(workspace_root).resolve()
        self.btp_dir = self.workspace_root / ".btp"
        self.sessions_dir = self.btp_dir / "sessions"
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        self.btp_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def profile_workspace_session(self, agent_name: str = "Autonomous Agent") -> Dict[str, Any]:
        """
        Gathers complete context economics and security telemetry for the current workspace.
        """
        t0 = time.perf_counter()

        # 1. Context Compression Economics
        compression_data = {}
        if compress_workspace_context:
            compression_data = compress_workspace_context(str(self.workspace_root))

        orig_tokens = compression_data.get("original_tokens_estimate", 0)
        comp_tokens = compression_data.get("compressed_tokens_estimate", 0)
        tokens_conserved = compression_data.get("tokens_conserved", 0)
        files_indexed = compression_data.get("files_indexed", 0)

        # Dollar savings calculation per 10-turn interaction loop
        turns_multiplier = 10
        total_tokens_saved_session = tokens_conserved * turns_multiplier
        usd_saved_per_turn = round((tokens_conserved / 1_000_000) * self.INPUT_TOKEN_RATE_PER_MILLION, 4)
        usd_saved_session = round((total_tokens_saved_session / 1_000_000) * self.INPUT_TOKEN_RATE_PER_MILLION, 4)

        # 2. Security Forensics
        sentinel_data = {}
        if run_sentinel:
            sentinel_data = run_sentinel(root_dir=str(self.workspace_root), auto_heal=False, once=True)

        files_audited = sentinel_data.get("files_scanned", 0)
        violations_found = sentinel_data.get("violations_found", 0)

        duration_ms = round((time.perf_counter() - t0) * 1000, 2)
        session_id = f"btp_sess_{int(time.time())}_{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"

        profile = {
            "session_id": session_id,
            "agent_name": agent_name,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_ms": duration_ms,
            "token_economics": {
                "files_indexed": files_indexed,
                "original_context_tokens": orig_tokens,
                "compressed_skeleton_tokens": comp_tokens,
                "tokens_conserved_per_turn": tokens_conserved,
                "compression_ratio": compression_data.get("compression_ratio_pct", "0%"),
                "estimated_usd_saved_per_turn": f"${usd_saved_per_turn:.4f} USD",
                "estimated_usd_saved_10_turn_session": f"${usd_saved_session:.4f} USD",
                "estimated_annual_developer_savings": f"${(usd_saved_session * 250):.2f} USD"
            },
            "security_forensics": {
                "files_audited": files_audited,
                "active_violations": violations_found,
                "compliance_score": "100/100 (A+)" if violations_found == 0 else f"{max(100 - violations_found * 10, 0)}/100 (Attention Needed)",
                "audit_ledger": ".btp/sentinel_audit.jsonl"
            }
        }

        # Persist session report
        out_path = self.sessions_dir / f"{session_id}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(profile, indent=2))

        return profile


def print_profile_report(profile: Dict[str, Any]) -> None:
    """
    Renders an ASCII executive forensics dashboard.
    """
    econ = profile["token_economics"]
    sec = profile["security_forensics"]

    print("\n" + "=" * 76)
    print("      BARTHOLOMEW AGENT COST & SECURITY FORENSICS (BTP v5.4.25)")
    print("=" * 76)
    print(f"  Session Identifier       : {profile['session_id']}")
    print(f"  Target Agent / Workspace : {profile['agent_name']}")
    print(f"  Profile Execution Time   : {profile['duration_ms']} ms")
    print("-" * 76)
    print("  TOKEN & FINANCIAL ECONOMICS (65-85% AST SKELETON PRUNING):")
    print(f"    - Workspace Source Files  : {econ['files_indexed']}")
    print(f"    - Full Context Burden     : {econ['original_context_tokens']:,} tokens")
    print(f"    - Compressed AST Skeleton : {econ['compressed_skeleton_tokens']:,} tokens")
    print(f"    - Tokens Saved / Turn     : {econ['tokens_conserved_per_turn']:,} tokens ({econ['compression_ratio']})")
    print(f"    - Direct Savings / Turn   : {econ['estimated_usd_saved_per_turn']}")
    print(f"    - Savings per Session     : {econ['estimated_usd_saved_10_turn_session']} (10 context re-reads)")
    print(f"    - Projected Annual Value  : {econ['estimated_annual_developer_savings']} per developer seat")
    print("-" * 76)
    print("  SECURITY POSTURE & INVARIANT HEALTH:")
    print(f"    - Files Audited           : {sec['files_audited']}")
    print(f"    - Active Violations       : {sec['active_violations']}")
    print(f"    - Workspace Safety Rating : {sec['compliance_score']}")
    print("=" * 76)
    print(f"  Detailed session forensics saved: .btp/sessions/{profile['session_id']}.json\n")
