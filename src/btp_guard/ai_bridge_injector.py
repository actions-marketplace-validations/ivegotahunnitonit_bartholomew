"""
Bartholomew Autonomous AI Bridge Context Injector (BTP v5.4.26)
===============================================================
Synthesizes and non-destructively injects AST invariant rules,
auto-healing error recovery, and semantic context compression pointers
into .cursorrules, CLAUDE.md, .windsurfrules, AGENTS.md, and GEMINI.md.
Zero external dependencies -- pure Python standard library.
"""

import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

INVARIANT_DIRECTIVE_BLOCK = """
<!-- BARTHOLOMEW TRUST PROTOCOL (BTP v5.4.26) INVARIANT DIRECTIVE -->
## Autonomous Security & Token Optimization Invariants
This repository is guarded by the Bartholomew Trust Protocol (BTP). All AI agents must follow these operational invariants:

1. Process Execution Gating:
   - Never execute raw unshielded shell calls (e.g. `os.system("...")`, unshielded `subprocess.Popen`).
   - Prefix any required subprocess calls with `# guard.shielded` or route through `btp-guard shield <command>`.
   - Never invoke recursive root deletions (`rm -rf /`), destructive SQL drops (`DROP TABLE`, `TRUNCATE`), or remote shell curl pipes.

2. Syntax Repair & Self-Healing:
   - If an error or veto occurs, run `btp-guard heal "<payload>"` or call MCP tool `btp_auto_heal` to safely neutralize syntax.

3. Context Token Conservation:
   - For repository structure, read `.btp/cache/compressed_repo.json` (69.6% prompt token conservation) rather than re-reading raw implementation bodies.
<!-- END BARTHOLOMEW INVARIANT DIRECTIVE -->
"""

TARGET_CONFIGS = {
    "cursor": ".cursorrules",
    "claude": "CLAUDE.md",
    "windsurf": ".windsurfrules",
    "agents": "AGENTS.md",
    "gemini": ".gemini/GEMINI.md"
}


class AIBridgeInjector:
    """
    Automated conditioner for AI agent workspace context rules.
    """

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = Path(workspace_root).resolve()
        self.btp_dir = self.workspace_root / ".btp"
        self.backup_dir = self.btp_dir / "backups"
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        self.btp_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def inject_target(self, target_key: str) -> Dict[str, Any]:
        """
        Injects BTP invariants into a single agent rule file.
        """
        rel_path = TARGET_CONFIGS.get(target_key.lower())
        if not rel_path:
            return {"target": target_key, "status": "ERROR", "message": f"Unknown target: {target_key}"}

        target_file = self.workspace_root / rel_path
        target_file.parent.mkdir(parents=True, exist_ok=True)

        existing_content = ""
        if target_file.exists():
            try:
                with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                    existing_content = f.read()
            except Exception:
                pass

        if "BARTHOLOMEW TRUST PROTOCOL" in existing_content:
            return {
                "target": target_key,
                "file": rel_path,
                "status": "ALREADY_INJECTED",
                "message": f"Invariants already active in {rel_path}"
            }

        # Backup existing
        if existing_content:
            ts = time.strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"{target_file.name}_{ts}.bak"
            try:
                with open(backup_file, "w", encoding="utf-8") as bf:
                    bf.write(existing_content)
            except Exception:
                pass

        # Append non-destructively
        new_content = existing_content.rstrip() + "\n" + INVARIANT_DIRECTIVE_BLOCK.strip() + "\n"
        try:
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(new_content)
            return {
                "target": target_key,
                "file": rel_path,
                "status": "SUCCESS",
                "message": f"Injected Bartholomew invariants into {rel_path}"
            }
        except Exception as e:
            return {
                "target": target_key,
                "file": rel_path,
                "status": "ERROR",
                "message": str(e)
            }

    def inject_all(self) -> List[Dict[str, Any]]:
        """
        Injects across all supported agent configurations.
        """
        results = []
        for key in TARGET_CONFIGS:
            results.append(self.inject_target(key))
        return results


def run_bridge_injection(workspace_root: str = ".", target: str = "all") -> Dict[str, Any]:
    """
    Entry point for CLI bridge injection.
    """
    injector = AIBridgeInjector(workspace_root=workspace_root)
    if target.lower() in ("all", "all-targets"):
        results = injector.inject_all()
    else:
        results = [injector.inject_target(target)]

    return {
        "status": "COMPLETED",
        "results": results
    }
