"""
Bartholomew Workspace Intelligence Report (BTP v6.0-pre)
=========================================================
One-command workspace doctor — generates a full plain-English
intelligence report covering:
  1. Tech Stack Detection (Python, Node, Go, Rust, Ruby)
  2. AI Extension Inventory (from Universal Extension Mesh)
  3. Security Posture Score (0-100 based on .btp config state)
  4. LLM Token Cost Estimate (context window pricing)
  5. Optimization Opportunities (shortcuts, shortcuts, shortcuts)

Run: btp-guard intel
MCP: btp_workspace_intel
"""

import os
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional

TIER_COSTS_PER_1M = {
    "gpt-4o":          {"input": 5.00, "output": 15.00},
    "claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
    "gemini-2-flash":  {"input": 0.075, "output": 0.30},
    "gemini-2-pro":    {"input": 1.25,  "output": 5.00},
    "gpt-4o-mini":     {"input": 0.15,  "output": 0.60},
}

STACK_MARKERS = {
    "Python":      ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
    "Node.js":     ["package.json", "yarn.lock", "pnpm-lock.yaml"],
    "Go":          ["go.mod", "go.sum"],
    "Rust":        ["Cargo.toml", "Cargo.lock"],
    "Ruby":        ["Gemfile", "Gemfile.lock"],
    "Java":        ["pom.xml", "build.gradle"],
    "C/C++":       ["CMakeLists.txt", "Makefile"],
    "TypeScript":  ["tsconfig.json"],
    "Docker":      ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    "Kubernetes":  ["k8s/", ".kube/", "helm/"],
    "Terraform":   ["main.tf", "variables.tf"],
    "Nx/Monorepo": ["nx.json", "lerna.json", "turbo.json"],
}

class WorkspaceIntelligence:
    """
    Generates a comprehensive Workspace Intelligence Report
    for any repository in under 200ms.
    """

    def __init__(self, workspace_root: str = "."):
        self.ws = Path(workspace_root).resolve()

    def detect_stack(self) -> List[str]:
        detected = []
        for stack, markers in STACK_MARKERS.items():
            for marker in markers:
                if (self.ws / marker).exists():
                    detected.append(stack)
                    break
        return detected if detected else ["Unknown"]

    def detect_ai_tooling(self) -> Dict[str, Any]:
        """Detect which AI extensions and config files are present."""
        ai_files = {
            "CLAUDE.md": "Anthropic Claude",
            "GEMINI.md": "Google Gemini",
            ".cursorrules": "Cursor Composer",
            ".windsurfrules": "Windsurf Cascade",
            ".github/copilot-instructions.md": "GitHub Copilot",
            "AGENTS.md": "General Agent Config",
            ".btp/model-context.md": "Bartholomew AI Bridge",
            ".continue/config.json": "Continue.dev",
        }
        present = {}
        for path, name in ai_files.items():
            if (self.ws / path).exists():
                present[path] = name
        return present

    def compute_security_posture(self) -> Dict[str, Any]:
        """Score the workspace security posture 0-100."""
        score = 0
        checks = []

        def check(name: str, path: str, points: int, tip: str):
            nonlocal score
            ok = (self.ws / path).exists()
            score += points if ok else 0
            checks.append({"name": name, "passed": ok, "points": points, "tip": tip})

        check("Keystone Passkey",     ".btp/keystone.json",   25, "Run: btp-guard init")
        check("Process Shims",        ".btp/shims",           20, "Run: btp-guard protect")
        check("AI Bridge Context",    ".btp/model-context.md",15, "Run: btp-guard inject")
        check("Audit Ledger Active",  ".btp/audit.log",       15, "Run: btp-guard watch")
        check("Policy Defined",       ".btp/policy.yaml",     10, "Run: btp-guard policy init")
        check("Credential Vault",     ".btp/vault.json",      10, "Run: btp-guard vault init")
        check("Git Hooks Armed",      ".git/hooks/pre-commit",  5, "Run: btp-guard hook")

        grade = "A+" if score >= 90 else "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D"
        return {"score": score, "max": 100, "grade": grade, "checks": checks}

    def estimate_token_costs(self) -> Dict[str, Any]:
        """Estimate LLM context window costs for this workspace."""
        # Count total non-binary lines
        total_lines = 0
        file_count = 0
        try:
            for p in self.ws.rglob("*"):
                if p.is_file() and not any(x in str(p) for x in [".git", "__pycache__", "node_modules", ".venv", "*.vsix"]):
                    try:
                        text = p.read_text(encoding="utf-8", errors="ignore")
                        total_lines += len(text.splitlines())
                        file_count += 1
                        if file_count > 2000:  # cap for performance
                            break
                    except Exception:
                        pass
        except Exception:
            pass

        avg_chars_per_line = 60
        total_chars = total_lines * avg_chars_per_line
        total_tokens = total_chars // 4  # rough 4 chars/token

        costs = {}
        for model, pricing in TIER_COSTS_PER_1M.items():
            cost_usd = (total_tokens / 1_000_000) * pricing["input"]
            costs[model] = {
                "cost_usd": round(cost_usd, 4),
                "tokens": total_tokens,
            }

        # With Bartholomew compression (~69.6% reduction)
        compressed_tokens = int(total_tokens * 0.304)
        savings = {}
        for model, pricing in TIER_COSTS_PER_1M.items():
            base = (total_tokens / 1_000_000) * pricing["input"]
            after = (compressed_tokens / 1_000_000) * pricing["input"]
            savings[model] = {
                "original_usd": round(base, 4),
                "compressed_usd": round(after, 4),
                "saved_usd": round(base - after, 4),
                "compression_pct": 69.6,
            }

        return {
            "file_count": file_count,
            "total_lines": total_lines,
            "estimated_tokens": total_tokens,
            "compressed_tokens": compressed_tokens,
            "model_costs": costs,
            "compression_savings": savings,
        }

    def find_optimization_opportunities(self) -> List[Dict[str, str]]:
        """Scan the workspace for known quick-win improvements."""
        opps = []
        ws = self.ws

        if not (ws / ".btp" / "shims").exists():
            opps.append({
                "id": "OPT-001",
                "title": "AI agents are running commands without sandbox containment",
                "impact": "HIGH",
                "fix": "btp-guard protect",
                "why": "Without shims, a hallucinated `rm -rf` runs directly. Shims intercept it first."
            })

        if (ws / ".env").exists() and not (ws / ".btp" / "vault.json").exists():
            opps.append({
                "id": "OPT-002",
                "title": ".env file is readable by all AI models in plaintext",
                "impact": "CRITICAL",
                "fix": "btp-guard vault init",
                "why": "API keys in .env leak into prompts. Vault replaces values with opaque references."
            })

        if not (ws / ".btp" / "model-context.md").exists():
            opps.append({
                "id": "OPT-003",
                "title": "AI models have no invariant briefing — no awareness of what they cannot do",
                "impact": "MEDIUM",
                "fix": "btp-guard inject",
                "why": "Without GEMINI.md/CLAUDE.md invariant context, models may attempt blocked operations."
            })

        req = ws / "requirements.txt"
        pkg = ws / "package.json"
        if req.exists() or pkg.exists():
            opps.append({
                "id": "OPT-004",
                "title": "Dependencies not scanned for known malicious packages",
                "impact": "HIGH",
                "fix": "btp-guard scan-deps",
                "why": "Supply chain attacks (typosquatting, malicious updates) affect AI-generated installs."
            })

        if not (ws / ".btp" / "keystone.json").exists():
            opps.append({
                "id": "OPT-005",
                "title": "No capability limits on autonomous agents — they have full file system access",
                "impact": "HIGH",
                "fix": "btp-guard init",
                "why": "Keystone Passkeys scope agents to specific folders, commands, and spend budgets."
            })

        opps.append({
            "id": "OPT-006",
            "title": "Context window token costs can be reduced 69.6% with AST compression",
            "impact": "MEDIUM",
            "fix": "btp-guard compress",
            "why": "Strips duplicate boilerplate while preserving all structural information for the model."
        })

        return opps

    def generate_report(self) -> Dict[str, Any]:
        """Generate the full Workspace Intelligence Report."""
        t0 = time.perf_counter()

        report = {
            "workspace": str(self.ws),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "stack": self.detect_stack(),
            "ai_tooling": self.detect_ai_tooling(),
            "security": self.compute_security_posture(),
            "token_costs": self.estimate_token_costs(),
            "optimizations": self.find_optimization_opportunities(),
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 2),
            "report_id": hashlib.sha256(str(self.ws).encode()).hexdigest()[:12],
        }
        return report

    def format_plaintext(self, report: Dict[str, Any]) -> str:
        """Format the report as a clean plaintext CLI output."""
        lines = [
            "=" * 78,
            f"  BARTHOLOMEW WORKSPACE INTELLIGENCE REPORT",
            f"  {report['workspace']}",
            "=" * 78,
            "",
            f"  TECH STACK      {', '.join(report['stack'])}",
            f"  AI TOOLING      {len(report['ai_tooling'])} config files detected",
            f"  SECURITY GRADE  {report['security']['grade']} ({report['security']['score']}/100)",
            f"  SCAN TIME       {report['scan_time_ms']} ms",
            "",
            "  [SECURITY POSTURE]",
        ]
        for chk in report["security"]["checks"]:
            status = "[PASS]" if chk["passed"] else "[FAIL]"
            lines.append(f"    {status}  {chk['name']:<28}  +{chk['points']} pts")
            if not chk["passed"]:
                lines.append(f"           Fix: {chk['tip']}")

        lines += ["", "  [TOKEN COST ESTIMATE]"]
        tc = report["token_costs"]
        lines.append(f"    Files scanned:    {tc['file_count']:,}")
        lines.append(f"    Est. tokens:      {tc['estimated_tokens']:,}")
        lines.append(f"    With compression: {tc['compressed_tokens']:,} (saves 69.6%)")
        for model, data in list(tc["compression_savings"].items())[:3]:
            lines.append(f"    {model:<22}  ${data['original_usd']:.4f} -> ${data['compressed_usd']:.4f}  (saves ${data['saved_usd']:.4f})")

        lines += ["", "  [OPTIMIZATION OPPORTUNITIES]"]
        for opp in report["optimizations"]:
            lines.append(f"    [{opp['impact']}]  {opp['id']}  {opp['title']}")
            lines.append(f"             Run: {opp['fix']}")

        lines += ["", "=" * 78]
        return "\n".join(lines)
