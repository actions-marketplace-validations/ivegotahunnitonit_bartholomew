"""
Bartholomew Automated Git Hook Immunity Installer (BTP v5.4.25)
===============================================================
Installs zero-dependency, high-speed (<50ms) pre-commit and pre-push
invariants into .git/hooks to prevent unshielded agent code injections,
destructive commands, and credential leaks from entering git version control.
"""

import os
import sys
import stat
from pathlib import Path
from typing import Dict, Any, List, Optional

PRE_COMMIT_SCRIPT = """#!/bin/sh
# Bartholomew Keystone Pre-Commit Hook (BTP v6.4)
# Fail-closed execution gate: blocks commits if checks fail or if security checkers are missing/erroring.

# 1. Execute preserved chained pre-commit hook if present
PRE_BTP_HOOK="$(dirname "$0")/pre-commit.pre-btp"
if [ -f "$PRE_BTP_HOOK" ]; then
    if [ -x "$PRE_BTP_HOOK" ]; then
        "$PRE_BTP_HOOK" "$@" || exit $?
    else
        sh "$PRE_BTP_HOOK" "$@" || exit $?
    fi
fi

# 2. Execute Bartholomew security verification (fail-closed)
if command -v btp-guard >/dev/null 2>&1; then
    btp-guard check --staged || {
        echo "[!] Bartholomew Guard (FAIL-CLOSED): Commit blocked due to security policy violations or checker error." >&2
        echo "    Run 'btp-guard check --explain' or inspect .btp/policy.yaml" >&2
        exit 1
    }
elif command -v python3 >/dev/null 2>&1; then
    python3 -m btp_guard.cli check --staged || {
        echo "[!] Bartholomew Guard (FAIL-CLOSED): Commit blocked due to security policy violations or checker error." >&2
        echo "    Run 'python3 -m btp_guard.cli check --explain' or inspect .btp/policy.yaml" >&2
        exit 1
    }
elif command -v python >/dev/null 2>&1; then
    python -m btp_guard.cli check --staged || {
        echo "[!] Bartholomew Guard (FAIL-CLOSED): Commit blocked due to security policy violations or checker error." >&2
        echo "    Run 'python -m btp_guard.cli check --explain' or inspect .btp/policy.yaml" >&2
        exit 1
    }
else
    echo "[!] Bartholomew Guard (FAIL-CLOSED): Neither 'btp-guard' nor Python is available in PATH to verify commit safety." >&2
    echo "    Commit aborted to protect repository integrity. Install btp-guard or Python to proceed." >&2
    exit 1
fi

exit 0
"""

PRE_PUSH_SCRIPT = """#!/bin/sh
# Bartholomew Trust Protocol (BTP v5.4.25) Git Pre-Push Security Hook
# Enforces enterprise SOC 2 and OWASP LLM readiness prior to remote push.

echo "[*] [BTP] Running pre-push enterprise compliance check..."

python -m btp_guard.cli audit . > .btp_push_temp.txt 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "[!] [BTP VETO] Codebase security audit failed prior to push."
    cat .btp_push_temp.txt
    rm -f .btp_push_temp.txt
    exit 1
fi

rm -f .btp_push_temp.txt
echo "[+] [BTP] Pre-push verification PASSED. Push allowed."
exit 0
"""


def install_git_hooks(repo_root: str = ".", pre_commit: bool = True, pre_push: bool = True) -> Dict[str, Any]:
    """
    Installs executable Git hooks in .git/hooks directory.
    """
    root = Path(repo_root).resolve()
    git_dir = root / ".git"

    if not git_dir.exists():
        return {
            "status": "ERROR",
            "message": f"Target path '{root}' is not a valid git repository (.git missing)."
        }

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    installed = []

    if pre_commit:
        pc_path = hooks_dir / "pre-commit"
        if pc_path.exists():
            try:
                with open(pc_path, "r", encoding="utf-8", errors="ignore") as f:
                    old_c = f.read()
                if "Bartholomew" not in old_c:
                    backup_hook = hooks_dir / "pre-commit.pre-btp"
                    with open(backup_hook, "w", encoding="utf-8", newline="\n") as f:
                        f.write(old_c)
                    try:
                        backup_hook.chmod(backup_hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    except Exception:
                        pass
            except Exception:
                pass
        with open(pc_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(PRE_COMMIT_SCRIPT)
        # Set executable permissions (0o755)
        try:
            pc_path.chmod(pc_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception:
            pass
        installed.append(str(pc_path))

    if pre_push:
        pp_path = hooks_dir / "pre-push"
        with open(pp_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(PRE_PUSH_SCRIPT)
        try:
            pp_path.chmod(pp_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception:
            pass
        installed.append(str(pp_path))

    return {
        "status": "SUCCESS",
        "hooks_installed": installed,
        "message": f"Successfully activated Bartholomew Git security hooks ({len(installed)} active)."
    }


def uninstall_git_hooks(repo_root: str = ".") -> Dict[str, Any]:
    """
    Removes Bartholomew hooks from .git/hooks directory.
    """
    root = Path(repo_root).resolve()
    hooks_dir = root / ".git" / "hooks"
    removed = []

    for hook_name in ["pre-commit", "pre-push"]:
        hook_path = hooks_dir / hook_name
        if hook_path.exists():
            try:
                with open(hook_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if "Bartholomew" in content:
                    hook_path.unlink()
                    removed.append(hook_name)
                    if hook_name == "pre-commit":
                        backup_path = hooks_dir / "pre-commit.pre-btp"
                        if backup_path.exists():
                            try:
                                backup_path.rename(hook_path)
                            except Exception:
                                pass
            except Exception:
                pass

    return {
        "status": "SUCCESS",
        "hooks_removed": removed,
        "message": f"Uninstalled Bartholomew hooks: {', '.join(removed) if removed else 'none found'}"
    }
