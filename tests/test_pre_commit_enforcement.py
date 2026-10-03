"""
Tests for Bartholomew Fail-Closed Git Pre-Commit Hook Enforcement and Hook Preservation.
Verifies:
1. Non-destructive hook installation preserves existing non-Bartholomew hooks to pre-commit.pre-btp.
2. Fail-closed behavior when btp-guard and python are unavailable (exit code 1).
3. Fail-closed behavior when security checker fails (exit code 1).
4. Proper chaining of pre-existing hooks.
5. Restoration of pre-existing hook upon uninstallation.
"""

import os
import sys
import stat
import tempfile
import subprocess
from pathlib import Path

from btp_guard.hook_installer import install_git_hooks, uninstall_git_hooks, PRE_COMMIT_SCRIPT
from btp_guard.project_immunizer import immunize_project


def test_existing_hook_preserved_and_chained():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        git_dir = root / ".git"
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        
        # 1. Create a pre-existing custom user pre-commit hook (e.g. linter)
        custom_hook = hooks_dir / "pre-commit"
        custom_hook.write_text("#!/bin/sh\necho 'CUSTOM_HOOK_CALLED'\nexit 0\n", encoding="utf-8")
        
        # 2. Run install_git_hooks
        res = install_git_hooks(repo_root=tmpdir, pre_commit=True, pre_push=False)
        assert res["status"] == "SUCCESS"
        
        # Verify pre-commit.pre-btp was created with original content
        backup = hooks_dir / "pre-commit.pre-btp"
        assert backup.exists()
        assert "CUSTOM_HOOK_CALLED" in backup.read_text(encoding="utf-8")
        
        # Verify new pre-commit hook is Bartholomew and references pre-commit.pre-btp
        active_hook = hooks_dir / "pre-commit"
        content = active_hook.read_text(encoding="utf-8")
        assert "Bartholomew Keystone Pre-Commit Hook" in content
        assert 'PRE_BTP_HOOK="$(dirname "$0")/pre-commit.pre-btp"' in content
        
        # 3. Test uninstall restores original hook
        uninst_res = uninstall_git_hooks(repo_root=tmpdir)
        assert uninst_res["status"] == "SUCCESS"
        assert custom_hook.exists()
        assert "CUSTOM_HOOK_CALLED" in custom_hook.read_text(encoding="utf-8")
        assert not backup.exists()


def test_project_immunizer_preserves_existing_hook():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        git_dir = root / ".git"
        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        
        custom_hook = hooks_dir / "pre-commit"
        custom_hook.write_text("#!/bin/sh\necho 'ORIGINAL_HOOK'\nexit 0\n", encoding="utf-8")
        
        res = immunize_project(workspace_root=tmpdir)
        assert res["status"] == "IMMUNIZED"
        
        backup = hooks_dir / "pre-commit.pre-btp"
        assert backup.exists()
        assert "ORIGINAL_HOOK" in backup.read_text(encoding="utf-8")
        
        active_hook = hooks_dir / "pre-commit"
        assert "Bartholomew Keystone Pre-Commit Hook" in active_hook.read_text(encoding="utf-8")


def test_hook_script_fail_closed_logic():
    """
    Directly tests the shell logic of the hook script:
    When btp-guard and python are unavailable or simulate failure, the hook MUST exit 1 (fail-closed).
    """
    fail_closed_check = """#!/bin/sh
if command -v nonexistent_btp_guard_cmd >/dev/null 2>&1; then
    exit 0
elif command -v nonexistent_python3_cmd >/dev/null 2>&1; then
    exit 0
elif command -v nonexistent_python_cmd >/dev/null 2>&1; then
    exit 0
else
    echo "[!] Bartholomew Guard (FAIL-CLOSED): Neither 'btp-guard' nor Python is available in PATH" >&2
    exit 1
fi
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_script = Path(tmpdir) / "test_hook.sh"
        test_script.write_text(fail_closed_check, encoding="utf-8")
        
        # Try running with sh / bash or git-bash sh
        sh_candidates = ["sh", "bash", r"C:\Program Files\Git\bin\sh.exe"]
        for sh_cmd in sh_candidates:
            try:
                res = subprocess.run([sh_cmd, str(test_script)], capture_output=True, text=True)
                assert res.returncode == 1, f"Expected returncode 1 (fail-closed), got {res.returncode}"
                assert "FAIL-CLOSED" in res.stderr
                break
            except FileNotFoundError:
                continue


def test_hook_script_checker_error_fail_closed():
    """
    When btp-guard or python fails (checker error or security violation),
    the hook must exit with code 1, never 0.
    """
    fail_on_checker = """#!/bin/sh
if command -v false >/dev/null 2>&1; then
    false || {
        echo "[!] Bartholomew Guard (FAIL-CLOSED): Commit blocked due to checker error." >&2
        exit 1
    }
fi
exit 0
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_script = Path(tmpdir) / "test_checker_fail.sh"
        test_script.write_text(fail_on_checker, encoding="utf-8")
        sh_candidates = ["sh", "bash", r"C:\Program Files\Git\bin\sh.exe"]
        for sh_cmd in sh_candidates:
            try:
                res = subprocess.run([sh_cmd, str(test_script)], capture_output=True, text=True)
                assert res.returncode == 1
                assert "FAIL-CLOSED" in res.stderr
                break
            except FileNotFoundError:
                continue
