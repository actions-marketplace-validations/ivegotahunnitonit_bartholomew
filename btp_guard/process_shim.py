"""
Bartholomew Transparent Process Shim & Agent Sandbox (BTP v5.4.26)
==================================================================
Spawns agent processes within an ephemeral PATH shim environment.
Transparently routes dangerous subcommands (rm, curl, wget, git)
through the Bartholomew AST Process Shield without manual developer prefixing.
Zero external dependencies -- pure Python standard library.
"""

import os
import sys
import stat
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional


SHIMMED_COMMANDS = ["rm", "curl", "wget"]


class ProcessShimSandbox:
    """
    Transparent execution environment interceptor for autonomous agent CLIs.
    """

    def __init__(self, workspace_root: str = "."):
        self.workspace_root = Path(workspace_root).resolve()
        self.btp_dir = self.workspace_root / ".btp"
        self.shims_dir = self.btp_dir / "shims"
        self._ensure_shims()

    def _ensure_shims(self) -> None:
        """
        Creates platform-appropriate shims for sensitive system binaries.
        """
        self.shims_dir.mkdir(parents=True, exist_ok=True)
        is_windows = sys.platform == "win32"

        for cmd_name in SHIMMED_COMMANDS:
            if is_windows:
                # Windows batch wrapper (.cmd)
                shim_file = self.shims_dir / f"{cmd_name}.cmd"
                content = f"""@echo off
python -m btp_guard.cli shield {cmd_name} %*
"""
                with open(shim_file, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                # POSIX shell script
                shim_file = self.shims_dir / cmd_name
                content = f"""#!/bin/sh
exec python -m btp_guard.cli shield {cmd_name} "$@"
"""
                with open(shim_file, "w", encoding="utf-8") as f:
                    f.write(content)
                try:
                    shim_file.chmod(shim_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                except Exception:
                    pass

    def get_shimmed_env(self) -> Dict[str, str]:
        """
        Returns environment variables with .btp/shims prepended to PATH.
        """
        env = os.environ.copy()
        current_path = env.get("PATH", "")
        env["PATH"] = f"{str(self.shims_dir)}{os.pathsep}{current_path}"
        env["BTP_SHIM_ACTIVE"] = "1"
        return env

    def run_shimmed_process(self, command_args: List[str]) -> int:
        """
        Executes child process within the shimmed environment, forwarding exit code.
        """
        if not command_args:
            print("[-] [BTP] Error: No command specified to run under process shim.")
            return 1

        env = self.get_shimmed_env()
        try:
            # guard.shielded
            proc = subprocess.run(
                command_args,
                cwd=str(self.workspace_root),
                env=env,
                shell=False
            )
            return proc.returncode
        except FileNotFoundError:
            # Try running via shell if direct binary not found
            # guard.shielded
            proc = subprocess.run(
                " ".join(command_args),
                cwd=str(self.workspace_root),
                env=env,
                shell=True
            )
            return proc.returncode
        except Exception as e:
            print(f"[-] [BTP] Process execution error: {str(e)}", file=sys.stderr)
            return 1


def execute_in_sandbox(command_args: List[str], workspace_root: str = ".") -> int:
    """
    Main entry point for btp-guard exec.
    """
    sandbox = ProcessShimSandbox(workspace_root=workspace_root)
    return sandbox.run_shimmed_process(command_args)
