"""
Bartholomew Extension Marketplace Publisher
===========================================
Publishes Bartholomew Guard and Keystone Passkey to:
1. Microsoft Visual Studio Code Marketplace
2. Open-VSX Registry (Cursor, Windsurf, VSCodium)

Usage:
  python scripts/publish_extensions.py --vsce-pat <TOKEN>
  python scripts/publish_extensions.py --ovsx-pat <TOKEN>
  python scripts/publish_extensions.py --vsce-pat <TOKEN> --ovsx-pat <TOKEN>
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def get_pkg_version(pkg_dir: Path) -> str:
    pkg_json = pkg_dir / "package.json"
    if pkg_json.exists():
        with open(pkg_json, "r", encoding="utf-8") as f:
            return json.load(f).get("version", "5.4.23")
    return "5.4.23"


def get_extensions():
    guard_dir = BASE_DIR / "packages" / "vscode-extension"
    keystone_dir = BASE_DIR / "packages" / "bartholomew-keystone"
    vault_dir = BASE_DIR / "packages" / "bartholomew-vault"
    trinity_dir = BASE_DIR / "packages" / "bartholomew-trinity"
    guard_ver = get_pkg_version(guard_dir)
    keystone_ver = get_pkg_version(keystone_dir)
    vault_ver = get_pkg_version(vault_dir)
    trinity_ver = get_pkg_version(trinity_dir)
    return [
        {
            "id": "bartholomew-guard-vscode",
            "dir": guard_dir,
            "vsix": guard_dir / f"bartholomew-guard-vscode-{guard_ver}.vsix",
        },
        {
            "id": "bartholomew-keystone",
            "dir": keystone_dir,
            "vsix": keystone_dir / f"bartholomew-keystone-{keystone_ver}.vsix",
        },
        {
            "id": "bartholomew-vault",
            "dir": vault_dir,
            "vsix": vault_dir / f"bartholomew-vault-{vault_ver}.vsix",
        },
        {
            "id": "bartholomew-trinity",
            "dir": trinity_dir,
            "vsix": trinity_dir / f"bartholomew-trinity-{trinity_ver}.vsix",
        },
    ]


def ensure_packaged():
    print("[*] Ensuring latest VSIX packages are built...")
    pkg_script = BASE_DIR / "scripts" / "package_all_vsix.py"
    res = subprocess.run(
        [sys.executable, str(pkg_script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if res.returncode != 0:
        output = (res.stdout or "") + (res.stderr or "")
        raise SystemExit(f"Packaging failed while preparing extension artifacts:\n{output}")
    print("[+] VSIX packages verified.")


def _run_publish_command(cmd):
    if sys.platform == "win32" and cmd and cmd[0] == "npx":
        cmd = ["npx.cmd"] + cmd[1:]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0:
        details = (res.stdout or "") + (res.stderr or "")
        raise RuntimeError(details.strip() or f"Command failed with exit code {res.returncode}: {' '.join(cmd)}")
    return res


def publish_vsce(pat: str, target_id: Optional[str] = None):
    print("\n" + "=" * 60)
    print("  PUBLISHING TO MICROSOFT VS CODE MARKETPLACE")
    print("=" * 60)

    for ext in get_extensions():
        if target_id and ext["id"] != target_id:
            continue
        vsix_path = ext["vsix"]
        if not vsix_path.exists():
            raise FileNotFoundError(f"Missing VSIX artifact for {ext['id']}: {vsix_path}")

        print(f"[*] Uploading {ext['id']} ({vsix_path.name}) to VS Code Marketplace...")
        cmd = ["npx", "-y", "@vscode/vsce", "publish", "--packagePath", str(vsix_path), "--pat", pat]
        try:
            _run_publish_command(cmd)
            print(f"[OK] Successfully published {ext['id']} to VS Code Marketplace!")
        except Exception as exc:
            if "already exists" in str(exc).lower() or "version" in str(exc).lower():
                print(f"[!] Note: {ext['id']} version might already exist on Marketplace: {exc}")
            else:
                raise SystemExit(f"VSCE publish failed for {ext['id']}: {exc}") from exc


def publish_ovsx(pat: str, target_id: Optional[str] = None):
    print("\n" + "=" * 60)
    print("  PUBLISHING TO OPEN-VSX REGISTRY (CURSOR / WINDSURF)")
    print("=" * 60)

    for ext in get_extensions():
        if target_id and ext["id"] != target_id:
            continue
        vsix_path = ext["vsix"]
        if not vsix_path.exists():
            raise FileNotFoundError(f"Missing VSIX artifact for {ext['id']}: {vsix_path}")

        print(f"[*] Uploading {ext['id']} ({vsix_path.name}) to Open-VSX...")
        cmd = ["npx", "-y", "ovsx", "publish", str(vsix_path), "--pat", pat]
        try:
            _run_publish_command(cmd)
            print(f"[OK] Successfully published {ext['id']} to Open-VSX!")
        except Exception as exc:
            if "already exists" in str(exc).lower() or "version" in str(exc).lower() or "already published" in str(exc).lower():
                print(f"[!] Note: {ext['id']} is already published on Open-VSX.")
            else:
                raise SystemExit(f"Open-VSX publish failed for {ext['id']}: {exc}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bartholomew Extension Marketplace Publisher")
    parser.add_argument("--vsce-pat", default=os.getenv("VSCE_PAT"), help="Microsoft VS Code Marketplace Personal Access Token")
    parser.add_argument("--ovsx-pat", default=os.getenv("OVSX_PAT"), help="Open-VSX Personal Access Token")
    parser.add_argument("--extension", default=None, help="Specific extension ID to publish (e.g. bartholomew-vault)")
    parser.add_argument("--package-only", action="store_true", help="Only build packages without uploading")
    args = parser.parse_args(argv)

    ensure_packaged()

    if args.package_only:
        print("[+] Packages are ready in packages/ directory.")
        return 0

    if not args.vsce_pat and not args.ovsx_pat:
        raise SystemExit("Error: provide at least one PAT via CLI or environment variables.")

    if args.vsce_pat:
        publish_vsce(args.vsce_pat, target_id=args.extension)

    if args.ovsx_pat:
        publish_ovsx(args.ovsx_pat, target_id=args.extension)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
