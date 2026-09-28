"""
Unit tests for Bartholomew Context Compressor and Sentinel Watcher (BTP v5.4.25).
"""

import os
import shutil
import tempfile
from pathlib import Path
from src.context_compressor import (
    compress_python_ast,
    compress_typescript_code,
    compress_workspace_context
)
from src.sentinel_watcher import SentinelWatcher, run_sentinel


def test_compress_python_ast():
    sample_code = '''
def calculate_metrics(data: list) -> dict:
    """Computes critical system metrics."""
    result = {}
    for item in data:
        result[item] = item * 2
    return result

class SecurityGuard:
    """Invariant enforcer."""
    def __init__(self, key: str):
        self.key = key
        self.validated = False

    def verify(self) -> bool:
        """Runs validation checks."""
        if len(self.key) > 5:
            return True
        return False
'''
    compressed, orig_tokens, comp_tokens = compress_python_ast(sample_code)
    assert "Computes critical system metrics." in compressed
    assert "Invariant enforcer." in compressed
    assert "class SecurityGuard" in compressed
    assert "def calculate_metrics" in compressed
    # Implementation loops should be pruned
    assert "result[item] = item * 2" not in compressed
    assert comp_tokens < orig_tokens


def test_compress_typescript_code():
    sample_ts = '''
export interface AuthToken {
    jwt: string;
    expiresAt: number;
}

export class KeyManager {
    private secret: string;
    constructor(secret: string) {
        this.secret = secret;
    }

    public sign(payload: string): string {
        const hash = doHeavyCalculation(payload);
        return hash;
    }
}
'''
    compressed, orig_tokens, comp_tokens = compress_typescript_code(sample_ts)
    assert "interface AuthToken" in compressed
    assert "jwt: string;" in compressed
    assert "class KeyManager" in compressed
    assert "doHeavyCalculation" not in compressed
    assert comp_tokens < orig_tokens


def test_compress_workspace_context():
    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "src"
        src_dir.mkdir()
        (src_dir / "service.py").write_text(
            "def run(data: list) -> int:\n"
            "    '''Service runner docstring'''\n"
            "    total = 0\n"
            "    for i in range(100):\n"
            "        total += i * 2\n"
            "    return total\n",
            encoding="utf-8"
        )
        (src_dir / "types.ts").write_text("export interface User { id: string; name: string; }\n", encoding="utf-8")

        summary = compress_workspace_context(root_path=tmpdir, target_dirs=["src"])
        assert summary["files_indexed"] == 2
        assert summary["tokens_conserved"] > 0
        assert (Path(tmpdir) / ".btp" / "cache" / "compressed_repo.json").exists()


def test_sentinel_watcher_detection_and_healing():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "dangerous_script.py"
        test_file.write_text("import os\nos.system('rm -rf /')\n", encoding="utf-8")

        # 1. Detection without auto-heal
        watcher = SentinelWatcher(root_dir=tmpdir, auto_heal=False)
        report = watcher.scan_once()
        assert report["files_scanned"] == 1
        assert report["violations_found"] == 1
        assert not report["findings"][0]["healed"]

        # 2. Detection with auto-heal
        watcher_healer = SentinelWatcher(root_dir=tmpdir, auto_heal=True)
        report2 = watcher_healer.scan_once()
        assert report2["files_scanned"] == 1
        assert report2["violations_found"] == 1
        assert report2["findings"][0]["healed"]

        # Check healed content
        healed_text = test_file.read_text(encoding="utf-8")
        assert "guard.shielded" in healed_text
        assert "btp_guard" in healed_text
        # Audit log written
        assert (Path(tmpdir) / ".btp" / "sentinel_audit.jsonl").exists()


def test_sentinel_watcher_secret_masking():
    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "prod_config.py"
        config_file.write_text("AWS_TOKEN = 'AKIAIOSFODNN7XABCD99'\n", encoding="utf-8")

        watcher = SentinelWatcher(root_dir=tmpdir, auto_heal=True)
        report = watcher.scan_once()
        assert report["violations_found"] == 1

        healed = config_file.read_text(encoding="utf-8")
        assert "BTP_GUARD_MASKED_CREDENTIAL" in healed
        assert "AKIAIOSFODNN7XABCD99" not in healed
