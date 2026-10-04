import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_SCRIPT = REPO_ROOT / "scripts" / "package_all_vsix.py"
PUBLISH_SCRIPT = REPO_ROOT / "scripts" / "publish_extensions.py"


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_package_all_vsix_requires_built_dist_bundle(tmp_path):
    pkg_dir = tmp_path / "demo-extension"
    pkg_dir.mkdir()
    (pkg_dir / "package.json").write_text(
        json.dumps({"version": "9.9.9", "publisher": "demo"}),
        encoding="utf-8",
    )

    package_module = load_module(PACKAGE_SCRIPT)
    with pytest.raises(FileNotFoundError, match=r"dist[\\/]extension\.js"):
        package_module.ensure_package_ready(pkg_dir)


def test_publish_extensions_exits_when_no_tokens_are_configured():
    publish_module = load_module(PUBLISH_SCRIPT)

    with pytest.raises(SystemExit, match="at least one PAT"):
        publish_module.main([])
