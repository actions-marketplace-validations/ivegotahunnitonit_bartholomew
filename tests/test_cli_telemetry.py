import os
import sys
import json
import argparse
from unittest.mock import patch

from src.btp_guard.cli import cmd_telemetry


def test_cli_telemetry_url_only(capsys, tmp_path):
    with patch("os.getcwd", return_value=str(tmp_path)):
        args = argparse.Namespace(url_only=True, reset_key=False)
        cmd_telemetry(args)
        
        captured = capsys.readouterr().out
        assert "BARTHOLOMEW PRIVATE SENTINEL TELEMETRY VAULT" in captured
        assert "Operator Node ID :" in captured
        assert "Isolation Scope  : STRICT_SINGLE_TENANT" in captured
        assert "https://bartholomew.info/telemetry.html?node=" in captured
        assert "token=" in captured

        node_file = tmp_path / ".btp" / "telemetry_node.json"
        assert node_file.exists()
        with open(node_file, "r") as f:
            data = json.load(f)
            assert "node_id" in data
            assert "token" in data
