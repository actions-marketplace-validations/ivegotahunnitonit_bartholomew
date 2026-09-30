"""
Tests for BTP v6 Pillars 6, 7, 8:
  6. Action Replay & Forensics Ledger (10 tests)
  7. In-context Secret Masker v2      (10 tests)
  8. Multi-workspace Fleet View        (6 tests)
"""

import re
import json
import pytest


#  ACTION REPLAY & FORENSICS LEDGER 

def test_replay_records_action():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    rec = ledger.record("bash", "git status", verdict="ALLOW")
    assert rec.tool == "bash"
    assert rec.action == "git status"
    assert rec.verdict == "ALLOW"
    assert rec.index == 0


def test_replay_chain_valid_after_records():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    ledger.record("bash", "ls -la", verdict="ALLOW")
    ledger.record("bash", "rm -rf /", verdict="BLOCK")
    ledger.record("auto_heal", "rm -rf /safe_dir", verdict="HEAL")
    result = ledger.verify_chain()
    assert result["valid"] is True
    assert result["entries"] == 3


def test_replay_receipt_is_hex():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    rec = ledger.record("mcp", "btp_evaluate_intent", verdict="ALLOW")
    assert re.fullmatch(r"[0-9a-f]{64}", rec.receipt)


def test_replay_chain_links_correctly():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    r1 = ledger.record("tool", "action_1", verdict="ALLOW")
    r2 = ledger.record("tool", "action_2", verdict="ALLOW")
    assert r2.prev_receipt == r1.receipt


def test_replay_empty_chain_valid():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    result = ledger.verify_chain()
    assert result["valid"] is True
    assert result["entries"] == 0


def test_replay_yields_actions_in_order():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    for i in range(5):
        ledger.record("tool", f"action_{i}", verdict="ALLOW")
    replayed = list(ledger.replay())
    assert [r.action for r in replayed] == [f"action_{i}" for i in range(5)]


def test_replay_partial_range():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    for i in range(10):
        ledger.record("tool", f"act_{i}", verdict="ALLOW")
    replayed = list(ledger.replay(start=2, end=5))
    assert len(replayed) == 3
    assert replayed[0].action == "act_2"


def test_replay_export_jsonl():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    ledger.record("bash", "git log", verdict="ALLOW", result_summary="12 commits")
    jsonl = ledger.export_jsonl()
    lines = jsonl.strip().split("\n")
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert obj["tool"] == "bash"
    assert obj["verdict"] == "ALLOW"


def test_replay_incident_report_contains_blocked():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    ledger.record("bash", "safe_command", verdict="ALLOW")
    ledger.record("bash", "rm -rf production/", verdict="BLOCK", result_summary="BTP-003")
    report = ledger.generate_incident_report()
    assert "BLOCKED" in report
    assert "rm -rf production/" in report


def test_replay_summary_structure():
    from src.action_replay_ledger import ActionReplayLedger
    ledger = ActionReplayLedger()
    ledger.record("tool", "act", verdict="ALLOW")
    ledger.record("tool", "bad", verdict="BLOCK")
    summary = ledger.get_summary()
    assert summary["total_records"] == 2
    assert summary["blocked"] == 1
    assert summary["chain_valid"] is True


#  IN-CONTEXT SECRET MASKER V2 

def test_masker_replaces_openai_key():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    text = "My key is sk-AbCdEf1234567890ABCDEFG and you should use it"
    masked, findings = sm.mask(text)
    assert "sk-AbCdEf1234567890ABCDEFG" not in masked
    assert "BTP-VAULT-REF-" in masked
    assert len(findings) >= 1


def test_masker_replaces_anthropic_key():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    # Anthropic key — reliable long-form match
    text = "auth: sk-ant-api03-abcdefghij1234567890ABCDEFGHIJ1234567890"
    masked, findings = sm.mask(text)
    assert "sk-ant-api03" not in masked
    assert "BTP-VAULT-REF-" in masked
    assert any(f["type"] in ("ANTHROPIC_KEY", "OPENAI_KEY") for f in findings)


def test_masker_replaces_aws_key():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    masked, findings = sm.mask(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in masked


def test_masker_allows_clean_content():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    text = "def hello_world():\n    print('Hello!')"
    masked, findings = sm.mask(text)
    assert masked == text
    assert len(findings) == 0


def test_masker_unmask_restores_original():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    secret = "sk-AbCdEf1234567890ABCDE12345"
    original = f"api_key = {secret}"
    masked, _ = sm.mask(original)
    restored = sm.unmask(masked)
    assert secret in restored


def test_masker_deterministic_ref():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    t1 = "key: sk-AbCdEf1234567890ABCDE12345 and more"
    t2 = "key: sk-AbCdEf1234567890ABCDE12345 elsewhere"
    m1, _ = sm.mask(t1)
    m2, _ = sm.mask(t2)
    ref1 = re.search(r"BTP-VAULT-REF-[0-9a-f]+", m1).group()
    ref2 = re.search(r"BTP-VAULT-REF-[0-9a-f]+", m2).group()
    assert ref1 == ref2


def test_masker_audit_secrets():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    sm.mask("key: sk-AbCdEf1234567890ABCDE12345")
    audit = sm.audit_secrets()
    assert len(audit) >= 1
    assert all("ref" in a and "type" in a and "original_length" in a for a in audit)


def test_masker_stats():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    sm.mask("key: sk-AbCdEf1234567890ABCDE12345")
    stats = sm.get_stats()
    assert stats["total_masked"] >= 1
    assert "secret_types" in stats
    assert "vault_size" in stats


def test_masker_replaces_jwt():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    masked, findings = sm.mask(jwt)
    assert jwt not in masked
    assert any(f["type"] == "JWT" for f in findings)


def test_masker_vault_size_grows():
    from src.secret_masker_v2 import SecretMaskerV2
    sm = SecretMaskerV2()
    # Two clearly distinct secrets — different values produce different vault entries
    sm.mask("First key: sk-AbCdEf1234567890ABCDE12345XXXX")
    sm.mask("Second key: sk-ZyXwVu9876543210FEDCBA54321YYYY")
    assert sm.get_vault_size() >= 2


#  MULTI-WORKSPACE FLEET VIEW 

def test_fleet_single_workspace(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.3.0", encoding="utf-8")
    from src.fleet_view import FleetView
    fleet = FleetView(workspace_roots=[str(tmp_path)])
    report = fleet.generate_fleet_report()
    assert report["workspace_count"] == 1
    assert report["scanned"] == 1
    assert "fleet_avg_score" in report


def test_fleet_grade_is_valid(tmp_path):
    from src.fleet_view import FleetView
    fleet = FleetView(workspace_roots=[str(tmp_path)])
    report = fleet.generate_fleet_report()
    assert report["fleet_grade"] in ("A+", "A", "B", "C", "D", "F")


def test_fleet_report_has_required_keys(tmp_path):
    from src.fleet_view import FleetView
    fleet = FleetView(workspace_roots=[str(tmp_path)])
    report = fleet.generate_fleet_report()
    for key in ("fleet_id", "workspace_count", "fleet_avg_score", "fleet_grade",
                "worst_workspace", "best_workspace", "workspaces", "scan_time_ms"):
        assert key in report, f"Missing: {key}"


def test_fleet_worst_equals_best_single(tmp_path):
    from src.fleet_view import FleetView
    fleet = FleetView(workspace_roots=[str(tmp_path)])
    report = fleet.generate_fleet_report()
    assert report["worst_workspace"]["name"] == report["best_workspace"]["name"]


def test_fleet_plaintext_format(tmp_path):
    from src.fleet_view import FleetView
    fleet = FleetView(workspace_roots=[str(tmp_path)])
    report = fleet.generate_fleet_report()
    text = fleet.format_plaintext(report)
    assert "BARTHOLOMEW FLEET VIEW" in text
    assert "Workspaces Scanned" in text


def test_fleet_fleet_id_is_hex(tmp_path):
    from src.fleet_view import FleetView
    fleet = FleetView(workspace_roots=[str(tmp_path)])
    report = fleet.generate_fleet_report()
    assert re.fullmatch(r"[0-9a-f]+", report["fleet_id"])
