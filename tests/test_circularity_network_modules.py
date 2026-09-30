"""
Test Suite: Autonomous Circularity Network Core Infrastructure (BTP v5.4.22)
=============================================================================
Validates:
  1. Sentinel Autonomous Guardian & Telemetry Tracking (src/sentinel.py).
  2. AST Auto-Healer & Invariant Repair Engine (src/auto_heal.py).
  3. Sovereign Agent Wallet & Micro-Settlement Escrow (src/agent_wallet.py).
  4. Autonomous Agent Directory & Tool Registry (src/agent_directory.py).
"""

import os
import json
import pytest
from src.sentinel import BartholomewSentinel
from src.auto_heal import ASTAutoHealer
from src.agent_wallet import AgentWallet, InsufficientFundsException
from src.agent_directory import AgentDirectory


class TestCircularityNetworkModules:
    """Verifies the complete circular agent economy and living sentinel."""

    def test_sentinel_guardian_metrics(self):
        sentinel = BartholomewSentinel(node_id="test_sentinel_node_99")
        
        # Record benign action
        sentinel.record_action(verdict="ALLOW", latency_us=18.4, rule_id="BTP-PASS-000")
        
        # Record threat action
        sentinel.record_action(
            verdict="DENY",
            latency_us=22.1,
            rule_id="BTP-AST-001",
            threat_type="DESTRUCTIVE_ROOT_WIPE",
            agent_id="test-rogue-bot",
            action_summary="rm -rf / --no-preserve-root"
        )
        
        metrics = sentinel.get_live_metrics()
        assert metrics["sentinel_status"] == "ONLINE_ACTIVE"
        assert metrics["node_id"] == "test_sentinel_node_99"
        assert metrics["total_evaluations"] >= 2
        assert metrics["total_blocked_threats"] >= 1
        assert len(metrics["recent_threats"]) >= 1
        assert metrics["recent_threats"][-1]["rule_id"] == "BTP-AST-001"

    def test_auto_healer_shell_and_sql(self):
        # 1. Shell root wipe repair
        healed, patched, reason = ASTAutoHealer.heal_shell_command("rm -rf / --no-preserve-root")
        assert healed is True
        assert "./tmp/btp_sandbox" in patched
        assert "Redirected dangerous" in reason  # message updated in auto_heal v6

        # 2. Path traversal containment
        healed_trav, patched_trav, _ = ASTAutoHealer.heal_shell_command("cat ../../../etc/passwd")
        assert healed_trav is True
        assert "../" not in patched_trav

        # 3. SQL unbounded DELETE repair
        healed_sql, patched_sql, _ = ASTAutoHealer.heal_sql_query("DELETE FROM customers;")
        assert healed_sql is True
        assert "WHERE id IS NULL" in patched_sql

        # 4. SQL stacked DDL pruning
        stacked = "SELECT * FROM orders; DROP TABLE audit_log CASCADE;"
        healed_stacked, patched_stacked, _ = ASTAutoHealer.heal_sql_query(stacked)
        assert healed_stacked is True
        assert "DROP TABLE" not in patched_stacked
        assert patched_stacked.startswith("SELECT * FROM orders;")

        # 5. Unified gateway
        res = ASTAutoHealer.heal_action("SHELL_EXEC", "rm -rf /")
        assert res["healed"] is True
        assert res["status"] == "HEALED_AND_PERMITTED"

    def test_agent_wallet_micro_settlement(self, tmp_path):
        wallet = AgentWallet(
            agent_id="test-trading-agent-01",
            initial_balance_usd=25.0,
            storage_dir=str(tmp_path)
        )
        
        # Test deposit
        dep = wallet.deposit(10.0, source="STRIPE_TEST")
        assert wallet.balance_usd == 35.0
        assert dep["new_balance_usd"] == 35.0

        # Test tool purchase with 2.5% fee
        # Price: $4.00 -> 2.5% fee is $0.10, net provider is $3.90
        receipt = wallet.pay_for_tool(
            tool_name="financial_signal_extractor",
            provider_agent_id="bloomberg-data-bot",
            price_usd=4.00
        )
        assert receipt["gross_amount_usd"] == 4.00
        assert receipt["protocol_fee_usd"] == 0.10
        assert receipt["provider_net_payout_usd"] == 3.90
        assert wallet.balance_usd == 31.0

        # Test warranty collateral lock
        wallet.lock_bond_collateral(bond_id="bond_abc_123", amount_usd=10.0)
        assert wallet.locked_collateral_usd == 10.0
        summary = wallet.get_summary()
        assert summary["spendable_balance_usd"] == 21.0

        # Attempt spend exceeding available balance
        with pytest.raises(InsufficientFundsException):
            wallet.pay_for_tool("expensive_supercomputer_run", "compute-bot", 25.0)

        # Release collateral
        wallet.release_bond_collateral(bond_id="bond_abc_123", amount_usd=10.0)
        assert wallet.locked_collateral_usd == 0.0
        assert wallet.get_summary()["spendable_balance_usd"] == 31.0

    def test_agent_directory_search_and_discovery(self, tmp_path):
        reg_file = str(tmp_path / "test_agents.json")
        dir_svc = AgentDirectory(storage_path=reg_file)

        # Register Agent A
        dir_svc.register_agent(
            agent_id="academic-researcher-01",
            name="Quantum Academic Bot",
            description="Deep academic paper retrieval and physics summarization",
            tools=[{"name": "arxiv_search", "description": "Fetches quantum physics papers"}],
            price_per_call_usd=0.02,
            initial_trust_score=98.5
        )

        # Register Agent B
        dir_svc.register_agent(
            agent_id="code-auditor-99",
            name="Rust & Go Code Auditor",
            description="High speed static analysis for microservices",
            tools=[{"name": "ast_lint", "description": "Static code analysis"}],
            price_per_call_usd=0.10,
            initial_trust_score=92.0
        )

        # Register Agent C (low trust score)
        dir_svc.register_agent(
            agent_id="unverified-scraper",
            name="Raw Web Scraper",
            description="Scrapes websites without rate limiting",
            tools=[{"name": "scrape_raw", "description": "Raw HTTP fetch"}],
            price_per_call_usd=0.01,
            initial_trust_score=65.0
        )

        # Search for physics / arxiv tool
        results = dir_svc.search_tools(query="physics", min_trust_score=80.0)
        assert len(results) == 1
        assert results[0]["agent_id"] == "academic-researcher-01"
        assert results[0]["trust_score"] == 98.5

        # Unverified agent should be filtered out by min_trust_score
        unverified_results = dir_svc.search_tools(query="scrape", min_trust_score=80.0)
        assert len(unverified_results) == 0

        # Stats check
        stats = dir_svc.get_directory_stats()
        assert stats["total_registered_agents"] == 3
        assert stats["total_tools_available"] == 3
