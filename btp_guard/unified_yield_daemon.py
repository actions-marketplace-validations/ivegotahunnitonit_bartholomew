"""
Bartholomew Unified Yield & Sentinel Node Daemon (BTP v6.0)
===========================================================
Autonomous background service combining:
  1. Subnet Consensus Validator (TAO / AWU emissions)
  2. DePIN Idle Compute Worker (verification yield credits)
  3. Model Inference Arbitrage (retail/wholesale spreads)
  4. Local Node Telemetry & Single-Tenant Attestation Ledger
"""

from __future__ import annotations

import os
import sys
import time
import json
import threading
from typing import Dict, Any, Optional

try:
    from src.subnet_validator import SubnetValidatorNode
    from src.depin_worker import DePinComputeWorker
    from src.model_arbitrage import ModelArbitrageEngine
except ImportError:
    from btp_guard.subnet_validator import SubnetValidatorNode
    from btp_guard.depin_worker import DePinComputeWorker
    from btp_guard.model_arbitrage import ModelArbitrageEngine


class UnifiedYieldDaemon:
    """
    Supervises background validator consensus, compute yield harvesting,
    and arbitrage routing in a unified low-overhead loop.
    """

    def __init__(self, workspace_root: str = ".", interval_seconds: float = 15.0):
        self.workspace_root = os.path.abspath(workspace_root)
        self.btp_dir = os.path.join(self.workspace_root, ".btp")
        os.makedirs(self.btp_dir, exist_ok=True)
        self.status_file = os.path.join(self.btp_dir, "node_daemon_status.json")
        self.interval_seconds = interval_seconds

        self.subnet = SubnetValidatorNode(self.workspace_root)
        self.depin = DePinComputeWorker(self.workspace_root)
        self.arbitrage = ModelArbitrageEngine(self.workspace_root)

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._start_time = 0.0
        self._cycle_count = 0

    def run_single_cycle(self) -> Dict[str, Any]:
        """Runs a discrete yield harvest & validation cycle."""
        self._cycle_count += 1
        t0 = time.perf_counter()

        # 1. Subnet validation challenge
        subnet_res = self.subnet.run_validation_cycle(3)
        subnet_stat = self.subnet.get_status()

        # 2. DePIN idle compute harvest
        depin_res = self.depin.execute_compute_batch(batch_size=100)
        depin_stat = self.depin.get_status()

        # 3. Model token arbitrage benchmark simulation
        arb_res = self.arbitrage.run_benchmark_simulation(count=2)
        arb_stat = self.arbitrage.get_summary()

        duration_ms = (time.perf_counter() - t0) * 1000

        snapshot = {
            "version": "6.0.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cycle": self._cycle_count,
            "cycle_duration_ms": round(duration_ms, 2),
            "status": "RUNNING_HEALTHY",
            "subnet": {
                "hotkey": subnet_stat["hotkey"],
                "consensus_score": subnet_stat["consensus_score"],
                "emissions_tao": subnet_stat["emission_balance_tao"],
                "awu_accumulated": subnet_stat["attested_work_units"]
            },
            "depin": {
                "worker_id": depin_stat["worker_id"],
                "cumulative_yield_usd": depin_stat.get("total_earned_usd", 0.0),
                "evals_per_sec": depin_res.get("throughput_evals_sec", 0)
            },
            "arbitrage": {
                "total_queries": arb_stat["total_queries"],
                "spread_captured_usd": arb_stat["net_spread_captured_usd"]
            }
        }

        with open(self.status_file, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)

        return snapshot

    def start_background(self):
        """Starts continuous daemon loop in background thread."""
        if self._running:
            return
        self._running = True
        self._start_time = time.time()

        def _loop():
            while self._running:
                try:
                    self.run_single_cycle()
                except Exception as e:
                    print(f"[!] Unified Daemon Cycle Warning: {e}", file=sys.stderr)
                time.sleep(self.interval_seconds)

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
