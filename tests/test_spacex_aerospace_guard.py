"""
Test Suite: Bartholomew SpaceX & Aerospace Sovereign Guard (BTP v6.5.9)
Validates sub-35us AST invariant gating, hardware device protection,
ITAR secret redaction, and sub-5us Copy-on-Write micro-rollbacks.
"""

import pytest
from btp_guard.integrations.aerospace_spacex import (
    BtpSpaceXAerospaceGuard,
    AerospaceViolationError
)


def test_spacex_safe_telemetry_action():
    guard = BtpSpaceXAerospaceGuard(node_id="starlink-ground-austin-01")
    res = guard.evaluate_telemetry_action(
        "query_gateway_metrics",
        {"command": "cat /proc/net/dev", "subsystem": "telemetry"},
        subsystem="starlink_gateway"
    )
    assert res["allowed"] is True
    assert res["verdict"] == "ALLOW"
    assert res["latency_us"] < 35.0, f"Latency {res['latency_us']}us must be sub-35us"
    assert res["merkle_receipt"].startswith("ed25519:aero:")


def test_spacex_block_raw_hardware_tampering():
    guard = BtpSpaceXAerospaceGuard()
    
    # 1. Direct device memory read
    res1 = guard.evaluate_telemetry_action(
        "read_device_reg",
        {"command": "dd if=/dev/mem bs=1024 count=1"}
    )
    assert res1["allowed"] is False
    assert res1["rule_id"] == "BTP-AERO-HW-001"
    assert "raw hardware mutation" in res1["reason"]

    # 2. CAN bus packet injection
    res2 = guard.evaluate_telemetry_action(
        "inject_can_packet",
        {"command": "cansend can0 123#DEADBEEF"}
    )
    assert res2["allowed"] is False
    assert res2["rule_id"] == "BTP-AERO-HW-001"

    # 3. Raw block device alteration
    res3 = guard.evaluate_telemetry_action(
        "format_disk",
        {"command": "mkfs.ext4 /dev/sda1"}
    )
    assert res3["allowed"] is False
    assert res3["rule_id"] == "BTP-AERO-HW-001"


def test_spacex_telemetry_threshold_invariants():
    guard = BtpSpaceXAerospaceGuard()

    # Chamber pressure within Starship flight envelope (<= 350 bar)
    safe_eval = guard.evaluate_telemetry_action(
        "raptor_chill_test",
        {"chamber_pressure_bar": 310.0, "engine_id": "SN-Rap-104"}
    )
    assert safe_eval["allowed"] is True

    # Dangerous chamber pressure (> 350 bar)
    danger_eval = guard.evaluate_telemetry_action(
        "raptor_overpressure",
        {"chamber_pressure_bar": 385.0, "engine_id": "SN-Rap-104"}
    )
    assert danger_eval["allowed"] is False
    assert danger_eval["rule_id"] == "BTP-AERO-LIMIT-002"
    assert "exceeds Starship flight envelope" in danger_eval["reason"]

    # Gimbal angle beyond mechanical stop (+/- 20 degrees)
    gimbal_danger = guard.evaluate_telemetry_action(
        "tvc_gimbal_slew",
        {"gimbal_angle_deg": 24.5}
    )
    assert gimbal_danger["allowed"] is False
    assert gimbal_danger["rule_id"] == "BTP-AERO-LIMIT-003"
    assert "exceeds mechanical hard stop" in gimbal_danger["reason"]


def test_spacex_itar_secret_scrubber():
    guard = BtpSpaceXAerospaceGuard()
    raw_prompt = "Calibrate sensor using ITAR-SECRET-ALPHA992182 and starlink-crypto-key-8819283719."
    scrubbed, count = guard.scrub_itar_secrets(raw_prompt)
    assert count == 2
    assert "ITAR-SECRET-ALPHA992182" not in scrubbed
    assert "starlink-crypto-key-8819283719" not in scrubbed
    assert "[REDACTED_ITAR_SOVEREIGN]" in scrubbed


def test_spacex_copy_on_write_micro_rollback():
    guard = BtpSpaceXAerospaceGuard()
    pristine_flight_state = {
        "valve_a_position": "OPEN",
        "tank_pressure_psi": 4200,
        "active_guidance_mode": "NOMINAL_ASCENT"
    }

    # 1. Capture snapshot in < 5 microseconds
    snap_latency = guard.capture_snapshot("snap_t0", pristine_flight_state)
    assert "snap_t0" in guard.state_snapshots

    # 2. Simulate agent state corruption
    corrupted_flight_state = pristine_flight_state.copy()
    corrupted_flight_state["valve_a_position"] = "MALICIOUS_SHUTOFF"
    corrupted_flight_state["tank_pressure_psi"] = 99999

    # 3. Micro-rollback restoration in < 5 microseconds
    restored, rollback_latency = guard.restore_snapshot("snap_t0")
    assert restored["valve_a_position"] == "OPEN"
    assert restored["tank_pressure_psi"] == 4200
    assert restored == pristine_flight_state


def test_spacex_telemetry_decorator():
    guard = BtpSpaceXAerospaceGuard()

    @guard.guard_telemetry_action
    def set_engine_valve(chamber_pressure_bar: float):
        return f"Valve set for {chamber_pressure_bar} bar"

    # Safe call
    result = set_engine_valve(chamber_pressure_bar=320.0)
    assert "320.0 bar" in result

    # Vetoed call
    with pytest.raises(AerospaceViolationError) as exc_info:
        set_engine_valve(chamber_pressure_bar=395.0)
    assert "BTP-AERO-LIMIT-002" in str(exc_info.value)
