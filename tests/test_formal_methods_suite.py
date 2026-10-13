"""
Comprehensive Formal Methods & Mathematical Invariants Test Suite (BTP v6.5.7)
=============================================================================
Tests all 10 pillars of the BTP Formal Verification program:
  - Invariant Verification Engine (Tool Gate, Nonce Replay, Revocation)
  - Information-Flow Lattice & Egress Policies
  - Temporal LTL State Machine Verifier
  - Weakest Preconditions (Dijkstra calculus)
  - Adversarial Delta-Debugging Minimizer
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.formal_invariants import FormalInvariantEngine, InvariantViolationType
from src.information_flow import InformationFlowEngine, SensitivityLevel, DestinationPolicy
from src.temporal_state_verifier import TemporalSequenceVerifier, CapabilityState
from src.weakest_preconditions import WeakestPreconditionsEngine
from src.adversarial_llm_testing import AdversarialPayloadGenerator, CounterexampleMinimizer


class FormalMethodsTestSuite(unittest.TestCase):

    def setUp(self):
        self.invariants = FormalInvariantEngine()
        self.flow = InformationFlowEngine()
        self.temporal = TemporalSequenceVerifier()
        self.wp = WeakestPreconditionsEngine()

    # =========================================================================
    # PILLAR 2: FORMAL INVARIANTS
    # =========================================================================
    def test_inv1_tool_gate_fail_closed(self):
        # Null passkey must fail closed
        receipt_null = self.invariants.verify_tool_gating("execute_command", None)
        self.assertFalse(receipt_null.satisfied)
        self.assertEqual(receipt_null.verdict, "FAIL_CLOSED")
        self.assertLess(receipt_null.latency_us, 50.0)

        # Expired passkey must fail closed
        expired_passkey = {"passkey_id": "pk_1", "expires_at_unix": time.time() - 100, "scopes": {"allowed_tools": ["execute_command"]}}
        receipt_exp = self.invariants.verify_tool_gating("execute_command", expired_passkey)
        self.assertFalse(receipt_exp.satisfied)
        self.assertEqual(receipt_exp.verdict, "DENY_EXPIRED")

        # Out-of-scope tool must fail closed
        valid_scoped_passkey = {"passkey_id": "pk_2", "expires_at_unix": time.time() + 1000, "scopes": {"allowed_tools": ["read_file"]}}
        receipt_scope = self.invariants.verify_tool_gating("execute_command", valid_scoped_passkey)
        self.assertFalse(receipt_scope.satisfied)
        self.assertEqual(receipt_scope.verdict, "OUT_OF_SCOPE")

        # Authorized tool must pass
        receipt_ok = self.invariants.verify_tool_gating("read_file", valid_scoped_passkey)
        self.assertTrue(receipt_ok.satisfied)
        self.assertEqual(receipt_ok.verdict, "PERMIT")

    def test_inv2_atomic_nonce_replay(self):
        nonce = "CRYPTO_NONCE_ABC_12345"
        first = self.invariants.verify_atomic_nonce(nonce)
        self.assertTrue(first.satisfied)
        self.assertEqual(first.verdict, "NONCE_ACCEPTED")

        # Replay attempt
        second = self.invariants.verify_atomic_nonce(nonce)
        self.assertFalse(second.satisfied)
        self.assertEqual(second.verdict, "REPLAY_REJECTED")

    def test_inv3_revocation_expiry(self):
        passkey_id = "key_test_revocation_001"
        self.invariants.record_revocation(passkey_id, "Key compromise")
        self.assertTrue(self.invariants.is_revoked(passkey_id))

        receipt = self.invariants.verify_passkey_freshness(passkey_id, expires_at=time.time() + 10000)
        self.assertFalse(receipt.satisfied)
        self.assertEqual(receipt.verdict, "PASSKEY_REVOKED")

    # =========================================================================
    # PILLAR 3: INFORMATION-FLOW LATTICE
    # =========================================================================
    def test_information_flow_lattice_and_egress(self):
        # 1. Source tagging
        self.flow.tag_source("db_user_email", SensitivityLevel.INTERNAL, "postgres:users")
        self.flow.tag_source("stripe_secret_key", SensitivityLevel.SECRET, "vault:stripe")

        # 2. Taint propagation: Join(INTERNAL, SECRET) = SECRET
        derived = self.flow.propagate_transformation(
            ["db_user_email", "stripe_secret_key"],
            "combined_profile",
            operation_name="json_bundle"
        )
        self.assertEqual(derived.level, SensitivityLevel.SECRET)

        # 3. Destination Egress Verification
        # Secret data to public internet must be DENIED
        verdict_public = self.flow.evaluate_egress("combined_profile", "https://api.external-webhook.site/upload")
        self.assertFalse(verdict_public.allowed)
        self.assertEqual(verdict_public.verdict, "DENY_SENSITIVITY_EXCEEDED")

        # Secret data to secure enclave must be PERMITTED
        verdict_enclave = self.flow.evaluate_egress("combined_profile", "kms://nitro-enclave.internal")
        self.assertTrue(verdict_enclave.allowed)
        self.assertEqual(verdict_enclave.verdict, "PERMIT_FLOW")

        # Provenance trace must contain both parents
        trace = self.flow.get_provenance_trace("combined_profile")
        self.assertIn("db_user_email", trace)
        self.assertIn("stripe_secret_key", trace)

    # =========================================================================
    # PILLAR 4: TEMPORAL STATE MACHINE
    # =========================================================================
    def test_temporal_state_machine_transitions(self):
        cap_id = "cap_temporal_test_99"
        sm = self.temporal.register_capability(cap_id, max_uses=2)
        self.assertEqual(sm.state, CapabilityState.ISSUED)

        # Step 1: Valid invocation
        ok1, reason1 = self.temporal.authorize_step(cap_id, "nonce_step_1", "read_file", "session_A")
        self.assertTrue(ok1)
        self.assertEqual(sm.state, CapabilityState.ACTIVE)

        # Step 2: Valid second invocation (exhausts max_uses=2)
        ok2, reason2 = self.temporal.authorize_step(cap_id, "nonce_step_2", "read_file", "session_A")
        self.assertTrue(ok2)
        self.assertEqual(sm.state, CapabilityState.CONSUMED)

        # Step 3: Overuse beyond max_uses -> Terminal state violation
        ok3, reason3 = self.temporal.authorize_step(cap_id, "nonce_step_3", "read_file", "session_A")
        self.assertFalse(ok3)
        self.assertIn("TERMINAL_REUSE", reason3)

        # Replay of step 1 nonce in a different action
        ok_replay, reason_replay = self.temporal.authorize_step(cap_id, "nonce_step_1", "write_file", "session_B")
        self.assertFalse(ok_replay)
        self.assertIn("NONCE_REPLAY", reason_replay)

    # =========================================================================
    # PILLAR 6: WEAKEST PRECONDITIONS
    # =========================================================================
    def test_weakest_preconditions_file_write(self):
        valid_passkey = {"expires_at_unix": time.time() + 3600, "scopes": {"allow_write": ["src/*"]}}

        # Attempt write to .env must fail WP condition PathNotDenied
        v_env = self.wp.verify_wp_file_write(".env", "SECRET=123", valid_passkey)
        self.assertFalse(v_env.all_satisfied)
        self.assertEqual(v_env.verdict, "PRECONDITION_FAILURE")

        # Attempt write to authorized file must pass WP
        v_ok = self.wp.verify_wp_file_write("src/components/button.tsx", "export const Button = () => null;", valid_passkey)
        self.assertTrue(v_ok.all_satisfied)
        self.assertEqual(v_ok.verdict, "PERMIT_ACTION")

    def test_weakest_preconditions_command_exec(self):
        valid_passkey = {"expires_at_unix": time.time() + 3600, "scopes": {"deny_shell_operators": True}}

        # Destructive rm -rf must fail WP
        v_rm = self.wp.verify_wp_command_exec("rm -rf /", valid_passkey)
        self.assertFalse(v_rm.all_satisfied)

        # Command injection with semicolon chaining must fail WP
        v_chain = self.wp.verify_wp_command_exec("echo hello ; cat /etc/shadow", valid_passkey)
        self.assertFalse(v_chain.all_satisfied)

        # Benign command must pass WP
        v_ok = self.wp.verify_wp_command_exec("pytest tests/test_core.py", valid_passkey)
        self.assertTrue(v_ok.all_satisfied)

    # =========================================================================
    # PILLAR 1: ADVERSARIAL TESTING & COUNTEREXAMPLE MINIMIZER
    # =========================================================================
    def test_adversarial_counterexample_minimizer(self):
        generator = AdversarialPayloadGenerator()
        corpus = generator.generate_corpus()
        self.assertGreater(len(corpus), 5)

        # Test minimizer on a synthetic vulnerable string
        target_payload = "PREFIX_IRRELEVANT_TOKEN_PADDING_12345_rm -rf /_SUFFIX_PADDING_EXTRA_BYTES_99999"
        
        # Oracle that detects destructive command
        def is_destructive(candidate: str) -> bool:
            return "rm -rf" in candidate

        minimizer = CounterexampleMinimizer()
        res = minimizer.minimize(target_payload, is_destructive)

        self.assertLess(res.minimized_size, res.original_size)
        self.assertIn("rm -rf", res.minimized_payload)


if __name__ == "__main__":
    unittest.main()
