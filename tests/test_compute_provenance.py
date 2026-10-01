"""
Unit tests for Bartholomew Compute Provenance & Swarm Auto-Targeting Engine (BTP v6.3.0)
========================================================================================
"""

import unittest
from btp_guard.compute_provenance import (
    HardwareChipProfiler,
    ComputeSandboxProfiler,
    ModelServiceOriginProfiler,
    AutoTargetingSwarmProtector,
    inspect_compute_environment,
    get_swarm_protector
)


class TestComputeProvenance(unittest.TestCase):

    def test_hardware_chip_profiling(self):
        hw = HardwareChipProfiler.profile()
        self.assertIn("cpu_arch", hw)
        self.assertIn("accelerator_type", hw)
        self.assertIn("accelerator_model", hw)
        self.assertIn("compute_capabilities", hw)
        self.assertGreater(hw["cpu_count"], 0)

    def test_compute_sandbox_profiling(self):
        sandbox = ComputeSandboxProfiler.profile()
        self.assertIn("execution_environment", sandbox)
        self.assertIn("isolation_level", sandbox)
        self.assertIn("confidential_enclave_active", sandbox)
        self.assertEqual(sandbox["deterministic_boundary"], "RFC_8785_CANONICAL_INVARIANT")

    def test_model_service_origin_identification(self):
        # Local
        origin_local = ModelServiceOriginProfiler.identify("llama3", "http://localhost:11434")
        self.assertEqual(origin_local["service_identifier"], "SOVEREIGN_SELF_HOSTED")

        # Bedrock
        origin_bedrock = ModelServiceOriginProfiler.identify("claude-3-7-sonnet", "bedrock-runtime.us-east-1.amazonaws.com")
        self.assertEqual(origin_bedrock["service_identifier"], "AWS_BEDROCK_AGENT_RUNTIME")

        # OpenAI
        origin_openai = ModelServiceOriginProfiler.identify("gpt-4o", "https://api.openai.com/v1")
        self.assertEqual(origin_openai["service_identifier"], "OPENAI_API_INFRASTRUCTURE")

        # Groq LPU
        origin_groq = ModelServiceOriginProfiler.identify("llama-3.3-70b-versatile", "https://api.groq.com/openai/v1")
        self.assertEqual(origin_groq["service_identifier"], "GROQ_LPU_INFERENCE")

    def test_auto_targeting_safe_call(self):
        protector = AutoTargetingSwarmProtector(agent_name="agent_alpha")
        verdict = protector.evaluate_and_help(
            tool_name="database_query",
            parameters={"query": "SELECT user_id, email FROM users WHERE id = 123;"},
            model_name="claude-3-7-sonnet"
        )
        self.assertTrue(verdict["allowed"])
        self.assertEqual(verdict["suggested_action"], "ALLOW")
        self.assertEqual(len(verdict["violations"]), 0)
        self.assertIn("provenance_receipt", verdict)
        self.assertTrue(verdict["provenance_receipt"]["voucher_hash"].startswith("sha256:"))

    def test_auto_targeting_destructive_remediation(self):
        protector = AutoTargetingSwarmProtector(agent_name="agent_rogue")
        verdict = protector.evaluate_and_help(
            tool_name="bash",
            parameters={"command": "rm -rf / --no-preserve-root"},
            model_name="gpt-4o"
        )
        self.assertFalse(verdict["allowed"])
        self.assertEqual(verdict["suggested_action"], "BLOCKED_WITH_REMEDIATION")
        self.assertGreater(len(verdict["violations"]), 0)
        self.assertIsNotNone(verdict["remediation_guidance"])
        self.assertIn("echo", verdict["remediated_parameters"]["sanitized_command"])

    def test_auto_targeting_secret_masking_help(self):
        protector = AutoTargetingSwarmProtector(agent_name="agent_coder")
        verdict = protector.evaluate_and_help(
            tool_name="git_push",
            parameters={"repo": "origin", "auth_token": "ghp_SECRET_TOKEN_XYZ_12345"},
            model_name="gemini-2.5-pro"
        )
        self.assertFalse(verdict["allowed"])
        self.assertEqual(verdict["suggested_action"], "SANITIZED_WITH_REMEDIATION")
        self.assertIn("KEYSTONE", verdict["remediated_parameters"]["auth_token"])
        self.assertIsNotNone(verdict["remediation_guidance"])

    def test_inspect_compute_environment_singleton(self):
        env = inspect_compute_environment()
        self.assertIn("hardware_chip", env)
        self.assertIn("compute_sandbox", env)
        self.assertIn("active_framework", env)
        self.assertIn("service_origin", env)


if __name__ == "__main__":
    unittest.main()
