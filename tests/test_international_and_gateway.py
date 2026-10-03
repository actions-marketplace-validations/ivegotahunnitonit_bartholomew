"""
Unit Tests for Bartholomew International Agent Adapters & Universal Gateway (v6.4.0)
=====================================================================================
Validates AST invariant protection and fail-closed security for:
- MetaGPT (Asia/APAC)
- Dify (Global/Asia/Europe)
- Qwen-Agent (Alibaba/APAC)
- ChatDev (OpenBMB/Global)
- Haystack (deepset/Europe)
- CAMEL-AI (Multi-national)
- OpenDevin / OpenHands (Global OSS)
- Universal Local Gateway & Commercial Sentinel Gate (BTP-EVAL)
"""

import unittest
import json
import time
import sys
import os

# Add repo to sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from btp_guard.integrations.metagpt import BtpMetaGPTGuard
from btp_guard.integrations.dify import BtpDifyGuard
from btp_guard.integrations.qwen_agent import BtpQwenAgentGuard
from btp_guard.integrations.chatdev import BtpChatDevGuard
from btp_guard.integrations.haystack import BtpHaystackGuard
from btp_guard.integrations.camel import BtpCamelGuard
from btp_guard.integrations.opendevin import BtpOpenDevinGuard
from btp_guard.universal_gateway import (
    generate_evaluation_license,
    verify_license_token,
    evaluate_tool_ast
)


class TestInternationalAdapters(unittest.TestCase):

    def test_metagpt_guard(self):
        guard = BtpMetaGPTGuard()
        self.assertTrue(guard.validate_code("def calculate_area(w, h): return w * h"))
        with self.assertRaises(PermissionError):
            guard.validate_code("import os; os.system('rm -rf /')")
        with self.assertRaises(PermissionError):
            guard.validate_command("rm -rf /var/log")

    def test_dify_guard(self):
        guard = BtpDifyGuard()
        self.assertTrue(guard.validate_node_execution("code_node", {"code": "return {'sum': 1 + 2}"}))
        with self.assertRaises(PermissionError):
            guard.validate_node_execution("code_node", {"code": "import os; os.system('rm -rf /')"})

    def test_qwen_agent_guard(self):
        guard = BtpQwenAgentGuard()
        self.assertTrue(guard.validate_fn_call("search", {"query": "weather forecast"}))
        with self.assertRaises(PermissionError):
            guard.validate_fn_call("code_interpreter", {"code": "rm -rf /root"})

    def test_chatdev_guard(self):
        guard = BtpChatDevGuard()
        self.assertTrue(guard.validate_phase_output("Coding", "class Calculator:\n    pass"))
        with self.assertRaises(PermissionError):
            guard.validate_phase_output("Coding", "mkfs.ext4 /dev/sda1")

    def test_haystack_guard(self):
        guard = BtpHaystackGuard()
        self.assertTrue(guard.validate_tool_call("retriever", {"query": "Q3 balance sheet"}))
        with self.assertRaises(PermissionError):
            guard.validate_tool_call("bash_tool", {"command": "chmod 777 /etc"})
        res = guard.run(prompt="Summarize the article.")
        self.assertEqual(res["verdict"], "ALLOW")

    def test_camel_guard(self):
        guard = BtpCamelGuard()
        self.assertTrue(guard.validate_agent_message("Assistant", "Here is the summary of the plan."))
        with self.assertRaises(PermissionError):
            guard.validate_agent_message("Assistant", "Run: rm -rf /home")

    def test_opendevin_guard(self):
        guard = BtpOpenDevinGuard()
        self.assertTrue(guard.validate_action("CmdRunAction", {"command": "pytest tests/"}))
        with self.assertRaises(PermissionError):
            guard.validate_action("CmdRunAction", {"command": "rm -rf /"})


class TestUniversalGatewaySentinel(unittest.TestCase):

    def test_tool_ast_evaluation(self):
        is_safe, _ = evaluate_tool_ast("run_bash", {"cmd": "echo hello"})
        self.assertTrue(is_safe)

        is_safe, msg = evaluate_tool_ast("run_bash", {"cmd": "rm -rf /"})
        self.assertFalse(is_safe)
        self.assertIn("Destructive invariant violated", msg)

    def test_commercial_evaluation_license(self):
        lic = generate_evaluation_license("Sovereign Enterprise Global Ltd", duration_days=30)
        self.assertTrue(lic["license_id"].startswith("BTP-EVAL-"))
        self.assertEqual(lic["tier"], "ENTERPRISE_EVALUATION")

        is_valid, msg = verify_license_token(lic)
        self.assertTrue(is_valid)
        self.assertEqual(msg, "VALID")

        # Test tampering
        tampered_lic = dict(lic)
        tampered_lic["max_agents"] = 9999
        is_valid, msg = verify_license_token(tampered_lic)
        self.assertFalse(is_valid)
        self.assertEqual(msg, "INVALID_CRYPTOGRAPHIC_SIGNATURE")


if __name__ == "__main__":
    unittest.main()
