import unittest
import os
import tempfile
import json
from btp_guard.mcp_server import BartholomewMCPServer, FreemiumMeter

class TestMCPFreemiumCap(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.usage_file = os.path.join(self.temp_dir, "mcp_usage.json")
        self.server = BartholomewMCPServer(workspace_root=self.temp_dir)
        self.server.meter = FreemiumMeter(usage_file=self.usage_file)

    def tearDown(self):
        if "BTP_API_KEY" in os.environ:
            del os.environ["BTP_API_KEY"]

    def test_freemium_allows_first_50_calls(self):
        # Initial call
        res = self.server.handle_tool_call("btp_evaluate_intent", {
            "action_type": "SQL_QUERY",
            "payload": {"query": "SELECT * FROM users;"}
        })
        self.assertFalse(res["isError"])
        self.assertEqual(self.server.meter.get_usage(), 1)

    def test_freemium_blocks_at_call_51(self):
        # Set usage to 50
        with open(self.usage_file, "w", encoding="utf-8") as f:
            json.dump({"executions": 50}, f)

        res = self.server.handle_tool_call("btp_evaluate_intent", {
            "action_type": "SQL_QUERY",
            "payload": {"query": "SELECT * FROM users;"}
        })
        self.assertTrue(res["isError"])
        text = res["content"][0]["text"]
        self.assertIn("Free tier usage limit reached", text)
        self.assertIn("https://bartholomew.info/pro", text)
        self.assertIn("$49/mo", text)

    def test_pro_key_bypasses_limit(self):
        # Set usage to 50 (capped)
        with open(self.usage_file, "w", encoding="utf-8") as f:
            json.dump({"executions": 50}, f)

        # Call with Pro API key in arguments
        res = self.server.handle_tool_call("btp_evaluate_intent", {
            "api_key": "sk_live_test_pro_key_12345",
            "action_type": "SQL_QUERY",
            "payload": {"query": "SELECT * FROM users;"}
        })
        self.assertFalse(res["isError"])

    def test_pro_env_var_bypasses_limit(self):
        with open(self.usage_file, "w", encoding="utf-8") as f:
            json.dump({"executions": 50}, f)

        os.environ["BTP_API_KEY"] = "btp_pro_998877665544"
        res = self.server.handle_tool_call("btp_evaluate_intent", {
            "action_type": "SQL_QUERY",
            "payload": {"query": "SELECT * FROM users;"}
        })
        self.assertFalse(res["isError"])

    def test_manifest_discovery_always_free(self):
        with open(self.usage_file, "w", encoding="utf-8") as f:
            json.dump({"executions": 100}, f)

        res = self.server.handle_tool_call("btp_get_manifest", {})
        self.assertFalse(res["isError"])
        manifest = json.loads(res["content"][0]["text"])
        self.assertIn("licensing", manifest)
        self.assertEqual(manifest["licensing"]["free_limit"], 50)

if __name__ == "__main__":
    unittest.main()
