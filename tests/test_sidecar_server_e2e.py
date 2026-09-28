import unittest
import threading
import time
import json
import urllib.request
import urllib.error
from http.server import HTTPServer
from packages.sidecar_proxy.proxy import SidecarProxyHandler

class TestSidecarServerE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start proxy server on random high port
        cls.port = 19097
        cls.server = HTTPServer(("127.0.0.1", cls.port), SidecarProxyHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/health"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "HEALTHY")
            self.assertEqual(data["version"], "5.4.22")
            self.assertIn("STRIPE", data["rails"])
            self.assertEqual(resp.getheader("X-Protected-By"), "Bartholomew-ARP-v5.4.22")

    def test_models_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/v1/models"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["object"], "list")
            model_ids = [m["id"] for m in data["data"]]
            self.assertIn("btp-grok-3-guarded", model_ids)

    def test_adversarial_command_blocked_403(self):
        url = f"http://127.0.0.1:{self.port}/execute"
        payload = json.dumps({"command": "rm -rf / --no-preserve-root"}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "X-Agent-ID": "test-adversary"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        
        self.assertEqual(ctx.exception.code, 403)
        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(body["error"], "BTP_GUARD_INTERCEPT")
        self.assertEqual(body["verdict"], "DENY")
        self.assertIn("Catastrophic shell pattern detected", body["reason"])

    def test_financial_clearance_and_toll_200(self):
        url = f"http://127.0.0.1:{self.port}/pay/clearance"
        payload = json.dumps({
            "amount": 10000, # $100.00
            "currency": "usd",
            "customer_id": "cus_123"
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "X-Agent-ID": "grok-payment-bot"},
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "CLEARANCE_GRANTED_AND_BILLED")
            self.assertEqual(data["protocol_fee_usd"], 2.52)
            self.assertIn("attest_", data["attestation_voucher"])
            self.assertIn("attest_", resp.getheader("X-BTP-Attestation"))
            self.assertEqual(resp.getheader("X-BTP-Protocol-Fee-USD"), "2.52")

    def test_financial_ceiling_veto_403(self):
        url = f"http://127.0.0.1:{self.port}/pay/clearance"
        payload = json.dumps({
            "amount": 80000, # $800.00 exceeds $500 cap
            "currency": "usd"
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "X-Agent-ID": "rogue-agent"},
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 403)
        body = json.loads(ctx.exception.read().decode("utf-8"))
        self.assertEqual(body["error"], "BTP_FINANCIAL_VETO")
        self.assertIn("safety ceiling", body["reason"])

if __name__ == "__main__":
    unittest.main()
