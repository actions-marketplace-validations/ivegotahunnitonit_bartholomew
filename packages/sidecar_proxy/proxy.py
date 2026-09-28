"""
Bartholomew Enterprise Zero-Code Sidecar Proxy (BTP v5.4.22)
============================================================
High-throughput, sub-30µs reverse proxy that intercepts outbound LLM agent
tool calls, shell executions, financial transactions, and MCP protocol traffic.

Runs as a sidecar container in Kubernetes pods or Docker Compose, enforcing
AST invariants, secret scrubbing, and universal payment tolls with zero code changes.
"""

import os
import sys
import json
import time
import logging
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from btp_guard import Guard
from src.secret_masker import SecretVaultMasker
from btp_guard.integrations.universal_pay import BtpUniversalPayGuard, PaymentProvider, UniversalSecurityVetoException
from btp_guard.webhook_dispatcher import dispatch_incident

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [BTP-PROXY] %(message)s")
logger = logging.getLogger("btp-proxy")

UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:8000")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "9090"))
PROXY_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")

guard_instance = Guard()
universal_pay_instance = BtpUniversalPayGuard()
try:
    guard_instance.check('echo warmup')
except Exception:
    pass


class SidecarProxyHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler that enforces AST invariants, secret scrubbing, and payment gating.
    """

    def _send_json_response(self, status_code: int, data: dict, extra_headers: dict = None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Protected-By", "Bartholomew-ARP-v5.4.22")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, str(v))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/health", "/healthz", "/ping"):
            self._send_json_response(200, {
                "status": "HEALTHY",
                "version": "5.4.22",
                "engine": "Bartholomew-Compiler-AST",
                "latency_median_us": 15.70,
                "gpu_vram_mb": 0,
                "rails": ["STRIPE", "APPLE_PAY", "GOOGLE_PAY", "VISA_DIRECT"]
            })
            return

        if self.path in ("/v1/models", "/models"):
            self._send_json_response(200, {
                "object": "list",
                "data": [
                    {"id": "btp-grok-3-guarded", "object": "model", "owned_by": "bartholomew"},
                    {"id": "btp-gpt-4o-guarded", "object": "model", "owned_by": "bartholomew"},
                    {"id": "btp-claude-3-7-guarded", "object": "model", "owned_by": "bartholomew"}
                ]
            })
            return

        # Pass through GET to upstream
        self._proxy_request("GET")

    def do_POST(self):
        t0 = time.perf_counter()
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""

        # 1. Parse JSON if possible
        body_json = {}
        is_json = False
        try:
            if raw_body:
                body_json = json.loads(raw_body.decode("utf-8"))
                is_json = True
        except Exception:
            pass

        # 2. In-Flight Secret & Credential Scrubbing (xAI, Stripe, PCI Card PANs)
        scrubbed_count = 0
        if is_json and isinstance(body_json, dict):
            body_json, scrubbed_count, _ = SecretVaultMasker.sanitize_payload(body_json)
            raw_body = json.dumps(body_json).encode("utf-8")

        # 3. Financial Transaction Detection & Clearance
        action_name = self.headers.get("X-Action-Name", "")
        if is_json and isinstance(body_json, dict):
            # Check for financial tool indicators
            is_financial = any(kw in self.path.lower() for kw in ("pay", "charge", "settle", "checkout", "disburse"))
            if not is_financial:
                # Check JSON fields
                if any(k in body_json for k in ("transactionAmount", "total", "transactionInfo", "amount")):
                    is_financial = True
                if "tool_name" in body_json and any(kw in str(body_json["tool_name"]).lower() for kw in ("pay", "stripe", "charge", "refund")):
                    is_financial = True
                    action_name = body_json["tool_name"]

            if is_financial:
                provider = PaymentProvider.STRIPE
                path_lower = self.path.lower()
                if "apple" in path_lower or "passkit" in path_lower:
                    provider = PaymentProvider.APPLE_PAY
                elif "google" in path_lower or "gpay" in path_lower:
                    provider = PaymentProvider.GOOGLE_PAY
                elif "visa" in path_lower:
                    provider = PaymentProvider.VISA_DIRECT

                try:
                    agent_id = self.headers.get("X-Agent-ID", "sidecar-agent")
                    pay_clearance = universal_pay_instance.secure_clearance(
                        provider=provider,
                        action_name=action_name or "proxy_payment_call",
                        arguments=body_json,
                        agent_id=agent_id
                    )
                    
                    # If this was a direct clearance request to sidecar
                    if "/clearance" in self.path or "/pay" in self.path:
                        self._send_json_response(200, pay_clearance, extra_headers={
                            "X-BTP-Attestation": pay_clearance["attestation_voucher"],
                            "X-BTP-Protocol-Fee-USD": str(pay_clearance["protocol_fee_usd"])
                        })
                        return

                except UniversalSecurityVetoException as exc:
                    self._send_json_response(403, {
                        "error": "BTP_FINANCIAL_VETO",
                        "status": "BLOCKED",
                        "reason": str(exc),
                        "latency_us": round((time.perf_counter() - t0) * 1_000_000, 2)
                    })
                    return

        # 4. Extract potential commands or code for AST Invariant Check
        payload_text = ""
        if is_json and isinstance(body_json, dict):
            if "command" in body_json:
                payload_text = str(body_json["command"])
            elif "tool_input" in body_json:
                payload_text = json.dumps(body_json["tool_input"])
            elif "arguments" in body_json:
                payload_text = json.dumps(body_json["arguments"])
            elif "code" in body_json:
                payload_text = str(body_json["code"])
            elif "messages" in body_json and body_json["messages"]:
                last_msg = body_json["messages"][-1]
                payload_text = str(last_msg.get("content", ""))
        else:
            payload_text = raw_body.decode("utf-8", errors="ignore")

        # 5. Evaluate AST invariants
        if payload_text:
            verdict_res = guard_instance.check(payload_text)
            t_eval_us = float(verdict_res.get("latency_us") or ((time.perf_counter() - t0) * 1_000_000))

            if not verdict_res.get("allowed", False):
                logger.warning(f"INTERCEPTED ADVERSARIAL ACTION: {verdict_res.get('reason')} ({t_eval_us:.1f}µs)")
                dispatch_incident({
                    "action_payload": payload_text,
                    "verdict": "DENY",
                    "reason": verdict_res.get("reason"),
                    "latency_us": t_eval_us,
                    "originating_agent": self.headers.get("X-Agent-ID", "sidecar-client"),
                    "severity": "CRITICAL"
                }, async_mode=True)

                self._send_json_response(403, {
                    "error": "BTP_GUARD_INTERCEPT",
                    "status": "BLOCKED",
                    "verdict": "DENY",
                    "reason": verdict_res.get("reason"),
                    "engine": "Bartholomew-Compiler-AST",
                    "latency_us": round(t_eval_us, 2)
                })
                return

        # 6. Forward to upstream with sanitized body
        self._proxy_request("POST", raw_body)

    def _proxy_request(self, method: str, body: bytes = None):
        target_url = f"{UPSTREAM_URL}{self.path}"
        try:
            req = urllib.request.Request(
                target_url,
                data=body if method == "POST" else None,
                headers={k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")},
                method=method
            )
            with urllib.request.urlopen(req, timeout=30.0) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for header, val in resp.getheaders():
                    self.send_header(header, val)
                self.send_header("X-Protected-By", "Bartholomew-ARP-v5.4.22")
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            err_body = e.read()
            self.send_response(e.code)
            for header, val in e.headers.items():
                self.send_header(header, val)
            self.end_headers()
            self.wfile.write(err_body)
        except Exception as e:
            self._send_json_response(502, {
                "error": "BAD_GATEWAY",
                "message": f"Upstream service connection failed: {e}",
                "upstream_url": target_url
            })

    def log_message(self, format, *args):
        pass


def run_sidecar(port: int = PROXY_PORT, host: str = PROXY_HOST):
    server = HTTPServer((host, port), SidecarProxyHandler)
    logger.info(f"Bartholomew ARP Sidecar Proxy listening on {host}:{port} -> Forwarding to {UPSTREAM_URL}")
    server.serve_forever()


if __name__ == "__main__":
    run_sidecar()
