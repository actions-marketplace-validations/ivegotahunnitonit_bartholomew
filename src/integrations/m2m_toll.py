"""
Bartholomew M2M Autonomous Micro-Streaming & HTTP 402 Toll Engine (BTP v5.4.22)
================================================================================
Enables autonomous agent-to-agent (M2M) sub-cent micro-streaming settlements
using the standard HTTP 402 Payment Required and RFC L402 protocol.

Eliminates the 30-cent credit card swipe minimum for sub-cent AI workloads:
  - $0.005 per vector search
  - $0.01 per fine-tuned inference task
  - $0.02 per Bartholomew safety invariant clearance
"""

import os
import sys
import json
import time
import uuid
from typing import Dict, Any, Optional, Tuple, Callable

from src.settlement.l402_protocol import L402ProtocolEngine, L402Challenge, L402Caveat


class BtpM2MMicroToll:
    """
    HTTP 402 / L402 Micro-Toll interceptor and settlement engine for agent swarms.
    """

    def __init__(self, root_secret_key: Optional[bytes] = None):
        self.engine = L402ProtocolEngine(root_secret_key=root_secret_key)
        self.settled_invoices = set()

    def create_402_challenge(
        self,
        service_id: str,
        amount_satoshis: int = 10,
        fee_usd: float = 0.01,
        agent_id: str = "caller-agent"
    ) -> Dict[str, Any]:
        """
        Generates standard HTTP 402 headers and L402 challenge for an M2M invocation.
        """
        challenge, preimage_hex = self.engine.create_challenge(
            agent_id=agent_id,
            action_type=service_id,
            amount_satoshis=amount_satoshis
        )
        return {
            "status_code": 402,
            "error": "PAYMENT_REQUIRED",
            "www_authenticate": challenge.to_header(),
            "payment_hash": challenge.payment_hash,
            "preimage_hex": preimage_hex,
            "invoice": challenge.invoice,
            "amount_satoshis": amount_satoshis,
            "fee_usd": fee_usd
        }

    def verify_payment_and_grant(
        self,
        auth_header: str,
        expected_agent_id: Optional[str] = None,
        expected_action: Optional[str] = None
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates the L402 Authorization token presented by an autonomous agent.
        Format: 'L402 <macaroon_b64>:<preimage_hex>'
        """
        if not auth_header or not auth_header.startswith("L402 "):
            return False, "Missing or invalid Authorization scheme. Expected 'L402 <macaroon_b64>:<preimage_hex>'", {}

        token_str = auth_header[5:].strip()
        parts = token_str.split(":")
        if len(parts) != 2:
            return False, "Malformed L402 token. Expected format '<macaroon_b64>:<preimage_hex>'", {}

        macaroon_b64, preimage_hex = parts[0], parts[1]

        # 1. Validate Macaroon
        is_valid_mac, mac_reason, mac_data = self.engine.verify_macaroon(
            macaroon_b64,
            expected_agent_id=expected_agent_id,
            expected_action=expected_action
        )
        if not is_valid_mac:
            return False, f"Macaroon verification failed: {mac_reason}", {}

        # 2. Validate Preimage proof
        payment_hash = mac_data.get("payment_hash") or mac_data.get("identifier") or ""
        if not self.engine.verify_preimage(payment_hash, preimage_hex):
            return False, "Cryptographic preimage verification failed: H(preimage) != payment_hash", {}

        self.settled_invoices.add(payment_hash)
        receipt = {
            "status": "M2M_MICROPAYMENT_CLEARED",
            "payment_hash": payment_hash,
            "settled_at": time.time(),
            "attestation": f"attest_l402_{uuid.uuid4().hex[:10]}"
        }
        return True, "SETTLED", receipt
