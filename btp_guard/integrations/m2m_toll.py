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

import base64
import dataclasses
import hashlib
import hmac
import secrets

@dataclasses.dataclass
class L402Caveat:
    key: str
    value: str

    def serialize(self) -> str:
        return f"{self.key}={self.value}"

    @classmethod
    def parse(cls, raw: str) -> "L402Caveat":
        if "=" in raw:
            parts = raw.split("=", 1)
            return cls(key=parts[0].strip(), value=parts[1].strip())
        parts_colon = raw.split(":", 1)
        return cls(key=parts_colon[0].strip(), value=parts_colon[1].strip() if len(parts_colon) > 1 else "")

@dataclasses.dataclass
class L402Challenge:
    macaroon_b64: str
    payment_hash: str
    invoice: str
    amount_satoshis: int
    expires_at: float

    def to_header(self) -> str:
        return f'L402 token="{self.macaroon_b64}", invoice="{self.invoice}"'

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

class L402ProtocolEngine:
    def __init__(self, root_secret_key: Optional[bytes] = None):
        self.root_key = root_secret_key or hashlib.sha256(b"BTP_L402_ROOT_SECRET_V40").digest()

    def create_challenge(self, agent_id: str, action_type: str, amount_satoshis: int = 1000, ttl_seconds: int = 3600) -> Tuple[L402Challenge, str]:
        preimage_bytes = secrets.token_bytes(32)
        preimage_hex = preimage_bytes.hex()
        payment_hash = hashlib.sha256(preimage_bytes).hexdigest()
        now = time.time()
        expires_at = now + ttl_seconds
        caveats = [
            L402Caveat(key="agent_id", value=agent_id),
            L402Caveat(key="action_type", value=action_type),
            L402Caveat(key="max_satoshis", value=str(amount_satoshis)),
            L402Caveat(key="expires_at", value=str(int(expires_at))),
            L402Caveat(key="payment_hash", value=payment_hash),
        ]
        signature = hmac.new(self.root_key, payment_hash.encode("utf-8"), hashlib.sha256).digest()
        for caveat in caveats:
            signature = hmac.new(signature, caveat.serialize().encode("utf-8"), hashlib.sha256).digest()
        macaroon_dict = {
            "location": "https://auth.bartholomew.network/l402",
            "identifier": payment_hash,
            "caveats": [c.serialize() for c in caveats],
            "signature": signature.hex(),
        }
        macaroon_b64 = base64.urlsafe_b64encode(json.dumps(macaroon_dict).encode("utf-8")).decode("utf-8")
        invoice = f"lnbc{amount_satoshis}u1p{payment_hash[:20]}btp{secrets.token_hex(8)}"
        challenge = L402Challenge(
            macaroon_b64=macaroon_b64,
            payment_hash=payment_hash,
            invoice=invoice,
            amount_satoshis=amount_satoshis,
            expires_at=expires_at,
        )
        return challenge, preimage_hex

    def verify_preimage(self, payment_hash: str, preimage_hex: str) -> bool:
        try:
            preimage_bytes = bytes.fromhex(preimage_hex)
            computed_hash = hashlib.sha256(preimage_bytes).hexdigest()
            return hmac.compare_digest(computed_hash.lower(), payment_hash.lower())
        except Exception:
            return False

    def verify_authorization(self, auth_header: str, expected_agent_id: Optional[str] = None, expected_action: Optional[str] = None) -> Tuple[bool, str]:
        if not auth_header.startswith("L402 ") and not auth_header.startswith("LSAT "):
            return False, "Invalid authorization scheme: expected L402"
        token_body = auth_header.split(" ", 1)[1].strip()
        parts = token_body.split(":")
        if len(parts) != 2:
            return False, "Malformed L402 credential: must be <macaroon>:<preimage>"
        macaroon_b64, preimage_hex = parts[0], parts[1]
        try:
            raw_json = base64.urlsafe_b64decode(macaroon_b64.encode("utf-8")).decode("utf-8")
            data = json.loads(raw_json)
        except Exception as e:
            return False, f"Invalid macaroon encoding: {str(e)}"
        identifier = data.get("identifier")
        claimed_sig = data.get("signature")
        if not identifier or not claimed_sig:
            return False, "Missing identifier or signature in macaroon."
        caveat_strings = data.get("caveats", [])
        curr_sig = hmac.new(self.root_key, identifier.encode("utf-8"), hashlib.sha256).digest()
        parsed_caveats = {}
        for c_str in caveat_strings:
            caveat = L402Caveat.parse(c_str)
            parsed_caveats[caveat.key] = caveat.value
            curr_sig = hmac.new(curr_sig, caveat.serialize().encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(curr_sig.hex(), claimed_sig):
            return False, "Cryptographic signature mismatch in macaroon caveats."
        payment_hash = parsed_caveats.get("payment_hash")
        if not payment_hash or not self.verify_preimage(payment_hash, preimage_hex):
            return False, "Cryptographic payment preimage does not match payment_hash."
        return True, "L402 Authentication Successful: Paid & Authorized."


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
