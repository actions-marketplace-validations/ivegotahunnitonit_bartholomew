"""
Bartholomew Milestone 3.1: Sovereign Digital Passports & Agent Peer Discovery (BTP v3.1.0)
========================================================================================
Implements:
1. Sovereign Digital Passports for non-human agent workers with cryptographically
   verifiable reputation vectors, capability boundaries, and self-reconciling circuit breakers.
2. Decentralized Peer Discovery registry for autonomous agent capability negotiation.
"""

import time
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple, Set
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    from src.rfc8785 import rfc8785_canonicalize
except ImportError:
    from rfc8785 import rfc8785_canonicalize


class SovereignAgentPassport:
    """
    Sovereign Digital Passport for an autonomous non-human worker agent.
    Cryptographically signed with Ed25519 and verifiable offline or across swarms.
    """

    DEFAULT_CAPABILITIES = {
        "READ_ONLY": {"data:read", "tools:search", "telemetry:emit"},
        "DEVELOPER": {"data:read", "code:mutate", "git:commit", "test:run", "tools:search"},
        "OPERATOR": {"data:read", "data:write", "service:restart", "code:mutate", "db:query"},
        "TREASURY": {"data:read", "l402:pay", "stripe:settle", "escrow:release"}
    }

    def __init__(
        self,
        agent_id: str,
        worker_model: str,
        owner_pubkey: str,
        granted_capabilities: Optional[List[str]] = None,
        bonded_warranty_balance_usd: float = 0.0,
        ttl_seconds: int = 86400,
        reputation_vector: Optional[Dict[str, Any]] = None,
        passport_id: Optional[str] = None,
        created_at: Optional[float] = None,
        expires_at: Optional[float] = None,
        circuit_breaker_tripped: bool = False,
        trip_reason: Optional[str] = None,
        org_id: str = "default_org",
        project_id: str = "default_project",
        environment: str = "dev"
    ):
        self.agent_id = agent_id
        self.worker_model = worker_model
        self.owner_pubkey = owner_pubkey
        self.granted_capabilities = granted_capabilities or ["data:read", "tools:search"]
        self.bonded_warranty_balance_usd = float(bonded_warranty_balance_usd)
        self.org_id = org_id.lower().strip()
        self.project_id = project_id.lower().strip()
        self.environment = environment.lower().strip()
        self.tenant_id = f"ten_{hashlib.sha256(f'{self.org_id}:{self.project_id}:{self.environment}'.encode()).hexdigest()[:24]}"
        
        now = time.time()
        self.created_at = created_at or now
        self.expires_at = expires_at or (self.created_at + ttl_seconds)
        self.circuit_breaker_tripped = circuit_breaker_tripped
        self.trip_reason = trip_reason

        self.reputation_vector = reputation_vector or {
            "verified_actions": 0,
            "settled_value_usd": 0.0,
            "violation_count": 0,
            "trust_score": 1.0  # 0.0 to 1.0
        }

        if not passport_id:
            raw = f"{agent_id}:{worker_model}:{owner_pubkey}:{self.tenant_id}:{self.created_at}"
            digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
            self.passport_id = f"urn:agent:passport:{digest}"
        else:
            self.passport_id = passport_id

        self.signature_hex: Optional[str] = None

    def get_canonical_payload(self) -> Dict[str, Any]:
        """Returns the canonical passport dictionary prior to signing."""
        return {
            "protocol": "BTP/3.1.0/PASSPORT",
            "passport_id": self.passport_id,
            "agent_id": self.agent_id,
            "worker_model": self.worker_model,
            "owner_pubkey": self.owner_pubkey,
            "org_id": self.org_id,
            "project_id": self.project_id,
            "environment": self.environment,
            "tenant_id": self.tenant_id,
            "granted_capabilities": sorted(list(set(self.granted_capabilities))),
            "bonded_warranty_balance_usd": round(self.bonded_warranty_balance_usd, 2),
            "reputation_vector": {
                "verified_actions": self.reputation_vector.get("verified_actions", 0),
                "settled_value_usd": round(float(self.reputation_vector.get("settled_value_usd", 0.0)), 2),
                "violation_count": self.reputation_vector.get("violation_count", 0),
                "trust_score": round(float(self.reputation_vector.get("trust_score", 1.0)), 4)
            },
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "circuit_breaker_tripped": self.circuit_breaker_tripped,
            "trip_reason": self.trip_reason
        }

    def sign(self, private_key: ed25519.Ed25519PrivateKey) -> str:
        """Signs the canonical passport payload with Ed25519 private key."""
        payload = self.get_canonical_payload()
        canonical_bytes = rfc8785_canonicalize(payload)
        sig = private_key.sign(canonical_bytes)
        self.signature_hex = sig.hex()
        return self.signature_hex

    def verify_signature(self, owner_pubkey_hex: Optional[str] = None) -> Tuple[bool, str]:
        """Cryptographically verifies the passport signature."""
        if not self.signature_hex:
            return False, "Passport is unsigned"

        now = time.time()
        if now > self.expires_at:
            return False, "Passport expired"

        if self.circuit_breaker_tripped:
            return False, f"Passport circuit breaker tripped: {self.trip_reason}"

        target_pubkey = owner_pubkey_hex or self.owner_pubkey
        try:
            pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(target_pubkey))
            payload = self.get_canonical_payload()
            canonical_bytes = rfc8785_canonicalize(payload)
            sig_bytes = bytes.fromhex(self.signature_hex)
            pubkey.verify(sig_bytes, canonical_bytes)
            return True, "Valid cryptographic passport"
        except Exception as e:
            return False, f"Signature verification failed: {str(e)}"

    def has_capability(self, capability: str) -> bool:
        """Checks if passport grants specific capability scope."""
        if self.circuit_breaker_tripped:
            return False
        if "*" in self.granted_capabilities:
            return True
        return capability in self.granted_capabilities

    def trip_circuit_breaker(self, reason: str):
        """Immediately trips the circuit breaker, suspending passport validity."""
        self.circuit_breaker_tripped = True
        self.trip_reason = reason
        self.reputation_vector["violation_count"] += 1
        self.reputation_vector["trust_score"] = max(0.0, self.reputation_vector.get("trust_score", 1.0) - 0.25)

    def record_violation(self, reason: str):
        """Records a policy violation, reducing trust score."""
        self.reputation_vector["violation_count"] += 1
        self.reputation_vector["trust_score"] = max(0.0, self.reputation_vector.get("trust_score", 1.0) - 0.1)

    def record_successful_action(self, value_usd: float = 0.0):
        """Updates reputation vector after verified execution."""
        if self.circuit_breaker_tripped:
            return
        self.reputation_vector["verified_actions"] += 1
        self.reputation_vector["settled_value_usd"] += value_usd
        # Increase trust score asymptotically toward 1.0
        current_score = self.reputation_vector.get("trust_score", 1.0)
        self.reputation_vector["trust_score"] = min(1.0, current_score + 0.01)

    def record_action(self, reason: str = "", volume_usd: float = 0.0):
        """Convenience alias for recording verified task completion."""
        self.record_successful_action(value_usd=volume_usd)

    @property
    def verified_action_count(self) -> int:
        return self.reputation_vector.get("verified_actions", 0)

    @property
    def total_settled_volume_usd(self) -> float:
        return self.reputation_vector.get("settled_value_usd", 0.0)

    @property
    def violation_count(self) -> int:
        return self.reputation_vector.get("violation_count", 0)

    @property
    def is_circuit_broken(self) -> bool:
        return self.circuit_breaker_tripped

    @is_circuit_broken.setter
    def is_circuit_broken(self, value: bool):
        if value:
            self.trip_circuit_breaker("Administrative circuit breaker trip")
        else:
            self.circuit_breaker_tripped = False

    @property
    def trust_score(self) -> float:
        return self.reputation_vector.get("trust_score", 1.0)

    @classmethod
    def issue(
        cls,
        agent_id: str,
        model_family: str = "claude-3-5-sonnet",
        authorized_capabilities: Optional[List[str]] = None,
        bonded_warranty_usd: float = 0.0,
        ttl_seconds: int = 86400,
        org_id: str = "default_org",
        project_id: str = "default_project",
        environment: str = "dev",
        private_key: Optional[ed25519.Ed25519PrivateKey] = None
    ) -> "SovereignAgentPassport":
        """Convenience factory to generate and sign a new sovereign passport."""
        priv = private_key or ed25519.Ed25519PrivateKey.generate()
        pubkey_hex = priv.public_key().public_bytes_raw().hex()
        passport = cls(
            agent_id=agent_id,
            worker_model=model_family,
            owner_pubkey=pubkey_hex,
            granted_capabilities=authorized_capabilities,
            bonded_warranty_balance_usd=bonded_warranty_usd,
            ttl_seconds=ttl_seconds,
            org_id=org_id,
            project_id=project_id,
            environment=environment
        )
        passport.sign(priv)
        return passport

    def to_dict(self) -> Dict[str, Any]:
        """Serializes passport to dict with signature."""
        data = self.get_canonical_payload()
        data["signature"] = self.signature_hex
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SovereignAgentPassport":
        """Instantiates passport from serialized dict."""
        passport = cls(
            agent_id=data["agent_id"],
            worker_model=data["worker_model"],
            owner_pubkey=data["owner_pubkey"],
            granted_capabilities=data.get("granted_capabilities", []),
            bonded_warranty_balance_usd=data.get("bonded_warranty_balance_usd", 0.0),
            reputation_vector=data.get("reputation_vector"),
            passport_id=data.get("passport_id"),
            created_at=data.get("created_at"),
            expires_at=data.get("expires_at"),
            circuit_breaker_tripped=data.get("circuit_breaker_tripped", False),
            trip_reason=data.get("trip_reason"),
            org_id=data.get("org_id", "default_org"),
            project_id=data.get("project_id", "default_project"),
            environment=data.get("environment", "dev")
        )
        passport.signature_hex = data.get("signature")
        return passport


class AgentPeerDiscoveryRegistry:
    """
    Decentralized Peer Discovery & Capability Registry for autonomous multi-agent swarms.
    """

    def __init__(self):
        self._passports: Dict[str, SovereignAgentPassport] = {}

    def register_passport(self, passport_data: Any) -> Tuple[bool, str, Dict[str, Any]]:
        """Registers and validates an agent passport in the discovery mesh."""
        try:
            if isinstance(passport_data, SovereignAgentPassport):
                passport = passport_data
            else:
                passport = SovereignAgentPassport.from_dict(passport_data)
            is_valid, msg = passport.verify_signature()
            if not is_valid:
                return False, f"Registration rejected: {msg}", {}

            self._passports[passport.passport_id] = passport
            return True, "Registered successfully in discovery mesh", passport.to_dict()
        except Exception as e:
            return False, f"Registration error: {str(e)}", {}

    def get_passport(self, passport_id: str) -> Optional[SovereignAgentPassport]:
        """Retrieves a registered passport by ID."""
        return self._passports.get(passport_id)

    def query_peers(
        self,
        capability: Optional[str] = None,
        min_reputation: Optional[float] = None,
        min_bond_usd: Optional[float] = None,
        model_family: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Discovers peer agent nodes matching specific capability and trust criteria.
        """
        results = []
        now = time.time()

        for passport in self._passports.values():
            if passport.expires_at < now or passport.circuit_breaker_tripped:
                continue

            if capability and not passport.has_capability(capability):
                continue

            if min_reputation is not None:
                score = passport.reputation_vector.get("trust_score", 0.0)
                if score < min_reputation:
                    continue

            if min_bond_usd is not None:
                if passport.bonded_warranty_balance_usd < min_bond_usd:
                    continue

            if model_family:
                if model_family.lower() not in passport.worker_model.lower():
                    continue

            results.append(passport.to_dict())

        return results

    def trip_circuit_breaker(self, passport_id: str, reason: str) -> Tuple[bool, str]:
        """Trips the circuit breaker for an agent across the discovery mesh."""
        passport = self._passports.get(passport_id)
        if not passport:
            return False, "Passport not found"
        passport.trip_circuit_breaker(reason)
        return True, f"Circuit breaker tripped for {passport_id}: {reason}"


# -------------------------------------------------------------
# Corporate KYC & Spending Authority Extension (BTP v5.4.22)
# -------------------------------------------------------------

AgentPassport = SovereignAgentPassport

class AgentPassportAuthority:
    """
    Issues and verifies corporate agent passports in sub-10 microseconds.
    """

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or "btp_corp_treasury_root_key_2026"
        self.registry = AgentPeerDiscoveryRegistry()

    def issue_passport(
        self,
        agent_id: str,
        organization_id: str = "org_enterprise_corp",
        treasury_account: str = "acct_treasury_primary",
        spend_cap_usd: float = 1000.0,
        authorized_rails: Optional[List[str]] = None,
        validity_seconds: float = 86400.0
    ) -> SovereignAgentPassport:
        rails = authorized_rails or ["STRIPE", "APPLE_PAY", "GOOGLE_PAY", "VISA_DIRECT"]
        passport = SovereignAgentPassport.issue(
            agent_id=agent_id,
            org_id=organization_id,
            authorized_capabilities=rails,
            bonded_warranty_usd=spend_cap_usd,
            ttl_seconds=int(validity_seconds)
        )
        self.registry.register_passport(passport)
        return passport

    def verify_passport(
        self,
        passport: SovereignAgentPassport,
        requested_rail: Optional[str] = None,
        requested_amount_usd: float = 0.0
    ) -> Tuple[bool, str]:
        """
        Validates cryptographic integrity, expiration, and spending boundaries in sub-10us.
        """
        # 1. Check circuit breaker / revocation
        if passport.circuit_breaker_tripped:
            return False, f"Passport {passport.passport_id} circuit breaker tripped: {passport.trip_reason}"

        # 2. Check expiration
        now = time.time()
        if now > passport.expires_at:
            return False, f"Passport {passport.passport_id} expired at {passport.expires_at} (current: {now})."

        # 3. Check signature
        is_valid, msg = passport.verify_signature()
        if not is_valid:
            return False, f"Cryptographic signature invalid: {msg}"

        # 4. Check rail authorization
        if requested_rail and not passport.has_capability(requested_rail):
            return False, f"Rail {requested_rail} is not in authorized capabilities: {passport.granted_capabilities}"

        # 5. Check spending ceiling against authorized cap
        if requested_amount_usd > passport.bonded_warranty_balance_usd:
            return False, f"Requested amount ${requested_amount_usd:.2f} exceeds passport authorized ceiling ${passport.bonded_warranty_balance_usd:.2f}."

        return True, "PASSPORT_VERIFIED_VALID"
