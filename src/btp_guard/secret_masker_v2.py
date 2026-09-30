"""
Bartholomew In-Context Secret Masker v2 (BTP v6.0-pre)
=======================================================
Scans any text payload and replaces detected secrets with opaque vault
references BEFORE the content enters an AI model's context window.

This prevents:
  - API keys, tokens, passwords from appearing in LLM prompts
  - Accidental secret logging via tool call results
  - .env file content leaking into model conversations

Replaces secrets with BTP-VAULT-REF-{16-char-hex} references.
The original values can be retrieved from the in-memory vault.
Vault references are session-scoped and never persisted to disk.

Zero external deps. Thread-safe.
"""

import re
import hashlib
import time
import threading
from typing import Dict, List, Tuple, Optional


#  SECRET DETECTION PATTERNS 
SECRET_PATTERNS = [
    # Generic API keys
    ("API_KEY",       re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?')),
    # Bearer tokens
    ("BEARER_TOKEN",  re.compile(r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})')),
    # JWT tokens
    ("JWT",           re.compile(r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+')),
    # OpenAI keys
    ("OPENAI_KEY",    re.compile(r'sk-[A-Za-z0-9]{20,}')),
    # Anthropic keys
    ("ANTHROPIC_KEY", re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}')),
    # AWS access keys
    ("AWS_KEY",       re.compile(r'AKIA[0-9A-Z]{16}')),
    # AWS secret
    ("AWS_SECRET",    re.compile(r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?')),
    # GitHub PAT
    ("GITHUB_PAT",    re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}')),
    # Google SA key (begins with AIza)
    ("GOOGLE_KEY",    re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    # Generic password in .env style
    ("ENV_SECRET",    re.compile(r'(?i)(password|passwd|secret|token|key)\s*=\s*["\']?([^\s"\']{8,})["\']?')),
    # Connection strings
    ("CONN_STRING",   re.compile(r'(?i)(postgres|mysql|mongodb|redis)://[^\s@]+:[^\s@]+@[^\s]+')),
    # Private key block
    ("PRIVATE_KEY",   re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
]


class SecretMaskerV2:
    """
    Scans text and replaces secrets with vault references.
    Maintains an in-memory vault for unmask operations.
    Thread-safe for concurrent agent sessions.
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or hashlib.sha256(
            f"masker:{time.time()}".encode()
        ).hexdigest()[:12]
        self._vault: Dict[str, Tuple[str, str]] = {}  # ref -> (original, secret_type)
        self._lock = threading.Lock()
        self.mask_count = 0

    def _make_ref(self, secret: str) -> str:
        """Generate a deterministic vault reference for a secret."""
        h = hashlib.sha256(f"{self.session_id}:{secret}".encode()).hexdigest()[:16]
        return f"BTP-VAULT-REF-{h}"

    def mask(self, text: str) -> Tuple[str, List[Dict]]:
        """
        Scan text, replace secrets with vault references.
        Returns (masked_text, list of findings).
        Collects all matches first before any mutation to avoid iterator invalidation.
        """
        # Phase 1: collect all matches before mutating text
        pending = []  # (secret_value, secret_type, full_match)
        for secret_type, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                full_match = match.group(0)
                # Use full_match for patterns without groups; last group for keyed patterns
                secret_value = match.group(match.lastindex) if match.lastindex else full_match
                if len(secret_value) >= 8:
                    pending.append((secret_value, secret_type, full_match))

        # Phase 2: apply all replacements
        findings = []
        result = text
        with self._lock:
            for secret_value, secret_type, full_match in pending:
                ref = self._make_ref(secret_value)
                if ref not in self._vault:
                    self._vault[ref] = (secret_value, secret_type)
                    self.mask_count += 1
                result = result.replace(secret_value, ref)
                findings.append({
                    "type": secret_type,
                    "ref": ref,
                    "original_length": len(secret_value),
                    "pattern_match": full_match[:40],
                })

        return result, findings

    def unmask(self, text: str) -> str:
        """Restore vault references back to original values."""
        with self._lock:
            for ref, (original, _) in self._vault.items():
                text = text.replace(ref, original)
        return text

    def audit_secrets(self) -> List[Dict]:
        """Return all secrets currently in the vault (types only, not values)."""
        with self._lock:
            return [
                {
                    "ref": ref,
                    "type": stype,
                    "original_length": len(original),
                }
                for ref, (original, stype) in self._vault.items()
            ]

    def get_vault_size(self) -> int:
        with self._lock:
            return len(self._vault)

    def get_stats(self) -> Dict:
        with self._lock:
            types = {}
            for _, (_, stype) in self._vault.items():
                types[stype] = types.get(stype, 0) + 1
            return {
                "session_id": self.session_id,
                "total_masked": self.mask_count,
                "vault_size": len(self._vault),
                "secret_types": types,
            }
