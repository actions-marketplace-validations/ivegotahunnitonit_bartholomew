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
    # Anthropic keys (check before generic OpenAI prefix)
    ("ANTHROPIC_KEY", re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}')),
    # OpenAI keys
    ("OPENAI_KEY",    re.compile(r'sk-(?:proj-)?(?!ant-)[A-Za-z0-9\-_]{20,}')),
    # Stripe keys
    ("STRIPE_KEY",    re.compile(r'\b[sr]k_live_[0-9a-zA-Z]{24,}\b')),
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
    # Social Security Numbers (SSN)
    ("SSN",           re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')),
    # Sensitive / Enterprise Emails
    ("EMAIL",         re.compile(r'\b[A-Za-z0-9._%+-]+@(?!example\.com|test\.com|localhost)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
]

def is_valid_luhn(digits: str) -> bool:
    clean = re.sub(r'[\s-]', '', digits)
    if not clean.isdigit() or not (13 <= len(clean) <= 19):
        return False
    digits_list = [int(d) for d in clean]
    checksum = 0
    reverse_digits = digits_list[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class SecretMaskerV2:
    """
    Scans text and replaces secrets with vault references or format-preserving surrogates.
    Maintains an in-memory vault for unmask operations and JIT OS dispatch.
    Thread-safe for concurrent agent sessions.
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or hashlib.sha256(
            f"masker:{time.time()}".encode()
        ).hexdigest()[:12]
        self._vault: Dict[str, Tuple[str, str]] = {}  # ref -> (original, secret_type)
        self._lock = threading.Lock()
        self.mask_count = 0

    def _make_ref(self, secret: str, secret_type: str = "SECRET", format_preserving: bool = False) -> str:
        """Generate a deterministic vault reference or format-preserving surrogate."""
        h = hashlib.sha256(f"{self.session_id}:{secret}".encode()).hexdigest()[:16]
        if not format_preserving:
            return f"BTP-VAULT-REF-{h}"
        
        # Format-preserving surrogates matching Bartholomew Vault standards
        h_upper = h[:8].upper()
        h_lower = h[:8].lower()
        if secret_type == "EMAIL":
            return f"anon-{h_lower}@btp-vault.internal"
        elif secret_type == "SSN":
            return f"999-{h_upper[:2]}-{h_upper[2:6]}"
        elif secret_type == "CREDIT_CARD":
            return f"4000-0000-0000-{h_upper[:4]}"
        elif secret_type == "OPENAI_KEY":
            return f"sk-proj-BTP_VAULT_{h_upper}"
        elif secret_type == "ANTHROPIC_KEY":
            return f"sk-ant-api03-BTP_VAULT_{h_upper}"
        elif secret_type == "STRIPE_KEY":
            return f"sk_live_BTP_VAULT_{h_upper}"
        elif secret_type == "AWS_KEY":
            return f"AKIA_BTP_VAULT_{h_upper}"
        elif secret_type == "GITHUB_PAT":
            return f"ghp_BTP_VAULT_{h_upper}"
        elif secret_type == "CONN_STRING":
            return f"postgres://btp_vault_user:btp_vault_pass@127.0.0.1:5432/btp_sanitized_{h_lower}"
        return f"BTP_TKN_{secret_type}_{h_upper}"

    def mask(self, text: str, format_preserving: bool = False) -> Tuple[str, List[Dict]]:
        """
        Scan text, replace secrets with vault references or format-preserving surrogates.
        Returns (masked_text, list of findings).
        """
        pending = []  # (secret_value, secret_type, full_match)

        # Standard patterns
        for secret_type, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                full_match = match.group(0)
                secret_value = match.group(match.lastindex) if match.lastindex else full_match
                if len(secret_value) >= 8:
                    pending.append((secret_value, secret_type, full_match))

        # Credit cards with Luhn validation
        cc_pattern = re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b')
        for match in cc_pattern.finditer(text):
            candidate = match.group(0)
            if is_valid_luhn(candidate):
                pending.append((candidate, "CREDIT_CARD", candidate))

        # Phase 2: apply all replacements
        findings = []
        result = text
        with self._lock:
            for secret_value, secret_type, full_match in pending:
                ref = self._make_ref(secret_value, secret_type, format_preserving)
                if ref not in self._vault:
                    self._vault[ref] = (secret_value, secret_type)
                    self.mask_count += 1
                result = result.replace(secret_value, ref)
                findings.append({
                    "type": secret_type,
                    "ref": ref,
                    "original_length": len(secret_value),
                    "pattern_match": full_match[:40],
                    "format_preserving": format_preserving
                })

        return result, findings

    def unmask(self, text: str) -> str:
        """Restore vault references back to original values."""
        with self._lock:
            for ref, (original, _) in self._vault.items():
                text = text.replace(ref, original)
        return text

    def detokenize_dispatch(self, command: str) -> Tuple[str, int]:
        """
        Just-In-Time OS Detokenization:
        Swaps surrogate tokens back to real credentials in command strings
        immediately before process execution so integration tests pass.
        """
        executable = command
        swapped = 0
        with self._lock:
            for ref, (original, _) in self._vault.items():
                if ref in executable:
                    executable = executable.replace(ref, original)
                    swapped += 1
        return executable, swapped

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
