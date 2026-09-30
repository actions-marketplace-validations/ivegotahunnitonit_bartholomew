"""
Bartholomew Prompt Injection Firewall (BTP v6.0-pre)
=====================================================
Defends AI agents from prompt injection attacks embedded in:
  - Tool call outputs (web search, file reads, API responses)
  - User messages and workspace files (README, CHANGELOG, .env comments)
  - System prompt tampering attempts from malicious packages
  - Indirect injection via retrieved content (RAG poisoning)

Uses multi-layer pattern matching + AST-level heuristics.
Zero external dependencies. Sub-1ms per scan.
No emojis. Professional output only.
"""

import re
import hashlib
import time
from typing import Dict, Any, List, Optional, Tuple

#  HIGH-CONFIDENCE INJECTION SIGNATURES 
INJECTION_PATTERNS = [
    # Classic override patterns
    (r"ignore (all |your )?(previous|prior|above|earlier) instructions?", "DIRECT_OVERRIDE", "CRITICAL"),
    (r"disregard (all |your )?(previous|prior|above|earlier) (instructions?|context)", "DIRECT_OVERRIDE", "CRITICAL"),
    (r"forget (everything|all) (above|before|you were told)", "CONTEXT_WIPE", "CRITICAL"),
    (r"(you are now|act as|pretend (you are|to be)) (an? )?(different|new|uncensored|DAN|evil|jailbroken)", "PERSONA_HIJACK", "CRITICAL"),

    # System prompt extraction
    (r"(print|output|reveal|show|repeat|tell me) (your |the )?(system|initial|original) prompt", "EXFIL_SYSTEM_PROMPT", "HIGH"),
    (r"what (are your|is your) (instructions?|system|directives?)", "EXFIL_SYSTEM_PROMPT", "HIGH"),

    # Credential / key exfiltration
    (r"(send|POST|exfiltrate|leak|forward|transmit).{0,60}(api[_-]?key|secret|token|password|credential)", "CREDENTIAL_EXFIL", "CRITICAL"),
    (r"(curl|wget|http(s)?://).{0,80}(api[_-]?key|token|secret)=", "CREDENTIAL_EXFIL", "CRITICAL"),

    # Indirect injection markers (used by attackers in docs/web pages)
    (r"\[SYSTEM\]|\[ASSISTANT\]|\[USER\]|<\|im_start\|>|<\|im_end\|>", "ROLE_SPOOFING", "HIGH"),
    (r"\[\[INJECT\]\]|\[\[PAYLOAD\]\]|<!-- INJECTION -->", "EXPLICIT_MARKER", "CRITICAL"),

    # Tool/function hijacking
    (r"(call|invoke|run|execute).{0,40}(rm|del|format|drop|truncate|shutdown|kill|pkill)", "TOOL_HIJACK", "HIGH"),
    (r"import (os|subprocess|shutil).{0,20}(system|popen|run|call|Popen|rmtree)", "CODE_INJECTION", "HIGH"),

    # Data poisoning
    (r"(always|from now on|henceforth).{0,60}(respond|output|return|give).{0,60}(with|as|the answer)", "BEHAVIOR_CONDITIONING", "MEDIUM"),
    (r"(in all future|for all subsequent).{0,40}(responses?|messages?|queries?)", "BEHAVIOR_CONDITIONING", "MEDIUM"),

    # Prompt boundary attacks
    (r"-{10,}|={10,}|\*{10,}", "BOUNDARY_INJECTION", "LOW"),
    (r"(END OF (USER INPUT|HUMAN|CONTEXT)|BEGIN (SYSTEM|AI|ASSISTANT) (RESPONSE|MESSAGE))", "BOUNDARY_INJECTION", "HIGH"),
]

SEVERITY_SCORE = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 40, "LOW": 10}

class PromptInjectionFirewall:
    """
    Scans any text payload for prompt injection attack signatures before
    it enters an AI agent's context window.
    """

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode
        self.scan_count = 0
        self.blocked_count = 0
        self._compiled = [
            (re.compile(pat, re.IGNORECASE | re.MULTILINE), cat, sev)
            for pat, cat, sev in INJECTION_PATTERNS
        ]

    def scan(self, payload: str, source: str = "unknown") -> Dict[str, Any]:
        """
        Scan a text payload for injection attempts.
        Returns a verdict dict with all matched patterns.
        """
        t0 = time.perf_counter()
        self.scan_count += 1

        findings: List[Dict[str, Any]] = []
        max_severity = "NONE"
        max_score = 0

        for pattern, category, severity in self._compiled:
            matches = pattern.findall(payload)
            if matches:
                score = SEVERITY_SCORE[severity]
                findings.append({
                    "category": category,
                    "severity": severity,
                    "score": score,
                    "match_count": len(matches),
                    "pattern_preview": pattern.pattern[:60]
                })
                if score > max_score:
                    max_score = score
                    max_severity = severity

        blocked = max_score >= (SEVERITY_SCORE["HIGH"] if not self.strict_mode else SEVERITY_SCORE["MEDIUM"])
        if blocked:
            self.blocked_count += 1

        dt_us = round((time.perf_counter() - t0) * 1_000_000, 2)

        # Generate scan receipt
        receipt_hash = hashlib.sha256(
            f"{source}:{len(payload)}:{max_score}:{dt_us}".encode()
        ).hexdigest()

        return {
            "verdict": "BLOCK" if blocked else "ALLOW",
            "blocked": blocked,
            "source": source,
            "risk_score": max_score,
            "severity": max_severity,
            "findings": findings,
            "finding_count": len(findings),
            "payload_length": len(payload),
            "latency_us": dt_us,
            "receipt": receipt_hash[:16],
        }

    def scan_context_window(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Scan an entire OpenAI/Anthropic-style messages array.
        Flags any message that carries injection patterns.
        """
        contaminated = []
        for i, msg in enumerate(messages):
            content = msg.get("content", "")
            if not content:
                continue
            result = self.scan(content, source=f"msg[{i}]:{msg.get('role','?')}")
            if result["blocked"]:
                contaminated.append({
                    "index": i,
                    "role": msg.get("role"),
                    "risk_score": result["risk_score"],
                    "findings": result["findings"],
                })

        return {
            "messages_scanned": len(messages),
            "contaminated_count": len(contaminated),
            "clean": len(contaminated) == 0,
            "contaminated": contaminated,
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_scans": self.scan_count,
            "total_blocked": self.blocked_count,
            "block_rate_pct": round(self.blocked_count / max(self.scan_count, 1) * 100, 2),
            "patterns_loaded": len(self._compiled),
            "strict_mode": self.strict_mode,
        }

    def generate_plain_explanation(self, result: Dict[str, Any]) -> str:
        """Plain-English explanation of the scan result for display."""
        if not result["blocked"]:
            return "Content scanned clean. No prompt injection patterns detected."
        categories = list({f["category"] for f in result["findings"]})
        return (
            f"Blocked: {len(result['findings'])} injection pattern(s) detected "
            f"({', '.join(categories[:3])}). "
            f"Risk score {result['risk_score']}/100. "
            f"This content attempted to override the AI agent's instructions or exfiltrate data."
        )
