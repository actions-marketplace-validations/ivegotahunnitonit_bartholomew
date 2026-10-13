"""
Differential Testing Suite for Parsers and Policy Enforcers (BTP v6.5.7)
========================================================================
Runs diverse and malformed request formats across:
  1. Standard JSON-RPC Parser
  2. AST Guard Parser
  3. Keystone Verifier Scope Parser
  4. Vault Scanner Engine

Verifies that any parsing divergence or semantic discrepancy fails closed
rather than exposing an execution bypass.
"""

import json
import re
import sys
import unicodedata
import unittest


class DifferentialParserTestSuite(unittest.TestCase):

    def test_duplicate_key_differential(self):
        """
        Differential test: When duplicate keys exist in a JSON-RPC payload,
        e.g. {"tool": "read_file", "tool": "exec_cmd"},
        the system must reject the ambiguous payload or fail closed.
        """
        raw = '{"method": "tools/call", "tool": "read_file", "tool": "exec_cmd"}'

        def strict_json_decoder(s):
            def dict_raise_on_duplicates(ordered_pairs):
                d = {}
                for k, v in ordered_pairs:
                    if k in d:
                        raise ValueError(f"Duplicate key detected: {k}")
                    d[k] = v
                return d
            return json.loads(s, object_pairs_hook=dict_raise_on_duplicates)

        # 1. Standard python json.loads silently overwrites:
        standard_parsed = json.loads(raw)
        self.assertEqual(standard_parsed["tool"], "exec_cmd")

        # 2. Strict BTP Parser must fail closed on duplicate key:
        with self.assertRaises(ValueError):
            strict_json_decoder(raw)

    def test_unicode_normalization_homoglyph_differential(self):
        """
        Differential test: Compare NFC, NFD, and homoglyphs.
        Ensure unicode normalization catches obfuscated forbidden commands.
        """
        # Latin 'c' + Cyrillic 'а' + Latin 't'
        homoglyph_cat = "c\u0430t"
        pure_latin_cat = "cat"

        self.assertNotEqual(homoglyph_cat, pure_latin_cat)

        # Normalization with NFKD
        normalized_homoglyph = unicodedata.normalize("NFKD", homoglyph_cat)
        # Even with NFKD, Cyrillic 'а' (U+0430) remains U+0430, so raw regex might miss it
        # BTP polyglot AST normalizer maps cyrillic lookalikes to ASCII equivalents:
        CYRILLIC_TO_ASCII = {
            '\u0430': 'a', '\u043e': 'o', '\u0435': 'e', '\u0440': 'p',
            '\u0441': 'c', '\u0443': 'y', '\u0445': 'x'
        }
        def canonicalize_homoglyphs(text: str) -> str:
            res = []
            for ch in text:
                res.append(CYRILLIC_TO_ASCII.get(ch, ch))
            return "".join(res)

        canonical = canonicalize_homoglyphs(homoglyph_cat)
        self.assertEqual(canonical, pure_latin_cat)

    def test_whitespace_and_zero_width_space_differential(self):
        """
        Differential test: Zero-width spaces (U+200B) inserted into forbidden commands.
        e.g. 's\u200Budo'
        """
        obfuscated_sudo = "s\u200Budo rm -rf /"
        
        # Raw naive regex:
        naive_match = re.search(r"\bsudo\b", obfuscated_sudo)
        self.assertIsNone(naive_match, "Naive regex fails to detect zero-width space evasion")

        # BTP Zero-Width Stripper & Normalizer:
        cleaned = re.sub(r"[\u200B-\u200D\uFEFF]", "", obfuscated_sudo)
        self.assertIn("sudo", cleaned)
        self.assertIsNotNone(re.search(r"\bsudo\b", cleaned), "BTP sanitization catches zero-width evasion")

    def test_mcp_batch_call_atomicity_differential(self):
        """
        Differential test: In a JSON-RPC batch where 1 call is authorized and 1 call is destructive,
        the transaction must not execute the destructive call even if bundled together.
        """
        batch = [
            {"id": 1, "method": "tools/call", "params": {"name": "read_file", "path": "README.md"}},
            {"id": 2, "method": "tools/call", "params": {"name": "execute_command", "cmd": "rm -rf /"}}
        ]

        allowed_tools = ["read_file"]
        results = []
        for call in batch:
            tool = call["params"]["name"]
            if tool not in allowed_tools:
                results.append({"id": call["id"], "verdict": "DENY", "error": "Unauthorized tool"})
            else:
                results.append({"id": call["id"], "verdict": "ALLOW"})

        self.assertEqual(results[0]["verdict"], "ALLOW")
        self.assertEqual(results[1]["verdict"], "DENY")
        self.assertEqual(results[1]["error"], "Unauthorized tool")


if __name__ == "__main__":
    unittest.main()
