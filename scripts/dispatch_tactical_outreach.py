"""
Bartholomew Tactical Outreach & Community Dispatch Tool
======================================================
Interactive CLI to browse 30+ high-probability targets across Discord,
GitHub, and Twitter, and generate copy-paste ready technical outreach.
"""

import sys
import os

TARGETS = [
    {"name": "LangChain / LangGraph", "cat": "Framework", "channel": "Discord: discord.gg/langchain (#ecosystem)", "angle": "Deterministic AST tool gating for LangGraph pre-tool hooks"},
    {"name": "CrewAI", "cat": "Framework", "channel": "Discord: discord.gg/crewai (#integrations)", "angle": "Spend circuit breaker & destructive command firewall"},
    {"name": "LlamaIndex", "cat": "Framework", "channel": "Discord: discord.gg/llamaindex (#agents)", "angle": "Deterministic invariant gate for tool dispatchers"},
    {"name": "OpenHands (All-Hands AI)", "cat": "Coding Agent", "channel": "Discord: discord.gg/openhands (#dev, #security)", "angle": "In-container terminal execution gate to prevent rogue rm -rf"},
    {"name": "Continue.dev", "cat": "IDE Assistant", "channel": "Discord: discord.gg/continue (#general)", "angle": "Open VSX extension parity & AST security boundary"},
    {"name": "E2B", "cat": "Sandbox", "channel": "Discord: discord.gg/e2b (#general)", "angle": "In-sandbox sub-35us AST firewall for agent executions"},
    {"name": "Codeium (Windsurf)", "cat": "Agentic IDE", "channel": "Discord: discord.gg/codeium (#windsurf)", "angle": "Sub-35us AST gate for Windsurf Cascade autonomous executions"},
    {"name": "Anysphere (Cursor)", "cat": "Agentic IDE", "channel": "Forum: forum.cursor.com / Discord", "angle": "6,000+ developers use Bartholomew on Cursor; native invariant clearance"},
    {"name": "Hugging Face smolagents", "cat": "Framework", "channel": "Discord: discord.gg/huggingface (#smolagents)", "angle": "1-line @secure_tool AST decorator for smolagents (0 MB VRAM)"},
    {"name": "Protect AI (Huntr)", "cat": "Security", "channel": "Discord: Huntr Bug Bounty Discord", "angle": "105,000-vector red-team benchmark & AST firewall interoperability"}
]

def main():
    print("=" * 76)
    print("BARTHOLOMEW BTP v6.0 TACTICAL OUTREACH DISPATCH")
    print("=" * 76)
    print("Top High-Probability Technical Channels (Discord / GitHub / Forums):")
    print("-" * 76)
    for i, t in enumerate(TARGETS, 1):
        print(f"[{i:2d}] {t['name']:<24} | {t['cat']:<12} | {t['channel']}")
        print(f"     Hook: {t['angle']}")
    print("-" * 76)
    print("See docs/DISCORD_GITHUB_ACTION_TEMPLATES.md for ready-to-paste messages.")
    print("See docs/TACTICAL_ENGINEER_OUTREACH_DIRECTORY.md for the full 30-team matrix.")
    print("=" * 76)

if __name__ == "__main__":
    main()
