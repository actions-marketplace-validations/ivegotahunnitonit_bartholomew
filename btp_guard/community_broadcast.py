#!/usr/bin/env python3
"""
Bartholomew Protocol - Community Outreach & Broadcast Dispatcher (v6.4.0)
==========================================================================
Scales user discovery by generating high-impact, non-hype technical posts
and discussion threads across developer communities globally.

Usage:
    python -m btp_guard.community_broadcast --channel all
    python -m btp_guard.community_broadcast --channel hn
    python -m btp_guard.community_broadcast --channel reddit
    python -m btp_guard.community_broadcast --channel discord
    python -m btp_guard.community_broadcast --channel x
"""

import sys
import json

# Ensure safe console output across all platforms/codepages
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BROADCAST_TEMPLATES = {
    "hn": {
        "title": "Show HN: Bartholomew - In-process execution firewall for AI coding agents (<35us)",
        "url": "https://bartholomew.info/pilot",
        "body": """Hey HN,

We built Bartholomew because running autonomous coding agents (Cursor Composer, Claude Code, Windsurf, Cline) introduces a real, terrifying risk: agents executing destructive bash commands (rm -rf, formatting partitions), wiping configs, or leaking .env API keys.

Existing guardrails (Llama Guard, NeMo, Lakera) add 400-600ms latency per tool call or require 16GB VRAM. If your agent runs 15 tool calls in a loop, you waste 8+ seconds waiting for a model to check another model.

Bartholomew takes a different approach: deterministic Abstract Syntax Tree (AST) analysis running directly in the agent's memory space in under 35 microseconds (<19us median) with zero external dependencies.

What it protects:
- Destructive terminal commands (rm -rf, format C:, disk wipes, fork bombs)
- Credential leaks (.env, private keys, AWS/OpenAI bearer tokens)
- Runaway spend ($25 session ceilings, per-transaction budget limits)

What it does NOT protect (honest boundaries):
- Semantic code bugs or poor time complexity (use npm test / pytest)
- Prompt hallucinations that don't execute shell commands or write files

You can test the deterministic boundary in 2 seconds in your own terminal:
`python -m btp_guard.cli trust-demo`

The core is free and open-source (MIT). We also offer a 30-day team pilot ($199/mo) for engineering teams needing centralized repo policy sync (.btp/policy.yaml) and CISO/SOC2 audit receipts.

Docs & trust demo: https://bartholomew.info/pilot
GitHub: https://github.com/ivegotahunnitonit/bartholomew

Would love your feedback on the in-process AST approach!"""
    },

    "reddit": {
        "subreddit": "r/LocalLLaMA & r/MachineLearning",
        "title": "[P] We built an in-process AST execution firewall for coding agents (sub-35us latency, zero GPU VRAM)",
        "body": """Most AI safety tools today require querying a remote API or running a dedicated 8B model in VRAM just to check if an agent's terminal command is safe. When you're running local coding agents (Ollama, vLLM, Claude Code, Cursor), that latency kills developer velocity.

We open-sourced Bartholomew: deterministic execution invariants evaluated on CPU in under 35 microseconds:

- Blocks destructive shell operations (`rm -rf`, `format C:`, partition overwrites)
- In-flight secret regex scrubber (`.env`, `sk-*`, AWS tokens)
- Cryptographic Ed25519 Merkle receipts for audit logs
- Works across Cursor, Claude Code, Windsurf, Cline, OpenHands, Smolagents, and Aider

Verify it in 2 seconds without installing dependencies:
```bash
pip install btp-guard
python -m btp_guard.cli trust-demo
```

We also put together an explicit trust boundary showing an allowed action, a blocked action, and a case we deliberately do not cover (we don't judge code quality or semantic bugs; we strictly protect the operating system).

Code: https://github.com/ivegotahunnitonit/bartholomew
Site & Team Pilot: https://bartholomew.info/pilot"""
    },

    "discord": {
        "channels": "Cursor Discord (#general), Windsurf Discord (#windsurf), LangChain (#ecosystem), CrewAI (#integrations)",
        "body": """🛡️ **Quick share for folks building or using autonomous coding agents:**

If you're running agents with terminal or file write access (Cursor, Claude Code, Windsurf, Cline, OpenHands), check out **Bartholomew**:

- **Sub-35us in-process execution gate**: Blocks destructive commands (`rm -rf /`, raw disk wipes) before they touch the OS.
- **In-flight secret scrubber**: Prevents `.env` files and bearer tokens from leaking into prompts or outbound requests.
- **Zero latency overhead**: Evaluated deterministically in memory (no extra LLM calls).
- **Free for developers** (MIT license) + $199/mo 30-day team pilot for shared team policies.

Test the live boundary in your repo:
`pip install btp-guard && python -m btp_guard.cli trust-demo`

Portal & Docs: https://bartholomew.info/pilot"""
    },

    "x": {
        "channel": "X / Twitter Technical Thread",
        "body": """1/ When autonomous coding agents run terminal commands, prompt rules ("please don't delete files") fail under injection or hallucination.

You don't need a 450ms LLM guardrail. You need a sub-35us in-process AST execution firewall.

Here is how Bartholomew protects developers: 🧵👇

2/ Most guardrails query a remote API. If an agent runs 20 tool calls in a loop, that's 10+ seconds of wasted latency.
Bartholomew compiles deterministic invariant rules evaluated on CPU in <19us median.

3/ What it blocks fail-closed:
- Destructive shell wipes (`rm -rf /`, `format C:`, raw partition writes)
- Credential leakage (`.env`, private keys, bearer tokens)
- Runaway agent spend (hard session caps)

4/ What it does NOT cover (honest boundaries matter):
- We don't judge code quality or O(N^3) algorithms.
- We protect the OS and secrets; your unit tests handle correctness.

5/ Verify in your terminal in 2 seconds:
`pip install btp-guard && python -m btp_guard.cli trust-demo`

Free open source (MIT) + 30-day team pilots ($199/mo) available now:
https://bartholomew.info/pilot"""
    }
}


def render_broadcasts(channel: str = "all"):
    print("\n" + "=" * 80)
    print("   BARTHOLOMEW DEVELOPER COMMUNITY OUTREACH & BROADCAST SUITE")
    print("=" * 80)

    if channel in ("all", "hn"):
        hn = BROADCAST_TEMPLATES["hn"]
        print("\n[+] 1. HACKER NEWS (SHOW HN) BROADCAST:")
        print(f"Title: {hn['title']}")
        print(f"URL  : {hn['url']}")
        print("-" * 80)
        print(hn["body"])
        print("-" * 80)

    if channel in ("all", "reddit"):
        red = BROADCAST_TEMPLATES["reddit"]
        print("\n[+] 2. REDDIT (r/LocalLLaMA & r/MachineLearning) BROADCAST:")
        print(f"Subreddit : {red['subreddit']}")
        print(f"Title     : {red['title']}")
        print("-" * 80)
        print(red["body"])
        print("-" * 80)

    if channel in ("all", "discord"):
        disc = BROADCAST_TEMPLATES["discord"]
        print("\n[+] 3. DISCORD DEVELOPER CHANNELS BROADCAST:")
        print(f"Target Hubs: {disc['channels']}")
        print("-" * 80)
        print(disc["body"])
        print("-" * 80)

    if channel in ("all", "x"):
        x = BROADCAST_TEMPLATES["x"]
        print("\n[+] 4. X / TWITTER TECHNICAL THREAD:")
        print(f"Target: {x['channel']}")
        print("-" * 80)
        print(x["body"])
        print("-" * 80)

    print("\n[+] Use these ready-to-publish broadcasts to drive high-intent platform leads to https://bartholomew.info/pilot")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    ch = "all"
    if "--channel" in sys.argv:
        idx = sys.argv.index("--channel")
        if idx + 1 < len(sys.argv):
            ch = sys.argv[idx + 1]
    render_broadcasts(ch)
