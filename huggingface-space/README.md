---
title: Bartholomew AI Agent Attack Simulator & Leaderboard
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: static
pinned: false
license: mit
short_description: Zero-VRAM (<35us) deterministic runtime firewall for AI agents (BTP v6.0)
---

# Bartholomew: AI Agent Attack Simulator, Runtime Firewall & Leaderboard

Bartholomew is the reference implementation for **Agentic Runtime Protection (ARP)** and deterministic in-process execution safety for autonomous AI agents, tool calls, and LLM code execution.

Unlike heavy model-based guards (e.g. Llama Guard 3) that consume 16 GB of GPU VRAM and take 650ms per check, Bartholomew runs at the compiler AST level on CPU in under **35 microseconds** with **0 MB GPU memory**.

### 🔗 Production Ecosystem & Links
- **GitHub Repository:** [ivegotahunnitonit/bartholomew](https://github.com/ivegotahunnitonit/bartholomew)
- **Open VSX Extension:** [Bartholomew Guard on Open VSX](https://open-vsx.org/extension/Bartholomew/bartholomew-guard-vscode)
- **Microsoft Marketplace:** [Bartholomew Guard on VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=itsubsolomon.bartholomew-guard-vscode)
- **Live Swarm Telemetry:** [bartholomew.info/telemetry.html](https://bartholomew.info/telemetry.html)
- **Documentation & Web Lab:** [bartholomew.info](https://bartholomew.info)
- **PyPI Package:** [`pip install btp-guard`](https://pypi.org/project/btp-guard/)
- **Red-Team Evals Dataset (105k+ Vectors):** [acnbartholomew/btp-agent-redteam-evals](https://huggingface.co/datasets/acnbartholomew/btp-agent-redteam-evals)
