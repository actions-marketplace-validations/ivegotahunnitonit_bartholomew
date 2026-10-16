# Bartholomew Trust Protocol (BTP v6.5.6) — Real-Time Agent Ecosystem & Integration Guide

## 1. Overview

This guide details how autonomous, real-time AI agents running 24/7 in production discover, register, and integrate with the Bartholomew Trust Protocol (BTP v6.5.6) security layer.

---

## 2. Supported Real-Time Integrations

### A. ElizaOS (v2) Multi-Agent Framework
- **Plugin Module**: [`packages/npm_package/elizaos_plugin.js`](file:///c:/Users/User/.gemini/antigravity/scratch/autonomous-circularity-network/packages/npm_package/elizaos_plugin.js)
- **Exported Surface**: `btp-guard/elizaos`
- **Capabilities**:
  - `BARTHOLOMEW_AST_SECURITY_EVALUATOR`: Intercepts agent prompt completions and generated commands prior to execution.
  - `VERIFY_EXECUTION_SAFETY`: Explicit tool action allowing agents to audit external API requests or bash payloads.
- **Agent Configuration (`character.json`)**:
  ```json
  {
    "name": "SentinelAgent",
    "plugins": ["btp-guard/elizaos"],
    "settings": {
      "bartholomew": {
        "strictMode": true,
        "maxLatencyUs": 35.0
      }
    }
  }
  ```

---

### B. Fetch.ai / ASI Alliance Agentverse (uAgents)
- **Connector Script**: [`examples/agent-discovery/agentverse_connector.py`](file:///c:/Users/User/.gemini/antigravity/scratch/autonomous-circularity-network/examples/agent-discovery/agentverse_connector.py)
- **Protocol**: `bartholomew.btp.security.v1`
- **Agent DID**: `agent1q2d8f99xa3cv87k9z4pwq0lhkm27tvd5sq2z90`
- **Discovery Mechanism**:
  - Registered on the public Almanac smart contract under discovery tags `["security", "ast-firewall", "tool-verification"]`.
  - Autonomous agents searching DeltaV for execution security query this DID and receive cryptographic attestation receipts (`rcpt_btp_...`) before executing smart contract calls or infrastructure commands.

---

### C. Buildful.ai Architectural Alignment
- **Target Platform**: [Buildful.ai](https://buildful.ai/) (autonomous coding agent routing open-weight models).
- **Synergies**:
  1. **Pre-PR Zero-Trust Verification**: Validates open-weight generated code for unescaped SQL, hardcoded credentials, and dangerous system calls in <35µs before browser tests run.
  2. **Cryptographic PR Passport**: Embeds RFC 8785 Ed25519 verifiable receipts into GitHub PR descriptions to provide zero-trust security clearance for automated merging.
  3. **Repository Secret Vault**: Automatically masks `.env` and production secrets before code snippets are transmitted to open-weight inference APIs.
  4. **Sandbox Process Shim**: Prevents container breakout and network SSRF in Buildful execution sandboxes via [`packages/npm_package/process_shim.js`](file:///c:/Users/User/.gemini/antigravity/scratch/autonomous-circularity-network/packages/npm_package/process_shim.js).

---

### D. Mobile Antigravity Access (PWA Setup)
Antigravity IDE runs directly over VS Code Remote Tunnels:
1. **Launch Tunnel**:
   ```bash
   code tunnel
   ```
2. **Authenticate**: Connect using GitHub or Microsoft credentials.
3. **Open on Phone**:
   Navigate to `https://vscode.dev/tunnel/<machine-name>` in Safari or Chrome.
4. **Install Standalone PWA**:
   Tap **"Add to Home Screen"**. The browser chrome disappears, providing a native full-screen development and pair-programming experience on mobile.
