# Bartholomew Agent Security Starter Template

A reference repository demonstrating zero-trust autonomous agent protection across IDEs, MCP servers, and CI/CD pipelines.

---

## What Is Included

1. **Pre-configured GitHub Actions Gate** (`.github/workflows/bartholomew_gate.yml`):
   - Audits agent code and tool integrations on every push and PR in `<35µs`.
   - Generates native SARIF alerts in GitHub Security & Code Scanning.
   - Posts cryptographic Merkle execution receipts to GitHub Step Summaries.
2. **Cursor & Claude Desktop MCP Proxy** (`.cursor/mcp.json` & `claude_desktop_config.json`):
   - Wraps MCP servers with `mcp-proxy-guard` to scrub secrets in-flight and veto destructive commands (`rm -rf`, `DROP TABLE`).
3. **Turnkey Python Agent** (`agent.py`):
   - Demonstrates safe tool execution protected by `btp-guard` in-process invariants.

---

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run In-Process Security Audit
```bash
python -m btp_guard.cli check
```

### 3. Verify MCP Proxy Guard
```bash
npx -y mcp-proxy-guard test
```

### 4. Push to GitHub
Once pushed to GitHub, `.github/workflows/bartholomew_gate.yml` will automatically verify your commits and issue an audit receipt.

Distributed under the MIT License.
