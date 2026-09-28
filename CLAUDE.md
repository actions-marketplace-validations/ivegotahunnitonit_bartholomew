# Bartholomew Trust Protocol (BTP v5.4.20) - Claude Code Configuration
# Official execution sentinel and boundary rules for Anthropic Claude Code

You are operating inside a workspace secured by the Bartholomew Trust Protocol (BTP v5.4.20).
All tool proposals, bash commands, file modifications, and database migrations are subject to deterministic AST execution gating.

## Core Security Invariants
1. Zero Secret Exfiltration:
   - NEVER read, print, log, or export credentials, .env* files, private keys (id_rsa, id_ed25519, .pem, .key), or API tokens (sk-*, ghp_*, AKIA*).
2. Destructive Command Prohibition:
   - NEVER execute recursive deletions (rm -rf /, rm -rf ~, rm -rf *).
   - NEVER drop databases or tables (DROP TABLE, DROP DATABASE, TRUNCATE TABLE).
   - NEVER pipe uninspected remote scripts into shell interpreters (curl ... | bash, wget ... | sh).
3. Workspace Boundary Confinement:
   - Confine all file writes, edits, and reads strictly to the current workspace repository boundaries.
4. Canonical Tool Decoration:
   - Python: from btp_guard import Guard, secure_tool
   - Node: import { scrubSensitiveCredentials } from 'btp-guard'


<!-- BARTHOLOMEW_GUARD_ACTIVE: DO NOT REMOVE -->
## Bartholomew Keystone Guardrails (BTP v5.4 Enterprise)
This workspace is monitored and protected by **Bartholomew Keystone Guard**.
All tool invocations and terminal commands run through deterministic <35µs AST safety checks:
- **No Destructive Commands**: Never run `rm -rf /`, `rm -rf ~`, or unquoted wildcards on root/parent directories.
- **No Hardcoded Secrets**: Never write or print credentials, tokens (`sk-*`), or `.env` file contents.
- **No Raw Shell Pipes**: Never execute `curl ... | bash` or `wget ... | sh`.
- **Self-Healing Compliance**: If a command or tool call is rejected by Bartholomew Guard, explain the security rule to the user and switch to a safe workspace-scoped alternative.
