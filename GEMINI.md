# autonomous-circularity-network - Gemini Project Context

<!-- BARTHOLOMEW_GUARD_ACTIVE: DO NOT REMOVE -->
## Bartholomew Keystone Security Invariants (BTP v5.4)
This repository is armed with **Bartholomew Keystone Guard** for autonomous agent safety.
- **AST Gating Active**: Destructive shell operations, secret leakage, and unauthorized system access are blocked in-process (<35µs).
- **Safe Code Generation**: Always use environment variables for sensitive parameters. Never hardcode live keys.
- **Safe Filesystem Edits**: Target specific project files. Preserve existing comments and docstrings.
- **Audit Verification**: Every allowed tool action is cryptographically signed and logged to `.btp/audit.log`.
- **Blocked Actions**: If a command is blocked by Bartholomew, do not attempt to bypass. Provide a compliant solution and inform the user.
