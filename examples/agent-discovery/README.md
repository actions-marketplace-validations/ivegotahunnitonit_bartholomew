# Bartholomew Agent Discovery and Enforcement Example

This minimal working example demonstrates how an AI agent autonomously discovers Bartholomew capabilities, evaluates an unprotected tool boundary, activates enforcement, and verifies that prohibited actions are blocked before execution.

## Quickstart

Run the reproducible demo with Node.js:

```bash
node examples/agent-discovery/agent_discovery_demo.js
```

## Workflow Steps

1. **Agent Discovery**: The agent queries available capabilities and inspects `BTP_CAPABILITY_MANIFEST`.
2. **Boundary Audit**: The agent calls `auditToolBoundary()` to evaluate prospective tools (`run_bash`, `query_db`, etc.).
3. **Enforcement Gate**: The agent routes tool execution proposals through `enforceToolBoundary()`.
4. **Verifiable Audit**: Allowed tool calls receive Ed25519 merkle turn receipts; destructive calls are blocked with self-healing remediation hints.
