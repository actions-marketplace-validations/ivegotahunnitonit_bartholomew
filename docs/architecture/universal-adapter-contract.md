# Bartholomew BTP v6.5.6 — Model-Agnostic Adapter Contract & Specification

**Document Identifier**: `docs/architecture/universal-adapter-contract.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Core Reference Module**: `packages/npm_package/universal_adapters.js`  
**Shared Enforcement Core**: `packages/npm_package/agent_core.js` (`enforceToolBoundary`)  
**Evaluation Date**: 2026-10-14  

---

## 1. Architectural Principle

```
+-----------------------------------------------------------------------------------+
|                            HETEROGENEOUS AGENT LAYER                              |
|  [Claude / Anthropic]  [OpenAI / GPT-4o]  [Cursor / VSCode]  [LangChain / CrewAI] |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     UNIVERSAL MODEL & RUNTIME ADAPTER LAYER                       |
|   MCPAdapter   |   OpenAIToolAdapter   |   LangChainAdapter   |   MediatedProcess |
+-----------------------------------------------------------------------------------+
                                         |  Canonical Normalization
                                         v  { tool, input, agent_id, session_id }
+-----------------------------------------------------------------------------------+
|                       SHARED BTP ENFORCEMENT CORE (<35µs)                         |
|   enforceToolBoundary() -> AST Invariants + Vault Tokenizer + Keystone Tokens     |
+-----------------------------------------------------------------------------------+
                     |                                         |
            [ALLOW]  |                                [DENY]   | [HOLD_FOR_APPROVAL]
                     v                                         v
+---------------------------------+           +-------------------------------------+
|   PROTECTED EXECUTION BOUNDARY  |           |        ZERO EXECUTOR INVOCATIONS    |
| (Database, Terminal, Filesystem)|           |   Structured Veto + Remediation Hint|
+---------------------------------+           +-------------------------------------+
```

**Core Invariant**:  
*Models may differ. Runtimes may differ. The security enforcement boundary must remain consistent.*

---

## 2. Standardized Action Request & Decision Contract

Every adapter must translate disparate incoming model/runtime payloads into the **BTP Canonical Action Request**:

### Canonical Request Schema
```typescript
interface BTPActionRequest {
  // Required
  tool: string;                           // Canonical name of the target tool (e.g. "run_command", "query_db")
  input: Record<string, any> | string;    // Tool arguments / parameters
  
  // Optional Context
  caller_type?: string;                   // "mcp", "openai_tool_call", "langchain", "subprocess", "delegation"
  agent_id?: string;                      // Identifier of the invoking agent (e.g. "cursor_copilot", "worker_01")
  session_id?: string;                    // Current conversation or session token
  clearance_token?: string | null;        // Keystone cryptographic clearance token (if required)
  tool_call_id?: string;                  // Model-specific tool invocation ID (e.g. OpenAI "call_abc123")
  options?: Record<string, any>;          // Security options (e.g. requireApprovalFor list)
}
```

### Canonical Decision Schema
```typescript
interface BTPDecision {
  verdict: "ALLOW" | "DENY" | "HOLD_FOR_APPROVAL";
  allowed: boolean;                       // true ONLY when verdict === "ALLOW"
  tool_name: string;
  rule_id?: string;                       // e.g. "BTP-MCP-INV-001" (Destructive Shell)
  reason?: string;                        // Human and machine-readable denial reason
  remediation_hint?: string;              // Guidance to self-correct the prompt
  safe_alternative?: string | null;       // Safe sandbox replacement (e.g. "rm -rf ./tmp/*")
  merkle_turn_receipt?: string;           // Cryptographic receipt ("ed25519:...") emitted on ALLOW
  latency_us: number;                     // Gate execution latency in microseconds (<35µs typical)
}
```

---

## 3. Enforcement Lifecycle & Interception Invariants

Every adapter implementation must strictly observe this execution sequence:

1. **Pre-Execution Interception**:  
   The adapter must intercept the tool call **strictly prior** to downstream executor dispatch.
2. **Canonical Normalization**:  
   Extract the target tool name and arguments regardless of whether they arrive as JSON-RPC, an OpenAI function call object, a LangChain `_call` input, or CLI parameters.
3. **Core Policy Evaluation**:  
   Call `enforceToolBoundary(normalized.tool, normalized.input, options)`.
4. **Enforcement Execution**:
   - If `decision.allowed === true`: Dispatch to the underlying executor; attach the Ed25519 Merkle turn receipt (`decision.merkle_turn_receipt`) to the return payload.
   - If `decision.allowed === false` (`DENY` or `HOLD_FOR_APPROVAL`):
     - **DO NOT** invoke the downstream executor under any circumstance.
     - Return or throw a model-appropriate error structure containing `[BTP-VETO]`, the `rule_id`, and the `remediation_hint`.
     - Confirm the downstream executor records **strictly 0 invocations**.

---

## 4. Working Reference Adapter Example (OpenAI / Frontier Models)

```javascript
import { enforceToolBoundary } from 'btp-guard';

export class ReferenceOpenAIAdapter {
  constructor(executor, options = {}) {
    this.executor = executor;
    this.options = options;
  }

  async handleModelToolCall(toolCall) {
    const toolName = toolCall.function.name;
    let toolInput = toolCall.function.arguments;
    if (typeof toolInput === 'string') {
      try { toolInput = JSON.parse(toolInput); } catch (_) { toolInput = { raw: toolInput }; }
    }

    // 1. Shared BTP In-Process Core Evaluation
    const decision = enforceToolBoundary(toolName, toolInput, this.options);

    // 2. Strict Enforcement Gate
    if (!decision.allowed) {
      // Return tool message with BTP veto; EXECUTOR IS NEVER CALLED
      return {
        role: "tool",
        tool_call_id: toolCall.id,
        content: JSON.stringify({
          error: "BTP_POLICY_VETO",
          verdict: decision.verdict,
          rule_id: decision.rule_id,
          reason: decision.reason,
          remediation_hint: decision.remediation_hint
        }),
        _btp_blocked: true,
        _executor_invocations: 0
      };
    }

    // 3. Permitted Dispatch
    const output = await this.executor(toolName, toolInput);
    return {
      role: "tool",
      tool_call_id: toolCall.id,
      content: typeof output === 'object' ? JSON.stringify(output) : String(output),
      _btp_receipt: decision.merkle_turn_receipt,
      _executor_invocations: 1
    };
  }
}
```

---

## 5. Adapter Conformance Checklist

To certify an adapter as BTP-compliant, it must pass the following checks in `tests/test_universal_compatibility.js`:
- [x] Pre-execution interception precedes any downstream side effect.
- [x] Zero downstream executor invocations for `rm -rf /`, `DROP TABLE`, and credential reads.
- [x] Emits valid Ed25519 Merkle turn receipts for allowed calls.
- [x] Handles malformed, null, and non-string inputs cleanly without crashing.
- [x] Preserves approval requirements (`HOLD_FOR_APPROVAL`) without dispatch.
