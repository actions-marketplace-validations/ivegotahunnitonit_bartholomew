# Bartholomew BTP v6.5.6 — Universal Compatibility Matrix & Integration Guide

**Document Identifier**: `docs/architecture/universal-compatibility-matrix.md`  
**Protocol Version**: Bartholomew Trust Protocol (BTP) v6.5.6  
**Shared Core**: `packages/npm_package/agent_core.js` (`enforceToolBoundary`)  
**Universal Adapters**: `packages/npm_package/universal_adapters.js`  
**Automated Test Suite**: `tests/test_universal_compatibility.js` (35 / 35 assertions passed)  
**Machine-Readable Evidence**: `audit_evidence/universal_compatibility_results.json`  
**Evaluation Date**: 2026-10-14  

---

## 1. Universal Integration & Compatibility Matrix

| Integration Category | Client / Framework / Model Target | Adapter Implementation | Verification Status | Allowed Executions | Denied Executions |
|---|---|---|---|---|---|
| **MCP Protocol** | Anthropic Claude Desktop, Cursor MCP, Open-source MCP Hosts | `MCPAdapter` | **VERIFIED WITH LIMITATIONS** | Dispatched (Invocations: 1) | Zero Invocations (0) |
| **Frontier LLM Tools** | OpenAI GPT-4o, Anthropic Claude 3.5 Sonnet, Google Gemini | `OpenAIToolAdapter` | **VERIFIED WITH LIMITATIONS** | Dispatched (Invocations: 1) | Zero Invocations (0) |
| **Agent Frameworks** | LangChain.js, LangGraph, LlamaIndex, AutoGen, CrewAI | `LangChainFrameworkAdapter` | **VERIFIED WITH LIMITATIONS** | Dispatched (Invocations: 1) | Zero Invocations (0) |
| **Terminal / CLI** | Mediated child_process, shell launchers, script runners | `MediatedProcessAdapter` | **VERIFIED WITH LIMITATIONS** | Spawned (Invocations: 1) | Zero Invocations (0) |
| **Multi-Agent Systems** | Supervisor-worker swarms, delegation chains, task dispatchers | `MultiAgentDelegationAdapter` | **VERIFIED WITH LIMITATIONS** | Delegated (Invocations: 1) | Zero Invocations (0) |
| **IDE Extensions** | VS Code, Cursor, Windsurf, Open VSX | `bartholomew-guard-vscode` (v6.5.6) | **LOCAL & REGISTRY VERIFIED** | Hooked via editor API | Zero Invocations (0) |
| **Direct Subprocess** | Raw `child_process.spawn` outside BTP wrappers | None (Unmediated) | **UNSUPPORTED / BYPASS** | Direct Execution (1) | Not Intercepted |
| **OS Block Devices** | Direct raw disk writes (`dd if=/dev/zero of=/dev/sda`) | None (Host OS level) | **UNSUPPORTED / OS SANDBOX REQUIRED** | Not Intercepted | Not Intercepted |

---

## 2. Setup Instructions for Verified Integrations

### Integration A: MCP Agents (Claude Desktop, Cursor, Claude Code)
Add to your `claude_desktop_config.json` or `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "btp-guard": {
      "command": "npx",
      "args": ["-y", "btp-guard@6.5.6", "mcp-shield", "--", "your_target_server"]
    }
  }
}
```

### Integration B: OpenAI / Frontier Model Tool Calling
```javascript
import { OpenAIToolAdapter } from 'btp-guard/universal_adapters';

const adapter = new OpenAIToolAdapter(async (toolName, toolInput) => {
  // Your downstream executor
  return await executeToolLocally(toolName, toolInput);
});

// Pass OpenAI response tool_calls directly through adapter
for (const toolCall of completion.choices[0].message.tool_calls) {
  const toolResponse = await adapter.handleToolCall(toolCall);
  conversation.push(toolResponse); // Appends safe result or BTP_POLICY_VETO
}
```

### Integration C: LangChain.js / LlamaIndex / Agent Frameworks
```javascript
import { LangChainFrameworkAdapter } from 'btp-guard/universal_adapters';
import { DynamicStructuredTool } from '@langchain/core/tools';

const adapter = new LangChainFrameworkAdapter();
const safeShellTool = adapter.wrapTool(new DynamicStructuredTool({
  name: "run_command",
  description: "Executes shell commands",
  schema: z.object({ command: z.string() }),
  func: async ({ command }) => execSync(command).toString()
}));
```

### Integration D: Mediated Process Spawner (CLI & Scripts)
```javascript
import { MediatedProcessAdapter } from 'btp-guard/universal_adapters';
import { exec } from 'child_process';
import util from 'util';
const execPromise = util.promisify(exec);

const spawner = new MediatedProcessAdapter(async (fullCommand, env) => {
  return await execPromise(fullCommand, { env });
});

// Safe execution:
const res = await spawner.executeCommand("git", ["status"]); // ALLOWED
const deny = await spawner.executeCommand("rm", ["-rf", "/"]); // DENIED (exit 126, ZERO process calls)
```

---

## 3. Confirmed Bypasses & Boundary Limitations

1. **Uninstrumented Raw Subprocess Invocation**:
   - Calling `child_process.spawn()` or `exec()` directly without passing through `MediatedProcessAdapter` or an in-process wrapper bypasses BTP completely.
   - **Remediation**: BTP must be deployed inside an OS container (Docker, gVisor) or non-root namespace where raw execution permissions are restricted.
2. **Multi-Stage Nested Base64 Obfuscation**:
   - Double-encoded commands (`base64 | base64 | sh`) evade the current single-stage regular expression.
   - **Remediation**: Implement recursive unescaping in the AST pre-unpacker.
3. **Dynamic Shell Variable Concatenation**:
   - Split commands (`A=rm; B=' -rf /'; $A$B`) evade static string pattern matching without a shell expansion emulator.
   - **Remediation**: Parse command AST using an in-process shell lexer (e.g. `bash-parser`).

---

## 4. Prioritized Compatibility Expansion Roadmap

1. **Phase 1: Recursive In-Process Obfuscation Normalizer (High Priority)**:
   - Enhance `enforceToolBoundary` with an iterative unescaping loop (depth limit 3) to normalize nested base64, hexadecimal (`\xHH`), and octal (`\0NNN`) escapes before AST invariant matching.
2. **Phase 2: Automated OS Process Monkey-Patching / Pre-Loader (Medium Priority)**:
   - Provide an optional Node.js `--require btp-guard/process_shim.js` pre-loader that automatically wraps `child_process.spawn`, `exec`, and `fork` at the runtime level to prevent raw uninstrumented bypasses.
3. **Phase 3: Python Async Middleware Parity for AutoGen & CrewAI (Medium Priority)**:
   - Extend `src/cross_framework_adapter.py` with native Python `asyncio` middleware decorators matching `packages/npm_package/universal_adapters.js`.
4. **Phase 4: Ephemeral eBPF / Container Sandbox Integration (Long-term)**:
   - Package reference Docker / Compose / devcontainer configurations with seccomp profiles enforcing execution boundaries at the Linux kernel level.
