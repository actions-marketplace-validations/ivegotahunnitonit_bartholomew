# Microsoft AutoGen & Semantic Kernel Middleware Integration Guide
## In-Process Sub-35µs Tool Invariants, AST Sandboxing, and Merkle Compliance for Microsoft AI Runtimes

**Protocol Version**: Bartholomew Trust Protocol (BTP v6.5.7)  
**Target Runtimes**: 
- Microsoft AutoGen (`autogen`, `pyautogen`, AutoGen GroupChat, AutoGen 0.4+)
- Microsoft Semantic Kernel (`semantic-kernel` Python, .NET / C#, Node.js)
**Packages**:
- NPM Package: `btp-guard` (`import { MicrosoftAutoGenMiddleware, MicrosoftSemanticKernelMiddleware } from 'btp-guard/microsoft'`)
- Python Package: `btp_guard` (`from btp_guard.integrations import btp_autogen_guard, btp_semantic_kernel_guard`)

---

### 1. Executive Summary

Autonomous agent swarms built with **Microsoft AutoGen** and enterprise applications powered by **Microsoft Semantic Kernel** face critical deployment barriers:
1. **Unbounded Code Execution**: AutoGen `UserProxyAgent` and `ConversableAgent` code execution blocks can trigger destructive operating system commands (`rm -rf`, raw disk writes, reverse shells).
2. **PII and Secret Ingestion**: Prompts sent to Azure OpenAI or local models often contain unmasked enterprise credentials, violating HIPAA, PCI-DSS, and GDPR.
3. **Execution Latency Penalty**: Adding external cloud moderation proxies adds 150ms-400ms per agent step.

Bartholomew Keystone provides native, in-process middleware for both AutoGen and Semantic Kernel. It executes in **<35 microseconds**, enforces deterministic AST boundaries, tokenizes secrets in-flight, and produces tamper-evident RFC 8785 Ed25519 Merkle receipts.

```
+--------------------------------------------------------------------------+
| Microsoft AI Agent Runtime (AutoGen / Semantic Kernel)                   |
|                                                                          |
|   ConversableAgent / Kernel Plugin                                       |
|          |                                                               |
|          v                                                               |
|   +-------------------------------------------------------------+        |
|   | Bartholomew Keystone In-Process Middleware                  |        |
|   | - Sub-35us AST Tool Grammar Validation                      |        |
|   | - Copy-on-Write Memory Buffer Snapshot                      |        |
|   | - Format-Preserving Secret Redaction                        |        |
|   | - RFC 8785 Ed25519 Merkle Turn Receipt Generator            |        |
|   +-------------------------------------------------------------+        |
|          | (Allowed)                              | (Vetoed)             |
|          v                                        v                      |
|   Execute Shell / SQL / Tool              Block in <35us                 |
|                                           Throw BTP-VETO Exception       |
+--------------------------------------------------------------------------+
```

---

### 2. AutoGen Integration (Node.js & TypeScript)

Install the package:
```bash
npm install btp-guard
```

Use `MicrosoftAutoGenMiddleware`:
```javascript
import { MicrosoftAutoGenMiddleware } from 'btp-guard/microsoft';

const guard = new MicrosoftAutoGenMiddleware({
  strictAst: true,
  blockDestructiveCommands: true,
  redactSecrets: true
});

// 1. Hook message transmissions before they reach conversational agents
const messageResult = guard.processMessageBeforeSend(senderAgent, receiverAgent, message);
if (!messageResult.proceed) {
  console.error("Message blocked:", messageResult.error);
}

// 2. Intercept code execution blocks before running on host or container
const execResult = await guard.interceptCodeExecution(codeBlock, 'python', senderAgent);
if (!execResult.allowed) {
  console.error("Execution vetoed:", execResult.output);
  // Exit code 126 returned automatically
}
```

---

### 3. Semantic Kernel Integration (Node.js & TypeScript)

Semantic Kernel allows registering invocation filters via `onFunctionInvocation` and `onPromptRendering`:

```javascript
import { MicrosoftSemanticKernelMiddleware } from 'btp-guard/microsoft';

const skGuard = new MicrosoftSemanticKernelMiddleware();

// Register with Semantic Kernel invocation pipeline
kernel.addFunctionInvocationFilter(async (context, next) => {
  return await skGuard.onFunctionInvocation(context, next);
});

// Register prompt rendering filter to block credential leakage
kernel.addPromptRenderingFilter(async (context, next) => {
  return await skGuard.onPromptRendering(context, next);
});
```

---

### 4. AutoGen Integration (Python)

Install the Python package:
```bash
pip install btp-guard
```

Wrap your AutoGen agents in one line:
```python
from autogen import AssistantAgent, UserProxyAgent
from btp_guard.integrations.autogen import btp_autogen_guard

# Initialize AutoGen agents
assistant = AssistantAgent("assistant", llm_config={"model": "gpt-4o"})
user_proxy = UserProxyAgent("user_proxy", code_execution_config={"work_dir": "coding"})

# Attach Bartholomew Keystone in-process invariant guard
btp_autogen_guard(assistant, strict_ast=True)
btp_autogen_guard(user_proxy, strict_ast=True)

# Safe to initiate group chat or autonomous code execution
user_proxy.initiate_chat(assistant, message="Analyze data in ./workspace")
```

---

### 5. Semantic Kernel Integration (Python)

```python
import semantic_kernel as sk
from btp_guard.integrations.semantic_kernel import btp_semantic_kernel_guard

kernel = sk.Kernel()

# Attach Bartholomew security filter to Kernel
guard_filter = btp_semantic_kernel_guard(kernel, strict_mode=True)

# All kernel plugins and prompt renders are now guarded with <35us latency
```

---

### 6. Pull Request Submission Manifest for Microsoft Repositories

When submitting to `microsoft/autogen` and `microsoft/semantic-kernel`:

* **Title**: `feat(security): In-process sub-35µs execution guardrails and Merkle receipts via Bartholomew (BTP)`
* **Description**:
  > Adds a zero-overhead, in-process execution boundary filter for AutoGen and Semantic Kernel. Intercepts shell, SQL, and tool calls deterministically using Abstract Syntax Tree inspection (<35µs latency), scrubs credentials in-flight, and generates tamper-evident RFC 8785 Ed25519 Merkle receipts for enterprise SOC 2 and HIPAA compliance.
* **Test Verification**: 
  - Node.js suite: `node packages/npm_package/test_microsoft_middleware.js` (10/10 PASS)
  - Python suite: Verified with `SemanticKernelBTPFilter` and `btp_autogen_guard`
