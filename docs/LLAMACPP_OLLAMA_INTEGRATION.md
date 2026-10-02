# Bartholomew Guard for Llama.cpp & Ollama
**Air-Gapped, Sub-35µs Deterministic Execution Armor for Local AI Agents**

---

### The Problem with Local AI Agents
Running open-weight models (`Llama-3`, `DeepSeek-Coder`, `Qwen-2.5`, `Mistral`) locally via **`llama.cpp`** or **Ollama** gives you complete privacy, zero censorship, and offline execution.

However, the moment you attach local models to agentic loops (allowing them to execute bash commands, edit files, query databases, or call MCP tools), **you have zero safety net**:
* Open-weight models hallucinate destructive commands (`rm -rf /`, formatting drives, clobbering repos).
* Runaway recursive loops burn 100% CPU/GPU and overheat workstations.
* Local agents lack cryptographic audit trails and delegation boundaries.

Traditional cloud guardrails require sending your data to external APIs—completely defeating the purpose of running local models!

**Bartholomew provides 100% local, offline, sub-35 microsecond execution armor.**

```
 ┌────────────────────────────────────────────────────────┐
 │   CLIENT / AGENT IDE                                   │
 │   Cursor / Continue.dev / Open WebUI / AutoGen / LangGraph│
 └───────────────────────────┬────────────────────────────┘
                             │ (POST /v1/chat/completions)
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │   BARTHOLOMEW LOCAL GATEWAY (:8081)                    │
 │   • Sub-35µs In-Process AST Gate                       │
 │   • Prompt Injection & Context Scrubber                │
 │   • Structured Remediation Envelopes                   │
 │   • RFC 8785 Ed25519 Merkle Audit Receipts             │
 └───────────────────────────┬────────────────────────────┘
                             │ (Transparent Passthrough)
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │   LOCAL AI ENGINE (:8080 / :11434)                     │
 │   llama.cpp server  |  Ollama  |  LM Studio  |  vLLM   │
 └────────────────────────────────────────────────────────┘
```

---

### Quickstart (1-Line CLI)

#### 1. With `llama.cpp` Server
Start your standard `llama.cpp` server on port 8080:
```bash
./llama-server -m models/deepseek-coder-7b.Q4_K_M.gguf --port 8080
```

In a separate terminal, launch the Bartholomew Guard:
```bash
# Using Python
btp wrap --upstream http://localhost:8080 --port 8081

# Or using Node.js / npx
npx btp-guard wrap --upstream http://localhost:8080 --port 8081
```

#### 2. With Ollama
Start Ollama (default port 11434):
```bash
ollama run qwen2.5-coder:7b
```

Wrap Ollama with Bartholomew:
```bash
btp wrap --upstream http://localhost:11434/v1 --port 8081
```

Now, point your agents, IDEs, or GUIs to **`http://localhost:8081/v1`**.

---

### How It Works: Self-Healing vs. Hard Crashing

When a raw local model proposes a destructive action (e.g., executing `rm -rf /` or escaping directories via `../../etc/shadow`), Bartholomew does **not** simply crash the agent or dump an ugly stack trace.

Instead, Bartholomew intercepts the tool call in **<35 microseconds** and returns a **Structured Remediation Envelope**:

```json
{
  "status": "VETOED_BY_LOCAL_GUARD",
  "original_tool": "run_shell",
  "remediation": {
    "allowed": false,
    "verdict": "REMEDIATED",
    "rule_id": "BTP-SHELL-001",
    "safe_alternative": "rm -rf ./tmp/btp_sandbox/*",
    "remediation_hint": "Re-scoped dangerous deletion from root filesystem to isolated sandbox directory.",
    "context_tokens_conserved": 1420
  }
}
```

The local model reads the safe alternative in its next generation pass and **autonomously self-corrects**, allowing complex local agent workflows to proceed safely without human panic.

---

### Programmatic Python Integration

If you write local Python agents using `llama_cpp`:

```python
from btp_guard.llamacpp_adapter import guard_llama_cpp, evaluate_local_tool_call

# 1. Start the guarded gateway proxy in the background
proxy = guard_llama_cpp(upstream_url="http://localhost:8080", port=8081)

# 2. Or evaluate tool calls directly in-process (<35µs)
is_safe, envelope = evaluate_local_tool_call(
    tool_name="bash",
    arguments={"cmd": "rm -rf / --no-preserve-root"}
)

if not is_safe:
    print(f"Intercepted: {envelope['remediation_hint']}")
    print(f"Safe Alternative: {envelope['safe_alternative']}")
```

---

### Client IDE Configuration

#### Continue.dev (`~/.continue/config.json`)
```json
{
  "models": [
    {
      "title": "Local DeepSeek (Bartholomew Guarded)",
      "provider": "openai",
      "model": "deepseek-coder",
      "apiBase": "http://localhost:8081/v1"
    }
  ]
}
```

#### Open WebUI / Jan / LM Studio
Set the OpenAI API Base URL to:
```
http://localhost:8081/v1
```

---

### Technical Specifications
* **Overhead Latency**: Sub-35 microseconds ($<0.035$ ms)
* **External Dependencies**: Zero (Pure standard library Python & Node.js)
* **Network Egress**: 0 bytes (100% offline, air-gapped capable)
* **Cryptographic Attestation**: Ed25519 signatures & RFC 8785 JSON canonicalization on all intercepted events
