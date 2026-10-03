# Bartholomew Protocol - Global Ecosystem & International Agent Runtimes
========================================================================

Bartholomew provides zero-latency deterministic AST invariant protection, fail-closed command guards, and sovereign cryptographic receipts for autonomous agent frameworks across the globe.

---

## 1. Zero-Friction Global Interception (The Universal Gateway)

Regardless of what country or framework your autonomous agents originate from, **zero code rewrites** are required. Simply route your LLM requests through Bartholomew's local proxy daemon on port `8081`:

```bash
# Start the local gateway (Sub-35µs AST evaluation, local SQLite receipt ledger)
python -m btp_guard.cli gateway start --port 8081

# In any shell, container, or agent runtime:
export OPENAI_BASE_URL="http://127.0.0.1:8081/v1"
```

Every tool proposal, command string, and code snippet will be inspected in-process in sub-35 microseconds before execution. Destructive attacks (`rm -rf`, disk wipes, fork bombs) are vetoed with fail-closed HTTP 403 responses.

---

## 2. Regional & International Framework Adapters

### A. APAC & Greater China Ecosystem

#### 1. MetaGPT (DeepWisdom)
Used across Asia for multi-agent software development organizations.
```python
from btp_guard.integrations.metagpt import BtpMetaGPTGuard

guard = BtpMetaGPTGuard(role_name="MetaGPT-Engineer")
guard.validate_code(generated_code)  # Blocks destructive scripts before compilation
```

#### 2. Dify.AI
Open-source LLM application engine widely deployed in enterprise workflows across Asia and Europe.
```python
from btp_guard.integrations.dify import BtpDifyGuard

guard = BtpDifyGuard(workflow_id="finance-automation")
guard.validate_node_execution("code_node", {"code": user_code})
```

#### 3. Qwen-Agent (Alibaba Cloud)
Leading open-weight tool-calling and code interpreter runtime.
```python
from btp_guard.integrations.qwen_agent import BtpQwenAgentGuard

guard = BtpQwenAgentGuard(agent_name="qwen-doc-assistant")
guard.validate_fn_call("code_interpreter", {"code": python_snippet})
```

#### 4. ChatDev (OpenBMB / Tsinghua)
Multi-agent collaborative software engineering teams.
```python
from btp_guard.integrations.chatdev import BtpChatDevGuard

guard = BtpChatDevGuard(org_name="ChatDev-Team")
guard.validate_phase_output("Coding", code_artifact)
```

---

### B. Europe & EMEA Ecosystem

#### 1. Smolagents (Hugging Face / France)
Ultra-lightweight code and tool-calling agent framework.
```python
from btp_guard.integrations.smolagents import BtpSmolagentsGuard

guard = BtpSmolagentsGuard()
guard.validate_code("import os; os.system('ls')")
```

#### 2. Haystack (deepset / Germany)
Production-grade enterprise agent pipelines and search components.
```python
from btp_guard.integrations.haystack import BtpHaystackGuard

guard = BtpHaystackGuard(pipeline_name="eu-compliance-pipeline")
guard.validate_tool_call("sql_query_tool", {"query": "SELECT * FROM users"})
```

---

### C. Americas & Multi-National Ecosystem

* **CrewAI**: `from btp_guard.integrations.crewai import BtpCrewAIGuard`
* **LangGraph & LangChain**: `from btp_guard.integrations.langgraph import LangGraphBTPGuard`
* **AutoGen (Microsoft)**: `from btp_guard.integrations.autogen import AutoGenBTPInterceptor`
* **CAMEL-AI**: `from btp_guard.integrations.camel import BtpCamelGuard`
* **OpenDevin / OpenHands**: `from btp_guard.integrations.opendevin import BtpOpenDevinGuard`

---

## 3. Commercial Fleet Tiers & Evaluation Keys

Bartholomew operates on a dual-track model designed to protect independent builders while monetizing enterprise fleets:

| Tier | Capacity | Key Requirement | Target Audience |
| :--- | :--- | :--- | :--- |
| **Community Free** | Up to 5 concurrent agents | None (Automatic) | Individual developers worldwide |
| **Team Mesh** | 6 - 50 agents | `BTP-EVAL` License | Startups & agent fleets |
| **Enterprise SOC2** | 50+ agents & SIEM export | Enterprise Passkey | Regulated organizations |

To generate a 30-day signed evaluation license for scaling fleets:
```bash
python -m btp_guard.cli gateway license --company "Acme Global AI" --days 30
```
