import json
from pathlib import Path

new_targets = [
    {
        "target_id": "FUNDED-028",
        "name": "Suno AI",
        "email": "security@suno.ai",
        "url": "https://suno.ai",
        "funding_round": "$125M Series B (Lightspeed, Matrix Partners)",
        "role_focus": "Voice & Conversational AI",
        "audit_wedge": "Generative audio watermarking bypass, copyright asset exposure, and unshielded API generation loop.",
        "tech_stack": "PyTorch / Python / CUDA / Distributed Audio Synthesizer",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-029",
        "name": "Udio",
        "email": "security@udio.com",
        "url": "https://udio.com",
        "funding_round": "$10M Seed (Andreessen Horowitz)",
        "role_focus": "Voice & Conversational AI",
        "audit_wedge": "Unconsented audio prompt injection, model weight tampering, and unauthorized web scraping triggers.",
        "tech_stack": "Python / TensorRT / WebRTC Audio Streaming",
        "tier": "Tier 1: Startup Invariant Package ($3,500)",
        "enterprise_intent_score": 85
    },
    {
        "target_id": "FUNDED-030",
        "name": "Phind",
        "email": "security@phind.com",
        "url": "https://phind.com",
        "funding_round": "$17M Series A (DST Global, Lightspeed)",
        "role_focus": "Autonomous Coding Agent",
        "audit_wedge": "Code search AST execution escape, developer repo token extraction, and malicious snippet generation.",
        "tech_stack": "Python / Rust / Custom Code Indexer",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-031",
        "name": "Braintrust",
        "email": "security@braintrustdata.com",
        "url": "https://braintrust.dev",
        "funding_round": "$36M Series A (Andreessen Horowitz, Elad Gil)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "Evaluation dataset poisoning, agent test harness credential leakage, and prompt metric spoofing.",
        "tech_stack": "TypeScript / Python / PostgreSQL / DuckDB",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-032",
        "name": "Humanloop",
        "email": "security@humanloop.com",
        "url": "https://humanloop.com",
        "funding_round": "$5M Seed (Y Combinator, Index Ventures)",
        "role_focus": "Enterprise Swarm Orchestration",
        "audit_wedge": "Prompt management tenant privilege escalation, unverified LLM tool calls, and EU AI Act logging gaps.",
        "tech_stack": "Python / TypeScript / Kubernetes",
        "tier": "Tier 1: Startup Invariant Package ($3,500)",
        "enterprise_intent_score": 85
    },
    {
        "target_id": "FUNDED-033",
        "name": "Arize AI",
        "email": "security@arize.com",
        "url": "https://arize.com",
        "funding_round": "$38M Series B (TCV, Battery Ventures)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "LLM observability telemetry injection, unredacted corporate PII logging, and rogue agent loop triggers.",
        "tech_stack": "Python / Go / OpenTelemetry / ClickHouse",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-034",
        "name": "Weights & Biases",
        "email": "security@wandb.com",
        "url": "https://wandb.ai",
        "funding_round": "$250M Series C ($1B+ valuation, Coatue, Insight)",
        "role_focus": "Enterprise Swarm Orchestration",
        "audit_wedge": "Artifact registry supply chain tampering, CI/CD training script breakout, and API key exposure.",
        "tech_stack": "Python / Go / GraphQL / Kubernetes",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 100
    },
    {
        "target_id": "FUNDED-035",
        "name": "Together AI",
        "email": "security@together.ai",
        "url": "https://together.ai",
        "funding_round": "$106M Series A ($1.25B valuation, Salesforce Ventures)",
        "role_focus": "Enterprise Swarm Orchestration",
        "audit_wedge": "Cloud GPU cluster tenant breakout, model endpoint prompt manipulation, and unmetered token depletion.",
        "tech_stack": "C++ / Python / CUDA / Distributed vLLM Engine",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 100
    },
    {
        "target_id": "FUNDED-036",
        "name": "Groq",
        "email": "security@groq.com",
        "url": "https://groq.com",
        "funding_round": "$640M Series D ($2.8B valuation, BlackRock)",
        "role_focus": "Enterprise Swarm Orchestration",
        "audit_wedge": "Ultra-fast LPU inference buffer overflow, real-time unshielded tool streaming, and memory leakage.",
        "tech_stack": "C++ / Assembly / Custom LPU Architecture",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 100
    },
    {
        "target_id": "FUNDED-037",
        "name": "Cerebras Systems",
        "email": "security@cerebras.net",
        "url": "https://cerebras.net",
        "funding_round": "$250M Series F ($4B+ valuation)",
        "role_focus": "Enterprise Swarm Orchestration",
        "audit_wedge": "Wafer-scale compute tenant isolation failure, model artifact exfiltration, and unverified batch jobs.",
        "tech_stack": "C++ / PyTorch / Custom Silicon Driver",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 100
    },
    {
        "target_id": "FUNDED-038",
        "name": "Fireworks AI",
        "email": "security@fireworks.ai",
        "url": "https://fireworks.ai",
        "funding_round": "$52M Series B (Benchmark, Sequoia Capital)",
        "role_focus": "Enterprise Swarm Orchestration",
        "audit_wedge": "Compound AI system function calling escaping, unshielded tool API triggers, and prompt injection.",
        "tech_stack": "C++ / PyTorch / Fast LoRA Runtime",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-039",
        "name": "Modal Labs",
        "email": "security@modal.com",
        "url": "https://modal.com",
        "funding_round": "$16M Series A (Redpoint Ventures, Amplify)",
        "role_focus": "Autonomous Coding Agent",
        "audit_wedge": "Serverless container root privilege breakout, arbitrary subshell execution, and cross-mount leaks.",
        "tech_stack": "Rust / Python / Linux Namespaces / gVisor",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-040",
        "name": "Replit",
        "email": "security@replit.com",
        "url": "https://replit.com",
        "funding_round": "$100M Series B ($1.16B valuation, a16z)",
        "role_focus": "Autonomous Coding Agent",
        "audit_wedge": "Replit Agent arbitrary terminal breakout, unshielded package installation, and secret environment scraping.",
        "tech_stack": "Go / Python / TypeScript / Nix Environment",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 100
    },
    {
        "target_id": "FUNDED-041",
        "name": "Sourcegraph (Cody)",
        "email": "security@sourcegraph.com",
        "url": "https://sourcegraph.com",
        "funding_round": "$125M Series D (Andreessen Horowitz, Sequoia)",
        "role_focus": "Autonomous Coding Agent",
        "audit_wedge": "Enterprise codebase indexing leakage, Cody agent command execution breakout, and MCP tool drift.",
        "tech_stack": "Go / TypeScript / Rust / Tree-sitter",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 100
    },
    {
        "target_id": "FUNDED-042",
        "name": "Tabnine",
        "email": "security@tabnine.com",
        "url": "https://tabnine.com",
        "funding_round": "$25M Series B (Telstra Ventures, Atlassian)",
        "role_focus": "Autonomous Coding Agent",
        "audit_wedge": "On-premise model telemetry leakage, unauthorized file access, and unverified AI patch application.",
        "tech_stack": "Rust / Python / Local Language Models",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-043",
        "name": "Anyscale (Ray)",
        "email": "security@anyscale.com",
        "url": "https://anyscale.com",
        "funding_round": "$100M Series C ($1B valuation, a16z, Addition)",
        "role_focus": "Enterprise Swarm Orchestration",
        "audit_wedge": "Distributed Ray cluster remote code execution, unauthenticated worker nodes, and cross-actor data exposure.",
        "tech_stack": "C++ / Python / Distributed Actor Architecture",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 100
    },
    {
        "target_id": "FUNDED-044",
        "name": "Predibase",
        "email": "security@predibase.com",
        "url": "https://predibase.com",
        "funding_round": "$12.2M Series A (Felicis Ventures)",
        "role_focus": "Enterprise Swarm Orchestration",
        "audit_wedge": "Fine-tuning data extraction, multi-tenant LoRA adapter poisoning, and unshielded SQL tool queries.",
        "tech_stack": "Python / Ludwig / LoRAX Inference Server",
        "tier": "Tier 1: Startup Invariant Package ($3,500)",
        "enterprise_intent_score": 85
    },
    {
        "target_id": "FUNDED-045",
        "name": "Cleanlab",
        "email": "security@cleanlab.ai",
        "url": "https://cleanlab.ai",
        "funding_round": "$25M Series A (Menlo Ventures, TQ Ventures)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "Data trust integrity spoofing, adversarial label perturbation, and unvalidated dataset mutation.",
        "tech_stack": "Python / NumPy / Scikit-learn / FastAPI",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 90
    },
    {
        "target_id": "FUNDED-046",
        "name": "Arthur AI",
        "email": "security@arthur.ai",
        "url": "https://arthur.ai",
        "funding_round": "$42M Series B (Acrew Capital, Greycroft)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "Agent firewall hallucination evasion, unmonitored agentic trajectory drift, and compliance report spoofing.",
        "tech_stack": "Python / Go / PostgreSQL / Shield Architecture",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-047",
        "name": "Patronus AI",
        "email": "security@patronus.ai",
        "url": "https://patronus.ai",
        "funding_round": "$17M Series A (Notable Capital, Lightspeed)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "Automated jailbreak evasion, evaluation rubric poisoning, and unverified agent scoring logs.",
        "tech_stack": "Python / FastAPI / Custom Evaluation Runtimes",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-048",
        "name": "Lakera AI",
        "email": "security@lakera.ai",
        "url": "https://lakera.ai",
        "funding_round": "$20M Series A (Eurazeo, Fly Ventures)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "Prompt injection firewall bypass, latency spikes (>100ms) degrading agent responsiveness, and secret leakage.",
        "tech_stack": "Python / Rust / Gandalf Benchmark System",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-049",
        "name": "Protect AI",
        "email": "security@protectai.com",
        "url": "https://protectai.com",
        "funding_round": "$35M Series A (Evolution Equity Partners)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "ML supply chain pickle deserialization exploit, model scanner evasion, and unverified notebook execution.",
        "tech_stack": "Python / Go / Guardian Gateway",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    },
    {
        "target_id": "FUNDED-050",
        "name": "Confident AI (DeepEval)",
        "email": "security@confident-ai.com",
        "url": "https://confident-ai.com",
        "funding_round": "$3M Seed (Y Combinator)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "Unit test assertion bypass, synthetic test set poisoning, and unshielded CI/CD test harness runner.",
        "tech_stack": "Python / DeepEval / Pytest Plugin Architecture",
        "tier": "Tier 1: Startup Invariant Package ($3,500)",
        "enterprise_intent_score": 85
    },
    {
        "target_id": "FUNDED-051",
        "name": "Galileo AI",
        "email": "security@galileo.ai",
        "url": "https://galileo.ai",
        "funding_round": "$45M Series B (Scale Venture Partners)",
        "role_focus": "Security & AI Evaluation",
        "audit_wedge": "Agent chain evaluation blindspots, unmonitored tool delegation loops, and SOC 2 evidence audit gaps.",
        "tech_stack": "Python / TypeScript / Vector Store Connectors",
        "tier": "Tier 2: Enterprise Fleet Audit ($7,500)",
        "enterprise_intent_score": 95
    }
]

fpath = Path("data/freshly_funded_ai_startups_targets.json")
with open(fpath, "r", encoding="utf-8") as f:
    data = json.load(f)

existing_ids = {t["target_id"] for t in data["targets"]}
added = 0
for nt in new_targets:
    if nt["target_id"] not in existing_ids:
        data["targets"].append(nt)
        added += 1

data["total"] = len(data["targets"])
with open(fpath, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(f"Added {added} targets. Total funded targets: {data['total']}")
