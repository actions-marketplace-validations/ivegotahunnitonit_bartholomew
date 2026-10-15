# Google Cloud & Vertex AI OEM Licensing Term Sheet
## Embedded In-Process Agentic Runtime Protection (ARP) Gateway for Vertex AI Agents

**Licensor**: Bartholomew Security / Sovereign Autonomous Circularity Network  
**Licensee**: Google LLC (Google Cloud / Vertex AI Division)  
**Document Type**: Non-Binding Commercial OEM Term Sheet & Architecture Brief  
**Classification**: Commercial Proprietary  

---

### 1. Technology Overview & Strategic Alignment

Google Cloud is investing heavily in **Vertex AI Agent Builder**, allowing enterprise customers to build autonomous agents that query BigQuery, execute Cloud Functions, and interface with enterprise databases. However, enterprise CISOs routinely delay production agent deployment due to the **Agentic Risk Surface**:
- Prompt injections causing unauthorized BigQuery data exfiltration.
- Unconstrained SQL statements (`DROP TABLE`, `TRUNCATE`, unindexed full scans).
- Environment secret exposure through unvetted container subshells.

Bartholomew provides a **sub-35 microsecond in-process execution gate** that embeds directly into Vertex AI Agent runtimes and Google Cloud Run containers. Unlike cloud-to-cloud security proxies that add 150ms-400ms per agent step, Bartholomew runs locally inside the process memory space, performing deterministic AST validation before the tool invocation touches any Google Cloud API.

```
+--------------------------------------------------------------------------+
| Google Cloud Run / Vertex AI Agent Container                             |
|                                                                          |
|  [ Gemini 1.5 / 2.0 ] ---> [ Agent Decision Engine ]                     |
|                                    |                                     |
|                                    v                                     |
|                      +-----------------------------+                     |
|                      | Bartholomew Embedded Gate   | < 35 microseconds   |
|                      | - AST Syntax & Tool Policy  | Fail-Closed In-Memory|
|                      | - Format-Preserving Vault   | Zero Exfiltration   |
|                      +-----------------------------+                     |
|                                    | (Authorized Actions Only)           |
|                                    v                                     |
|                     [ BigQuery / Spanner / GCS ]                         |
+--------------------------------------------------------------------------+
```

---

### 2. Commercial Terms & Pricing Structure

#### Option A: Enterprise OEM Master Embedded License
* **License Grant**: Non-exclusive, worldwide license to embed, compile, and distribute Bartholomew Keystone runtime binaries (`libbtpguard.so`, WASM, and Python native extensions) within Vertex AI Agent Builder SDK and Google Cloud SDK.
* **Annual Base Fee**: **$1,250,000 USD / year** (includes Tier-3 engineering escalations and dedicated quarterly invariant updates).
* **Usage Tier Royalty**: $0.00010 USD per 1,000 guarded agent tool executions billed through Google Cloud Marketplace.

#### Option B: Google Cloud Marketplace Managed Gateway (Co-Sell)
* **Structure**: Bartholomew is deployed as a Premier Managed Add-on in Google Cloud Marketplace.
* **Revenue Share**: 80% to Licensor / 20% to Google Cloud Marketplace.
* **Enterprise SaaS Pricing**: $2,500 USD / tenant / month for unlimited intra-cluster tool validation.

---

### 3. Core Deliverables & Technical Integration

1. **Native Google Cloud Container Base Image**:
   Pre-hardened container images for Cloud Run and Google Kubernetes Engine (GKE) pre-loaded with `btp-guard` in-process hooks.
2. **BigQuery & Spanner Deterministic Filter**:
   Pre-execution SQL AST validation preventing accidental large-scale scans, unpartitioned table drops, and unauthorized schema alterations.
3. **Hardware Enclave (Confidential VMs) Support**:
   Support for AMD SEV-SNP and Intel TDX confidential computing environments on GCP, storing Bartholomew Merkle audit roots in tamper-evident hardware memory.

---

### 4. Mutual Invariants & Governance

* **Zero Data Retention**: The embedded engine retains zero prompt text, operating entirely in volatile RAM with immediate zeroization.
* **Fail-Closed SLA**: If the execution gate detects policy evasion or memory tampering, the tool call terminates deterministically in <35 microseconds with an RFC 8785 signed error receipt.
