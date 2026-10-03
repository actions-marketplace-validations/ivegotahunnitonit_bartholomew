"""
Bartholomew Protocol - Industry-Specific Policy Templates (v6.4.0)
==================================================================
Pre-configured, least-privilege policies tailored to unblock enterprise
SOC 2, HIPAA, LegalTech confidentiality, and multi-tenant dev shop requirements.
"""

from typing import Dict, Any

TEMPLATES: Dict[str, Dict[str, Any]] = {
    "fintech": {
        "name": "Fintech & Banking SOC 2 Compliance Pack",
        "description": "Enforces strict non-destructive shell boundaries, prevents API token egress, and mandates cryptographic audit receipts.",
        "filename": "policy.fintech.yaml",
        "yaml": """# Bartholomew Enterprise Policy -- Fintech & Banking (SOC 2 Type II)
version: "6.4.0"
compliance_frameworks:
  - "SOC2_TYPE_II"
  - "PCI_DSS_v4.0"
  - "ISO_27001"

invariants:
  block_destructive_shell: true
  mask_credentials: true
  quarantine_pipe_to_shell: true
  enforce_immutable_audit_receipts: true
  fail_closed_precommit: true
  max_session_spend_usd: 50.00
  max_transaction_spend_usd: 15.00

allowed_commands:
  - "git status"
  - "git diff"
  - "git commit"
  - "npm test"
  - "npm run build"
  - "pytest"
  - "cargo test"
  - "mvn test"

blocked_patterns:
  - "rm -rf"
  - "drop table"
  - "drop database"
  - "truncate"
  - "format "
  - "/etc/shadow"
  - "stripe_secret_key"
  - "aws_secret_access_key"

audit:
  engine: "Ed25519-Merkle-Ledger"
  log_path: ".btp/audit_ledger.db"
  require_signed_receipts: true
"""
    },
    "healthcare": {
        "name": "Healthcare SaaS & HIPAA Data Boundary Pack",
        "description": "Enforces deterministic regex masking for patient identifiers (MRN, SSN, EHR tokens) and locks database mock write paths.",
        "filename": "policy.healthcare.yaml",
        "yaml": """# Bartholomew Enterprise Policy -- Healthcare & Life Sciences (HIPAA Security Rule)
version: "6.4.0"
compliance_frameworks:
  - "HIPAA_SECURITY_RULE"
  - "HITECH"
  - "HITRUST_CSF"

invariants:
  block_destructive_shell: true
  mask_credentials: true
  mask_patient_phi: true
  sandbox_database_mocks: true
  enforce_immutable_audit_receipts: true
  fail_closed_precommit: true

phi_patterns:
  - "\\b\\d{3}-\\d{2}-\\d{4}\\b"           # US SSN
  - "\\bMRN[0-9]{6,10}\\b"                   # Medical Record Number
  - "\\b[A-Z]{2}[0-9]{7}\\b"                  # National Health Identifier
  - "patient_name|dob|diagnosis|prescription" # Common PHI parameter names

blocked_patterns:
  - "cat .env"
  - "type .env"
  - "curl *phi*"
  - "wget *phi*"
  - "drop table"
  - "rm -rf"

audit:
  engine: "Ed25519-Merkle-Ledger"
  log_path: ".btp/audit_ledger.db"
  require_signed_receipts: true
"""
    },
    "legaltech": {
        "name": "LegalTech & Contract NDA Confidentiality Pack",
        "description": "Strips client names, privileged work product, and unredacted contract clauses from outbound model prompts and tools.",
        "filename": "policy.legaltech.yaml",
        "yaml": """# Bartholomew Enterprise Policy -- LegalTech & Contract Automation (Confidentiality)
version: "6.4.0"
compliance_frameworks:
  - "ATTORNEY_CLIENT_PRIVILEGE"
  - "ABA_MODEL_RULE_1.6"
  - "SOC2_CONFIDENTIALITY"

invariants:
  block_destructive_shell: true
  mask_credentials: true
  mask_confidential_contract_clauses: true
  enforce_immutable_audit_receipts: true
  fail_closed_precommit: true

confidentiality_filters:
  - "CONFIDENTIAL & PROPRIETARY"
  - "NON-DISCLOSURE AGREEMENT"
  - "ATTORNEY WORK PRODUCT"
  - "SETTLEMENT PRIVILEGE"

blocked_patterns:
  - "rm -rf"
  - "curl -d @*.doc*"
  - "curl -d @*.pdf"
  - "cat .env"

audit:
  engine: "Ed25519-Merkle-Ledger"
  log_path: ".btp/audit_ledger.db"
"""
    },
    "devshop": {
        "name": "Dev Shop & Agency Multi-Client Isolation Pack",
        "description": "Protects agency codebases and client credentials from rogue contractor scripts and runaway agent token loops.",
        "filename": "policy.devshop.yaml",
        "yaml": """# Bartholomew Team Policy -- Agency & Dev Shop Multi-Tenant Isolation
version: "6.4.0"
team:
  type: "AGENCY_DEV_SHOP"
  enforce_client_codebase_isolation: true

invariants:
  block_destructive_shell: true
  mask_credentials: true
  quarantine_pipe_to_shell: true
  max_session_spend_usd: 25.00
  max_transaction_spend_usd: 10.00
  fail_closed_precommit: true

blocked_patterns:
  - "rm -rf"
  - "git push *--force*"
  - "cat .env*"
  - "sk-*"
  - "npm publish"

audit:
  engine: "Ed25519-Merkle-Ledger"
  log_path: ".btp/audit_ledger.db"
"""
    }
}


def get_template(industry: str) -> Dict[str, Any]:
    return TEMPLATES.get(industry.lower(), TEMPLATES["fintech"])


def list_templates() -> Dict[str, str]:
    return {k: v["name"] for k, v in TEMPLATES.items()}
