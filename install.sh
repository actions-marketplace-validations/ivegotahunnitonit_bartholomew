#!/usr/bin/env bash
# ==============================================================================
# Bartholomew Trust Protocol (BTP v6.5.8) — Standalone Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/install.sh | bash
# ==============================================================================

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"
RESET="\033[0m"

echo -e "${CYAN}======================================================================${RESET}"
echo -e "${BOLD}${CYAN}  BARTHOLOMEW KEYSTONE GUARD — STANDALONE INSTALLER (BTP v6.5.8)${RESET}"
echo -e "  Sub-35µs In-Process Agentic Runtime Protection (ARP) Gateway"
echo -e "${CYAN}======================================================================${RESET}"

# Check for Node.js
if command -v node >/dev/null 2>&1; then
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -ge 18 ]; then
        echo -e "${GREEN}[+] Detected Node.js $(node -v) (Satisfies >= 18.0.0 requirement)${RESET}"
    else
        echo -e "${YELLOW}[!] Warning: Node.js version is older than v18.0.0. Updating recommended.${RESET}"
    fi
else
    echo -e "${YELLOW}[!] Node.js not detected. You can run pre-compiled binaries or install Node.js >= 18.${RESET}"
fi

# Install btp-guard globally via npm if npm is present
if command -v npm >/dev/null 2>&1; then
    echo -e "[*] Installing btp-guard v6.5.8 globally via npm..."
    npm install -g btp-guard --silent || npm install -g btp-guard
    echo -e "${GREEN}[+] btp-guard installed globally.${RESET}"
fi

# Initialize workspace security invariants if inside a git repository
if [ -d ".git" ]; then
    echo -e "[*] Arming current workspace with Bartholomew security invariants..."
    mkdir -p .btp
    cat << 'EOF' > .btp/invariants.json
{
  "protocol_version": "BTP v6.5.8",
  "organization": "Sovereign Enterprise",
  "armed_at": "INSTALL_TIME",
  "enforcement_mode": "fail-closed",
  "max_execution_latency_us": 35,
  "rules": {
    "block_destructive_shell": true,
    "block_destructive_sql": true,
    "block_path_traversal": true,
    "redact_in_flight_secrets": true,
    "require_merkle_receipts": true
  }
}
EOF
    echo -e "${GREEN}[+] Workspace armed (.btp/invariants.json configured).${RESET}"
fi

echo -e "\n${CYAN}======================================================================${RESET}"
echo -e "${BOLD}${GREEN}  INSTALLATION COMPLETE!${RESET}"
echo -e "${CYAN}======================================================================${RESET}"
echo -e "  Quick-Start Commands:"
echo -e "    1. One-Command Immunizer : ${BOLD}npx btp-guard auto${RESET}"
echo -e "    2. Real-Time Web & PWA   : ${BOLD}npx btp-guard hud${RESET}"
echo -e "    3. Guard Any Command     : ${BOLD}npx btp-guard run <command>${RESET}"
echo -e "    4. 5-Attack Test-Drive   : ${BOLD}npx btp-guard test-drive${RESET}"
echo -e "${CYAN}======================================================================${RESET}"
