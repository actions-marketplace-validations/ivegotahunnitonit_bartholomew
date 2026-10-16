# ==============================================================================
# Bartholomew Trust Protocol (BTP v6.5.8) — Windows Standalone Installer
# Usage: irm https://raw.githubusercontent.com/ivegotahunnitonit/bartholomew/main/install.ps1 | iex
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  BARTHOLOMEW KEYSTONE GUARD -- WINDOWS INSTALLER (BTP v6.5.8)" -ForegroundColor Cyan
Write-Host "  Sub-35us In-Process Agentic Runtime Protection (ARP) Gateway"
Write-Host "======================================================================" -ForegroundColor Cyan

# Check Node.js
if (Get-Command node -ErrorAction SilentlyContinue) {
    $nodeVer = (node -v)
    Write-Host "[+] Detected Node.js $nodeVer" -ForegroundColor Green
} else {
    Write-Host "[!] Node.js not detected in PATH. Please install Node.js >= 18 from nodejs.org" -ForegroundColor Yellow
}

# Install btp-guard globally via npm
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "[*] Installing btp-guard v6.5.8 globally via npm..." -ForegroundColor Cyan
    npm install -g btp-guard
    Write-Host "[+] btp-guard installed successfully." -ForegroundColor Green
}

# Initialize workspace security invariants if inside a git repository
if (Test-Path ".git") {
    Write-Host "[*] Arming current workspace with Bartholomew security invariants..." -ForegroundColor Cyan
    if (!(Test-Path ".btp")) {
        New-Item -ItemType Directory -Path ".btp" -Force | Out-Null
    }
    $invariants = @{
        protocol_version = "BTP v6.5.8"
        organization = "Sovereign Enterprise"
        armed_at = (Get-Date).ToString("o")
        enforcement_mode = "fail-closed"
        max_execution_latency_us = 35
        rules = @{
            block_destructive_shell = $true
            block_destructive_sql = $true
            block_path_traversal = $true
            redact_in_flight_secrets = $true
            require_merkle_receipts = $true
        }
    } | ConvertTo-Json -Depth 5
    $invariants | Out-File -FilePath ".btp\invariants.json" -Encoding utf8
    Write-Host "[+] Workspace armed (.btp/invariants.json configured)." -ForegroundColor Green
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Quick-Start Commands:"
Write-Host '    1. One-Command Immunizer : npx btp-guard auto'
Write-Host '    2. Real-Time Web & PWA   : npx btp-guard hud'
Write-Host '    3. Guard Any Command     : npx btp-guard run <command>'
Write-Host '    4. 5-Attack Test-Drive   : npx btp-guard test-drive'
Write-Host "======================================================================" -ForegroundColor Cyan
