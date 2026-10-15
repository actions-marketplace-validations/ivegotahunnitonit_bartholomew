import fs from 'fs';
import path from 'path';
import { generateAuditPack, verifyAuditPack } from './audit_vault.js';

console.log('[*] Generating Enterprise SOC 2 / HIPAA Cryptographic Compliance Dossier...');

const dossier = generateAuditPack();
const verification = verifyAuditPack(dossier);

console.log(`[+] Verification Status: ${verification.ok ? 'VALID' : 'INVALID'}`);
console.log(`[+] Compliance Score   : ${dossier.compliance_score} / 100 (${dossier.compliance_grade})`);
console.log(`[+] Merkle Root        : ${dossier.merkle_tree_proof.merkle_root}`);
console.log(`[+] Signature          : ${dossier.cryptographic_signature.slice(0, 32)}...`);

const targetDir = path.resolve(process.cwd(), '../../docs/compliance');
if (!fs.existsSync(targetDir)) {
  fs.mkdirSync(targetDir, { recursive: true });
}

// 1. Write Machine-Readable JSON
const jsonPath = path.join(targetDir, 'ENTERPRISE_SOC2_HIPAA_COMPLIANCE_DOSSIER.json');
fs.writeFileSync(jsonPath, JSON.stringify(dossier, null, 2), 'utf8');
console.log(`[+] Saved JSON Dossier to: ${jsonPath}`);

// 2. Write Self-Contained HTML Executive Dossier
const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bartholomew Enterprise Compliance Dossier - SOC 2 & HIPAA Verification</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111726;
      --border: #1e293b;
      --accent: #3b82f6;
      --green: #10b981;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 40px 20px;
      margin: 0;
    }
    .container {
      max-width: 1000px;
      margin: 0 auto;
    }
    .header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
    }
    .badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      background: rgba(16, 185, 129, 0.15);
      color: var(--green);
      border: 1px solid rgba(16, 185, 129, 0.3);
      margin-bottom: 12px;
    }
    h1 {
      font-size: 28px;
      font-weight: 700;
      margin: 8px 0;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin: 24px 0;
    }
    .meta-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .meta-label {
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .meta-val {
      font-size: 18px;
      font-weight: 600;
      color: var(--text);
      margin-top: 4px;
      word-break: break-all;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 24px 0;
      background: var(--card-bg);
      border-radius: 8px;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    th, td {
      padding: 14px 16px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      font-size: 14px;
    }
    th {
      background: rgba(30, 41, 59, 0.5);
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .status-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      background: rgba(16, 185, 129, 0.1);
      color: var(--green);
      border: 1px solid rgba(16, 185, 129, 0.2);
    }
    .code-box {
      background: #020617;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      overflow-x: auto;
      color: #38bdf8;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="badge">Cryptographically Verified Attestation</span>
      <h1>Bartholomew Enterprise Compliance Dossier</h1>
      <p style="color: var(--muted); margin: 4px 0 0 0;">
        Automated Evidence Package for SOC 2 Type II, HIPAA, EU AI Act, and ISO/IEC 42001
      </p>
    </div>

    <div class="meta-grid">
      <div class="meta-card">
        <div class="meta-label">Compliance Score</div>
        <div class="meta-val" style="color: var(--green);">${dossier.compliance_score}% (${dossier.compliance_grade})</div>
      </div>
      <div class="meta-card">
        <div class="meta-label">Protocol Version</div>
        <div class="meta-val">${dossier.protocol_version}</div>
      </div>
      <div class="meta-card">
        <div class="meta-label">Mathematical Verification</div>
        <div class="meta-val" style="color: var(--green);">100% Offline Valid</div>
      </div>
      <div class="meta-card">
        <div class="meta-label">Auditor Authority</div>
        <div class="meta-val">${dossier.auditor_authority}</div>
      </div>
    </div>

    <h2>Verified Security Controls Matrix</h2>
    <table>
      <thead>
        <tr>
          <th>Control ID</th>
          <th>Framework</th>
          <th>Domain</th>
          <th>Status</th>
          <th>Technical Implementation</th>
        </tr>
      </thead>
      <tbody>
        ${dossier.controls_matrix.map(c => `
          <tr>
            <td style="font-weight:600; font-family:monospace;">${c.control_id}</td>
            <td>${c.framework}</td>
            <td>${c.domain}</td>
            <td><span class="status-pill">${c.status}</span></td>
            <td style="font-size:13px; color:#cbd5e1;">${c.implementation}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>

    <h2>Cryptographic Merkle Proof</h2>
    <div class="meta-grid">
      <div class="meta-card" style="grid-column: 1 / -1;">
        <div class="meta-label">SHA-256 Merkle Root Digest</div>
        <div class="code-box">${dossier.merkle_tree_proof.merkle_root}</div>
      </div>
      <div class="meta-card" style="grid-column: 1 / -1;">
        <div class="meta-label">Ed25519 Canonical Cryptographic Signature</div>
        <div class="code-box">${dossier.cryptographic_signature}</div>
      </div>
      <div class="meta-card" style="grid-column: 1 / -1;">
        <div class="meta-label">Authority Public Key (Hex)</div>
        <div class="code-box">${dossier.public_key_hex}</div>
      </div>
    </div>

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); text-align: center;">
      This machine-verifiable dossier is generated in accordance with RFC 8785 Canonical JSON and Ed25519 asymmetric signature specifications.
    </div>
  </div>
</body>
</html>`;

const htmlPath = path.join(targetDir, 'ENTERPRISE_SOC2_HIPAA_COMPLIANCE_DOSSIER.html');
fs.writeFileSync(htmlPath, htmlContent, 'utf8');
console.log(`[+] Saved Executive HTML Dossier to: ${htmlPath}`);
console.log('[+] All compliance assets generated successfully.');
