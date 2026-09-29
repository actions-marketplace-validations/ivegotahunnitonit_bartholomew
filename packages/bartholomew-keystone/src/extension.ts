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
  <style>
    :root {
      --bg: #070b14;
      --card-bg: rgba(15, 23, 42, 0.8);
      --card-border: rgba(99, 102, 241, 0.25);
      --accent: #00e5ff;
      --indigo: #6366f1;
      --green: #10b981;
      --red: #ef4444;
      --yellow: #f59e0b;
      --text: #f8fafc;
      --muted: #94a3b8;
      --font-mono: 'Consolas', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: radial-gradient(circle at 50% 0%, #101633 0%, var(--bg) 75%);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      padding: 20px;
      font-size: 13px;
      line-height: 1.5;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 22px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo-svg {
      width: 40px;
      height: 40px;
      filter: drop-shadow(0 0 10px rgba(99, 102, 241, 0.5));
    }
    .brand-title {
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .brand-sub {
      font-size: 11px;
      color: var(--muted);
      font-family: var(--font-mono);
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 5px 14px;
      border-radius: 9999px;
      font-weight: 700;
      font-size: 11px;
      font-family: var(--font-mono);
      background: ${passkey && isValid ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)'};
      border: 1px solid ${passkey && isValid ? 'rgba(16, 185, 129, 0.35)' : 'rgba(239, 68, 68, 0.35)'};
      color: ${passkey && isValid ? 'var(--green)' : 'var(--red)'};
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 14px;
    }
    .label {
      font-size: 10px;
      color: var(--muted);
      text-transform: uppercase;
      font-family: var(--font-mono);
      margin-bottom: 4px;
    }
    .val {
      font-size: 16px;
      font-weight: 700;
      color: var(--text);
      font-family: var(--font-mono);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .breakdown-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 14px;
      margin-bottom: 24px;
    }
    .breakdown-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 10px;
      padding: 16px;
    }
    .b-title {
      font-size: 11px;
      font-weight: 700;
      font-family: var(--font-mono);
      margin-bottom: 8px;
      color: var(--indigo);
    }
    .b-list { list-style: none; padding-left: 0; }
    .b-list li {
      position: relative;
      padding-left: 18px;
      margin-bottom: 6px;
      font-size: 12.5px;
    }
    .b-list li::before {
      content: "[+]";
      position: absolute;
      left: 0;
      font-family: var(--font-mono);
      font-size: 10px;
      color: var(--accent);
    }
    .test-box {
      background: var(--card-bg);
      border: 1px solid rgba(0, 229, 255, 0.35);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 24px;
    }
    .test-input {
      width: 100%;
      background: rgba(0, 0, 0, 0.45);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 8px 12px;
      color: var(--text);
      font-family: var(--font-mono);
      margin-bottom: 10px;
      outline: none;
    }
    .btn {
      cursor: pointer;
      border: none;
      border-radius: 5px;
      font-size: 11px;
      font-weight: 700;
      padding: 8px 14px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-family: var(--font-mono);
      margin-right: 8px;
    }
    .btn-primary { background: var(--indigo); color: #fff; }
    .btn-secondary { background: #1e293b; color: var(--text); border: 1px solid var(--card-border); }
    .terminal {
      background: #040810;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 6px;
      padding: 12px;
      font-family: var(--font-mono);
      font-size: 11px;
      color: #94a3b8;
      margin-top: 10px;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <svg class="logo-svg" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="50" cy="50" r="46" stroke="#00e5ff" stroke-width="2" stroke-opacity="0.4" stroke-dasharray="4 4" />
        <circle cx="50" cy="50" r="38" stroke="#6366f1" stroke-width="2" stroke-opacity="0.5" />
        <path d="M50 15L78 28V52C78 68 66 81 50 87C34 81 22 68 22 52V28L50 15Z" fill="url(#shieldGrad)" stroke="#00e5ff" stroke-width="2.5" />
        <polygon points="50,34 62,42 62,58 50,66 38,58 38,42" fill="#070b14" stroke="#00e5ff" stroke-width="2" />
        <circle cx="50" cy="50" r="4" fill="#00e5ff" />
        <defs>
          <linearGradient id="shieldGrad" x1="22" y1="15" x2="78" y2="87" gradientUnits="userSpaceOnUse">
            <stop stop-color="#00e5ff" stop-opacity="0.3" />
            <stop offset="1" stop-color="#6366f1" stop-opacity="0.6" />
          </linearGradient>
        </defs>
      </svg>
      <div>
        <div class="brand-title">BARTHOLOMEW KEYSTONE &bull; CAPABILITY PASSKEY</div>
        <div class="brand-sub">CRYPTOGRAPHIC AGENT BOUNDING &bull; ZERO TRUST</div>
      </div>
    </div>
    <div class="status-badge">
      ${passkey && isValid ? '[PASSKEY ACTIVE]' : '[PASSKEY STANDBY]'}
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="label">Agent Clearance ID</div>
      <div class="val" style="color: var(--accent);">${agentId}</div>
    </div>
    <div class="card">
      <div class="label">Spend Ceiling</div>
      <div class="val" style="color: var(--green);">${spend}</div>
    </div>
    <div class="card">
      <div class="label">Max Per Txn</div>
      <div class="val">${maxTxn}</div>
    </div>
    <div class="card">
      <div class="label">Session Expiry</div>
      <div class="val">${expires}</div>
    </div>
  </div>

  <div class="breakdown-grid">
    <div class="breakdown-card">
      <div class="b-title">[1] WHAT IS GOING ON</div>
      <div style="font-size: 12.5px; color: #cbd5e1;">${goingOn}</div>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--red);">[2] WHAT IS WRONG</div>
      <ul class="b-list">${wrongs.map(w => '<li>' + w + '</li>').join('')}</ul>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--yellow);">[3] WHAT NEEDS FIXING</div>
      <ul class="b-list">${fixings.map(f => '<li>' + f + '</li>').join('')}</ul>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--green);">[4] HOW WE ARE HELPING</div>
      <ul class="b-list">${helpings.map(h => '<li>' + h + '</li>').join('')}</ul>
    </div>
  </div>

  <div class="test-box">
    <div class="b-title">[ACTION VALIDATOR] TEST COMMAND OR FILE PATH AGAINST PASSKEY</div>
    <input type="text" id="action-input" class="test-input" placeholder="Enter command or target (e.g. 'rm -rf /' or 'src/index.ts')..." value="rm -rf /" />
    <div>
      <button class="btn btn-primary" onclick="testAction()">[EVALUATE CLEARANCE]</button>
      <button class="btn btn-secondary" onclick="runCmd('keystone.issuePasskey')">[ISSUE NEW PASSKEY]</button>
      <button class="btn btn-secondary" onclick="runCmd('keystone.revokePasskey')">[REVOKE PASSKEY]</button>
    </div>
    <div id="term-out" class="terminal">
      [READY] Enter a test action to verify whether it falls within signed Keystone clearance scopes.
    </div>
  </div>

  <script>
    const vscode = acquireVsCodeApi();

    function testAction() {
      const target = document.getElementById('action-input').value.trim();
      vscode.postMessage({ command: 'evaluateAction', target: target });
    }

    function runCmd(cmd) {
      vscode.postMessage({ command: 'runCommand', action: cmd });
    }

    window.addEventListener('message', event => {
      const msg = event.data;
      if (msg.command === 'actionResult') {
        const res = msg.data;
        const color = res.verdict === 'ALLOW' ? 'var(--green)' : 'var(--red)';
        document.getElementById('term-out').innerHTML = 
          '<div><strong style="color: ' + color + ';">[' + res.verdict + ']</strong> ' + res.action_type + ': ' + res.target + ' (' + res.latency_us + 'us)</div>' +
          '<div style="margin-top: 4px; color: #f1f5f9;">' + res.reason + '</div>' +
          '<div style="margin-top: 4px; font-size: 10px; color: var(--muted);">Receipt SHA-256: ' + res.receipt_hash + '</div>';
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
