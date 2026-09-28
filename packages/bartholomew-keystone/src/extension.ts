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
  statusBarItem.command = 'keystone.inspectClearance';
  statusBarItem.text = `$(key) KEYSTONE: ARMED`;
  statusBarItem.tooltip = `Bartholomew Keystone -- Agent Capability Passkey Active | Click to inspect clearance`;
  context.subscriptions.push(statusBarItem);
  statusBarItem.show();

  function getPasskeyPath(): string {
    const rootPath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '.';
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
    fs.writeFileSync(savePath, JSON.stringify(passkey, null, 2), 'utf-8');

    vscode.window.showInformationMessage(
      `Keystone Passkey issued for '${agentId}'! Clearance active for 2 hours.`,
      'Copy Token ID',
      'Inspect Scopes'
    ).then((choice: string) => {
      if (choice === 'Copy Token ID') {
        vscode.env.clipboard.writeText(passkey.passkey_id);
      } else if (choice === 'Inspect Scopes') {
        vscode.commands.executeCommand('keystone.inspectClearance');
      }
    });

    statusBarItem.text = `$(key) KEYSTONE: ${agentId} ARMED`;
  });

  // 3. Command: Inspect Active Agent Clearance
  const inspectCmd = vscode.commands.registerCommand('keystone.inspectClearance', () => {
    const passkey = getActivePasskey();
    if (!passkey) {
      vscode.window.showInformationMessage(
        'No active Keystone Passkey found in this workspace.',
        'Issue New Passkey'
      ).then((choice: string) => {
        if (choice === 'Issue New Passkey') {
          vscode.commands.executeCommand('keystone.issuePasskey');
        }
      });
      return;
    }

    const isValid = engine.verifyPasskey(passkey);
    const status = isValid ? 'VALID & ACTIVE' : 'EXPIRED / INVALID';
    const writeScopes = passkey.scopes.files?.allow_write?.join(', ') || 'None (Read-Only)';
    const spend = passkey.scopes.budget?.max_spend_usd ?? 0;
    const maxTxn = passkey.scopes.budget?.max_per_txn_usd ?? 0;

    vscode.window.showInformationMessage(
      `Keystone Clearance [${status}]\n\nAgent: ${passkey.agent_id}\nToken: ${passkey.passkey_id}\nExpires: ${new Date(passkey.expires_at).toLocaleTimeString()}\nWrite Scopes: ${writeScopes}\nSpend Ceiling: $${spend.toFixed(2)} (Max/Txn: $${maxTxn.toFixed(2)})`,
      'Revoke Key',
      'Audit Receipts',
      'Renew Key'
    ).then((choice: string) => {
      if (choice === 'Revoke Key') {
        vscode.commands.executeCommand('keystone.revokePasskey');
      } else if (choice === 'Audit Receipts') {
        vscode.commands.executeCommand('keystone.auditReceipts');
      } else if (choice === 'Renew Key') {
        vscode.commands.executeCommand('keystone.issuePasskey');
      }
    });
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

  context.subscriptions.push(issueCmd, inspectCmd, revokeCmd, validateCmd, auditCmd);
}

export function deactivate() {}
