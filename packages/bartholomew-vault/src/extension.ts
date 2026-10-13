/**
 * Bartholomew Vault - VS Code / Cursor / Windsurf Extension
 * ==========================================================
 * Provides in-process data tokenization, PII sanitization, and
 * just-in-time OS detokenization for AI coding assistants.
 */

import * as vscode from 'vscode';
import { VaultEngine } from './vault_engine';

let vaultEngine: VaultEngine;
let statusBarItem: vscode.StatusBarItem;
let totalTokensVaulted = 0;

export function activate(context: vscode.ExtensionContext) {
  vaultEngine = new VaultEngine();

  // Create Status Bar Item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 102);
  statusBarItem.command = 'vault.inspectVault';
  updateStatusBar();
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // 1. Tokenize Selection
  context.subscriptions.push(
    vscode.commands.registerCommand('vault.tokenizeSelection', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('Bartholomew Vault: No active editor to tokenize.');
        return;
      }

      const selection = editor.selection;
      const text = editor.document.getText(selection.isEmpty ? undefined : selection);
      if (!text) {
        vscode.window.showInformationMessage('Bartholomew Vault: Selection is empty.');
        return;
      }

      const config = vscode.workspace.getConfiguration('vault');
      const formatPreserving = config.get<boolean>('formatPreserving', true);

      const result = vaultEngine.tokenize(text, { formatPreserving });
      if (result.tokenCount === 0) {
        vscode.window.showInformationMessage('Bartholomew Vault: No sensitive secrets or PII detected in selection.');
        return;
      }

      await editor.edit((editBuilder: vscode.TextEditorEdit) => {
        if (selection.isEmpty) {
          const fullRange = new vscode.Range(
            editor.document.positionAt(0),
            editor.document.positionAt(text.length)
          );
          editBuilder.replace(fullRange, result.sanitized);
        } else {
          editBuilder.replace(selection, result.sanitized);
        }
      });

      totalTokensVaulted += result.tokenCount;
      updateStatusBar();

      vscode.window.showInformationMessage(
        `[Bartholomew Vault] Sanitized ${result.tokenCount} sensitive item(s) in ${result.latencyUs}us. Safe for cloud AI.`
      );
    })
  );

  // 2. Detokenize Selection
  context.subscriptions.push(
    vscode.commands.registerCommand('vault.detokenizeSelection', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;

      const selection = editor.selection;
      const text = editor.document.getText(selection.isEmpty ? undefined : selection);
      if (!text) return;

      const restored = vaultEngine.detokenize(text);
      if (restored === text) {
        vscode.window.showInformationMessage('Bartholomew Vault: No active surrogate tokens found in selection.');
        return;
      }

      await editor.edit((editBuilder: vscode.TextEditorEdit) => {
        if (selection.isEmpty) {
          const fullRange = new vscode.Range(
            editor.document.positionAt(0),
            editor.document.positionAt(text.length)
          );
          editBuilder.replace(fullRange, restored);
        } else {
          editBuilder.replace(selection, restored);
        }
      });

      vscode.window.showInformationMessage('[Bartholomew Vault] Detokenized selected items.');
    })
  );

  // 3. Inspect Vault
  context.subscriptions.push(
    vscode.commands.registerCommand('vault.inspectVault', async () => {
      const active = vaultEngine.getActiveSurrogateSummary();
      if (active.length === 0) {
        vscode.window.showInformationMessage('[Bartholomew Vault] In-memory vault is empty (0 active surrogates).');
        return;
      }

      const items: vscode.QuickPickItem[] = active.map(entry => ({
        label: `$(key) ${entry.surrogate}`,
        description: `Category: ${entry.category}`,
        detail: `Masked Preview: ${entry.preview}`
      }));

      await vscode.window.showQuickPick(items, {
        placeHolder: `Active In-Memory Surrogates (${active.length} protected)`
      });
    })
  );

  // 4. Clear Vault
  context.subscriptions.push(
    vscode.commands.registerCommand('vault.clearVault', () => {
      vaultEngine.clearVault();
      totalTokensVaulted = 0;
      updateStatusBar();
      vscode.window.showInformationMessage('[Bartholomew Vault] In-memory surrogate vault wiped.');
    })
  );

  // 5. Export Compliance Report (Drata / Vanta Dossier)
  context.subscriptions.push(
    vscode.commands.registerCommand('vault.exportComplianceReport', async () => {
      const dossier = vaultEngine.exportComplianceDossier();
      const content = JSON.stringify(dossier, null, 2);

      const doc = await vscode.workspace.openTextDocument({
        content,
        language: 'json'
      });
      await vscode.window.showTextDocument(doc);

      vscode.window.showInformationMessage(
        `[Bartholomew Vault] Generated Drata/Vanta Audit Dossier [${dossier.dossier_id}].`
      );
    })
  );

  // 6. Test JIT Dispatch Detokenization
  context.subscriptions.push(
    vscode.commands.registerCommand('vault.testDispatch', async () => {
      // Simulate an agent preparing to run an API call with a vaulted token
      const mockSample = 'sk-proj-DEMO_SECRET_KEY_FOR_TESTING_1234567890';
      const tokenized = vaultEngine.tokenize(mockSample);
      const agentCommand = `curl -X POST https://api.openai.com/v1/chat -H "Authorization: Bearer ${tokenized.sanitized}"`;

      const dispatch = vaultEngine.detokenizeProcessExecution(agentCommand);

      vscode.window.showInformationMessage(
        `[Bartholomew Vault] JIT OS Dispatch Test: Swapped ${dispatch.swappedCount} surrogate token(s) into OS execution environment. Cloud LLM saw: [${tokenized.sanitized}].`
      );
    })
  );
}

function updateStatusBar() {
  if (!statusBarItem) return;
  statusBarItem.text = `$(shield) BTP Vault: ${totalTokensVaulted} Vaulted`;
  statusBarItem.tooltip = 'Bartholomew Vault: In-Process PII & Secret Tokenizer Active (<35µs)';
}

export function deactivate() {
  if (vaultEngine) {
    vaultEngine.clearVault();
  }
}
