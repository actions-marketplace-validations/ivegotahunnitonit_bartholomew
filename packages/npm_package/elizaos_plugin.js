/**
 * Bartholomew BTP v6.5.6 — ElizaOS Real-Time Agent Plugin
 * Path: packages/npm_package/elizaos_plugin.js
 * 
 * Provides native ElizaOS (v2) action evaluators, security gates, and vault
 * protections for 24/7 autonomous agents running on Twitter, Discord, and Telegram.
 */

import { enforceToolBoundary } from './agent_core.js';
import { UniversalBTPDispatcher } from './universal_adapters.js';

export const bartholomewSecurityEvaluator = {
  name: 'BARTHOLOMEW_AST_SECURITY_EVALUATOR',
  similes: ['SECURITY_EVALUATOR', 'EXECUTION_FIREWALL', 'INVARIANT_GATE'],
  description: 'Evaluates candidate agent actions and generated bash/SQL/code against zero-trust AST invariants before execution (<35µs).',
  validate: async (runtime, message) => {
    return !!(message && message.content);
  },
  handler: async (runtime, message, state) => {
    const text = typeof message.content === 'string' ? message.content : (message.content.text || '');
    
    // Check if the agent is about to emit or execute a command
    const evaluation = enforceToolBoundary('bash', { command: text }, {
      agent_id: runtime?.agentId || 'eliza-agent',
      session_id: message?.roomId || 'default'
    });

    if (evaluation.allowed === false || evaluation.verdict === 'DENY') {
      return {
        allowed: false,
        rule_id: evaluation.rule_id,
        reason: evaluation.reason,
        remediation: evaluation.safe_alternative || evaluation.suggested_alternative
      };
    }

    return {
      allowed: true,
      receipt_id: evaluation.receipt?.receipt_id
    };
  }
};

export const bartholomewGateAction = {
  name: 'VERIFY_EXECUTION_SAFETY',
  similes: ['CHECK_SAFETY', 'AUDIT_ACTION', 'VERIFY_TOOL'],
  description: 'Cryptographically verifies and evaluates any tool call or external API request before execution.',
  validate: async (runtime, message) => true,
  handler: async (runtime, message, state, options, callback) => {
    const rawAction = options?.action || { tool: 'bash', input: { command: message.content.text } };
    const result = await UniversalBTPDispatcher.executeGuarded(
      rawAction,
      async (act) => ({ status: 'EXECUTED_SAFELY', target: act }),
      { agent_id: runtime?.agentId || 'eliza-agent' }
    );

    if (callback) {
      callback({
        text: result.decision === 'DENY' 
          ? `[Bartholomew Blocked] ${result.reason}. Suggested alternative: ${result.suggested_alternative || 'None'}`
          : `[Bartholomew Verified] Action cleared AST gate in ${result.evaluation_latency_us}µs.`
      });
    }

    return result.decision !== 'DENY';
  },
  examples: [
    [
      { user: '{{user1}}', content: { text: 'Execute rm -rf /var/data' } },
      { user: '{{agent}}', content: { text: '[Bartholomew Blocked] BTP-AST-001: Root filesystem mutation prohibited.' } }
    ]
  ]
};

export const bartholomewPlugin = {
  name: 'bartholomew-guard',
  description: 'Sub-35µs Zero-Trust AST Security Gate, Secret Vault, and Non-Human Identity Attestation for ElizaOS agents.',
  actions: [bartholomewGateAction],
  evaluators: [bartholomewSecurityEvaluator],
  providers: [
    {
      get: async (runtime, message, state) => {
        return 'Bartholomew Trust Protocol active (SLA <35µs, Zero-Trust Invariants enabled).';
      }
    }
  ]
};

export default bartholomewPlugin;
