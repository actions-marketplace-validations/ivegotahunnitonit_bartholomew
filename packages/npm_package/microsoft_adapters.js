/**
 * Bartholomew BTP v6.5.7 — Microsoft Agentic Middleware Suite
 * Path: packages/npm_package/microsoft_adapters.js
 * 
 * Production-ready in-process security and execution middleware for:
 * 1. Microsoft AutoGen (ConversableAgent, AssistantAgent, UserProxyAgent, GroupChat)
 * 2. Microsoft Semantic Kernel (Kernel Plugin Filters, FunctionInvocationFilter)
 * 
 * Provides sub-35µs AST inspection, copy-on-write micro-rollbacks, and
 * RFC 8785 Ed25519 Merkle audit turn receipts for Microsoft AI runtimes.
 */

import { enforceToolBoundary, auditToolBoundary, BTP_CAPABILITY_MANIFEST } from './agent_core.js';
import crypto from 'crypto';

/**
 * 1. Microsoft AutoGen In-Process Middleware
 * 
 * Intercepts AutoGen message exchanges, code execution blocks,
 * and tool calls before they run on the operating system or reach agents.
 */
export class MicrosoftAutoGenMiddleware {
  constructor(options = {}) {
    this.options = {
      strictAst: true,
      blockDestructiveCommands: true,
      redactSecrets: true,
      maxExecutionLatencyUs: 35,
      ...options
    };
    this.auditLog = [];
  }

  /**
   * Hook for AutoGen ConversableAgent.register_hook("process_message_before_send")
   */
  processMessageBeforeSend(sender, recipient, message) {
    const rawContent = typeof message === 'string' ? message : (message?.content || JSON.stringify(message));
    const senderId = sender?.name || sender?.id || 'autogen_sender';
    const recipientId = recipient?.name || recipient?.id || 'autogen_recipient';

    const decision = enforceToolBoundary('autogen_message', {
      sender: senderId,
      recipient: recipientId,
      content: rawContent
    }, this.options);

    const logEntry = {
      timestamp: new Date().toISOString(),
      type: 'message_filter',
      sender: senderId,
      recipient: recipientId,
      allowed: decision.allowed,
      verdict: decision.verdict,
      rule_id: decision.rule_id || null,
      merkle_turn_receipt: decision.merkle_turn_receipt
    };
    this.auditLog.push(logEntry);

    if (!decision.allowed) {
      return {
        proceed: false,
        intercepted: true,
        error: `[BTP-VETO] Message blocked by ${decision.rule_id}: ${decision.reason}`,
        verdict: decision.verdict,
        rule_id: decision.rule_id,
        remediation: decision.remediation_hint || null
      };
    }

    return {
      proceed: true,
      intercepted: false,
      message,
      merkle_turn_receipt: decision.merkle_turn_receipt
    };
  }

  /**
   * Hook for AutoGen code execution blocks before execution on host/container
   */
  async interceptCodeExecution(code, language = 'python', agentContext = {}) {
    const agentId = agentContext.name || 'autogen_code_executor';
    
    // Deterministic tool boundary check for command/code
    const decision = enforceToolBoundary('run_command', {
      command: code,
      language,
      agent_id: agentId
    }, this.options);

    const logEntry = {
      timestamp: new Date().toISOString(),
      type: 'code_execution_filter',
      language,
      agent: agentId,
      allowed: decision.allowed,
      verdict: decision.verdict,
      rule_id: decision.rule_id || null,
      merkle_turn_receipt: decision.merkle_turn_receipt
    };
    this.auditLog.push(logEntry);

    if (!decision.allowed) {
      return {
        exitCode: 126,
        output: `[BTP VETO] Unauthorized code execution blocked by ${decision.rule_id}: ${decision.reason}`,
        allowed: false,
        verdict: decision.verdict,
        rule_id: decision.rule_id
      };
    }

    return {
      exitCode: 0,
      allowed: true,
      verdict: "ALLOW",
      merkle_turn_receipt: decision.merkle_turn_receipt
    };
  }

  /**
   * Hook for AutoGen GroupChat speaker selection and broadcast consensus
   */
  verifyGroupChatConsensus(speakers, plannedAction) {
    const actionPayload = typeof plannedAction === 'object' ? plannedAction : { action: plannedAction };
    const decision = enforceToolBoundary('swarm_consensus', {
      speakers: speakers.map(s => s.name || s),
      ...actionPayload
    }, this.options);

    return {
      consensusAllowed: decision.allowed,
      verdict: decision.verdict,
      receipt: decision.merkle_turn_receipt
    };
  }
}

/**
 * 2. Microsoft Semantic Kernel In-Process Middleware
 * 
 * Implements Semantic Kernel's IFunctionInvocationFilter and
 * IPromptRenderingFilter middleware interface.
 */
export class MicrosoftSemanticKernelMiddleware {
  constructor(options = {}) {
    this.options = {
      enforceInvariants: true,
      auditReceipts: true,
      ...options
    };
    this.invocations = [];
  }

  /**
   * Function invocation filter: wraps any Semantic Kernel function / plugin call
   */
  async onFunctionInvocation(context, next) {
    const functionName = context.function?.name || context.name || 'sk_kernel_function';
    const pluginName = context.function?.pluginName || context.pluginName || 'default_plugin';
    const rawArguments = context.arguments || context.variables || {};

    const decision = enforceToolBoundary(`${pluginName}.${functionName}`, rawArguments, this.options);

    const record = {
      id: crypto.randomBytes(8).toString('hex'),
      plugin: pluginName,
      function: functionName,
      allowed: decision.allowed,
      verdict: decision.verdict,
      rule_id: decision.rule_id || null,
      timestamp: Date.now()
    };
    this.invocations.push(record);

    if (!decision.allowed) {
      const error = new Error(`[BTP-VETO] Semantic Kernel execution of '${pluginName}.${functionName}' vetoed by ${decision.rule_id}: ${decision.reason}`);
      error.rule_id = decision.rule_id;
      error.verdict = decision.verdict;
      error.remediation = decision.remediation_hint;
      throw error;
    }

    // Call downstream kernel function
    if (typeof next === 'function') {
      const result = await next(context);
      context.result = result;
      context._btp_receipt = decision.merkle_turn_receipt;
      return result;
    }

    return {
      status: 'APPROVED',
      merkle_receipt: decision.merkle_turn_receipt
    };
  }

  /**
   * Prompt rendering filter: ensures zero-leakage tokenization before prompts reach the LLM
   */
  async onPromptRendering(context, next) {
    const rawPrompt = context.renderedPrompt || context.prompt || '';
    
    // Check for credential leaks
    const hasSecret = /(sk-proj-[a-zA-Z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|Bearer\s+ey[a-zA-Z0-9_\-\.]{20,})/i.test(rawPrompt);
    if (hasSecret) {
      const err = new Error('[BTP-VETO] Prompt contains unmasked credentials or live API keys (violates BTP-VAULT-SECRET-LEAK)');
      err.rule_id = 'BTP-VAULT-SECRET-LEAK';
      err.verdict = 'DENY';
      throw err;
    }

    // Check for prompt injections and policy violations
    const decision = enforceToolBoundary('prompt_render', { prompt: rawPrompt }, this.options);
    if (!decision.allowed) {
      const err = new Error(`[BTP-VETO] Prompt rendering rejected by ${decision.rule_id}: ${decision.reason}`);
      err.rule_id = decision.rule_id;
      err.verdict = decision.verdict;
      throw err;
    }

    if (typeof next === 'function') {
      return await next(context);
    }
    return rawPrompt;
  }
}

/**
 * Helper factory functions for fast 1-line integration
 */
export function createMicrosoftAutoGenHook(options = {}) {
  const middleware = new MicrosoftAutoGenMiddleware(options);
  return {
    process_message_before_send: (sender, recipient, message) => middleware.processMessageBeforeSend(sender, recipient, message),
    intercept_code_execution: (code, lang, ctx) => middleware.interceptCodeExecution(code, lang, ctx),
    middleware
  };
}

export function createMicrosoftSemanticKernelFilter(options = {}) {
  const middleware = new MicrosoftSemanticKernelMiddleware(options);
  return {
    onFunctionInvocation: (ctx, next) => middleware.onFunctionInvocation(ctx, next),
    onPromptRendering: (ctx, next) => middleware.onPromptRendering(ctx, next),
    middleware
  };
}
