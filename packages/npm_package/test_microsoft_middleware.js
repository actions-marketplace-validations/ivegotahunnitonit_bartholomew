import assert from 'assert';
import {
  MicrosoftAutoGenMiddleware,
  MicrosoftSemanticKernelMiddleware,
  createMicrosoftAutoGenHook,
  createMicrosoftSemanticKernelFilter
} from './microsoft_adapters.js';

console.log('[*] Running Bartholomew Microsoft Middleware Test Suite...');

async function testAutoGenMiddleware() {
  console.log('  Testing MicrosoftAutoGenMiddleware...');
  const autogen = new MicrosoftAutoGenMiddleware();

  // 1. Safe message transmission
  const safeMsg = autogen.processMessageBeforeSend(
    { name: 'PlannerAgent' },
    { name: 'CoderAgent' },
    'Analyze the database schema for performance improvements.'
  );
  assert.strictEqual(safeMsg.proceed, true, 'Safe message should proceed');
  assert.strictEqual(safeMsg.intercepted, false);
  console.log('    [PASS] Safe message before send');

  // 2. Destructive code execution block
  const dangerousExec = await autogen.interceptCodeExecution('rm -rf / --no-preserve-root', 'bash', { name: 'CoderAgent' });
  assert.strictEqual(dangerousExec.allowed, false, 'Dangerous code must be blocked');
  assert.strictEqual(dangerousExec.exitCode, 126, 'Exit code must be 126 on veto');
  assert.ok(dangerousExec.output.includes('BTP VETO'), 'Output must contain BTP VETO');
  console.log('    [PASS] Destructive code execution vetoed');

  // 3. Safe code execution block
  const safeExec = await autogen.interceptCodeExecution('SELECT count(*) FROM users;', 'sql', { name: 'CoderAgent' });
  assert.strictEqual(safeExec.allowed, true, 'Safe code must be allowed');
  assert.strictEqual(safeExec.exitCode, 0);
  assert.ok(safeExec.merkle_turn_receipt, 'Must provide merkle turn receipt');
  console.log('    [PASS] Safe code execution allowed with Merkle receipt');

  // 4. GroupChat consensus
  const consensus = autogen.verifyGroupChatConsensus(
    [{ name: 'Admin' }, { name: 'Auditor' }],
    { action: 'read_metrics', target: 'cpu_usage' }
  );
  assert.strictEqual(consensus.consensusAllowed, true, 'Consensus should be allowed');
  console.log('    [PASS] GroupChat consensus check passed');
}

async function testSemanticKernelMiddleware() {
  console.log('  Testing MicrosoftSemanticKernelMiddleware...');
  const sk = new MicrosoftSemanticKernelMiddleware();

  // 1. Safe function invocation
  let nextCalled = false;
  const mockContext = {
    function: { name: 'get_weather', pluginName: 'WeatherPlugin' },
    arguments: { city: 'Calgary' }
  };
  const result = await sk.onFunctionInvocation(mockContext, async (ctx) => {
    nextCalled = true;
    return 'Sunny, 18C';
  });
  assert.strictEqual(nextCalled, true, 'Downstream function must be called');
  assert.strictEqual(result, 'Sunny, 18C');
  console.log('    [PASS] Safe Semantic Kernel function invocation allowed');

  // 2. Dangerous function invocation (destructive shell)
  const dangerousContext = {
    function: { name: 'run_bash', pluginName: 'TerminalPlugin' },
    arguments: { command: 'rm -rf /var/data' }
  };
  let errorCaught = false;
  try {
    await sk.onFunctionInvocation(dangerousContext, async () => {
      throw new Error('Should not reach here');
    });
  } catch (err) {
    errorCaught = true;
    assert.ok(err.message.includes('BTP-VETO'), 'Error message must specify BTP-VETO');
  }
  assert.strictEqual(errorCaught, true, 'Dangerous function invocation must throw');
  console.log('    [PASS] Destructive Semantic Kernel function invocation vetoed');

  // 3. Prompt rendering with live secret leak
  const leakingPromptCtx = {
    prompt: 'Please send this payload to OpenAI using sk-proj-99999999999999999999999999'
  };
  let leakCaught = false;
  try {
    await sk.onPromptRendering(leakingPromptCtx, async () => {});
  } catch (err) {
    leakCaught = true;
    assert.ok(err.message.includes('BTP-VETO') || err.message.includes('credential'), 'Secret leak must be caught');
  }
  assert.strictEqual(leakCaught, true, 'Secret leakage in prompt must be blocked');
  console.log('    [PASS] Prompt rendering secret leak blocked');

  // 4. Safe prompt rendering
  const safePromptCtx = { prompt: 'Summarize the Q3 financial report.' };
  let promptNextCalled = false;
  await sk.onPromptRendering(safePromptCtx, async (ctx) => {
    promptNextCalled = true;
    return ctx.prompt;
  });
  assert.strictEqual(promptNextCalled, true, 'Safe prompt must pass');
  console.log('    [PASS] Safe prompt rendering approved');
}

async function testFactoryHelpers() {
  console.log('  Testing Factory Helpers...');
  const autogenHook = createMicrosoftAutoGenHook();
  assert.ok(autogenHook.process_message_before_send, 'Must expose process_message_before_send');
  assert.ok(autogenHook.intercept_code_execution, 'Must expose intercept_code_execution');

  const skFilter = createMicrosoftSemanticKernelFilter();
  assert.ok(skFilter.onFunctionInvocation, 'Must expose onFunctionInvocation');
  assert.ok(skFilter.onPromptRendering, 'Must expose onPromptRendering');
  console.log('    [PASS] Factory helpers verified');
}

async function main() {
  await testAutoGenMiddleware();
  await testSemanticKernelMiddleware();
  await testFactoryHelpers();
  console.log('\n[+] ALL MICROSOFT AGENTIC MIDDLEWARE TESTS PASSED (10/10)!');
}

main().catch(err => {
  console.error('[!] Test failed:', err);
  process.exit(1);
});
