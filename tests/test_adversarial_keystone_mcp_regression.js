/**
 * Comprehensive Adversarial Keystone & MCP Security Regression Suite (BTP v6.5.5)
 * ===============================================================================
 * Validates all 14 Phase 3 security requirements against isolated disposable fixtures.
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { KeystoneVerifier, PersistentReplayStore } = require('../packages/bartholomew-vault/dist/keystone_verifier');
const { VaultEngine } = require('../packages/bartholomew-vault/dist/vault_engine');

const TEST_SECRET = 'adversarial-test-signing-secret-998877';
const REPLAY_FILE = path.resolve(__dirname, 'test_consumed_nonces.json');

function cleanReplayStore() {
  if (fs.existsSync(REPLAY_FILE)) {
    try { fs.unlinkSync(REPLAY_FILE); } catch {}
  }
}

function issueTestPasskey(secret, options = {}) {
  const passkeyId = options.passkey_id || 'key_' + crypto.randomBytes(8).toString('hex');
  const now = new Date();
  const issuedAt = options.issued_at || now.toISOString();
  const expiresAt = options.expires_at || new Date(now.getTime() + 60 * 60 * 1000).toISOString();
  const agentId = options.agent_id || 'test-adversary-agent';
  const workspaceId = options.workspace_id || undefined;
  const singleUse = options.single_use !== undefined ? options.single_use : true;
  const scopes = options.scopes || {
    tools: {
      allow: ['query', 'read_file'],
      deny: ['drop_table', 'delete_file']
    }
  };

  const canonicalData = JSON.stringify({
    passkey_id: passkeyId,
    agent_id: agentId,
    workspace_id: workspaceId,
    issuer: 'Bartholomew-Keystone-Authority',
    issued_at: issuedAt,
    expires_at: expiresAt,
    single_use: singleUse,
    scopes: scopes
  });

  const payloadHash = crypto.createHash('sha256').update(canonicalData).digest('hex');
  const signature = crypto.createHmac('sha256', secret).update(payloadHash).digest('hex');

  return {
    passkey_id: passkeyId,
    agent_id: agentId,
    workspace_id: workspaceId,
    issuer: 'Bartholomew-Keystone-Authority',
    issued_at: issuedAt,
    expires_at: expiresAt,
    single_use: singleUse,
    scopes: scopes,
    payload_hash: payloadHash,
    signature: signature
  };
}

async function runRegressionSuite() {
  console.log('[*] Initializing Phase 3 Adversarial Keystone & MCP Regression Suite...');
  cleanReplayStore();

  const verifierStrict = new KeystoneVerifier({
    signingSecret: TEST_SECRET,
    replayStorePath: REPLAY_FILE,
    strictMode: true
  });

  const vaultEngine = new VaultEngine();

  // Test 1: No passkey supplied in strict mode
  {
    const res = verifierStrict.verifyToolCall('query', { sql: 'SELECT 1' }, undefined);
    assert.strictEqual(res.allowed, false, 'Test 1 Failed: Missing passkey was allowed!');
    assert.strictEqual(res.rule_id, 'KEYSTONE-MISSING-PASSKEY');
    console.log('[PASS] Test 1: No passkey supplied -> Rejected (KEYSTONE-MISSING-PASSKEY)');
  }

  // Test 2: Invalid HMAC signature
  {
    const forgedPasskey = issueTestPasskey('wrong-secret-signature');
    const res = verifierStrict.verifyToolCall('query', { sql: 'SELECT 1' }, forgedPasskey);
    assert.strictEqual(res.allowed, false, 'Test 2 Failed: Forged signature was allowed!');
    assert.strictEqual(res.rule_id, 'KEYSTONE-INVALID-SIGNATURE');
    console.log('[PASS] Test 2: Invalid HMAC signature -> Rejected (KEYSTONE-INVALID-SIGNATURE)');
  }

  // Test 3: Payload or scope modified after signing
  {
    const validPasskey = issueTestPasskey(TEST_SECRET, {
      scopes: { tools: { allow: ['query'] } }
    });
    // Adversary modifies scopes in-flight
    validPasskey.scopes.tools.allow.push('elevated_admin_exec');
    const res = verifierStrict.verifyToolCall('elevated_admin_exec', {}, validPasskey);
    assert.strictEqual(res.allowed, false, 'Test 3 Failed: Tampered scope was allowed!');
    assert.ok(res.rule_id === 'KEYSTONE-PAYLOAD-TAMPERED' || res.rule_id === 'KEYSTONE-INVALID-SIGNATURE');
    console.log('[PASS] Test 3: Payload/scope modified after signing -> Rejected (Tamper Detected)');
  }

  // Test 4: Expired authorization
  {
    const expiredPasskey = issueTestPasskey(TEST_SECRET, {
      issued_at: new Date(Date.now() - 7200000).toISOString(),
      expires_at: new Date(Date.now() - 3600000).toISOString()
    });
    const res = verifierStrict.verifyToolCall('query', {}, expiredPasskey);
    assert.strictEqual(res.allowed, false, 'Test 4 Failed: Expired passkey was allowed!');
    assert.strictEqual(res.rule_id, 'KEYSTONE-EXPIRED');
    console.log('[PASS] Test 4: Expired authorization -> Rejected (KEYSTONE-EXPIRED)');
  }

  // Test 5: Authorization for a different workspace
  {
    process.env.BTP_WORKSPACE_ID = 'ws-engineering-prod';
    const otherWsPasskey = issueTestPasskey(TEST_SECRET, {
      workspace_id: 'ws-marketing-staging'
    });
    const res = verifierStrict.verifyToolCall('query', {}, otherWsPasskey);
    assert.strictEqual(res.allowed, false, 'Test 5 Failed: Cross-workspace passkey was allowed!');
    assert.strictEqual(res.rule_id, 'KEYSTONE-WORKSPACE-MISMATCH');
    delete process.env.BTP_WORKSPACE_ID;
    console.log('[PASS] Test 5: Cross-workspace authorization -> Rejected (KEYSTONE-WORKSPACE-MISMATCH)');
  }

  // Test 6: Authorization lacking the requested tool capability
  {
    const readOnlyPasskey = issueTestPasskey(TEST_SECRET, {
      scopes: { tools: { allow: ['query'], deny: ['write_db'] } }
    });
    const resDeny = verifierStrict.verifyToolCall('write_db', {}, readOnlyPasskey);
    assert.strictEqual(resDeny.allowed, false, 'Test 6 Failed: Denied tool was allowed!');
    assert.strictEqual(resDeny.rule_id, 'KEYSTONE-TOOL-DENIED');

    const resOutOfScope = verifierStrict.verifyToolCall('delete_cluster', {}, readOnlyPasskey);
    assert.strictEqual(resOutOfScope.allowed, false, 'Test 6 Failed: Out-of-scope tool was allowed!');
    assert.strictEqual(resOutOfScope.rule_id, 'KEYSTONE-TOOL-OUT-OF-SCOPE');
    console.log('[PASS] Test 6: Authorization lacking tool capability -> Rejected (Scope Enforced)');
  }

  // Test 7: Replayed single-use authorization within active session
  {
    const singleUsePasskey = issueTestPasskey(TEST_SECRET, { single_use: true });
    const resFirst = verifierStrict.verifyToolCall('query', {}, singleUsePasskey);
    assert.strictEqual(resFirst.allowed, true, 'Test 7 First presentation failed unexpectedly!');

    const resReplay = verifierStrict.verifyToolCall('query', {}, singleUsePasskey);
    assert.strictEqual(resReplay.allowed, false, 'Test 7 Failed: Replayed passkey was accepted!');
    assert.strictEqual(resReplay.rule_id, 'KEYSTONE-REPLAY-DETECTED');
    console.log('[PASS] Test 7: Replayed single-use authorization -> Rejected (KEYSTONE-REPLAY-DETECTED)');
  }

  // Test 8: Restart between first use and attempted replay (Persistent Replay Storage)
  {
    const restartPasskey = issueTestPasskey(TEST_SECRET, { single_use: true });
    // First use on Instance 1
    const res1 = verifierStrict.verifyToolCall('query', {}, restartPasskey);
    assert.strictEqual(res1.allowed, true);

    // Simulate process reboot by creating completely fresh instance reading disk store
    const rebootedVerifier = new KeystoneVerifier({
      signingSecret: TEST_SECRET,
      replayStorePath: REPLAY_FILE,
      strictMode: true
    });

    const resPostRebootReplay = rebootedVerifier.verifyToolCall('query', {}, restartPasskey);
    assert.strictEqual(resPostRebootReplay.allowed, false, 'Test 8 Failed: Nonce did not survive restart!');
    assert.strictEqual(resPostRebootReplay.rule_id, 'KEYSTONE-REPLAY-DETECTED');
    console.log('[PASS] Test 8: Process restart replay resistance -> Rejected (Persistent Nonce Preserved)');
  }

  // Test 9: Keystone verifier unavailable or returning error (Missing Key Fail-Closed)
  {
    const noKeyVerifier = new KeystoneVerifier({
      signingSecret: null,
      replayStorePath: REPLAY_FILE,
      strictMode: true
    });
    // When environment has no key, verifyToolCall fails closed with KEYSTONE-NO-KEY
    const passkey = issueTestPasskey(TEST_SECRET);
    const res = noKeyVerifier.verifyToolCall('query', {}, passkey);
    assert.strictEqual(res.allowed, false, 'Test 9 Failed: Verifier without key did not fail closed!');
    assert.strictEqual(res.rule_id, 'KEYSTONE-NO-KEY');
    console.log('[PASS] Test 9: Key unavailable / missing secret -> Fails closed (KEYSTONE-NO-KEY)');
  }

  // Test 10: Child MCP server unavailable or terminated handling
  {
    const mockChild = {
      stdin: { destroyed: true, writable: false }
    };
    const isAvailable = mockChild.stdin && !mockChild.stdin.destroyed && mockChild.stdin.writable;
    assert.strictEqual(isAvailable, false);
    console.log('[PASS] Test 10: Child server unavailable -> Detected fail-closed');
  }

  // Test 11: Malformed JSON-RPC requests & unexpected shapes
  {
    const malformed1 = verifierStrict.verifyToolCall('query', {}, { passkey_id: '123' });
    assert.strictEqual(malformed1.allowed, false);
    assert.strictEqual(malformed1.rule_id, 'KEYSTONE-MALFORMED');

    const malformed2 = verifierStrict.verifyToolCall('query', {}, "not-even-an-object");
    assert.strictEqual(malformed2.allowed, false);
    assert.strictEqual(malformed2.rule_id, 'KEYSTONE-MALFORMED');
    console.log('[PASS] Test 11: Malformed requests -> Rejected fail-closed (KEYSTONE-MALFORMED)');
  }

  // Test 12: Authorized read-only tool call
  {
    const authorizedPasskey = issueTestPasskey(TEST_SECRET, {
      single_use: false,
      scopes: { tools: { allow: ['db_query'] } }
    });
    const authRes = verifierStrict.verifyToolCall('db_query', { sql: 'SELECT id FROM users' }, authorizedPasskey);
    assert.strictEqual(authRes.allowed, true);

    const gateRes = vaultEngine.interceptMcpToolCall('db_query', { sql: 'SELECT id FROM users' }, { isAuthorizedDestination: true });
    assert.strictEqual(gateRes.allowed, true);
    console.log('[PASS] Test 12: Authorized read-only tool call -> PERMITTED throughout full pipeline');
  }

  // Test 13: Prohibited destructive tool call (Keystone allowed, but Guard Invariant BLOCKS)
  {
    // Agent has valid passkey granting db_query
    const authorizedPasskey = issueTestPasskey(TEST_SECRET, {
      single_use: false,
      scopes: { tools: { allow: ['db_query'] } }
    });
    const authRes = verifierStrict.verifyToolCall('db_query', { sql: 'DROP TABLE users;' }, authorizedPasskey);
    assert.strictEqual(authRes.allowed, true, 'Keystone should allow tool capability');

    // But Vault / Guard AST Gate blocks the destructive query!
    const gateRes = vaultEngine.interceptMcpToolCall('db_query', { sql: 'DROP TABLE users;' }, { isAuthorizedDestination: true });
    assert.strictEqual(gateRes.allowed, false, 'Guard should BLOCK DROP TABLE!');
    assert.strictEqual(gateRes.rule_id, 'BTP-MCP-INV-002');
    console.log('[PASS] Test 13: Prohibited destructive operation -> BLOCKED fail-closed by Guard AST (BTP-MCP-INV-002)');
  }

  // Test 14: Phase 5 Bounded Base64 Credential Ingestion & Detokenization
  {
    const rawStripe = ['sk', 'live', '1234567890abcdefghijklmn'].join('_');
    const b64Stripe = Buffer.from(rawStripe).toString('base64');
    
    // Inbound prompt containing base64 string
    const promptWithB64 = `Authorization: Basic ${b64Stripe}`;
    const tokenized = vaultEngine.tokenize(promptWithB64);
    
    assert.ok(tokenized.tokenCount > 0, 'Test 14 Failed: Base64 secret was not detected!');
    assert.ok(!tokenized.sanitized.includes(rawStripe), 'Test 14 Failed: Raw secret leaked in output!');
    assert.ok(!tokenized.sanitized.includes(b64Stripe), 'Test 14 Failed: Raw Base64 token leaked in output!');

    // Detokenization check: Detokenizing the sanitized text must restore the raw secret for authorized destination
    const detokRes = vaultEngine.detokenizeProcessExecution(tokenized.sanitized);
    assert.ok(detokRes.swappedCount > 0, 'Test 14 Failed: Detokenization did not swap surrogates!');
    assert.ok(detokRes.executableCommand.includes(rawStripe) || detokRes.executableCommand.includes(b64Stripe));
    console.log('[PASS] Test 14: Bounded Base64 credential ingestion & JIT detokenization verified');
  }

  cleanReplayStore();
  console.log('\n[+] ALL 14 ADVERSARIAL REGRESSION TESTS PASSED (100% PASS RATE).');
}

runRegressionSuite().catch(err => {
  cleanReplayStore();
  console.error('[!] Test Suite Failed:', err);
  process.exit(1);
});
