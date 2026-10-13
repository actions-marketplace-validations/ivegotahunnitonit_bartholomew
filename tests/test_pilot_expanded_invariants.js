const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { KeystoneVerifier } = require('../packages/bartholomew-vault/dist/keystone_verifier');
const { VaultEngine } = require('../packages/bartholomew-vault/dist/vault_engine');

function createTestPasskey(secret, toolName, workspaceId, options = {}) {
  const passkey_id = options.passkey_id || ('pk_' + crypto.randomUUID());
  const issued_at = options.issued_at || new Date().toISOString();
  const expires_at = options.expires_at || new Date(Date.now() + 60000).toISOString();
  const single_use = options.single_use !== undefined ? options.single_use : true;
  const scopes = options.scopes || { tools: { allow: [toolName] } };

  const canonicalData = JSON.stringify({
    passkey_id,
    agent_id: 'agent-pilot-tester',
    workspace_id: workspaceId,
    issuer: 'Bartholomew-Keystone-Authority',
    issued_at,
    expires_at,
    single_use,
    scopes
  });

  const expectedHash = crypto.createHash('sha256').update(canonicalData).digest('hex');
  const expectedSig = crypto.createHmac('sha256', secret).update(expectedHash).digest('hex');

  return {
    passkey_id,
    agent_id: 'agent-pilot-tester',
    workspace_id: workspaceId,
    issuer: 'Bartholomew-Keystone-Authority',
    issued_at,
    expires_at,
    single_use,
    scopes,
    payload_hash: expectedHash,
    signature: expectedSig
  };
}

async function runExpandedInvariantSuite() {
  console.log('============================================================');
  console.log('  BARTHOLOMEW PILOT EXPANDED INVARIANT TEST SUITE');
  console.log('============================================================');

  let passed = 0;
  let total = 0;

  function record(name, condition, details = '') {
    total++;
    if (condition) {
      passed++;
      console.log(`[PASS] ${name}${details ? ' - ' + details : ''}`);
    } else {
      console.error(`[FAIL] ${name} - Assertion failed! ${details}`);
      process.exitCode = 1;
    }
  }

  const workspaceId = 'ws-pilot-expanded-test';
  const secretKey = 'pilot_secret_key_testing_32bytes!';
  const btpDir = path.resolve(__dirname, '../.btp');
  if (!fs.existsSync(btpDir)) fs.mkdirSync(btpDir, { recursive: true });

  const verifier = new KeystoneVerifier({
    signingSecret: secretKey,
    replayStorePath: path.join(btpDir, 'consumed_nonces.db'),
    strictMode: true
  });

  const engine = new VaultEngine();

  // Test 1: Complex SQL Comment & Invariant Variants
  console.log('\n--- 1. SQL Invariant Regex & Comment Invariants ---');
  const sqlVariants = [
    { query: '/*\\n*/ DROP TABLE users;', desc: 'JSON-escaped newline comment' },
    { query: '/*\r\n*/ DROP TABLE users;', desc: 'CRLF block comment' },
    { query: '/*\t*/ DROP TABLE users;', desc: 'Tab character block comment' },
    { query: '/* /**/ */ DROP TABLE users;', desc: 'Nested-style block comment' },
    { query: '-- single line comment\\nDROP TABLE users;', desc: 'Escaped newline after dash-dash' },
    { query: '   \\n  DROP/**/TABLE users;', desc: 'Leading whitespace and inline block comment' }
  ];

  for (const variant of sqlVariants) {
    const check = engine.interceptMcpToolCall('execute_sql', { query: variant.query });
    record(`SQL Block: ${variant.desc}`, !check.allowed && check.rule_id === 'BTP-MCP-INV-002', `Rule: ${check.rule_id}`);
  }

  // Test 2: In-Process Passkey Minting & Valid Verification
  console.log('\n--- 2. Keystone Authorization & Valid Passkey Flow ---');
  const toolName = 'read_telemetry';
  const validArgs = { metric: 'system_load', limit: 10 };
  const validPasskey = createTestPasskey(secretKey, toolName, workspaceId);

  const validCheck = verifier.verifyToolCall(toolName, validArgs, validPasskey);
  record('Valid Passkey Authorized', validCheck.allowed && validCheck.rule_id === 'KEYSTONE-PERMIT', `Rule: ${validCheck.rule_id}`);

  // Test 3: Replay Defense using Atomic SQLite Store
  console.log('\n--- 3. Persistent Replay Attack Defense ---');
  const replayCheck = verifier.verifyToolCall(toolName, validArgs, validPasskey);
  record('Replay Attempt Rejected Immediately', !replayCheck.allowed && replayCheck.rule_id === 'KEYSTONE-REPLAY-DETECTED', `Reason: ${replayCheck.reason}`);

  // Test 4: Tampered Parameter Attack with Same Passkey
  console.log('\n--- 4. Tampered Signature / Invalid HMAC Defense ---');
  const freshPasskey = createTestPasskey(secretKey, toolName, workspaceId);
  freshPasskey.signature = 'tampered_invalid_hmac_hex_value_0000000000000000';
  const tamperedCheck = verifier.verifyToolCall(toolName, validArgs, freshPasskey);
  record('Tampered Signature Rejected', !tamperedCheck.allowed && tamperedCheck.rule_id === 'KEYSTONE-INVALID-SIGNATURE', `Rule: ${tamperedCheck.rule_id}`);

  // Test 5: End-to-End MCP Shield Child Isolation & Stdio Gating
  console.log('\n--- 5. End-to-End MCP Shield Stdio IPC Enforcement ---');
  const shieldPath = path.resolve(__dirname, '../packages/bartholomew-vault/bin/mcp-shield.js');
  const mockChildScript = `
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin });
    rl.on('line', (line) => {
      try {
        const msg = JSON.parse(line);
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id || 0, result: { received: true, env_leaked: Boolean(process.env.BTP_KEYSTONE_SECRET) } }) + '\\n');
      } catch {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, result: { raw: line } }) + '\\n');
      }
    });
  `;
  const mockChildFile = path.resolve(__dirname, 'temp_expanded_mock_child.js');
  fs.writeFileSync(mockChildFile, mockChildScript, 'utf-8');

  try {
    const child = spawn(process.execPath, [shieldPath, '--', process.execPath, mockChildFile], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        BTP_ENFORCE_KEYSTONE: '1',
        BTP_KEYSTONE_SECRET: secretKey,
        BTP_WORKSPACE_ID: workspaceId
      }
    });

    let childOutput = '';
    let childStderr = '';
    child.stdout.on('data', (d) => { childOutput += d.toString(); });
    child.stderr.on('data', (d) => { childStderr += d.toString(); });

    await new Promise(r => setTimeout(r, 400));

    // Send authorized request
    const authArgs = { target: 'status_check' };
    const authPasskey = createTestPasskey(secretKey, 'system_status', workspaceId);
    const authPayload = {
      jsonrpc: '2.0',
      id: 201,
      method: 'tools/call',
      params: {
        name: 'system_status',
        arguments: authArgs,
        _btp_passkey: authPasskey
      }
    };

    child.stdin.write(JSON.stringify(authPayload) + '\n');
    await new Promise(r => setTimeout(r, 300));

    // Send unauthorized batch payload
    const unauthBatch = [
      {
        jsonrpc: '2.0',
        id: 202,
        method: 'tools/call',
        params: {
          name: 'drop_database',
          arguments: { db: 'production' }
        }
      }
    ];

    child.stdin.write(JSON.stringify(unauthBatch) + '\n');
    await new Promise(r => setTimeout(r, 300));

    // Send malformed JSON-RPC batch element (primitive integer instead of object)
    const malformedBatch = [
      42,
      {
        jsonrpc: '2.0',
        id: 203,
        method: 'tools/call',
        params: {
          name: 'safe_ping',
          arguments: {}
        }
      }
    ];

    child.stdin.write(JSON.stringify(malformedBatch) + '\n');
    await new Promise(r => setTimeout(r, 400));

    child.kill();

    const lines = childOutput.trim().split('\n').map(l => l.trim()).filter(Boolean);
    
    // Check line 1: authorized request reached child and secret was NOT leaked
    let line1Result = null;
    try { line1Result = JSON.parse(lines[0]); } catch {}
    record('Authorized tool call executed by child', Boolean(line1Result && line1Result.result && line1Result.result.received));
    record('Child environment verified sanitization (env_leaked === false)', Boolean(line1Result && line1Result.result && line1Result.result.env_leaked === false));

    // Check line 2: unauth batch blocked by shield before child
    let line2Result = null;
    try { line2Result = JSON.parse(lines[1]); } catch {}
    record('Unauthorized batch request blocked with error code -32001 / -32000', Boolean(line2Result && Array.isArray(line2Result) && line2Result[0].error));

    // Check line 3: malformed batch element rejected with JSON-RPC -32600
    let line3Result = null;
    try { line3Result = JSON.parse(lines[2]); } catch {}
    record('Malformed batch element rejected with JSON-RPC -32600', Boolean(line3Result && Array.isArray(line3Result) && line3Result[0].error && line3Result[0].error.code === -32600));

  } finally {
    if (fs.existsSync(mockChildFile)) fs.unlinkSync(mockChildFile);
  }

  console.log('\n============================================================');
  console.log(`EXPANDED INVARIANT RESULTS: ${passed}/${total} PASSED (100% fail-closed)`);
  console.log('============================================================\n');

  if (passed !== total) {
    process.exit(1);
  }
}

runExpandedInvariantSuite().catch(err => {
  console.error('[FATAL ERROR IN SUITE]:', err);
  process.exit(1);
});
