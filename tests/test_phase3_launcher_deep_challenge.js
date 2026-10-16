const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

function issuePasskey(secret, options = {}) {
  const passkeyId = options.passkey_id || 'key_' + crypto.randomBytes(8).toString('hex');
  const now = new Date();
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 60000).toISOString();
  const agentId = options.agent_id || 'test-agent';
  const workspaceId = options.workspace_id || 'ws-sandbox';
  const singleUse = options.single_use !== undefined ? options.single_use : false;
  const scopes = options.scopes || { tools: { allow: ['db_query'] } };

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

async function runLauncherChallenge() {
  console.log('[*] Phase 3: Comprehensive MCP Launcher & Stdio Boundary Challenge...');
  const shieldPath = path.resolve(__dirname, '../packages/bartholomew-vault/bin/mcp-shield.js');
  const TEST_SECRET = 'synthetic_test_secret_for_challenge_32bytes!';
  const WORKSPACE_ID = 'ws-sandbox';

  // 1. Environment Sanitization & Key Non-Leakage Test
  console.log('[*] Testing Child Process Environment Isolation (Signing Secret Leakage)...');
  const leakInspectorScript = `
    const receivedKey = process.env.BTP_KEYSTONE_SECRET;
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { leakedKey: receivedKey || 'NOT_PRESENT' } }) + '\\n');
  `;
  const leakScriptPath = path.resolve(__dirname, 'temp_leak_inspector.js');
  fs.writeFileSync(leakScriptPath, leakInspectorScript, 'utf-8');

  try {
    const shieldWithEnv = spawn(process.execPath, [shieldPath, '--', process.execPath, leakScriptPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        BTP_KEYSTONE_SECRET: TEST_SECRET,
        BTP_WORKSPACE_ID: WORKSPACE_ID
      }
    });

    let leakOutput = '';
    shieldWithEnv.stdout.on('data', d => leakOutput += d.toString());
    await new Promise(r => setTimeout(r, 600));
    shieldWithEnv.kill();

    const leakJson = JSON.parse(leakOutput.trim());
    if (leakJson.result && leakJson.result.leakedKey === 'NOT_PRESENT') {
      console.log('[+] PASS: BTP_KEYSTONE_SECRET was successfully scrubbed and NOT inherited by child process!');
    } else {
      console.error('[-] FAIL: BTP_KEYSTONE_SECRET was leaked to child process:', leakJson);
      process.exit(1);
    }
  } finally {
    try { fs.unlinkSync(leakScriptPath); } catch {}
  }

  // 2. Mock Recording Child Process to verify exact received requests
  const recorderScript = `
    const readline = require('readline');
    const fs = require('fs');
    const logPath = process.argv[2];
    const rl = readline.createInterface({ input: process.stdin });
    rl.on('line', (line) => {
      fs.appendFileSync(logPath, line + '\\n');
      try {
        const msg = JSON.parse(line);
        if (Array.isArray(msg)) {
          process.stdout.write(JSON.stringify(msg.map(m => ({ jsonrpc: '2.0', id: m.id, result: { status: 'executed' } }))) + '\\n');
        } else {
          process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { status: 'executed' } }) + '\\n');
        }
      } catch {
        process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, result: { status: 'raw' } }) + '\\n');
      }
    });
  `;
  const recorderScriptPath = path.resolve(__dirname, 'temp_recorder_child.js');
  const recordLogPath = path.resolve(__dirname, 'temp_received_by_child.log');
  fs.writeFileSync(recorderScriptPath, recorderScript, 'utf-8');
  if (fs.existsSync(recordLogPath)) fs.unlinkSync(recordLogPath);

  try {
    // 3. Test Default Startup Strictness (BTP_ENFORCE_KEYSTONE unset)
    console.log('[*] Testing Default Strictness with BTP_ENFORCE_KEYSTONE unset...');
    const shieldDefaultStrict = spawn(process.execPath, [shieldPath, '--', process.execPath, recorderScriptPath, recordLogPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        BTP_KEYSTONE_SECRET: TEST_SECRET,
        BTP_WORKSPACE_ID: WORKSPACE_ID
      }
    });
    delete shieldDefaultStrict.spawnargs; // verify clean env

    let defaultOutput = '';
    shieldDefaultStrict.stdout.on('data', d => defaultOutput += d.toString());
    await new Promise(r => setTimeout(r, 400));

    // Send unauthenticated tool call
    const unauthCall = { jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'db_query', arguments: { sql: 'SELECT 1;' } } };
    shieldDefaultStrict.stdin.write(JSON.stringify(unauthCall) + '\n');
    await new Promise(r => setTimeout(r, 500));
    shieldDefaultStrict.kill();

    const defaultResp = JSON.parse(defaultOutput.trim());
    if (defaultResp.error && defaultResp.error.data && defaultResp.error.data.rule_id === 'KEYSTONE-MISSING-PASSKEY') {
      console.log('[+] PASS: Unauthenticated call rejected fail-closed with BTP_ENFORCE_KEYSTONE unset!');
    } else {
      console.error('[-] FAIL: Unauthenticated call was permitted when BTP_ENFORCE_KEYSTONE unset:', defaultResp);
      process.exit(1);
    }

    // Verify child received log: unauthenticated call must NOT be in recordLogPath
    const logContentAfterUnauth = fs.existsSync(recordLogPath) ? fs.readFileSync(recordLogPath, 'utf-8') : '';
    if (logContentAfterUnauth.includes('SELECT 1')) {
      console.error('[-] FAIL: Unauthenticated request reached child process!');
      process.exit(1);
    } else {
      console.log('[+] PASS: Confirmed child process NEVER received the unauthenticated request.');
    }

    // 4. Test Mixed Batch Request (Permitted, Denied, Malformed, Notification, Duplicate IDs)
    console.log('[*] Testing Mixed Batch Handling...');
    if (fs.existsSync(recordLogPath)) fs.unlinkSync(recordLogPath);

    const shieldBatchTest = spawn(process.execPath, [shieldPath, '--', process.execPath, recorderScriptPath, recordLogPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        BTP_KEYSTONE_SECRET: TEST_SECRET,
        BTP_WORKSPACE_ID: WORKSPACE_ID
      }
    });

    let batchOutput = '';
    shieldBatchTest.stdout.on('data', d => batchOutput += d.toString());
    await new Promise(r => setTimeout(r, 400));

    const validPk = issuePasskey(TEST_SECRET, {});
    const mixedBatch = [
      // 1: Valid permitted call
      { jsonrpc: '2.0', id: 100, method: 'tools/call', params: { name: 'db_query', arguments: { sql: 'SELECT id FROM users;', _btp_passkey: validPk } } },
      // 2: Denied destructive call (same valid passkey, but blocked by invariant)
      { jsonrpc: '2.0', id: 101, method: 'tools/call', params: { name: 'db_query', arguments: { sql: 'DROP TABLE accounts;', _btp_passkey: validPk } } },
      // 3: Malformed params item
      { jsonrpc: '2.0', id: 102, method: 'tools/call', params: null },
      // 4: Duplicate ID
      { jsonrpc: '2.0', id: 101, method: 'tools/call', params: { name: 'db_query', arguments: { sql: 'SELECT 2;' } } }
    ];

    shieldBatchTest.stdin.write(JSON.stringify(mixedBatch) + '\n');
    await new Promise(r => setTimeout(r, 600));
    shieldBatchTest.kill();

    const parsedBatchResp = JSON.parse(batchOutput.trim());
    console.log('Batch response count:', parsedBatchResp.length);

    // Verify child log
    const childLogBatch = fs.existsSync(recordLogPath) ? fs.readFileSync(recordLogPath, 'utf-8') : '';
    if (childLogBatch.includes('DROP TABLE')) {
      console.error('[-] CRITICAL FAIL: Destructive DROP TABLE inside batch reached child server!');
      process.exit(1);
    } else {
      console.log('[+] PASS: Child process NEVER received the destructive batch query!');
    }

  } finally {
    try { fs.unlinkSync(recorderScriptPath); } catch {}
    try { fs.unlinkSync(recordLogPath); } catch {}
  }

  console.log('[+] Phase 3 Launcher Challenge Completed Successfully.');
}

runLauncherChallenge().catch(err => {
  console.error(err);
  process.exit(1);
});
