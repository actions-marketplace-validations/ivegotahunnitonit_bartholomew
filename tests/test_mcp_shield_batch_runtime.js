const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

async function testBatchInterception() {
  console.log('[*] Testing mcp-shield stdio IPC batch request handling...');

  const shieldPath = path.resolve(__dirname, '../packages/bartholomew-vault/bin/mcp-shield.js');
  
  // A simple node child process that echos received lines to stdout
  const mockChildScript = `
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin });
    rl.on('line', (line) => {
      process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: 999, result: { received: line } }) + '\\n');
    });
  `;
  const mockChildFile = path.resolve(__dirname, 'temp_mock_child.js');
  fs.writeFileSync(mockChildFile, mockChildScript, 'utf-8');

  try {
    // Launch mcp-shield wrapping the mock child
  const child = spawn(process.execPath, [shieldPath, '--', process.execPath, mockChildFile], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      BTP_ENFORCE_KEYSTONE: '1',
      BTP_KEYSTONE_SECRET: 'test_synthetic_key_32bytes_sec!',
      BTP_WORKSPACE_ID: 'ws-test-sandbox'
    }
  });

  let childOutput = '';
  let childStderr = '';
  child.stdout.on('data', (d) => { childOutput += d.toString(); });
  child.stderr.on('data', (d) => { childStderr += d.toString(); });

  await new Promise(r => setTimeout(r, 400));

  // Send an unauthorized batch request
  const batchPayload = [
    {
      jsonrpc: '2.0',
      id: 101,
      method: 'tools/call',
      params: {
        name: 'destructive_action',
        arguments: { query: 'DROP/**/TABLE secrets;' }
      }
    }
  ];

  child.stdin.write(JSON.stringify(batchPayload) + '\n');
  await new Promise(r => setTimeout(r, 600));

  child.kill();

  console.log('mcp-shield stderr:', childStderr.trim());
  console.log('mcp-shield response:', childOutput.trim());
  const parsedResp = JSON.parse(childOutput.trim());

  if (Array.isArray(parsedResp) && parsedResp.length > 0 && parsedResp[0].error) {
    console.log('[+] PASS: Batch unauthorized request was intercepted and rejected by mcp-shield proxy!');
    console.log('    Error code:', parsedResp[0].error.code);
    console.log('    Error message:', parsedResp[0].error.message);
  } else {
    console.error('[-] FAIL: Batch request was not rejected:', parsedResp);
    process.exit(1);
  }

  // Next test: Passkey valid for tool 'db_query', but payload contains destructive SQL comment injection 'DROP/**/TABLE'
  console.log('[*] Testing mcp-shield stdio IPC batch request with valid passkey but destructive SQL comment injection...');
  const crypto = require('crypto');
  function issuePasskey(secret, options = {}) {
    const passkeyId = options.passkey_id || 'key_' + crypto.randomBytes(8).toString('hex');
    const now = new Date();
    const issuedAt = now.toISOString();
    const expiresAt = new Date(now.getTime() + 60000).toISOString();
    const agentId = 'agent-1';
    const workspaceId = 'ws-test-sandbox';
    const singleUse = false;
    const scopes = { tools: { allow: ['db_query'] } };

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

  const validPasskey = issuePasskey('test_synthetic_key_32bytes_sec!');
  const child2 = spawn(process.execPath, [shieldPath, '--', process.execPath, mockChildFile], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      BTP_ENFORCE_KEYSTONE: '1',
      BTP_KEYSTONE_SECRET: 'test_synthetic_key_32bytes_sec!',
      BTP_WORKSPACE_ID: 'ws-test-sandbox'
    }
  });

  let child2Output = '';
  let child2Stderr = '';
  child2.stdout.on('data', (d) => { child2Output += d.toString(); });
  child2.stderr.on('data', (d) => { child2Stderr += d.toString(); });
  await new Promise(r => setTimeout(r, 600));

  const destructiveBatch = [
    {
      jsonrpc: '2.0',
      id: 202,
      method: 'tools/call',
      params: {
        name: 'db_query',
        arguments: {
          sql: 'DROP/**/TABLE sensitive_accounts;',
          _btp_passkey: validPasskey
        }
      }
    }
  ];

  child2.stdin.write(JSON.stringify(destructiveBatch) + '\n');
  await new Promise(r => setTimeout(r, 800));
  child2.kill();

  console.log('mcp-shield stderr 2:', child2Stderr.trim());
  console.log('mcp-shield response 2:', child2Output.trim());
  const parsedResp2 = JSON.parse(child2Output.trim());
  if (Array.isArray(parsedResp2) && parsedResp2.length > 0 && parsedResp2[0].error) {
    console.log('[+] PASS: Destructive SQL comment injection inside batch was blocked by AST invariant!');
    console.log('    Error code:', parsedResp2[0].error.code);
    console.log('    Error message:', parsedResp2[0].error.message);
  } else {
    console.error('[-] FAIL: Destructive SQL in batch was not blocked:', parsedResp2);
    process.exit(1);
  }
  } finally {
    try { fs.unlinkSync(mockChildFile); } catch {}
  }
}

testBatchInterception().catch(err => {
  console.error(err);
  process.exit(1);
});
