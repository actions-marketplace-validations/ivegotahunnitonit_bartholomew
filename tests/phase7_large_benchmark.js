/**
 * Phase 7 Performance Benchmark (Statistically Sound Sample Size)
 * ==============================================================
 * Measures latency distributions with 200+ end-to-end IPC samples.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { KeystoneVerifier, PersistentReplayStore } = require('../packages/bartholomew-vault/dist/keystone_verifier');
const { VaultEngine } = require('../packages/bartholomew-vault/dist/vault_engine');

function stats(arr) {
  arr.sort((a, b) => a - b);
  const n = arr.length;
  return {
    count: n,
    min: arr[0],
    median: arr[Math.floor(n * 0.5)],
    p95: arr[Math.floor(n * 0.95)],
    p99: arr[Math.floor(n * 0.99)],
    max: arr[n - 1]
  };
}

async function runPhase7Benchmark() {
  console.log('[*] Executing Phase 7 Extended Performance Benchmark...');
  const testFile = path.resolve(__dirname, 'bench_large_nonces.json');
  if (fs.existsSync(testFile)) fs.unlinkSync(testFile);

  const verifier = new KeystoneVerifier({
    signingSecret: 'large-bench-secret-123456',
    replayStorePath: testFile,
    strictMode: true
  });
  const engine = new VaultEngine();

  // 1. In-Process Keystone Verification Latency (2,000 iterations)
  const hmacTimes = [];
  const validPasskey = {
    passkey_id: 'key_bench_perf',
    agent_id: 'bench-agent',
    issuer: 'Bartholomew-Keystone-Authority',
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    single_use: false,
    scopes: { tools: { allow: ['db_query'] } },
    payload_hash: '',
    signature: ''
  };
  const canonical = JSON.stringify({
    passkey_id: validPasskey.passkey_id,
    agent_id: validPasskey.agent_id,
    workspace_id: undefined,
    issuer: validPasskey.issuer,
    issued_at: validPasskey.issued_at,
    expires_at: validPasskey.expires_at,
    single_use: false,
    scopes: validPasskey.scopes
  });
  validPasskey.payload_hash = require('crypto').createHash('sha256').update(canonical).digest('hex');
  validPasskey.signature = require('crypto').createHmac('sha256', 'large-bench-secret-123456').update(validPasskey.payload_hash).digest('hex');

  // Warmup
  for (let i = 0; i < 200; i++) {
    verifier.verifyToolCall('db_query', {}, validPasskey);
  }

  for (let i = 0; i < 2000; i++) {
    const t0 = process.hrtime.bigint();
    verifier.verifyToolCall('db_query', {}, validPasskey);
    const t1 = process.hrtime.bigint();
    hmacTimes.push(Number(t1 - t0) / 1000);
  }

  // 2. In-Process MCP Permitted Call Latency (2,000 iterations)
  const inProcSafeTimes = [];
  for (let i = 0; i < 2000; i++) {
    const t0 = process.hrtime.bigint();
    engine.interceptMcpToolCall('db_query', { sql: 'SELECT id FROM users' }, { isAuthorizedDestination: true });
    const t1 = process.hrtime.bigint();
    inProcSafeTimes.push(Number(t1 - t0) / 1000);
  }

  // 3. In-Process MCP Blocked Call Latency (2,000 iterations)
  const inProcBlockTimes = [];
  for (let i = 0; i < 2000; i++) {
    const t0 = process.hrtime.bigint();
    engine.interceptMcpToolCall('db_query', { sql: 'DROP TABLE users;' }, { isAuthorizedDestination: true });
    const t1 = process.hrtime.bigint();
    inProcBlockTimes.push(Number(t1 - t0) / 1000);
  }

  // 4. End-to-End Stdio IPC Round-Trip (200 samples)
  const shieldScript = path.resolve(__dirname, '../packages/bartholomew-vault/bin/mcp-shield.js');
  const dummyServer = path.resolve(__dirname, 'dummy_mcp_server.js');
  
  const child = spawn('node', [shieldScript, '--', 'node', dummyServer], {
    stdio: ['pipe', 'pipe', 'inherit'],
    shell: false,
    env: { ...process.env, BTP_KEYSTONE_SECRET: 'large-bench-secret-123456', BTP_ENFORCE_KEYSTONE: '1' }
  });

  const rlOut = readline.createInterface({ input: child.stdout, terminal: false });
  let pendingMap = new Map();
  let msgId = 0;

  rlOut.on('line', (line) => {
    try {
      const msg = JSON.parse(line.trim());
      if (pendingMap.has(msg.id)) {
        const { t0, resolve } = pendingMap.get(msg.id);
        const t1 = process.hrtime.bigint();
        pendingMap.delete(msg.id);
        resolve(Number(t1 - t0) / 1000);
      }
    } catch {}
  });

  // Warmup 10 calls
  for (let i = 0; i < 10; i++) {
    msgId++;
    await new Promise((resolve) => {
      const t0 = process.hrtime.bigint();
      pendingMap.set(msgId, { t0, resolve });
      child.stdin.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msgId,
        method: 'tools/call',
        params: {
          name: 'db_query',
          arguments: { sql: 'SELECT 1' },
          _meta: { btp_passkey: validPasskey }
        }
      }) + '\n');
    });
  }

  // 200 Permitted E2E Calls
  const e2ePermittedTimes = [];
  for (let i = 0; i < 200; i++) {
    msgId++;
    const lat = await new Promise((resolve) => {
      const t0 = process.hrtime.bigint();
      pendingMap.set(msgId, { t0, resolve });
      child.stdin.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msgId,
        method: 'tools/call',
        params: {
          name: 'db_query',
          arguments: { sql: 'SELECT 1' },
          _meta: { btp_passkey: validPasskey }
        }
      }) + '\n');
    });
    e2ePermittedTimes.push(lat);
  }

  // 200 Blocked E2E Calls
  const e2eBlockedTimes = [];
  for (let i = 0; i < 200; i++) {
    msgId++;
    const lat = await new Promise((resolve) => {
      const t0 = process.hrtime.bigint();
      pendingMap.set(msgId, { t0, resolve });
      child.stdin.write(JSON.stringify({
        jsonrpc: '2.0',
        id: msgId,
        method: 'tools/call',
        params: {
          name: 'db_query',
          arguments: { sql: 'DROP TABLE orders;' },
          _meta: { btp_passkey: validPasskey }
        }
      }) + '\n');
    });
    e2eBlockedTimes.push(lat);
  }

  child.kill();
  if (fs.existsSync(testFile)) fs.unlinkSync(testFile);

  const results = {
    keystone_auth: stats(hmacTimes),
    in_process_permitted: stats(inProcSafeTimes),
    in_process_blocked: stats(inProcBlockTimes),
    end_to_end_permitted: stats(e2ePermittedTimes),
    end_to_end_blocked: stats(e2eBlockedTimes)
  };

  fs.writeFileSync(path.resolve(__dirname, 'phase7_bench_results.json'), JSON.stringify(results, null, 2), 'utf-8');
  console.log('[+] Phase 7 Extended Benchmark Completed.');
  console.log('Results (µs):');
  console.log(`- Keystone Auth (2000 runs):     Median=${results.keystone_auth.median.toFixed(2)} | P95=${results.keystone_auth.p95.toFixed(2)} | P99=${results.keystone_auth.p99.toFixed(2)} | Max=${results.keystone_auth.max.toFixed(2)}`);
  console.log(`- In-Proc Permitted (2000 runs):  Median=${results.in_process_permitted.median.toFixed(2)} | P95=${results.in_process_permitted.p95.toFixed(2)} | P99=${results.in_process_permitted.p99.toFixed(2)} | Max=${results.in_process_permitted.max.toFixed(2)}`);
  console.log(`- In-Proc Blocked (2000 runs):    Median=${results.in_process_blocked.median.toFixed(2)} | P95=${results.in_process_blocked.p95.toFixed(2)} | P99=${results.in_process_blocked.p99.toFixed(2)} | Max=${results.in_process_blocked.max.toFixed(2)}`);
  console.log(`- E2E Permitted IPC (200 runs):   Median=${results.end_to_end_permitted.median.toFixed(2)} | P95=${results.end_to_end_permitted.p95.toFixed(2)} | P99=${results.end_to_end_permitted.p99.toFixed(2)} | Max=${results.end_to_end_permitted.max.toFixed(2)}`);
  console.log(`- E2E Blocked IPC (200 runs):     Median=${results.end_to_end_blocked.median.toFixed(2)} | P95=${results.end_to_end_blocked.p95.toFixed(2)} | P99=${results.end_to_end_blocked.p99.toFixed(2)} | Max=${results.end_to_end_blocked.max.toFixed(2)}`);
}

runPhase7Benchmark().catch(err => {
  console.error(err);
  process.exit(1);
});
