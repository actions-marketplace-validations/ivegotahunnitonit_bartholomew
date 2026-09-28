const { KeystoneEngine } = require('./dist/keystone_passkey.js');

async function testKeystone() {
  console.log('='.repeat(80));
  console.log('TESTING BARTHOLOMEW KEYSTONE v5.4.23 -- ADVANCED CAPABILITIES');
  console.log('='.repeat(80) + '\n');

  const engine = new KeystoneEngine('keystone-root-dev-authority');

  // 1. Issue Passkey
  const passkey = engine.issuePasskey('agent-swe-01', {
    files: {
      allow_read: ['**/*'],
      allow_write: ['src/components', 'site/'],
      deny: ['.env', 'secrets', 'credentials.json', 'id_rsa']
    },
    commands: {
      allow_exec: ['npm test', 'npm run build', 'python -m unittest'],
      deny_exec: ['rm', 'curl', 'wget', 'sudo'],
      deny_shell_operators: true
    },
    network: {
      allow_domains: ['github.com', 'npmjs.com', 'docs.python.org'],
      allow_search: true
    },
    budget: {
      max_spend_usd: 25.00,
      max_per_txn_usd: 10.00
    },
    env: {
      deny_keys: ['KEY', 'SECRET', 'TOKEN']
    }
  }, 120);

  console.log('[1] Issued Passkey Token ID:', passkey.passkey_id);
  console.log('    Agent:', passkey.agent_id);
  console.log('    Expires At:', passkey.expires_at);
  if (!passkey.signature || !passkey.payload_hash) throw new Error('Failed to generate cryptographic passkey signature!');

  // 2. Signature verification
  const isValid = engine.verifyPasskey(passkey);
  console.log('[2] Cryptographic Signature Valid:', isValid);
  if (!isValid) throw new Error('Passkey signature verification failed!');

  // 3. Test In-Scope Action: Allowed file write
  const safeWrite = engine.evaluateAction(passkey, 'FILE_WRITE', 'src/components/Navbar.tsx');
  console.log('[3] In-Scope File Write Clearance:', safeWrite.verdict, `(${safeWrite.status}) in ${safeWrite.latency_us} us | Receipt: ${safeWrite.receipt_hash}`);
  if (safeWrite.verdict !== 'ALLOW') throw new Error('In-scope file write was blocked!');

  // 4. Test Out-of-Scope Action: Denied file read (.env)
  const secretRead = engine.evaluateAction(passkey, 'FILE_READ', '.env');
  console.log('[4] Out-of-Scope Secret Read Interception:', secretRead.verdict, `(${secretRead.reason}) in ${secretRead.latency_us} us`);
  if (secretRead.verdict !== 'DENY') throw new Error('Out-of-scope .env read was not blocked!');

  // 5. Test Out-of-Scope Action: Unauthorized file write outside scope
  const badWrite = engine.evaluateAction(passkey, 'FILE_WRITE', '.github/workflows/deploy.yml');
  console.log('[5] Out-of-Scope Workflow Write Interception:', badWrite.verdict, `(${badWrite.reason}) in ${badWrite.latency_us} us`);
  if (badWrite.verdict !== 'DENY') throw new Error('Out-of-scope workflow write was not blocked!');

  // 6. Test Out-of-Scope Action: Restricted terminal command
  const badCmd = engine.evaluateAction(passkey, 'COMMAND_EXEC', 'rm -rf /var/data');
  console.log('[6] Out-of-Scope Command Interception:', badCmd.verdict, `(${badCmd.reason}) in ${badCmd.latency_us} us`);
  if (badCmd.verdict !== 'DENY') throw new Error('Restricted rm command was not blocked!');

  // 7. Test Out-of-Scope Action: Shell injection operator
  const chainedCmd = engine.evaluateAction(passkey, 'COMMAND_EXEC', 'npm test && cat /etc/passwd');
  console.log('[7] Shell Injection Interception:', chainedCmd.verdict, `(${chainedCmd.reason}) in ${chainedCmd.latency_us} us`);
  if (chainedCmd.verdict !== 'DENY') throw new Error('Chained shell command was not blocked!');

  // 8. Test Out-of-Scope Action: Env credential access
  const badEnv = engine.evaluateAction(passkey, 'ENV_ACCESS', 'OPENAI_API_KEY');
  console.log('[8] Protected Env Interception:', badEnv.verdict, `(${badEnv.reason}) in ${badEnv.latency_us} us`);
  if (badEnv.verdict !== 'DENY') throw new Error('Protected env key access was not blocked!');

  // 9. Test Out-of-Scope Action: Spend exceeding single transaction cap ($10)
  const badTxn = engine.evaluateAction(passkey, 'FINANCIAL_SPEND', 'api-compute', 15.00);
  console.log('[9] Single-Txn Cap Interception ($15 > $10):', badTxn.verdict, `(${badTxn.reason}) in ${badTxn.latency_us} us`);
  if (badTxn.verdict !== 'DENY') throw new Error('Over-txn spend was not blocked!');

  // 10. Test Audit Receipts
  const receipts = engine.getReceiptHistory();
  console.log(`[10] Recorded ${receipts.length} audit receipts in memory.`);
  if (receipts.length < 5) throw new Error('Receipts history not recorded!');

  console.log('\n' + '='.repeat(80));
  console.log('ALL KEYSTONE v5.4.23 ADVANCED CAPABILITY TESTS PASSED 100% CLEAN!');
  console.log('='.repeat(80));
}

testKeystone().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
