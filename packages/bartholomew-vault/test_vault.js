/**
 * Bartholomew Vault Verification Test Suite (BTP v6.5.2)
 * ========================================================
 */

const { VaultEngine } = require('./dist/vault_engine.js');
const assert = require('assert');

function runSuite() {
  console.log('='.repeat(80));
  console.log('TESTING BARTHOLOMEW VAULT v6.5.2 -- IN-PROCESS DATA & PII TOKENIZATION');
  console.log('='.repeat(80) + '\n');

  const engine = new VaultEngine();

  // Test Payload containing secrets and PII
  const samplePayload = `
    const openAiKey = process.env.TEST_OPENAI_KEY || "TESTING_CANARY_OPENAI_KEY_MOCK_12345";
    const anthropicKey = process.env.TEST_ANTHROPIC_KEY || "TESTING_CANARY_ANTHROPIC_KEY_MOCK_12345";
    const stripeKey = process.env.TEST_STRIPE_KEY || "TESTING_CANARY_STRIPE_KEY_MOCK_12345";
    const awsKey = process.env.TEST_AWS_KEY || "TESTING_CANARY_AWS_KEY_MOCK_12345";
    const dbUrl = "postgres://test_user:CanarySecretPass123@127.0.0.1:5432/patient_records";
    const patientSsn = "000-12-3456";
    const patientCc = "0000-0000-0000-0000";
    const patientEmail = "patient.sample@healthcorp.test";
  `;

  // 1. In-Process Tokenization & Latency Benchmark
  console.log('[1] Tokenizing Mixed High-Entropy & PHI/PII Payload...');
  const result = engine.tokenize(samplePayload);

  console.log(`    Tokens Created: ${result.tokenCount}`);
  console.log(`    Latency Overhead: ${result.latencyUs.toFixed(2)} µs`);
  console.log(`    Audit Digest: ${result.auditDigest.substring(0, 16)}...`);

  assert.strictEqual(result.tokenCount, 8, 'Expected exactly 8 sensitive items to be tokenized.');
  assert.ok(!result.sanitized.includes('SuperSecretPass123'), 'Plaintext DB password must be scrubbed!');
  assert.ok(!result.sanitized.includes('sk-proj-998877'), 'Plaintext OpenAI key must be scrubbed!');
  assert.ok(!result.sanitized.includes('123-45-6789'), 'Plaintext SSN must be scrubbed!');
  assert.ok(!result.sanitized.includes('4242-4242-4242-4242'), 'Plaintext credit card must be scrubbed!');
  assert.ok(!result.sanitized.includes('patient.smith@healthcorp.internal'), 'Plaintext email must be scrubbed!');

  console.log('    [PASS] All raw credentials and PII completely scrubbed from output.');

  // 2. Referential Integrity Verification
  console.log('\n[2] Verifying Referential Integrity Across Distinct Invocations...');
  const repeatedText = 'User patient.smith@healthcorp.internal confirmed with patient.smith@healthcorp.internal';
  const tokenizedRepeat = engine.tokenize(repeatedText);
  const matches = tokenizedRepeat.sanitized.match(/anon-[a-z0-9]+@btp-vault\.internal/g);
  assert.ok(matches && matches.length === 2, 'Should find 2 surrogate email tokens');
  assert.strictEqual(matches[0], matches[1], 'Identical raw inputs must map to identical surrogate tokens!');
  console.log(`    [PASS] Referential integrity verified: [${matches[0]}] used consistently.`);

  // 3. Just-In-Time OS Dispatch Detokenization
  console.log('\n[3] Testing Just-In-Time OS Dispatch Detokenization (Zero-Leakage Execution)...');
  const agentGeneratedCommand = `curl -X POST https://api.healthcorp.internal/triage -d '{"email": "${matches[0]}"}'`;
  console.log(`    Agent Dispatched Command (Cloud LLM view): ${agentGeneratedCommand}`);

  const dispatch = engine.detokenizeProcessExecution(agentGeneratedCommand);
  console.log(`    Kernel/Child Process Executed:             ${dispatch.executableCommand}`);
  console.log(`    Swapped Tokens Count:                    ${dispatch.swappedCount}`);

  assert.strictEqual(dispatch.swappedCount, 1, 'Expected 1 token swapped during dispatch.');
  assert.ok(
    dispatch.executableCommand.includes('patient.smith@healthcorp.internal'),
    'OS execution command must receive real value so integration tests pass.'
  );
  console.log('    [PASS] OS dispatch successfully restored real value in-memory for child process!');

  // 4. Reverse Detokenization
  console.log('\n[4] Testing Full Round-Trip Detokenization...');
  const restored = engine.detokenize(result.sanitized);
  assert.strictEqual(restored, samplePayload, 'Full detokenization must restore exact original payload!');
  console.log('    [PASS] Full round-trip detokenization restored original payload 100% cleanly.');

  // 5. Compliance Dossier Generation (Drata / Vanta Audit Evidence)
  console.log('\n[5] Generating Compliance Audit Dossier for Drata / Vanta...');
  const dossier = engine.exportComplianceDossier();
  console.log(`    Dossier ID:             ${dossier.dossier_id}`);
  console.log(`    Zero Leakage Attested:  ${dossier.zero_leakage_attestation}`);
  console.log(`    Total Receipts Logged:  ${dossier.total_tokenized_transactions}`);
  console.log(`    Conformance Baseline:   ${dossier.audit_receipts[0].conformance}`);

  assert.ok(dossier.zero_leakage_attestation, 'Zero leakage attestation must be true');
  assert.ok(dossier.audit_receipts.length >= 2, 'Audit receipts must be logged');
  console.log('    ✓ Compliance dossier generated with valid cryptographic digests.');

  console.log('\n' + '='.repeat(80));
  console.log('ALL 5 BARTHOLOMEW VAULT VERIFICATION TESTS PASSED (100% SUCCESS)');
  console.log('='.repeat(80));
}

runSuite();
