/**
 * Comprehensive Node.js verification for Keystone and Vault formal features
 * (Revocation, Invocation Ceilings, Sensitivity Lattice, Destination Policies)
 */

const assert = require('assert');
const path = require('path');

// Import compiled or source modules
const { KeystoneEngine } = require('../packages/bartholomew-keystone/dist/keystone_passkey.js');
const { VaultEngine, SENSITIVITY_LATTICE_RANK } = require('../packages/bartholomew-vault/dist/vault_engine.js');

console.log('[*] Testing Keystone & Vault Formal Extensions in Node.js runtime...');

// 1. KEYSTONE REVOCATION & INVOCATION LIMITS
const keystone = new KeystoneEngine('keystone-formal-secret-key-999');

const passkey = keystone.issuePasskey('agent-007', {
  tools: {
    allow_tools: ['read_file', 'mcp_search'],
    allow_operations: ['query', 'fetch']
  },
  invocation_limits: {
    max_uses: 2,
    max_payload_bytes: 2048
  },
  destinations: {
    allow_destinations: ['mcp://local-*']
  }
}, 60);

// Evaluation 1: Valid invocation
const eval1 = keystone.evaluateMcpToolAction(passkey, 'read_file', { operation: 'fetch' }, 'mcp://local-db');
assert.strictEqual(eval1.verdict, 'ALLOW');
assert.strictEqual(eval1.status, 'CLEARANCE_GRANTED');
console.log('  [PASS] Keystone valid tool invocation allowed');

// Evaluation 2: Valid invocation (exhausts max_uses=2)
const eval2 = keystone.evaluateMcpToolAction(passkey, 'mcp_search', { operation: 'query' }, 'mcp://local-search');
assert.strictEqual(eval2.verdict, 'ALLOW');
console.log('  [PASS] Keystone second invocation allowed within max_uses=2');

// Evaluation 3: 3rd invocation must exceed limit
const eval3 = keystone.evaluateMcpToolAction(passkey, 'read_file', { operation: 'fetch' }, 'mcp://local-db');
assert.strictEqual(eval3.verdict, 'DENY');
assert.strictEqual(eval3.status, 'LIMIT_EXCEEDED');
console.log('  [PASS] Keystone exceeded invocation ceiling correctly blocked (LIMIT_EXCEEDED)');

// Revocation test
const freshPasskey = keystone.issuePasskey('agent-008', {}, 60);
assert.strictEqual(keystone.verifyPasskey(freshPasskey), true);
keystone.revokePasskey(freshPasskey.passkey_id, 'Admin revocation test');
assert.strictEqual(keystone.isRevoked(freshPasskey.passkey_id), true);
assert.strictEqual(keystone.verifyPasskey(freshPasskey), false);

const evalRevoked = keystone.evaluateMcpToolAction(freshPasskey, 'read_file');
assert.strictEqual(evalRevoked.verdict, 'DENY');
assert.strictEqual(evalRevoked.status, 'PASSKEY_REVOKED');
console.log('  [PASS] Keystone actively revoked passkey immediately blocked (PASSKEY_REVOKED)');

// 2. VAULT INFORMATION-FLOW TRACKING & EGRESS POLICIES
const vault = new VaultEngine();

// Tag source data
const t1 = vault.tagDataOrigin('data_user_email', 'INTERNAL', 'db:users');
const t2 = vault.tagDataOrigin('data_stripe_key', 'SECRET', 'vault:stripe');
assert.strictEqual(t1.label, 'INTERNAL');
assert.strictEqual(t2.label, 'SECRET');

// Lattice supremum join: max(INTERNAL, SECRET) = SECRET
const derived = vault.propagateTaint(['data_user_email', 'data_stripe_key'], 'bundle_01');
assert.strictEqual(derived.label, 'SECRET');
console.log('  [PASS] Vault Lattice join correctly calculated supremum (INTERNAL + SECRET -> SECRET)');

// Evaluate egress of SECRET to public internet -> Must DENY
const egressPublic = vault.evaluateDestinationEgress('bundle_01', 'https://api.external-webhook.site/post');
assert.strictEqual(egressPublic.allowed, false);
assert.strictEqual(egressPublic.verdict, 'DENY');
console.log('  [PASS] Vault egress to public internet denied for SECRET data');

// Evaluate egress of SECRET to secure enclave -> Must PERMIT
const egressEnclave = vault.evaluateDestinationEgress('bundle_01', 'mcp://secure-vault');
assert.strictEqual(egressEnclave.allowed, true);
assert.strictEqual(egressEnclave.verdict, 'PERMIT');
console.log('  [PASS] Vault egress to secure enclave permitted for SECRET data');

console.log('[OK] All Node.js formal tests passed successfully!');
