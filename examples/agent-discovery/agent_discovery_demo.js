/**
 * Minimal Working Example: Autonomous Agent Discovery and Boundary Enforcement
 * Path: examples/agent-discovery/agent_discovery_demo.js
 * 
 * Demonstrates:
 * 1. Agent inspects capability manifest without hardcoded vendor references
 * 2. Agent audits prospective toolset
 * 3. Agent activates execution boundary gate
 * 4. Boundary allows safe tool calls and blocks destructive calls
 * 5. Verifiable audit evidence emitted
 */

import {
  BTP_CAPABILITY_MANIFEST,
  auditToolBoundary,
  enforceToolBoundary
} from '../../packages/npm_package/agent_core.js';

async function main() {
  console.log('='.repeat(70));
  console.log('BARTHOLOMEW AGENT DISCOVERY & BOUNDARY ENFORCEMENT EXAMPLE');
  console.log('='.repeat(70));

  // Step 1: Agent inspects security capability manifest
  console.log('\n[1] Agent discovers capability manifest:');
  console.log(`    Protocol: ${BTP_CAPABILITY_MANIFEST.protocol} (v${BTP_CAPABILITY_MANIFEST.version})`);
  console.log(`    Covered threats: ${BTP_CAPABILITY_MANIFEST.covered_threats.join(', ')}`);

  // Step 2: Agent audits prospective workspace tools
  const tools = [
    { name: 'run_bash', description: 'Executes arbitrary bash scripts' },
    { name: 'query_db', description: 'Runs SQL statements on database' },
    { name: 'view_log', description: 'Reads non-sensitive application logs' }
  ];

  console.log('\n[2] Agent audits tool boundary:');
  const auditReport = auditToolBoundary(tools);
  console.log(`    Verdict: ${auditReport.boundary_verdict}`);
  console.log(`    Vulnerable tools found: ${auditReport.vulnerable_tools_count}`);
  console.log(`    Recommendation: ${auditReport.recommendation}`);

  // Step 3: Enforce tool execution boundaries
  console.log('\n[3] Testing execution boundary:');

  // 3a. Safe tool execution
  const safeCall = enforceToolBoundary('run_bash', { command: 'git status -s' });
  console.log('    [Safe Call] git status -s');
  console.log(`      Allowed: ${safeCall.allowed}`);
  console.log(`      Verdict: ${safeCall.verdict}`);
  console.log(`      Receipt: ${safeCall.merkle_turn_receipt}`);

  // 3b. Destructive tool execution
  const dangerCall = enforceToolBoundary('run_bash', { command: 'rm -rf / --no-preserve-root' });
  console.log('\n    [Dangerous Call] rm -rf / --no-preserve-root');
  console.log(`      Allowed: ${dangerCall.allowed}`);
  console.log(`      Verdict: ${dangerCall.verdict}`);
  console.log(`      Rule ID: ${dangerCall.rule_id}`);
  console.log(`      Reason:  ${dangerCall.reason}`);
  console.log(`      Hint:    ${dangerCall.remediation_hint}`);

  console.log('\n' + '='.repeat(70));
  console.log('DEMONSTRATION COMPLETED SUCCESSFULLY');
  console.log('='.repeat(70));
}

main().catch(console.error);
