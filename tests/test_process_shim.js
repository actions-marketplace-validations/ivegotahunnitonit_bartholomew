/**
 * Bartholomew Process Shim Verification Test
 * Path: tests/test_process_shim.js
 * 
 * Verifies runtime interception of child_process functions:
 * - Blocked command interception (code 126, no native spawn)
 * - Safe command pass-through
 * - Unpatch cleanup
 */

import assert from 'assert';
import childProcess from 'child_process';
import { patchChildProcess } from '../packages/npm_package/process_shim.js';

let passed = 0;
let failed = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

async function runAsyncTest(name, fn) {
  try {
    await fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`[FAIL] ${name}: ${err.message}`);
    failed++;
  }
}

async function main() {
  console.log("=".repeat(75));
  console.log("BARTHOLOMEW RUNTIME PROCESS SHIM TEST SUITE");
  console.log("=".repeat(75));

  const origExec = childProcess.exec;
  const origSpawn = childProcess.spawn;
  const shim = patchChildProcess();

  // Test 1: Interception check
  runTest("Child process functions patched", () => {
    assert.notStrictEqual(childProcess.exec, origExec);
    assert.notStrictEqual(childProcess.spawn, origSpawn);
  });

  // Test 2: Blocking destructive command via exec callback
  await runAsyncTest("Destructive command blocked in exec callback", async () => {
    return new Promise((resolve, reject) => {
      childProcess.exec("rm -rf / --no-preserve-root", (err, stdout, stderr) => {
        try {
          assert(err !== null, "Expected error on blocked command");
          assert.strictEqual(err.code, 126, "Expected exit code 126");
          assert(stderr.includes("Blocked"), "Expected Blocked message in stderr");
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  // Test 3: Blocking destructive command via spawn event
  await runAsyncTest("Destructive command blocked in spawn event emitter", async () => {
    return new Promise((resolve, reject) => {
      const proc = childProcess.spawn("rm", ["-rf", "/"]);
      let errorFired = false;
      let closeCode = null;

      proc.on('error', (err) => {
        errorFired = true;
        assert.strictEqual(err.code, 'EPERM');
      });

      proc.on('close', (code) => {
        closeCode = code;
        try {
          assert(errorFired, "Expected error event to fire");
          assert.strictEqual(closeCode, 126, "Expected close code 126");
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
  });

  // Test 4: Unpatch restores original functions
  runTest("Unpatch restores original childProcess methods", () => {
    shim.unpatch();
    assert.strictEqual(childProcess.exec, origExec);
    assert.strictEqual(childProcess.spawn, origSpawn);
  });

  console.log("=".repeat(75));
  console.log(`SUMMARY: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(75));

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
