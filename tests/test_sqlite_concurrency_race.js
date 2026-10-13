const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

async function testConcurrentReplay() {
  console.log('[*] Testing concurrent cross-process replay consumption with SQLite WAL...');
  const dbFile = path.resolve(__dirname, 'test_race.db');

  // Helper script for workers
  const workerScript = `
    const { DatabaseSync } = require('node:sqlite');
    const dbPath = process.argv[2];
    const nonce = process.argv[3];
    const db = new DatabaseSync(dbPath);
    db.exec('PRAGMA journal_mode = WAL;');
    db.exec('PRAGMA busy_timeout = 5000;');
    db.exec('CREATE TABLE IF NOT EXISTS consumed_nonces (passkey_id TEXT PRIMARY KEY, expires_at INTEGER, consumed_at INTEGER);');

    try {
      const stmt = db.prepare('INSERT INTO consumed_nonces (passkey_id, expires_at, consumed_at) VALUES (?, ?, ?)');
      stmt.run(nonce, Date.now() + 60000, Date.now());
      process.stdout.write('SUCCESS\\n');
    } catch (err) {
      if (err.message && err.message.includes('UNIQUE constraint failed')) {
        process.stdout.write('REPLAY_DETECTED\\n');
      } else {
        process.stdout.write('ERROR:' + err.message + '\\n');
      }
    }
  `;

  const workerFile = path.resolve(__dirname, 'temp_sqlite_worker.js');
  fs.writeFileSync(workerFile, workerScript, 'utf-8');

  try {
    // Test 1: Two processes attempt to consume the SAME token simultaneously
    const targetNonce = 'race_token_' + Date.now();

    const p1 = spawn(process.execPath, [workerFile, dbFile, targetNonce]);
    const p2 = spawn(process.execPath, [workerFile, dbFile, targetNonce]);

    let out1 = '', out2 = '';
    p1.stdout.on('data', d => out1 += d.toString());
    p2.stdout.on('data', d => out2 += d.toString());

    await Promise.all([
      new Promise(res => p1.on('exit', res)),
      new Promise(res => p2.on('exit', res))
    ]);

    const results = [out1.trim(), out2.trim()].sort();
    console.log('Results from concurrent callers:', results);

    if (results[0] === 'REPLAY_DETECTED' && results[1] === 'SUCCESS') {
      console.log('[+] PASS: Exactly ONE process succeeded, and the other was rejected with REPLAY_DETECTED!');
    } else {
      console.error('[-] FAIL: Concurrency race condition detected! Both succeeded or error occurred:', results);
      process.exit(1);
    }

    // Test 2: Simultaneous consumption of different tokens (detect lost updates)
    const nonceA = 'token_A_' + Date.now();
    const nonceB = 'token_B_' + Date.now();

    const pA = spawn(process.execPath, [workerFile, dbFile, nonceA]);
    const pB = spawn(process.execPath, [workerFile, dbFile, nonceB]);

    let outA = '', outB = '';
    pA.stdout.on('data', d => outA += d.toString());
    pB.stdout.on('data', d => outB += d.toString());

    await Promise.all([
      new Promise(res => pA.on('exit', res)),
      new Promise(res => pB.on('exit', res))
    ]);

    if (outA.trim() === 'SUCCESS' && outB.trim() === 'SUCCESS') {
      console.log('[+] PASS: Different tokens consumed concurrently without lost updates!');
    } else {
      console.error('[-] FAIL: Lost update or failure during distinct token consumption:', outA, outB);
      process.exit(1);
    }
  } finally {
    try { fs.unlinkSync(workerFile); } catch {}
    [dbFile, dbFile + '-wal', dbFile + '-shm'].forEach(f => {
      try { fs.unlinkSync(f); } catch {}
    });
  }
}

testConcurrentReplay().catch(err => {
  console.error(err);
  process.exit(1);
});
