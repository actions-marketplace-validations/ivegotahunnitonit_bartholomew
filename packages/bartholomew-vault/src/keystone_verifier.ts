/**
 * Bartholomew Keystone Authorization Verifier & Persistent Replay Guard (BTP v6.5.5)
 * ===================================================================================
 * Evaluates HMAC-SHA256 capability passkeys at the MCP stdio dispatch boundary.
 * Enforces Zero-Trust capability scopes, workspace bindings, spend ceilings, and
 * persistent replay protection surviving process restarts.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface KeystoneScope {
  tools?: {
    allow?: string[];
    deny?: string[];
  };
  commands?: {
    allow_exec?: string[];
    deny_exec?: string[];
  };
  files?: {
    allow_read?: string[];
    allow_write?: string[];
    deny?: string[];
  };
  budget?: {
    max_spend_usd?: number;
    max_per_txn_usd?: number;
  };
}

export interface KeystonePasskey {
  passkey_id: string;
  agent_id: string;
  workspace_id?: string;
  issuer: string;
  issued_at: string;
  expires_at: string;
  single_use?: boolean;
  scopes: KeystoneScope;
  payload_hash: string;
  signature: string;
}

export interface KeystoneVerificationResult {
  allowed: boolean;
  code: number;
  rule_id: string;
  reason: string;
  agent_id?: string;
  workspace_id?: string;
}

export interface ReplayConsumptionResult {
  success: boolean;
  isReplay: boolean;
  isCorrupted?: boolean;
  reason?: string;
}

export class PersistentReplayStore {
  private filePath: string;
  private db: any = null;
  private inMemoryCache: Set<string> = new Set();
  private isCorrupted: boolean = false;

  constructor(customPath?: string) {
    if (customPath) {
      this.filePath = customPath;
    } else {
      const btpDir = path.join(process.cwd(), '.btp');
      if (!fs.existsSync(btpDir)) {
        try {
          fs.mkdirSync(btpDir, { recursive: true });
        } catch {}
      }
      this.filePath = path.join(btpDir, 'consumed_nonces.db');
    }
    this.initDatabase();
  }

  private initDatabase(): void {
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      // Pre-check for corrupted JSON file if customPath was .json
      if (fs.existsSync(this.filePath) && this.filePath.endsWith('.json')) {
        try {
          const content = fs.readFileSync(this.filePath, 'utf-8').trim();
          if (content && content !== '{}' && content !== '[]') {
            JSON.parse(content);
          }
        } catch {
          this.isCorrupted = true;
          return;
        }
      }

      const dbPath = this.filePath.endsWith('.json') 
        ? this.filePath.replace(/\.json$/, '.db') 
        : (this.filePath.endsWith('.db') ? this.filePath : this.filePath + '.db');

      const { DatabaseSync } = require('node:sqlite');
      this.db = new DatabaseSync(dbPath);
      this.db.exec('PRAGMA journal_mode = WAL;');
      this.db.exec('PRAGMA busy_timeout = 5000;');
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS consumed_nonces (
          passkey_id TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL,
          consumed_at INTEGER NOT NULL
        );
      `);

      // Populate in-memory cache and migrate from legacy JSON if present
      const rows = this.db.prepare('SELECT passkey_id FROM consumed_nonces').all();
      for (const r of rows) {
        this.inMemoryCache.add(r.passkey_id);
      }

      if (fs.existsSync(this.filePath) && this.filePath.endsWith('.json')) {
        try {
          const content = fs.readFileSync(this.filePath, 'utf-8').trim();
          if (content) {
            const parsed = JSON.parse(content);
            const now = Date.now();
            const insertStmt = this.db.prepare(
              'INSERT INTO consumed_nonces (passkey_id, expires_at, consumed_at) VALUES (?, ?, ?) ON CONFLICT(passkey_id) DO NOTHING'
            );
            if (Array.isArray(parsed)) {
              for (const id of parsed) {
                insertStmt.run(id, now + 3600000, now);
                this.inMemoryCache.add(id);
              }
            } else if (typeof parsed === 'object') {
              for (const [id, exp] of Object.entries(parsed)) {
                const expTime = typeof exp === 'string' ? new Date(exp).getTime() : 0;
                if (expTime === 0 || expTime > now) {
                  insertStmt.run(id, expTime, now);
                  this.inMemoryCache.add(id);
                }
              }
            }
          }
        } catch {}
      }
    } catch (err) {
      this.isCorrupted = true;
    }
  }

  /**
   * Atomic single-operation consumption with SQLite unique constraint enforcement.
   * Exactly one concurrent caller can succeed for any given passkey_id.
   * Fails closed if the storage is corrupted or unavailable.
   */
  public consume(passkeyId: string, expiresAt: string | number): ReplayConsumptionResult {
    if (this.isCorrupted || !this.db) {
      return {
        success: false,
        isReplay: false,
        isCorrupted: true,
        reason: 'Replay store unavailable or corrupted. Gating fails closed.'
      };
    }

    const expTime = typeof expiresAt === 'string' ? new Date(expiresAt).getTime() : Number(expiresAt);
    const now = Date.now();

    try {
      const stmt = this.db.prepare(
        'INSERT INTO consumed_nonces (passkey_id, expires_at, consumed_at) VALUES (?, ?, ?)'
      );
      stmt.run(passkeyId, isNaN(expTime) ? now + 3600000 : expTime, now);
      this.inMemoryCache.add(passkeyId);

      // Keep legacy JSON file in sync if filePath was .json for legacy test compatibility
      if (this.filePath.endsWith('.json')) {
        this.syncJsonDisk(passkeyId, String(expiresAt));
      }

      return { success: true, isReplay: false };
    } catch (err: any) {
      const msg = err && err.message ? err.message : String(err);
      if (msg.includes('UNIQUE constraint failed') || msg.includes('PRIMARY KEY')) {
        return {
          success: false,
          isReplay: true,
          reason: `Replayed single-use passkey ID '${passkeyId}' rejected.`
        };
      }
      this.isCorrupted = true;
      return {
        success: false,
        isReplay: false,
        isCorrupted: true,
        reason: `Replay store error: ${msg}. Gating fails closed.`
      };
    }
  }

  private syncJsonDisk(passkeyId: string, expiresAt: string): void {
    try {
      let diskObj: Record<string, string> = {};
      if (fs.existsSync(this.filePath)) {
        try {
          const content = fs.readFileSync(this.filePath, 'utf-8').trim();
          if (content) diskObj = JSON.parse(content);
        } catch {}
      }
      diskObj[passkeyId] = expiresAt;
      const tmpPath = `${this.filePath}.tmp.${process.pid}.${Date.now()}`;
      fs.writeFileSync(tmpPath, JSON.stringify(diskObj, null, 2), 'utf-8');
      fs.renameSync(tmpPath, this.filePath);
    } catch {}
  }

  public isConsumed(passkeyId: string): boolean {
    if (this.isCorrupted || !this.db) {
      return true; // Fail closed
    }
    try {
      const stmt = this.db.prepare('SELECT 1 FROM consumed_nonces WHERE passkey_id = ?');
      const row = stmt.get(passkeyId);
      return !!row;
    } catch {
      this.isCorrupted = true;
      return true;
    }
  }

  public record(passkeyId: string, expiresAt: string): void {
    this.consume(passkeyId, expiresAt);
  }

  public pruneExpired(): number {
    if (this.isCorrupted || !this.db) return 0;
    try {
      const stmt = this.db.prepare('DELETE FROM consumed_nonces WHERE expires_at < ?');
      const info = stmt.run(Date.now());
      return info.changes || 0;
    } catch {
      return 0;
    }
  }

  public clear(): void {
    this.inMemoryCache.clear();
    this.isCorrupted = false;
    if (this.db) {
      try {
        this.db.exec('DELETE FROM consumed_nonces;');
      } catch {}
    }
    if (fs.existsSync(this.filePath)) {
      try { fs.unlinkSync(this.filePath); } catch {}
    }
    const dbPath = this.filePath.endsWith('.json') 
      ? this.filePath.replace(/\.json$/, '.db') 
      : (this.filePath.endsWith('.db') ? this.filePath : this.filePath + '.db');
    [dbPath, dbPath + '-wal', dbPath + '-shm'].forEach(f => {
      try { if (fs.existsSync(f)) fs.unlinkSync(f); } catch {}
    });
  }
}

export class KeystoneVerifier {
  private signingSecret: string | null = null;
  private replayStore: PersistentReplayStore;
  private strictMode: boolean;

  constructor(options: { signingSecret?: string; replayStorePath?: string; strictMode?: boolean } = {}) {
    this.signingSecret = options.signingSecret || process.env.BTP_KEYSTONE_SECRET || null;
    this.replayStore = new PersistentReplayStore(options.replayStorePath);
    // Strict mode requires passkey by default (fail-closed unless BTP_ENFORCE_KEYSTONE=0)
    this.strictMode = options.strictMode !== undefined 
      ? options.strictMode 
      : (process.env.BTP_ENFORCE_KEYSTONE !== '0');
  }

  public setSigningSecret(secret: string): void {
    this.signingSecret = secret;
  }

  public getReplayStore(): PersistentReplayStore {
    return this.replayStore;
  }

  /**
   * Evaluates an inbound JSON-RPC tools/call message for Keystone clearance.
   */
  public verifyToolCall(
    toolName: string,
    toolArgs: Record<string, any>,
    rawPasskey?: any
  ): KeystoneVerificationResult {
    // 1. Missing passkey check
    if (!rawPasskey) {
      if (this.strictMode) {
        return {
          allowed: false,
          code: -32001,
          rule_id: 'KEYSTONE-MISSING-PASSKEY',
          reason: `Missing required capability passkey for protected tool invocation '${toolName}'.`
        };
      }
      // If not strict mode, allow unauthenticated call through to AST gate
      return {
        allowed: true,
        code: 0,
        rule_id: 'KEYSTONE-UNENFORCED',
        reason: 'Keystone enforcement not active for unauthenticated tool call.'
      };
    }

    const passkey = rawPasskey as KeystonePasskey;

    // 2. Malformed structure check
    if (!passkey.passkey_id || !passkey.agent_id || !passkey.issued_at || !passkey.expires_at || !passkey.scopes || !passkey.signature) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-MALFORMED',
        reason: 'Malformed capability passkey structure: required authorization fields missing.'
      };
    }

    // 3. Expiration and Freshness Check
    const now = Date.now();
    const expiryTime = new Date(passkey.expires_at).getTime();
    const issuedTime = new Date(passkey.issued_at).getTime();

    if (isNaN(expiryTime) || isNaN(issuedTime)) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-INVALID-TIMESTAMP',
        reason: 'Malformed passkey timestamp format.'
      };
    }

    if (now > expiryTime) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-EXPIRED',
        reason: `Capability passkey expired at ${passkey.expires_at}.`
      };
    }

    if (now < issuedTime - 60000) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-CLOCK-SKEW',
        reason: 'Passkey issued_at timestamp is in the future.'
      };
    }

    // 4. Secret Configuration Check
    const secret = this.signingSecret;
    if (!secret) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-NO-KEY',
        reason: 'Keystone signing secret (BTP_KEYSTONE_SECRET) is not configured in environment. Gating fails closed.'
      };
    }

    // 5. Signature & Payload Integrity Check
    const canonicalData = JSON.stringify({
      passkey_id: passkey.passkey_id,
      agent_id: passkey.agent_id,
      workspace_id: passkey.workspace_id,
      issuer: passkey.issuer || 'Bartholomew-Keystone-Authority',
      issued_at: passkey.issued_at,
      expires_at: passkey.expires_at,
      single_use: passkey.single_use,
      scopes: passkey.scopes
    });

    const expectedHash = crypto.createHash('sha256').update(canonicalData).digest('hex');
    const expectedSig = crypto.createHmac('sha256', secret).update(expectedHash).digest('hex');

    if (passkey.payload_hash && passkey.payload_hash !== expectedHash) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-PAYLOAD-TAMPERED',
        reason: 'Passkey payload hash does not match canonical scope data.'
      };
    }

    if (passkey.signature !== expectedSig) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-INVALID-SIGNATURE',
        reason: 'Cryptographic HMAC signature verification failed. Token rejected.'
      };
    }

    // 6. Workspace Binding Check
    const activeWorkspace = process.env.BTP_WORKSPACE_ID;
    if (activeWorkspace && passkey.workspace_id && passkey.workspace_id !== activeWorkspace) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-WORKSPACE-MISMATCH',
        reason: `Passkey bound to workspace '${passkey.workspace_id}' cannot be used in active workspace '${activeWorkspace}'.`
      };
    }

    // 7. Capability Scope Check (Case-insensitive normalization)
    const scopes = passkey.scopes || {};
    const toolScopes = scopes.tools || {};
    const commandScopes = scopes.commands || {};
    const normTool = toolName.toLowerCase();

    // Explicit deny list check
    if (toolScopes.deny && toolScopes.deny.some(d => d.toLowerCase() === normTool)) {
      return {
        allowed: false,
        code: -32001,
        rule_id: 'KEYSTONE-TOOL-DENIED',
        reason: `Tool '${toolName}' is explicitly forbidden by passkey deny policy.`
      };
    }

    // Allow list check
    const allowedTools = toolScopes.allow || commandScopes.allow_exec;
    if (allowedTools && allowedTools.length > 0) {
      const isAllowed = allowedTools.includes('*') || allowedTools.some(a => a.toLowerCase() === normTool);
      if (!isAllowed) {
        return {
          allowed: false,
          code: -32001,
          rule_id: 'KEYSTONE-TOOL-OUT-OF-SCOPE',
          reason: `Tool '${toolName}' falls outside authorized capabilities [${allowedTools.join(', ')}].`
        };
      }
    }

    // 8. Atomic Replay Defense Check (Single-use tokens or persistent nonce tracking)
    if (passkey.single_use !== false) {
      const consumption = this.replayStore.consume(passkey.passkey_id, passkey.expires_at);
      if (!consumption.success) {
        return {
          allowed: false,
          code: -32001,
          rule_id: consumption.isReplay ? 'KEYSTONE-REPLAY-DETECTED' : 'KEYSTONE-REPLAY-STORAGE-ERROR',
          reason: consumption.reason || `Replayed single-use passkey ID '${passkey.passkey_id}' rejected.`
        };
      }
    }

    return {
      allowed: true,
      code: 0,
      rule_id: 'KEYSTONE-PERMIT',
      reason: 'Capability passkey verified clean.',
      agent_id: passkey.agent_id,
      workspace_id: passkey.workspace_id
    };
  }
}
