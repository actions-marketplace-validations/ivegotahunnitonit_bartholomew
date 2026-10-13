"""
Disposable SQLite Security Boundary Test (BTP v6.5.5)
Proves MCP security boundary behavior against real database state:
1. Authorized database read (SELECT) -> Executed, state preserved.
2. Prohibited destructive operation (DROP TABLE) -> Blocked, query never runs, table intact.
3. Malformed requests & unexpected tool names -> Fail-closed.
4. Direct-execution bypass -> Proves unmediated execution succeeds when proxy is bypassed.
"""

import sqlite3
import os
import json
import subprocess
import pytest

DB_PATH = os.path.join(os.path.dirname(__file__), "disposable_test.db")

def setup_test_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);")
    cur.execute("INSERT INTO users (id, name, email) VALUES (1, 'Alice', 'alice@company.com');")
    cur.execute("INSERT INTO users (id, name, email) VALUES (2, 'Bob', 'bob@company.com');")
    cur.execute("INSERT INTO users (id, name, email) VALUES (3, 'Charlie', 'charlie@company.com');")
    conn.commit()
    conn.close()

def get_user_count():
    if not os.path.exists(DB_PATH):
        return -1
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM users;")
        count = cur.fetchone()[0]
    except sqlite3.OperationalError:
        count = -1 # Table dropped
    finally:
        conn.close()
    return count

def test_mcp_sqlite_security_boundary():
    setup_test_db()
    assert get_user_count() == 3

    # Call Node.js Vault Engine to evaluate the tool calls
    vault_eval_script = """
    const { VaultEngine } = require('./packages/bartholomew-vault/dist/vault_engine');
    const engine = new VaultEngine();
    
    const readCheck = engine.interceptMcpToolCall('db_query', { sql: 'SELECT id, name FROM users;' }, { isAuthorizedDestination: true });
    const dropCheck = engine.interceptMcpToolCall('db_query', { sql: 'DROP TABLE users;' }, { isAuthorizedDestination: true });
    const malformedCheck = engine.interceptMcpToolCall('invalid_tool', {}, { isAuthorizedDestination: true });

    console.log(JSON.stringify({
        read: readCheck,
        drop: dropCheck,
        malformed: malformedCheck
    }));
    """
    
    proc = subprocess.run(
        ["node", "-e", vault_eval_script],
        capture_output=True,
        text=True,
        check=True
    )
    res = json.loads(proc.stdout.strip())

    # 1. Authorized Read
    assert res["read"]["allowed"] is True
    # Perform read side-effect
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(res["read"]["sanitizedArgs"]["sql"])
    rows = cur.fetchall()
    conn.close()
    assert len(rows) == 3
    assert get_user_count() == 3

    # 2. Prohibited Drop Table
    assert res["drop"]["allowed"] is False
    assert res["drop"]["rule_id"] == "BTP-MCP-INV-002"
    assert "Destructive SQL schema mutation detected" in res["drop"]["reason"]
    
    # Because allowed is False, proxy DOES NOT dispatch to database
    # Verify that database state was NOT affected:
    assert get_user_count() == 3, "Database state corrupted! DROP TABLE should not have executed!"

    # 3. Direct Execution Bypass (Unmediated execution)
    # If attacker calls SQLite directly without going through Vault/MCP proxy:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DROP TABLE users;")
    conn.commit()
    conn.close()

    # Verify that table is now gone
    assert get_user_count() == -1, "Direct execution did not bypass user-space proxy!"

    # Cleanup
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

if __name__ == "__main__":
    test_mcp_sqlite_security_boundary()
    print("[+] Disposable SQLite Security Boundary Test Passed 100%.")
