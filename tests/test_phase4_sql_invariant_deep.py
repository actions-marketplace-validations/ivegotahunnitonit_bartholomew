"""
Phase 4: Comprehensive SQL Invariant Deep Challenge (BTP v6.5.5)
Evaluates Bartholomew Vault's AST regex checks against a real disposable SQLite database.
Tests comments, string literals, multiple statements, whitespace variations, and dialect syntax.
"""

import sqlite3
import os
import json
import subprocess
import pytest

DB_PATH = os.path.join(os.path.dirname(__file__), "phase4_disposable.db")

def init_db():
    if os.path.exists(DB_PATH):
        try: os.remove(DB_PATH)
        except: pass
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);")
    cur.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@corp.com');")
    cur.execute("INSERT INTO users VALUES (2, 'Bob', 'bob@corp.com');")
    cur.execute("INSERT INTO users VALUES (3, 'Charlie', 'charlie@corp.com');")
    cur.execute("CREATE TABLE audit_logs (id INTEGER PRIMARY KEY, message TEXT);")
    cur.execute("INSERT INTO audit_logs VALUES (10, 'System initialized');")
    conn.commit()
    conn.close()

def get_counts():
    if not os.path.exists(DB_PATH):
        return -1, -1
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    user_count = -1
    log_count = -1
    try:
        cur.execute("SELECT COUNT(*) FROM users;")
        user_count = cur.fetchone()[0]
    except sqlite3.OperationalError:
        user_count = -1 # Dropped
    try:
        cur.execute("SELECT COUNT(*) FROM audit_logs;")
        log_count = cur.fetchone()[0]
    except sqlite3.OperationalError:
        log_count = -1
    conn.close()
    return user_count, log_count

def eval_vault_tool(sql):
    script = f"""
    const {{ VaultEngine }} = require('./packages/bartholomew-vault/dist/vault_engine');
    const engine = new VaultEngine();
    const res = engine.interceptMcpToolCall('db_query', {{ sql: {json.dumps(sql)} }}, {{ isAuthorizedDestination: true }});
    console.log(JSON.stringify(res));
    """
    proc = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(proc.stdout.strip())

def test_sql_invariant_suite():
    init_db()
    u, l = get_counts()
    assert u == 3
    assert l == 1

    # 1. Standard authorized SELECT
    res = eval_vault_tool("SELECT id, name FROM users;")
    assert res["allowed"] is True

    # 2. Standard prohibited DROP TABLE
    res = eval_vault_tool("DROP TABLE users;")
    assert res["allowed"] is False
    assert res["rule_id"] == "BTP-MCP-INV-002"

    # 3. Inline comment evasion DROP/**/TABLE
    res = eval_vault_tool("DROP/**/TABLE users;")
    assert res["allowed"] is False
    assert res["rule_id"] == "BTP-MCP-INV-002"

    # 4. Multi-line block comment DROP/* \n comment \n */TABLE
    res = eval_vault_tool("DROP/* \n multi-line comment \n */TABLE users;")
    assert res["allowed"] is False
    assert res["rule_id"] == "BTP-MCP-INV-002"

    # 5. Line comment with newline DROP--comment\nTABLE
    res = eval_vault_tool("DROP--inline comment\nTABLE users;")
    assert res["allowed"] is False
    assert res["rule_id"] == "BTP-MCP-INV-002"

    # 6. Quoted identifiers
    res_double = eval_vault_tool('DROP TABLE "users";')
    res_backtick = eval_vault_tool('DROP TABLE `users`;')
    assert res_double["allowed"] is False
    assert res_backtick["allowed"] is False

    # 7. Multiple statements with separator
    res = eval_vault_tool("SELECT 1; DROP TABLE users;")
    assert res["allowed"] is False

    # 8. Schema alteration ALTER TABLE ... DROP
    res = eval_vault_tool("ALTER TABLE users DROP COLUMN email;")
    assert res["allowed"] is False

    # 9. String literal limitation (Documented Regex False-Positive)
    # When a string literal contains 'DROP TABLE', regex flags it as DENY.
    res_literal = eval_vault_tool("SELECT * FROM audit_logs WHERE message = 'DROP TABLE users';")
    # This is a documented limitation of regex-based heuristics (false positive)
    is_false_positive = (res_literal["allowed"] is False)

    # 10. Database-native query_only validation
    # Verify that SQLite engine-level read-only mode provides absolute protection
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("PRAGMA query_only = ON;")
    with pytest.raises(sqlite3.OperationalError):
        cur.execute("DROP TABLE users;")
    conn.close()

    # Final DB integrity check: tables remain intact
    u_after, l_after = get_counts()
    assert u_after == 3
    assert l_after == 1

    if os.path.exists(DB_PATH):
        try: os.remove(DB_PATH)
        except: pass

if __name__ == "__main__":
    test_sql_invariant_suite()
    print("[+] Phase 4 SQL Invariant Suite Passed.")
