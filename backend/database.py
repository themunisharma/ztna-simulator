# ============================================================
#  database.py  —  Zero Trust Network Access Simulator
#  SQLite persistence for access logs and session stats
# ============================================================

import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "ztna.db"

# ── Init ──────────────────────────────────────────────────────
def init_db():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL,
            username      TEXT    NOT NULL,
            full_name     TEXT    NOT NULL,
            role          TEXT    NOT NULL,
            resource      TEXT    NOT NULL,
            device_health TEXT    NOT NULL,
            location      TEXT    NOT NULL,
            login_hour    INTEGER NOT NULL,
            failed_logins INTEGER NOT NULL,
            risk_score    INTEGER NOT NULL,
            verdict       TEXT    NOT NULL,
            reason        TEXT    NOT NULL,
            factors_json  TEXT    NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id        INTEGER PRIMARY KEY CHECK (id = 1),
            total     INTEGER DEFAULT 0,
            allowed   INTEGER DEFAULT 0,
            mfa       INTEGER DEFAULT 0,
            denied    INTEGER DEFAULT 0
        )
    """)
    conn.execute("INSERT OR IGNORE INTO stats (id) VALUES (1)")
    conn.commit()
    conn.close()

# ── Log an access event ───────────────────────────────────────
def log_access(
    username:      str,
    full_name:     str,
    role:          str,
    resource:      str,
    device_health: str,
    location:      str,
    login_hour:    int,
    failed_logins: int,
    risk_score:    int,
    verdict:       str,
    reason:        str,
    factors:       list,
):
    conn = sqlite3.connect(DB_PATH)
    ts = datetime.now(timezone.utc).isoformat()
    factors_json = json.dumps([f.model_dump() for f in factors])
    conn.execute("""
        INSERT INTO access_logs
        (timestamp, username, full_name, role, resource, device_health,
         location, login_hour, failed_logins, risk_score, verdict, reason, factors_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (ts, username, full_name, role, resource, device_health,
          location, login_hour, failed_logins, risk_score, verdict, reason, factors_json))

    # Update summary stats
    col = {"ALLOW": "allowed", "MFA_REQUIRED": "mfa", "DENY": "denied"}.get(verdict, "denied")
    conn.execute(f"UPDATE stats SET total = total + 1, {col} = {col} + 1 WHERE id = 1")
    conn.commit()
    conn.close()

# ── Fetch logs ────────────────────────────────────────────────
def get_logs(limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM access_logs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    result = []
    for row in rows:
        d = dict(row)
        d["factors"] = json.loads(d.pop("factors_json"))
        result.append(d)
    return result

# ── Fetch stats ───────────────────────────────────────────────
def get_stats() -> dict:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM stats WHERE id = 1").fetchone()
    conn.close()
    if not row:
        return {"total": 0, "allowed": 0, "mfa": 0, "denied": 0}
    return dict(row)

# ── High-risk users ───────────────────────────────────────────
def get_high_risk_users(min_score: int = 70, limit: int = 10) -> list[dict]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT username, full_name, role,
               COUNT(*) as attempts,
               MAX(risk_score) as max_score,
               SUM(CASE WHEN verdict='DENY' THEN 1 ELSE 0 END) as denials,
               MAX(timestamp) as last_attempt
        FROM access_logs
        WHERE risk_score >= ?
        GROUP BY username
        ORDER BY max_score DESC
        LIMIT ?
    """, (min_score, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── Clear logs (for demo reset) ───────────────────────────────
def clear_logs():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM access_logs")
    conn.execute("UPDATE stats SET total=0, allowed=0, mfa=0, denied=0 WHERE id=1")
    conn.commit()
    conn.close()
