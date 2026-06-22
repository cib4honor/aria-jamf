"""
ARIA audit log — SQLite backend.

Drop-in replacement for the previous flat-JSON audit log. Instead of loading,
appending, and rewriting the whole file on every event, each write is a single
INSERT and each read is a single indexed query.

Schema mirrors the old JSON records exactly:
    {ts, action, tech, detail, ip}   (ts = milliseconds since epoch)

The DB path is taken from the ARIA_DB_PATH env var, falling back to
<this dir>/aria.db. Each call opens its own short-lived connection, which keeps
things thread-safe under Flask's threaded workers.
"""

import os
import time
import sqlite3
from pathlib import Path

_DEFAULT_DB = Path(__file__).parent / "aria.db"

# Columns returned to callers — matches the original JSON record shape exactly
# (no surrogate id) so existing API consumers/front-end keep working unchanged.
_FIELDS = ("ts", "action", "tech", "detail", "ip")


def get_db_path() -> Path:
    """Resolve the audit DB path from ARIA_DB_PATH, else the default location."""
    return Path(os.environ.get("ARIA_DB_PATH") or _DEFAULT_DB)


def _connect(db_path=None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path or get_db_path()))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=None) -> None:
    """Create the audit_log table and its index if they don't already exist."""
    with _connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     INTEGER NOT NULL,
                action TEXT    NOT NULL,
                tech   TEXT,
                detail TEXT,
                ip     TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
        conn.commit()


def write_audit(action: str, tech: str, detail: str, ip: str = "", db_path=None) -> None:
    """Append a single audit event. ts is stamped here as ms-since-epoch."""
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, action, tech, detail, ip) VALUES (?, ?, ?, ?, ?)",
            (int(time.time() * 1000), action, tech, detail, ip),
        )
        conn.commit()


def read_audit(limit: int = 100, offset: int = 0, db_path=None):
    """
    Return (entries, total) where entries are newest-first dicts with the
    original {ts, action, tech, detail, ip} shape — same contract the old
    inline reader exposed (reversed, then paginated).
    """
    with _connect(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        rows = conn.execute(
            "SELECT ts, action, tech, detail, ip FROM audit_log "
            "ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    entries = [{f: row[f] for f in _FIELDS} for row in rows]
    return entries, total


def count_entries(db_path=None) -> int:
    """Total number of audit rows — used by the migration verifier."""
    with _connect(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
