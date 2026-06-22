"""
One-time migration: audit_log.json -> aria.db (SQLite).

Reads the flat JSON audit log and bulk-inserts every record into the
audit_log table created by aria_audit_sqlite.init_db(). Safe to reason about:
it refuses to run if the audit_log table already contains rows, so a second
accidental run can't duplicate the data. Pass --force to wipe and reimport.

Usage:
    python3 migrate_audit_log.py [--force]
"""

import sys
import json
import sqlite3
from pathlib import Path

import aria_audit_sqlite as audit_db

BASE_DIR = Path(__file__).parent
JSON_PATH = BASE_DIR / "audit_log.json"


def main() -> int:
    force = "--force" in sys.argv[1:]
    db_path = audit_db.get_db_path()

    if not JSON_PATH.exists():
        print(f"ERROR: source not found: {JSON_PATH}")
        return 1

    records = json.loads(JSON_PATH.read_text())
    print(f"Source : {JSON_PATH} ({len(records)} entries)")
    print(f"Target : {db_path}")

    audit_db.init_db(db_path)

    existing = audit_db.count_entries(db_path)
    if existing and not force:
        print(
            f"ABORT: audit_log already has {existing} rows. "
            f"Re-run with --force to wipe and reimport."
        )
        return 1

    with sqlite3.connect(str(db_path)) as conn:
        if force and existing:
            conn.execute("DELETE FROM audit_log")
            print(f"--force: cleared {existing} existing rows")
        conn.executemany(
            "INSERT INTO audit_log (ts, action, tech, detail, ip) VALUES (?, ?, ?, ?, ?)",
            [
                (
                    int(r["ts"]),
                    r.get("action", ""),
                    r.get("tech", ""),
                    r.get("detail", ""),
                    r.get("ip", ""),
                )
                for r in records
            ],
        )
        conn.commit()

    final = audit_db.count_entries(db_path)
    print(f"Done   : {final} rows in audit_log")
    if final != len(records):
        print(f"WARNING: row count {final} != source count {len(records)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
