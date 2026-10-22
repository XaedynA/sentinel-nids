"""Local SQLite alert history. Never stores packet payloads."""
from __future__ import annotations
import json
from contextlib import closing
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path.home() / ".nids_portfolio" / "alerts.sqlite3"

def connect(db_path=None):
    path = Path(db_path) if db_path else DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path))
    db.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL, capture_name TEXT NOT NULL,
        packet_count INTEGER NOT NULL, source_count INTEGER NOT NULL,
        alert_count INTEGER NOT NULL, alerts_json TEXT NOT NULL)""")
    db.commit()
    return db

def save_scan(name, records, alerts, db_path=None):
    with closing(connect(db_path)) as db:
        cursor = db.execute("""INSERT INTO scans
            (created_at, capture_name, packet_count, source_count, alert_count, alerts_json)
            VALUES (?, ?, ?, ?, ?, ?)""", (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            str(name), len(records), len({p.src for p in records}), len(alerts),
            json.dumps([a.to_dict() for a in alerts])))
        db.commit()
        return cursor.lastrowid

def list_scans(db_path=None, limit=100):
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    with closing(connect(db_path)) as db:
        db.row_factory = sqlite3.Row
        return [dict(r) for r in db.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (int(limit),))]
