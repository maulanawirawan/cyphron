"""SQLite persistence (stdlib sqlite3): scans, findings, audit chain."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .guardrails.authorization import AuditLog
from .orchestrator import ScanOptions, ScanSummary

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    auth_id TEXT,
    steps INTEGER, refused INTEGER,
    confirmed INTEGER, unconfirmed INTEGER,
    elapsed_s REAL
);
CREATE TABLE IF NOT EXISTS findings (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    tool TEXT NOT NULL,
    title TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE(scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS audit_entries (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    idx INTEGER NOT NULL,
    hash TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE(scan_id, idx)
);
"""


def persist(out_dir: Path, opts: ScanOptions, summary: ScanSummary, audit: AuditLog) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    db_path = out_dir / "cyphron.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(_SCHEMA)
        cur = conn.execute(
            "INSERT INTO scans (started_at, target, mode, auth_id, steps, refused, confirmed, unconfirmed, elapsed_s) "
            "VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)",
            (opts.target, summary.mode, summary.auth_id,
             summary.steps_executed, summary.refused_actions,
             len(summary.confirmed), len(summary.unconfirmed), summary.elapsed_s),
        )
        scan_id = cur.lastrowid
        for f in summary.confirmed + summary.unconfirmed:
            conn.execute(
                "INSERT OR IGNORE INTO findings (scan_id, fingerprint, status, severity, tool, title, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, f.id, f.status, f.severity, f.tool, f.title, f.to_json()),
            )
        for idx, entry in enumerate(audit.entries):
            conn.execute(
                "INSERT OR IGNORE INTO audit_entries (scan_id, idx, hash, payload) VALUES (?, ?, ?, ?)",
                (scan_id, idx, entry["hash"], json.dumps(entry, default=str)),
            )
        conn.commit()
    finally:
        conn.close()
    return db_path
