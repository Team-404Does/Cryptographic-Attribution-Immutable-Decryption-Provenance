"""SQLite metadata store (identities, documents, key wraps, sessions, ledger, reports)."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, token_label TEXT NOT NULL,
    cert TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT
);
CREATE TABLE IF NOT EXISTS recipients (
    id TEXT PRIMARY KEY, employee_id TEXT NOT NULL, name TEXT NOT NULL, department TEXT, clearance TEXT,
    token_label TEXT NOT NULL, cert TEXT NOT NULL, created_at TEXT NOT NULL,
    enrolled_by TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    revoked_at TEXT, revoked_by TEXT, revoked_reason TEXT
);
-- at most one *active* identity per employee id
CREATE UNIQUE INDEX IF NOT EXISTS ux_recipient_active_employee ON recipients(employee_id) WHERE status='active';
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY, title TEXT NOT NULL, filename TEXT NOT NULL, sha3 TEXT NOT NULL,
    size INTEGER NOT NULL, pages INTEGER NOT NULL, blob_path TEXT NOT NULL,
    created_at TEXT NOT NULL, created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS key_wraps (
    doc_id TEXT NOT NULL REFERENCES documents(id), recipient_id TEXT NOT NULL,  -- recipient id or custodian token
    kem_ct TEXT NOT NULL, wrapped_cek TEXT NOT NULL, created_at TEXT NOT NULL, granted_by TEXT,
    PRIMARY KEY (doc_id, recipient_id)
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, wm_id TEXT UNIQUE NOT NULL, doc_id TEXT NOT NULL, recipient_id TEXT NOT NULL,
    record TEXT NOT NULL, record_hash TEXT NOT NULL, signature TEXT NOT NULL,
    block_index INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blocks (
    idx INTEGER PRIMARY KEY, header TEXT NOT NULL, block_hash TEXT NOT NULL,
    events TEXT NOT NULL, endorsements TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, verdict TEXT NOT NULL, wm_id TEXT,
    report TEXT NOT NULL, pdf_path TEXT, created_by TEXT
);
"""
SCHEMA_VERSION = 2


class SchemaMismatch(RuntimeError):
    pass

# One process-wide connection guarded by a re-entrant lock: the prototype is a
# single-user desktop app, so serialising database access keeps it simple and safe.
_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        config.ensure_dirs()
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA foreign_keys=ON")
        _conn.execute("PRAGMA journal_mode=WAL")
        version = _conn.execute("PRAGMA user_version").fetchone()[0]
        has_tables = _conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
        if has_tables and version != SCHEMA_VERSION:
            _conn.close()
            _conn = None
            raise SchemaMismatch(f"data directory {config.DATA_DIR} was created by an older version; "
                                 "delete it (or POST /api/demo/reset in demo mode) to re-initialise")
        _conn.executescript(SCHEMA)
        _conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    return _conn


def close() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None


@contextmanager
def tx():
    with _lock:
        conn = connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def rows(sql: str, *args) -> list[dict]:
    with _lock:
        return [dict(r) for r in connect().execute(sql, args).fetchall()]


def row(sql: str, *args) -> dict | None:
    with _lock:
        r = connect().execute(sql, args).fetchone()
        return dict(r) if r else None


def loads(s: str | None):
    return json.loads(s) if s else None
