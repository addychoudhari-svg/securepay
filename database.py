"""
database.py — SQLite schema, initialization, and all DB helper functions.
"""

import sqlite3
import json
from datetime import datetime, timezone


DB_PATH = "fintech.db"


# ── Schema ────────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    public_key  TEXT NOT NULL,
    bcrypt_hash TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS private_keys (
    user_id             TEXT PRIMARY KEY,
    encrypted_pem       TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce       TEXT PRIMARY KEY,
    used_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id      TEXT PRIMARY KEY,
    sender      TEXT NOT NULL,
    receiver    TEXT NOT NULL,
    amount      REAL NOT NULL,
    currency    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    signature   TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- Append-only audit log: no UPDATE or DELETE ever runs on this table
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    txn_id      TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    detail      TEXT,
    logged_at   TEXT    NOT NULL
);
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


# ── Users ─────────────────────────────────────────────────────────────────────

def save_user(user_id: str, public_pem: bytes, encrypted_pem: bytes, bcrypt_hash: bytes):
    now = _now()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (id, public_key, bcrypt_hash, created_at) VALUES (?,?,?,?)",
            (user_id, public_pem.decode(), bcrypt_hash.decode(), now)
        )
        conn.execute(
            "INSERT INTO private_keys (user_id, encrypted_pem) VALUES (?,?)",
            (user_id, encrypted_pem.decode())
        )


def get_user(user_id: str) -> sqlite3.Row | None:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def get_public_key(user_id: str) -> bytes | None:
    row = get_user(user_id)
    return row["public_key"].encode() if row else None


def get_encrypted_private_key(user_id: str) -> bytes | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT encrypted_pem FROM private_keys WHERE user_id=?", (user_id,)
        ).fetchone()
        return row["encrypted_pem"].encode() if row else None


def get_bcrypt_hash(user_id: str) -> bytes | None:
    row = get_user(user_id)
    return row["bcrypt_hash"].encode() if row else None


def list_users() -> list:
    with get_conn() as conn:
        rows = conn.execute("SELECT id, created_at FROM users").fetchall()
        return [dict(r) for r in rows]


# ── Nonces ────────────────────────────────────────────────────────────────────

def nonce_exists(nonce: str) -> bool:
    with get_conn() as conn:
        row = conn.execute("SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone()
        return row is not None


def save_nonce(nonce: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO nonces (nonce, used_at) VALUES (?,?)", (nonce, _now())
        )


# ── Transactions ──────────────────────────────────────────────────────────────

def save_transaction(payload: dict, signature: str, status: str):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO transactions
               (txn_id, sender, receiver, amount, currency, timestamp, nonce, signature, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                payload["txn_id"],
                payload["sender"],
                payload["receiver"],
                payload["amount"],
                payload["currency"],
                payload["timestamp"],
                payload["nonce"],
                signature,
                status,
                _now(),
            ),
        )


def get_transactions() -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM transactions ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
        return [dict(r) for r in rows]


# ── Audit log ─────────────────────────────────────────────────────────────────

def audit(txn_id: str, event_type: str, detail: str = ""):
    """
    Append-only audit entry. Every verification attempt — pass or fail —
    must call this. Never update or delete from audit_log.
    """
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_log (txn_id, event_type, detail, logged_at) VALUES (?,?,?,?)",
            (txn_id, event_type, detail, _now()),
        )


def get_audit_log(txn_id: str = None) -> list:
    with get_conn() as conn:
        if txn_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE txn_id=? ORDER BY id", (txn_id,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT 100"
            ).fetchall()
        return [dict(r) for r in rows]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
