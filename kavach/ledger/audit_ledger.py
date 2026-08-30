"""
Tamper-evident SQLite audit trail.

Every record is chained: each row stores the SHA-256 hash of its own
payload concatenated with the previous row's hash, so any retroactive
edit to an earlier row breaks every subsequent hash (a minimal
hash-chain / Merkle-style tamper-evidence scheme, no external deps).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict

from kavach.models import AuditRecord

GENESIS_HASH = "0" * 64


class AuditLedger:
    def __init__(self, db_path: str = "kavach_audit.sqlite3"):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id TEXT NOT NULL,
                finding_id TEXT,
                patch_id TEXT,
                verification_id TEXT,
                patch_sha256 TEXT,
                outcome TEXT,
                recorded_at REAL,
                payload_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                row_hash TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def _last_hash(self) -> str:
        cur = self._conn.execute("SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        return row[0] if row else GENESIS_HASH

    def record(self, record: AuditRecord) -> str:
        payload = json.dumps(asdict(record), sort_keys=True)
        prev_hash = self._last_hash()
        row_hash = hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()

        self._conn.execute(
            """
            INSERT INTO audit_log
                (record_id, finding_id, patch_id, verification_id, patch_sha256,
                 outcome, recorded_at, payload_json, prev_hash, row_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.id,
                record.finding_id,
                record.patch_id,
                record.verification_id,
                record.patch_sha256,
                record.outcome,
                record.recorded_at or time.time(),
                payload,
                prev_hash,
                row_hash,
            ),
        )
        self._conn.commit()
        return row_hash

    def verify_chain(self) -> bool:
        """Recomputes the hash chain and returns True iff nothing has
        been tampered with."""
        cur = self._conn.execute(
            "SELECT payload_json, prev_hash, row_hash FROM audit_log ORDER BY seq ASC"
        )
        expected_prev = GENESIS_HASH
        for payload_json, prev_hash, row_hash in cur.fetchall():
            if prev_hash != expected_prev:
                return False
            recomputed = hashlib.sha256((prev_hash + payload_json).encode("utf-8")).hexdigest()
            if recomputed != row_hash:
                return False
            expected_prev = row_hash
        return True

    def all_records(self) -> list[dict]:
        cur = self._conn.execute(
            "SELECT seq, record_id, finding_id, patch_id, verification_id, "
            "patch_sha256, outcome, recorded_at, row_hash FROM audit_log ORDER BY seq ASC"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
