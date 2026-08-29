"""SQLite persistence for jobs, documents, vault entries and wrapped keys.

Nothing in this database is plaintext PII. Values are stored encrypted, tokens
are stored as keyed hashes, and filenames are encrypted because a filename like
Smith_John_K1.pdf is exactly what the tool exists to keep out of storage.

Vault entries are scoped to the job, not the document. That is what allows one
document of a batch to be restored on its own with no special handling: the
lookup was never document-scoped to begin with.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple

from core.crypto import TENANT_ID, aad_filename, decrypt, encrypt, token_hash

DEFAULT_RETENTION_DAYS = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    policy      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    status      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    id             TEXT PRIMARY KEY,
    job_id         TEXT NOT NULL REFERENCES jobs(id),
    filename_ct    BLOB,
    filename_nonce BLOB,
    form_id        TEXT,
    page_count     INTEGER,
    status         TEXT NOT NULL,
    reason         TEXT,
    token_hashes   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL REFERENCES jobs(id),
    token_hash TEXT NOT NULL,
    pii_type   TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    UNIQUE (job_id, token_hash)
);

CREATE TABLE IF NOT EXISTS job_keys (
    job_id           TEXT PRIMARY KEY REFERENCES jobs(id),
    wrapped_data_key BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_entries_lookup ON vault_entries (job_id, token_hash);
-- Needed to resolve a token to its job without being told the job first. The
-- index above cannot serve it: job_id is its leading column.
CREATE INDEX IF NOT EXISTS idx_entries_token ON vault_entries (token_hash);
CREATE INDEX IF NOT EXISTS idx_documents_job ON documents (job_id);
"""


class Entry(NamedTuple):
    token: str
    pii_type: str
    ciphertext: bytes
    nonce: bytes


class Document(NamedTuple):
    id: str
    job_id: str
    form_id: str | None
    page_count: int | None
    status: str
    reason: str | None
    token_hashes: list[str]


class JobExpired(Exception):
    """Raised when a job is past its retention window."""


class JobNotFound(Exception):
    """Raised when a job id does not resolve."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def connect(path: str | os.PathLike[str]) -> sqlite3.Connection:
    """Open the vault at ``path``.

    Deliberately has no default. Three modules used to carry their own
    "vault.db" literal and they drifted apart; a caller that forgets is now a
    TypeError at the call site rather than a fourth silent divergence.
    ``core.paths`` is what answers where.
    """
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def create_job(
    conn: sqlite3.Connection,
    policy: dict[str, Any],
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> str:
    """Create a job row and return its id. Does not commit."""
    job_id = str(uuid.uuid4())
    created = _now()
    conn.execute(
        "INSERT INTO jobs (id, tenant_id, policy, created_at, expires_at, status)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            job_id,
            TENANT_ID,
            json.dumps(policy),
            created.isoformat(),
            (created + timedelta(days=retention_days)).isoformat(),
            "processing",
        ),
    )
    return job_id


def set_job_status(conn: sqlite3.Connection, job_id: str, status: str) -> None:
    conn.execute("UPDATE jobs SET status = ? WHERE id = ?", (status, job_id))


def get_job(conn: sqlite3.Connection, job_id: str) -> dict[str, Any]:
    """Return a job, raising if it is unknown or past its retention window."""
    row = conn.execute(
        "SELECT id, tenant_id, policy, created_at, expires_at, status FROM jobs WHERE id = ?",
        (job_id,),
    ).fetchone()
    if row is None:
        raise JobNotFound(f"no such job: {job_id}")
    if datetime.fromisoformat(row[4]) < _now():
        raise JobExpired(f"job {job_id} expired at {row[4]}")
    return {
        "id": row[0],
        "tenant_id": row[1],
        "policy": json.loads(row[2]),
        "created_at": row[3],
        "expires_at": row[4],
        "status": row[5],
    }


def list_jobs(conn: sqlite3.Connection, limit: int = 50) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT j.id, j.created_at, j.expires_at, j.status, COUNT(d.id)"
        " FROM jobs j LEFT JOIN documents d ON d.job_id = j.id"
        " GROUP BY j.id ORDER BY j.created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [
        {
            "id": r[0],
            "created_at": r[1],
            "expires_at": r[2],
            "status": r[3],
            "document_count": r[4],
        }
        for r in rows
    ]


def count_jobs(conn: sqlite3.Connection) -> int:
    """Total jobs, expired ones included. What `status` reports."""
    return conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]


def snapshot(conn: sqlite3.Connection, destination: str | os.PathLike[str]) -> None:
    """Write a consistent, compacted copy of the vault.

    VACUUM INTO rather than a file copy: it cannot capture a torn file while the
    web app is mid-write, and it drops free pages, so ciphertext from rows that
    are gone does not ride along into a backup.

    SQLite requires the destination not to exist.
    """
    conn.execute("VACUUM INTO ?", (str(destination),))


def store_key(conn: sqlite3.Connection, job_id: str, wrapped_key: bytes) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO job_keys (job_id, wrapped_data_key) VALUES (?, ?)",
        (job_id, wrapped_key),
    )


def get_wrapped_key(conn: sqlite3.Connection, job_id: str) -> bytes:
    row = conn.execute(
        "SELECT wrapped_data_key FROM job_keys WHERE job_id = ?", (job_id,)
    ).fetchone()
    if row is None:
        raise JobNotFound(f"no key stored for job {job_id}")
    return row[0]


def store_entries(conn: sqlite3.Connection, job_id: str, entries: list[Entry]) -> None:
    """Persist vault entries, hashing tokens on the way in.

    INSERT OR IGNORE because a value shared across documents in a batch resolves
    to one token and therefore one row.
    """
    conn.executemany(
        "INSERT OR IGNORE INTO vault_entries (job_id, token_hash, pii_type, ciphertext, nonce)"
        " VALUES (?, ?, ?, ?, ?)",
        [(job_id, token_hash(e.token), e.pii_type, e.ciphertext, e.nonce) for e in entries],
    )


def lookup(conn: sqlite3.Connection, job_id: str, token: str) -> Entry | None:
    """Resolve a token within a job. Returns None rather than guessing."""
    row = conn.execute(
        "SELECT pii_type, ciphertext, nonce FROM vault_entries"
        " WHERE job_id = ? AND token_hash = ?",
        (job_id, token_hash(token)),
    ).fetchone()
    if row is None:
        return None
    return Entry(token=token, pii_type=row[0], ciphertext=row[1], nonce=row[2])


def find_by_token_hashes(conn: sqlite3.Connection, hashes: list[str]) -> dict[str, list[str]]:
    """Return {job_id: [token_hash, ...]} for every job owning any of these.

    This is what lets a scrubbed document identify its own job. Token hashes are
    keyed by the lookup secret alone, not by the job, so the same token hashes
    identically everywhere and the vault can be queried without being told which
    job to look in.
    """
    if not hashes:
        return {}

    owners: dict[str, list[str]] = {}
    # Chunked to stay under SQLite's variable limit on a large document.
    for start in range(0, len(hashes), 500):
        chunk = hashes[start : start + 500]
        placeholders = ",".join("?" * len(chunk))
        rows = conn.execute(
            f"SELECT job_id, token_hash FROM vault_entries WHERE token_hash IN ({placeholders})",
            chunk,
        ).fetchall()
        for job_id, token_hash_value in rows:
            owners.setdefault(job_id, []).append(token_hash_value)
    return owners


def store_document(
    conn: sqlite3.Connection,
    job_id: str,
    filename: str,
    job_key: bytes,
    status: str,
    form_id: str | None = None,
    page_count: int | None = None,
    token_hashes: list[str] | None = None,
    reason: str | None = None,
) -> str:
    """Persist one document with its filename encrypted.

    The id is generated here rather than by the database because it is an input
    to the filename AAD.
    """
    doc_id = str(uuid.uuid4())
    ciphertext, nonce = encrypt(job_key, filename, aad_filename(job_id, doc_id))
    conn.execute(
        "INSERT INTO documents"
        " (id, job_id, filename_ct, filename_nonce, form_id, page_count,"
        "  status, reason, token_hashes)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            doc_id,
            job_id,
            ciphertext,
            nonce,
            form_id,
            page_count,
            status,
            reason,
            json.dumps(token_hashes or []),
        ),
    )
    return doc_id


def list_documents(conn: sqlite3.Connection, job_id: str) -> list[Document]:
    rows = conn.execute(
        "SELECT id, job_id, form_id, page_count, status, reason, token_hashes"
        " FROM documents WHERE job_id = ?",
        (job_id,),
    ).fetchall()
    return [Document(r[0], r[1], r[2], r[3], r[4], r[5], json.loads(r[6])) for r in rows]


def document_filename(conn: sqlite3.Connection, doc_id: str, job_key: bytes) -> str:
    """Decrypt a stored filename, for display only."""
    row = conn.execute(
        "SELECT job_id, filename_ct, filename_nonce FROM documents WHERE id = ?", (doc_id,)
    ).fetchone()
    if row is None:
        raise JobNotFound(f"no such document: {doc_id}")
    return decrypt(job_key, row[1], row[2], aad_filename(row[0], doc_id))


def set_document_status(conn: sqlite3.Connection, doc_id: str, status: str) -> None:
    conn.execute("UPDATE documents SET status = ? WHERE id = ?", (status, doc_id))
