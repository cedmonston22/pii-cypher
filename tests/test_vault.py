"""Vault persistence, and the guarantee that nothing plaintext reaches disk."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from core.crypto import aad, decrypt, encrypt, token_hash
from core.keys import generate_data_key, unwrap, wrap
from core.vault import (
    Entry,
    JobExpired,
    JobNotFound,
    connect,
    create_job,
    document_filename,
    get_job,
    get_wrapped_key,
    list_documents,
    list_jobs,
    lookup,
    set_document_status,
    store_document,
    store_entries,
    store_key,
)

POLICY = {"pii_types": ["ein", "ssn_tin", "address"]}


@pytest.fixture
def db(tmp_path):
    return connect(str(tmp_path / "vault.db"))


@pytest.fixture
def job(db):
    job_key = generate_data_key()
    job_id = create_job(db, POLICY)
    store_key(db, job_id, wrap(job_key))
    db.commit()
    return job_id, job_key


def test_job_round_trip(db, job):
    job_id, _ = job
    loaded = get_job(db, job_id)
    assert loaded["id"] == job_id
    assert loaded["policy"] == POLICY
    assert loaded["status"] == "processing"
    assert loaded["tenant_id"] == "local"


def test_unknown_job_raises(db):
    with pytest.raises(JobNotFound):
        get_job(db, "nope")


def test_expired_job_raises(db):
    """An expired job must stop the caller, not yield a partial restore."""
    job_id = create_job(db, POLICY, retention_days=-1)
    db.commit()
    with pytest.raises(JobExpired):
        get_job(db, job_id)


def test_job_key_round_trip(db, job):
    job_id, job_key = job
    assert unwrap(get_wrapped_key(db, job_id)) == job_key


def test_entry_lookup_by_token(db, job):
    job_id, job_key = job
    token = "PII-ABC23456"
    ct, nonce = encrypt(job_key, "000-00-0000", aad(job_id, "ssn_tin", token))
    store_entries(db, job_id, [Entry(token, "ssn_tin", ct, nonce)])
    db.commit()

    found = lookup(db, job_id, token)
    assert found is not None
    assert decrypt(job_key, found.ciphertext, found.nonce, aad(job_id, "ssn_tin", token)) == "000-00-0000"


def test_unknown_token_returns_none(db, job):
    job_id, _ = job
    assert lookup(db, job_id, "PII-ZZZZZZZZ") is None


def test_token_is_not_resolvable_from_another_job(db, job):
    """Entries are job-scoped: the same token in another job must not resolve."""
    job_id, job_key = job
    token = "PII-ABC23456"
    ct, nonce = encrypt(job_key, "000-00-0000", aad(job_id, "ssn_tin", token))
    store_entries(db, job_id, [Entry(token, "ssn_tin", ct, nonce)])

    other = create_job(db, POLICY)
    db.commit()
    assert lookup(db, other, token) is None


def test_duplicate_entry_is_stored_once(db, job):
    """A value shared across documents is one token and therefore one row."""
    job_id, job_key = job
    token = "PII-ABC23456"
    ct, nonce = encrypt(job_key, "000-00-0000", aad(job_id, "ssn_tin", token))
    entry = Entry(token, "ssn_tin", ct, nonce)
    store_entries(db, job_id, [entry])
    store_entries(db, job_id, [entry])
    db.commit()

    count = db.execute("SELECT COUNT(*) FROM vault_entries WHERE job_id = ?", (job_id,)).fetchone()[0]
    assert count == 1


def test_document_filename_is_encrypted_at_rest(db, job):
    job_id, job_key = job
    doc_id = store_document(db, job_id, "Smith_John_K1.pdf", job_key, "scrubbed", "us-1065-k1", 1)
    db.commit()

    stored = db.execute("SELECT filename_ct FROM documents WHERE id = ?", (doc_id,)).fetchone()[0]
    assert b"Smith_John_K1" not in stored
    assert document_filename(db, doc_id, job_key) == "Smith_John_K1.pdf"


def test_document_listing_and_status(db, job):
    job_id, job_key = job
    hashes = [token_hash("PII-ABC23456")]
    doc_id = store_document(
        db, job_id, "a.pdf", job_key, "scrubbed", "us-1065-k1", 1, token_hashes=hashes
    )
    store_document(db, job_id, "b.pdf", job_key, "quarantined", reason="no text layer")
    db.commit()

    docs = {d.id: d for d in list_documents(db, job_id)}
    assert len(docs) == 2
    assert docs[doc_id].token_hashes == hashes
    assert docs[doc_id].status == "scrubbed"

    set_document_status(db, doc_id, "restored")
    db.commit()
    assert {d.id: d for d in list_documents(db, job_id)}[doc_id].status == "restored"


def test_list_jobs_counts_documents(db, job):
    job_id, job_key = job
    store_document(db, job_id, "a.pdf", job_key, "scrubbed")
    db.commit()
    entry = next(j for j in list_jobs(db) if j["id"] == job_id)
    assert entry["document_count"] == 1


def test_database_file_contains_no_plaintext(db, job, tmp_path):
    """The whole point of the vault: read the raw file and find nothing.

    Covers values, filenames, and raw tokens -- the token is stored only as a
    keyed hash so a stolen database cannot be scanned for tokens seen elsewhere.
    """
    job_id, job_key = job
    token = "PII-ABC23456"
    secrets_in = ["000-00-0000", "00-0000000", "AUSTIN, TX 78701", "456 SAMPLE AVE"]

    entries = []
    for value in secrets_in:
        ct, nonce = encrypt(job_key, value, aad(job_id, "address", token))
        entries.append(Entry(token, "address", ct, nonce))
        token = token[:-1] + "Z"

    store_entries(db, job_id, entries)
    store_document(db, job_id, "ALEX_TESTER_K1.pdf", job_key, "scrubbed")
    db.commit()
    db.close()

    raw = (tmp_path / "vault.db").read_bytes()
    for value in [*secrets_in, "ALEX_TESTER", "PII-ABC23456", "PII-ABC2345Z"]:
        assert value.encode() not in raw, f"{value!r} found in the database file"


def test_foreign_key_enforced(db, job):
    with pytest.raises(sqlite3.IntegrityError):
        store_key(db, "not-a-job", b"x")
        db.commit()
