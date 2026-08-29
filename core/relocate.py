"""Moving a vault, and adopting one that already exists.

Composes ``keys``, ``vault`` and ``paths``, which is exactly what none of them
may do to each other -- ``vault.py`` stays SQL-only and ``paths.py`` must not
import ``vault``. The CLI and the web app both call this, so the refusals live
here rather than in either front end.

The rule the whole module is built around: **inspecting a candidate must never
use ``vault.connect``.** That call runs ``executescript(SCHEMA)``, so merely
looking at a path would turn an unrelated SQLite file into a vault, or a typo
into a fully-formed empty one that then reports zero jobs.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from core import keys, paths, vault
from core.crypto import LOOKUP_SECRET_ENV
from core.keys import MASTER_KEY_ENV, unwrap

SECRET_NAMES = (MASTER_KEY_ENV, LOOKUP_SECRET_ENV)
REQUIRED_TABLES = frozenset({"jobs", "documents", "vault_entries", "job_keys"})


class RelocateRefused(Exception):
    """A relocation was refused. The message is meant to be shown to the user."""


class MovePlan(NamedTuple):
    source: Path
    destination: Path
    job_count: int
    replacing_empty: bool


class MoveResult(NamedTuple):
    destination: Path
    kept: Path
    detail: str


class AdoptPlan(NamedTuple):
    path: Path
    job_count: int
    detail: str


@contextlib.contextmanager
def without_ambient_keys() -> Iterator[None]:
    """Hide exported key material so only the key file on disk is consulted."""
    saved = {name: os.environ.pop(name) for name in SECRET_NAMES if name in os.environ}
    keys.clear_cache()
    try:
        yield
    finally:
        os.environ.update(saved)
        keys.clear_cache()


def _read_only(path: Path) -> sqlite3.Connection:
    """Open an existing file without any chance of writing to it."""
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)


def looks_like_a_vault(path: Path) -> bool:
    """Whether an existing file is one of our vaults.

    Opened read-only, and never through ``vault.connect`` -- see the module
    docstring. A zero-byte file is valid SQLite carrying no tables, so size is
    the only thing separating "empty file" from "database" before we look.
    """
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        conn = _read_only(path)
    except sqlite3.Error:
        return False
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        return REQUIRED_TABLES.issubset({row[0] for row in rows})
    except sqlite3.DatabaseError:
        return False
    finally:
        conn.close()


def count_jobs(path: Path) -> int:
    """Jobs in an existing vault, read-only."""
    conn = _read_only(path)
    try:
        return conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    finally:
        conn.close()


def verify_decryptable(
    db_path: Path, *, ambient_keys: bool = True
) -> tuple[bool, str]:
    """Prove a vault decrypts, rather than merely that it opens.

    A vault that opens and cannot be read is the failure nobody notices until a
    client asks for a restore, so this unwraps a real job key and decrypts a
    real filename.

    ``ambient_keys=False`` hides exported key material so only the key file is
    consulted. That is right for ``migrate``, which relocates the key file and
    must check the copy the way the *migrated* install will read it. It is
    wrong for everything else: a move that leaves the keys where they are has to
    verify against the environment exactly as it stands, or an install whose
    launcher exports its keys fails a perfectly good move.
    """
    if not looks_like_a_vault(db_path):
        return False, "not a pii-cypher vault"

    context = contextlib.nullcontext() if ambient_keys else without_ambient_keys()
    with context:
        conn = vault.connect(db_path)
        try:
            jobs = vault.list_jobs(conn, limit=1)
            if not jobs:
                return True, "no jobs to verify"
            job_id = jobs[0]["id"]
            job_key = unwrap(vault.get_wrapped_key(conn, job_id))
            documents = vault.list_documents(conn, job_id)
            if not documents:
                return True, "unwrapped a job key"
            if not vault.document_filename(conn, documents[0].id, job_key):
                return False, "a document filename decrypted to nothing"
            return True, "unwrapped a job key and decrypted a filename"
        except Exception as exc:
            # Any exception means the copy is not trustworthy. The caller must
            # keep the original rather than crash part-way through a move.
            return False, f"{type(exc).__name__}: {exc}"
        finally:
            conn.close()


def plan_move(source: Path, destination: Path) -> MovePlan:
    """Everything a move can check without writing. Raises RelocateRefused."""
    if not source.is_file():
        raise RelocateRefused(f"There is no vault at {source}.")
    if not looks_like_a_vault(source):
        raise RelocateRefused(f"{source} is not a pii-cypher vault.")
    if destination.exists() and destination.samefile(source):
        raise RelocateRefused(f"The vault is already at {destination}.")

    replacing_empty = False
    if destination.exists():
        if not looks_like_a_vault(destination):
            raise RelocateRefused(
                f"{destination} already exists and is not a pii-cypher vault. "
                "Choose another name rather than overwriting it."
            )
        existing = count_jobs(destination)
        if existing:
            raise RelocateRefused(
                f"A vault holding {existing} job(s) is already at {destination}. "
                "Choosing between two populated vaults is not this program's decision."
            )
        # An empty one is the stub a stray run from another directory leaves.
        replacing_empty = True

    return MovePlan(
        source=source,
        destination=destination,
        job_count=count_jobs(source),
        replacing_empty=replacing_empty,
    )


def move_vault(source: Path, destination: Path) -> MoveResult:
    """Copy a vault to a new file, verify it, then point the setting at it.

    The order is the safety property: snapshot, verify, record, and only then
    rename the source. A failure anywhere before the last step leaves the
    setting unwritten and the original still called vault.db.

    The key file does not move. It stays in the per-user directory, so a vault
    placed on another drive is inert to anyone who has not been given the keys.
    """
    plan_move(source, destination)

    paths.ensure_dir(destination.parent)
    if destination.exists():
        destination.unlink()

    conn = vault.connect(source)
    try:
        vault.snapshot(conn, destination)
    finally:
        conn.close()

    verified, detail = verify_decryptable(destination)
    if not verified:
        # Our own copy, made moments ago, so removing it loses nothing and
        # leaves a retry unobstructed. The source is untouched.
        destination.unlink(missing_ok=True)
        raise RelocateRefused(
            f"The copy at {destination} did not verify ({detail}). "
            f"Nothing was changed and {source} is untouched."
        )

    paths.set_configured_db(destination)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    kept = source.with_name(f"vault.moved-{stamp}.db")
    source.rename(kept)
    return MoveResult(destination=destination, kept=kept, detail=detail)


def plan_adopt(path: Path) -> AdoptPlan:
    """Everything adopting an existing vault checks. Writes nothing."""
    if not path.exists():
        raise RelocateRefused(
            f"There is nothing at {path}. Use Move to put the current vault there."
        )
    if not looks_like_a_vault(path):
        raise RelocateRefused(f"{path} is not a pii-cypher vault.")

    jobs = count_jobs(path)
    if not jobs:
        # Adopting an empty vault is indistinguishable from typing a new path
        # and getting a fresh one, which is the outcome this design exists to
        # make impossible to reach by accident.
        raise RelocateRefused(
            f"The vault at {path} is empty. Use Move to put the current vault there."
        )

    verified, detail = verify_decryptable(path)
    if not verified:
        raise RelocateRefused(
            f"The vault at {path} opens, but this machine's keys do not decrypt it "
            f"({detail}). It was created under different key material. Paste that "
            f"vault's two keys into {paths.env_file_path()} first -- `cli.py backup` "
            "prints them, and they grant access to everything in that vault."
        )

    return AdoptPlan(path=path, job_count=jobs, detail=detail)


def adopt_vault(path: Path) -> AdoptPlan:
    """Point the setting at an existing vault, once it has proved readable."""
    plan = plan_adopt(path)
    paths.set_configured_db(path)
    return plan
