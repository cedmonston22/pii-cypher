"""Moving and adopting vaults, and everything both refuse to do.

Two hazards drive this file. Looking at a candidate through ``vault.connect``
would run our schema on it, turning any file into a vault and any typo into an
empty one. And because the key file does not travel with the vault, a vault
adopted from elsewhere can open perfectly and decrypt nothing.
"""

import base64
import secrets
import sqlite3

import pytest

from core import keys, paths, relocate, vault
from core.crypto import LOOKUP_SECRET_ENV
from core.keys import MASTER_KEY_ENV, generate_data_key, wrap
from core.relocate import RelocateRefused

POLICY = {"pii_types": ["EIN"]}


@pytest.fixture
def home(monkeypatch, tmp_path):
    """A per-user directory, so the settings file lands somewhere disposable."""
    destination = tmp_path / "home"
    monkeypatch.setenv(paths.VAULT_DIR_ENV, str(destination))
    monkeypatch.delenv(paths.VAULT_DB_ENV, raising=False)
    keys.clear_cache()
    yield destination
    keys.clear_cache()


def populate(db_path, filename="Smith_John_K1.pdf"):
    """A vault with one job and one document, so a filename can be decrypted."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = vault.connect(db_path)
    job_key = generate_data_key()
    job_id = vault.create_job(conn, POLICY)
    vault.store_key(conn, job_id, wrap(job_key))
    vault.store_document(conn, job_id, filename, job_key, status="scrubbed")
    conn.commit()
    conn.close()
    return job_id


def foreign_keys(monkeypatch):
    """Swap in key material unrelated to anything already written."""
    monkeypatch.setenv(MASTER_KEY_ENV, base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setenv(LOOKUP_SECRET_ENV, base64.b64encode(secrets.token_bytes(32)).decode())
    keys.clear_cache()


class TestLooksLikeAVault:
    def test_a_real_vault(self, tmp_path):
        populate(tmp_path / "vault.db")

        assert relocate.looks_like_a_vault(tmp_path / "vault.db")

    def test_a_missing_file(self, tmp_path):
        assert not relocate.looks_like_a_vault(tmp_path / "nothing.db")

    def test_a_zero_byte_file(self, tmp_path):
        """Valid SQLite carrying no tables, so size is the only thing that
        separates an empty file from a database before we look inside."""
        (tmp_path / "empty.db").touch()

        assert not relocate.looks_like_a_vault(tmp_path / "empty.db")

    def test_a_file_that_is_not_a_database(self, tmp_path):
        (tmp_path / "notes.db").write_text("this is just text", encoding="utf-8")

        assert not relocate.looks_like_a_vault(tmp_path / "notes.db")

    def test_a_database_that_is_not_ours(self, tmp_path):
        conn = sqlite3.connect(tmp_path / "other.db")
        conn.execute("CREATE TABLE invoices (id INTEGER)")
        conn.commit()
        conn.close()

        assert not relocate.looks_like_a_vault(tmp_path / "other.db")

    def test_a_directory(self, tmp_path):
        (tmp_path / "vault.db").mkdir()

        assert not relocate.looks_like_a_vault(tmp_path / "vault.db")


def test_inspecting_a_foreign_database_does_not_touch_it(home, tmp_path):
    """The headline safety property of the whole module.

    ``vault.connect`` runs ``executescript(SCHEMA)``, so inspecting a candidate
    through it would silently add our four tables to someone else's database --
    and would turn a mistyped path into a fully-formed empty vault that then
    reports zero jobs.
    """
    other = tmp_path / "someone-elses.db"
    conn = sqlite3.connect(other)
    conn.execute("CREATE TABLE invoices (id INTEGER)")
    conn.commit()
    conn.close()
    before = other.read_bytes()

    assert not relocate.looks_like_a_vault(other)
    with pytest.raises(RelocateRefused, match="not a pii-cypher vault"):
        relocate.plan_adopt(other)

    assert other.read_bytes() == before


class TestMove:
    def test_copies_verifies_records_and_keeps_the_original(self, home, tmp_path):
        source = tmp_path / "checkout" / "vault.db"
        populate(source)
        destination = tmp_path / "elsewhere" / "vault.db"

        result = relocate.move_vault(source, destination)

        assert result.destination == destination
        assert "decrypted a filename" in result.detail
        assert relocate.count_jobs(destination) == 1
        assert not source.exists()
        assert result.kept.exists() and result.kept.name.startswith("vault.moved-")
        assert paths.configured_db_path() == destination

    def test_the_original_is_not_left_named_vault_db(self, home, tmp_path):
        """A file still called vault.db is a trap: a later --db typo or a
        PII_VAULT_DIR finds a stale vault full of real jobs and reads as success."""
        source = tmp_path / "checkout" / "vault.db"
        populate(source)

        relocate.move_vault(source, tmp_path / "elsewhere" / "vault.db")

        assert not (tmp_path / "checkout" / "vault.db").exists()

    def test_refuses_a_populated_destination(self, home, tmp_path):
        source = tmp_path / "checkout" / "vault.db"
        populate(source)
        destination = tmp_path / "elsewhere" / "vault.db"
        populate(destination)

        with pytest.raises(RelocateRefused, match="not this program's decision"):
            relocate.move_vault(source, destination)

        assert source.exists()
        assert paths.configured_db_path() is None

    def test_replaces_an_empty_stub(self, home, tmp_path):
        """A stray run from another directory leaves one; refusing on it would
        block the move for no reason."""
        source = tmp_path / "checkout" / "vault.db"
        populate(source)
        destination = tmp_path / "elsewhere" / "vault.db"
        destination.parent.mkdir(parents=True)
        vault.connect(destination).close()

        relocate.move_vault(source, destination)

        assert relocate.count_jobs(destination) == 1

    def test_refuses_to_overwrite_something_that_is_not_a_vault(self, home, tmp_path):
        source = tmp_path / "checkout" / "vault.db"
        populate(source)
        destination = tmp_path / "important.db"
        destination.write_text("someone else's file", encoding="utf-8")

        with pytest.raises(RelocateRefused, match="not a pii-cypher vault"):
            relocate.move_vault(source, destination)

        assert destination.read_text(encoding="utf-8") == "someone else's file"

    def test_refuses_a_source_that_is_not_a_vault(self, home, tmp_path):
        with pytest.raises(RelocateRefused, match="no vault at"):
            relocate.move_vault(tmp_path / "nothing.db", tmp_path / "to.db")

    def test_a_failed_verification_changes_nothing(self, home, tmp_path, monkeypatch):
        """The order is the safety property: snapshot, verify, record, rename.

        A failure before the last step must leave the setting unwritten and the
        original still called vault.db, or a bad move would look like a good one.
        """
        source = tmp_path / "checkout" / "vault.db"
        populate(source)
        destination = tmp_path / "elsewhere" / "vault.db"
        monkeypatch.setattr(
            relocate, "verify_decryptable", lambda *a, **k: (False, "InvalidTag: ")
        )

        with pytest.raises(RelocateRefused, match="did not verify"):
            relocate.move_vault(source, destination)

        assert source.exists()
        assert not destination.exists()
        assert paths.configured_db_path() is None

    def test_plan_writes_nothing(self, home, tmp_path):
        source = tmp_path / "checkout" / "vault.db"
        populate(source)
        destination = tmp_path / "elsewhere" / "vault.db"

        plan = relocate.plan_move(source, destination)

        assert plan.job_count == 1
        assert not plan.replacing_empty
        assert not destination.exists()
        assert paths.configured_db_path() is None


class TestAdopt:
    def test_points_the_setting_at_an_existing_vault(self, home, tmp_path):
        existing = tmp_path / "shared" / "vault.db"
        populate(existing)

        plan = relocate.adopt_vault(existing)

        assert plan.job_count == 1
        assert paths.configured_db_path() == existing

    def test_the_setting_is_what_resolve_db_then_returns(self, monkeypatch, tmp_path):
        """End to end, with PII_VAULT_DIR out of the way.

        The fixture sets that variable so the settings file lands somewhere
        disposable, but it deliberately outranks the settings tier, so it has to
        go before the tier itself can be observed.
        """
        monkeypatch.setattr(paths, "config_path", lambda: tmp_path / paths.CONFIG_FILENAME)
        monkeypatch.delenv(paths.VAULT_DIR_ENV, raising=False)
        monkeypatch.delenv(paths.VAULT_DB_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        existing = tmp_path / "shared" / "vault.db"
        populate(existing)

        relocate.adopt_vault(existing)

        assert paths.resolve_db() == (existing, "settings")

    def test_does_not_copy_anything(self, home, tmp_path):
        existing = tmp_path / "shared" / "vault.db"
        populate(existing)

        relocate.adopt_vault(existing)

        assert [p.name for p in (tmp_path / "shared").iterdir()] == ["vault.db"]

    def test_refuses_a_missing_file_and_names_the_other_action(self, home, tmp_path):
        with pytest.raises(RelocateRefused, match="Use Move"):
            relocate.adopt_vault(tmp_path / "nothing.db")

    def test_refuses_an_empty_vault_and_names_the_other_action(self, home, tmp_path):
        """Adopting an empty vault is indistinguishable from typing a new path
        and silently getting a fresh one -- the outcome the split exists to
        make unreachable. Each action refusing the other's input is what makes
        two actions sufficient."""
        empty = tmp_path / "shared" / "vault.db"
        empty.parent.mkdir()
        vault.connect(empty).close()

        with pytest.raises(RelocateRefused, match="empty"):
            relocate.adopt_vault(empty)

        assert paths.configured_db_path() is None

    def test_refuses_a_vault_created_under_different_key_material(
        self, home, tmp_path, monkeypatch
    ):
        """The direct consequence of the key file not travelling with the vault.

        Such a vault opens and lists jobs perfectly; only decryption fails. If
        this were accepted, every restore would fail later with InvalidTag and
        nothing would explain why.
        """
        existing = tmp_path / "shared" / "vault.db"
        populate(existing)
        foreign_keys(monkeypatch)

        with pytest.raises(RelocateRefused) as excinfo:
            relocate.adopt_vault(existing)

        message = str(excinfo.value)
        assert "do not decrypt it" in message
        assert "cli.py backup" in message
        assert paths.configured_db_path() is None

    def test_plan_writes_nothing(self, home, tmp_path):
        existing = tmp_path / "shared" / "vault.db"
        populate(existing)

        assert relocate.plan_adopt(existing).job_count == 1
        assert paths.configured_db_path() is None


class TestVerifyDecryptable:
    def test_an_empty_vault_verifies_with_nothing_to_check(self, home, tmp_path):
        empty = tmp_path / "vault.db"
        vault.connect(empty).close()

        assert relocate.verify_decryptable(empty) == (True, "no jobs to verify")

    def test_foreign_key_material_fails_rather_than_raising(self, home, tmp_path, monkeypatch):
        populate(tmp_path / "vault.db")
        foreign_keys(monkeypatch)

        verified, detail = relocate.verify_decryptable(tmp_path / "vault.db")

        assert not verified
        assert "InvalidTag" in detail

    def test_ambient_keys_are_used_by_default(self, home, tmp_path):
        """The trap this parameter exists for: migrate relocates the key file
        and must check the copy as the migrated install will read it, but a
        plain move leaves the keys put and must trust the environment as it
        stands. Defaulting the other way fails every good move made from a
        launcher that exports its keys.
        """
        populate(tmp_path / "vault.db")

        assert relocate.verify_decryptable(tmp_path / "vault.db")[0]
        # The same vault, checked as if the environment did not exist, cannot be
        # read -- there is no key file in this per-user directory.
        assert not relocate.verify_decryptable(tmp_path / "vault.db", ambient_keys=False)[0]
