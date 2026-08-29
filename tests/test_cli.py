"""The commands that move live state, and what they refuse to do.

There is no backup behind `migrate`, so the properties worth pinning are the
refusals: it must not choose between two populated vaults, must not overwrite
key material it did not write, and must not report success on a copy it has not
proved it can decrypt.
"""

import base64
import secrets

import pytest

import cli
from core import keys, paths, relocate, vault
from core.crypto import LOOKUP_SECRET_ENV
from core.keys import MASTER_KEY_ENV, generate_data_key, wrap

MASTER = base64.b64encode(secrets.token_bytes(32)).decode()
LOOKUP = base64.b64encode(secrets.token_bytes(32)).decode()
POLICY = {"pii_types": ["EIN"]}


@pytest.fixture
def home(monkeypatch, tmp_path):
    """A per-user location and a working directory, both empty."""
    destination = tmp_path / "home"
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    # data_dir is patched rather than PII_VAULT_DIR being set: that variable
    # deliberately outranks the settings tier, so setting it here would hide
    # the very thing half of these tests are about.
    monkeypatch.setattr(paths, "data_dir", lambda: destination)
    monkeypatch.delenv(paths.VAULT_DIR_ENV, raising=False)
    monkeypatch.delenv(paths.VAULT_DB_ENV, raising=False)
    monkeypatch.chdir(checkout)
    keys.clear_cache()
    yield destination
    keys.clear_cache()


@pytest.fixture
def ambient_keys(monkeypatch):
    monkeypatch.setenv(MASTER_KEY_ENV, MASTER)
    monkeypatch.setenv(LOOKUP_SECRET_ENV, LOOKUP)
    keys.clear_cache()


def write_key_file(directory, master=MASTER, lookup=LOOKUP):
    path = directory / paths.ENV_FILENAME
    path.write_text(f"{MASTER_KEY_ENV}={master}\n{LOOKUP_SECRET_ENV}={lookup}\n", encoding="utf-8")
    keys.clear_cache()
    return path


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


class TestStatus:
    def test_reports_the_path_and_the_rule_that_found_it(self, home, ambient_keys, capsys):
        assert cli.main(["status"]) == 0

        out = capsys.readouterr().out
        assert str(home / paths.DB_FILENAME) in out
        assert "located by: default" in out
        assert "does not exist yet" in out

    def test_never_prints_secret_material(self, home, ambient_keys, capsys):
        cli.main(["status"])

        out = capsys.readouterr().out
        assert MASTER not in out
        assert LOOKUP not in out
        assert "environment" in out

    def test_names_the_legacy_vault_and_the_way_out(self, home, ambient_keys, tmp_path, capsys):
        """A vault beside the code is adopted, and says so.

        Adopting rather than refusing is what keeps a pre-move install working;
        the warning is what stops it being adopted forever.
        """
        populate(tmp_path / "checkout" / paths.DB_FILENAME)

        assert cli.main(["status"]) == 0

        out = capsys.readouterr().out
        assert "located by: legacy" in out
        assert "1 job(s)" in out
        assert "migrate" in out


class TestInit:
    def test_generates_when_there_is_nothing_to_orphan(self, home, monkeypatch, capsys):
        monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
        monkeypatch.delenv(LOOKUP_SECRET_ENV, raising=False)
        keys.clear_cache()

        assert cli.main(["init"]) == 0

        values = keys.read_key_file(home / paths.ENV_FILENAME)
        assert base64.b64decode(values[MASTER_KEY_ENV], validate=True) != b""
        assert values[MASTER_KEY_ENV] != values[LOOKUP_SECRET_ENV]
        assert "backup" in capsys.readouterr().out

    def test_refuses_to_generate_beside_a_vault_it_cannot_read(self, home, monkeypatch, capsys):
        """The old run scripts generated on a missing file rather than a missing
        vault, so a fresh clone minted a key and bricked every job."""
        home.mkdir(parents=True)
        populate(home / paths.DB_FILENAME)
        monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
        monkeypatch.delenv(LOOKUP_SECRET_ENV, raising=False)
        keys.clear_cache()

        assert cli.main(["init"]) == 2

        assert not (home / paths.ENV_FILENAME).exists()
        assert "permanently unreadable" in capsys.readouterr().err

    def test_is_a_no_op_when_keys_already_resolve(self, home, ambient_keys, capsys):
        """run.ps1 calls this on every launch."""
        assert cli.main(["init"]) == 0

        assert not (home / paths.ENV_FILENAME).exists()
        assert "already present" in capsys.readouterr().out

    def test_quiet_says_nothing_when_already_set_up(self, home, ambient_keys, capsys):
        assert cli.main(["init", "--quiet"]) == 0

        assert capsys.readouterr().out == ""


class TestBackup:
    def test_copies_the_vault_and_prints_both_keys(self, home, ambient_keys, tmp_path, capsys):
        home.mkdir(parents=True)
        populate(home / paths.DB_FILENAME)
        destination = tmp_path / "backup.db"

        assert cli.main(["backup", str(destination)]) == 0

        out = capsys.readouterr().out
        assert MASTER in out and LOOKUP in out
        conn = vault.connect(destination)
        assert vault.count_jobs(conn) == 1
        conn.close()

    def test_refuses_to_overwrite(self, home, ambient_keys, tmp_path, capsys):
        home.mkdir(parents=True)
        populate(home / paths.DB_FILENAME)
        destination = tmp_path / "backup.db"
        destination.touch()

        assert cli.main(["backup", str(destination)]) == 2
        assert "already exists" in capsys.readouterr().err


class TestMigrate:
    @pytest.fixture
    def checkout(self, home, ambient_keys, tmp_path):
        """A pre-move install: vault and key file beside the code."""
        directory = tmp_path / "checkout"
        job_id = populate(directory / paths.DB_FILENAME)
        write_key_file(directory)
        return directory, job_id

    def test_dry_run_changes_nothing(self, checkout, home, capsys):
        directory, _ = checkout

        assert cli.main(["migrate", "--dry-run"]) == 0

        assert (directory / paths.DB_FILENAME).exists()
        assert not (home / paths.DB_FILENAME).exists()
        out = capsys.readouterr().out
        assert "nothing was changed" in out

    def test_moves_verifies_and_keeps_the_original(self, checkout, home, capsys):
        directory, _ = checkout

        assert cli.main(["migrate"]) == 0

        assert (home / paths.DB_FILENAME).exists()
        assert (home / paths.ENV_FILENAME).exists()
        assert not (directory / paths.DB_FILENAME).exists()
        kept = list(directory.glob("vault.pre-migration-*.db"))
        assert len(kept) == 1
        out = capsys.readouterr().out
        assert "decrypted a filename" in out

    def test_the_migrated_vault_reads_without_any_ambient_key_material(self, checkout, home, monkeypatch):
        """The point of the move: a plain terminal can open it.

        Verified the way a later run will read it, with the launcher's exported
        variables gone -- otherwise the check passes on key material the
        migrated install does not have.
        """
        _, job_id = checkout
        cli.main(["migrate"])
        monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
        monkeypatch.delenv(LOOKUP_SECRET_ENV, raising=False)
        keys.clear_cache()

        conn = vault.connect(home / paths.DB_FILENAME)
        try:
            job_key = keys.unwrap(vault.get_wrapped_key(conn, job_id))
            document = vault.list_documents(conn, job_id)[0]
            assert vault.document_filename(conn, document.id, job_key) == "Smith_John_K1.pdf"
        finally:
            conn.close()

    def test_refuses_when_the_destination_holds_jobs(self, checkout, home, capsys):
        home.mkdir(parents=True)
        populate(home / paths.DB_FILENAME)

        assert cli.main(["migrate"]) == 2

        directory, _ = checkout
        assert (directory / paths.DB_FILENAME).exists()
        assert "not this program's decision" in capsys.readouterr().err

    def test_replaces_an_empty_destination(self, checkout, home):
        """A stray run from another directory leaves an empty vault behind;
        refusing on that would block the move for no reason."""
        home.mkdir(parents=True)
        vault.connect(home / paths.DB_FILENAME).close()

        assert cli.main(["migrate"]) == 0

        conn = vault.connect(home / paths.DB_FILENAME)
        assert vault.count_jobs(conn) == 1
        conn.close()

    def test_refuses_when_different_keys_are_already_installed(self, checkout, home, capsys):
        home.mkdir(parents=True)
        write_key_file(home, master=base64.b64encode(b"z" * 32).decode())

        assert cli.main(["migrate"]) == 2

        assert "orphan" in capsys.readouterr().err

    def test_refuses_without_a_key_file(self, home, ambient_keys, tmp_path, capsys):
        populate(tmp_path / "checkout" / paths.DB_FILENAME)

        assert cli.main(["migrate"]) == 2

        assert "no key file" in capsys.readouterr().err

    def test_refuses_a_key_file_missing_a_secret(self, home, ambient_keys, tmp_path, capsys):
        directory = tmp_path / "checkout"
        populate(directory / paths.DB_FILENAME)
        (directory / paths.ENV_FILENAME).write_text(f"{MASTER_KEY_ENV}={MASTER}\n", encoding="utf-8")
        keys.clear_cache()

        assert cli.main(["migrate"]) == 2

        assert LOOKUP_SECRET_ENV in capsys.readouterr().err

    def test_refuses_a_master_key_of_the_wrong_length(self, home, ambient_keys, tmp_path, capsys):
        directory = tmp_path / "checkout"
        populate(directory / paths.DB_FILENAME)
        write_key_file(directory, master=base64.b64encode(b"short").decode())

        assert cli.main(["migrate"]) == 2

        assert "must decode to 32 bytes" in capsys.readouterr().err

    def test_keeps_the_original_when_the_copy_does_not_decrypt(self, checkout, home, capsys):
        """Key material that does not match the vault must not ship as success.

        A copy that opens is not a copy that decrypts, and this is the failure
        nobody notices until a client asks for a restore.
        """
        directory, _ = checkout
        write_key_file(directory, master=base64.b64encode(b"w" * 32).decode())

        assert cli.main(["migrate"]) == 2

        assert (directory / paths.DB_FILENAME).exists()
        assert not list(directory.glob("vault.pre-migration-*.db"))
        assert "did not verify" in capsys.readouterr().err


class TestMoveAndUse:
    """The commands behind the settings page, and the repair path.

    These exist as a CLI as well because a setting pointing at a drive that is
    no longer connected stops the web app from starting, and the repair then
    has to come from somewhere else.
    """

    @pytest.fixture
    def installed(self, home, ambient_keys, tmp_path):
        """A working install at the per-user location."""
        home.mkdir(parents=True)
        populate(home / paths.DB_FILENAME)
        return home / paths.DB_FILENAME

    def test_move_records_the_choice(self, installed, tmp_path, capsys):
        destination = tmp_path / "elsewhere" / "firm.db"

        assert cli.main(["move", str(destination)]) == 0

        assert paths.configured_db_path() == destination
        assert relocate.count_jobs(destination) == 1
        out = capsys.readouterr().out
        assert "verified:" in out
        assert "key file has not moved" in out

    def test_move_dry_run_changes_nothing(self, installed, tmp_path, capsys):
        destination = tmp_path / "elsewhere" / "firm.db"

        assert cli.main(["move", str(destination), "--dry-run"]) == 0

        assert not destination.exists()
        assert paths.configured_db_path() is None
        assert "nothing was changed" in capsys.readouterr().out

    def test_move_refuses_a_relative_path(self, installed, capsys):
        """A relative destination would follow the working directory, which is
        the bug the fixed location exists to close."""
        assert cli.main(["move", "somewhere/vault.db"]) == 2

        assert paths.configured_db_path() is None
        assert "not a full path" in capsys.readouterr().err

    def test_use_adopts_an_existing_vault_without_copying(self, home, ambient_keys, tmp_path):
        existing = tmp_path / "shared" / "vault.db"
        populate(existing)

        assert cli.main(["use", str(existing)]) == 0

        assert paths.configured_db_path() == existing
        assert [p.name for p in (tmp_path / "shared").iterdir()] == ["vault.db"]

    def test_use_refuses_a_vault_this_machine_cannot_decrypt(
        self, home, ambient_keys, tmp_path, monkeypatch, capsys
    ):
        """The consequence of the key file staying behind. The message has to
        name the way out, because nothing else in the tool explains it."""
        existing = tmp_path / "shared" / "vault.db"
        populate(existing)
        monkeypatch.setenv(MASTER_KEY_ENV, base64.b64encode(secrets.token_bytes(32)).decode())
        keys.clear_cache()

        assert cli.main(["use", str(existing)]) == 2

        assert paths.configured_db_path() is None
        assert "cli.py backup" in capsys.readouterr().err

    def test_use_refuses_an_empty_vault_and_points_at_move(
        self, home, ambient_keys, tmp_path, capsys
    ):
        empty = tmp_path / "shared" / "vault.db"
        empty.parent.mkdir()
        vault.connect(empty).close()

        assert cli.main(["use", str(empty)]) == 2

        assert "Use Move" in capsys.readouterr().err

    def test_forget_falls_back_and_names_the_kept_copies(self, installed, tmp_path, capsys):
        """The recovery this command exists for: a move to somewhere that is no
        longer reachable leaves the data beside the fallback under its kept name."""
        destination = tmp_path / "removable" / "firm.db"
        cli.main(["move", str(destination)])
        capsys.readouterr()

        assert cli.main(["forget"]) == 0

        assert paths.configured_db_path() is None
        out = capsys.readouterr().out
        assert "setting cleared" in out
        assert "vault.moved-" in out

    def test_forget_survives_an_unreadable_settings_file(self, home, ambient_keys, capsys):
        """read() refuses a corrupt file rather than falling through, so without
        this the app could not be recovered in place at all."""
        paths.config_path().parent.mkdir(parents=True, exist_ok=True)
        paths.config_path().write_text("{not json", encoding="utf-8")

        assert cli.main(["forget"]) == 0

        assert paths.configured_db_path() is None


class TestStatusReporting:
    def test_reports_that_the_keys_decrypt_the_vault(self, home, ambient_keys, capsys):
        home.mkdir(parents=True)
        populate(home / paths.DB_FILENAME)

        cli.main(["status"])

        assert "keys decrypt it: yes" in capsys.readouterr().out

    def test_reports_when_the_keys_do_not(self, home, ambient_keys, monkeypatch, capsys):
        """A vault that opens and cannot be read is the whole hazard of a
        movable vault, and status is what has to say so."""
        home.mkdir(parents=True)
        populate(home / paths.DB_FILENAME)
        monkeypatch.setenv(MASTER_KEY_ENV, base64.b64encode(secrets.token_bytes(32)).decode())
        keys.clear_cache()

        cli.main(["status"])

        assert "keys decrypt it: NO" in capsys.readouterr().out

    def test_reports_a_setting_pointing_at_nothing(self, home, ambient_keys, tmp_path, capsys):
        paths.set_configured_db(tmp_path / "removable" / "firm.db")

        cli.main(["status"])

        out = capsys.readouterr().out
        assert "MISSING" in out
        assert "forget" in out

    def test_refuses_a_corrupt_settings_file_rather_than_guessing(
        self, home, ambient_keys, capsys
    ):
        paths.config_path().parent.mkdir(parents=True, exist_ok=True)
        paths.config_path().write_text("{not json", encoding="utf-8")

        assert cli.main(["status"]) == 2

        assert "forget" in capsys.readouterr().err

    def test_does_not_run_our_schema_over_a_file_that_is_not_a_vault(
        self, home, ambient_keys, capsys
    ):
        """status must not be the thing that turns a mistyped path into a vault."""
        home.mkdir(parents=True)
        decoy = home / paths.DB_FILENAME
        decoy.write_text("not a database", encoding="utf-8")

        cli.main(["status"])

        assert "not a pii-cypher vault" in capsys.readouterr().out
        assert decoy.read_text(encoding="utf-8") == "not a database"


class TestMigrateDestination:
    def test_to_moves_the_vault_but_never_the_keys(self, home, ambient_keys, tmp_path, capsys):
        """A convenience flag must not be able to write key material onto a
        share; that would be a security regression delivered by an option."""
        directory = tmp_path / "checkout"
        populate(directory / paths.DB_FILENAME)
        write_key_file(directory)
        elsewhere = tmp_path / "elsewhere" / "firm.db"

        assert cli.main(["migrate", "--to", str(elsewhere)]) == 0

        assert relocate.count_jobs(elsewhere) == 1
        assert (home / paths.ENV_FILENAME).is_file()
        assert not (elsewhere.parent / paths.ENV_FILENAME).exists()
