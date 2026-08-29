"""Where the vault resolves to, and why.

The bug this file guards against is silent: a tool that cannot find the vault
reports zero jobs rather than erroring, so every rule here is pinned by name.
"""

from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from core import config, paths


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    """Start from no overrides and a directory holding no vault.

    conftest sets PII_VAULT_DIR for the whole session; these tests are the ones
    that need to see what happens without it.
    """
    monkeypatch.delenv(paths.VAULT_DB_ENV, raising=False)
    monkeypatch.delenv(paths.VAULT_DIR_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    # config_path() follows data_dir(), and with no override that is the real
    # per-user location. Without this redirect a test would read -- or worse,
    # write -- the developer's actual settings.
    monkeypatch.setattr(paths, "config_path", lambda: tmp_path / paths.CONFIG_FILENAME)


def test_flag_wins_over_everything(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.VAULT_DB_ENV, str(tmp_path / "from-env.db"))
    monkeypatch.setenv(paths.VAULT_DIR_ENV, str(tmp_path / "dir"))
    (tmp_path / paths.DB_FILENAME).touch()

    assert paths.resolve_db(tmp_path / "chosen.db") == (tmp_path / "chosen.db", "flag")


def test_db_env_wins_over_dir_env(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.VAULT_DB_ENV, str(tmp_path / "from-env.db"))
    monkeypatch.setenv(paths.VAULT_DIR_ENV, str(tmp_path / "dir"))

    path, source = paths.resolve_db()

    assert (path, source) == (tmp_path / "from-env.db", paths.VAULT_DB_ENV)


def test_dir_env_wins_over_a_vault_in_the_working_directory(monkeypatch, tmp_path):
    """The override is explicit configuration; the legacy vault is a fallback."""
    monkeypatch.setenv(paths.VAULT_DIR_ENV, str(tmp_path / "dir"))
    (tmp_path / paths.DB_FILENAME).touch()

    path, source = paths.resolve_db()

    assert (path, source) == (tmp_path / "dir" / paths.DB_FILENAME, paths.VAULT_DIR_ENV)


def test_a_vault_in_the_working_directory_wins_over_the_default(tmp_path):
    """Live client data beats an empty vault that does not exist yet.

    Reversing these two is the whole failure: the tool would create a fresh
    vault in the per-user location and report zero jobs on a machine holding
    eleven.
    """
    legacy = tmp_path / paths.DB_FILENAME
    legacy.touch()

    path, source = paths.resolve_db()

    assert (path, source) == (legacy, "legacy")


def test_the_default_applies_when_nothing_else_does():
    path, source = paths.resolve_db()

    assert source == "default"
    assert path == paths.default_db_path()


def test_a_directory_named_vault_db_is_not_a_vault(tmp_path):
    (tmp_path / paths.DB_FILENAME).mkdir()

    assert paths.legacy_db_path() is None
    assert paths.resolve_db()[1] == "default"


def test_only_the_legacy_source_warns():
    assert paths.legacy_warning("legacy") is not None
    assert "migrate" in paths.legacy_warning("legacy")
    for source in ("flag", "default", paths.VAULT_DB_ENV, paths.VAULT_DIR_ENV):
        assert paths.legacy_warning(source) is None


def test_the_key_file_sits_beside_the_vault(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.VAULT_DIR_ENV, str(tmp_path / "dir"))

    assert paths.env_file_path().parent == paths.default_db_path().parent


class TestDataDir:
    """The platform matrix, exercised on whatever host is running the suite."""

    HOME = Path("/home/u")

    def test_windows_uses_local_appdata(self):
        result = paths._data_dir("win32", {"LOCALAPPDATA": r"C:\Users\u\AppData\Local"}, self.HOME)

        assert result == Path(r"C:\Users\u\AppData\Local") / paths.APP_DIR_NAME

    def test_windows_never_uses_roaming_appdata(self):
        """APPDATA roams to a server at logon on a domain-joined machine.

        Resolving there would sync the vault -- and the key file beside it --
        off the laptop as a side effect of logging in, which is the copy this
        whole move exists to prevent. platformdirs defaults to it, which is why
        this is hand-rolled.
        """
        environ = {"APPDATA": r"C:\SENTINEL\Roaming", "LOCALAPPDATA": r"C:\Users\u\AppData\Local"}

        assert "SENTINEL" not in str(paths._data_dir("win32", environ, self.HOME))

    def test_windows_falls_back_when_local_appdata_is_unset(self):
        result = paths._data_dir("win32", {}, self.HOME)

        assert result == self.HOME / "AppData" / "Local" / paths.APP_DIR_NAME

    def test_macos_uses_application_support(self):
        result = paths._data_dir("darwin", {}, self.HOME)

        assert result == self.HOME / "Library" / "Application Support" / paths.APP_DIR_NAME

    def test_linux_honours_xdg_then_falls_back(self):
        assert paths._data_dir("linux", {"XDG_DATA_HOME": "/x"}, self.HOME) == Path("/x") / paths.APP_DIR_NAME
        assert paths._data_dir("linux", {}, self.HOME) == self.HOME / ".local" / "share" / paths.APP_DIR_NAME


class TestSettingsTier:
    """The persisted choice, and where it sits relative to everything else."""

    def test_a_chosen_vault_beats_one_in_the_working_directory(self, tmp_path):
        """Load-bearing ordering, not taste.

        A checkout still holding its own vault.db is the normal case. If legacy
        won, choosing a new location would have no effect at all and the tool
        would say nothing about it -- the same silence this whole feature exists
        to avoid producing.
        """
        (tmp_path / paths.DB_FILENAME).touch()
        chosen = tmp_path / "elsewhere" / "vault.db"
        paths.set_configured_db(chosen)

        assert paths.resolve_db() == (chosen, "settings")

    def test_both_environment_variables_beat_the_setting(self, monkeypatch, tmp_path):
        """Matches keys.load_secret: a deliberate per-process launch decision
        outranks a stored preference, which is what keeps CI and a server
        started from an EnvironmentFile predictable."""
        paths.set_configured_db(tmp_path / "chosen.db")

        monkeypatch.setenv(paths.VAULT_DIR_ENV, str(tmp_path / "dir"))
        assert paths.resolve_db()[1] == paths.VAULT_DIR_ENV

        monkeypatch.setenv(paths.VAULT_DB_ENV, str(tmp_path / "env.db"))
        assert paths.resolve_db()[1] == paths.VAULT_DB_ENV

    def test_the_flag_still_beats_the_setting(self, tmp_path):
        paths.set_configured_db(tmp_path / "chosen.db")

        assert paths.resolve_db(tmp_path / "flag.db") == (tmp_path / "flag.db", "flag")

    def test_a_setting_pointing_nowhere_still_resolves_to_it(self, tmp_path):
        """Resolution is not existence. The caller decides what a missing file
        means -- status reports it, the settings page offers to clear it."""
        missing = tmp_path / "gone" / "vault.db"
        paths.set_configured_db(missing)

        assert paths.resolve_db() == (missing, "settings")

    def test_clearing_falls_back_to_the_next_tier(self, tmp_path):
        paths.set_configured_db(tmp_path / "chosen.db")
        paths.clear_configured_db()

        assert paths.resolve_db()[1] == "default"

    def test_clearing_works_even_when_the_config_is_corrupt(self, tmp_path):
        """This is the repair path; a corrupt file is what it exists to fix."""
        paths.config_path().write_text("{not json", encoding="utf-8")

        paths.clear_configured_db()

        assert paths.configured_db_path() is None

    def test_a_corrupt_config_refuses_rather_than_silently_falling_back(self, tmp_path):
        paths.config_path().write_text("{not json", encoding="utf-8")

        with pytest.raises(config.ConfigError):
            paths.resolve_db()

    def test_setting_the_vault_preserves_the_rest_of_the_file(self, tmp_path):
        config.write(paths.config_path(), {"something_else": "kept"})

        paths.set_configured_db(tmp_path / "chosen.db")

        assert config.read(paths.config_path())["something_else"] == "kept"


class TestValidateShape:
    """Pure shape rules, run against an explicit flavour.

    PurePosixPath("D:/x/v.db") is a relative single-component name, so running
    the Windows cases through the host's native flavour on Linux would assert
    the opposite of the truth.
    """

    @pytest.mark.parametrize(
        "text",
        [r"C:\Users\u\vault.db", r"\\server\share\vault.db"],
    )
    def test_windows_absolute_forms_are_accepted(self, text):
        assert paths._validate(text, PureWindowsPath) == PureWindowsPath(text)

    @pytest.mark.parametrize("text", [r"C:vault.db", r"\vault.db", r"data\vault.db"])
    def test_windows_forms_that_are_not_absolute_are_refused(self, text):
        """C:vault.db is drive-relative and \vault.db is rootless. Both look
        absolute at a glance and neither pins a location."""
        with pytest.raises(ValueError, match="not a full path"):
            paths._validate(text, PureWindowsPath)

    def test_a_quoted_paste_is_accepted(self):
        """Explorer's Copy as path includes the quotes, so this is the very
        first thing a user tries."""
        assert paths._validate(r'"C:\Users\u\vault.db"', PureWindowsPath) == PureWindowsPath(
            r"C:\Users\u\vault.db"
        )

    def test_a_path_with_no_extension_is_refused_as_a_folder(self):
        """The likely mistake is pasting a folder that does not exist yet, which
        cannot be told from a file name any other way."""
        with pytest.raises(ValueError, match="looks like a folder"):
            paths._validate(r"C:\Users\u\vaults", PureWindowsPath)

    @pytest.mark.parametrize("text", ["", "   ", '""'])
    def test_an_empty_path_is_refused(self, text):
        with pytest.raises(ValueError, match="Give the full path"):
            paths._validate(text, PureWindowsPath)

    def test_posix_absolute_and_relative(self):
        assert paths._validate("/srv/pii/vault.db", PurePosixPath) == PurePosixPath(
            "/srv/pii/vault.db"
        )
        with pytest.raises(ValueError, match="not a full path"):
            paths._validate("srv/vault.db", PurePosixPath)


class TestValidateAgainstDisk:
    def test_a_directory_without_a_suffix_is_caught_by_the_shape_rule(self, tmp_path):
        """The usual case, and it never reaches the disk check."""
        with pytest.raises(ValueError, match="looks like a folder"):
            paths.validate_vault_path(str(tmp_path))

    def test_a_directory_that_looks_like_a_file_is_caught_on_disk(self, tmp_path):
        """A folder named vault.db passes every shape rule, so only the
        filesystem can tell. Connecting to it would raise sqlite3 noise instead
        of something a user can act on."""
        decoy = tmp_path / "vault.db"
        decoy.mkdir()

        with pytest.raises(ValueError, match="is a folder"):
            paths.validate_vault_path(str(decoy))

    def test_one_missing_folder_is_fine_but_two_is_a_typo(self, tmp_path):
        path, warnings = paths.validate_vault_path(str(tmp_path / "new" / "vault.db"))
        assert path == tmp_path / "new" / "vault.db"
        assert warnings == []

        with pytest.raises(ValueError, match="usually means a typo"):
            paths.validate_vault_path(str(tmp_path / "new" / "deeper" / "vault.db"))

    def test_an_existing_path_produces_no_warnings(self, tmp_path):
        target = tmp_path / "vault.db"
        target.touch()

        assert paths.validate_vault_path(str(target)) == (target, [])
