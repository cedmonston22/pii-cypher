"""The settings file, and what it refuses to load.

The failure this guards is quiet: a setting that does not apply sends the tool
to a different vault and reports zero jobs. So a broken file raises rather than
falling back to the default location.
"""

import json

import pytest

from core import config
from core.config import ConfigError


@pytest.fixture
def config_file(tmp_path):
    return tmp_path / "config.json"


def test_round_trip(config_file, tmp_path):
    config.write(config_file, {config.VAULT_DB_KEY: str(tmp_path / "vault.db")})

    assert config.read(config_file)[config.VAULT_DB_KEY] == str(tmp_path / "vault.db")


def test_a_version_is_recorded_so_growing_the_file_needs_no_migration(config_file, tmp_path):
    config.write(config_file, {config.VAULT_DB_KEY: str(tmp_path / "vault.db")})

    assert json.loads(config_file.read_text(encoding="utf-8"))["version"] == config.CONFIG_VERSION


def test_a_missing_file_is_empty_not_an_error(config_file):
    assert config.read(config_file) == {}


def test_corrupt_json_refuses(config_file):
    config_file.write_text("{not json", encoding="utf-8")

    with pytest.raises(ConfigError, match="not valid JSON"):
        config.read(config_file)


def test_a_json_scalar_is_not_a_config(config_file):
    config_file.write_text('"just a string"', encoding="utf-8")

    with pytest.raises(ConfigError, match="JSON object"):
        config.read(config_file)


def test_a_relative_path_refuses(config_file):
    """A hand-edited file is the last way the working-directory bug gets back in.

    A relative vault path would follow the shell again, which is precisely what
    the per-user location exists to stop.
    """
    config_file.write_text(json.dumps({config.VAULT_DB_KEY: "vault.db"}), encoding="utf-8")

    with pytest.raises(ConfigError, match="absolute path"):
        config.read(config_file)


@pytest.mark.parametrize("value", ["", "   ", 42, ["/a/b"]])
def test_a_vault_path_that_is_not_a_usable_string_refuses(config_file, value):
    config_file.write_text(json.dumps({config.VAULT_DB_KEY: value}), encoding="utf-8")

    with pytest.raises(ConfigError):
        config.read(config_file)


def test_an_explicit_null_reads_as_no_setting(config_file):
    """Indistinguishable from an absent key, and benign: resolution falls to the
    next tier rather than to a path that cannot be used."""
    config_file.write_text(json.dumps({config.VAULT_DB_KEY: None}), encoding="utf-8")

    assert config.read(config_file)[config.VAULT_DB_KEY] is None


def test_an_absent_vault_key_is_allowed(config_file):
    """The file may exist holding only a version, which is not a broken file."""
    config_file.write_text(json.dumps({"version": 1}), encoding="utf-8")

    assert config.read(config_file) == {"version": 1}


def test_write_leaves_no_temp_file_behind(config_file, tmp_path):
    config.write(config_file, {config.VAULT_DB_KEY: str(tmp_path / "vault.db")})

    assert [p.name for p in tmp_path.iterdir()] == ["config.json"]


def test_write_creates_the_parent_directory(tmp_path):
    nested = tmp_path / "pii-cypher" / "config.json"

    config.write(nested, {config.VAULT_DB_KEY: str(tmp_path / "vault.db")})

    assert config.read(nested)[config.VAULT_DB_KEY] == str(tmp_path / "vault.db")


def test_a_failed_write_leaves_the_previous_settings_intact(config_file, tmp_path, monkeypatch):
    """read() refuses a truncated file, so a half-written one would stop the app."""
    config.write(config_file, {config.VAULT_DB_KEY: str(tmp_path / "first.db")})

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(config.os, "replace", explode)
    with pytest.raises(OSError):
        config.write(config_file, {config.VAULT_DB_KEY: str(tmp_path / "second.db")})

    assert config.read(config_file)[config.VAULT_DB_KEY] == str(tmp_path / "first.db")
    assert [p.name for p in tmp_path.iterdir()] == ["config.json"]
