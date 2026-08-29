"""Resolving key material, and the guarantee that none of it is invented.

Every failure here has the same worst case: a tool that cannot find the master
key and generates a replacement makes every existing job permanently
unreadable. So the tests assert refusal, not recovery.
"""

import base64

import pytest

from core import keys, paths
from core.keys import MASTER_KEY_ENV, MissingKeyMaterial, load_secret

OTHER = base64.b64encode(b"o" * 32).decode()
FROM_FILE = base64.b64encode(b"f" * 32).decode()


@pytest.fixture(autouse=True)
def key_dir(monkeypatch, tmp_path):
    """An empty key directory, with the session's ambient key material removed."""
    monkeypatch.setenv(paths.VAULT_DIR_ENV, str(tmp_path))
    monkeypatch.delenv(MASTER_KEY_ENV, raising=False)
    monkeypatch.delenv("PII_LOOKUP_SECRET", raising=False)
    keys.clear_cache()
    yield
    keys.clear_cache()


def write_key_file(text: str, encoding: str = "utf-8") -> None:
    paths.env_file_path().write_text(text, encoding=encoding)
    keys.clear_cache()


def test_the_environment_wins_over_the_key_file(monkeypatch):
    """Tests, CI and a systemd EnvironmentFile all depend on this order."""
    write_key_file(f"{MASTER_KEY_ENV}={FROM_FILE}")
    monkeypatch.setenv(MASTER_KEY_ENV, OTHER)

    assert load_secret(MASTER_KEY_ENV) == b"o" * 32


def test_the_key_file_is_used_when_the_environment_is_unset():
    """`python cli.py` in a plain terminal used to fail here."""
    write_key_file(f"{MASTER_KEY_ENV}={FROM_FILE}")

    assert load_secret(MASTER_KEY_ENV) == b"f" * 32


def test_neither_source_names_the_way_out():
    with pytest.raises(MissingKeyMaterial) as excinfo:
        load_secret(MASTER_KEY_ENV)

    message = str(excinfo.value)
    assert "migrate" in message
    assert "never generated automatically" in message


def test_an_empty_environment_value_falls_through_to_the_file(monkeypatch):
    write_key_file(f"{MASTER_KEY_ENV}={FROM_FILE}")
    monkeypatch.setenv(MASTER_KEY_ENV, "")

    assert load_secret(MASTER_KEY_ENV) == b"f" * 32


def test_a_malformed_line_refuses_rather_than_loading_half_a_file():
    """A typo that dropped one secret would otherwise read as "not set",
    which invites the user to generate a replacement."""
    write_key_file(f"{MASTER_KEY_ENV}={FROM_FILE}\nthis line has no equals sign")

    with pytest.raises(MissingKeyMaterial, match="line 2"):
        load_secret(MASTER_KEY_ENV)


def test_blank_lines_and_comments_are_not_malformed():
    write_key_file(f"# a comment\n\n{MASTER_KEY_ENV}={FROM_FILE}\n")

    assert load_secret(MASTER_KEY_ENV) == b"f" * 32


def test_a_byte_order_mark_does_not_become_part_of_the_first_key_name():
    """PowerShell's Out-File -Encoding utf8 writes one, and run.ps1 uses it."""
    write_key_file(f"{MASTER_KEY_ENV}={FROM_FILE}", encoding="utf-8-sig")

    assert load_secret(MASTER_KEY_ENV) == b"f" * 32


def test_quoted_values_are_accepted():
    write_key_file(f'{MASTER_KEY_ENV}="{FROM_FILE}"')

    assert load_secret(MASTER_KEY_ENV) == b"f" * 32


def test_invalid_base64_is_a_clear_error_not_a_traceback(monkeypatch):
    monkeypatch.setenv(MASTER_KEY_ENV, "not base64 at all!!")

    with pytest.raises(MissingKeyMaterial, match="valid base64"):
        load_secret(MASTER_KEY_ENV)


def test_length_is_checked_only_when_asked(monkeypatch):
    """The master key must be 32 bytes; the lookup secret is unconstrained,
    or a hand-set one of another size locks its owner out of a live vault."""
    monkeypatch.setenv(MASTER_KEY_ENV, base64.b64encode(b"short").decode())

    assert load_secret(MASTER_KEY_ENV) == b"short"
    with pytest.raises(MissingKeyMaterial, match="must decode to 32 bytes"):
        load_secret(MASTER_KEY_ENV, length=32)


def test_a_missing_key_file_is_empty_not_an_error():
    assert not paths.env_file_path().exists()

    with pytest.raises(MissingKeyMaterial, match="is not set"):
        load_secret(MASTER_KEY_ENV)


def test_the_file_is_read_once_however_many_secrets_are_resolved(monkeypatch):
    """With no environment set this is on the path of every token hashed."""
    write_key_file(f"{MASTER_KEY_ENV}={FROM_FILE}")
    reads = 0
    real_read = type(paths.env_file_path()).read_text

    def counting_read(self, *args, **kwargs):
        nonlocal reads
        reads += 1
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(type(paths.env_file_path()), "read_text", counting_read)
    for _ in range(50):
        load_secret(MASTER_KEY_ENV)

    assert reads == 1
