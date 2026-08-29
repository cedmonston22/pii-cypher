"""Data key generation and wrapping.

This is the only module that needs to change when key custody moves to a KMS.
``wrap``/``unwrap`` become ``kms.encrypt``/``kms.decrypt`` and nothing upstream
is touched -- which is why the indirection exists now, before it is needed.
"""

from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import paths

MASTER_KEY_ENV = "PII_MASTER_KEY"
NONCE_LEN = 12
KEY_LEN = 32


class MissingKeyMaterial(Exception):
    """Raised when required key material is absent from the environment."""


_key_file_cache: dict[Path, dict[str, str]] = {}


def clear_cache() -> None:
    """Forget parsed key files. For tests that write one after reading it."""
    _key_file_cache.clear()


def read_key_file(path: Path) -> dict[str, str]:
    """Parse a KEY=value file. A missing file is empty, a malformed one raises.

    Cached by path: with no environment set, this is consulted once per token
    hashed, which is hundreds of times for one batch.

    Read as utf-8-sig because PowerShell's ``Out-File -Encoding utf8`` writes a
    BOM, and the first key in the file would otherwise carry it in its name.
    """
    if path in _key_file_cache:
        return _key_file_cache[path]

    values: dict[str, str] = {}
    if path.is_file():
        for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            name, separator, value = stripped.partition("=")
            if not separator:
                # Refusing beats loading half a file: a typo that dropped one
                # secret would otherwise surface as "not set" and invite the
                # user to generate a replacement.
                raise MissingKeyMaterial(f"{path}: line {number} is not KEY=value")
            values[name.strip()] = value.strip().strip("\"'")

    _key_file_cache[path] = values
    return values


def load_secret(env_var: str, *, length: int | None = None) -> bytes:
    """Resolve one secret: the environment first, then the key file.

    The environment wins so the test suite, CI and a server started from a
    systemd EnvironmentFile all keep working. That is also where an OS keystore
    slots in later, as a step between the two.

    Never generates. A generated master key makes every existing job
    permanently unreadable, and a tool that quietly does that because it was
    launched from the wrong directory is worse than one that refuses to start.
    """
    raw = os.environ.get(env_var) or read_key_file(paths.env_file_path()).get(env_var)
    if not raw:
        raise MissingKeyMaterial(_missing_message(env_var))
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MissingKeyMaterial(f"{env_var} is not valid base64") from exc
    if length is not None and len(key) != length:
        raise MissingKeyMaterial(f"{env_var} must decode to {length} bytes, got {len(key)}")
    return key


def secret_source(env_var: str) -> str | None:
    """Where a secret would be resolved from, without revealing its value.

    Only `status` needs this: the point of that command is to explain what the
    install is actually using, and printing the secret to do so would defeat
    the move that put it outside the checkout.
    """
    if os.environ.get(env_var):
        return "environment"
    try:
        if read_key_file(paths.env_file_path()).get(env_var):
            return str(paths.env_file_path())
    except MissingKeyMaterial:
        return None
    return None


def _missing_message(env_var: str) -> str:
    """The one message standing between a confused user and a new master key."""
    return f"""{env_var} is not set, and no value for it is in {paths.env_file_path()}

  existing checkout   python cli.py migrate
  server or CI        set the variable to a base64 32-byte value

Key material is never generated automatically: a new master key makes every
existing job permanently unreadable."""


def _master_key() -> bytes:
    return load_secret(MASTER_KEY_ENV, length=KEY_LEN)


def generate_data_key() -> bytes:
    """Return a fresh 32-byte job key. Never persisted unwrapped."""
    return os.urandom(KEY_LEN)


def wrap(key: bytes) -> bytes:
    """Encrypt a job key under the master key. Returns nonce || ciphertext."""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(_master_key()).encrypt(nonce, key, None)


def unwrap(wrapped: bytes) -> bytes:
    """Recover a job key. Raises InvalidTag if the master key does not match."""
    return AESGCM(_master_key()).decrypt(wrapped[:NONCE_LEN], wrapped[NONCE_LEN:], None)
