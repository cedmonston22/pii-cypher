"""Data key generation and wrapping.

This is the only module that needs to change when key custody moves to a KMS.
``wrap``/``unwrap`` become ``kms.encrypt``/``kms.decrypt`` and nothing upstream
is touched -- which is why the indirection exists now, before it is needed.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASTER_KEY_ENV = "PII_MASTER_KEY"
NONCE_LEN = 12
KEY_LEN = 32


class MissingKeyMaterial(Exception):
    """Raised when required key material is absent from the environment."""


def _master_key() -> bytes:
    raw = os.environ.get(MASTER_KEY_ENV)
    if not raw:
        raise MissingKeyMaterial(f"{MASTER_KEY_ENV} is not set")
    key = base64.b64decode(raw)
    if len(key) != KEY_LEN:
        raise MissingKeyMaterial(f"{MASTER_KEY_ENV} must decode to {KEY_LEN} bytes, got {len(key)}")
    return key


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
