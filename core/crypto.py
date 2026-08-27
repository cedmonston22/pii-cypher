"""Value encryption and token hashing.

One canonical AAD builder is used by both encryption and decryption. Binding the
job, PII type and token into the AAD means a ciphertext lifted from one job
cannot be decrypted in the context of another -- GCM will reject the tag.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.keys import MissingKeyMaterial

TENANT_ID = "local"
LOOKUP_SECRET_ENV = "PII_LOOKUP_SECRET"
NONCE_LEN = 12


def aad(job_id: str, pii_type: str, token: str) -> bytes:
    """Additional authenticated data binding a ciphertext to its context.

    The literal "value" is a domain tag. Without it a pii_type of "filename"
    would produce the same AAD as aad_filename, letting an encrypted filename be
    substituted into a value slot without GCM objecting.
    """
    return f"{TENANT_ID}|{job_id}|value|{pii_type}|{token}".encode()


def aad_filename(job_id: str, doc_id: str) -> bytes:
    """AAD for an encrypted filename.

    ``doc_id`` is an input, so it must be generated before the row is inserted
    rather than assigned by the database.
    """
    return f"{TENANT_ID}|{job_id}|filename|{doc_id}".encode()


def encrypt(job_key: bytes, plaintext: str, associated: bytes) -> tuple[bytes, bytes]:
    """Encrypt one value. Returns (ciphertext, nonce) with a fresh nonce."""
    nonce = os.urandom(NONCE_LEN)
    return AESGCM(job_key).encrypt(nonce, plaintext.encode(), associated), nonce


def decrypt(job_key: bytes, ciphertext: bytes, nonce: bytes, associated: bytes) -> str:
    """Decrypt one value.

    Deliberately does not catch InvalidTag. A tag failure means the ciphertext
    was tampered with or belongs to another job; continuing past it would return
    or write the wrong value.
    """
    return AESGCM(job_key).decrypt(nonce, ciphertext, associated).decode()


def _lookup_secret() -> bytes:
    raw = os.environ.get(LOOKUP_SECRET_ENV)
    if not raw:
        raise MissingKeyMaterial(f"{LOOKUP_SECRET_ENV} is not set")
    return base64.b64decode(raw)


def token_hash(token: str) -> str:
    """Keyed hash of a token, hex encoded.

    The vault is queried by this, so a raw token never reaches the database and
    a stolen database cannot be scanned for tokens seen elsewhere.
    """
    return hmac.new(_lookup_secret(), token.encode(), hashlib.sha256).hexdigest()
