"""Crypto round trips and the AAD binding that makes cross-job reuse fail."""

import pytest
from cryptography.exceptions import InvalidTag

from core.crypto import aad, aad_filename, decrypt, encrypt, token_hash
from core.keys import generate_data_key, unwrap, wrap


def test_key_wrap_round_trip():
    key = generate_data_key()
    assert len(key) == 32
    assert unwrap(wrap(key)) == key


def test_wrapped_key_is_not_the_key():
    key = generate_data_key()
    assert key not in wrap(key)


def test_value_round_trip():
    key = generate_data_key()
    context = aad("job1", "ssn_tin", "PII-ABC23456")
    ct, nonce = encrypt(key, "000-00-0000", context)
    assert decrypt(key, ct, nonce, context) == "000-00-0000"


def test_nonce_is_fresh_per_value():
    key = generate_data_key()
    context = aad("job1", "ssn_tin", "PII-ABC23456")
    first = encrypt(key, "000-00-0000", context)
    second = encrypt(key, "000-00-0000", context)
    assert first[1] != second[1]
    assert first[0] != second[0]


@pytest.mark.parametrize(
    "wrong",
    [
        ("job2", "ssn_tin", "PII-ABC23456"),
        ("job1", "ein", "PII-ABC23456"),
        ("job1", "ssn_tin", "PII-ZZZ99999"),
    ],
    ids=["wrong_job", "wrong_type", "wrong_token"],
)
def test_aad_mismatch_raises(wrong):
    """A ciphertext lifted into another context must not decrypt."""
    key = generate_data_key()
    ct, nonce = encrypt(key, "000-00-0000", aad("job1", "ssn_tin", "PII-ABC23456"))
    with pytest.raises(InvalidTag):
        decrypt(key, ct, nonce, aad(*wrong))


def test_wrong_job_key_raises():
    context = aad("job1", "ssn_tin", "PII-ABC23456")
    ct, nonce = encrypt(generate_data_key(), "000-00-0000", context)
    with pytest.raises(InvalidTag):
        decrypt(generate_data_key(), ct, nonce, context)


def test_ciphertext_corruption_raises():
    key = generate_data_key()
    context = aad("job1", "ssn_tin", "PII-ABC23456")
    ct, nonce = encrypt(key, "000-00-0000", context)
    corrupted = bytes([ct[0] ^ 0xFF]) + ct[1:]
    with pytest.raises(InvalidTag):
        decrypt(key, corrupted, nonce, context)


def test_filename_aad_is_distinct_from_value_aad():
    """A pii_type of "filename" must not collide with the filename domain.

    Without a domain tag both build "local|job1|filename|doc1", so a filename
    ciphertext could be substituted into a value slot and still authenticate.
    """
    assert aad_filename("job1", "doc1") != aad("job1", "filename", "doc1")


def test_filename_ciphertext_cannot_be_decrypted_as_a_value():
    key = generate_data_key()
    ct, nonce = encrypt(key, "Smith_John_K1.pdf", aad_filename("job1", "doc1"))
    with pytest.raises(InvalidTag):
        decrypt(key, ct, nonce, aad("job1", "filename", "doc1"))


def test_token_hash_is_stable_and_not_the_token():
    digest = token_hash("PII-ABC23456")
    assert digest == token_hash("PII-ABC23456")
    assert digest != token_hash("PII-ABC23457")
    assert "PII-ABC23456" not in digest
    assert len(digest) == 64
