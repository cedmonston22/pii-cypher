import base64
import os
import secrets
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "k1-sample.pdf"
FIXTURE_2025 = Path(__file__).parent / "fixtures" / "k1-2025.pdf"


@pytest.fixture(scope="session", autouse=True)
def key_material():
    """Provide ephemeral key material so tests never depend on a real master key."""
    os.environ["PII_MASTER_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()
    os.environ["PII_LOOKUP_SECRET"] = base64.b64encode(secrets.token_bytes(32)).decode()


@pytest.fixture(scope="session")
def k1_bytes() -> bytes:
    """The 2021 Schedule K-1."""
    return FIXTURE.read_bytes()


@pytest.fixture(scope="session")
def k1_2025_bytes() -> bytes:
    """The 2025 Schedule K-1.

    A different revision of the same form: labels reworded, typographic
    apostrophes, and the label-to-value indent inverted. One concept map has to
    cover both.
    """
    return FIXTURE_2025.read_bytes()
