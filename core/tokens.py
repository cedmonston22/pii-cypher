"""Token minting and discovery.

Tokens are random, never derived from the value they replace. A derived token
would leak its input to anyone who can guess the derivation.
"""

from __future__ import annotations

import re
import secrets

from core.extract import Line

# 32 symbols. 0/O/1/I are omitted so a token can be read aloud or retyped from
# a printed page without ambiguity. Uppercase L is kept; lowercase is unused.
ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
PREFIX = "PII-"
LENGTH = 8

TOKEN_RE = re.compile(rf"\b{re.escape(PREFIX)}[{ALPHABET}]{{{LENGTH}}}\b")


def mint_token(taken: set[str] | None = None) -> str:
    """Return a fresh token, avoiding any already issued for this job.

    32**8 is about 1.1e12, so a collision is vanishingly unlikely at realistic
    job sizes -- but the check costs nothing and removes the failure mode.
    """
    taken = taken or set()
    while True:
        token = PREFIX + "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))
        if token not in taken:
            return token


def assign(values: list[str], token_map: dict[str, str]) -> dict[str, str]:
    """Assign tokens to values, reusing any already minted in this job.

    ``token_map`` is owned by the batch, not the document, so a value appearing
    in several documents receives one token across all of them. Mutated in place.
    """
    taken = set(token_map.values())
    for value in values:
        if value not in token_map:
            token = mint_token(taken)
            taken.add(token)
            token_map[value] = token
    return token_map


def find_tokens(pages: list[list[Line]]) -> list[str]:
    """Return every distinct token appearing in the document, in reading order."""
    seen: dict[str, None] = {}
    for lines in pages:
        for line in lines:
            for match in TOKEN_RE.finditer(line["text"]):
                seen.setdefault(match.group(0), None)
    return list(seen)
