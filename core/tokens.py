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

# The separator between a token and a revealed digit run. It must be a non-word
# character. TOKEN_RE ends in a word boundary, so appending digits straight to
# the token -- "PII-ABC234566789" -- destroys that boundary and find_tokens
# returns nothing, leaving the document unidentifiable and every restore
# unmatched. test_find_tokens_ignores_near_misses pins it.
SUFFIX_SEP = "-"

# Six leaves three digits of a nine-digit SSN or EIN hidden: a thousand
# combinations, and fewer in practice, because the hidden leading run of a
# pre-2011 SSN is a geographically assigned area number. Past this the setting
# is not partial disclosure any more, so the range stops here.
MAX_REVEAL_DIGITS = 6
DEFAULT_REVEAL_DIGITS = 4


def digits_of(value: str) -> str:
    """The digits of a value, in order. ``512-44-8890`` -> ``512448890``."""
    return "".join(c for c in value if c.isdigit())


def display(token: str, value: str, reveal: int = 0) -> str:
    """The text drawn on the page in place of ``value``.

    Falls back to the bare token when nothing is revealed, and when the value
    has no more digits than the policy would show: revealing every digit is not
    redaction, and ``verify_scrubbed`` would refuse the document anyway.
    """
    if reveal <= 0:
        return token
    tail = digits_of(value)
    if len(tail) <= reveal:
        return token
    return f"{token}{SUFFIX_SEP}{tail[-reveal:]}"


def display_candidates(token: str, value: str) -> list[str]:
    """Every form ``token`` might wear on a page, longest first.

    Restore searches these in order rather than being told the job's policy. By
    then it holds the decrypted value, so it can reconstruct what was drawn, and
    a document mixing reveal counts across types still resolves.

    The ordering is load-bearing: matching a six-digit tail as a four-digit one
    would leave two digits stranded outside the removal box.
    """
    forms = [display(token, value, n) for n in range(MAX_REVEAL_DIGITS, 0, -1)]
    return list(dict.fromkeys([f for f in forms if f != token] + [token]))



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
