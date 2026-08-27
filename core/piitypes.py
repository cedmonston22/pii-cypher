"""The canonical PII type vocabulary.

One name per kind of identifier, uppercase, shared by field maps, policies and
the detection subsystem. It lives here rather than in ``detect/`` because
``core.fieldmap`` must be able to reject an unknown type at load time, and
``core`` importing ``detect`` would invert the layering.

Two vocabularies drifting apart is not a cosmetic problem in this codebase. A
policy whose types match nothing empties the field list, ``redact`` draws
nothing, and both release gates pass vacuously -- the batch is reported as
scrubbed while every document still carries its identifiers.
``core.pipeline.PolicyMismatch`` catches that at run time; ``canonical`` and
``PII_TYPES`` are what stop it arising in the first place.

The set is what a Schedule K-1 can carry, plus the two shapes the coverage
filter would otherwise swallow. EMAIL, ROUTING and BANK_ACCOUNT were here and
were removed: a K-1 has none of them, and a value of any of those shapes still
surfaces as unaccounted-for fill, so naming them bought nothing and carried a
checksum that could never run. A later form family that labels them can have
them back in three lines.

Names are deliberately absent. They are out of policy on a K-1 and stay on the
form; see ``skip_lines`` in ``forms/us-1065-k1.json``.
"""

from __future__ import annotations

from typing import Literal, get_args

PiiType = Literal[
    "SSN",
    "ITIN",
    "EIN",
    "ADDRESS",
    "PHONE",
    "DOB",
]

PII_TYPES: frozenset[str] = frozenset(get_args(PiiType))

# Field maps and policies written before the vocabulary was fixed. One-way and
# loader-only: nothing writes these names again. ``address_locality`` never was
# a valid policy type -- it existed only as a pattern key in the old audit --
# and is folded into ADDRESS here so the drift dies with the rename.
_LEGACY: dict[str, str] = {
    "ssn_tin": "SSN",
    "ein": "EIN",
    "address": "ADDRESS",
    "address_locality": "ADDRESS",
}


class UnknownPiiType(ValueError):
    """Raised for a type name in neither the vocabulary nor the legacy map."""


def canonical(pii_type: str) -> str:
    """Return the canonical name for a type, accepting legacy spellings.

    Raises:
        UnknownPiiType: naming the offender and the vocabulary it must be in.
    """
    if pii_type in PII_TYPES:
        return pii_type
    if pii_type in _LEGACY:
        return _LEGACY[pii_type]
    raise UnknownPiiType(f"{pii_type!r} is not a PII type; expected one of {sorted(PII_TYPES)}")
