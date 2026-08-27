"""Structured identifiers, by shape and then by validator.

Deterministic and content-based, which makes this the exact complement of the
structural coverage check: that layer sees any unaccounted-for fill except
digit-shaped values, and this layer sees digit-shaped values wherever they sit.
Together they cover the case neither manages alone -- a form revision that
moves every identifier out of the map at once, where the coverage check has no
fill style left to recognise.

The patterns from the audit this replaces are carried forward rather than
rewritten. They were precision-clean against 38 distractors drawn from tax-form
furniture, and that property is worth more than breadth: a noisy audit is one
people learn to ignore. Two deliberate widenings, both documented misses of the
old patterns: locality lines match case-insensitively, and street lines admit
the forms with no house number.

Validation never widens recall -- every validated type is matched by shape
first. It only decides whether a candidate is worth acting on.

PHONE and DOB are not fields a Schedule K-1 carries. They are here because
coverage.amountish discards phone- and date-shaped text as form furniture, so
these patterns are the only thing standing between such a value and silence.
EMAIL, ROUTING and BANK_ACCOUNT were removed for the opposite reason: the
filter keeps their shapes, so they still surface as unaccounted-for fill
without a pattern naming them.
"""

from __future__ import annotations

import re
from datetime import date, datetime

from core.tokens import TOKEN_RE

from detect.types import Candidate, Item, PiiType

__all__ = ["EIN_PREFIXES", "LABEL_ONLY", "LINE_PATTERNS", "excluded", "scan", "valid"]

# Whole item must be the value.
LINE_PATTERNS: dict[str, re.Pattern[str]] = {
    "SSN": re.compile(r"^(?!9)\d{3}[- ]?\d{2}[- ]?\d{4}$"),
    "ITIN": re.compile(r"^9\d{2}[- ]?\d{2}[- ]?\d{4}$"),
    "EIN": re.compile(r"^\d{2}[- ]?\d{7}$"),
    # Street lines. Two alternatives, because neither alone is both precise and
    # case-blind.
    #
    # The naive "number, space, anything" rejects nothing on a tax form: a K-1
    # is built out of numbered line items, so it matches "1 Ordinary business
    # income (loss)" and "15 Foreign transactions" as readily as a street. It
    # produced 5 of 7 false positives against the distractor set.
    #
    # So: either the line ends in a street-type token, which admits lowercase
    # safely, or it satisfies the previous audit's all-caps shape, which is
    # what still catches a foreign street name like 12 RUE DE RIVOLI that ends
    # in no token this list knows.
    "ADDRESS": re.compile(
        r"""^(?:
              \d+[A-Za-z]?\s+[\w .'#-]*?\s*
                (?:AVE|AVENUE|ST|STREET|RD|ROAD|LN|LANE|BLVD|BOULEVARD|DR
                  |DRIVE|CT|COURT|PL|PLACE|PLAZA|WAY|TER|TERRACE|PKWY
                  |PARKWAY|HWY|HIGHWAY|CIR|CIRCLE|SQ|SQUARE|TRL|TRAIL|LOOP)
                \.?(?:\s+(?:N|S|E|W|NE|NW|SE|SW))?
            | P\.?\s?O\.?\s+BOX\s+\d+
            | (?:ONE|TWO|THREE)\s+[A-Za-z][\w .'#-]*
            | (?:APT|STE|SUITE|UNIT|FLOOR|RM|ROOM)\.?\s*\#?\s*\S+
            )$""",
        re.IGNORECASE | re.VERBOSE,
    ),
    # The all-caps shape carried over verbatim from the audit this replaces.
    # Requiring three consecutive capitals is what rejects "01 01 2025" and
    # "25 12 31 25" while admitting a street name in any language.
    "ADDRESS_CAPS": re.compile(r"^\d+[A-Z]?\s+(?=.*[A-Z]{3})[A-Z0-9 .'#-]+$"),
    # City, ST ZIP. Case-insensitive, which the previous audit was not, and
    # which is why it missed every lowercase city line.
    "ADDRESS_LOCALITY": re.compile(
        r"^[A-Za-z .’'-]+,\s*[A-Za-z]{2}\s+\d{5}(-\d{4})?$"
    ),
    "PHONE": re.compile(r"^(\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?[2-9]\d{2}[-. ]?\d{4}$"),
    "DOB": re.compile(r"^(\d{1,2}[/-]\d{1,2}[/-]\d{4}|\d{4}-\d{2}-\d{2})$"),
}

# Distinctive enough to find inside a longer line without false alarms.
EMBEDDED_PATTERNS: dict[str, re.Pattern[str]] = {
    "SSN": re.compile(r"(?<!\d)(?!9)\d{3}-\d{2}-\d{4}(?!\d)"),
    "ITIN": re.compile(r"(?<!\d)9\d{2}-\d{2}-\d{4}(?!\d)"),
    "EIN": re.compile(r"(?<!\d)\d{2}-\d{7}(?!\d)"),
}

# A tax form is full of dates, and 12/31/2021 is a period end rather than a
# birthday. Nothing about the digits tells the two apart, so DOB fires only
# where a label says what it is; see detect.labels. Emitting it on shape alone
# is how a review queue becomes something nobody reads.
#
# DOB is here for a reason that is easy to undo by accident: coverage.amountish
# discards date-shaped text as form furniture, so if this pattern goes, nothing
# catches a birthday at all. See the coupling test in test_detect_patterns.
LABEL_ONLY: frozenset[str] = frozenset({"DOB"})

# Toll-free ranges are never a person's number. The IRS help line is printed on
# the form itself, so without this every K-1 reports 800-829-1040 as PII.
_TOLL_FREE = frozenset({"800", "833", "844", "855", "866", "877", "888"})

# Campus and internet prefixes the IRS has issued. A prefix outside this set is
# not an EIN, whatever its shape.
EIN_PREFIXES: frozenset[str] = frozenset(
    """01 02 03 04 05 06 10 11 12 13 14 15 16 20 21 22 23 24 25 26 27 30 31 32
    33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 50 51 52 53 54 55 56 57 58
    59 60 61 62 63 64 65 66 67 68 71 72 73 74 75 76 77 80 81 82 83 84 85 86 87
    88 90 91 92 93 94 95 98 99""".split()
)

# ITIN group ranges the IRS has assigned.
_ITIN_GROUPS = ((50, 65), (70, 88), (90, 92), (94, 99))

_NON_DIGIT = re.compile(r"\D")


def _digits(text: str) -> str:
    return _NON_DIGIT.sub("", text)


def _valid_ssn(text: str) -> bool:
    digits = _digits(text)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return (
        area not in {"000", "666"}
        and area[0] != "9"
        and group != "00"
        and serial != "0000"
    )


def _valid_itin(text: str) -> bool:
    digits = _digits(text)
    if len(digits) != 9 or digits[0] != "9":
        return False
    group = int(digits[3:5])
    return any(low <= group <= high for low, high in _ITIN_GROUPS)


def _valid_ein(text: str) -> bool:
    digits = _digits(text)
    return len(digits) == 9 and digits[:2] in EIN_PREFIXES


def _is_toll_free(text: str) -> bool:
    digits = _digits(text)
    if len(digits) == 11 and digits[0] == "1":
        digits = digits[1:]
    return len(digits) == 10 and digits[:3] in _TOLL_FREE


def _valid_dob(text: str) -> bool:
    for fmt in ("%m/%d/%Y", "%m-%d-%Y", "%Y-%m-%d"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return 1900 <= parsed.year <= date.today().year
    return False


VALIDATORS = {
    "SSN": _valid_ssn,
    "ITIN": _valid_itin,
    "EIN": _valid_ein,
    "DOB": _valid_dob,
}

# Exclusions are not validators, and conflating them costs precision in one
# direction or recall in the other. A validator asks "is this a well-formed
# instance of the type?" and a shape that fails still gets reported, at low
# confidence -- 000-00-0000 is not an issued SSN but it is worth flagging.
# An exclusion asks "can this be this type at all?" and the answer is no: a
# toll-free number is nobody's personal number, so reporting it is pure noise.
EXCLUSIONS = {
    "PHONE": _is_toll_free,
}


def excluded(pii_type: str, value: str) -> bool:
    """Whether a shape match is categorically not this type."""
    rule = EXCLUSIONS.get(pii_type)
    return bool(rule and rule(value))


def valid(pii_type: str, value: str) -> bool | None:
    """True or False where a validator exists, None where none does."""
    validator = VALIDATORS.get(pii_type)
    return None if validator is None else bool(validator(value))


def _canonical(pii_type: str) -> PiiType:
    # ADDRESS_LOCALITY is a pattern name, not a vocabulary entry. Keeping the
    # two separate is what the old audit failed to do, and its stray
    # address_locality key would have matched no policy had anyone used it.
    if pii_type in ("ADDRESS_LOCALITY", "ADDRESS_CAPS"):
        return "ADDRESS"
    return pii_type  # type: ignore[return-value]


def _grade(pii_type: str, value: str, item: Item) -> tuple[tuple[str, ...], str]:
    """Grade a shape match. Validation decides confidence, never survival.

    A validator that suppresses is a validator that hides things. Both shipped
    fixtures use placeholder identifiers -- SSN area 000, EIN prefix 00, neither
    of which the IRS issues -- so dropping shape matches that fail validation
    made the audit silent on the two most obviously SSN-shaped strings in the
    repository. For a layer that only ever warns, "looks like an SSN but is not
    a valid one" is worth saying out loud at low confidence.

    It matters in the other direction too: a quarantine gate keyed on high
    confidence must never fire on one of these, and grading rather than
    dropping is what keeps that true.
    """
    verdict = valid(pii_type, value)
    evidence = [f"pattern:{pii_type}"]
    if verdict is True:
        evidence.append(f"validator:{pii_type}")
    elif verdict is False:
        evidence.append(f"validator:{pii_type}:failed")
    if item["source"] == "joined":
        evidence.append("joined:adjacent-spans")
    return tuple(evidence), ("medium" if verdict is True else "low")


def scan(items: list[Item]) -> list[Candidate]:
    """Every structured identifier the patterns recognise, typed and graded.

    Tokens this tool minted are excluded explicitly. Without that, a scrubbed
    document run through detection a second time reports every one of its own
    tokens as PII and the audit never goes quiet again.
    """
    out: list[Candidate] = []

    for item in items:
        surfaces = [item["text"].strip()]
        if item["dense"] != surfaces[0]:
            surfaces.append(item["dense"])

        for surface in surfaces:
            if not surface or TOKEN_RE.search(surface):
                continue
            for pii_type, pattern in LINE_PATTERNS.items():
                if pii_type in LABEL_ONLY or not pattern.match(surface):
                    continue
                if excluded(pii_type, surface):
                    continue
                evidence, confidence = _grade(pii_type, surface, item)
                out.append(
                    Candidate(
                        value=surface,
                        pii_type=_canonical(pii_type),
                        page=item["page"],
                        bbox=item["bbox"],
                        evidence=evidence,
                        confidence=confidence,  # type: ignore[arg-type]
                    )
                )

        text = item["text"].strip()
        for pii_type, pattern in EMBEDDED_PATTERNS.items():
            for match in pattern.finditer(text):
                found = match.group(0)
                if found == text or TOKEN_RE.search(found):
                    continue
                if excluded(pii_type, found):
                    continue
                evidence, _ = _grade(pii_type, found, item)
                out.append(
                    Candidate(
                        value=found,
                        pii_type=_canonical(pii_type),
                        page=item["page"],
                        bbox=item["bbox"],
                        evidence=evidence + ("embedded",),
                        confidence="low",
                    )
                )

    return out
