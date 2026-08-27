"""Which types are in scope, and what each needs to clear.

Two things are deliberate. The default is firm-level rather than a set of blank
checkboxes per job, because someone in a hurry clicks through whatever is in
front of them and the default is what actually governs behaviour. And SSN and
ITIN cannot be switched off: they carry real regulatory weight, and making them
non-optional costs nothing anyone would miss.

Confidence thresholds are not set here from first principles. They are meant to
be re-derived from measured precision on the evaluation corpus whenever a
detector changes, and until that corpus exists the only honest setting is the
one that releases nothing automatically.
"""

from __future__ import annotations

from typing import Any, TypedDict

from core.piitypes import PII_TYPES, canonical
from core.tokens import MAX_REVEAL_DIGITS

__all__ = [
    "DEFAULT_TYPES",
    "FLOOR",
    "Policy",
    "resolve",
    "resolve_reveal",
    "auto_release",
]


class Policy(TypedDict, total=False):
    pii_types: list[str]
    reveal_digits: dict[str, int]
    thresholds: dict[str, str]
    auto_release_types: list[str]
    quarantine_on_gap: bool


# Detected whatever the policy says. Not negotiable.
FLOOR: frozenset[str] = frozenset({"SSN", "ITIN"})

# What a firm gets without choosing anything. Matches what the tool has always
# redacted on a K-1, plus ITIN, which the old lowercase vocabulary could not
# express separately from SSN.
DEFAULT_TYPES: frozenset[str] = frozenset({"SSN", "ITIN", "EIN", "ADDRESS"})


def resolve(policy: dict[str, Any] | None) -> frozenset[str]:
    """The types to detect: what was asked for, plus the floor.

    Legacy spellings are accepted for the same reason the field-map loader
    accepts them -- a policy stored on an older job is read back for display --
    but an unrecognised name raises rather than silently matching nothing.

    Raises:
        UnknownPiiType
    """
    if policy is None or "pii_types" not in policy:
        return DEFAULT_TYPES | FLOOR
    chosen = {canonical(name) for name in policy["pii_types"]}
    return frozenset(chosen | FLOOR)


def resolve_reveal(policy: dict[str, Any] | None) -> dict[str, int]:
    """How many trailing digits each type may show on the page.

    A type absent from the mapping, or set to zero, reveals nothing -- which is
    what every job written before this setting existed did, so an old policy
    read back means the same thing it always did.

    Raises:
        UnknownPiiType: for a name outside the vocabulary.
        ValueError: for a count outside the range. Refused rather than clamped:
            quietly showing four digits when six were configured is exactly the
            gap between stated and actual policy this module exists to close.
    """
    if policy is None:
        return {}
    resolved: dict[str, int] = {}
    for name, count in (policy.get("reveal_digits") or {}).items():
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError(f"reveal_digits[{name!r}] must be an integer, got {count!r}")
        if not 0 <= count <= MAX_REVEAL_DIGITS:
            raise ValueError(
                f"reveal_digits[{name!r}] is {count}; the range is 0 to {MAX_REVEAL_DIGITS}"
            )
        if count:
            resolved[canonical(name)] = count
    return resolved


def auto_release(policy: dict[str, Any] | None) -> frozenset[str]:
    """Types allowed to clear review without a person looking.

    Empty by default. A tier only means something once it has been measured
    against a corpus, and asserting a threshold before then is the detector
    grading its own work.
    """
    if policy is None:
        return frozenset()
    return frozenset(canonical(name) for name in policy.get("auto_release_types", ()))


def in_scope(pii_type: str | None, types: frozenset[str]) -> bool:
    """Untyped structural findings are always in scope.

    The coverage check cannot say what it found, so filtering it by type would
    discard exactly the finding that matters most: data the map does not
    describe, of a kind nobody thought to configure.
    """
    return pii_type is None or pii_type in types


assert FLOOR <= PII_TYPES
assert DEFAULT_TYPES <= PII_TYPES
