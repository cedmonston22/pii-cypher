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

__all__ = ["DEFAULT_TYPES", "FLOOR", "Policy", "resolve", "auto_release"]


class Policy(TypedDict, total=False):
    pii_types: list[str]
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
