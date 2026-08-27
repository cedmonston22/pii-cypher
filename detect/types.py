"""The shapes detection passes around.

``Item`` is what a detector scans; ``Candidate`` is what it reports. Neither is
ever handed to ``core.redact`` -- location stays label-driven, and detection
only ever produces warnings. That is the constraint which lets a Candidate
carry the whole line's bounding box: nothing downstream will try to remove
glyphs with it, so a fabricated sub-line box would be a lie with no purpose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, TypedDict

from core.piitypes import PII_TYPES, PiiType

__all__ = ["Candidate", "Confidence", "Item", "PII_TYPES", "PiiType", "dense"]

Confidence = Literal["high", "medium", "low"]

_WHITESPACE = re.compile(r"\s+")


def dense(text: str) -> str:
    """Whitespace stripped entirely, for matching values a PDF split apart."""
    return _WHITESPACE.sub("", text)


class Item(TypedDict):
    """One scannable run of text, with the three surfaces detectors match on.

    ``text`` is what the page says, ``norm`` is folded for label comparison,
    and ``dense`` catches an identifier a PDF rendered as ``512 44 8890``.
    Carrying all three costs a few bytes and removes a whole class of bug where
    one detector normalises and the next does not.

    ``fontname`` and ``size`` are carried beyond what the spec's Item needs,
    because the structural coverage check learns this document's fill style
    from them and cannot work without them.
    """

    text: str
    norm: str
    dense: str
    page: int
    bbox: tuple[float, float, float, float]
    source: str
    fontname: str
    size: float


@dataclass(frozen=True, slots=True)
class Candidate:
    """PII-shaped text, with why it is believed and how strongly.

    Frozen and hashable so merging can dedupe with a set, which is why
    ``evidence`` is a tuple rather than the list the specification asks for.

    ``pii_type`` is None for a structural finding: the coverage check can say
    there is unaccounted-for data here without being able to say what it is.
    """

    value: str
    pii_type: PiiType | None
    page: int
    bbox: tuple[float, float, float, float]
    evidence: tuple[str, ...]
    confidence: Confidence

    def __str__(self) -> str:
        """For display. Carries the value -- never persist this."""
        return f"{self.pii_type or 'UNTYPED'} on page {self.page}: {self.value!r}"

    def masked(self) -> str:
        """Value-free, for anything durable.

        ``documents.reason`` is plaintext while filenames beside it are
        encrypted, so an exception message that reaches quarantine must not
        carry a value or it puts PII at rest in the clear.
        """
        x0, top, _, _ = self.bbox
        return f"{self.pii_type or 'UNTYPED'} on page {self.page} at ({x0:.1f}, {top:.1f})"
