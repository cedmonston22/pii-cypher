"""PII detection: what the field map did not account for.

``verify_labels`` can only ask whether the labels a map names are on the page.
It iterates the map, so it can never ask the question that matters -- whether
the page carries a field the map omits. This package asks that one.

Detection runs *beside* location, never instead of it. Nothing found here is
redacted: ``core.fieldmap.locate`` alone decides what gets replaced, and these
candidates exist to say "you may have missed something". That constraint is
what lets a candidate carry the whole line's bounding box, and it is why a
detector being wrong costs a spurious warning rather than a corrupted document.

Two layers, complementary rather than redundant:

- ``coverage`` recognises filled-in text the map does not account for, without
  inspecting content. It cannot see digit-shaped values, because no filter that
  removes ``125,000`` can keep ``000-00-0000``.
- ``patterns`` recognises structured identifiers by shape wherever they sit,
  including the case where a revision moves every identifier out of the map at
  once and the coverage check has no fill style left to learn from.

Failure is closed. A detector that raises turns into a low-confidence marker,
so a crash surfaces as something to review rather than as a clean document.
"""

from __future__ import annotations

from typing import Any

from core.extract import Line
from core.fieldmap import Field

from detect import coverage, labels, patterns
from detect.adapter import Geometry, geometry, items
from detect.merge import merge
from detect.policy import in_scope, resolve
from detect.types import Candidate, Item

__all__ = ["Candidate", "CoverageGap", "Item", "Report", "detect"]


class CoverageGap(Exception):
    """PII the field map did not claim, at a confidence worth stopping for.

    The message names type, page and box and never the value. It is written
    verbatim into ``documents.reason``, which is plaintext while the filename
    beside it is encrypted, so a value in this message is PII at rest in the
    clear.
    """


class Report:
    """Everything detection found, and the subset the map did not explain."""

    __slots__ = ("candidates", "unclaimed")

    def __init__(self, candidates: list[Candidate], unclaimed: list[Candidate]) -> None:
        self.candidates = tuple(candidates)
        self.unclaimed = tuple(unclaimed)

    @property
    def warnings(self) -> list[str]:
        """Display strings, drop-in for the audit this replaces.

        These carry values, because the whole point of a coverage warning is to
        tell an operator what was missed. They are shown and never stored; see
        ``Candidate.masked`` for anything durable.
        """
        return [str(c) for c in self.unclaimed]

    def gaps(self, minimum: str = "high") -> list[Candidate]:
        order = {"low": 0, "medium": 1, "high": 2}
        return [c for c in self.unclaimed if order[c.confidence] >= order[minimum]]


def _safely(name: str, run, page_hint: int = 1) -> list[Candidate]:
    """Run one detector, converting a crash into something reviewable."""
    try:
        return run()
    except Exception as exc:  # noqa: BLE001 -- deliberately broad; see below
        # The type of failure matters less than the fact of it. A detector that
        # dies must not leave the document looking clean, and the exception must
        # not carry a value into a log or a traceback.
        return [
            Candidate(
                value="",
                pii_type=None,
                page=page_hint,
                bbox=(0.0, 0.0, 0.0, 0.0),
                evidence=(f"detector-failed:{name}:{type(exc).__name__}",),
                confidence="low",
            )
        ]


def detect(
    pages: list[list[Line]],
    *,
    field_map: dict[str, Any],
    located: list[Field],
    policy: dict[str, Any] | None = None,
) -> Report:
    """Find PII the field map did not account for.

    ``field_map`` and ``located`` are required and keyword-only. The coverage
    check learns this document's filled-in style from what ``locate`` claimed,
    so a call without them would quietly degrade to patterns alone -- which is
    exactly the failure mode of the audit this replaces.
    """
    types = resolve(policy)
    scannable = items(pages)
    geo = geometry(pages, field_map, located)

    groups = [
        _safely("patterns", lambda: patterns.scan(scannable)),
        _safely("coverage", lambda: coverage.unclaimed(scannable, geo)),
        _safely("labels", lambda: labels.label_only(scannable, pages, geo)),
    ]

    candidates = [
        c for c in merge(groups, scannable, pages, geo) if in_scope(c.pii_type, types)
    ]

    claimed = {f["value"].strip() for f in located}
    unclaimed = [
        c
        for c in candidates
        if c.value.strip() not in claimed
        and not any(c.value.strip() and c.value.strip() in v for v in claimed)
    ]

    return Report(candidates, unclaimed)
