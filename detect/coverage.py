"""Structural coverage: filled-in data the field map does not account for.

``verify_labels`` asks whether every label the map names is on the page. It
cannot ask the question that matters -- whether the page carries a field the
map omits -- because it iterates the map, not the document.

This does ask that, without inspecting content. Filled-in text is
stylistically distinct from the form template, so a value the map has not
claimed can be recognised as *data* even when nothing about its shape says
what kind of data it is.

The style class is learned per document from what ``locate`` claimed, never
hardcoded. The two shipped fixtures share no fill style at all -- the 2021
revision fills in Helvetica-Bold 9/10pt against a 7.2-8pt template, the 2025
revision in base-14 Helvetica 8pt against subset-embedded template faces -- so
any fixed rule fits one and fails the other.

What this cannot see: anything the amount filter removes, which includes every
digit-shaped identifier. That is not a tuning failure, it is the filter's
nature -- ``000-00-0000`` and ``125,000`` are both digits and punctuation.
``detect.patterns`` owns those, and the two layers are complementary rather
than redundant. Neither alone is a coverage check.
"""

from __future__ import annotations

import re

from detect.adapter import Geometry
from detect.types import Candidate, Item

__all__ = ["amountish", "unclaimed"]

# Currency, percentages, ownership shares and accounting parentheses: the
# furniture a tax form is mostly made of.
#
# The obvious broad version, ^[$()\d ,.%/-]+$, also matches 000-00-0000 and
# 45-1234567. Using it makes every stale-map test pass for the wrong reason --
# not because the map is complete but because no identifier can ever be
# reported. Requiring a decimal, a separator or a percent is what keeps bare
# hyphenated identifiers out of it.
_AMOUNT = re.compile(
    r"""^\(?\$?\s*
        \d{1,3}(,\d{3})+(\.\d+)?      # thousands-grouped
      | ^\(?\$?\s*\d+\.\d+            # decimal
      | ^\(?\$?\s*\d+\s*%             # percentage
    """,
    re.VERBOSE,
)
_TRAILING = re.compile(r"[\s)%]*$")
_DATE = re.compile(r"^\d{1,4}([ /.-]\d{1,4}){1,5}$")
_IDENTIFIER = re.compile(r"^\d{2,3}-\d{2}-?\d{4,7}$")


def amountish(text: str) -> bool:
    """Whether a line is form furniture rather than a filled-in value.

    An identifier is never furniture, however digit-heavy it looks. That
    exemption is load-bearing: without it this function eats every SSN and EIN
    on the page and the coverage check reports a clean document forever.
    """
    stripped = text.strip()
    if not stripped:
        return True
    if _IDENTIFIER.match(stripped):
        return False
    return bool(_AMOUNT.match(stripped)) or bool(_DATE.match(stripped))


def unclaimed(items: list[Item], geo: Geometry) -> list[Candidate]:
    """Fill-styled text in a label column that the map does not account for.

    Emits untyped, low-confidence candidates. A style match says *there is data
    here*, never *this is an SSN* -- claiming otherwise would be exactly the
    self-reported confidence that makes a detector untrustworthy, and under a
    quarantine gate it would reject clean documents.
    """
    out: list[Candidate] = []
    seen: set[tuple[int, str]] = set()

    for item in items:
        if item["source"] == "joined":
            continue  # a join duplicates lines that are already scanned
        if not geo.is_fill(item):
            continue
        if not geo.in_label_column(item):
            continue
        if geo.accounted_for(item):
            continue
        if amountish(item["text"]):
            continue

        key = (item["page"], item["text"])
        if key in seen:
            continue
        seen.add(key)

        out.append(
            Candidate(
                value=item["text"],
                pii_type=None,
                page=item["page"],
                bbox=item["bbox"],
                evidence=("style:unclaimed-fill",),
                confidence="low",
            )
        )

    return out
