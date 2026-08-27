"""Label association: what the page says a value is.

Two jobs, both of which depend on finding the label that governs a given item.

The first is corroboration. A nine-digit number under "Partner's SSN or TIN" is
a different candidate from one floating in a table, and that agreement between
two independent signals is what earns a candidate high confidence. Label
association never mints a candidate on its own.

The second is gating. ROUTING, BANK_ACCOUNT and DOB have no shape that
distinguishes them from tax-form furniture -- a nine-digit run is equally an
unhyphenated SSN or an invoice reference, and a tax form is full of dates. For
those types the label is not corroboration, it is the whole basis, so they are
minted here rather than in ``detect.patterns``.

Position is always relative. Absolute coordinates are a template in disguise:
between the 2021 and 2025 Schedule K-1 the IRS inverted the label-to-value
indent, so anything keyed to a coordinate fits one revision and extracts
nothing from the other.
"""

from __future__ import annotations

from core.extract import Line
from core.fieldmap import normalize

from detect.adapter import Geometry
from detect.patterns import LABEL_ONLY, LINE_PATTERNS, excluded, valid
from detect.types import Candidate, Item, PiiType

__all__ = ["SENSITIVE_LABELS", "governing_label", "label_suggests", "label_only"]

# Normalised fragments that name a type. Matched as substrings of a normalised
# label, so a reworded label still matches: the IRS appended a sentence to
# "SSN or TIN" between revisions and the fragment survived it.
SENSITIVE_LABELS: dict[str, tuple[str, ...]] = {
    "SSN": ("ssn", "social security", "ssn or tin", "taxpayer identification number"),
    "ITIN": ("itin", "individual taxpayer identification"),
    "EIN": ("ein", "employer identification number"),
    "ADDRESS": ("address", "city state and zip", "street", "zip code"),
    "ROUTING": ("routing", "aba", "rtn"),
    "BANK_ACCOUNT": ("account number", "bank account", "deposit account"),
    "DOB": ("date of birth", "birth date", "dob"),
    "EMAIL": ("email", "e mail"),
    "PHONE": ("phone", "telephone"),
}


def governing_label(item: Item, pages: list[list[Line]], geo: Geometry) -> str | None:
    """The normalised text of the label above this item, if there is one.

    The nearest line above, in the same column band, that is not itself
    filled-in text. Excluding fill styles is what stops one value being read as
    the label of the value beneath it -- on a K-1 the address lines sit
    directly under the partner name, and without the style test the name would
    be treated as a label.
    """
    x0, top = item["bbox"][0], item["bbox"][1]
    best: Line | None = None

    for line in pages[item["page"] - 1]:
        if line["top"] >= top - 0.5:
            continue
        if abs(line["x0"] - x0) > geo.col_tol:
            continue
        if (line["fontname"], round(line["size"], 1)) in geo.fill_styles:
            continue
        if best is None or line["top"] > best["top"]:
            best = line

    return None if best is None else normalize(best["text"])


def label_suggests(label: str | None, pii_type: str) -> bool:
    """Whether a label names this type.

    Both sides are normalised. Form labels carry multiple spaces, line wraps
    and typographic apostrophes; extraction collapses them differently. Raw
    comparison fails on nearly every anchor, and the failure looks exactly like
    the label simply not being present.
    """
    if label is None:
        return False
    return any(fragment in label for fragment in SENSITIVE_LABELS.get(pii_type, ()))


def label_only(items: list[Item], pages: list[list[Line]], geo: Geometry) -> list[Candidate]:
    """Mint the types that a shape alone cannot justify.

    Confidence is capped at medium even with a matching label and a passing
    checksum. BANK_ACCOUNT has no checksum at all, and a routing number under a
    label is still a routing number the document may simply be quoting.
    """
    out: list[Candidate] = []

    for item in items:
        surface = item["text"].strip()
        if not surface:
            continue

        for pii_type in LABEL_ONLY:
            if not LINE_PATTERNS[pii_type].match(surface):
                continue
            if excluded(pii_type, surface):
                continue
            label = governing_label(item, pages, geo)
            if not label_suggests(label, pii_type):
                continue

            evidence = [f"pattern:{pii_type}", f"label:{label}"]
            verdict = valid(pii_type, surface)
            if verdict is True:
                evidence.append(f"validator:{pii_type}")
            elif verdict is False:
                evidence.append(f"validator:{pii_type}:failed")

            out.append(
                Candidate(
                    value=surface,
                    pii_type=pii_type,  # type: ignore[arg-type]
                    page=item["page"],
                    bbox=item["bbox"],
                    evidence=tuple(evidence),
                    confidence="medium" if verdict is not False else "low",
                )
            )

    return out


def corroborate(
    candidate: Candidate, pages: list[list[Line]], geo: Geometry, item_by_box: dict
) -> Candidate:
    """Attach label evidence to a candidate, promoting it if the label agrees."""
    item = item_by_box.get((candidate.page, candidate.bbox))
    if item is None or candidate.pii_type is None:
        return candidate

    label = governing_label(item, pages, geo)
    if not label_suggests(label, candidate.pii_type):
        return candidate

    evidence = candidate.evidence + (f"label:{label}",)
    validated = any(e.startswith("validator:") and not e.endswith(":failed") for e in evidence)
    confidence: PiiType = "high" if validated else "medium"  # type: ignore[assignment]
    return Candidate(
        value=candidate.value,
        pii_type=candidate.pii_type,
        page=candidate.page,
        bbox=candidate.bbox,
        evidence=evidence,
        confidence=confidence,  # type: ignore[arg-type]
    )
