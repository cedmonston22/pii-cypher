"""Form identification and adaptive field location.

A field map describes *what to look for*, not *where it sits*. Fields are named by
distinctive label keywords; the geometry relating a label to its value is
discovered per document.

This matters because the geometry is not stable. Between the 2021 and 2025
Schedule K-1 the IRS reworded three of four labels, changed the apostrophe to a
typographic one, and inverted the indent -- 2021 puts values 30pt right of their
label, 2025 puts them flush and the numeric fields 1.8pt to the *left*. A map that
declares its offsets is valid for exactly one revision. A map that declares only
keywords covers the family.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any, TypedDict

from core.extract import Line

FORMS_DIR = Path(__file__).resolve().parent.parent / "forms"

# How far a value may sit from its label's left edge. A loose band, not an offset:
# it has to admit both the +30pt (2021) and the -1.8pt (2025) case.
DEFAULT_COL_TOL = 90.0

# Rules 2 and 3 bound a field in practice. This is a backstop against a
# pathological document, so a runaway box cannot redact half a page.
MAX_FIELD_LINES = 8

_PUNCT = re.compile(r"[^a-z0-9 ]")
_SPACES = re.compile(r"\s+")
# Typographic characters that PDF producers substitute for their ASCII forms.
_FOLD = str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"',
                       "–": "-", "—": "-", "�": "'"})


class Field(TypedDict):
    name: str
    pii_type: str
    value: str
    page: int
    bbox: tuple[float, float, float, float]
    fontname: str
    size: float


class UnknownForm(Exception):
    """Raised when no field map matches the document."""


class AnchorMismatch(Exception):
    """Raised when a map's labels are not all present.

    The map does not fit this document, so any values it located would be
    guesses. The caller must quarantine rather than continue.
    """


def normalize(text: str) -> str:
    """Fold text to a form that survives typography and rewording.

    NFKC, typographic characters folded to ASCII, punctuation stripped,
    whitespace collapsed, lowercased. Applied to both keywords and page text.

    Without this, a label set with a typographic apostrophe fails to match a
    keyword written with a straight one -- the 2025 K-1's "Partner's SSN or TIN"
    against "Partner's SSN or TIN" -- and nothing about the failure suggests
    punctuation is the cause.
    """
    folded = unicodedata.normalize("NFKC", text).translate(_FOLD)
    return _SPACES.sub(" ", _PUNCT.sub(" ", folded.lower())).strip()


def load_field_maps(forms_dir: Path | None = None) -> list[dict[str, Any]]:
    directory = forms_dir or FORMS_DIR
    maps = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]
    for field_map in maps:
        _validate(field_map)
    return maps


def _validate(field_map: dict[str, Any]) -> None:
    for key in ("form_id", "identify", "fields"):
        if key not in field_map:
            raise ValueError(f"field map missing {key!r}")
    if not field_map["identify"].get("all_of"):
        raise ValueError(f"{field_map['form_id']!r} has no identify.all_of markers")
    for field in field_map["fields"]:
        for key in ("name", "pii_type", "keywords"):
            if key not in field:
                raise ValueError(f"field {field.get('name')!r} missing {key!r}")
        if field.get("skip_lines", 0) < 0:
            raise ValueError(f"field {field['name']!r} has a negative skip_lines")


def identify(pages: list[list[Line]], field_maps: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the field map matching this document's form family.

    Markers identify the family, not the revision. There is deliberately no year
    check: the year was only ever a proxy for "a layout that was measured", and
    once the geometry is discovered per document the proxy has no job. What
    guards against an unfamiliar revision is verify_labels -- every field's
    keywords must still be found, or the document is quarantined.

    Raises:
        UnknownForm: if no map matches.
    """
    for field_map in field_maps:
        spec = field_map["identify"]
        pages_to_search = pages[: spec["page"]] if spec.get("page") else pages
        haystack = normalize(" ".join(ln["text"] for page in pages_to_search for ln in page))
        if all(normalize(marker) in haystack for marker in spec["all_of"]):
            return field_map
    raise UnknownForm("no field map matches this document")


def find_label(pages: list[list[Line]], keywords: str) -> Line | None:
    """Return the line whose text contains these keywords, once normalized."""
    needle = normalize(keywords)
    for lines in pages:
        for line in lines:
            if needle in normalize(line["text"]):
                return line
    return None


def _same_style(a: Line, b: Line) -> bool:
    return a["fontname"] == b["fontname"] and abs(a["size"] - b["size"]) < 0.3


def discover_field(
    pages: list[list[Line]], label: Line, col_tol: float = DEFAULT_COL_TOL
) -> list[Line]:
    """Return the lines belonging to a label's box, discovering the geometry.

    Three rules, and their order matters:

    1. Column -- only lines below the label and within ``col_tol`` of its left
       edge. This must be applied *first*. Filtering after the rule 2 check lets
       an unrelated line in another column, which happens to share the label's
       font size, end the scan immediately and return nothing.
    2. The next label closes the box -- a line sharing the label's own style.
    3. A style change closes the field -- values in one box share a font and
       size, so the first line that differs from the first value ends it.

    Rule 3 is what stops an address box swallowing the single stray character or
    the following section heading that sit just beyond it.
    """
    column = sorted(
        (
            line
            for line in pages[label["page"] - 1]
            if line["top"] > label["top"] + 1 and abs(line["x0"] - label["x0"]) <= col_tol
        ),
        key=lambda ln: ln["top"],
    )

    found: list[Line] = []
    style: Line | None = None

    for line in column:
        if _same_style(line, label):
            break
        if style is None:
            style = line
        elif not _same_style(line, style):
            break
        found.append(line)
        if len(found) >= MAX_FIELD_LINES:
            break

    return found


def verify_labels(pages: list[list[Line]], field_map: dict[str, Any]) -> None:
    """Confirm every field's keywords are present.

    Raises:
        AnchorMismatch: naming the keywords that were not found.
    """
    missing = [f["keywords"] for f in field_map["fields"] if find_label(pages, f["keywords"]) is None]
    if missing:
        raise AnchorMismatch(f"labels not found: {missing}")


# Retained under its v1 name so callers and tests reading as "anchors" still work.
verify_anchors = verify_labels


def locate(pages: list[list[Line]], field_map: dict[str, Any]) -> list[Field]:
    """Extract every described field's value and bounding box.

    Each line of a field becomes its own Field so it can be redacted
    independently.
    """
    col_tol = field_map.get("col_tol", DEFAULT_COL_TOL)
    fields: list[Field] = []

    for spec in field_map["fields"]:
        label = find_label(pages, spec["keywords"])
        if label is None:
            raise AnchorMismatch(f"label not found: {spec['keywords']!r}")

        # skip_lines drops leading lines of a box that are out of policy -- on a
        # K-1 the first line of an address box is the name.
        lines = discover_field(pages, label, col_tol)[spec.get("skip_lines", 0) :]
        if not lines:
            raise AnchorMismatch(
                f"field {spec['name']!r} has no value lines below its label "
                f"{spec['keywords']!r}"
            )

        for line in lines:
            fields.append(
                Field(
                    name=spec["name"],
                    pii_type=spec["pii_type"],
                    value=line["text"],
                    page=line["page"],
                    bbox=(line["x0"], line["top"], line["x1"], line["bottom"]),
                    fontname=line["fontname"],
                    size=line["size"],
                )
            )

    return fields


def propagate(pages: list[list[Line]], fields: list[Field]) -> list[Field]:
    """Add a Field for every other occurrence of an already-located value.

    Values repeat in footers and on continuation pages that the map does not
    describe. Located bboxes are skipped so a value is never redacted twice.
    """
    located = {(f["page"], round(f["bbox"][0], 1), round(f["bbox"][1], 1)) for f in fields}
    by_value = {f["value"]: f for f in fields}
    extra: list[Field] = []

    for lines in pages:
        for line in lines:
            source = by_value.get(line["text"])
            if source is None:
                continue
            key = (line["page"], round(line["x0"], 1), round(line["top"], 1))
            if key in located:
                continue
            located.add(key)
            extra.append(
                Field(
                    name=source["name"],
                    pii_type=source["pii_type"],
                    value=line["text"],
                    page=line["page"],
                    bbox=(line["x0"], line["top"], line["x1"], line["bottom"]),
                    fontname=line["fontname"],
                    size=line["size"],
                )
            )

    return fields + extra
