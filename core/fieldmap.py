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
from typing import Any, NamedTuple, TypedDict

from core.extract import Line
from core.piitypes import canonical

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


class Instance(NamedTuple):
    """One filled copy of the form within a file.

    A firm exporting thirty K-1s as a single PDF is a likely real shape, and
    every label lookup has to be scoped to one of these. Document-wide,
    ``find_label`` returns partner 1's line for all thirty.
    """

    index: int
    pages: frozenset[int]

    def describe(self) -> str:
        """For an error message. Named by ordinal and page span, never by value."""
        lo, hi = min(self.pages), max(self.pages)
        span = f"page {lo}" if lo == hi else f"pages {lo}-{hi}"
        return f"instance {self.index} ({span})"


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
    """Load and validate every field map, canonicalising its type names.

    Canonicalisation happens here because this is the only boundary a legacy
    spelling can cross -- a map written before the vocabulary was fixed, or one
    supplied by a third party. Translating anywhere further in would leave two
    vocabularies alive inside ``core`` with a conversion at every comparison.
    """
    directory = forms_dir or FORMS_DIR
    maps = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]
    for field_map in maps:
        _validate(field_map)
        for field in field_map["fields"]:
            field["pii_type"] = canonical(field["pii_type"])
    return maps


def _validate(field_map: dict[str, Any]) -> None:
    for key in ("form_id", "identify", "fields"):
        if key not in field_map:
            raise ValueError(f"field map missing {key!r}")
    if not field_map["identify"].get("all_of"):
        raise ValueError(f"{field_map['form_id']!r} has no identify.all_of markers")
    # Labels whose boxes are known not to carry PII -- the IRS service centre on
    # a K-1 is filled-in text, in the label column, that no field claims. It is
    # deliberately NOT checked by verify_labels: a missing ignore label costs
    # one box of suppression, while a missing *field* label is a quarantine.
    if not isinstance(field_map.get("ignore", []), list):
        raise ValueError(f"{field_map['form_id']!r} has a non-list ignore")
    for keywords in field_map.get("ignore", []):
        if not isinstance(keywords, str) or not keywords.strip():
            raise ValueError(f"{field_map['form_id']!r} has an empty ignore entry")
    # Optional. Absent means the file holds one instance of the form, which is
    # what every map meant before segmentation existed. Present and empty is a
    # typo that would silently mean the same thing, so refuse it.
    anchor = field_map.get("instance_anchor")
    if anchor is not None and (not isinstance(anchor, str) or not anchor.strip()):
        raise ValueError(f"{field_map['form_id']!r} has an empty instance_anchor")
    for field in field_map["fields"]:
        for key in ("name", "pii_type", "keywords"):
            if key not in field:
                raise ValueError(f"field {field.get('name')!r} missing {key!r}")
        if field.get("skip_lines", 0) < 0:
            raise ValueError(f"field {field['name']!r} has a negative skip_lines")
        # An unrecognised type is silent damage: it matches no policy, so the
        # field is filtered out and the document is returned unredacted with
        # every release gate satisfied. Refuse the map instead.
        canonical(field["pii_type"])


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


def find_labels(
    pages: list[list[Line]], keywords: str, within: frozenset[int] | None = None
) -> list[Line]:
    """Every line whose text contains these keywords, in document order.

    ``within`` restricts the search to one instance's page numbers. That is not
    an optimisation: on a packet the same label appears once per partner, and
    the only thing separating partner 3's field E from partner 1's is which
    pages the caller is willing to look at.
    """
    needle = normalize(keywords)
    return [
        line
        for lines in pages
        for line in lines
        if (within is None or line["page"] in within)
        and needle in normalize(line["text"])
    ]


def find_label(
    pages: list[list[Line]], keywords: str, within: frozenset[int] | None = None
) -> Line | None:
    """Return the first line whose text contains these keywords, once normalized.

    First match, and it stays first match after segmentation. Keywords are not
    unique within one form: on both K-1 revisions "name address city state and
    zip code" matches field B *and* field F, so a map naming that keyword relies
    on B coming first. Taking every occurrence instead would locate F twice, the
    second time mislabelled as the partnership's address -- a worse bug than the
    one multi-instance support exists to fix.
    """
    return next(iter(find_labels(pages, keywords, within)), None)


def segment(pages: list[list[Line]], field_map: dict[str, Any]) -> list[Instance]:
    """Split a file into the form instances it contains.

    A map declares ``instance_anchor``: a keyword occurring exactly once per
    filled copy of the form. On the K-1 that is "ssn or tin" -- field E. Most
    keywords will not do. "name address city state and zip code" matches twice
    per form, and the identify markers match two or three times on a single
    page, so neither can delimit anything.

    Without an anchor, or with fewer than two occurrences of one, the whole file
    is one instance. That is the behaviour that predates segmentation exactly,
    so a one-page document, a single K-1 spanning twenty pages, and any form
    family whose map declares no anchor are all unaffected.

    Boundaries are page-granular. A K-1 is a full-page form, so two instances
    sharing a physical page is not the real shape; detection still reports the
    second copy as a coverage gap if it ever occurs.
    """
    every = frozenset(range(1, len(pages) + 1))
    anchor = field_map.get("instance_anchor")
    starts = sorted({ln["page"] for ln in find_labels(pages, anchor)}) if anchor else []

    if len(starts) < 2:
        return [Instance(index=1, pages=every)]

    bounds = starts + [len(pages) + 1]
    instances = [
        Instance(index=i + 1, pages=frozenset(range(bounds[i], bounds[i + 1])))
        for i in range(len(starts))
    ]

    # A cover sheet ahead of the first anchor joins the first instance. Dropping
    # those pages would take them out of every lookup, and out of verify_labels
    # with them.
    head = instances[0]
    return [head._replace(pages=head.pages | frozenset(range(1, starts[0])))] + instances[1:]


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
    """Confirm every field's keywords are present, in every instance.

    Per instance, because a packet whose third K-1 is missing field E is exactly
    what this exists to catch. Asked document-wide, partner 1's label satisfies
    the check on all thirty partners' behalf.

    Raises:
        AnchorMismatch: naming the instance and the keywords not found in it.
    """
    instances = segment(pages, field_map)
    for instance in instances:
        note = "" if len(instances) == 1 else f"{instance.describe()}: "
        missing = [
            f["keywords"]
            for f in field_map["fields"]
            if find_label(pages, f["keywords"], instance.pages) is None
        ]
        if missing:
            raise AnchorMismatch(f"{note}labels not found: {missing}")


# Retained under its v1 name so callers and tests reading as "anchors" still work.
verify_anchors = verify_labels


def locate(pages: list[list[Line]], field_map: dict[str, Any]) -> list[Field]:
    """Extract every described field's value and bounding box, in every instance.

    Each line of a field becomes its own Field so it can be redacted
    independently.

    Lookup is scoped per instance and still takes the *first* match inside it.
    Both halves matter: without the scope, partners 2..N of a packet are never
    located and ship readable; without first-match, "name address city state and
    zip code" claims field F as well as field B.
    """
    col_tol = field_map.get("col_tol", DEFAULT_COL_TOL)
    instances = segment(pages, field_map)
    fields: list[Field] = []
    seen: set[tuple[int, float, float]] = set()

    for instance in instances:
        note = "" if len(instances) == 1 else f"{instance.describe()}: "

        for spec in field_map["fields"]:
            label = find_label(pages, spec["keywords"], instance.pages)
            if label is None:
                raise AnchorMismatch(f"{note}label not found: {spec['keywords']!r}")

            # skip_lines drops leading lines of a box that are out of policy --
            # on a K-1 the first line of an address box is the name.
            lines = discover_field(pages, label, col_tol)[spec.get("skip_lines", 0) :]
            if not lines:
                raise AnchorMismatch(
                    f"{note}field {spec['name']!r} has no value lines below its "
                    f"label {spec['keywords']!r}"
                )

            for line in lines:
                # No two instances may claim the same box. A mis-declared anchor
                # is how that happens, and the cost is a value redacted twice --
                # the second pass drawing its token over the first one's, which
                # verify_tokens_present cannot see because both tokens are on
                # the page.
                key = (line["page"], round(line["x0"], 1), round(line["top"], 1))
                if key in seen:
                    continue
                seen.add(key)
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
