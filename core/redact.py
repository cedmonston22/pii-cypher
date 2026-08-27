"""PDF rewriting: tokens in on scrub, values back out on restore.

Uses real redaction. ``apply_redactions`` removes the glyphs from the content
stream; it is not a filled rectangle laid over text that anyone can select
underneath.

Removal and drawing are two separate steps. ``add_redact_annot(text=...)``
derives its own font size from the height of the box and ignores the size it is
given, so it cannot reproduce the original styling. Redacting first and then
calling ``insert_text`` puts the face, weight, size, colour and baseline back
under our control, so a scrubbed form reads as a form rather than as a form with
foreign text pasted into it.
"""

from __future__ import annotations

import re

import pymupdf

from core.fieldmap import Field
from core.tokens import display_candidates

DEFAULT_FONT = "helv"
FALLBACK_SIZE = 9.0
MIN_FONTSIZE = 5.0
RIGHT_MARGIN = 18.0
# Pad the removal box so fragments of ascenders and descenders do not survive.
GLYPH_PADDING = 1.5
# Clearance kept between a removal box and the neighbouring line's glyphs.
NEIGHBOUR_GAP = 0.5
# Fractions of the point size covered above and below the baseline. Between
# them they span the ink of a line without reaching the lines around it.
CAP_HEIGHT = 0.80
DESCENDER = 0.25

# Embedded fonts are commonly subset-tagged, e.g. "ABCDEF+Helvetica-Bold".
_SUBSET_PREFIX = re.compile(r"^[A-Z]{6}\+")

# PyMuPDF's own aliases, so the mapping is idempotent: feeding a value that
# has already been mapped must return it unchanged rather than falling through
# to the Helvetica default.
_ALIASES = frozenset(
    {"helv", "hebo", "heit", "hebi", "cour", "cobo", "coit", "cobi",
     "tiro", "tibo", "tiit", "tibi", "symb", "zadb"}
)

_FAMILIES = {
    "times": "ti",
    "timesnewroman": "ti",
    "georgia": "ti",
    "garamond": "ti",
    "serif": "ti",
    "courier": "co",
    "consolas": "co",
    "mono": "co",
}


def base14(fontname: str | None) -> str:
    """Map an arbitrary PDF font name onto a PyMuPDF base-14 alias.

    Preserves family, weight and slant. Anything unrecognised falls back to the
    Helvetica family, which is what most tax forms use.
    """
    if not fontname:
        return DEFAULT_FONT

    name = _SUBSET_PREFIX.sub("", fontname).lower().replace(" ", "")
    if name in _ALIASES:
        return name
    if "symbol" in name:
        return "symb"
    if "zapf" in name or "dingbat" in name:
        return "zadb"

    family = "he"
    for needle, code in _FAMILIES.items():
        if needle in name:
            family = code
            break

    bold = any(w in name for w in ("bold", "black", "heavy", "semibold"))
    italic = "italic" in name or "oblique" in name

    if family == "ti":
        # Times' upright face is "tiro", not "ti" plus a neutral suffix.
        return {(False, False): "tiro", (True, False): "tibo",
                (False, True): "tiit", (True, True): "tibi"}[(bold, italic)]

    suffix = {(False, False): "lv" if family == "he" else "ur",
              (True, False): "bo", (False, True): "it", (True, True): "bi"}[(bold, italic)]
    return family + suffix


class ReplacementTooSmall(Exception):
    """Raised when replacement text cannot be rendered legibly.

    Better to fail the document than to emit an unreadable smear that the user
    cannot tell apart from a successful redaction.
    """


class _Draw:
    """A replacement to draw once the glyphs beneath it have been removed."""

    __slots__ = ("page_no", "origin", "text", "font", "size", "color")

    def __init__(self, page_no, origin, text, font, size, color):
        self.page_no = page_no
        self.origin = origin
        self.text = text
        self.font = font
        self.size = size
        self.color = color


def _rgb(packed: int) -> tuple[float, float, float]:
    return ((packed >> 16 & 255) / 255, (packed >> 8 & 255) / 255, (packed & 255) / 255)


def _span_at(page: pymupdf.Page, rect: pymupdf.Rect) -> dict | None:
    """Return the text span occupying a box, by greatest overlap.

    Reading the style off the page rather than trusting stored coordinates is
    what lets a document that was edited after scrubbing still restore with the
    right appearance.
    """
    best, best_area = None, 0.0
    for block in page.get_text("dict")["blocks"]:
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                overlap = pymupdf.Rect(span["bbox"]) & rect
                if overlap.is_valid and overlap.get_area() > best_area:
                    best, best_area = span, overlap.get_area()
    return best if best_area > 0 else None


def _ink_box(rect: pymupdf.Rect, origin: pymupdf.Point, size: float) -> pymupdf.Rect:
    """Tighten a box to roughly the ink of one line of text.

    A reported span box spans the font's full ascent and descent -- about 1.37x
    the point size. On the 2025 K-1, whose address lines sit 10pt apart at 8pt
    type, consecutive span boxes therefore *overlap*, and ``apply_redactions``
    deletes any glyph whose box intersects the region. Redacting a token that
    way took the name on the line above with it.

    Tightening is safe because removal is all-or-nothing per glyph: the box only
    has to *intersect* the text it is removing, not enclose it. So a box drawn
    to cap height and descender still removes the whole line, while leaving its
    neighbours untouched.
    """
    return pymupdf.Rect(
        rect.x0,
        origin.y - CAP_HEIGHT * size,
        rect.x1,
        origin.y + DESCENDER * size,
    )


def _removal_box(page: pymupdf.Page, rect: pymupdf.Rect) -> pymupdf.Rect:
    """Pad a value's box vertically without reaching its neighbours.

    Padding clears fragments of ascenders and descenders that a box matching the
    glyph bbox exactly can leave behind. But ``apply_redactions`` deletes any
    glyph whose box merely *intersects* the region, so padding that touches the
    line above removes that entire line.

    That is not hypothetical: the 2025 K-1 sets its address blocks 10pt apart
    (the 2021 form uses 15pt), and a flat 1.5pt pad silently destroyed the
    partner and partnership names -- the two fields deliberately kept on the
    form. Padding is therefore clamped to the real gap to each neighbour.
    """
    room_above, room_below = GLYPH_PADDING, GLYPH_PADDING

    for x0, y0, x1, y1, *_ in page.get_text("words"):
        horizontally_overlaps = x0 < rect.x1 and x1 > rect.x0
        if not horizontally_overlaps:
            continue
        if y1 <= rect.y0:
            room_above = min(room_above, rect.y0 - y1)
        elif y0 >= rect.y1:
            room_below = min(room_below, y0 - rect.y1)

    pad_above = max(0.0, min(GLYPH_PADDING, room_above - NEIGHBOUR_GAP))
    pad_below = max(0.0, min(GLYPH_PADDING, room_below - NEIGHBOUR_GAP))
    return pymupdf.Rect(rect.x0, rect.y0 - pad_above, rect.x1, rect.y1 + pad_below)


def _row_limit(page: pymupdf.Page, rect: pymupdf.Rect) -> float:
    """How far right text may run before it would collide with its neighbours."""
    limit = page.rect.width - RIGHT_MARGIN
    for x0, y0, x1, y1, *_ in page.get_text("words"):
        vertically_overlaps = y0 < rect.y1 and y1 > rect.y0
        if vertically_overlaps and x0 >= rect.x1 - 0.5:
            limit = min(limit, x0 - 2.0)
    return max(limit, rect.x1)


def _plan(
    page: pymupdf.Page,
    page_no: int,
    rect: pymupdf.Rect,
    text: str,
    font: str,
    size: float,
) -> _Draw:
    """Work out where and how to draw a replacement, and queue its removal.

    Keeps the original size wherever it fits, and shrinks only when the text
    would otherwise run into whatever sits to its right.
    """
    span = _span_at(page, rect)
    origin = pymupdf.Point(*span["origin"]) if span else pymupdf.Point(rect.x0, rect.y1)
    color = _rgb(span["color"]) if span else (0.0, 0.0, 0.0)

    if span is not None:
        rect = _ink_box(rect, origin, float(span["size"]))

    if size < MIN_FONTSIZE:
        size = float(span["size"]) if span else FALLBACK_SIZE
    if size < MIN_FONTSIZE:
        size = FALLBACK_SIZE

    room = _row_limit(page, rect) - origin.x
    needed = pymupdf.get_text_length(text, fontname=font, fontsize=size)
    if needed > room:
        size *= room / needed
    if size < MIN_FONTSIZE:
        raise ReplacementTooSmall(f"{text!r} cannot be rendered above {MIN_FONTSIZE}pt")

    page.add_redact_annot(_removal_box(page, rect))
    return _Draw(page_no, origin, text, font, size, color)


def _commit(doc: pymupdf.Document, draws: list[_Draw]) -> None:
    """Remove every marked region, then draw the replacements into the gaps."""
    for page in doc:
        page.apply_redactions()
    for draw in draws:
        doc[draw.page_no].insert_text(
            draw.origin,
            draw.text,
            fontname=draw.font,
            fontsize=draw.size,
            color=draw.color,
        )


def redact(pdf_bytes: bytes, fields: list[Field], token_by_value: dict[str, str]) -> bytes:
    """Replace every located field value with its token, matching its styling."""
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    try:
        draws = [
            _plan(
                doc[field["page"] - 1],
                field["page"] - 1,
                pymupdf.Rect(*field["bbox"]),
                token_by_value[field["value"]],
                base14(field.get("fontname")),
                float(field.get("size", 0.0)),
            )
            for field in fields
        ]
        _commit(doc, draws)
        return doc.tobytes()
    finally:
        doc.close()


def restore_pdf(pdf_bytes: bytes, value_by_token: dict[str, str]) -> tuple[bytes, list[str]]:
    """Replace every token with its original value, matching the token's styling.

    Token positions are found by searching the uploaded file rather than by
    trusting stored coordinates, so a document that was edited after scrubbing
    still restores correctly. The token was written in the value's own font, so
    reading the style back off the token reproduces the original appearance.

    Returns the rewritten PDF and any tokens that were not found on any page.
    """
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    try:
        draws: list[_Draw] = []
        placed: set[str] = set()
        for page_no, page in enumerate(doc):
            for token, value in value_by_token.items():
                # Longest form first. A token whose page shows a revealed digit
                # run must be matched whole: search_for returns only the needle's
                # glyphs, so matching the bare token would leave the run outside
                # the removal box, surviving apply_redactions and overprinting
                # the restored value. Matching a six-digit tail as a four-digit
                # one strands two digits the same way.
                rects: list = []
                for form in display_candidates(token, value):
                    rects = page.search_for(form)
                    if rects:
                        break
                for rect in rects:
                    span = _span_at(page, rect)
                    font = base14(span.get("font")) if span else DEFAULT_FONT
                    size = float(span["size"]) if span else 0.0
                    draws.append(_plan(page, page_no, rect, value, font, size))
                    placed.add(token)
        _commit(doc, draws)
        return doc.tobytes(), sorted(set(value_by_token) - placed)
    finally:
        doc.close()
