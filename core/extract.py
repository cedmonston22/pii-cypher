"""PDF text extraction into positioned line segments.

Lines are assembled in two stages. Words are first grouped into rows by their
vertical position, then each row is split into segments wherever a horizontal
gap exceeds ``gap_tol``.

The second stage is not cosmetic. Multi-column tax forms place unrelated
columns on shared baselines -- on the Schedule K-1 fixture the partner's SSN
sits 3pt from a Part III line item and the partner's city/state/ZIP sits 2pt
from the Part IV heading. Grouping by vertical position alone merges them into
one line whose bbox spans the full page width, so redacting the SSN would blank
half the form.
"""

from __future__ import annotations

import io
from collections import Counter
from typing import TypedDict

import pdfplumber

DEFAULT_ROW_TOL = 1.5
DEFAULT_GAP_TOL = 20.0


class Line(TypedDict):
    """One horizontal run of text with its bounding box.

    ``top`` and ``bottom`` are distances from the top of the page, matching
    pdfplumber's coordinate space. "Below" therefore means a greater ``top``.

    ``fontname`` and ``size`` are carried so a replacement can be drawn in the
    same face and weight as the text it replaces, rather than in a default.
    """

    text: str
    x0: float
    top: float
    x1: float
    bottom: float
    page: int
    fontname: str
    size: float


class NoTextLayer(Exception):
    """Raised for a PDF whose first page carries no extractable characters."""


def has_text_layer(pdf_bytes: bytes) -> bool:
    """Return whether page 1 has any extractable characters.

    A raster scan yields zero. Such a document must be quarantined rather than
    processed, because every downstream stage would find nothing to redact and
    report success on a document that still shows every value.
    """
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        if not pdf.pages:
            return False
        return len(pdf.pages[0].chars) > 0


def page_count(pdf_bytes: bytes) -> int:
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        return len(pdf.pages)


def _split_row(words: list[dict], gap_tol: float, page_no: int) -> list[Line]:
    """Split one row of words into segments at horizontal gaps."""
    segments: list[Line] = []
    run: list[dict] = []

    for word in sorted(words, key=lambda w: w["x0"]):
        if run and word["x0"] - run[-1]["x1"] > gap_tol:
            segments.append(_to_line(run, page_no))
            run = []
        run.append(word)

    if run:
        segments.append(_to_line(run, page_no))
    return segments


def _to_line(words: list[dict], page_no: int) -> Line:
    # Weight the font by character count so a stray differently-styled word
    # cannot decide the whole segment's face.
    faces = Counter()
    for word in words:
        faces[word.get("fontname", "Helvetica")] += len(word["text"])

    return Line(
        text=" ".join(w["text"] for w in words),
        x0=min(w["x0"] for w in words),
        top=min(w["top"] for w in words),
        x1=max(w["x1"] for w in words),
        bottom=max(w["bottom"] for w in words),
        page=page_no,
        fontname=faces.most_common(1)[0][0],
        size=max(w.get("size", 0.0) for w in words),
    )


def extract_lines(
    pdf_bytes: bytes,
    row_tol: float = DEFAULT_ROW_TOL,
    gap_tol: float = DEFAULT_GAP_TOL,
) -> list[list[Line]]:
    """Extract positioned line segments, one list per page.

    Raises:
        NoTextLayer: if page 1 has no extractable characters.
    """
    pages: list[list[Line]] = []

    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        if not pdf.pages or not pdf.pages[0].chars:
            raise NoTextLayer("page 1 has no extractable text")

        for page_no, page in enumerate(pdf.pages, start=1):
            words = page.extract_words(
                x_tolerance=1.5, y_tolerance=1.5, extra_attrs=["fontname", "size"]
            )
            lines: list[Line] = []
            row: list[dict] = []
            row_top: float | None = None

            for word in sorted(words, key=lambda w: (w["top"], w["x0"])):
                if row_top is None or abs(word["top"] - row_top) <= row_tol:
                    if row_top is None:
                        row_top = word["top"]
                    row.append(word)
                else:
                    lines.extend(_split_row(row, gap_tol, page_no))
                    row, row_top = [word], word["top"]

            if row:
                lines.extend(_split_row(row, gap_tol, page_no))

            lines.sort(key=lambda ln: (ln["top"], ln["x0"]))
            pages.append(lines)

    return pages
