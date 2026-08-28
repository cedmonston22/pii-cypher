"""Document builders shared by the location, detection and pipeline tests.

Everything here rewrites a shipped fixture rather than drawing a fresh page.
The two-column baseline collisions are what make this form interesting to
locate -- the partner's SSN sits 1pt from a Part III line item -- and a
hand-built page would not have them.
"""

from __future__ import annotations

from collections.abc import Sequence

import pymupdf

from core.extract import extract_lines
from core.fieldmap import identify, load_field_maps, locate, propagate
from core.redact import redact

# Partners 2 and 3 get an EIN, a TIN and a home address of their own, so a
# packet exercises distinct values per instance. The partnership's own address
# (456 SAMPLE AVE / DENVER, CO 80202) is deliberately left shared: one
# partnership issues every K-1 in the file, and that is also the case where one
# token has to be drawn at several sites.
#
# Sharing address strings is exactly what made merged fixtures look better than
# they were -- propagate rescued them by exact text match, hiding the fact that
# locate never saw page 2 at all. These swaps are what remove that cover.
PARTNER_SWAPS: tuple[dict[str, str], ...] = (
    {},
    {
        "00-0000000": "45-1234567",
        "000-00-0000": "512-44-8890",
        "123 EXAMPLE LANE": "77 MAPLE COURT",
        "AUSTIN, TX 78701": "RENO, NV 89501",
    },
    {
        "00-0000000": "81-7654321",
        "000-00-0000": "606-12-3456",
        "123 EXAMPLE LANE": "9 BIRCH WAY",
        "AUSTIN, TX 78701": "MIAMI, FL 33101",
    },
)

# Every value that belongs to exactly one partner. A scrub of a packet must
# leave none of these on the page.
PARTNER_VALUES: tuple[str, ...] = tuple(
    value for swaps in PARTNER_SWAPS for value in swaps.values()
) + ("00-0000000", "000-00-0000", "123 EXAMPLE LANE", "AUSTIN, TX 78701")


def variant(pdf_bytes: bytes, swaps: dict[str, str]) -> bytes:
    """A second document at the same coordinates with different values."""
    if not swaps:
        return pdf_bytes
    pages = extract_lines(pdf_bytes)
    field_map = identify(pages, load_field_maps())
    fields = [f for f in propagate(pages, locate(pages, field_map)) if f["value"] in swaps]
    return redact(pdf_bytes, fields, swaps)


def concat(documents: Sequence[bytes]) -> bytes:
    """One file holding these documents in order."""
    merged = pymupdf.open()
    for source in documents:
        page = pymupdf.open(stream=source, filetype="pdf")
        merged.insert_pdf(page)
        page.close()
    return merged.tobytes()


def packet(pdf_bytes: bytes, swaps: Sequence[dict[str, str]] = PARTNER_SWAPS) -> bytes:
    """A firm's export: several K-1s from one partnership, one file.

    Each is a full page, which is the real shape -- the K-1 is a full-page form.
    """
    return concat([variant(pdf_bytes, s) for s in swaps])


def repeat(pdf_bytes: bytes, times: int) -> bytes:
    """The same document `times` over. For the page cap, where content is moot."""
    return concat([pdf_bytes] * times)
