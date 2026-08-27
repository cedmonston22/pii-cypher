"""The release gate: confirm no original value survived into the output.

Verification deliberately uses PyMuPDF while location uses pdfplumber. A bug in
one extractor cannot then hide itself from the check -- if the two disagree
about what text a page contains, the disagreement surfaces here rather than
shipping.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import pymupdf


class PlaintextSurvived(Exception):
    """Raised when a value the pipeline claimed to redact is still readable.

    The output must be discarded and the document quarantined. Returning it
    would hand the user a file that looks scrubbed and is not.
    """


def _normalize(text: str) -> str:
    """Collapse whitespace so extraction spacing cannot mask a match."""
    return re.sub(r"\s+", " ", text).strip()


def extract_all_text(pdf_bytes: bytes) -> str:
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    try:
        return _normalize(" ".join(page.get_text() for page in doc))
    finally:
        doc.close()


def verify_scrubbed(pdf_bytes: bytes, original_values: Iterable[str]) -> None:
    """Raise if any original value is still present in the produced PDF.

    Raises:
        PlaintextSurvived: listing every value that survived.
    """
    haystack = extract_all_text(pdf_bytes)
    survived = sorted({v for v in original_values if v and _normalize(v) in haystack})
    if survived:
        raise PlaintextSurvived(f"values still present after redaction: {survived}")


class TokenNotWritten(Exception):
    """Raised when a value was removed but its token never appeared.

    This is data loss, not redaction: the original is gone from the document
    and there is no token left to look it up by.
    """


def missing_tokens(pdf_bytes: bytes, tokens: Iterable[str]) -> list[str]:
    """Return tokens that failed to appear in the output."""
    haystack = extract_all_text(pdf_bytes)
    return sorted({t for t in tokens if t not in haystack})


def verify_tokens_present(pdf_bytes: bytes, tokens: Iterable[str]) -> None:
    """Raise if any token failed to land.

    The renderer can drop replacement text without reporting it, so the output
    is checked rather than trusted.

    Raises:
        TokenNotWritten
    """
    missing = missing_tokens(pdf_bytes, tokens)
    if missing:
        raise TokenNotWritten(f"tokens missing from output: {missing}")
