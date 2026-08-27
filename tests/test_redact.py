"""Redaction mechanics, style fidelity, and the release gates.

Replacements must be indistinguishable in styling from the text they replace:
same face, weight, size, colour and baseline. These tests pin that, plus the
gate that catches a replacement which never made it onto the page.
"""

import pymupdf
import pytest

from core.fieldmap import Field
from core.redact import base14, redact, restore_pdf
from core.verify import (
    PlaintextSurvived,
    TokenNotWritten,
    extract_all_text,
    missing_tokens,
    verify_scrubbed,
    verify_tokens_present,
)

TOKEN = "PII-9HCJ6GPF"


def _page_with(
    text: str, fontsize: float = 10.0, at=(57.0, 100.0), fontname: str = "helv"
) -> tuple[bytes, Field]:
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text(at, text, fontsize=fontsize, fontname=fontname)
    data = doc.tobytes()

    found = pymupdf.open(stream=data, filetype="pdf")[0].search_for(text)[0]
    field = Field(
        name="f", pii_type="ssn_tin", value=text, page=1,
        bbox=(found.x0, found.y0, found.x1, found.y1),
        fontname=fontname, size=fontsize,
    )
    return data, field


def _spans(data: bytes) -> list[dict]:
    page = pymupdf.open(stream=data, filetype="pdf")[0]
    return [
        span
        for block in page.get_text("dict")["blocks"]
        for line in block.get("lines", [])
        for span in line.get("spans", [])
    ]


def _span_for(data: bytes, needle: str) -> dict:
    return next(s for s in _spans(data) if needle in s["text"])


def test_glyphs_are_removed_not_covered():
    """Real redaction: the original must be gone from the content stream."""
    data, field = _page_with("000-00-0000")
    out = redact(data, [field], {"000-00-0000": TOKEN})
    assert "000-00-0000" not in extract_all_text(out)
    assert b"000-00-0000" not in out
    assert TOKEN in extract_all_text(out)


@pytest.mark.parametrize("fontsize", [5.0, 6.0, 8.0, 10.0, 14.0, 20.0])
def test_token_lands_at_every_size(fontsize):
    """Regression: replacement text used to vanish silently in short boxes.

    add_redact_annot(text=...) omits its text when the box is under ~9pt tall
    and reports no error, so a value would be removed with no token to look it
    up by. Drawing with insert_text after the redaction removes that hazard.
    """
    data, field = _page_with("000-00-0000", fontsize=fontsize)
    out = redact(data, [field], {"000-00-0000": TOKEN})
    assert TOKEN in extract_all_text(out), f"token dropped at fontsize {fontsize}"


@pytest.mark.parametrize("fontsize", [7.0, 9.0, 10.0, 12.0])
def test_token_keeps_the_original_size(fontsize):
    """add_redact_annot derives size from box height; we must not inherit that."""
    data, field = _page_with("000-00-0000", fontsize=fontsize)
    out = redact(data, [field], {"000-00-0000": TOKEN})
    assert _span_for(out, TOKEN)["size"] == pytest.approx(fontsize, abs=0.1)


def test_token_keeps_weight_and_baseline():
    """Bold values must come back bold, on the same baseline."""
    data, field = _page_with("000-00-0000", fontname="hebo", fontsize=10.0)
    before = _span_for(data, "000-00-0000")

    after = _span_for(redact(data, [field], {"000-00-0000": TOKEN}), TOKEN)
    assert after["font"] == before["font"] == "Helvetica-Bold"
    assert after["size"] == pytest.approx(before["size"], abs=0.1)
    assert after["origin"] == pytest.approx(before["origin"], abs=0.1)


def test_restore_reproduces_the_original_styling():
    data, field = _page_with("000-00-0000", fontname="hebo", fontsize=10.0)
    before = _span_for(data, "000-00-0000")

    scrubbed = redact(data, [field], {"000-00-0000": TOKEN})
    restored, _ = restore_pdf(scrubbed, {TOKEN: "000-00-0000"})

    after = _span_for(restored, "000-00-0000")
    assert after["font"] == before["font"]
    assert after["size"] == pytest.approx(before["size"], abs=0.1)
    assert after["origin"] == pytest.approx(before["origin"], abs=0.1)


@pytest.mark.parametrize(
    "fontname, expected",
    [("helv", "Helvetica"), ("hebo", "Helvetica-Bold"), ("tiro", "Times-Roman"),
     ("tibo", "Times-Bold"), ("cour", "Courier")],
)
def test_face_is_preserved_across_families(fontname, expected):
    data, field = _page_with("000-00-0000", fontname=fontname, fontsize=10.0)
    out = redact(data, [field], {"000-00-0000": TOKEN})
    assert _span_for(out, TOKEN)["font"] == expected


@pytest.mark.parametrize(
    "source, alias",
    [("Helvetica", "helv"), ("ABCDEF+Helvetica-Bold", "hebo"), ("Arial-BoldMT", "hebo"),
     ("Times-Roman", "tiro"), ("TimesNewRomanPS-BoldItalicMT", "tibi"),
     ("Courier-Bold", "cobo"), ("Symbol", "symb"), (None, "helv"), ("Unknown", "helv")],
)
def test_font_name_mapping(source, alias):
    assert base14(source) == alias


@pytest.mark.parametrize("alias", ["helv", "hebo", "tiro", "tibi", "cobo", "symb", "zadb"])
def test_font_mapping_is_idempotent(alias):
    """Mapping an already-mapped name must not fall back to the default."""
    assert base14(alias) == alias
    assert base14(base14(alias)) == alias


def test_long_value_fits_by_widening_the_box():
    """A value longer than its token must not be shrunk into illegibility."""
    data, field = _page_with("PII-9HCJ6GPF", fontsize=9.0)
    long_value = "1234 SOMEWHERE VERY LONG AVENUE, SPRINGFIELD, IL 62704"
    out = redact(data, [field], {"PII-9HCJ6GPF": long_value})
    assert long_value in extract_all_text(out)


def test_restore_round_trip():
    data, field = _page_with("000-00-0000")
    scrubbed = redact(data, [field], {"000-00-0000": TOKEN})
    restored, unplaced = restore_pdf(scrubbed, {TOKEN: "000-00-0000"})
    assert unplaced == []
    assert "000-00-0000" in extract_all_text(restored)
    assert TOKEN not in extract_all_text(restored)


def test_restore_reports_a_token_that_is_not_present():
    data, _ = _page_with("nothing to see")
    _, unplaced = restore_pdf(data, {TOKEN: "000-00-0000"})
    assert unplaced == [TOKEN]


def test_verify_scrubbed_catches_a_missed_replacement():
    """Deliberately skip a field and confirm the gate refuses the output."""
    data, field = _page_with("000-00-0000")
    doc = pymupdf.open(stream=data, filetype="pdf")
    doc[0].insert_text((57, 200), "AUSTIN, TX 78701", fontsize=10, fontname="helv")
    both = doc.tobytes()

    out = redact(both, [field], {"000-00-0000": TOKEN})
    with pytest.raises(PlaintextSurvived) as exc:
        verify_scrubbed(out, ["000-00-0000", "AUSTIN, TX 78701"])
    assert "AUSTIN, TX 78701" in str(exc.value)
    assert "000-00-0000" not in str(exc.value)


def test_verify_scrubbed_ignores_whitespace_differences():
    data, field = _page_with("000-00-0000")
    out = redact(data, [field], {"000-00-0000": TOKEN})
    verify_scrubbed(out, ["  000-00-0000  "])


def test_verify_tokens_present_raises_when_a_token_is_missing():
    data, _ = _page_with("nothing here")
    assert missing_tokens(data, [TOKEN]) == [TOKEN]
    with pytest.raises(TokenNotWritten):
        verify_tokens_present(data, [TOKEN])


def test_redaction_leaves_neighbouring_text_alone():
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((57, 100), "000-00-0000", fontsize=10, fontname="helv")
    page.insert_text((317, 100), "15 Foreign transactions", fontsize=10, fontname="helv")
    data = doc.tobytes()

    found = pymupdf.open(stream=data, filetype="pdf")[0].search_for("000-00-0000")[0]
    field = Field(
        name="f", pii_type="ssn_tin", value="000-00-0000", page=1,
        bbox=(found.x0, found.y0, found.x1, found.y1),
    )
    out = redact(data, [field], {"000-00-0000": TOKEN})
    text = extract_all_text(out)
    assert "15 Foreign transactions" in text, "the adjacent column must survive"
    assert "000-00-0000" not in text
