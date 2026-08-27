"""Regression tests for two-column line assembly.

The Schedule K-1 places Parts I/II and Parts III/IV on shared baselines. Every
in-scope value sits within ~1pt of an unrelated right-column line, so row
grouping alone merges them. These tests pin the behaviour that keeps them apart.
"""

from pathlib import Path

import pytest

from core.extract import NoTextLayer, extract_lines, has_text_layer, page_count

FIXTURE = Path(__file__).parent / "fixtures" / "k1-sample.pdf"


@pytest.fixture(scope="module")
def pdf_bytes() -> bytes:
    return FIXTURE.read_bytes()


@pytest.fixture(scope="module")
def lines(pdf_bytes: bytes):
    return extract_lines(pdf_bytes)[0]


def _find(lines, text: str):
    return [ln for ln in lines if ln["text"] == text]


def test_has_text_layer(pdf_bytes: bytes):
    assert has_text_layer(pdf_bytes) is True
    assert page_count(pdf_bytes) == 1


def test_no_text_layer_raises():
    import pymupdf

    doc = pymupdf.open()
    doc.new_page()
    with pytest.raises(NoTextLayer):
        extract_lines(doc.tobytes())


@pytest.mark.parametrize(
    "value, neighbour",
    [
        ("000-00-0000", "16 Alternative minimum tax items"),
        ("AUSTIN, TX 78701", "Part IV"),
        ("00-0000000", "5 Interest income"),
    ],
)
def test_value_is_isolated_from_right_column(lines, value, neighbour):
    """Each in-scope value is its own segment, not merged with its neighbour.

    Redacting a merged segment would blank the full page width and destroy the
    unrelated right-column content.
    """
    matches = _find(lines, value)
    assert len(matches) == 1, f"{value!r} was not extracted as its own segment"
    assert _find(lines, neighbour), f"neighbour {neighbour!r} missing"

    seg = matches[0]
    assert seg["x1"] < 300, f"{value!r} bbox bleeds into the right column"


def test_colliding_rows_are_within_row_tolerance(lines):
    """Confirm the collisions are real: the gap split, not row_tol, separates them."""
    ssn = _find(lines, "000-00-0000")[0]
    neighbour = _find(lines, "16 Alternative minimum tax items")[0]
    assert abs(ssn["top"] - neighbour["top"]) < 1.5
    assert neighbour["x0"] - ssn["x1"] > 20.0


def test_address_lines_are_separate_segments(lines):
    for value in ("456 SAMPLE AVE", "DENVER, CO 80202", "123 EXAMPLE LANE"):
        assert len(_find(lines, value)) == 1


def test_anchors_present(lines):
    for anchor in (
        "Partnership's employer identification number",
        "Partnership's name, address, city, state, and ZIP code",
        "Partner's SSN or TIN",
        "Name, address, city, state, and ZIP code for partner",
    ):
        assert any(anchor in ln["text"] for ln in lines), anchor
