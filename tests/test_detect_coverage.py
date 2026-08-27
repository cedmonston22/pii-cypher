"""Structural coverage, and the whole detector, across both K-1 revisions.

The question this layer exists to answer is the one verify_labels cannot ask:
not "is every label the map names on the page" but "does the page carry a field
the map omits". The tests below drop one field at a time from the map and
require the value to surface.

Both revisions are exercised for every case, because their fill styles are
disjoint -- 2021 fills in Helvetica-Bold 9/10pt against a 7.2-8pt template,
2025 in base-14 Helvetica 8pt against subset-embedded faces -- so any rule that
happens to be hardcoded fits one and fails the other.
"""

import copy

import pytest

from core.extract import extract_lines
from core.fieldmap import identify, load_field_maps, locate, propagate
from detect import detect
from detect.adapter import geometry, items
from detect.coverage import amountish, unclaimed


@pytest.fixture
def both(k1_bytes, k1_2025_bytes):
    return {"2021": k1_bytes, "2025": k1_2025_bytes}


def _prepare(pdf_bytes, drop=()):
    pages = extract_lines(pdf_bytes)
    field_map = copy.deepcopy(identify(pages, load_field_maps()))
    field_map["fields"] = [f for f in field_map["fields"] if f["name"] not in drop]
    located = propagate(pages, locate(pages, field_map))
    return pages, field_map, located


def _warnings(pdf_bytes, drop=()):
    pages, field_map, located = _prepare(pdf_bytes, drop)
    return detect(pages, field_map=field_map, located=located).unclaimed


# --------------------------------------------------------------------------
# the noise floor
# --------------------------------------------------------------------------


@pytest.mark.parametrize("revision", ["2021", "2025"])
def test_a_fitting_map_produces_no_warnings_at_all(both, revision):
    """Silence when the map fits is what makes the audit worth reading.

    Three things have to line up for this: skip_lines drops are recognised as
    deliberate rather than missed, the IRS service centre is named in the map's
    ignore list, and the amount filter removes the dollar column.
    """
    assert [str(c) for c in _warnings(both[revision])] == []


@pytest.mark.parametrize("revision", ["2021", "2025"])
def test_the_names_the_map_deliberately_skips_are_not_reported(both, revision):
    """skip_lines: 1 drops the name line of each address box.

    Those lines are filled-in text in the label column that no field claims --
    exactly the shape of a coverage gap -- so without recognising them as
    deliberate the audit would report two names on every clean document.
    """
    pages, field_map, located = _prepare(both[revision])
    geo = geometry(pages, field_map, located)
    assert len(geo.skipped) == 2


@pytest.mark.parametrize("revision", ["2021", "2025"])
def test_the_ignore_list_covers_the_irs_service_centre(both, revision):
    pages, field_map, located = _prepare(both[revision])
    geo = geometry(pages, field_map, located)
    assert len(geo.ignored) >= 1


# --------------------------------------------------------------------------
# a stale map has to speak
# --------------------------------------------------------------------------


EXPECTED = {
    ("2021", "partnership_ein"): {"00-0000000"},
    ("2021", "partner_tin"): {"000-00-0000"},
    ("2021", "partnership_address"): {"456 SAMPLE AVE", "DENVER, CO 80202"},
    ("2021", "partner_address"): {"123 EXAMPLE LANE", "AUSTIN, TX 78701"},
    ("2025", "partnership_ein"): {"45-1234567"},
    ("2025", "partner_tin"): {"512-44-8890"},
    ("2025", "partnership_address"): {"456 SAMPLE AVE", "DENVER, CO 80202"},
    ("2025", "partner_address"): {"123 EXAMPLE LANE", "AUSTIN, TX 78701"},
}


@pytest.mark.parametrize("revision, field", sorted(EXPECTED))
def test_dropping_a_field_surfaces_its_value(both, revision, field):
    found = {c.value for c in _warnings(both[revision], drop=(field,))}
    assert EXPECTED[(revision, field)] <= found


@pytest.mark.parametrize("revision", ["2021", "2025"])
def test_the_pattern_layer_covers_the_structural_layers_blind_spot(both, revision):
    """Dropping every identifier field at once defeats structural detection.

    The fill style is learned from what locate() claimed, so removing both
    identifier fields from the 2021 map removes every claimed example of
    Helvetica-Bold 10pt and the style stops being recognisable as fill. The
    structural layer goes silent; the pattern layer does not. That is the
    argument for having both, and it is why neither alone is a coverage check.
    """
    drop = ("partner_tin", "partnership_ein")
    pages, field_map, located = _prepare(both[revision], drop)
    geo = geometry(pages, field_map, located)

    structural = {c.value for c in unclaimed(items(pages), geo)}
    everything = {c.value for c in _warnings(both[revision], drop=drop)}

    if revision == "2021":
        assert structural == set(), "the documented blind spot has moved"
    assert len(everything) == 2, f"both identifiers must still surface: {everything}"


# --------------------------------------------------------------------------
# the furniture filter
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["000-00-0000", "00-0000000", "45-1234567", "512-44-8890"])
def test_an_identifier_is_never_furniture(text):
    """The trap this filter sets for itself.

    The obvious broad version, anything made of digits and punctuation, also
    matches every SSN and EIN on the page. Using it makes the stale-map tests
    above pass for the wrong reason -- not because the map is complete but
    because no identifier can ever be reported.
    """
    assert not amountish(text)


@pytest.mark.parametrize(
    "text", ["125,000", "45,600", "$ 1,200", "(1,250)", "25.0000", "12 31 25", "01 01 2025"]
)
def test_amounts_and_dates_are_furniture(text):
    assert amountish(text)


# --------------------------------------------------------------------------
# detection never touches redaction
# --------------------------------------------------------------------------


@pytest.mark.parametrize("revision", ["2021", "2025"])
def test_a_candidate_carries_no_font_information(both, revision):
    """Nothing detection produces can reach redact(), by construction.

    A Candidate has no fontname and no size, so it cannot be turned into a
    Field and drawn. That is deliberate: replacements are drawn in the source's
    own face, and a candidate's bounding box is the whole line rather than the
    span of the value.
    """
    pages, field_map, located = _prepare(both[revision], drop=("partner_tin",))
    candidate = detect(pages, field_map=field_map, located=located).unclaimed[0]
    assert not hasattr(candidate, "fontname")
    assert not hasattr(candidate, "size")


def test_a_failing_detector_produces_a_warning_not_a_clean_document(both, monkeypatch):
    """Fail closed. A crash must never look like a document with no PII."""
    import detect as detect_pkg

    def boom(*args, **kwargs):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(detect_pkg.patterns, "scan", boom)
    pages, field_map, located = _prepare(both["2021"])
    report = detect(pages, field_map=field_map, located=located)

    markers = [c for c in report.candidates if any("detector-failed" in e for e in c.evidence)]
    assert markers, "a crashed detector must leave a trace"


def test_a_failure_marker_carries_no_value(both, monkeypatch):
    """An exception message is the most likely leak in this codebase."""
    import detect as detect_pkg

    def boom(*args, **kwargs):
        raise RuntimeError("SSN 000-00-0000 blew up")

    monkeypatch.setattr(detect_pkg.patterns, "scan", boom)
    pages, field_map, located = _prepare(both["2021"])
    report = detect(pages, field_map=field_map, located=located)

    rendered = " ".join(str(c) + " ".join(c.evidence) for c in report.candidates)
    assert "000-00-0000" not in rendered
