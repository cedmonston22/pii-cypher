"""The content-pattern audit, and an honest record of its limits.

These patterns are the reason location is label-driven rather than
content-driven. The recall test below is not a target to improve; it is the
evidence that this layer must never be trusted to decide what gets redacted.
"""

import pytest

from core.detect import EMBEDDED_PATTERNS, LINE_PATTERNS, audit, scan
from core.extract import Line
from core.fieldmap import identify, load_field_maps, locate, propagate


def _line(text: str, page: int = 1) -> Line:
    return Line(
        text=text, x0=57.0, top=100.0, x1=200.0, bottom=110.0,
        page=page, fontname="Helvetica-Bold", size=9.0,
    )


# --------------------------------------------------------------------------
# behaviour on the real fixtures
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def maps():
    return load_field_maps()


@pytest.mark.parametrize("fixture", ["k1_bytes", "k1_2025_bytes"])
def test_audit_is_silent_when_the_map_covers_the_form(fixture, maps, request):
    """A quiet audit is the normal case. A noisy one is learned to be ignored."""
    from core.extract import extract_lines

    pages = extract_lines(request.getfixturevalue(fixture))
    located = propagate(pages, locate(pages, identify(pages, maps)))
    assert audit(pages, {f["value"] for f in located}) == []


@pytest.mark.parametrize("fixture", ["k1_bytes", "k1_2025_bytes"])
def test_audit_speaks_when_the_map_goes_stale(fixture, maps, request):
    """Drop a field from the map; the audit must notice what stopped being claimed."""
    import copy

    from core.extract import extract_lines

    stale = copy.deepcopy(maps[0])
    stale["fields"] = [f for f in stale["fields"] if f["name"] != "partner_tin"]

    pages = extract_lines(request.getfixturevalue(fixture))
    located = propagate(pages, locate(pages, stale))
    findings = audit(pages, {f["value"] for f in located})

    assert findings, "a dropped SSN field must produce a warning"
    assert any(f.pii_type == "ssn_tin" for f in findings)


def test_finding_reads_usefully():
    findings = scan([[_line("000-00-0000")]])
    assert str(findings[0]) == "ssn_tin on page 1: '000-00-0000'"


def test_audit_suppresses_matches_inside_a_claimed_value():
    """An embedded match must not double-report a value already located."""
    pages = [[_line("SSN 000-00-0000 on file")]]
    assert audit(pages, {"SSN 000-00-0000 on file"}) == []


def test_embedded_identifiers_are_found_mid_line():
    findings = scan([[_line("C IRS center: 000-00-0000 filed")]])
    assert [f.text for f in findings] == ["000-00-0000"]


# --------------------------------------------------------------------------
# precision: tax-form furniture must not raise alarms
# --------------------------------------------------------------------------


DISTRACTORS = [
    "125,000", "45,600", "$ 1,200", "(1,250)", "25.0000 %", "0", "$ 0",
    "01 01 2025", "12/31/2021", "20 25", "2021", "25 12 31 25",
    "Part III", "Part I", "6a", "13", "Schedule K-1", "(Form 1065)",
    "OMB No. 1545-0123", "OGDEN, UT", "Final K-1", "Amended K-1",
    "1 Ordinary business income (loss)", "15 Foreign transactions",
    "INDIVIDUAL", "General partner", "LLC member-manager", "Yes", "No",
    "For calendar year 2021, or tax year", "SAMPLE - NOT FOR FILING",
    "Department of the Treasury", "Internal Revenue Service", "CANADA",
    "GERMANY", "1545-0123", "800-829-1040", "www.irs.gov/Form1065",
]


def test_no_false_alarms_on_tax_form_furniture():
    """38 distractors from real forms. Precision is what makes the audit usable."""
    findings = scan([[_line(text) for text in DISTRACTORS]])
    assert findings == [], f"false alarms: {[str(f) for f in findings]}"


# --------------------------------------------------------------------------
# recall: the documented limit
# --------------------------------------------------------------------------


REAL_PII = [
    "123-45-6789", "123456789", "XXX-XX-6789", "***-**-6789", "123 45 6789",
    "12-3456789",
    "456 SAMPLE AVE", "456 Sample Ave", "1600 PENNSYLVANIA AVE NW",
    "PO BOX 1234", "P.O. BOX 1234", "ONE MARKET PLAZA", "SUITE 400",
    "DENVER, CO 80202", "Denver, CO 80202", "WINSTON-SALEM, NC 27101",
    "AUSTIN, TX 78701-1234", "NEW YORK NY 10001",
    "TORONTO, ON M5H 2N2", "LONDON, UNITED KINGDOM", "12 RUE DE RIVOLI",
    "ALEX TESTER", "SMITH & CO LLP", "O'BRIEN FAMILY TRUST",
]


def test_recall_on_realistic_variation_is_poor_by_design():
    """Pins the measured limit so nobody promotes this layer to a detector.

    Every miss is a *format* miss -- a lowercase city line, a PO box, a foreign
    postal code, a name -- sitting exactly where the field map would have found
    it by label. That asymmetry is the argument for label-driven location.
    """
    caught = {text for text in REAL_PII if scan([[_line(text)]])}
    recall = len(caught) / len(REAL_PII)

    assert recall < 0.5, (
        f"recall is {recall:.0%}; if these patterns really improved, revisit the "
        "claim in core/detect.py rather than silently widening this bound"
    )
    for missed in ("PO BOX 1234", "Denver, CO 80202", "ALEX TESTER"):
        assert missed not in caught, f"{missed!r} is a documented miss"


@pytest.mark.parametrize("group", [LINE_PATTERNS, EMBEDDED_PATTERNS])
def test_every_pattern_is_typed(group):
    """A finding's pii_type feeds the report, so each pattern must name one."""
    for pii_type, pattern in group.items():
        assert pii_type
        assert pattern.pattern
