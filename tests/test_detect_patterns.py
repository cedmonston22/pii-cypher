"""Structured identifiers: shape, validation, and the precision that matters.

The distractor and variant lists are carried forward verbatim from the regex
audit this layer replaces, so the two are measured on identical ground. The old
numbers were 8/24 recall and 0/38 false positives; the assertions below pin
what replaced them.
"""

import pytest

from core.fieldmap import normalize
from core.tokens import PREFIX
from detect.patterns import EIN_PREFIXES, LABEL_ONLY, LINE_PATTERNS, excluded, scan, valid
from detect.types import Item, dense


def _item(text: str, source: str = "native_text") -> Item:
    return Item(
        text=text,
        norm=normalize(text),
        dense=dense(text),
        page=1,
        bbox=(0.0, 0.0, 100.0, 10.0),
        source=source,
        fontname="Helvetica",
        size=9.0,
    )


def _values(text: str) -> set[str]:
    return {c.value for c in scan([_item(text)])}


# Carried over from tests/test_detect.py verbatim.
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

# Measured, not aspirational. Raise this only alongside a rerun that shows the
# distractor count is still zero -- recall bought with precision is a loss.
RECALL_FLOOR = 0.62


def test_no_false_alarms_on_tax_form_furniture():
    """38 distractors from real forms. Zero, exactly as the old audit managed.

    This is the property that makes an audit usable at all. Losing it to buy
    recall would be a downgrade however good the recall number looked.
    """
    raised = {d: sorted(_values(d)) for d in DISTRACTORS if _values(d)}
    assert raised == {}, f"false alarms: {raised}"


def test_recall_beats_the_audit_it_replaces():
    caught = {text for text in REAL_PII if _values(text)}
    recall = len(caught) / len(REAL_PII)
    assert recall >= RECALL_FLOOR, f"recall fell to {recall:.0%}"


@pytest.mark.parametrize(
    "text",
    [
        "123456789",        # unhyphenated
        "123 45 6789",      # space separated
        "456 Sample Ave",   # lowercase street
        "Denver, CO 80202", # lowercase locality
        "PO BOX 1234",      # no house number
        "P.O. BOX 1234",
        "ONE MARKET PLAZA",
        "SUITE 400",
    ],
)
def test_documented_misses_of_the_old_audit_are_now_caught(text):
    """Each of these was a format miss for a value the map found by label."""
    assert _values(text), f"{text!r} is still missed"


@pytest.mark.parametrize("text", ["ALEX TESTER", "SMITH & CO LLP", "O'BRIEN FAMILY TRUST"])
def test_names_remain_out_of_scope(text):
    """Names are deliberately not detected and stay on the form."""
    assert not _values(text)


# --------------------------------------------------------------------------
# validation grades; it does not suppress
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pii_type, value, expected",
    [
        ("SSN", "000-00-0000", False),   # area 000 is never issued
        ("SSN", "666-12-3456", False),
        ("SSN", "123-00-6789", False),   # group 00
        ("SSN", "123-45-0000", False),   # serial 0000
        ("SSN", "512-44-8890", True),
        ("EIN", "00-0000000", False),    # prefix 00 is never issued
        ("EIN", "45-1234567", True),
        ("ITIN", "912-70-1234", True),
        ("ITIN", "912-01-1234", False),  # group outside the assigned ranges
        ("ROUTING", "011000015", True),  # ABA 3-7-1 checksum
        ("ROUTING", "011000016", False),
        ("DOB", "01/15/1980", True),
        ("DOB", "13/45/1980", False),
    ],
)
def test_validators(pii_type, value, expected):
    assert valid(pii_type, value) is expected


def test_a_shape_that_fails_validation_is_still_reported():
    """Validation decides confidence, never survival.

    Both shipped fixtures use placeholder identifiers that no validator accepts.
    Suppressing on a failed validator made detection silent on the two most
    obviously SSN-shaped strings in the repository, which is the opposite of
    what an audit is for.
    """
    found = scan([_item("000-00-0000")])
    assert [c.value for c in found] == ["000-00-0000"]
    assert found[0].confidence == "low"
    assert "validator:SSN:failed" in found[0].evidence


def test_a_valid_identifier_outranks_an_invalid_one():
    weak = scan([_item("000-00-0000")])[0]
    strong = scan([_item("512-44-8890")])[0]
    assert weak.confidence == "low"
    assert strong.confidence == "medium"
    assert "validator:SSN" in strong.evidence


def test_a_toll_free_number_is_excluded_not_merely_downgraded():
    """The IRS help line is printed on the form. Reporting it is pure noise.

    This is a different question from validation: not "is this a well-formed
    phone number" but "can this be a person's number at all".
    """
    assert excluded("PHONE", "800-829-1040")
    assert not _values("800-829-1040")


# --------------------------------------------------------------------------
# the token format must never be re-detected
# --------------------------------------------------------------------------


def test_the_tools_own_tokens_are_not_reported_as_pii():
    """A scrubbed document run through detection again must come back quiet."""
    token = f"{PREFIX}K7D4X9AB"
    assert not _values(token)
    assert token not in _values(f"SSN {token} on file")


# --------------------------------------------------------------------------
# structure of the pattern table
# --------------------------------------------------------------------------


def test_label_only_types_never_fire_on_shape_alone():
    """A bare nine-digit run is an SSN, a routing number or an invoice."""
    for pii_type in LABEL_ONLY:
        assert pii_type in LINE_PATTERNS
    assert "ROUTING" not in {c.pii_type for c in scan([_item("011000015")])}


def test_ein_prefixes_are_a_closed_set():
    assert "00" not in EIN_PREFIXES
    assert "45" in EIN_PREFIXES
    assert all(len(p) == 2 and p.isdigit() for p in EIN_PREFIXES)
