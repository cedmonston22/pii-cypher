"""Structured identifiers: shape, validation, and the precision that matters.

The distractor and variant lists are carried forward verbatim from the regex
audit this layer replaces, so the two are measured on identical ground. The old
numbers were 8/24 recall and 0/38 false positives; the assertions below pin
what replaced them.
"""

import pytest

from core.extract import Line
from core.fieldmap import normalize
from core.piitypes import PII_TYPES
from core.tokens import PREFIX
from detect.adapter import Geometry, _joins
from detect.coverage import amountish
from detect.labels import label_only
from detect.patterns import (
    EIN_PREFIXES,
    LABEL_ONLY,
    LINE_PATTERNS,
    _canonical,
    excluded,
    scan,
    valid,
)
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
    """A date on a tax form is overwhelmingly a period end, not a birthday."""
    for pii_type in LABEL_ONLY:
        assert pii_type in LINE_PATTERNS
    assert "DOB" not in {c.pii_type for c in scan([_item("03/14/1979")])}


def test_ein_prefixes_are_a_closed_set():
    assert "00" not in EIN_PREFIXES
    assert "45" in EIN_PREFIXES
    assert all(len(p) == 2 and p.isdigit() for p in EIN_PREFIXES)


# --------------------------------------------------------------------------
# why the vocabulary is the size it is
#
# Six types, and each one has to justify itself. Four are what a Schedule K-1
# carries. The other two are here only because the coverage filter would
# otherwise swallow them, and these tests are what stop someone removing them
# on the reasonable-sounding grounds that a K-1 has no phone numbers.
# --------------------------------------------------------------------------


def test_phone_has_no_backstop_but_this_pattern():
    """Why PHONE stays despite not being a field a K-1 carries.

    coverage.amountish discards phone-shaped text as form furniture, which is
    what stops it reporting date-like line items on every document. The cost is
    that the structural layer cannot see a real phone number, so this pattern is
    the only thing between one and silence.
    """
    assert amountish("415-555-0142"), "the coverage layer discards this shape"
    assert _values("415-555-0142"), "so the pattern layer is the only thing left"


def test_an_unlabelled_date_of_birth_is_caught_by_nothing():
    """A documented hole, not an oversight.

    The filter discards date-shaped text, and DOB is label-gated so scan() will
    not mint one from shape. A birthday with no label near it therefore reaches
    no layer at all.

    The alternative is worse. Firing DOB on shape means reporting every period
    end, every "For calendar year 2021", and every line-item date on the form --
    the noise the filter exists to remove. A form that labels a date of birth is
    handled; one that does not is a limitation worth stating rather than a bug
    worth fixing here.
    """
    assert amountish("03/14/1979"), "the coverage layer discards it"
    assert not _values("03/14/1979"), "and the pattern layer will not mint it unlabelled"


@pytest.mark.parametrize("text", ["alex@example.com", "011000015", "1234567890123"])
def test_types_a_k1_does_not_carry_were_dropped_without_losing_them(text):
    """Why EMAIL, ROUTING and BANK_ACCOUNT could go.

    The filter keeps their shapes, so a value of any of them still surfaces as
    unaccounted-for fill. Dropping the pattern lost the label on the finding,
    not the finding -- which is the opposite of the PHONE and DOB case above.
    """
    assert not amountish(text), "the coverage layer keeps this shape"
    assert text.upper() not in {c.pii_type for c in scan([_item(text)]) if c.pii_type}


def test_the_vocabulary_is_closed():
    """Every type has a pattern, and every pattern names a real type."""
    named = {_canonical(name) for name in LINE_PATTERNS}
    assert named == PII_TYPES


# --------------------------------------------------------------------------
# the label-gated path
#
# Never exercised by either fixture: no K-1 labels a date of birth. It needs no
# PDF to test, only lines in a template style with a value beneath them.
# --------------------------------------------------------------------------


def _line(text, x0, top, font="Helvetica-Bold", size=9.0):
    return Line(text=text, x0=x0, top=top, x1=x0 + 60, bottom=top + 9,
                page=1, fontname=font, size=size)


def _geo(fill=("Helvetica-Bold", 9.0), x0=50.0):
    return Geometry(claimed=frozenset(), skipped=frozenset(), ignored=frozenset(),
                    fill_styles=frozenset({fill}), label_x0=(x0,), col_tol=90.0)


def _from_line(line):
    return _item(line["text"])._replace() if hasattr(_item(line["text"]), "_replace") else Item(
        text=line["text"], norm=normalize(line["text"]), dense=dense(line["text"]),
        page=line["page"], bbox=(line["x0"], line["top"], line["x1"], line["bottom"]),
        source="native_text", fontname=line["fontname"], size=line["size"])


def test_a_dob_fires_under_a_label_and_not_otherwise():
    """The label is the whole basis, not corroboration.

    A form is full of dates and a period end looks exactly like a birthday, so
    shape alone must not mint one.
    """
    label = _line("Date of birth", 50.0, 100.0, "Helvetica", 7.0)
    value = _line("03/14/1979", 50.0, 112.0)
    pages = [[label, value]]

    got = label_only([_from_line(value)], pages, _geo())
    assert [(c.pii_type, c.value) for c in got] == [("DOB", "03/14/1979")]
    assert got[0].confidence == "medium", "a quoted date is not a person's birthday"
    assert any(e.startswith("label:") for e in got[0].evidence)


def test_the_same_date_under_an_unrelated_label_is_not_a_dob():
    label = _line("For calendar year", 50.0, 100.0, "Helvetica", 7.0)
    value = _line("03/14/1979", 50.0, 112.0)
    assert label_only([_from_line(value)], [[label, value]], _geo()) == []


def test_a_value_is_not_read_as_its_own_label():
    """Fill styles are excluded when looking upward for a label.

    On a K-1 the address lines sit directly under the partner name, so without
    the style test a value would be treated as the label of the value beneath.
    """
    above = _line("Date of birth", 50.0, 100.0)          # in the FILL style
    value = _line("03/14/1979", 50.0, 112.0)
    assert label_only([_from_line(value)], [[above, value]], _geo()) == []


# --------------------------------------------------------------------------
# split identifiers
#
# Neither fixture splits one, so this path has never run on a real document.
# --------------------------------------------------------------------------


def test_an_identifier_split_across_spans_is_rejoined():
    """PDFs routinely render 123-45-6789 as two spans, and a regex over either
    half finds nothing."""
    parts = [_line("123-45-", 50.0, 200.0), _line("6789", 112.0, 200.0)]
    joined = list(_joins(parts))

    assert [i["text"] for i in joined] == ["123-45-6789"]
    assert joined[0]["source"] == "joined"
    assert "SSN" in {c.pii_type for c in scan(joined)}


def test_unrelated_columns_are_not_fused():
    """The guard that makes joining safe.

    Without the shape test, "General partner" and "LLC member-manager" -- 80pt
    apart on one row of the 2021 fixture -- fuse into a single item spanning
    both columns.
    """
    parts = [_line("General partner", 50.0, 200.0), _line("LLC member-manager", 211.0, 200.0)]
    assert list(_joins(parts)) == []


def test_a_join_needs_a_digit_and_a_small_gap():
    far = [_line("123-45-", 50.0, 200.0), _line("6789", 300.0, 200.0)]
    assert list(_joins(far)) == [], "a wide gap is a different column"

    wordy = [_line("Alex", 50.0, 200.0), _line("Tester", 112.0, 200.0)]
    assert list(_joins(wordy)) == [], "two words are not a split identifier"
