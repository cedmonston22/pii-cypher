"""Form identification and adaptive field location.

The headline case is that ONE concept map extracts the same four fields from two
Schedule K-1 revisions whose geometry disagrees: 2021 indents values 30pt right of
their label, 2025 puts them flush and the numeric fields 1.8pt to the left.
"""

import copy
import json

import pytest

from core.extract import extract_lines
from core.piitypes import PII_TYPES, UnknownPiiType
from core.fieldmap import (
    MAX_FIELD_LINES,
    AnchorMismatch,
    UnknownForm,
    discover_field,
    find_label,
    identify,
    load_field_maps,
    locate,
    normalize,
    propagate,
    verify_labels,
)

EXPECTED = {
    "2021": {
        "partnership_ein": ["00-0000000"],
        "partnership_address": ["456 SAMPLE AVE", "DENVER, CO 80202"],
        "partner_tin": ["000-00-0000"],
        "partner_address": ["123 EXAMPLE LANE", "AUSTIN, TX 78701"],
    },
    "2025": {
        "partnership_ein": ["45-1234567"],
        "partnership_address": ["456 SAMPLE AVE", "DENVER, CO 80202"],
        "partner_tin": ["512-44-8890"],
        "partner_address": ["123 EXAMPLE LANE", "AUSTIN, TX 78701"],
    },
}
NAMES = ["DEMO HARBOR PARTNERS LP", "ALEX TESTER"]


@pytest.fixture(scope="module")
def maps():
    return load_field_maps()


@pytest.fixture(scope="module")
def pages_2021():
    from tests.conftest import FIXTURE

    return extract_lines(FIXTURE.read_bytes())


@pytest.fixture(scope="module")
def pages_2025():
    from tests.conftest import FIXTURE_2025

    return extract_lines(FIXTURE_2025.read_bytes())


@pytest.fixture
def both(pages_2021, pages_2025):
    return {"2021": pages_2021, "2025": pages_2025}


# --------------------------------------------------------------------------
# normalize
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Partner's SSN or TIN", "partner s ssn or tin"),
        ("Partner’s SSN or TIN", "partner s ssn or tin"),
        ("PARTNER'S   SSN  or TIN", "partner s ssn or tin"),
        ("Partnership’s name, address, city", "partnership s name address city"),
        ("  spaced   out  ", "spaced out"),
    ],
)
def test_normalize_folds_typography_case_and_punctuation(raw, expected):
    assert normalize(raw) == expected


def test_typographic_and_straight_apostrophes_agree():
    """The bug this exists to kill: a curly apostrophe defeating label matching."""
    assert normalize("Partner's SSN") == normalize("Partner’s SSN")


# --------------------------------------------------------------------------
# identify -- one map, both revisions
# --------------------------------------------------------------------------


def test_one_map_identifies_both_revisions(both, maps):
    for tag, pages in both.items():
        assert identify(pages, maps)["form_id"] == "us-1065-k1", tag


def test_identify_does_not_depend_on_the_year(both, maps):
    """The 2025 form is four revisions from the one the map was written against."""
    haystack_2025 = " ".join(ln["text"] for ln in both["2025"][0])
    assert "2021" not in haystack_2025
    assert identify(both["2025"], maps)["form_id"] == "us-1065-k1"


def test_identify_rejects_an_unrelated_document(maps):
    import pymupdf

    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "Commercial Invoice No. 4471", fontsize=11)
    with pytest.raises(UnknownForm):
        identify(extract_lines(doc.tobytes()), maps)


def test_identify_requires_every_marker(both, maps):
    partial = copy.deepcopy(maps[0])
    partial["identify"]["all_of"] = ["schedule k 1", "form 1120s"]
    with pytest.raises(UnknownForm):
        identify(both["2021"], [partial])


# --------------------------------------------------------------------------
# find_label -- keywords survive rewording
# --------------------------------------------------------------------------


def test_label_found_despite_rewording(both):
    """2025 appended a sentence to this label; the distinctive keywords remain."""
    label_2021 = find_label(both["2021"], "ssn or tin")
    label_2025 = find_label(both["2025"], "ssn or tin")
    assert label_2021 is not None and label_2025 is not None
    assert "Do not use TIN" in label_2025["text"], "2025 label really is reworded"


def test_missing_keywords_return_none(both):
    assert find_label(both["2021"], "partner's favourite colour") is None


# --------------------------------------------------------------------------
# discover_field -- the three rules
# --------------------------------------------------------------------------


def test_geometry_is_discovered_not_declared(both, maps):
    """Same rules, opposite offsets. This is the whole point of the rewrite."""
    offsets = {}
    for tag, pages in both.items():
        label = find_label(pages, "ssn or tin")
        value = discover_field(pages, label)[0]
        offsets[tag] = round(value["x0"] - label["x0"], 1)

    assert offsets["2021"] > 25, f"2021 indents its values, got {offsets['2021']}"
    assert offsets["2025"] < 0, f"2025 outdents its values, got {offsets['2025']}"
    assert not any("x0_offset" in f for f in maps[0]["fields"]), "no offsets in the map"


def test_column_filter_runs_before_the_label_check(both):
    """Regression: inverting rule order returns nothing at all.

    Checking "is this the next label" before filtering by column lets an
    unrelated line in another column, which happens to share the label's font
    size, end the scan on its first iteration.
    """
    for tag, pages in both.items():
        label = find_label(pages, "employer identification number")
        assert discover_field(pages, label), f"{tag}: column filter must be applied first"

        # Prove the hazard is real: such a line does exist on this page.
        rivals = [
            ln
            for ln in pages[0]
            if ln["top"] > label["top"]
            and abs(ln["x0"] - label["x0"]) > 90
            and abs(ln["size"] - label["size"]) < 0.3
        ]
        assert rivals, f"{tag}: expected a same-size line in another column"


def test_next_label_closes_the_box(both):
    """Field A holds one line; field B's label must stop the scan."""
    for tag, pages in both.items():
        label = find_label(pages, "employer identification number")
        found = [ln["text"] for ln in discover_field(pages, label)]
        assert len(found) == 1, f"{tag}: got {found}"


def test_style_change_closes_the_field(both):
    """The address box must not swallow what follows it.

    On 2025 the next lines are a stray 'G' and the field C heading, neither of
    which shares the address values' style.
    """
    for tag, pages in both.items():
        label = find_label(pages, "zip code for partner")
        found = [ln["text"] for ln in discover_field(pages, label)]
        assert found == ["ALEX TESTER", "123 EXAMPLE LANE", "AUSTIN, TX 78701"], tag


def test_field_line_count_is_capped(both):
    for tag, pages in both.items():
        for keywords in ("ssn or tin", "zip code for partner"):
            label = find_label(pages, keywords)
            assert len(discover_field(pages, label)) <= MAX_FIELD_LINES, tag


def test_narrow_column_tolerance_finds_nothing(both):
    """col_tol is a band around the label, so an absurdly tight one excludes all."""
    label = find_label(both["2021"], "ssn or tin")
    assert discover_field(both["2021"], label, col_tol=1.0) == []


# --------------------------------------------------------------------------
# locate -- the headline
# --------------------------------------------------------------------------


def test_one_map_extracts_both_revisions(both, maps):
    for tag, pages in both.items():
        by_name: dict[str, list[str]] = {}
        for field in locate(pages, identify(pages, maps)):
            by_name.setdefault(field["name"], []).append(field["value"])
        assert by_name == EXPECTED[tag], tag


def test_names_are_excluded_on_both_revisions(both, maps):
    """skip_lines drops line 1 of an address box, which is the name."""
    for tag, pages in both.items():
        values = [f["value"] for f in locate(pages, identify(pages, maps))]
        for name in NAMES:
            assert name not in values, f"{tag}: {name} should be out of policy"


def test_located_fields_carry_their_styling(both, maps):
    """redact.py needs these to reproduce the source appearance."""
    for tag, pages in both.items():
        for field in locate(pages, identify(pages, maps)):
            assert field["fontname"], tag
            assert field["size"] > 0, tag


def test_located_bboxes_stay_in_the_left_column(both, maps):
    for tag, pages in both.items():
        for field in locate(pages, identify(pages, maps)):
            assert field["bbox"][2] < 320, f"{tag}: {field['value']!r} bleeds right"


# --------------------------------------------------------------------------
# failure paths
# --------------------------------------------------------------------------


def test_verify_labels_passes_on_both(both, maps):
    for pages in both.values():
        verify_labels(pages, identify(pages, maps))


def test_verify_labels_reports_every_missing_label(both, maps):
    broken = copy.deepcopy(maps[0])
    broken["fields"][0]["keywords"] = "favourite colour"
    broken["fields"][2]["keywords"] = "lucky number"
    with pytest.raises(AnchorMismatch) as exc:
        verify_labels(both["2021"], broken)
    assert "favourite colour" in str(exc.value)
    assert "lucky number" in str(exc.value)


def test_locate_fails_loudly_on_an_unmatched_label(both, maps):
    broken = copy.deepcopy(maps[0])
    broken["fields"][0]["keywords"] = "favourite colour"
    with pytest.raises(AnchorMismatch):
        locate(both["2021"], broken)


def test_locate_fails_when_skip_lines_consumes_the_field(both, maps):
    """Skipping more lines than a box holds must raise, not return nothing."""
    greedy = copy.deepcopy(maps[0])
    greedy["fields"][0]["skip_lines"] = 5
    with pytest.raises(AnchorMismatch) as exc:
        locate(both["2021"], greedy)
    assert "partnership_ein" in str(exc.value)


def test_map_without_markers_is_rejected(maps):
    from core.fieldmap import _validate

    broken = copy.deepcopy(maps[0])
    broken["identify"]["all_of"] = []
    with pytest.raises(ValueError):
        _validate(broken)


# --------------------------------------------------------------------------
# propagate
# --------------------------------------------------------------------------


def test_propagate_adds_nothing_on_a_single_page_form(both, maps):
    for tag, pages in both.items():
        located = locate(pages, identify(pages, maps))
        assert len(propagate(pages, located)) == len(located), tag


def test_propagate_catches_a_repeated_value(both, maps):
    pages = both["2021"]
    located = locate(pages, identify(pages, maps))

    extra = [list(pages[0])]
    footer = dict(extra[0][0])
    footer.update({"text": "000-00-0000", "x0": 400.0, "top": 700.0, "x1": 460.0, "bottom": 710.0})
    extra[0].append(footer)

    grown = propagate(extra, located)
    assert len(grown) == len(located) + 1
    assert sum(1 for f in grown if f["value"] == "000-00-0000") == 2


def test_the_loader_canonicalises_legacy_type_names(tmp_path):
    """A map written in the old vocabulary still loads, spelled the new way.

    The loader is the only boundary a legacy spelling can cross. Translating
    any deeper in would leave two vocabularies alive inside core with a
    conversion at every comparison, and a missed one redacts nothing silently.
    """
    (tmp_path / "legacy.json").write_text(
        json.dumps(
            {
                "form_id": "legacy",
                "identify": {"all_of": ["marker"]},
                "fields": [
                    {"name": "a", "pii_type": "ssn_tin", "keywords": "ssn"},
                    {"name": "b", "pii_type": "address", "keywords": "addr"},
                ],
            }
        ),
        encoding="utf-8",
    )

    loaded = load_field_maps(tmp_path)[0]

    assert [f["pii_type"] for f in loaded["fields"]] == ["SSN", "ADDRESS"]


def test_a_map_naming_an_unknown_type_is_refused(tmp_path):
    """An unrecognised type matches no policy, so the field is filtered out and
    the document is returned unredacted with every release gate satisfied.
    Refusing the map is the only way that failure stays visible.
    """
    (tmp_path / "bad.json").write_text(
        json.dumps(
            {
                "form_id": "bad",
                "identify": {"all_of": ["marker"]},
                "fields": [{"name": "a", "pii_type": "passport", "keywords": "k"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(UnknownPiiType, match="passport"):
        load_field_maps(tmp_path)


def test_the_shipped_map_uses_the_canonical_vocabulary():
    """Guards against the shipped map drifting back out of the vocabulary."""
    for field in load_field_maps()[0]["fields"]:
        assert field["pii_type"] in PII_TYPES
