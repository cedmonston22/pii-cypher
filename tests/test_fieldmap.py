"""Form identification and adaptive field location.

The headline case is that ONE concept map extracts the same four fields from two
Schedule K-1 revisions whose geometry disagrees: 2021 indents values 30pt right of
their label, 2025 puts them flush and the numeric fields 1.8pt to the left.
"""

import copy
import json

import pymupdf
import pytest

from core.extract import extract_lines
from core.piitypes import PII_TYPES, UnknownPiiType
from core.fieldmap import (
    MAX_FIELD_LINES,
    AnchorMismatch,
    UnknownForm,
    discover_field,
    find_label,
    find_labels,
    identify,
    load_field_maps,
    locate,
    normalize,
    propagate,
    segment,
    verify_labels,
)
from tests.helpers import concat, packet, variant

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


def test_an_ignore_label_resolves_to_the_box_that_is_not_pii(k1_bytes):
    """The IRS service centre is filled-in text no field claims.

    It is stylistically identical to the addresses and sits in the label
    column, so a coverage check keyed on style would report it on every clean
    document. Naming the label is the only way to say "known, and not PII"
    without guessing at content.
    """
    pages = extract_lines(k1_bytes)
    field_map = load_field_maps()[0]

    label = find_label(pages, field_map["ignore"][0])
    assert label is not None

    box = discover_field(pages, label, field_map.get("col_tol", 90.0))
    assert [line["text"] for line in box] == ["OGDEN, UT"]


def test_a_missing_ignore_label_is_not_an_anchor_mismatch(k1_bytes):
    """An absent ignore costs one box of suppression; an absent field is fatal.

    verify_labels must keep iterating fields alone, or a form revision that
    reworded a non-PII label would quarantine documents it has no business
    rejecting.
    """
    pages = extract_lines(k1_bytes)
    field_map = copy.deepcopy(load_field_maps()[0])
    field_map["ignore"] = ["a label this form does not have"]

    verify_labels(pages, field_map)  # must not raise


def test_a_malformed_ignore_is_refused(tmp_path):
    (tmp_path / "bad.json").write_text(
        json.dumps(
            {
                "form_id": "bad",
                "identify": {"all_of": ["marker"]},
                "ignore": ["  "],
                "fields": [{"name": "a", "pii_type": "SSN", "keywords": "k"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="ignore"):
        load_field_maps(tmp_path)


# --------------------------------------------------------------------------
# Instances: several filled copies of one form in a single file
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def packet_pages():
    """Three K-1s, one partnership, distinct partner values, one file."""
    from tests.conftest import FIXTURE

    return extract_lines(packet(FIXTURE.read_bytes()))


@pytest.mark.parametrize("revision", ["2021", "2025"])
def test_a_single_document_is_one_instance(both, maps, revision):
    """The no-regression pin. Segmentation must be invisible to a lone form."""
    instances = segment(both[revision], maps[0])

    assert len(instances) == 1
    assert instances[0].pages == frozenset(range(1, len(both[revision]) + 1))


def test_a_map_without_an_anchor_is_one_instance(packet_pages, maps):
    """Absent instance_anchor means the file holds one form, as it always did.

    This is what keeps every form family that has not been looked at yet on
    exactly the behaviour it shipped with.
    """
    unanchored = copy.deepcopy(maps[0])
    del unanchored["instance_anchor"]

    assert len(segment(packet_pages, unanchored)) == 1


def test_a_packet_segments_into_one_instance_per_form(packet_pages, maps):
    instances = segment(packet_pages, maps[0])

    assert [i.pages for i in instances] == [frozenset({1}), frozenset({2}), frozenset({3})]
    assert [i.index for i in instances] == [1, 2, 3]


def test_a_cover_page_joins_the_first_instance(maps):
    """Pages ahead of the first anchor are not dropped out of every lookup."""
    from tests.conftest import FIXTURE

    cover = pymupdf.open()
    # Text-bearing, because a blank first page trips the text-layer gate before
    # any of this is reached -- and a real transmittal sheet has text on it.
    cover.new_page().insert_text((72, 72), "PARTNER COPIES ENCLOSED", fontsize=12)
    body = packet(FIXTURE.read_bytes(), swaps=[{}, {"000-00-0000": "512-44-8890"}])
    pages = extract_lines(concat([cover.tobytes(), body]))

    instances = segment(pages, maps[0])

    assert [i.pages for i in instances] == [frozenset({1, 2}), frozenset({3})]


def test_find_labels_returns_every_occurrence(pages_2021):
    """Why locate cannot simply take them all.

    One K-1 carries this keyword twice -- field B for the partnership and field
    F for the partner. A map naming it relies on B coming first, so location has
    to stay first-match and be scoped by instance instead.
    """
    hits = find_labels(pages_2021, "name address city state and zip code")

    assert len(hits) == 2
    assert hits[0]["text"].startswith("B")
    assert hits[1]["text"].startswith("F")


def test_a_packet_locates_every_instance(packet_pages, maps):
    """The bug this exists to close: partners 2 and 3 used to ship readable."""
    fields = locate(packet_pages, maps[0])

    assert len(fields) == 18
    assert sorted({f["page"] for f in fields}) == [1, 2, 3]

    located = {f["value"] for f in fields}
    for value in ("45-1234567", "512-44-8890", "77 MAPLE COURT", "RENO, NV 89501"):
        assert value in located, f"partner 2's {value!r} was not located"
    for value in ("81-7654321", "606-12-3456", "9 BIRCH WAY", "MIAMI, FL 33101"):
        assert value in located, f"partner 3's {value!r} was not located"


def test_the_partner_box_is_never_claimed_as_the_partnerships(packet_pages, maps):
    """The regression a naive find-all would introduce.

    "name address city state and zip code" matches field B and field F alike, so
    taking every occurrence would locate the partner's home address a second
    time under the partnership's name.
    """
    fields = locate(packet_pages, maps[0])
    partnership = {f["value"] for f in fields if f["name"] == "partnership_address"}

    assert partnership == {"456 SAMPLE AVE", "DENVER, CO 80202"}


def test_a_packet_leaves_propagate_nothing_to_rescue(packet_pages, maps):
    """Location, not the safety net, is what covers the later partners now.

    Merged fixtures used to look healthy because propagate matched addresses the
    two documents happened to share. With distinct values per partner there is
    nothing for it to match, so anything it adds here would mean locate missed.
    """
    fields = locate(packet_pages, maps[0])

    assert propagate(packet_pages, fields) == fields


def test_one_box_is_never_claimed_by_two_instances(packet_pages, maps):
    positions = [(f["page"], round(f["bbox"][0], 1), round(f["bbox"][1], 1)) for f in locate(packet_pages, maps[0])]

    assert len(positions) == len(set(positions))


def test_an_incomplete_instance_is_named(maps, k1_bytes, k1_2025_bytes):
    """A packet whose second form lacks a field must say which one.

    Asked document-wide, partner 1's label answers on everyone's behalf and the
    missing field is never noticed. "do not use tin" is wording the 2025
    revision added to field E, so it is present in one instance and not the
    other.
    """
    pages = extract_lines(concat([k1_bytes, k1_2025_bytes]))
    broken = copy.deepcopy(maps[0])
    broken["fields"][2]["keywords"] = "do not use tin"

    assert len(segment(pages, broken)) == 2

    with pytest.raises(AnchorMismatch) as exc:
        verify_labels(pages, broken)
    assert "instance 1" in str(exc.value)
    assert "do not use tin" in str(exc.value)

    with pytest.raises(AnchorMismatch) as exc:
        locate(pages, broken)
    assert "instance 1" in str(exc.value)


def test_a_lone_documents_message_names_no_instance(both, maps):
    """One instance carries no ordinal -- there is nothing to disambiguate."""
    broken = copy.deepcopy(maps[0])
    broken["fields"][0]["keywords"] = "favourite colour"

    with pytest.raises(AnchorMismatch) as exc:
        verify_labels(both["2021"], broken)
    assert "instance" not in str(exc.value)


def test_an_empty_instance_anchor_is_refused(tmp_path):
    """Present-but-blank would silently mean "one instance", which is a typo."""
    (tmp_path / "bad.json").write_text(
        json.dumps(
            {
                "form_id": "bad",
                "identify": {"all_of": ["marker"]},
                "instance_anchor": "  ",
                "fields": [{"name": "a", "pii_type": "SSN", "keywords": "k"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="instance_anchor"):
        load_field_maps(tmp_path)
