"""Batch scrub and selective restore, end to end on the real fixture."""

import pymupdf
import pytest

from core import vault
from core.crypto import token_hash
from core.extract import extract_lines
from core.fieldmap import identify, load_field_maps, locate, propagate
from core.keys import unwrap
from core.pipeline import (
    DEFAULT_POLICY,
    identify_job,
    MAX_FILES,
    BatchTooLarge,
    NotAPdf,
    PolicyMismatch,
    accept_batch,
    match_document,
    restore_batch,
    scrub_batch,
)
from core.tokens import find_tokens
from core.verify import extract_all_text

K1_VALUES = [
    "00-0000000",
    "456 SAMPLE AVE",
    "DENVER, CO 80202",
    "000-00-0000",
    "123 EXAMPLE LANE",
    "AUSTIN, TX 78701",
]
NAMES_KEPT = ["DEMO HARBOR PARTNERS LP", "ALEX TESTER"]


@pytest.fixture
def db(tmp_path):
    return vault.connect(str(tmp_path / "vault.db"))


def _variant(pdf_bytes: bytes, swaps: dict[str, str]) -> bytes:
    """Produce a second document at the same coordinates with different values.

    Built by rewriting the fixture in place so the two-column collisions that
    make this form interesting are preserved exactly.
    """
    from core.redact import redact

    pages = extract_lines(pdf_bytes)
    field_map = identify(pages, load_field_maps())
    fields = [f for f in propagate(pages, locate(pages, field_map)) if f["value"] in swaps]
    return redact(pdf_bytes, fields, swaps)


def _blank_pdf() -> bytes:
    doc = pymupdf.open()
    doc.new_page()
    return doc.tobytes()


def _text_pdf(text: str) -> bytes:
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), text, fontsize=11)
    return doc.tobytes()


def test_accept_rejects_non_pdf():
    with pytest.raises(NotAPdf):
        accept_batch([("x.pdf", b"not a pdf at all")])


def test_accept_rejects_oversized_batch(k1_bytes):
    with pytest.raises(BatchTooLarge):
        accept_batch([(f"{i}.pdf", k1_bytes) for i in range(MAX_FILES + 1)])


def test_accept_rejects_empty_batch():
    with pytest.raises(BatchTooLarge):
        accept_batch([])


def test_scrub_removes_values_and_keeps_names(db, k1_bytes):
    result = scrub_batch(db, [("k1.pdf", k1_bytes)])
    assert not result.quarantined
    doc = result.scrubbed[0]
    assert doc.form_id == "us-1065-k1"
    assert doc.replaced_count == len(K1_VALUES)

    text = extract_all_text(doc.pdf_bytes)
    for value in K1_VALUES:
        assert value not in text
    for name in NAMES_KEPT:
        assert name in text, "names are out of policy and must survive"
    assert "OGDEN, UT" in text, "unmapped fields must not be touched"


def test_job_and_document_recorded(db, k1_bytes):
    result = scrub_batch(db, [("k1.pdf", k1_bytes)])
    job = vault.get_job(db, result.job_id)
    assert job["status"] == "scrubbed"
    assert job["policy"] == DEFAULT_POLICY

    docs = vault.list_documents(db, result.job_id)
    assert len(docs) == 1
    assert docs[0].status == "scrubbed"
    assert len(docs[0].token_hashes) == len(K1_VALUES)

    job_key = unwrap(vault.get_wrapped_key(db, result.job_id))
    assert vault.document_filename(db, docs[0].id, job_key) == "k1.pdf"


def test_shared_value_gets_one_token_across_the_batch(db, k1_bytes):
    """The reason token_map lives at job level, and the easiest thing to break.

    Two documents share a partner (same SSN and address) but differ in the
    partnership. The shared values must resolve to one token and one vault row.
    """
    other = _variant(k1_bytes, {"00-0000000": "11-1111111", "456 SAMPLE AVE": "789 SAMPLE WAY"})
    result = scrub_batch(db, [("a.pdf", k1_bytes), ("b.pdf", other)])
    assert not result.quarantined, result.quarantined
    assert len(result.scrubbed) == 2

    tokens_a = set(find_tokens(extract_lines(result.scrubbed[0].pdf_bytes)))
    tokens_b = set(find_tokens(extract_lines(result.scrubbed[1].pdf_bytes)))

    shared = tokens_a & tokens_b
    assert len(shared) == 4, "SSN, city/state/zip and both partner address lines are shared"

    # Nine distinct values across the batch: 6 in the first, 2 changed in the second.
    rows = db.execute(
        "SELECT COUNT(*) FROM vault_entries WHERE job_id = ?", (result.job_id,)
    ).fetchone()[0]
    assert rows == len(tokens_a | tokens_b)
    assert rows == 8


def test_one_bad_file_does_not_sink_the_batch(db, k1_bytes):
    files = [
        ("good1.pdf", k1_bytes),
        ("scan.pdf", _blank_pdf()),
        ("stranger.pdf", _text_pdf("An invoice, not a tax form")),
        ("good2.pdf", _variant(k1_bytes, {"000-00-0000": "111-11-1111"})),
    ]
    result = scrub_batch(db, files)

    assert [d.filename for d in result.scrubbed] == ["good1.pdf", "good2.pdf"]
    assert [d.filename for d in result.quarantined] == ["scan.pdf", "stranger.pdf"]
    assert "NoTextLayer" in result.quarantined[0].reason
    assert "UnknownForm" in result.quarantined[1].reason

    statuses = {d.status for d in vault.list_documents(db, result.job_id)}
    assert statuses == {"scrubbed", "quarantined"}


def test_restore_returns_every_value(db, k1_bytes):
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    scrubbed = batch.scrubbed[0]

    result = restore_batch(db, [("k1-scrubbed.pdf", scrubbed.pdf_bytes)], batch.job_id)
    assert not result.unmatched
    restored = result.restored[0]
    assert restored.tokens_found == len(K1_VALUES)
    assert restored.tokens_resolved == len(K1_VALUES)
    assert restored.unresolved == []

    text = extract_all_text(restored.pdf_bytes)
    for value in K1_VALUES:
        assert value in text


def test_restored_page_is_pixel_identical_to_the_original(db, k1_bytes):
    """The strongest fidelity claim available: render both and compare.

    Holds because replacements are drawn in the source's own face, weight, size,
    colour and baseline. A document using an embedded font outside the base-14
    set would be mapped to the nearest base-14 face and would not reach this bar.
    """
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    restored = restore_batch(
        db, [("k1.pdf", batch.scrubbed[0].pdf_bytes)], batch.job_id
    ).restored[0].pdf_bytes

    before = pymupdf.open(stream=k1_bytes, filetype="pdf")[0].get_pixmap(dpi=150)
    after = pymupdf.open(stream=restored, filetype="pdf")[0].get_pixmap(dpi=150)

    assert (before.width, before.height) == (after.width, after.height)
    assert before.samples == after.samples, "restored page does not render identically"


def test_scrubbed_tokens_match_the_styling_they_replace(db, k1_bytes):
    """Tokens must not read as foreign text pasted into the form."""
    original = {
        span["text"].strip(): span
        for block in pymupdf.open(stream=k1_bytes, filetype="pdf")[0].get_text("dict")["blocks"]
        for line in block.get("lines", [])
        for span in line.get("spans", [])
    }
    scrubbed = scrub_batch(db, [("k1.pdf", k1_bytes)]).scrubbed[0].pdf_bytes
    tokens = [
        span
        for block in pymupdf.open(stream=scrubbed, filetype="pdf")[0].get_text("dict")["blocks"]
        for line in block.get("lines", [])
        for span in line.get("spans", [])
        if span["text"].strip().startswith("PII-")
    ]
    assert len(tokens) == len(K1_VALUES)

    # Every value on this form is bold; the EIN and SSN are 10pt, addresses 9pt.
    for span in tokens:
        assert span["font"] == "Helvetica-Bold"
        assert span["size"] in (pytest.approx(9.0), pytest.approx(10.0))

    ssn = original["000-00-0000"]
    replacement = next(t for t in tokens if t["origin"] == pytest.approx(ssn["origin"], abs=0.1))
    assert replacement["size"] == pytest.approx(ssn["size"], abs=0.1)


def test_restore_matches_a_renamed_file(db, k1_bytes):
    batch = scrub_batch(db, [("original-name.pdf", k1_bytes)])
    result = restore_batch(db, [("totally-different.pdf", batch.scrubbed[0].pdf_bytes)], batch.job_id)

    assert result.restored[0].doc_id == batch.scrubbed[0].doc_id
    assert vault.list_documents(db, batch.job_id)[0].status == "restored"


def test_selective_restore_leaves_others_restorable(db, k1_bytes):
    """Restoring one document must not consume or alter the others."""
    second = _variant(k1_bytes, {"00-0000000": "11-1111111"})
    third = _variant(k1_bytes, {"000-00-0000": "222-22-2222"})
    batch = scrub_batch(db, [("a.pdf", k1_bytes), ("b.pdf", second), ("c.pdf", third)])
    assert len(batch.scrubbed) == 3

    middle = batch.scrubbed[1]
    first_pass = restore_batch(db, [("b.pdf", middle.pdf_bytes)], batch.job_id)
    assert first_pass.restored[0].tokens_resolved == first_pass.restored[0].tokens_found

    statuses = {d.id: d.status for d in vault.list_documents(db, batch.job_id)}
    assert statuses[middle.doc_id] == "restored"
    assert statuses[batch.scrubbed[0].doc_id] == "scrubbed"

    # The untouched documents still restore fully afterwards.
    for doc in (batch.scrubbed[0], batch.scrubbed[2]):
        again = restore_batch(db, [(doc.filename, doc.pdf_bytes)], batch.job_id)
        entry = again.restored[0]
        assert entry.unresolved == []
        assert entry.tokens_resolved == entry.tokens_found


def test_file_is_not_attributed_to_the_wrong_job(db, k1_bytes):
    """Pinning a restore to the wrong batch must refuse, not half-restore.

    The tokens are real, but they belong to another job. Filtering to the wrong
    one has to say so rather than reporting six unresolvable tokens, which reads
    like a tool failure instead of a mismatch.
    """
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    other = scrub_batch(db, [("k1.pdf", k1_bytes)])
    scrubbed = batch.scrubbed[0].pdf_bytes

    wrong = restore_batch(db, [("k1.pdf", scrubbed)], other.job_id)
    assert not wrong.restored
    assert "not in this vault" in wrong.unmatched[0].reason

    # and with no job given, it finds its own
    right = restore_batch(db, [("k1.pdf", scrubbed)])
    assert right.restored[0].job_id == batch.job_id
    assert right.restored[0].unresolved == []


def test_a_token_the_vault_does_not_know_is_left_in_place(db, k1_bytes):
    """Partial resolution: a value dropped from the vault stays tokenised."""
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    scrubbed = batch.scrubbed[0].pdf_bytes

    victim = find_tokens(extract_lines(scrubbed))[0]
    db.execute(
        "DELETE FROM vault_entries WHERE job_id = ? AND token_hash = ?",
        (batch.job_id, token_hash(victim)),
    )
    db.commit()

    result = restore_batch(db, [("k1.pdf", scrubbed)])
    doc = result.restored[0]
    assert doc.unresolved == [victim]
    assert doc.tokens_resolved == doc.tokens_found - 1
    assert victim in extract_all_text(doc.pdf_bytes), "unresolved tokens stay in place"


def test_file_without_tokens_is_unmatched(db, k1_bytes):
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    result = restore_batch(db, [("plain.pdf", k1_bytes)], batch.job_id)
    assert not result.restored
    assert "no tokens found" in result.unmatched[0].reason


def test_match_document_prefers_the_right_document(db, k1_bytes):
    """Jaccard, not recall: a subset document must not win against a superset."""
    second = _variant(k1_bytes, {"00-0000000": "11-1111111", "456 SAMPLE AVE": "789 SAMPLE WAY"})
    batch = scrub_batch(db, [("a.pdf", k1_bytes), ("b.pdf", second)])

    for doc in batch.scrubbed:
        assert match_document(db, batch.job_id, doc.pdf_bytes) == doc.doc_id


def test_expired_job_is_reported_not_silently_dropped(db, k1_bytes):
    """An expired batch must name itself, not leave tokens in an unresolved list.

    Burying expiry among unresolved tokens reads as "the tool failed" rather
    than "this batch aged out", which are very different things to a user.
    """
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    db.execute(
        "UPDATE jobs SET expires_at = ? WHERE id = ?", ("2000-01-01T00:00:00+00:00", batch.job_id)
    )
    db.commit()

    result = restore_batch(db, [("k1.pdf", batch.scrubbed[0].pdf_bytes)])
    assert not result.restored
    assert "expired" in result.unmatched[0].reason



# --------------------------------------------------------------------------
# cross-revision batches: one concept map, two form generations
# --------------------------------------------------------------------------

K1_2025_VALUES = [
    "45-1234567",
    "456 SAMPLE AVE",
    "DENVER, CO 80202",
    "512-44-8890",
    "123 EXAMPLE LANE",
    "AUSTIN, TX 78701",
]


def test_both_revisions_scrub_in_one_batch(db, k1_bytes, k1_2025_bytes):
    """The 2025 form used to quarantine as UnknownForm. Same map now covers both."""
    result = scrub_batch(db, [("k1-2021.pdf", k1_bytes), ("k1-2025.pdf", k1_2025_bytes)])
    assert not result.quarantined, result.quarantined
    assert len(result.scrubbed) == 2
    assert {d.form_id for d in result.scrubbed} == {"us-1065-k1"}

    for doc, values in zip(result.scrubbed, (K1_VALUES, K1_2025_VALUES)):
        assert doc.replaced_count == len(values)
        text = extract_all_text(doc.pdf_bytes)
        for value in values:
            assert value not in text, f"{doc.filename}: {value!r} survived"
        for name in NAMES_KEPT:
            assert name in text, f"{doc.filename}: names are out of policy"


def test_shared_partner_across_revisions_gets_one_token(db, k1_bytes, k1_2025_bytes):
    """Both fixtures describe the same partner at the same address.

    The addresses are shared, the EIN and SSN differ. Token sharing must work
    across form revisions, not just across copies of one revision.
    """
    result = scrub_batch(db, [("a.pdf", k1_bytes), ("b.pdf", k1_2025_bytes)])
    tokens_a = set(find_tokens(extract_lines(result.scrubbed[0].pdf_bytes)))
    tokens_b = set(find_tokens(extract_lines(result.scrubbed[1].pdf_bytes)))

    assert len(tokens_a & tokens_b) == 4, "both address blocks are shared"
    rows = db.execute(
        "SELECT COUNT(*) FROM vault_entries WHERE job_id = ?", (result.job_id,)
    ).fetchone()[0]
    assert rows == len(tokens_a | tokens_b) == 8


def test_restore_works_across_revisions(db, k1_bytes, k1_2025_bytes):
    batch = scrub_batch(db, [("a.pdf", k1_bytes), ("b.pdf", k1_2025_bytes)])
    for doc, values in zip(batch.scrubbed, (K1_VALUES, K1_2025_VALUES)):
        result = restore_batch(db, [(doc.filename, doc.pdf_bytes)], batch.job_id)
        restored = result.restored[0]
        assert restored.unresolved == []
        text = extract_all_text(restored.pdf_bytes)
        for value in values:
            assert value in text


def test_2025_restore_is_pixel_identical(db, k1_2025_bytes):
    """The fidelity guarantee has to hold on the revision it was not tuned against."""
    batch = scrub_batch(db, [("k1.pdf", k1_2025_bytes)])
    restored = restore_batch(
        db, [("k1.pdf", batch.scrubbed[0].pdf_bytes)], batch.job_id
    ).restored[0].pdf_bytes

    before = pymupdf.open(stream=k1_2025_bytes, filetype="pdf")[0].get_pixmap(dpi=150)
    after = pymupdf.open(stream=restored, filetype="pdf")[0].get_pixmap(dpi=150)
    assert before.samples == after.samples


def test_no_coverage_warnings_when_the_map_fits(db, k1_bytes, k1_2025_bytes):
    result = scrub_batch(db, [("a.pdf", k1_bytes), ("b.pdf", k1_2025_bytes)])
    assert all(doc.warnings == [] for doc in result.scrubbed)


def test_stale_map_produces_a_coverage_warning(db, k1_bytes):
    """A field the map stops describing must surface, not pass through silently."""
    import copy

    from core.fieldmap import load_field_maps

    stale = copy.deepcopy(load_field_maps()[0])
    stale["fields"] = [f for f in stale["fields"] if f["name"] != "partner_tin"]

    result = scrub_batch(db, [("k1.pdf", k1_bytes)], field_maps=[stale])
    doc = result.scrubbed[0]

    assert doc.warnings, "the dropped SSN field must be reported"
    assert any("000-00-0000" in w for w in doc.warnings)
    # and it really did survive into the output, which is what the warning is about
    assert "000-00-0000" in extract_all_text(doc.pdf_bytes)


# --------------------------------------------------------------------------
# self-identifying restore: the file knows which batch it came from
# --------------------------------------------------------------------------


def test_identify_job_finds_the_right_batch_among_several(db, k1_bytes, k1_2025_bytes):
    """Three batches in the vault; each document still names its own."""
    a = scrub_batch(db, [("a.pdf", k1_bytes)])
    b = scrub_batch(db, [("b.pdf", k1_2025_bytes)])
    c = scrub_batch(db, [("c.pdf", k1_bytes)])

    for batch in (a, b, c):
        match = identify_job(db, batch.scrubbed[0].pdf_bytes)
        assert match.job_id == batch.job_id
        assert match.resolved == len(match.tokens)
        assert match.other_jobs == [], "tokens must not be shared between batches"
        assert match.reason is None


def test_identify_job_reports_why_it_failed(db, k1_bytes):
    """Distinct reasons: nothing to go on vs tokens from somewhere else."""
    scrub_batch(db, [("k1.pdf", k1_bytes)])

    unscrubbed = identify_job(db, k1_bytes)
    assert unscrubbed.job_id is None
    assert "no tokens found" in unscrubbed.reason

    import pymupdf

    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "PII-ABC23456", fontsize=10)
    foreign = identify_job(db, doc.tobytes())
    assert foreign.job_id is None
    assert foreign.tokens == ["PII-ABC23456"]
    assert "not in this vault" in foreign.reason


def test_restore_needs_no_job_id(db, k1_bytes):
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    result = restore_batch(db, [("whatever-they-renamed-it.pdf", batch.scrubbed[0].pdf_bytes)])

    doc = result.restored[0]
    assert doc.job_id == batch.job_id
    assert doc.original_filename == "k1.pdf", "the report names what it used to be called"
    assert doc.unresolved == []
    assert extract_all_text(doc.pdf_bytes).count("000-00-0000") >= 1


def test_one_upload_spans_several_batches(db, k1_bytes, k1_2025_bytes):
    """The point of the change, and the easiest thing to regress.

    Three files, three separate jobs, one upload, no job id anywhere.
    """
    a = scrub_batch(db, [("a.pdf", k1_bytes)])
    b = scrub_batch(db, [("b.pdf", k1_2025_bytes)])
    c = scrub_batch(db, [("c.pdf", k1_bytes)])

    result = restore_batch(
        db,
        [
            ("one.pdf", a.scrubbed[0].pdf_bytes),
            ("two.pdf", b.scrubbed[0].pdf_bytes),
            ("three.pdf", c.scrubbed[0].pdf_bytes),
        ],
    )

    assert not result.unmatched
    assert len(result.restored) == 3
    assert sorted(result.jobs) == sorted({a.job_id, b.job_id, c.job_id})

    by_name = {d.filename: d for d in result.restored}
    assert by_name["one.pdf"].job_id == a.job_id
    assert by_name["two.pdf"].job_id == b.job_id
    assert by_name["three.pdf"].job_id == c.job_id
    for doc in result.restored:
        assert doc.unresolved == []
        assert doc.tokens_resolved == doc.tokens_found


def test_document_assembled_from_two_batches_restores_fully(db, k1_bytes):
    """Resolution is per token, so a merged file is not half-unresolvable.

    Pages from two jobs are concatenated. A document-level lookup would resolve
    one page and report the other's tokens as strangers.
    """
    import pymupdf

    a = scrub_batch(db, [("a.pdf", k1_bytes)])
    b = scrub_batch(db, [("b.pdf", k1_bytes)])

    merged = pymupdf.open()
    for source in (a.scrubbed[0].pdf_bytes, b.scrubbed[0].pdf_bytes):
        merged.insert_pdf(pymupdf.open(stream=source, filetype="pdf"))
    blended = merged.tobytes()

    match = identify_job(db, blended)
    assert match.other_jobs, "this file genuinely spans two batches"

    result = restore_batch(db, [("merged.pdf", blended)])
    doc = result.restored[0]
    assert doc.unresolved == [], "tokens from the second batch must resolve too"
    assert doc.tokens_resolved == doc.tokens_found == 12


def test_explicit_job_id_still_filters(db, k1_bytes):
    """The override remains available for a caller that already knows the batch."""
    a = scrub_batch(db, [("a.pdf", k1_bytes)])
    b = scrub_batch(db, [("b.pdf", k1_bytes)])

    result = restore_batch(
        db,
        [("a.pdf", a.scrubbed[0].pdf_bytes), ("b.pdf", b.scrubbed[0].pdf_bytes)],
        a.job_id,
    )
    assert [d.filename for d in result.restored] == ["a.pdf"]
    assert [d.filename for d in result.unmatched] == ["b.pdf"]


def test_a_policy_matching_no_field_is_quarantined_not_reported_scrubbed(db, k1_bytes):
    """A policy in a different vocabulary must not pass as a clean scrub.

    Without this guard the filter empties the field list, ``redact`` draws
    nothing, and both release gates pass vacuously -- there is no surviving
    value among no values, and no missing token among no tokens. The batch was
    reported as scrubbed while the document still carried every identifier.
    """
    result = scrub_batch(db, [("k1.pdf", k1_bytes)], policy={"pii_types": ["ssn_tin", "ein"]})

    assert result.scrubbed == []
    assert len(result.quarantined) == 1
    assert "PolicyMismatch" in result.quarantined[0].reason


def test_the_mismatch_reason_names_both_vocabularies(db, k1_bytes):
    """The failure has to be self-explanatory: drift is invisible otherwise."""
    result = scrub_batch(db, [("k1.pdf", k1_bytes)], policy={"pii_types": ["ssn_tin"]})

    reason = result.quarantined[0].reason
    assert "'ssn_tin'" in reason, "the reason must show what the policy asked for"
    assert "'SSN'" in reason, "and what the map actually describes"
    assert "us-1065-k1" in reason


def test_a_deliberately_narrow_policy_still_scrubs(db, k1_bytes):
    """Sharing one type is enough. Narrow is not the same as mismatched."""
    result = scrub_batch(db, [("k1.pdf", k1_bytes)], policy={"pii_types": ["EIN"]})

    assert len(result.scrubbed) == 1
    doc = result.scrubbed[0]
    assert doc.replaced_count == 1

    text = extract_all_text(doc.pdf_bytes)
    assert "00-0000000" not in text
    assert "000-00-0000" in text, "an out-of-policy value must be left alone"
