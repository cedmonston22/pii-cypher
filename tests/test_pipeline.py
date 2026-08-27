"""Batch scrub and selective restore, end to end on the real fixture."""

import pymupdf
import pytest

from core import vault
from core.extract import extract_lines
from core.fieldmap import identify, load_field_maps, locate, propagate
from core.keys import unwrap
from core.pipeline import (
    DEFAULT_POLICY,
    MAX_FILES,
    BatchTooLarge,
    NotAPdf,
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

    result = restore_batch(db, batch.job_id, [("k1-scrubbed.pdf", scrubbed.pdf_bytes)])
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
        db, batch.job_id, [("k1.pdf", batch.scrubbed[0].pdf_bytes)]
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
    result = restore_batch(db, batch.job_id, [("totally-different.pdf", batch.scrubbed[0].pdf_bytes)])

    assert result.restored[0].doc_id == batch.scrubbed[0].doc_id
    assert vault.list_documents(db, batch.job_id)[0].status == "restored"


def test_selective_restore_leaves_others_restorable(db, k1_bytes):
    """Restoring one document must not consume or alter the others."""
    second = _variant(k1_bytes, {"00-0000000": "11-1111111"})
    third = _variant(k1_bytes, {"000-00-0000": "222-22-2222"})
    batch = scrub_batch(db, [("a.pdf", k1_bytes), ("b.pdf", second), ("c.pdf", third)])
    assert len(batch.scrubbed) == 3

    middle = batch.scrubbed[1]
    first_pass = restore_batch(db, batch.job_id, [("b.pdf", middle.pdf_bytes)])
    assert first_pass.restored[0].tokens_resolved == first_pass.restored[0].tokens_found

    statuses = {d.id: d.status for d in vault.list_documents(db, batch.job_id)}
    assert statuses[middle.doc_id] == "restored"
    assert statuses[batch.scrubbed[0].doc_id] == "scrubbed"

    # The untouched documents still restore fully afterwards.
    for doc in (batch.scrubbed[0], batch.scrubbed[2]):
        again = restore_batch(db, batch.job_id, [(doc.filename, doc.pdf_bytes)])
        entry = again.restored[0]
        assert entry.unresolved == []
        assert entry.tokens_resolved == entry.tokens_found


def test_unknown_token_is_reported_not_guessed(db, k1_bytes):
    """A token from another job must be left in place and surfaced."""
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    other = scrub_batch(db, [("k1.pdf", k1_bytes)])

    result = restore_batch(db, other.job_id, [("k1.pdf", batch.scrubbed[0].pdf_bytes)])
    restored = result.restored[0]
    assert restored.tokens_resolved == 0
    assert len(restored.unresolved) == len(K1_VALUES)
    assert restored.doc_id is None, "must not claim a match in the wrong job"

    text = extract_all_text(restored.pdf_bytes)
    for token in restored.unresolved:
        assert token in text, "unresolved tokens stay in place"


def test_file_without_tokens_is_unmatched(db, k1_bytes):
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    result = restore_batch(db, batch.job_id, [("plain.pdf", k1_bytes)])
    assert not result.restored
    assert result.unmatched[0].reason == "no tokens found"


def test_match_document_prefers_the_right_document(db, k1_bytes):
    """Jaccard, not recall: a subset document must not win against a superset."""
    second = _variant(k1_bytes, {"00-0000000": "11-1111111", "456 SAMPLE AVE": "789 SAMPLE WAY"})
    batch = scrub_batch(db, [("a.pdf", k1_bytes), ("b.pdf", second)])

    for doc in batch.scrubbed:
        assert match_document(db, batch.job_id, doc.pdf_bytes) == doc.doc_id


def test_restore_rejects_expired_job(db, k1_bytes):
    batch = scrub_batch(db, [("k1.pdf", k1_bytes)])
    db.execute(
        "UPDATE jobs SET expires_at = ? WHERE id = ?", ("2000-01-01T00:00:00+00:00", batch.job_id)
    )
    db.commit()
    with pytest.raises(vault.JobExpired):
        restore_batch(db, batch.job_id, [("k1.pdf", batch.scrubbed[0].pdf_bytes)])


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
        result = restore_batch(db, batch.job_id, [(doc.filename, doc.pdf_bytes)])
        restored = result.restored[0]
        assert restored.unresolved == []
        text = extract_all_text(restored.pdf_bytes)
        for value in values:
            assert value in text


def test_2025_restore_is_pixel_identical(db, k1_2025_bytes):
    """The fidelity guarantee has to hold on the revision it was not tuned against."""
    batch = scrub_batch(db, [("k1.pdf", k1_2025_bytes)])
    restored = restore_batch(
        db, batch.job_id, [("k1.pdf", batch.scrubbed[0].pdf_bytes)]
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
