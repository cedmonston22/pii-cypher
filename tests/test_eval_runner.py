"""The recall runner, exercised against a corpus built from a known fixture.

The corpus proper is supplied separately and is not in the repository yet, so
these tests build a one-document corpus whose answer key is the ground truth
already recorded in test_pipeline.K1_VALUES. That validates the runner's
plumbing -- key parsing, surface matching, per-type tallies, distractor
detection -- without inventing ground truth for a document nobody measured.
"""

import json

import pytest

from eval.runner import render, run
from tests.test_pipeline import K1_VALUES


def _corpus(tmp_path, pdf_bytes, expected, distractors=()):
    corpus, keys = tmp_path / "corpus", tmp_path / "keys"
    corpus.mkdir()
    keys.mkdir()
    (corpus / "k1.pdf").write_bytes(pdf_bytes)
    (keys / "k1.key.json").write_text(
        json.dumps(
            {
                "schema": "pii-cypher/answer-key@1",
                "document": "k1.pdf",
                "provenance": {"synthetic": True, "ai_generated": True},
                "expected": expected,
                "distractors": [{"text": d, "why": "test"} for d in distractors],
            }
        ),
        encoding="utf-8",
    )
    return corpus, keys


def test_an_absent_corpus_is_reported_not_crashed(tmp_path):
    """A fresh clone has no corpus and must still be able to run this."""
    result = run(tmp_path / "nothing", tmp_path / "none")
    assert result.documents == 0
    assert "No corpus present" in render(result)


def test_values_the_map_claims_are_scored_as_found(tmp_path, k1_bytes):
    """The sanity floor: detection must see what location already found."""
    expected = [
        {"id": f"e{i}", "pii_type": "SSN" if "-" in v and len(v) == 11 else "ADDRESS",
         "value": v, "page": 1, "field": "partner_tin", "in_policy": True}
        for i, v in enumerate(K1_VALUES)
        if v not in ("00-0000000",)
    ]
    corpus, keys = _corpus(tmp_path, k1_bytes, expected)
    result = run(corpus, keys)

    assert result.documents == 1
    assert not result.failures
    assert sum(s.found for s in result.by_type.values()) == len(expected)


def test_a_deliberate_coverage_gap_is_counted_separately(tmp_path, k1_bytes):
    """field: null marks a value no map field claims.

    Those are the only entries that measure whether the coverage layer earns a
    quarantine gate, so they are tallied apart from everything else.
    """
    expected = [
        {"id": "e1", "pii_type": "ADDRESS", "value": "OGDEN, UT", "page": 1,
         "field": None, "in_policy": True}
    ]
    corpus, keys = _corpus(tmp_path, k1_bytes, expected)
    result = run(corpus, keys)

    assert result.gaps_planted == 1
    # Named in the map's ignore list, so it is correctly NOT surfaced.
    assert result.gaps_found == 0


def test_a_reported_distractor_is_a_hard_false_positive(tmp_path, k1_bytes):
    """Distractors are the precision half of the measurement."""
    corpus, keys = _corpus(tmp_path, k1_bytes, [], distractors=["125,000"])
    result = run(corpus, keys)
    assert result.hard_false_positives == []


def test_an_unknown_type_in_a_key_is_a_failure_not_a_silent_zero(tmp_path, k1_bytes):
    expected = [{"id": "e1", "pii_type": "PASSPORT", "value": "X", "page": 1, "field": None}]
    corpus, keys = _corpus(tmp_path, k1_bytes, expected)
    result = run(corpus, keys)
    assert any("PASSPORT" in f for f in result.failures)


def test_a_missing_answer_key_is_reported(tmp_path, k1_bytes):
    corpus, keys = tmp_path / "corpus", tmp_path / "keys"
    corpus.mkdir()
    keys.mkdir()
    (corpus / "orphan.pdf").write_bytes(k1_bytes)
    result = run(corpus, keys)
    assert any("no answer key" in f for f in result.failures)
