"""Per-type recall and review rate for the detection package.

Run it: ``python -m eval.runner``

Two rules shape the output. Recall is reported **per type**, never aggregated,
because an overall 97% can be SSN at 100 and ADDRESS at 88 and the second number
is the one that matters. And review rate sits beside recall, because a detector
with excellent recall and a forty-percent review rate is not usable by anyone.

Confidence tiers are measured here, not asserted. A tier means something only
once a corpus has said what it means; a threshold written in advance is the
detector grading its own work.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.extract import NoTextLayer, extract_lines
from core.fieldmap import (
    AnchorMismatch,
    UnknownForm,
    identify,
    load_field_maps,
    locate,
    propagate,
)
from core.piitypes import PII_TYPES
from detect import detect
from detect.types import dense

EVAL_DIR = Path(__file__).resolve().parent
CORPUS = EVAL_DIR / "corpus"
KEYS = EVAL_DIR / "keys"

ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class TypeScore:
    planted: int = 0
    found: int = 0
    reported: int = 0

    @property
    def recall(self) -> float | None:
        return None if not self.planted else self.found / self.planted


@dataclass
class Result:
    documents: int = 0
    failures: list[str] = field(default_factory=list)
    by_type: dict[str, TypeScore] = field(default_factory=dict)
    gaps_planted: int = 0
    gaps_found: int = 0
    surfaced: int = 0
    hard_false_positives: list[str] = field(default_factory=list)
    tiers: dict[str, dict[str, int]] = field(default_factory=dict)

    @property
    def review_rate(self) -> float:
        return 0.0 if not self.documents else self.surfaced / self.documents

    def precision(self, tier: str) -> float | None:
        counts = self.tiers.get(tier)
        if not counts or not counts["n"]:
            return None
        return counts["real"] / counts["n"]


def _matches(value: str, surfaces: list[str]) -> bool:
    """A candidate matches an expected value on any of its renderings.

    Comparison is on the whitespace-stripped form so the answer key does not
    have to predict how extraction spaced the value out.
    """
    target = dense(value).lower()
    return any(dense(s).lower() == target for s in surfaces)


def _score_document(pdf: Path, key: dict[str, Any], result: Result) -> None:
    pages = extract_lines(pdf.read_bytes())
    field_maps = load_field_maps()
    field_map = identify(pages, field_maps)
    located = propagate(pages, locate(pages, field_map))
    report = detect(pages, field_map=field_map, located=located)

    values = [c.value for c in report.candidates]
    result.surfaced += len(report.unclaimed)

    for expected in key.get("expected", []):
        pii_type = expected["pii_type"]
        if pii_type not in PII_TYPES:
            result.failures.append(f"{pdf.name}: unknown type {pii_type!r} in answer key")
            continue

        score = result.by_type.setdefault(pii_type, TypeScore())
        score.planted += 1

        surfaces = expected.get("surface") or [expected["value"]]
        hit = any(_matches(v, surfaces) for v in values)
        if hit:
            score.found += 1

        # A gap is a value no map field claims. Those are the only entries that
        # say whether the coverage layer earns a quarantine gate, so they are
        # counted apart from the sanity floor of "would detection have found
        # what location already found".
        if expected.get("field") is None:
            result.gaps_planted += 1
            if any(_matches(c.value, surfaces) for c in report.unclaimed):
                result.gaps_found += 1

    for candidate in report.candidates:
        if candidate.pii_type:
            result.by_type.setdefault(candidate.pii_type, TypeScore()).reported += 1

    planted_surfaces = [
        s for e in key.get("expected", []) for s in (e.get("surface") or [e["value"]])
    ]
    for candidate in report.candidates:
        tier = result.tiers.setdefault(candidate.confidence, {"n": 0, "real": 0})
        tier["n"] += 1
        if _matches(candidate.value, planted_surfaces):
            tier["real"] += 1

    for distractor in key.get("distractors", []):
        text = distractor["text"] if isinstance(distractor, dict) else distractor
        if any(_matches(c.value, [text]) for c in report.unclaimed):
            result.hard_false_positives.append(f"{pdf.name}: {text!r}")


def run(corpus: Path = CORPUS, keys: Path = KEYS) -> Result:
    """Score every document that has an answer key."""
    result = Result()
    if not corpus.is_dir():
        return result

    for pdf in sorted(corpus.glob("*.pdf")):
        key_path = keys / f"{pdf.stem}.key.json"
        if not key_path.is_file():
            result.failures.append(f"{pdf.name}: no answer key at {key_path.name}")
            continue

        key = json.loads(key_path.read_text(encoding="utf-8"))
        result.documents += 1
        try:
            _score_document(pdf, key, result)
        except (NoTextLayer, UnknownForm, AnchorMismatch) as exc:
            # Quarantine is a real outcome, not a crash. Record it and keep
            # going: one unreadable document must not sink the measurement.
            result.failures.append(f"{pdf.name}: {type(exc).__name__}: {exc}")

    return result


def render(result: Result) -> str:
    if not result.documents:
        return (
            "No corpus present.\n\n"
            f"Put synthetic PDFs in {CORPUS} and an answer key per document in\n"
            f"{KEYS}, named <document>.key.json. See eval/README.md for the schema\n"
            "and for the nine cases the corpus needs to cover."
        )

    lines = [
        f"{result.documents} documents",
        "",
        f"{'type':<14}{'planted':>9}{'found':>7}{'recall':>9}{'reported':>10}",
    ]
    for pii_type in sorted(result.by_type):
        score = result.by_type[pii_type]
        recall = "-" if score.recall is None else f"{score.recall:.0%}"
        lines.append(
            f"{pii_type:<14}{score.planted:>9}{score.found:>7}{recall:>9}{score.reported:>10}"
        )

    lines += ["", f"coverage gaps: {result.gaps_found}/{result.gaps_planted} surfaced"]
    lines.append(f"review rate:   {result.review_rate:.1f} warnings per document")
    lines.append(f"hard false positives: {len(result.hard_false_positives)}")
    for entry in result.hard_false_positives:
        lines.append(f"   {entry}")

    lines += ["", f"{'tier':<10}{'n':>6}{'precision':>12}"]
    for tier in ("high", "medium", "low"):
        precision = result.precision(tier)
        if precision is None:
            continue
        lines.append(f"{tier:<10}{result.tiers[tier]['n']:>6}{precision:>11.0%}")

    if result.failures:
        lines += ["", "failures:"]
        lines += [f"   {f}" for f in result.failures]

    return "\n".join(lines)


def main(argv: list[str]) -> int:
    result = run()
    if "--json" in argv:
        print(
            json.dumps(
                {
                    "documents": result.documents,
                    "recall": {t: s.recall for t, s in result.by_type.items()},
                    "review_rate": result.review_rate,
                    "gaps": [result.gaps_found, result.gaps_planted],
                    "hard_false_positives": result.hard_false_positives,
                    "failures": result.failures,
                },
                indent=2,
            )
        )
    else:
        print(render(result))
    return 1 if result.hard_false_positives or result.failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
