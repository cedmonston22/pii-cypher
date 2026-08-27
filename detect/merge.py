"""Combine the detectors into one list, and grade what comes out.

Three detectors see the same document from different angles, so the same value
arrives more than once by design. That agreement is the point -- it is what
separates a candidate worth acting on from a shape that happened to match --
but only if the duplicates are collapsed into one candidate carrying all of the
reasons rather than emitted three times.
"""

from __future__ import annotations

from core.extract import Line

from detect.adapter import Geometry
from detect.types import Candidate, Item, dense

__all__ = ["PRECEDENCE", "merge"]

# Most specific first. Two candidates whose values nest inside one another keep
# the earlier entry: an address line that also contains a locality stays one
# ADDRESS rather than becoming an ADDRESS plus whatever matched inside it.
PRECEDENCE: tuple[str, ...] = (
    "ITIN",
    "SSN",
    "EIN",
    "DOB",
    "PHONE",
    "ADDRESS",
)

_RANK = {name: index for index, name in enumerate(PRECEDENCE)}


def _rank(candidate: Candidate) -> int:
    # An untyped structural finding always loses to a typed one covering the
    # same box: "there is data here" is strictly weaker than naming it.
    return _RANK.get(candidate.pii_type or "", len(PRECEDENCE))


def _overlaps(a: Candidate, b: Candidate) -> bool:
    if a.page != b.page:
        return False
    ax0, atop, ax1, abottom = a.bbox
    bx0, btop, bx1, bbottom = b.bbox
    return not (ax1 < bx0 or bx1 < ax0 or abottom < btop or bbottom < atop)


def _nests(a: Candidate, b: Candidate) -> bool:
    da, db = dense(a.value), dense(b.value)
    return da in db or db in da


def _resolve_overlaps(candidates: list[Candidate]) -> list[Candidate]:
    """Drop a candidate that another, more specific one already covers.

    Without an explicit rule here the ZIP inside a located address surfaces
    alongside the address itself. Under a warning-only pass that is noise; the
    moment anything downstream acts on a candidate it is a double-replacement
    that corrupts the document.
    """
    kept: list[Candidate] = []
    for candidate in sorted(candidates, key=lambda c: (_rank(c), -len(c.value))):
        if any(
            _overlaps(candidate, other) and _nests(candidate, other)
            for other in kept
        ):
            continue
        kept.append(candidate)
    return kept


def _dedupe(candidates: list[Candidate]) -> list[Candidate]:
    """One candidate per value, carrying every reason it was found.

    Keyed on the dense value so ``512-44-8890`` and ``512 44 8890`` collapse.
    The strongest confidence wins and the pages are recorded as evidence, which
    is how a value repeated in a footer stops being a second finding and starts
    being corroboration of the first.
    """
    order = {"low": 0, "medium": 1, "high": 2}
    merged: dict[tuple[str | None, str], Candidate] = {}

    for candidate in candidates:
        key = (candidate.pii_type, dense(candidate.value))
        existing = merged.get(key)
        if existing is None:
            merged[key] = candidate
            continue

        evidence = list(existing.evidence)
        for reason in candidate.evidence:
            if reason not in evidence:
                evidence.append(reason)
        if candidate.page != existing.page:
            repeat = f"repeat:p{candidate.page}"
            if repeat not in evidence:
                evidence.append(repeat)

        best = max(existing, candidate, key=lambda c: order[c.confidence])
        merged[key] = Candidate(
            value=existing.value,
            pii_type=existing.pii_type,
            page=existing.page,
            bbox=existing.bbox,
            evidence=tuple(evidence),
            confidence=best.confidence,
        )

    return list(merged.values())


def _promote_repeats(candidates: list[Candidate], items: list[Item]) -> list[Candidate]:
    """Record every other place a confirmed value appears.

    Most real misses are a known value on a continuation page or in a footer,
    not an exotic undetected format.
    """
    by_dense = {dense(c.value): c for c in candidates if c.value}
    seen: dict[str, set[int]] = {}

    for item in items:
        for key, candidate in by_dense.items():
            if key and key in item["dense"] and item["page"] != candidate.page:
                seen.setdefault(key, set()).add(item["page"])

    out: list[Candidate] = []
    for candidate in candidates:
        pages = sorted(seen.get(dense(candidate.value), ()))
        if not pages:
            out.append(candidate)
            continue
        evidence = candidate.evidence + tuple(f"repeat:p{p}" for p in pages)
        out.append(
            Candidate(
                value=candidate.value,
                pii_type=candidate.pii_type,
                page=candidate.page,
                bbox=candidate.bbox,
                evidence=tuple(dict.fromkeys(evidence)),
                confidence=candidate.confidence,
            )
        )
    return out


def merge(
    groups: list[list[Candidate]],
    items: list[Item],
    pages: list[list[Line]],
    geo: Geometry,
) -> list[Candidate]:
    """Everything the detectors found, deduplicated and corroborated."""
    from detect.labels import corroborate

    item_by_box = {(item["page"], item["bbox"]): item for item in items}

    flat = [c for group in groups for c in group]
    corroborated = [corroborate(c, pages, geo, item_by_box) for c in flat]
    resolved = _resolve_overlaps(corroborated)
    deduped = _dedupe(resolved)
    return sorted(
        _promote_repeats(deduped, items),
        key=lambda c: (c.page, c.bbox[1], c.bbox[0]),
    )
