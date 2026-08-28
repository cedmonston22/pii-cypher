"""Extractor output and field-map geometry, in the shapes detection wants.

Two jobs. ``items`` turns positioned lines into scannable Items. ``geometry``
recovers what the field map already knows about this document -- which boxes
were claimed, which were deliberately dropped, and what this document's
filled-in text looks like -- so the coverage check does not have to guess any
of it from first principles.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

from core.extract import Line
from core.fieldmap import (
    DEFAULT_COL_TOL,
    Field,
    discover_field,
    find_label,
    normalize,
    segment,
)

from detect.types import Item, dense

__all__ = ["Geometry", "geometry", "items", "key_of"]

# How far apart two same-row segments may sit and still be one identifier.
# core.extract already split the row at gaps over its own gap_tol, so this only
# ever rejoins what that split separated.
JOIN_GAP = 25.0

# A segment that could be part of a split identifier: alphanumerics, masking
# characters and the punctuation identifiers actually use.
_JOINABLE = re.compile(r"^[0-9A-Za-z*Xx#-]+$")
_HAS_DIGIT = re.compile(r"\d")


def key_of(page: int, x0: float, top: float) -> tuple[int, float, float]:
    """Position key, rounded exactly as ``fieldmap.propagate`` rounds it.

    Sharing the derivation is what makes "claimed" here and "located" there
    agree by construction rather than by coincidence.
    """
    return (page, round(x0, 1), round(top, 1))


def _to_item(line: Line, source: str = "native_text") -> Item:
    return Item(
        text=line["text"],
        norm=normalize(line["text"]),
        dense=dense(line["text"]),
        page=line["page"],
        bbox=(line["x0"], line["top"], line["x1"], line["bottom"]),
        source=source,
        fontname=line["fontname"],
        size=line["size"],
    )


def _joins(lines: list[Line]) -> Iterator[Item]:
    """Fuse adjacent same-row segments that could be one split identifier.

    A PDF routinely renders ``123-45-6789`` as ``123-45-`` and ``6789`` in
    separate spans, and a regex over either half finds nothing. Joining is
    guarded rather than unconditional: without the shape test, ``General
    partner`` and ``LLC member-manager`` -- 80pt apart on one row of the 2021
    fixture -- fuse into a single item spanning both columns.
    """
    for left, right in zip(lines, lines[1:]):
        if left["page"] != right["page"]:
            continue
        if abs(left["top"] - right["top"]) > 1.5:
            continue
        if not 0 <= right["x0"] - left["x1"] <= JOIN_GAP:
            continue
        if not (_JOINABLE.match(left["text"]) and _JOINABLE.match(right["text"])):
            continue
        if not (_HAS_DIGIT.search(left["text"]) or _HAS_DIGIT.search(right["text"])):
            continue

        text = left["text"] + right["text"]
        yield Item(
            text=text,
            norm=normalize(text),
            dense=dense(text),
            page=left["page"],
            bbox=(left["x0"], min(left["top"], right["top"]),
                  right["x1"], max(left["bottom"], right["bottom"])),
            source="joined",
            fontname=left["fontname"],
            size=left["size"],
        )


def items(pages: list[list[Line]]) -> list[Item]:
    """One Item per line, plus a joined Item per split-identifier candidate."""
    out: list[Item] = []
    for lines in pages:
        out.extend(_to_item(line) for line in lines)
        out.extend(_joins(lines))
    return out


@dataclass(frozen=True, slots=True)
class Geometry:
    """What the field map already established about this document."""

    claimed: frozenset[tuple[int, float, float]]
    skipped: frozenset[tuple[int, float, float]]
    ignored: frozenset[tuple[int, float, float]]
    fill_styles: frozenset[tuple[str, float]]
    label_x0: tuple[float, ...]
    col_tol: float

    def accounted_for(self, item: Item) -> bool:
        """Whether the map already explains this item's position."""
        key = key_of(item["page"], item["bbox"][0], item["bbox"][1])
        return key in self.claimed or key in self.skipped or key in self.ignored

    def is_fill(self, item: Item) -> bool:
        return (item["fontname"], round(item["size"], 1)) in self.fill_styles

    def in_label_column(self, item: Item) -> bool:
        return any(abs(item["bbox"][0] - x0) <= self.col_tol for x0 in self.label_x0)


def geometry(
    pages: list[list[Line]], field_map: dict[str, Any], located: list[Field]
) -> Geometry:
    """Recover the map's own geometry, including the lines it chose to drop.

    ``locate`` discards ``skip_lines`` leaders before returning, so they are
    re-derived here by re-running the public ``find_label`` and
    ``discover_field``. That is a second pass over a page of text, which costs
    nothing, and it means ``core.fieldmap`` needs no change to support any of
    this.

    Both passes are scoped per instance for the same reason ``locate`` is.
    Document-wide, only the first partner's skipped names and ignored boxes are
    recovered, and every later partner's name and IRS service centre resurface
    as unaccounted-for fill. That is not cosmetic: a fitting map is supposed to
    produce no warnings at all, and an audit people learn to ignore is worth
    nothing.
    """
    col_tol = field_map.get("col_tol", DEFAULT_COL_TOL)

    claimed = {key_of(f["page"], f["bbox"][0], f["bbox"][1]) for f in located}
    fill_styles = {(f["fontname"], round(f["size"], 1)) for f in located}

    instances = segment(pages, field_map)
    skipped: set[tuple[int, float, float]] = set()
    ignored: set[tuple[int, float, float]] = set()
    label_x0: list[float] = []

    for instance in instances:
        for spec in field_map["fields"]:
            label = find_label(pages, spec["keywords"], instance.pages)
            if label is None:
                continue
            label_x0.append(label["x0"])
            box = discover_field(pages, label, col_tol)
            for line in box[: spec.get("skip_lines", 0)]:
                skipped.add(key_of(line["page"], line["x0"], line["top"]))

        for keywords in field_map.get("ignore", []):
            label = find_label(pages, keywords, instance.pages)
            if label is None:
                continue
            label_x0.append(label["x0"])
            for line in discover_field(pages, label, col_tol):
                ignored.add(key_of(line["page"], line["x0"], line["top"]))

    return Geometry(
        claimed=frozenset(claimed),
        skipped=frozenset(skipped),
        ignored=frozenset(ignored),
        fill_styles=frozenset(fill_styles),
        label_x0=tuple(sorted(set(label_x0))),
        col_tol=col_tol,
    )
