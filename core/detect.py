"""Content-pattern audit: PII-shaped text the field map did not claim.

This layer never redacts anything. It exists to make a stale field map speak
instead of failing silently -- if a form revision adds a field the concept map
does not describe, the audit reports it as a coverage warning rather than the
value passing through untouched.

It is deliberately not the detector. Measured against 28 realistic PII variants
these patterns recall about a third: they miss lowercase city lines, addresses
with no house number (``PO BOX 1234``, ``ONE MARKET PLAZA``), foreign postal
formats, unhyphenated and masked SSNs, and every personal name. That is fine for
"you may have missed something" and disqualifying for "this is what I removed",
which is why location is label-driven and this only ever produces warnings.

The patterns are kept tight rather than broad for the same reason: against 38
distractors drawn from tax-form furniture (amounts, dates, line numbers, form
titles) they raise nothing. A noisy audit is one people learn to ignore.
"""

from __future__ import annotations

import re

from core.extract import Line

# Anchored patterns: the whole line must be the value.
LINE_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn_tin": re.compile(r"^\d{3}-\d{2}-\d{4}$"),
    "ein": re.compile(r"^\d{2}-\d{7}$"),
    "address": re.compile(r"^\d+[A-Z]?\s+(?=.*[A-Z]{3})[A-Z0-9 .'#-]+$"),
    "address_locality": re.compile(r"^[A-Z .'-]+,\s*[A-Z]{2}\s+\d{5}(-\d{4})?$"),
}

# Distinctive enough to find inside a longer line without false alarms.
EMBEDDED_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn_tin": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "ein": re.compile(r"\b\d{2}-\d{7}\b"),
}


class Finding(tuple):
    """A PII-shaped string the field map did not account for."""

    __slots__ = ()

    def __new__(cls, pii_type: str, text: str, page: int):
        return super().__new__(cls, (pii_type, text, page))

    @property
    def pii_type(self) -> str:
        return self[0]

    @property
    def text(self) -> str:
        return self[1]

    @property
    def page(self) -> int:
        return self[2]

    def __str__(self) -> str:
        return f"{self.pii_type} on page {self.page}: {self.text!r}"


def scan(pages: list[list[Line]]) -> list[Finding]:
    """Return every PII-shaped string on the page, claimed or not."""
    found: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for lines in pages:
        for line in lines:
            text = line["text"].strip()
            for pii_type, pattern in LINE_PATTERNS.items():
                if pattern.match(text):
                    key = (pii_type, text)
                    if key not in seen:
                        seen.add(key)
                        found.append(Finding(pii_type, text, line["page"]))
            for pii_type, pattern in EMBEDDED_PATTERNS.items():
                for match in pattern.finditer(text):
                    key = (pii_type, match.group(0))
                    if key not in seen:
                        seen.add(key)
                        found.append(Finding(pii_type, match.group(0), line["page"]))

    return found


def audit(pages: list[list[Line]], claimed: set[str]) -> list[Finding]:
    """Return PII-shaped text that the field map did not locate.

    ``claimed`` should be every value the map located, *before* the policy filter
    is applied. Comparing against the post-filter set would report a deliberate
    policy exclusion as a coverage gap.

    A finding is suppressed when it appears inside a claimed value, so an address
    line that was located as a whole does not also surface as an embedded match.
    """
    return [
        finding
        for finding in scan(pages)
        if finding.text not in claimed and not any(finding.text in value for value in claimed)
    ]
