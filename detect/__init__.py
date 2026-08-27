"""PII detection: what the field map did not account for.

``verify_labels`` can only ask whether the labels a map names are on the page.
It iterates the map, so it can never ask the question that matters -- whether
the page carries a field the map omits. This package asks that one.

Detection runs beside location, never instead of it. Nothing found here is
redacted: ``core.fieldmap.locate`` alone decides what gets replaced.
"""
