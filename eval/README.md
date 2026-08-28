# Detection evaluation

Per-type recall and review rate for the `detect/` package.

## Provenance

Every document here is **synthetic and AI-generated**. No real taxpayer data has
ever been in this repository and none may be added. The two documents under
`tests/fixtures/` carry C2PA manifests identifying them as AI-generated; treat
anything added here the same way and record it in the document's answer key.

## What replaced the regex audit

`core/detect.py` scanned for PII-shaped text and reported anything the field map
had not claimed. It never redacted. It was retired once `detect/` measurably beat
it on the same lists, which are carried forward verbatim into
`tests/test_detect_patterns.py` so the comparison stays honest.

Measured on the 24 realistic variants and 38 tax-form distractors that module
shipped with:

| | old regex audit | `detect/` |
|---|---|---|
| recall | 8/24 = 33% | 16/24 = 67% |
| false positives | 0/38 | 0/38 |
| names | 0/3, by design | 0/3, by design |

Nothing the old audit caught was lost. The eight gained are the format misses it
documented: unhyphenated and space-separated identifiers, lowercase street and
city lines, PO boxes, and addresses with no house number.

The five remaining misses are masked identifiers (`XXX-XX-6789`), a locality
line with no comma, and two foreign postal formats. The three names are out of
scope: names stay on the form, and `skip_lines: 1` drops them from each address
box.

## Coverage, measured on both fixtures

Dropping one field at a time from `forms/us-1065-k1.json` and asking whether the
value surfaces:

| map state | 2021 | 2025 |
|---|---|---|
| complete | 0 warnings | 0 warnings |
| `partnership_ein` dropped | caught | caught |
| `partner_tin` dropped | caught | caught |
| `partnership_address` dropped | caught | caught |
| `partner_address` dropped | caught | caught |
| both identifier fields dropped | caught (patterns only) | caught |

Zero warnings on a fitting map is the number that decides whether this is usable.
A noisy audit is one people learn to ignore.

The last row is the documented blind spot of the structural layer: it learns this
document's filled-in style from what `locate()` claimed, so removing every
claimed example of a style makes that style unrecognisable. The pattern layer
covers it. That is why both exist.

## The corpus

Not yet present. `corpus/` holds synthetic PDFs and `keys/` an answer key per
document, named `<document>.key.json`:

```json
{
  "schema": "pii-cypher/answer-key@1",
  "document": "k1-0007.pdf",
  "form_id": "us-1065-k1",
  "pages": 2,
  "provenance": {
    "synthetic": true,
    "ai_generated": true,
    "created": "2026-08-27",
    "note": "No real taxpayer data."
  },
  "expected": [
    {
      "id": "e1",
      "pii_type": "SSN",
      "value": "512-44-8890",
      "page": 1,
      "field": "partner_tin",
      "in_policy": true,
      "surface": ["512-44-8890", "512 44 8890"],
      "repeats": [2]
    }
  ],
  "distractors": [{ "text": "125,000", "page": 1, "why": "currency" }]
}
```

- `value` is the exact string in the PDF's text layer. Matching is by normalised
  and whitespace-stripped comparison, so spacing does not have to be predicted.
- `surface` lists alternate renderings. This is what makes split-span detection
  testable rather than merely asserted.
- `field` names the map field that should claim the value, or `null`. A `null` is
  a deliberate coverage gap, and those are the only entries that measure whether
  the structural layer earns a quarantine gate.
- `in_policy` separates "detection missed it" from "policy correctly excluded it".
- `distractors` must never be reported. They are the precision half.

### What the corpus needs to cover

The two shipped fixtures cannot test these on their own:

1. Template and fill in the **same font family**, separated only by size. This is
   the realistic case; the 2025 fixture separates cleanly only because its fill
   was stamped in base-14 Helvetica over subset-embedded template faces.
2. Template and fill in the **same font and size** — where the structural layer
   is blind by construction. Its recall there should be reported as 0, not hidden.
3. Masked identifiers, lowercase city lines, foreign postal formats.
4. A value split across text spans (`123-45-` / `6789`).
5. A value repeating in a footer or on a continuation page.
6. A document with no PII at all.
7. A two-column page where a value shares a baseline with an unrelated figure.
8. **Structurally valid identifiers.** Both fixtures use placeholders that fail
   real validators — SSN area `000` and EIN prefix `00` are never issued — so
   neither can reach high confidence, and a quarantine gate keyed on high
   confidence cannot be calibrated on them at all.
9. A multi-page document. Partly covered now: location is per instance, and the
   tests build a three-partner packet from the fixture, so several K-1s in one
   file are exercised end to end. What is still missing is the shape those
   packets cannot make — a form whose *box* continues onto the next page, where
   the column gate would meet a different margin. Every instance in the fixtures
   starts a fresh page, so that gate has still never run.
