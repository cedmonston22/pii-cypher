# PII Scrubber

Batch-scrubs identifiers out of Schedule K-1s and puts them back on demand.

Firms send K-1s to lenders, counsel and auditors who need the numbers but have no
business seeing the partner's SSN or home address. Redacting by hand is
irreversible, so the firm keeps an unredacted second copy — which is its own
problem. This tool replaces identifiers with tokens and encrypts the originals,
so the shadow copy is unnecessary.

## Quick start

```bash
pip install -r requirements-dev.txt
./run.sh          # or .\run.ps1 on Windows  ->  http://127.0.0.1:8000
```

`run.sh` generates key material into `.env.local` on first run and reuses it after.
**Deleting that file makes every existing job permanently unreadable** —
`PII_MASTER_KEY` wraps each job's data key. Both variables are base64-encoded 32-byte
values if you prefer to set them yourself.

Command line equivalent:

```bash
python cli.py scrub k1a.pdf k1b.pdf --out scrubbed.zip   # prints the job id
python cli.py jobs -v                                     # decrypts filenames for display
python cli.py restore scrubbed/k1a.pdf --job <job_id> --out restored.zip
```

`scrub` and `restore` exit non-zero when any file was quarantined, any token failed
to resolve, or the audit flagged uncovered PII — so a script cannot mistake a
partial run for a clean one.

## How it works

A **job** is one batch upload. It owns a single encryption key and a single token
pool, so a value appearing in several documents gets the same token in all of them
and one row in the vault. Because vault lookups are scoped to the job rather than
the document, restoring one document of a batch needs no special handling and
leaves the others untouched.

```
accept -> text-layer gate -> extract lines -> identify form -> verify labels
       -> locate -> propagate -> audit -> filter by policy -> tokenise
       -> encrypt -> redact -> verify -> store
```

Every stage that cannot complete confidently raises. Failure is per document: one
unreadable file is quarantined and the rest of the batch continues.

### What gets replaced

| Type | Fields on the K-1 |
|---|---|
| `ein` | A — partnership employer identification number |
| `ssn_tin` | E — partner's SSN or TIN |
| `address` | B and F — street, city, state and ZIP |

Names are deliberately out of policy and stay on the form. `skip_lines: 1` drops the
first line of each address box, which is the name.

## Field maps describe *what*, not *where*

`forms/us-1065-k1.json` is one file per form **family**, not per year, and contains
no coordinates:

```json
{ "name": "partner_tin", "pii_type": "ssn_tin", "keywords": "ssn or tin" }
```

This matters because form geometry is not stable. Between the 2021 and 2025
Schedule K-1 the IRS reworded three of four labels, switched `'` to `'`, merged one
field's label and value onto a single line, and **inverted the indent**: 2021 puts
values 30pt right of their label, 2025 puts them flush and the numeric fields 1.8pt
to the *left*. Forcing the 2021 coordinates onto the 2025 form extracts nothing.

So the geometry is discovered per document, by three rules:

1. **Column** — candidate lines sit below the label, within `col_tol` (90pt) of its
   left edge. A band, not an offset: it admits +30pt and −1.8pt alike.
2. **The next label closes the box** — a line sharing the *label's* font and size.
3. **A style change closes the field** — values within a box share a font and size;
   the first line that differs ends it.

Rule order matters. The column filter must run **first** — checking rule 2 before
filtering by column lets an unrelated line in another column, which happens to share
the label's font size, end the scan on its first iteration and return nothing.
There is a test for exactly that.

Label matching runs through `normalize()` — NFKC, typographic characters folded,
punctuation stripped, whitespace collapsed, lowercased — so `Partner's` and
`Partner's` agree, and `ssn or tin` still matches after the IRS appended a sentence
to that label.

A new form family still needs a map. What it no longer needs is a new map every
year.

## The audit layer

After location, `core/detect.py` scans the page for PII-shaped text the map did not
claim, and reports it as a **coverage warning**. It never redacts anything.

It is deliberately not the detector. Measured against 28 realistic PII variants
these patterns recall about a third — they miss lowercase city lines, addresses with
no house number (`PO BOX 1234`, `ONE MARKET PLAZA`), foreign postal formats,
unhyphenated and masked SSNs, and every personal name. Each of those is a *format*
miss for a value sitting exactly where the label-driven pass finds it, which is the
whole argument for locating by label rather than by content.

What it is good for is noticing when a map goes stale: if a revision adds a field
the map does not describe, the value surfaces as a warning instead of passing
through silently. Precision is what makes that usable — against 38 distractors drawn
from tax-form furniture (amounts, dates, line numbers, form titles) it raises
nothing. A noisy audit is one people learn to ignore.

## Extraction

**The K-1 is two-column and the columns share baselines.** The partner's SSN sits
1pt from `16 Alternative minimum tax items`; `AUSTIN, TX 78701` sits 1.2pt from the
Part IV heading. Grouping words into lines by vertical position — pdfplumber's
default tolerance is 3pt — merges them into one line whose bbox spans the page, so
redacting the SSN would blank half the form. `core/extract.py` groups by row *and
then splits each row at horizontal gaps over `gap_tol`*. The gap stage is what
actually separates the columns.

## Redaction

**Replacements are drawn, not delegated.** `add_redact_annot(text=...)` derives its
own font size from the height of the box and ignores the size it is given, so it
cannot reproduce the original styling — it rendered 10pt bold values at 7pt, and
shrank them again on every pass. `core/redact.py` redacts and draws as two steps:
`apply_redactions()` removes the glyphs, then `insert_text` puts the replacement back
in the source's own face, weight, size, colour and baseline.

**Removal boxes are tightened to the ink.** A reported span box spans the font's full
ascent and descent, about 1.37× the point size. The 2025 K-1 sets address lines 10pt
apart at 8pt type, so consecutive span boxes *overlap* — and `apply_redactions`
deletes any glyph whose box merely intersects the region. Redacting a token that way
took the name on the line above with it. Because removal is all-or-nothing per glyph,
a box only has to *intersect* what it removes, so drawing it to cap height and
descender is both safe and neighbour-preserving.

## Security properties

- Values are AES-256-GCM encrypted under a per-job key, fresh nonce each.
- The job key is wrapped by `PII_MASTER_KEY`. `core/keys.py` exposes only
  `wrap`/`unwrap`; moving custody to a KMS changes that file and nothing else.
- AAD binds each ciphertext to `tenant|job|value|pii_type|token`, so a ciphertext
  lifted into another job or another field fails its tag rather than decrypting.
- Tokens reach the database only as `HMAC-SHA256(PII_LOOKUP_SECRET, token)`.
- Filenames are encrypted: `Smith_John_K1.pdf` is itself PII.
- Uploaded bytes are never written to disk. Finished archives are held in memory and
  their download links are single-use with a 15-minute expiry.
- Two release gates run before anything is returned: no original value may appear in
  the output, and every token must have landed. The second exists because a
  replacement can fail to render without raising.

Jobs expire after 30 days; restore refuses an expired job rather than returning a
partial result.

## Known gaps

**Two documents is not a sample.** The three location rules extract 8/8 fields across
two synthetic K-1 revisions. That is encouraging, not proof. Treat them as
provisional until they have seen a real form from a different preparer.

**Three structural assumptions can break.** Labels and values must be stylistically
distinguishable; a field's values must be stylistically homogeneous; values must sit
below their label in the same column band. The third is already false for 2025 field
C, where the value shares the label's line — it is out of policy, so unhandled.

**A flattened or scanned-then-OCR'd form loses font information**, which disables
rules 2 and 3. The text-layer gate catches pure scans; it does not catch a
print-to-PDF that kept its text layer.

**Unmapped form families still quarantine.** A 1099 with no concept map is refused.
Best-effort detector-only scrubbing was considered and rejected: at ~32% recall it
would ship files labelled "scrubbed" that are not.

**Non-text PII is not handled.** `apply_redactions()` does not touch the document
info dictionary, XMP metadata, embedded files, or annotations. In a real firm's K-1,
`/Title` is routinely the client filename.

**No cross-document value hunting.** A value located in document A is not searched for
in document B where B's map does not cover it.

**`documents.token_hashes` leaks a join.** Anyone with database access learns which
documents share a value, though not what the value is.

**Restores are not byte-identical.** The page *renders* identically — restored K-1s
are pixel-for-pixel the same as their source at 150 DPI, on both revisions — but the
file is rewritten, so bytes and object numbering differ. Documents using an embedded
font outside the base-14 set are mapped to the nearest base-14 face and will not
reach that bar.

## Layout

```
core/
  extract.py    PDF bytes -> positioned line segments (row grouping + gap splitting)
  fieldmap.py   normalize(), identify(), find_label(), discover_field(), locate()
  detect.py     content-pattern audit; reports, never redacts
  tokens.py     minting, batch-wide assignment, discovery regex
  keys.py       wrap / unwrap            <- the only file a KMS swap touches
  crypto.py     AAD, encrypt / decrypt, token hashing
  vault.py      SQLite: jobs, documents, vault_entries, job_keys
  redact.py     tokens in, values back out, styling preserved
  verify.py     the release gates
  pipeline.py   scrub_batch(), restore_batch(), match_document()
forms/          concept maps, one JSON per form family
web/            FastAPI app and templates
cli.py          command line harness over the same pipeline functions
```

## Tests

```bash
python -m pytest tests/ -q
```

Notable cases: the two-column collisions in `test_extract.py`; one concept map
extracting both revisions, and the rule-ordering regression, in `test_fieldmap.py`;
the documented recall limit in `test_detect.py`; AAD misuse in `test_crypto.py`; a
raw-file scan proving no plaintext reaches the database in `test_vault.py`; style
fidelity in `test_redact.py`; and in `test_pipeline.py`, that a partner shared across
a 2021 and a 2025 K-1 collapses to one token, and that both restore pixel-identically.

Fixtures are synthetic. Never point this at a real K-1 while developing.
