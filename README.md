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
python cli.py restore scrubbed/*.pdf --out restored.zip   # no job id needed
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
| `EIN` | A — partnership employer identification number |
| `SSN` | E — partner's SSN or TIN |
| `ADDRESS` | B and F — street, city, state and ZIP |

Names are deliberately out of policy and stay on the form. `skip_lines: 1` drops the
first line of each address box, which is the name.

Both columns of that table are choices, not fixtures. A policy names which types to
tokenise, and unticking one leaves that identifier readable on the document — the
result page and `pii-scrubber scrub` both say which types were left and how many,
because the detection layer cannot: it runs against everything `locate()` claimed,
before the policy filter, so a field excluded by policy reads to it as claimed.

### Showing the last digits

A recipient holding `PII-7ZURMBHA` cannot match it against their own records. A
policy may leave a trailing run of digits readable instead:

```json
{ "pii_types": ["SSN", "EIN", "ADDRESS"], "reveal_digits": { "EIN": 4 } }
```

```
45-1234567   ->   PII-7ZURMBHA-4567   ->   45-1234567
```

The value is still encrypted whole and still restores whole. Only the drawing
changes: the vault stores the bare token, `token_hashes` records the bare token, and
restore reconstructs the on-page form from the value it just decrypted, so a document
mixing counts across types still resolves without being told the policy.

The range is 0 to 6, refused rather than clamped outside it. Six is the cap because
that is where the setting stops being partial: an SSN and an EIN are both nine
digits, so six leaves three hidden, and for a pre-2011 SSN the hidden leading run is
a geographically assigned area number. At the top of the range this is closer to
disclosure than to redaction.

The separator is load-bearing. `TOKEN_RE` ends in a word boundary, so
`PII-7ZURMBHA4567` matches nothing, `find_tokens` returns nothing, and every restore
comes back unmatched. `test_the_separator_is_load_bearing` pins it.

## Restore identifies itself

Restoring takes no job ID. Upload any scrubbed files and each one works out which
batch it came from, so a single upload can mix files from different batches and
renaming them changes nothing.

This works because `token_hash()` is keyed by `PII_LOOKUP_SECRET` alone, not by
the job, so a token hashes identically everywhere and the vault can be asked *who
owns these?* without being told where to look.

Resolution is per **token**, not per document. A file whose pages were merged from
two batches restores fully, where a document-level lookup would resolve one page
and report the other's tokens as strangers. The document's batch, used for
reporting and status, is just the dominant owner.

The job ID was never access control, despite looking like it: `/jobs` lists every
batch, and `/restore?job_id=X` decrypts filenames for any job handed to it.
Dropping the field removed friction, not protection. Restricting restore would
need authentication, which does not exist.

`--job` and `?job_id=` survive as an optional filter for a caller that already
knows the batch. Nothing requires them.

## Field maps describe *what*, not *where*

`forms/us-1065-k1.json` is one file per form **family**, not per year, and contains
no coordinates:

```json
{ "name": "partner_tin", "pii_type": "SSN", "keywords": "ssn or tin" }
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

## The coverage layer

After location, `detect/` scans the page for PII the field map did not claim and
reports it as a **coverage warning**. It never redacts anything.

This is the question `verify_labels` cannot ask. That check iterates the *map* and
asks whether each label it names is on the page, so it can confirm the fields the
map lists are present and can never ask whether fields exist that the map omits.

Two layers, because neither answers it alone.

**Structural.** Filled-in text is stylistically distinct from the form template, so
a value can be recognised as *data* without reading it. The style is learned per
document from what `locate()` claimed — never hardcoded, because the two revisions
share no fill style at all: 2021 fills in Helvetica-Bold 9/10pt against a 7.2–8pt
template, 2025 in base-14 Helvetica against subset-embedded faces. Any fixed rule
fits one and fails the other.

It has one blind spot, and it is structural rather than incidental: the style is
learned from claimed examples, so a revision that moves *every* field of a style
out of the map leaves that style unrecognisable. It also cannot see digit-shaped
values, because no filter that removes `125,000` keeps `000-00-0000`.

**Patterns.** Structured identifiers by shape, wherever they sit, which is exactly
the blind spot above. Validation — SSN area and group rules, the IRS EIN prefix
set, ITIN group ranges — decides *confidence*, never survival. A shape that fails its validator is still reported, at low
confidence: both fixtures use placeholder identifiers that no validator accepts,
and suppressing on a failed validator made detection silent on the two most
obviously SSN-shaped strings in the repository.

The vocabulary is six types, and each earns its place. `SSN`, `ITIN`, `EIN` and
`ADDRESS` are what the form carries — `ITIN` because field E is "SSN *or TIN*" and a
foreign partner has one. `PHONE` and `DOB` are not on a K-1 at all; they are there
because the furniture filter discards their shapes, so without a pattern nothing
would ever see them. `EMAIL`, `ROUTING` and `BANK_ACCOUNT` were removed for the
opposite reason: the filter keeps *their* shapes, so those values still surface as
unaccounted-for fill and naming them bought nothing.

`DOB` fires only under a matching label, because a tax form is full of dates and a
period end looks exactly like a birthday. The consequence is a stated limitation
rather than a hidden one: an unlabelled date of birth reaches no layer at all.
Firing on shape would mean reporting every date on the form, which is the noise the
filter exists to remove.

Against the 24 realistic variants and 38 distractors the previous regex audit
shipped with, recall went from 33% to 67% with **false positives still at zero**.
Nothing it caught was lost. The remaining misses are masked identifiers, two
foreign postal formats, and names — which are out of policy.

On a fitting map both fixtures produce **no warnings at all**. That number matters
as much as recall: a noisy audit is one people learn to ignore.

### The coverage gate

`{"quarantine_on_gap": true}` in a policy turns a high-confidence unclaimed value
from a warning into a quarantine. It is **off by default and should stay off until
the evaluation corpus has measured precision at high confidence** — switching it on
early converts every false positive into a rejected client document.

High confidence needs three independent signals to agree: the shape matched, the
validator passed, and a nearby label named the same type. Neither shipped fixture
can calibrate the gate, and the 2021 revision demonstrates why — its placeholder
identifiers (`000-00-0000`, `00-0000000`) use an SSN area and an EIN prefix the IRS
has never issued, so they stop at medium however clearly the label agrees.

The gate raises before tokenisation, encryption and redaction, so a quarantined
document leaves no vault rows behind. Its message names the type, page and box and
never the value: `documents.reason` is plaintext while the filename beside it is
encrypted.

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
- Three release gates run before anything is returned: no original value may appear
  in the output, every token must have landed, and no value may show more of itself
  than the policy authorised. The second exists because a replacement can fail to
  render without raising. The third is not implied by the first — `verify_scrubbed`
  looks for whole values, so it passes cleanly over a page leaking the last six
  digits of every identifier — and its message carries counts, never digits, because
  `documents.reason` is plaintext while the filename beside it is encrypted.

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
Best-effort detector-only scrubbing was considered and rejected. Detection is a
coverage check, not a locator: at 67% recall it would ship files labelled
"scrubbed" that are not.

**Non-text PII is not handled.** `apply_redactions()` does not touch the document
info dictionary, XMP metadata, embedded files, or annotations. In a real firm's K-1,
`/Title` is routinely the client filename.

**No cross-document value hunting.** A value located in document A is not searched for
in document B where B's map does not cover it.

**Cross-job token collisions are theoretically possible.** Tokens are 8
characters from a 32-symbol alphabet and are minted with a uniqueness check
*within* a job only. A collision across jobs is about 1 in 10^12 per pair, and a
document carries several tokens, so misidentifying a file would need simultaneous
collisions. Worth knowing, not worth a mechanism.

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
  piitypes.py   the canonical PII type vocabulary
  tokens.py     minting, batch-wide assignment, discovery regex
  keys.py       wrap / unwrap            <- the only file a KMS swap touches
  crypto.py     AAD, encrypt / decrypt, token hashing
  vault.py      SQLite: jobs, documents, vault_entries, job_keys
  redact.py     tokens in, values back out, styling preserved
  verify.py     the release gates
  pipeline.py   scrub_batch(), restore_batch(), match_document()
detect/
  __init__.py   detect() -- the only public entry point
  adapter.py    extracted lines -> items, and the field map's own geometry
  patterns.py   structured identifiers, by shape then by validator
  coverage.py   filled-in text the map does not account for
  labels.py     label association; gates the types shape cannot justify
  merge.py      overlap precedence, dedupe, confidence
  policy.py     which types, and the floor that cannot be switched off
forms/          concept maps, one JSON per form family
eval/           per-type recall and review rate; the corpus and its answer keys
web/            FastAPI app and templates
cli.py          command line harness over the same pipeline functions
```

## Tests

```bash
python -m pytest tests/ -q
```

Notable cases: the two-column collisions in `test_extract.py`; one concept map
extracting both revisions, and the rule-ordering regression, in `test_fieldmap.py`;
the stale-map matrix across both revisions in `test_detect_coverage.py`, and the
carried-forward precision and recall lists in `test_detect_patterns.py`; AAD misuse in `test_crypto.py`; a
raw-file scan proving no plaintext reaches the database in `test_vault.py`; style
fidelity in `test_redact.py`; and in `test_pipeline.py`, that a partner shared across
a 2021 and a 2025 K-1 collapses to one token, and that both restore pixel-identically.

Fixtures are synthetic. Never point this at a real K-1 while developing.
