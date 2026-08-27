"""Batch scrub and selective restore. Orchestration only.

A job is one batch upload. It owns a single encryption key and a single token
pool, so the same value receives the same token in every document of the batch.
That pool is the reason ``token_map`` is created here and threaded through the
document loop rather than being built per document.

Failure is per document. One unreadable file must not sink the other thirty-nine.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field as dataclass_field
from typing import Any

from core import vault
from core.crypto import aad, decrypt, encrypt, token_hash
from core.extract import NoTextLayer, extract_lines, page_count
from core.fieldmap import (
    AnchorMismatch,
    Field,
    UnknownForm,
    identify,
    load_field_maps,
    locate,
    propagate,
    verify_labels,
)
from core.keys import generate_data_key, unwrap, wrap
from core.piitypes import canonical
from core.redact import ReplacementTooSmall, redact, restore_pdf
from core.tokens import assign, display, find_tokens
from detect import CoverageGap, Report, detect
from detect.policy import resolve_reveal
from core.verify import (
    OverDisclosed,
    PlaintextSurvived,
    TokenNotWritten,
    extract_all_text,
    verify_disclosure,
    verify_scrubbed,
    verify_tokens_present,
)

MAX_FILES = 25
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_BATCH_BYTES = 50 * 1024 * 1024
MAX_PAGES = 20
PDF_MAGIC = b"%PDF"

DEFAULT_POLICY: dict[str, Any] = {"pii_types": ["SSN", "ITIN", "EIN", "ADDRESS"]}

# A document must share this fraction of its tokens with an upload to be
# considered the same document. Below it, ask the user rather than guess.
MATCH_THRESHOLD = 0.5


class PolicyMismatch(Exception):
    """Raised when a policy and a field map name no pii_type in common.

    A policy that matches nothing is not a policy that redacts nothing quietly:
    ``_in_policy`` returns an empty list, ``redact`` draws nothing, and both
    release gates pass vacuously -- ``verify_scrubbed`` finds no surviving value
    among no values, and ``verify_tokens_present`` finds no missing token among
    no tokens. The batch is then reported as scrubbed while every document is
    returned with its SSN, EIN and addresses intact.

    Spelling drift used to be how this arose -- a map saying ``ssn_tin`` against
    a policy saying ``SSN``. Both sides now run through ``canonical``, so that
    particular case cannot happen any more. What remains is a policy that is
    genuinely disjoint from the form: ``{"pii_types": ["PHONE"]}`` against a K-1,
    which describes none. Deliberately narrow policies are unaffected --
    ``{"pii_types": ["EIN"]}`` against a map that describes an EIN shares a type
    and passes.
    """


# Quarantine is expected for these; anything else is a bug and must propagate.
QUARANTINE_ERRORS = (
    NoTextLayer,
    UnknownForm,
    AnchorMismatch,
    PolicyMismatch,
    CoverageGap,
    PlaintextSurvived,
    ReplacementTooSmall,
    TokenNotWritten,
    OverDisclosed,
)


class BatchTooLarge(Exception):
    """Raised when an upload exceeds the caps that keep the request synchronous."""


class NotAPdf(Exception):
    """Raised when a file is not a PDF by magic bytes."""


@dataclass
class ScrubbedDoc:
    doc_id: str
    filename: str
    form_id: str
    page_count: int
    replaced_count: int
    pdf_bytes: bytes
    # PII-shaped text the field map did not claim. Non-blocking: the document is
    # still delivered, but a stale map surfaces here instead of failing silently.
    warnings: list[str] = dataclass_field(default_factory=list)
    # The candidates behind those warnings, with their evidence, for a review
    # screen. Not persisted: candidates carry values and documents.reason is
    # plaintext.
    candidates: tuple = ()
    # Per type, how many located values the policy deliberately left on the
    # page. Detection cannot report these -- it runs against everything
    # located, so an excluded field reads as claimed -- and without them
    # unticking a type yields a clean green result over a document that
    # still carries the identifier.
    left_by_policy: dict[str, int] = dataclass_field(default_factory=dict)


@dataclass
class QuarantinedDoc:
    filename: str
    reason: str


@dataclass
class BatchResult:
    job_id: str
    scrubbed: list[ScrubbedDoc] = dataclass_field(default_factory=list)
    quarantined: list[QuarantinedDoc] = dataclass_field(default_factory=list)


@dataclass
class JobMatch:
    """Which job (or jobs) a scrubbed document's tokens belong to."""

    job_id: str | None
    tokens: list[str]
    resolved: int
    other_jobs: list[str] = dataclass_field(default_factory=list)
    reason: str | None = None


@dataclass
class RestoredDoc:
    doc_id: str | None
    filename: str
    tokens_found: int
    tokens_resolved: int
    unresolved: list[str]
    pdf_bytes: bytes
    job_id: str | None = None
    # The name the document had when it was scrubbed, decrypted for the report.
    # Uploads get renamed, so this is often the only thing the user recognises.
    original_filename: str | None = None


@dataclass
class UnmatchedDoc:
    filename: str
    reason: str


@dataclass
class RestoreResult:
    restored: list[RestoredDoc] = dataclass_field(default_factory=list)
    unmatched: list[UnmatchedDoc] = dataclass_field(default_factory=list)

    @property
    def jobs(self) -> list[str]:
        """Every distinct job this upload drew from."""
        return sorted({d.job_id for d in self.restored if d.job_id})


def accept_batch(files: list[tuple[str, bytes]]) -> None:
    """Validate an upload against the caps and the PDF magic bytes.

    Caps are what keep one synchronous request under the server timeout; they
    are a correctness requirement of the no-queue design, not a nicety.

    Raises:
        BatchTooLarge, NotAPdf
    """
    if not files:
        raise BatchTooLarge("no files supplied")
    if len(files) > MAX_FILES:
        raise BatchTooLarge(f"{len(files)} files exceeds the cap of {MAX_FILES}")

    total = 0
    for filename, data in files:
        if not data.startswith(PDF_MAGIC):
            raise NotAPdf(f"{filename} is not a PDF")
        if len(data) > MAX_FILE_BYTES:
            raise BatchTooLarge(f"{filename} exceeds {MAX_FILE_BYTES} bytes")
        total += len(data)
    if total > MAX_BATCH_BYTES:
        raise BatchTooLarge(f"batch of {total} bytes exceeds {MAX_BATCH_BYTES}")


def _policy_types(policy: dict[str, Any]) -> set[str]:
    """The types a policy names, canonicalised.

    ``detect.policy.resolve`` already canonicalises the same dict. Doing it here
    too is what stops one policy meaning two different things depending on which
    subsystem reads it.

    Raises:
        UnknownPiiType: for a name outside the vocabulary. Louder than matching
            nothing, which is the failure ``PolicyMismatch`` exists to catch.
    """
    return {canonical(name) for name in policy.get("pii_types", [])}


def _in_policy(fields: list[Field], policy: dict[str, Any]) -> list[Field]:
    allowed = _policy_types(policy)
    return [f for f in fields if f["pii_type"] in allowed]


def _check_policy_fits(field_map: dict[str, Any], policy: dict[str, Any]) -> None:
    """Raise unless the policy and the map share at least one pii_type.

    Raises:
        PolicyMismatch: naming both vocabularies, so the drift is obvious.
    """
    allowed = _policy_types(policy)
    described = {f["pii_type"] for f in field_map["fields"]}
    if not allowed & described:
        raise PolicyMismatch(
            f"policy types {sorted(allowed)} match nothing in field map "
            f"{field_map['form_id']!r}, which describes {sorted(described)}"
        )


def scrub_one(
    pdf_bytes: bytes,
    job_id: str,
    job_key: bytes,
    token_map: dict[str, str],
    encrypted: set[str],
    policy: dict[str, Any],
    field_maps: list[dict[str, Any]],
) -> tuple[
    bytes, str, list[Field], list[vault.Entry], list[str], Report, dict[str, int]
]:
    """Scrub one document. Raises rather than returning a partial result.

    Returns the scrubbed PDF, the form id, the fields replaced, vault entries for
    values not already encrypted earlier in this batch, any coverage warnings
    from the content audit, and a per-type count of what the policy left behind.
    """
    pages = extract_lines(pdf_bytes)
    if page_count(pdf_bytes) > MAX_PAGES:
        raise BatchTooLarge(f"document exceeds {MAX_PAGES} pages")

    field_map = identify(pages, field_maps)
    _check_policy_fits(field_map, policy)
    verify_labels(pages, field_map)
    located = propagate(pages, locate(pages, field_map))

    # Detection runs beside location, never instead of it: nothing it finds is
    # redacted, and locate() alone decides what gets replaced. It runs against
    # everything located, before the policy filter, because comparing against
    # the post-filter set would report a deliberate policy exclusion as a gap.
    report = detect(pages, field_map=field_map, located=located, policy=policy)
    warnings = report.warnings

    # The coverage gate, off unless a policy asks for it. It raises here --
    # before assign, encrypt and redact -- because raising after encrypt would
    # leave vault entries behind for a document that never ships: store_entries
    # sits past the except clause in scrub_batch, so failing early is also what
    # keeps the batch transaction clean.
    #
    # It stays off by default deliberately. Turning it on before the evaluation
    # corpus has measured precision at high confidence converts every false
    # positive into a rejected client document, and neither shipped fixture can
    # supply that measurement: both use placeholder identifiers that no
    # validator accepts, so nothing in them ever reaches high confidence.
    if policy.get("quarantine_on_gap", False):
        gaps = report.gaps("high")
        if gaps:
            # masked(), never str(): this message is written verbatim into
            # documents.reason, which is plaintext while the filename beside it
            # is encrypted.
            raise CoverageGap("; ".join(c.masked() for c in gaps))

    allowed = _policy_types(policy)
    fields = _in_policy(located, policy)

    # What the policy deliberately left readable. The detection layer cannot say
    # this -- it runs against everything located, so a field excluded by policy
    # reads to it as claimed -- and a narrowed policy must not look like a clean
    # scrub. Counts only; the values themselves stay out of the report.
    left_by_policy: dict[str, int] = {}
    for located_field in located:
        if located_field["pii_type"] not in allowed:
            pii_type = located_field["pii_type"]
            left_by_policy[pii_type] = left_by_policy.get(pii_type, 0) + 1

    values = [f["value"] for f in fields]
    assign(values, token_map)

    # First spelling wins, matching the lookup this replaced.
    type_by_value: dict[str, str] = {}
    for f in fields:
        type_by_value.setdefault(f["value"], f["pii_type"])

    # What actually gets drawn on the page. Partial disclosure needs no change
    # in ``redact``, which renders whatever a value maps to: the vault still
    # stores the bare token, ``token_hashes`` still records it, and
    # ``verify_tokens_present`` still finds it, because the token remains a
    # literal prefix of the display form.
    reveal = resolve_reveal(policy)
    display_by_value = {
        value: display(token_map[value], value, reveal.get(type_by_value[value], 0))
        for value in dict.fromkeys(values)
    }

    entries: list[vault.Entry] = []
    for value in dict.fromkeys(values):
        if value in encrypted:
            continue
        pii_type = type_by_value[value]
        token = token_map[value]
        ciphertext, nonce = encrypt(job_key, value, aad(job_id, pii_type, token))
        entries.append(vault.Entry(token, pii_type, ciphertext, nonce))
        encrypted.add(value)

    scrubbed = redact(pdf_bytes, fields, display_by_value)

    # Hard gates. Nothing is released to the user unverified.
    # Three directions matter: no original may survive whole, every token must
    # have landed -- a value removed without its token is unrecoverable -- and
    # no value may show more of itself than the policy authorised. The third is
    # not implied by the first: verify_scrubbed looks for whole values, so it
    # passes cleanly over a page leaking every identifier's last six digits.
    verify_scrubbed(scrubbed, values)
    verify_tokens_present(scrubbed, {token_map[v] for v in values})
    verify_disclosure(
        scrubbed,
        [
            (token_map[value], value, reveal.get(type_by_value[value], 0))
            for value in dict.fromkeys(values)
        ],
    )

    return (
        scrubbed,
        field_map["form_id"],
        fields,
        entries,
        warnings,
        report,
        left_by_policy,
    )


def scrub_batch(
    conn: sqlite3.Connection,
    files: list[tuple[str, bytes]],
    policy: dict[str, Any] | None = None,
    field_maps: list[dict[str, Any]] | None = None,
) -> BatchResult:
    """Scrub a batch of documents under one job key and one token pool."""
    policy = policy or DEFAULT_POLICY
    field_maps = field_maps if field_maps is not None else load_field_maps()
    accept_batch(files)

    # Resolve the policy before a job row exists. A bad type name or an
    # out-of-range reveal count is a configuration error for the whole batch,
    # not a per-document one, and failing here leaves nothing half written.
    _policy_types(policy)
    resolve_reveal(policy)

    job_key = generate_data_key()
    job_id = vault.create_job(conn, policy)
    vault.store_key(conn, job_id, wrap(job_key))

    result = BatchResult(job_id=job_id)
    token_map: dict[str, str] = {}
    encrypted: set[str] = set()

    for filename, pdf_bytes in files:
        try:
            (
                scrubbed,
                form_id,
                fields,
                entries,
                warnings,
                report,
                left_by_policy,
            ) = scrub_one(
                pdf_bytes, job_id, job_key, token_map, encrypted, policy, field_maps
            )
        except QUARANTINE_ERRORS as exc:
            doc_reason = f"{type(exc).__name__}: {exc}"
            vault.store_document(conn, job_id, filename, job_key, "quarantined", reason=doc_reason)
            result.quarantined.append(QuarantinedDoc(filename=filename, reason=doc_reason))
            continue

        vault.store_entries(conn, job_id, entries)
        tokens = sorted({token_map[f["value"]] for f in fields})
        doc_id = vault.store_document(
            conn,
            job_id,
            filename,
            job_key,
            "scrubbed",
            form_id=form_id,
            page_count=page_count(pdf_bytes),
            token_hashes=[token_hash(t) for t in tokens],
        )
        result.scrubbed.append(
            ScrubbedDoc(
                doc_id=doc_id,
                filename=filename,
                form_id=form_id,
                page_count=page_count(pdf_bytes),
                replaced_count=len(fields),
                pdf_bytes=scrubbed,
                warnings=warnings,
                candidates=report.unclaimed,
                left_by_policy=left_by_policy,
            )
        )

    vault.set_job_status(conn, job_id, "scrubbed" if result.scrubbed else "failed")
    # One transaction for the whole job: a crash cannot leave it half written.
    conn.commit()
    return result


def match_document(conn: sqlite3.Connection, job_id: str, pdf_bytes: bytes) -> str | None:
    """Identify which document of a job an upload is, by token overlap.

    Files get renamed, so matching is on content. Jaccard rather than overlap
    against the recorded set: because a batch deliberately shares tokens across
    documents, a small document whose tokens are a subset of a larger one would
    otherwise score a perfect match against both.

    Returns None when no document clears the threshold. The caller must ask
    rather than guess.
    """
    try:
        found = {token_hash(t) for t in find_tokens(extract_lines(pdf_bytes))}
    except NoTextLayer:
        return None
    if not found:
        return None

    best_id, best_score = None, 0.0
    for doc in vault.list_documents(conn, job_id):
        recorded = set(doc.token_hashes)
        if not recorded:
            continue
        score = len(found & recorded) / len(found | recorded)
        if score > best_score:
            best_id, best_score = doc.id, score

    return best_id if best_score >= MATCH_THRESHOLD else None


def identify_job(
    conn: sqlite3.Connection, pdf_bytes: bytes, job_id: str | None = None
) -> JobMatch:
    """Work out which job a scrubbed document belongs to, from the file alone.

    Users do not keep the job id -- it is a UUID shown once, and by the time a
    scrub needs reversing the file is the only thing they still have. Token
    hashes are keyed by the lookup secret rather than by the job, so the vault
    can be asked "who owns these?" without being told where to look.

    ``job_id`` restricts the answer to one job when the caller already knows it.
    """
    try:
        tokens = find_tokens(extract_lines(pdf_bytes))
    except NoTextLayer:
        return JobMatch(None, [], 0, reason="no text layer")

    if not tokens:
        return JobMatch(None, [], 0, reason="no tokens found -- was this scrubbed by this tool?")

    owners = vault.find_by_token_hashes(conn, [token_hash(t) for t in tokens])
    if job_id is not None:
        owners = {k: v for k, v in owners.items() if k == job_id}
    if not owners:
        return JobMatch(None, tokens, 0, reason="these tokens are not in this vault")

    ranked = sorted(owners.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    best, hashes = ranked[0]
    return JobMatch(best, tokens, len(hashes), other_jobs=[j for j, _ in ranked[1:]])


def _job_key(conn: sqlite3.Connection, job_id: str, cache: dict[str, bytes]) -> bytes:
    """Unwrap a job key once per job, not once per token."""
    if job_id not in cache:
        vault.get_job(conn, job_id)  # raises if unknown or expired
        cache[job_id] = unwrap(vault.get_wrapped_key(conn, job_id))
    return cache[job_id]


def restore_batch(
    conn: sqlite3.Connection,
    files: list[tuple[str, bytes]],
    job_id: str | None = None,
) -> RestoreResult:
    """Restore scrubbed documents, resolving each file's job from the file itself.

    Every file is resolved independently, so one upload may draw from several
    batches. Tokens are resolved individually against whichever job owns them,
    which means a document assembled from two batches still restores fully
    rather than reporting half its tokens as strangers.

    ``job_id`` is an optional filter for a caller that already knows the job. It
    is never required.
    """
    accept_batch(files)

    result = RestoreResult()
    keys: dict[str, bytes] = {}

    for filename, pdf_bytes in files:
        match = identify_job(conn, pdf_bytes, job_id)
        if match.job_id is None:
            result.unmatched.append(UnmatchedDoc(filename, match.reason or "unidentified"))
            continue

        # Check the owning batch up front so expiry stays loud. Discovering it
        # per token would bury the reason in a list of unresolved tokens, and a
        # user would read that as "the tool failed" rather than "this expired".
        try:
            _job_key(conn, match.job_id, keys)
        except (vault.JobExpired, vault.JobNotFound) as exc:
            result.unmatched.append(UnmatchedDoc(filename, str(exc)))
            continue

        value_by_token: dict[str, str] = {}
        unresolved: list[str] = []

        for token in match.tokens:
            owners = vault.find_by_token_hashes(conn, [token_hash(token)])
            if job_id is not None:
                owners = {k: v for k, v in owners.items() if k == job_id}
            if not owners:
                unresolved.append(token)
                continue

            owner = match.job_id if match.job_id in owners else next(iter(owners))
            try:
                key = _job_key(conn, owner, keys)
            except (vault.JobExpired, vault.JobNotFound):
                # One expired batch must not sink tokens belonging to others.
                unresolved.append(token)
                continue

            entry = vault.lookup(conn, owner, token)
            if entry is None:
                unresolved.append(token)
                continue
            # An AAD failure means tampering or a value from elsewhere. Let it raise.
            value_by_token[token] = decrypt(
                key, entry.ciphertext, entry.nonce, aad(owner, entry.pii_type, token)
            )

        restored, unplaced = restore_pdf(pdf_bytes, value_by_token)
        unresolved.extend(unplaced)

        # The renderer can drop replacement text silently, so confirm each value
        # actually landed rather than reporting a restore that did not happen.
        landed = extract_all_text(restored)
        failed = {t for t, v in value_by_token.items() if v not in landed}
        unresolved.extend(failed)

        doc_id = match_document(conn, match.job_id, pdf_bytes)
        original = None
        if doc_id is not None:
            vault.set_document_status(conn, doc_id, "restored")
            try:
                original = vault.document_filename(conn, doc_id, _job_key(conn, match.job_id, keys))
            except (vault.JobExpired, vault.JobNotFound):
                original = None

        result.restored.append(
            RestoredDoc(
                doc_id=doc_id,
                filename=filename,
                tokens_found=len(match.tokens),
                tokens_resolved=len(value_by_token) - len(failed),
                unresolved=sorted(set(unresolved)),
                pdf_bytes=restored,
                job_id=match.job_id,
                original_filename=original,
            )
        )

    conn.commit()
    return result
