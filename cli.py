"""Command line harness over the same pipeline functions the web app uses.

Useful for running a batch without a browser and for checking the caps and
quarantine paths from a shell.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

from core import vault
from core.keys import MissingKeyMaterial, unwrap
from core.pipeline import BatchTooLarge, NotAPdf, restore_batch, scrub_batch


def _read(paths: list[str]) -> list[tuple[str, bytes]]:
    return [(Path(p).name, Path(p).read_bytes()) for p in paths]


def _write_zip(destination: Path, files: list[tuple[str, bytes]]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files:
            archive.writestr(name, data)


def cmd_scrub(args: argparse.Namespace) -> int:
    conn = vault.connect(args.db)
    try:
        result = scrub_batch(conn, _read(args.files))
    finally:
        conn.close()

    print(f"job_id: {result.job_id}")
    for doc in result.scrubbed:
        print(f"  scrubbed    {doc.filename}  ({doc.form_id}, {doc.replaced_count} replaced)")
        for warning in doc.warnings:
            print(f"      NOT REPLACED, looks like PII: {warning}")
    for doc in result.quarantined:
        print(f"  QUARANTINED {doc.filename}  {doc.reason}")

    if result.scrubbed:
        _write_zip(Path(args.out), [(d.filename, d.pdf_bytes) for d in result.scrubbed])
        print(f"wrote {args.out}")

    if result.quarantined:
        print(f"\n{len(result.quarantined)} file(s) were NOT scrubbed and are not in the archive.")
        return 1
    if any(d.warnings for d in result.scrubbed):
        print("\nSome PII-shaped text was not covered by the field map. See above.")
        return 1
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    conn = vault.connect(args.db)
    try:
        result = restore_batch(conn, _read(args.files), args.job)
    finally:
        conn.close()

    for doc in result.restored:
        state = "ok" if doc.tokens_resolved == doc.tokens_found else "PARTIAL"
        origin = f"batch {doc.job_id[:8]}" if doc.job_id else "unknown batch"
        was = f", originally {doc.original_filename}" if doc.original_filename else ""
        print(f"  {state:9} {doc.filename}  {doc.tokens_resolved}/{doc.tokens_found} tokens"
              f"  [{origin}{was}]")
        for token in doc.unresolved:
            print(f"      unresolved: {token}")
    for doc in result.unmatched:
        print(f"  UNMATCHED {doc.filename}  {doc.reason}")

    if result.restored:
        _write_zip(Path(args.out), [(d.filename, d.pdf_bytes) for d in result.restored])
        print(f"wrote {args.out}")
    if len(result.jobs) > 1:
        print(f"{chr(10)}These files came from {len(result.jobs)} different batches.")

    incomplete = any(d.unresolved for d in result.restored) or result.unmatched
    return 1 if incomplete else 0


def cmd_jobs(args: argparse.Namespace) -> int:
    conn = vault.connect(args.db)
    try:
        for job in vault.list_jobs(conn):
            print(f"{job['id']}  {job['created_at'][:19]}  {job['document_count']:>3} docs  {job['status']}")
            if args.verbose:
                job_key = unwrap(vault.get_wrapped_key(conn, job["id"]))
                for doc in vault.list_documents(conn, job["id"]):
                    name = vault.document_filename(conn, doc.id, job_key)
                    print(f"    {doc.status:12} {name}")
    finally:
        conn.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pii-scrubber", description=__doc__)
    parser.add_argument("--db", default="vault.db", help="vault database path")
    sub = parser.add_subparsers(dest="command", required=True)

    scrub = sub.add_parser("scrub", help="scrub a batch of PDFs")
    scrub.add_argument("files", nargs="+")
    scrub.add_argument("--out", default="scrubbed.zip")
    scrub.set_defaults(func=cmd_scrub)

    restore = sub.add_parser("restore", help="restore any subset of a job")
    restore.add_argument("files", nargs="+")
    restore.add_argument(
        "--job",
        default=None,
        help="optional: restrict to one batch. Files identify their own batch without it.",
    )
    restore.add_argument("--out", default="restored.zip")
    restore.set_defaults(func=cmd_restore)

    jobs = sub.add_parser("jobs", help="list jobs")
    jobs.add_argument("-v", "--verbose", action="store_true", help="decrypt and show filenames")
    jobs.set_defaults(func=cmd_jobs)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except MissingKeyMaterial as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("set PII_MASTER_KEY and PII_LOOKUP_SECRET to base64 32-byte values", file=sys.stderr)
        return 2
    except (BatchTooLarge, NotAPdf, vault.JobNotFound, vault.JobExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
