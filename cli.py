"""Command line harness over the same pipeline functions the web app uses.

Useful for running a batch without a browser and for checking the caps and
quarantine paths from a shell.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import secrets
import sqlite3
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import keys, paths, relocate, vault
from core.config import ConfigError
from core.crypto import LOOKUP_SECRET_ENV
from core.keys import KEY_LEN, MASTER_KEY_ENV, MissingKeyMaterial, load_secret, unwrap
from core.relocate import SECRET_NAMES, RelocateRefused
from core.piitypes import PII_TYPES, UnknownPiiType, canonical
from core.pipeline import (
    DEFAULT_POLICY,
    BatchTooLarge,
    NotAPdf,
    PolicyMismatch,
    restore_batch,
    scrub_batch,
)
from core.tokens import MAX_REVEAL_DIGITS


def _pii_type(text: str) -> str:
    """Accept a type name in any case. argparse checks it against ``choices``."""
    return text.strip().upper()


def _reveal_pair(text: str) -> tuple[str, int]:
    """Parse ``TYPE=N``.

    Raises:
        argparse.ArgumentTypeError: so a bad flag is a usage error rather than a
            traceback. ``canonical`` raises ValueError, which argparse renders
            the same way.
    """
    name, separator, count = text.partition("=")
    if not separator or not count.isdigit():
        raise argparse.ArgumentTypeError(f"expected TYPE=N, got {text!r}")
    return canonical(_pii_type(name)), int(count)


def _policy(args: argparse.Namespace) -> dict[str, Any]:
    """Build a policy from the flags, starting from the shipped default.

    Starting from the default matters: a bare ``--reveal EIN=4`` must not read
    as "redact nothing but reveal an EIN", which is a policy matching no field
    and quarantines the whole batch.
    """
    policy: dict[str, Any] = dict(DEFAULT_POLICY)
    if args.pii_types is not None:
        policy["pii_types"] = args.pii_types
    if args.reveal:
        policy["reveal_digits"] = dict(args.reveal)
    return policy


def _read(files: list[str]) -> list[tuple[str, bytes]]:
    return [(Path(f).name, Path(f).read_bytes()) for f in files]


def _open_vault(args: argparse.Namespace) -> sqlite3.Connection:
    """Open the vault the flags and environment point at.

    The warning is printed for a vault still sitting in the working directory:
    it is found today, but only from that directory, which is the bug `migrate`
    exists to end.
    """
    path, source = paths.resolve_db(args.db)
    warning = paths.legacy_warning(source)
    if warning:
        print(warning, file=sys.stderr)
    paths.ensure_dir(path.parent)
    return vault.connect(path)


def _write_zip(destination: Path, files: list[tuple[str, bytes]]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files:
            archive.writestr(name, data)


def cmd_scrub(args: argparse.Namespace) -> int:
    policy = _policy(args)
    conn = _open_vault(args)
    try:
        result = scrub_batch(conn, _read(args.files), policy=policy)
    finally:
        conn.close()

    print(f"job_id: {result.job_id}")
    print(f"tokenising: {', '.join(sorted(policy['pii_types']))}")
    for pii_type, count in sorted((policy.get("reveal_digits") or {}).items()):
        if count:
            print(f"  showing the last {count} digits of each {pii_type}")

    for doc in result.scrubbed:
        print(f"  scrubbed    {doc.filename}  ({doc.form_id}, {doc.replaced_count} replaced)")
        for warning in doc.warnings:
            print(f"      NOT REPLACED, looks like PII: {warning}")
        for pii_type, count in sorted(doc.left_by_policy.items()):
            print(f"      LEFT READABLE by policy: {count} x {pii_type}")
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
    if any(d.left_by_policy for d in result.scrubbed):
        print("\nSome identifiers stayed readable because the policy excluded"
              " their type. See above.")
        return 1
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    conn = _open_vault(args)
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
    conn = _open_vault(args)
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


def _err(message: str) -> None:
    print(message, file=sys.stderr)


def _generate() -> str:
    return base64.b64encode(secrets.token_bytes(KEY_LEN)).decode()


def _write_key_file(
    path: Path, master: str, lookup: str, carry_over: dict[str, str] | None = None
) -> None:
    """Set the two vault secrets, preserving anything else in the file.

    This used to write exactly two lines, which silently discarded every other
    key. That is survivable only while the vault secrets are the only things
    living here, and nothing guarantees they stay that way: ``migrate`` calls
    this, so any other secret in the file would be destroyed as a side effect of
    moving a vault.

    ``carry_over`` is for ``migrate``, whose destination file does not exist yet
    -- the secrets to preserve are in the *source*, so reading the destination
    alone would find nothing to keep and drop them just as silently.

    A file that cannot be parsed is refused rather than replaced -- the rule
    ``read_key_file`` already follows, and for the same reason: overwriting is
    how key material that was merely misspelled becomes key material that is
    gone.
    """
    existing = dict(keys.read_key_file(path))
    existing.update(carry_over or {})
    existing[MASTER_KEY_ENV] = master
    existing[LOOKUP_SECRET_ENV] = lookup

    # The two vault secrets lead, then whatever else was already there, so the
    # file a user opens still reads the way it always has.
    ordered = [MASTER_KEY_ENV, LOOKUP_SECRET_ENV]
    ordered += [name for name in existing if name not in ordered]

    path.write_text(
        "".join(f"{name}={existing[name]}\n" for name in ordered),
        encoding="utf-8",
    )
    if os.name == "posix":
        path.chmod(0o600)
    # The parsed file is cached by path, and a miss is cached too. Without this
    # a process that generates key material then reads it back still sees "not
    # set" and is invited to generate again.
    keys.clear_cache()


def _keys_present() -> bool:
    """Whether both secrets resolve right now, from wherever they live."""
    try:
        load_secret(MASTER_KEY_ENV, length=KEY_LEN)
        load_secret(LOOKUP_SECRET_ENV)
    except MissingKeyMaterial:
        return False
    return True


def cmd_init(args: argparse.Namespace) -> int:
    """Generate key material, and only ever when there is no vault to orphan.

    The run scripts used to generate whenever .env.local was absent, so a fresh
    clone beside an existing vault minted a new master key and made every job in
    it permanently unreadable. What matters is whether a vault exists, not
    whether a file does.
    """
    if _keys_present():
        if not args.quiet:
            print(f"key material already present ({keys.secret_source(MASTER_KEY_ENV)})")
        return 0

    db_path, _ = paths.resolve_db(args.db)
    if db_path.exists():
        _err(f"error: a vault exists at {db_path}, but its key material is missing.")
        _err("Generating a new key would make every job in it permanently unreadable,")
        _err("so nothing has been written.")
        _err("")
        _err("  keys in a checkout .env.local   python cli.py migrate")
        _err("  keys held elsewhere             set them in the environment")
        return 2

    key_file = paths.env_file_path()
    paths.ensure_dir(key_file.parent)
    _write_key_file(key_file, _generate(), _generate())
    print(f"generated key material into {key_file}")
    print("Nothing backs this up yet. Run: python cli.py backup <path>")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Explain what this install is actually using. Never prints a secret."""
    try:
        db_path, source = paths.resolve_db(args.db)
    except ConfigError as exc:
        _err(f"error: {exc}")
        _err("Fix the file by hand, or run `python cli.py forget` to clear the setting.")
        return 2

    print(f"vault   {db_path}")
    print(f"        located by: {source}")
    if source == "settings":
        print(f"        set in {paths.config_path()}")

    if not db_path.is_file():
        if source == "settings":
            print("        MISSING -- the setting points at a file that is not there.")
            print("        Reconnect the drive, or run `python cli.py forget`.")
        else:
            print("        does not exist yet")
    elif not relocate.looks_like_a_vault(db_path):
        # Never vault.connect here: it would run our schema over whatever this
        # actually is, which for a status command is an absurd thing to do.
        print("        exists but is not a pii-cypher vault")
    else:
        print(f"        {relocate.count_jobs(db_path)} job(s)")
        verified, detail = relocate.verify_decryptable(db_path)
        # The whole hazard of a movable vault is one that opens and cannot be
        # read, and this is the command whose job is to say what is really going on.
        print(f"        keys decrypt it: {'yes' if verified else 'NO'}  ({detail})")

    print("keys")
    for name in SECRET_NAMES:
        print(f"        {name:<18} {keys.secret_source(name) or 'NOT FOUND'}")

    warning = paths.legacy_warning(source)
    if warning:
        print("")
        print(warning)
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    """Copy the vault, then print the two keys that make it readable."""
    db_path, _ = paths.resolve_db(args.db)
    if not db_path.is_file():
        _err(f"error: no vault at {db_path}")
        return 2

    destination = Path(args.path)
    if destination.exists():
        _err(f"error: {destination} already exists")
        return 2
    destination.parent.mkdir(parents=True, exist_ok=True)

    conn = vault.connect(db_path)
    try:
        vault.snapshot(conn, destination)
        job_count = vault.count_jobs(conn)
    finally:
        conn.close()

    print(f"wrote {destination}  ({job_count} job(s))")
    print("")
    print("That copy is inert without the two keys below. Put them in a password")
    print("manager, somewhere other than the backup itself -- keeping the two")
    print("together is the arrangement this move exists to end.")
    print("")
    for name in SECRET_NAMES:
        print(f"  {name}={base64.b64encode(load_secret(name)).decode()}")
    return 0


def _validated(raw: str) -> Path | None:
    """Normalise a typed path, printing any warnings. None means refused."""
    try:
        path, warnings = paths.validate_vault_path(raw)
    except ValueError as exc:
        _err(f"error: {exc}")
        return None
    for warning in warnings:
        print(f"note: {warning}")
        print("")
    return path


def cmd_move(args: argparse.Namespace) -> int:
    """Copy the vault to a chosen file and remember the choice.

    The key file does not go with it. A vault on another drive is inert to
    anyone who has not been given the two keys `backup` prints.
    """
    source, _ = paths.resolve_db(args.db)
    destination = _validated(args.path)
    if destination is None:
        return 2

    try:
        if args.dry_run:
            plan = relocate.plan_move(source, destination)
            print("would move:")
            print(f"  {plan.source}")
            print(f"  -> {plan.destination}"
                  + ("  (replacing an empty one)" if plan.replacing_empty else ""))
            print(f"  {plan.job_count} job(s); the key file stays at {paths.env_file_path()}")
            print("")
            print("nothing was changed")
            return 0
        result = relocate.move_vault(source, destination)
    except RelocateRefused as exc:
        _err(f"error: {exc}")
        return 2

    print(f"vault  -> {result.destination}")
    print(f"verified: {result.detail}")
    print("")
    print(f"The original is kept as {result.kept.name}.")
    print(f"The key file has not moved; it is still at {paths.env_file_path()}.")
    return 0


def cmd_use(args: argparse.Namespace) -> int:
    """Point at a vault that already exists, without copying anything."""
    path = _validated(args.path)
    if path is None:
        return 2

    try:
        plan = relocate.plan_adopt(path) if args.dry_run else relocate.adopt_vault(path)
    except RelocateRefused as exc:
        _err(f"error: {exc}")
        return 2

    if args.dry_run:
        print(f"would use {plan.path}  ({plan.job_count} job(s), {plan.detail})")
        print("")
        print("nothing was changed")
        return 0

    print(f"vault  -> {plan.path}  ({plan.job_count} job(s))")
    print(f"verified: {plan.detail}")
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    """Clear the chosen vault and fall back to the per-user default.

    The repair path. A setting pointing at a drive that is no longer connected
    stops the app from starting, and `read` refuses rather than falling through,
    so this has to work even when the settings file is unreadable.
    """
    paths.clear_configured_db()
    fallback, source = paths.resolve_db()
    print(f"setting cleared; the vault is now {fallback} (located by: {source})")
    if fallback.is_file():
        return 0

    print("Nothing is there yet, so a new empty vault will be created on first use.")
    # The likeliest reason to be running this is a move that went somewhere
    # unreachable, and in that case the data is sitting right next to the
    # fallback under its kept name. Saying so beats leaving it to be found.
    kept = sorted(fallback.parent.glob("vault.*-*.db")) if fallback.parent.is_dir() else []
    if kept:
        print("")
        print("These look like earlier copies of a vault, kept by move or migrate:")
        for path in kept:
            print(f"  {path}")
        print("Point at one with `python cli.py use <path>` if it is the one you want.")
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    """Move a checkout vault to the per-user location, deliberately.

    Every step refuses rather than guessing. There is no backup behind this, so
    a wrong guess is unrecoverable.
    """
    source_db = Path(args.source)
    source_keys = Path(args.env_file)
    dest_db = Path(args.to) if args.to else paths.default_db_path()
    dest_keys = paths.env_file_path()

    if not source_db.is_file():
        _err(f"error: no vault at {source_db}")
        return 2
    if not source_keys.is_file():
        _err(f"error: no key file at {source_keys}")
        _err("Without it the vault cannot be read, and moving it would relocate")
        _err("ciphertext that nothing can open.")
        return 2
    if source_db.resolve() == dest_db.resolve():
        print(f"already at {dest_db}; nothing to do")
        return 0

    values = keys.read_key_file(source_keys)
    absent = [name for name in SECRET_NAMES if not values.get(name)]
    if absent:
        _err(f"error: {source_keys} does not define {', '.join(absent)}")
        return 2
    try:
        master = base64.b64decode(values[MASTER_KEY_ENV], validate=True)
    except (binascii.Error, ValueError):
        _err(f"error: {MASTER_KEY_ENV} in {source_keys} is not valid base64")
        return 2
    if len(master) != KEY_LEN:
        _err(f"error: {MASTER_KEY_ENV} must decode to {KEY_LEN} bytes, got {len(master)}")
        return 2

    replace_stub = False
    if dest_db.exists():
        conn = vault.connect(dest_db)
        try:
            existing = vault.count_jobs(conn)
        finally:
            conn.close()
        if existing:
            _err(f"error: a vault holding {existing} job(s) is already at {dest_db}")
            _err("Choosing between two populated vaults is not this program's decision.")
            return 2
        # An empty one is the stub a stray run from another directory leaves.
        replace_stub = True

    if dest_keys.is_file():
        existing_values = keys.read_key_file(dest_keys)
        if any(existing_values.get(n) != values.get(n) for n in SECRET_NAMES):
            _err(f"error: different key material is already at {dest_keys}")
            _err("Overwriting it would orphan whatever it belongs to.")
            return 2

    if args.dry_run:
        print("would migrate:")
        print(f"  vault      {source_db}")
        print(f"          -> {dest_db}" + ("  (replacing an empty one)" if replace_stub else ""))
        print(f"  keys       {source_keys}")
        print(f"          -> {dest_keys}")
        print("  then rename the source to vault.pre-migration-<timestamp>.db")
        print("")
        print("nothing was changed")
        return 0

    paths.ensure_dir(dest_db.parent)
    # Not the same directory once --to is given, and the key file always
    # goes to the per-user location regardless of where the vault lands.
    paths.ensure_dir(dest_keys.parent)
    if replace_stub:
        dest_db.unlink()
    conn = vault.connect(source_db)
    try:
        vault.snapshot(conn, dest_db)
    finally:
        conn.close()
    _write_key_file(
        dest_keys, values[MASTER_KEY_ENV], values[LOOKUP_SECRET_ENV], carry_over=values
    )

    # ambient_keys=False because migrate relocates the key file too, so the
    # copy must be checked the way the migrated install will read it rather
    # than the way this shell happens to be configured.
    verified, detail = relocate.verify_decryptable(dest_db, ambient_keys=False)
    if not verified:
        _err(f"error: the copy did not verify ({detail})")
        _err(f"Nothing was removed; {source_db} is untouched.")
        _err(f"Inspect {dest_db} and delete it before trying again.")
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    kept = source_db.with_name(f"vault.pre-migration-{stamp}.db")
    source_db.rename(kept)

    print(f"vault  -> {dest_db}")
    print(f"keys   -> {dest_keys}")
    print(f"verified: {detail}")
    print("")
    print(f"The original is kept as {kept.name}.")
    print(f"Delete it and {source_keys.name} once you have confirmed a real restore.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pii-scrubber", description=__doc__)
    parser.add_argument(
        "--db",
        default=None,
        help="vault database path (default: the per-user location, see `status`)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scrub = sub.add_parser("scrub", help="scrub a batch of PDFs")
    scrub.add_argument("files", nargs="+")
    scrub.add_argument("--out", default="scrubbed.zip")
    scrub.add_argument(
        "--pii-types",
        nargs="+",
        type=_pii_type,
        choices=sorted(PII_TYPES),
        default=None,
        help="which types to tokenise (default: the shipped policy)",
    )
    scrub.add_argument(
        "--reveal",
        action="append",
        type=_reveal_pair,
        metavar="TYPE=N",
        help=f"leave the last N digits of TYPE readable, 0 to {MAX_REVEAL_DIGITS}; repeatable",
    )
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

    status = sub.add_parser("status", help="where the vault and keys are")
    status.set_defaults(func=cmd_status)

    init = sub.add_parser("init", help="generate key material for a new install")
    init.add_argument("--quiet", action="store_true", help="say nothing when already set up")
    init.set_defaults(func=cmd_init)

    backup = sub.add_parser("backup", help="copy the vault and print its keys")
    backup.add_argument("path", help="destination file, which must not exist")
    backup.set_defaults(func=cmd_backup)

    migrate = sub.add_parser("migrate", help="move a checkout vault to the per-user location")
    migrate.add_argument("--from", dest="source", default="vault.db", help="vault to move")
    migrate.add_argument("--env-file", default=".env.local", help="key file to move with it")
    migrate.add_argument(
        "--to",
        default=None,
        help="where the VAULT goes (default: the per-user location). The key file"
        " always goes to the per-user location regardless, so a vault can be put"
        " on a shared drive without the key that opens it following it there.",
    )
    migrate.add_argument("--dry-run", action="store_true", help="print the plan and stop")
    migrate.set_defaults(func=cmd_migrate)

    move = sub.add_parser("move", help="move the vault to a chosen file and remember it")
    move.add_argument("path", help="destination file, as a full path")
    move.add_argument("--dry-run", action="store_true", help="print the plan and stop")
    move.set_defaults(func=cmd_move)

    use = sub.add_parser("use", help="point at a vault that already exists")
    use.add_argument("path", help="the vault to use, as a full path")
    use.add_argument("--dry-run", action="store_true", help="check it and stop")
    use.set_defaults(func=cmd_use)

    forget = sub.add_parser("forget", help="clear the chosen vault and use the default")
    forget.set_defaults(func=cmd_forget)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except MissingKeyMaterial as exc:
        # The exception already names the file it looked in and the way out; a
        # second generic hint here only buried it.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (BatchTooLarge, NotAPdf, vault.JobNotFound, vault.JobExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (PolicyMismatch, UnknownPiiType, ValueError) as exc:
        # A policy is wrong for the whole batch rather than for one document,
        # so it is a usage error here, not a per-document quarantine.
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
