"""FastAPI front end: batch scrub in, zip out; selective restore.

Processing is synchronous. One request scrubs the batch and returns the result,
which is why ``core.pipeline`` caps batch size -- the caps are what keep the
request inside the server timeout without a queue or a worker.

Uploaded bytes are never written to disk. Finished archives are held in memory
only long enough for the browser to fetch them.
"""

from __future__ import annotations

import io
import secrets
import time
import zipfile
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from core import paths, relocate, vault
from core.config import ConfigError
from core.relocate import RelocateRefused
from core.keys import MissingKeyMaterial, unwrap
from core.piitypes import canonical
from core.pipeline import (
    MAX_BATCH_BYTES,
    MAX_FILES,
    MAX_FILE_BYTES,
    MAX_PAGES,
    DEFAULT_POLICY,
    BatchTooLarge,
    NotAPdf,
    restore_batch,
    scrub_batch,
)
from core.tokens import MAX_REVEAL_DIGITS
from detect.policy import resolve_reveal

BASE_DIR = Path(__file__).resolve().parent

# Finished archives live here between the POST that builds them and the GET that
# downloads them. In memory, short lived, and never on disk.
DOWNLOAD_TTL_SECONDS = 900
MAX_PENDING_DOWNLOADS = 32

# The scrub form's policy controls. Only the types a field map can actually
# describe are offered: PHONE and DOB exist in the vocabulary for detection, and
# a policy naming only those would match no field and quarantine the batch.
POLICY_ROWS = [
    {"type": "EIN", "field": "A — partnership employer identification number", "digits": True},
    {"type": "SSN", "field": "E — partner's SSN or TIN", "digits": True},
    {"type": "ITIN", "field": "E — partner's ITIN, where one is used instead", "digits": True},
    {"type": "ADDRESS", "field": "B and F — street, city, state and ZIP", "digits": False},
]
REVEAL_CHOICES = list(range(2, MAX_REVEAL_DIGITS + 1))

# Rendered into the upload copy and the client-side gauges. Derived from the
# constants the pipeline actually enforces, never retyped: the template used to
# hard-code "20 pages per document" and still said it after the cap moved to 100.
CAPS = {
    "max_files": MAX_FILES,
    "max_file_bytes": MAX_FILE_BYTES,
    "max_batch_bytes": MAX_BATCH_BYTES,
    "max_file_mb": MAX_FILE_BYTES // (1024 * 1024),
    "max_batch_mb": MAX_BATCH_BYTES // (1024 * 1024),
    "max_pages": MAX_PAGES,
}

app = FastAPI(title="PII Scrubber")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
# Alpine is vendored rather than pulled from a CDN: the tool is meant to run
# offline on a firm's own machine, and a scrubbing UI that silently depends on
# a third party at page load is the wrong trade.
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

_downloads: dict[str, tuple[float, str, bytes]] = {}


def same_origin(request: Request) -> None:
    """Refuse a form POST that came from another site.

    There is no authentication here, so without this a page on any other site
    could make the browser submit to the app -- repointing the vault, or making
    it chew through PDFs of the attacker's choosing. A CSRF token would need a
    session and a cookie, which is new state for one form; this needs neither
    and can therefore cover every mutating route the same way.

    An absent Origin is allowed. That is a non-browser client -- curl, the CLI,
    the test suite -- and browsers always send the header on a cross-origin form
    POST, so the case this exists for is covered. It is not full CSRF protection
    and should not be described as such.
    """
    origin = request.headers.get("origin")
    if origin is None:
        return
    if origin != f"{request.url.scheme}://{request.url.netloc}":
        raise HTTPException(status_code=403, detail="cross-site request refused")


def _db():
    """Open the vault, resolving its location on every call.

    Resolved per call rather than captured at import so the environment can be
    set after this module is imported -- which is what the test suite does, and
    what a launcher that sources a key file before starting uvicorn needs.
    """
    path, _ = paths.resolve_db()
    paths.ensure_dir(path.parent)
    return vault.connect(path)


def _stash(filename: str, payload: bytes) -> str:
    """Hold an archive for download and evict anything stale."""
    now = time.time()
    for key in [k for k, (t, _, _) in _downloads.items() if now - t > DOWNLOAD_TTL_SECONDS]:
        del _downloads[key]
    while len(_downloads) >= MAX_PENDING_DOWNLOADS:
        del _downloads[min(_downloads, key=lambda k: _downloads[k][0])]

    token = secrets.token_urlsafe(16)
    _downloads[token] = (now, filename, payload)
    return token


def _zip(files: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files:
            archive.writestr(name, data)
    return buffer.getvalue()


async def _read_uploads(uploads: list[UploadFile]) -> list[tuple[str, bytes]]:
    return [(u.filename or "unnamed.pdf", await u.read()) for u in uploads if u.filename]


def _parse_reveal(pairs: list[str]) -> dict[str, int]:
    """Read the ``TYPE=N`` values the reveal selects submit.

    The same shape the CLI's ``--reveal`` takes. Kept as four lines in each
    place rather than shared: the string form is a transport detail of two
    interfaces, not something the policy layer should know about.
    """
    digits: dict[str, int] = {}
    for pair in pairs:
        name, separator, count = pair.partition("=")
        if not separator or not count.isdigit():
            raise ValueError(f"Unreadable disclosure setting: {pair!r}")
        digits[canonical(name.strip().upper())] = int(count)
    return digits


def _build_policy(pii_types: list[str], reveal: list[str]) -> dict:
    """Turn the submitted form into a policy, or raise for the 400.

    Raises:
        ValueError: for an empty selection, an unknown type or an out-of-range
            count. ``resolve_reveal`` is called here rather than left to
            ``scrub_batch`` so a bad form is a 400 the user can fix, not a 500.
    """
    chosen = [canonical(t.strip().upper()) for t in pii_types]
    if not chosen:
        raise ValueError(
            "Choose at least one type to tokenise. A policy matching nothing "
            "would return every document unchanged."
        )
    policy = {"pii_types": chosen, "reveal_digits": _parse_reveal(reveal)}
    resolve_reveal(policy)
    return policy


def _safe_reveal(pairs: list[str]) -> dict[str, int]:
    """Best-effort parse for re-rendering a form that was already rejected."""
    try:
        return _parse_reveal(pairs)
    except ValueError:
        return {}


def _form_context(
    chosen: list[str] | None = None, reveal: dict[str, int] | None = None
) -> dict:
    """Context for the scrub form, so a rejected submission keeps its settings."""
    return {
        "rows": POLICY_ROWS,
        "reveal_choices": REVEAL_CHOICES,
        "chosen": set(chosen if chosen is not None else DEFAULT_POLICY["pii_types"]),
        "reveal": reveal or {},
        "caps": CAPS,
        "nav": "scrub",
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "scrub.html", _form_context())


@app.post("/scrub", response_class=HTMLResponse, dependencies=[Depends(same_origin)])
async def scrub(
    request: Request,
    files: list[UploadFile],
    policy_form: str = Form(default=""),
    pii_types: list[str] = Form(default=[]),
    reveal: list[str] = Form(default=[]),
):
    def rejected(message: str, status: int):
        # Re-render with the settings intact. Losing them on a rejected upload
        # invites the user to re-tick from memory and get it wrong.
        chosen = pii_types if policy_form else None
        context = {**_form_context(chosen, _safe_reveal(reveal)), "error": message}
        return templates.TemplateResponse(request, "scrub.html", context, status_code=status)

    # An absent marker means the client sent no policy at all, which takes the
    # shipped default. Only a submitted-but-empty selection is an error: the
    # form always carries the marker, so unticking everything is a real choice
    # rather than a client that never knew about the controls.
    try:
        policy = _build_policy(pii_types, reveal) if policy_form else dict(DEFAULT_POLICY)
    except ValueError as exc:
        return rejected(str(exc), 400)

    payloads = await _read_uploads(files)
    conn = _db()
    try:
        result = scrub_batch(conn, payloads, policy=policy)
    except (BatchTooLarge, NotAPdf) as exc:
        return rejected(str(exc), 400)
    except MissingKeyMaterial as exc:
        return rejected(f"Server not configured: {exc}", 500)
    finally:
        conn.close()

    download = None
    if result.scrubbed:
        archive = _zip([(d.filename, d.pdf_bytes) for d in result.scrubbed])
        download = _stash(f"scrubbed-{result.job_id[:8]}.zip", archive)

    return templates.TemplateResponse(
        request,
        "scrub_result.html",
        {"result": result, "download": download, "policy": policy},
    )


@app.get("/jobs", response_class=HTMLResponse)
def jobs(request: Request):
    conn = _db()
    try:
        return templates.TemplateResponse(
            request, "jobs.html", {"jobs": vault.list_jobs(conn), "nav": "history"}
        )
    finally:
        conn.close()


def _vault_facts() -> dict:
    """What the settings page reports about the vault currently in use.

    Never reaches a candidate through ``vault.connect``: on a file that is not
    ours that would write our schema into it, and on a missing path it would
    create a vault as a side effect of describing the situation.
    """
    path, source = paths.resolve_db()
    facts = {
        "path": str(path),
        "source": source,
        "config_path": str(paths.config_path()),
        "job_count": None,
        "decrypts": None,
        "detail": None,
        "chosen": source == "settings",
    }
    if not path.is_file():
        facts["state"] = "missing" if source == "settings" else "absent"
    elif not relocate.looks_like_a_vault(path):
        facts["state"] = "foreign"
    else:
        facts["state"] = "ok"
        facts["job_count"] = relocate.count_jobs(path)
        facts["decrypts"], facts["detail"] = relocate.verify_decryptable(path)
    return facts


def _settings_context(**overrides) -> dict:
    """Context for the settings page, so a rejected submission keeps its path."""
    context = {
        "nav": "settings",
        "key_file": str(paths.env_file_path()),
        "typed": "",
        "preview": None,
        "notice": None,
        "config_error": None,
        "vault": None,
    }
    try:
        context["vault"] = _vault_facts()
    except ConfigError as exc:
        # The one state the page must still render: resolution refuses rather
        # than falling through, so without this the app cannot be repaired
        # from its own UI.
        context["config_error"] = str(exc)
    return {**context, **overrides}


@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request):
    return templates.TemplateResponse(request, "settings.html", _settings_context())


@app.post("/settings", response_class=HTMLResponse, dependencies=[Depends(same_origin)])
async def settings_change(
    request: Request,
    action: str = Form(default=""),
    path: str = Form(default=""),
):
    """Move the vault, adopt an existing one, or clear the setting.

    Deliberately ``async``. ``scrub`` is also async and has no await between
    resolving the vault and finishing the batch, so nothing else can be
    scheduled in between. A sync handler here would run in the threadpool and
    could interleave with that stretch, switching the vault out from under a
    scrub that is mid-write.
    """

    def rejected(message: str):
        return templates.TemplateResponse(
            request,
            "settings.html",
            _settings_context(typed=path, error=message),
            status_code=400,
        )

    def preview_of(action_name, destination, job_count, *, source=None, detail=None,
                   replacing_empty=False, warnings=()):
        return templates.TemplateResponse(
            request,
            "settings.html",
            _settings_context(
                typed=path,
                preview={
                    "action": action_name,
                    "source": str(source) if source else None,
                    "destination": str(destination),
                    "job_count": job_count,
                    "detail": detail,
                    "replacing_empty": replacing_empty,
                    "warnings": list(warnings),
                },
            ),
        )

    if action == "forget":
        paths.clear_configured_db()
        return templates.TemplateResponse(
            request,
            "settings.html",
            _settings_context(notice="Setting cleared. The vault is back at the default location."),
        )

    try:
        destination, warnings = paths.validate_vault_path(path)
    except ValueError as exc:
        return rejected(str(exc))

    try:
        if action == "move":
            source, _ = paths.resolve_db()
            plan = relocate.plan_move(source, destination)
            return preview_of(
                "move", plan.destination, plan.job_count, source=plan.source,
                replacing_empty=plan.replacing_empty, warnings=warnings,
            )
        if action == "move-confirm":
            source, _ = paths.resolve_db()
            result = relocate.move_vault(source, destination)
            notice = (
                f"The vault is now at {result.destination}. "
                f"The previous file is kept as {result.kept.name}."
            )
        elif action == "use":
            plan = relocate.plan_adopt(destination)
            return preview_of("use", plan.path, plan.job_count, detail=plan.detail,
                              warnings=warnings)
        elif action == "use-confirm":
            plan = relocate.adopt_vault(destination)
            notice = f"Now using the vault at {plan.path}, holding {plan.job_count} job(s)."
        else:
            return rejected("Choose either Move or Use.")
    except (RelocateRefused, ConfigError) as exc:
        return rejected(str(exc))

    return templates.TemplateResponse(request, "settings.html", _settings_context(notice=notice))


@app.get("/restore", response_class=HTMLResponse)
def restore_form(request: Request, job_id: str = ""):
    """Upload form. The job list is for browsing only -- restore does not need it."""
    conn = _db()
    try:
        documents = []
        if job_id:
            try:
                job_key = unwrap(vault.get_wrapped_key(conn, job_id))
                vault.get_job(conn, job_id)
                documents = [
                    {
                        "id": doc.id,
                        "filename": vault.document_filename(conn, doc.id, job_key),
                        "status": doc.status,
                        "form_id": doc.form_id,
                    }
                    for doc in vault.list_documents(conn, job_id)
                ]
            except (vault.JobNotFound, vault.JobExpired) as exc:
                return templates.TemplateResponse(
                    request, "restore.html", {"error": str(exc), "job_id": job_id, "nav": "restore"}
                )
        return templates.TemplateResponse(
            request,
            "restore.html",
            {
                "job_id": job_id,
                "documents": documents,
                "jobs": vault.list_jobs(conn, limit=10),
                "nav": "restore",
            },
        )
    finally:
        conn.close()


@app.post("/restore", response_class=HTMLResponse, dependencies=[Depends(same_origin)])
async def restore(request: Request, files: list[UploadFile] = None):
    """Restore uploaded files. No job id: each file identifies its own batch."""
    payloads = await _read_uploads(files or [])
    conn = _db()
    try:
        result = restore_batch(conn, payloads)
    except (BatchTooLarge, NotAPdf) as exc:
        return templates.TemplateResponse(
            request, "restore.html", {"error": str(exc), "nav": "restore"}, status_code=400
        )
    except MissingKeyMaterial as exc:
        return templates.TemplateResponse(
            request, "restore.html", {"error": f"Server not configured: {exc}"}, status_code=500
        )
    finally:
        conn.close()

    download = None
    if result.restored:
        archive = _zip([(d.filename, d.pdf_bytes) for d in result.restored])
        stamp = result.jobs[0][:8] if result.jobs else "files"
        download = _stash(f"restored-{stamp}.zip", archive)

    return templates.TemplateResponse(
        request, "restore_result.html", {"result": result, "download": download, "nav": "restore"}
    )


@app.get("/download/{token}")
def download(token: str):
    entry = _downloads.pop(token, None)
    if entry is None:
        raise HTTPException(status_code=404, detail="This download has expired.")
    _, filename, payload = entry
    return Response(
        content=payload,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
