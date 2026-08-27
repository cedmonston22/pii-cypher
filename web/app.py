"""FastAPI front end: batch scrub in, zip out; selective restore.

Processing is synchronous. One request scrubs the batch and returns the result,
which is why ``core.pipeline`` caps batch size -- the caps are what keep the
request inside the server timeout without a queue or a worker.

Uploaded bytes are never written to disk. Finished archives are held in memory
only long enough for the browser to fetch them.
"""

from __future__ import annotations

import io
import os
import secrets
import time
import zipfile
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from core import vault
from core.keys import MissingKeyMaterial, unwrap
from core.pipeline import BatchTooLarge, NotAPdf, restore_batch, scrub_batch

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("PII_VAULT_DB", "vault.db")

# Finished archives live here between the POST that builds them and the GET that
# downloads them. In memory, short lived, and never on disk.
DOWNLOAD_TTL_SECONDS = 900
MAX_PENDING_DOWNLOADS = 32

app = FastAPI(title="PII Scrubber")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

_downloads: dict[str, tuple[float, str, bytes]] = {}


def _db():
    return vault.connect(DB_PATH)


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


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "scrub.html", {})


@app.post("/scrub", response_class=HTMLResponse)
async def scrub(request: Request, files: list[UploadFile]):
    payloads = await _read_uploads(files)
    conn = _db()
    try:
        result = scrub_batch(conn, payloads)
    except (BatchTooLarge, NotAPdf) as exc:
        return templates.TemplateResponse(
            request, "scrub.html", {"error": str(exc)}, status_code=400
        )
    except MissingKeyMaterial as exc:
        return templates.TemplateResponse(
            request, "scrub.html", {"error": f"Server not configured: {exc}"}, status_code=500
        )
    finally:
        conn.close()

    download = None
    if result.scrubbed:
        archive = _zip([(d.filename, d.pdf_bytes) for d in result.scrubbed])
        download = _stash(f"scrubbed-{result.job_id[:8]}.zip", archive)

    return templates.TemplateResponse(
        request, "scrub_result.html", {"result": result, "download": download}
    )


@app.get("/jobs", response_class=HTMLResponse)
def jobs(request: Request):
    conn = _db()
    try:
        return templates.TemplateResponse(request, "jobs.html", {"jobs": vault.list_jobs(conn)})
    finally:
        conn.close()


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
                    request, "restore.html", {"error": str(exc), "job_id": job_id}
                )
        return templates.TemplateResponse(
            request,
            "restore.html",
            {"job_id": job_id, "documents": documents, "jobs": vault.list_jobs(conn, limit=10)},
        )
    finally:
        conn.close()


@app.post("/restore", response_class=HTMLResponse)
async def restore(request: Request, files: list[UploadFile] = None):
    """Restore uploaded files. No job id: each file identifies its own batch."""
    payloads = await _read_uploads(files or [])
    conn = _db()
    try:
        result = restore_batch(conn, payloads)
    except (BatchTooLarge, NotAPdf) as exc:
        return templates.TemplateResponse(
            request, "restore.html", {"error": str(exc)}, status_code=400
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
        request, "restore_result.html", {"result": result, "download": download}
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
