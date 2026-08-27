"""Web layer: the full upload -> zip -> restore path a user actually takes."""

import io
import zipfile

import pymupdf
import pytest
from fastapi.testclient import TestClient

from core.verify import extract_all_text
from tests.test_pipeline import K1_VALUES, NAMES_KEPT


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PII_VAULT_DB", str(tmp_path / "web.db"))
    import importlib

    from web import app as app_module

    importlib.reload(app_module)
    return TestClient(app_module.app)


def _zip_members(payload: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _upload(name: str, data: bytes):
    return ("files", (name, data, "application/pdf"))


def _job_id_from(html: str) -> str:
    marker = 'class="jobid mono">'
    start = html.index(marker) + len(marker)
    return html[start : html.index("<", start)].strip()


def _download_token(html: str) -> str:
    marker = '/download/'
    start = html.index(marker) + len(marker)
    return html[start : html.index('"', start)]


def test_index_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Scrub a batch" in response.text


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_scrub_download_and_restore(client, k1_bytes):
    scrub = client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)])
    assert scrub.status_code == 200
    job_id = _job_id_from(scrub.text)
    assert "us-1065-k1" in scrub.text

    archive = client.get(f"/download/{_download_token(scrub.text)}")
    assert archive.headers["content-type"] == "application/zip"
    members = _zip_members(archive.content)
    assert list(members) == ["k1.pdf"], "original filenames are preserved in the archive"

    scrubbed_text = extract_all_text(members["k1.pdf"])
    for value in K1_VALUES:
        assert value not in scrubbed_text
    for name in NAMES_KEPT:
        assert name in scrubbed_text

    restore = client.post(
        "/restore",
        data={"job_id": job_id},
        files=[_upload("renamed.pdf", members["k1.pdf"])],
    )
    assert restore.status_code == 200
    restored = _zip_members(client.get(f"/download/{_download_token(restore.text)}").content)
    restored_text = extract_all_text(restored["renamed.pdf"])
    for value in K1_VALUES:
        assert value in restored_text


def test_download_link_is_single_use(client, k1_bytes):
    scrub = client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)])
    token = _download_token(scrub.text)
    assert client.get(f"/download/{token}").status_code == 200
    assert client.get(f"/download/{token}").status_code == 404


def test_quarantined_files_are_shown_prominently(client, k1_bytes):
    """A user who does not notice a skipped file will assume it was processed."""
    blank = pymupdf.open()
    blank.new_page()

    response = client.post(
        "/scrub",
        files=[_upload("good.pdf", k1_bytes), _upload("scan.pdf", blank.tobytes())],
    )
    assert "were not scrubbed" in response.text
    assert "scan.pdf" in response.text
    assert "NoTextLayer" in response.text

    members = _zip_members(client.get(f"/download/{_download_token(response.text)}").content)
    assert list(members) == ["good.pdf"], "quarantined files must not ship in the archive"


def test_non_pdf_upload_is_rejected(client):
    response = client.post("/scrub", files=[_upload("evil.pdf", b"MZ not a pdf")])
    assert response.status_code == 400
    assert "not a PDF" in response.text


def test_restore_with_unknown_job_is_rejected(client, k1_bytes):
    response = client.post(
        "/restore",
        data={"job_id": "00000000-0000-0000-0000-000000000000"},
        files=[_upload("k1.pdf", k1_bytes)],
    )
    assert response.status_code == 400
    assert "no such job" in response.text


def test_unresolved_tokens_are_surfaced(client, k1_bytes):
    """A partial restore must never look finished."""
    first = client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)])
    first_zip = _zip_members(client.get(f"/download/{_download_token(first.text)}").content)

    second = client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)])
    other_job = _job_id_from(second.text)

    response = client.post(
        "/restore", data={"job_id": other_job}, files=[_upload("k1.pdf", first_zip["k1.pdf"])]
    )
    assert "could not be restored" in response.text
    assert "did not resolve" in response.text


def test_jobs_page_lists_the_batch(client, k1_bytes):
    job_id = _job_id_from(client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)]).text)
    jobs = client.get("/jobs")
    assert job_id in jobs.text


def test_job_detail_decrypts_filenames_for_display(client, k1_bytes):
    job_id = _job_id_from(client.post("/scrub", files=[_upload("Smith_John_K1.pdf", k1_bytes)]).text)
    page = client.get(f"/restore?job_id={job_id}")
    assert "Smith_John_K1.pdf" in page.text
