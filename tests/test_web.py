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

    # No job id: the file identifies its own batch.
    restore = client.post("/restore", files=[_upload("renamed.pdf", members["k1.pdf"])])
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


def test_unscrubbed_file_is_reported_not_crashed(client, k1_bytes):
    """A file that was never scrubbed has no tokens to identify it."""
    response = client.post("/restore", files=[_upload("plain.pdf", k1_bytes)])
    assert response.status_code == 200
    assert "could not be matched" in response.text
    assert "no tokens found" in response.text


def test_restore_needs_no_job_id_field(client, k1_bytes):
    """The form must not ask for something the user will not have."""
    page = client.get("/restore")
    assert 'name="job_id"' not in page.text
    assert "identifies which batch" in page.text


def test_one_upload_can_span_two_batches(client, k1_bytes, k1_2025_bytes):
    """The point of the change: a pile of files from anywhere, all restored."""
    first = client.post("/scrub", files=[_upload("a.pdf", k1_bytes)])
    a = _zip_members(client.get(f"/download/{_download_token(first.text)}").content)["a.pdf"]

    second = client.post("/scrub", files=[_upload("b.pdf", k1_2025_bytes)])
    b = _zip_members(client.get(f"/download/{_download_token(second.text)}").content)["b.pdf"]

    assert _job_id_from(first.text) != _job_id_from(second.text)

    response = client.post("/restore", files=[_upload("a.pdf", a), _upload("b.pdf", b)])
    assert response.status_code == 200
    assert "different batches" in response.text

    restored = _zip_members(client.get(f"/download/{_download_token(response.text)}").content)
    assert set(restored) == {"a.pdf", "b.pdf"}
    assert "000-00-0000" in extract_all_text(restored["a.pdf"])
    assert "512-44-8890" in extract_all_text(restored["b.pdf"])


def test_unresolved_tokens_are_surfaced(client, k1_bytes, tmp_path):
    """A partial restore must never look finished."""
    import re

    from core import vault
    from core.crypto import token_hash

    scrub = client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)])
    scrubbed = _zip_members(client.get(f"/download/{_download_token(scrub.text)}").content)["k1.pdf"]

    victim = re.findall(r"PII-[A-Z0-9]{8}", extract_all_text(scrubbed))[0]
    conn = vault.connect(str(tmp_path / "web.db"))
    conn.execute("DELETE FROM vault_entries WHERE token_hash = ?", (token_hash(victim),))
    conn.commit()
    conn.close()

    response = client.post("/restore", files=[_upload("k1.pdf", scrubbed)])
    assert "could not be restored" in response.text
    assert "did not resolve" in response.text
    assert victim in response.text


def test_jobs_page_lists_the_batch(client, k1_bytes):
    job_id = _job_id_from(client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)]).text)
    jobs = client.get("/jobs")
    assert job_id in jobs.text


def test_job_detail_decrypts_filenames_for_display(client, k1_bytes):
    job_id = _job_id_from(client.post("/scrub", files=[_upload("Smith_John_K1.pdf", k1_bytes)]).text)
    page = client.get(f"/restore?job_id={job_id}")
    assert "Smith_John_K1.pdf" in page.text


def test_the_review_screen_shows_why_a_value_was_flagged(client, k1_2025_bytes, monkeypatch):
    """Evidence is not decoration -- it is what makes a warning actionable.

    A bare "this looks like PII" gives a reviewer nothing to judge. Naming the
    signals that agreed lets them tell a genuine map gap from a coincidence.
    """
    import copy

    from core import fieldmap

    original = fieldmap.load_field_maps

    def stale(*args, **kwargs):
        maps = copy.deepcopy(original(*args, **kwargs))
        maps[0]["fields"] = [f for f in maps[0]["fields"] if f["name"] != "partner_tin"]
        return maps

    monkeypatch.setattr("core.pipeline.load_field_maps", stale)

    response = client.post("/scrub", files=[_upload("k1.pdf", k1_2025_bytes)])
    html = response.text

    assert "Possible missed values" in html
    assert "512-44-8890" in html, "the value itself is shown, for review"
    assert "SSN" in html
    assert "validator:SSN" in html, "the evidence must reach the screen"
    assert "high" in html


# --------------------------------------------------------------------------
# the policy controls on the scrub form
# --------------------------------------------------------------------------


def _policy_form(types=("SSN", "ITIN", "EIN", "ADDRESS"), **reveal):
    """The fields the scrub form submits. Selects always send TYPE=N."""
    return {
        "policy_form": "1",
        "pii_types": list(types),
        "reveal": [f"{t}={n}" for t, n in reveal.items()],
    }


def _scrubbed_text(client, k1_bytes, data):
    response = client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)], data=data)
    assert response.status_code == 200, response.text
    archive = client.get(f"/download/{_download_token(response.text)}")
    return response.text, extract_all_text(_zip_members(archive.content)["k1.pdf"])


def test_the_form_offers_the_policy_controls(client):
    html = client.get("/").text
    assert 'name="pii_types"' in html
    assert 'name="reveal"' in html
    assert 'value="SSN=6"' in html, "the full range must be reachable"
    assert 'value="ADDRESS=4"' not in html, "an address has no last digits"


def test_an_unticked_type_is_left_and_reported(client, k1_bytes):
    """The green result must not hide an identifier the policy let through."""
    html, text = _scrubbed_text(client, k1_bytes, _policy_form(types=["EIN", "ADDRESS"]))

    assert "000-00-0000" in text, "the unticked SSN stays on the document"
    assert "Left readable by your policy" in html
    assert "SSN" in html


def test_a_revealed_tail_reaches_the_page(client, k1_bytes):
    html, text = _scrubbed_text(client, k1_bytes, _policy_form(SSN=4))

    assert "000-00-0000" not in text, "the whole value must still be gone"
    assert "-0000" in text, "the authorised tail must be readable"
    assert "The last <strong>4</strong> digits" in html


def test_unticking_everything_is_refused_not_defaulted(client, k1_bytes):
    """Silently applying the default would ignore what the user asked for."""
    response = client.post(
        "/scrub", files=[_upload("k1.pdf", k1_bytes)], data=_policy_form(types=[])
    )
    assert response.status_code == 400
    assert "at least one type" in response.text


def test_a_count_outside_the_range_is_a_400_not_a_500(client, k1_bytes):
    response = client.post(
        "/scrub", files=[_upload("k1.pdf", k1_bytes)], data=_policy_form(SSN=9)
    )
    assert response.status_code == 400
    assert "range is 0 to 6" in response.text


def test_a_rejected_submission_keeps_its_settings(client):
    """Re-ticking from memory is how the wrong policy gets submitted twice."""
    response = client.post(
        "/scrub", files=[_upload("bad.pdf", b"MZ not a pdf")], data=_policy_form(types=["EIN"], EIN=6)
    )
    assert response.status_code == 400

    html = response.text
    ein_box = html.index('value="EIN"')
    assert "checked" in html[ein_box : ein_box + 120], "EIN must still be ticked"
    ein_six = html.index('value="EIN=6"')
    assert "selected" in html[ein_six : ein_six + 60], "and still set to 6"
    assert 'value="SSN"' in html and "checked" not in html[html.index('value="SSN"') :][:100]


def test_a_client_that_sends_no_policy_still_gets_the_default(client, k1_bytes):
    """The endpoint predates the controls; an absent policy is not an empty one."""
    _, text = _scrubbed_text(client, k1_bytes, None)
    for value in K1_VALUES:
        assert value not in text
