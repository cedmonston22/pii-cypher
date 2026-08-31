"""Web layer: the full upload -> zip -> restore path a user actually takes."""

import io
import time
import zipfile

import pymupdf
import pytest
from fastapi.testclient import TestClient

from core import keys, paths, relocate, vault
from core.crypto import LOOKUP_SECRET_ENV
from core.keys import MASTER_KEY_ENV, generate_data_key, wrap
from core.verify import extract_all_text
from web import app as app_module
from web import picker
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


def test_download_link_expires_on_its_own(client, k1_bytes, monkeypatch):
    """The README promises "single-use with a 15-minute expiry" and only the
    first half was true.

    Stale entries were swept when a *new* archive was stashed and nowhere else,
    so on a quiet server -- which is every server outside business hours -- a
    link kept working indefinitely. Nothing in the app noticed, because the
    single-use pop happens whether or not the entry has aged out.
    """
    scrub = client.post("/scrub", files=[_upload("k1.pdf", k1_bytes)])
    token = _download_token(scrub.text)

    later = time.time() + app_module.DOWNLOAD_TTL_SECONDS + 1
    monkeypatch.setattr(app_module.time, "time", lambda: later)

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


class TestCrossSiteRequests:
    """Layered now, rather than the only thing standing here.

    On a hosted install the SameSite=Lax session cookie is the primary defence:
    a cross-site POST arrives without it and is bounced as unauthenticated. This
    check remains for the local install, which has no session at all, and as a
    second layer on the hosted one.
    """

    def test_a_foreign_origin_is_refused(self, client, k1_bytes):
        response = client.post(
            "/scrub",
            files=[("files", ("k1.pdf", k1_bytes, "application/pdf"))],
            headers={"origin": "http://evil.example"},
        )

        assert response.status_code == 403

    def test_restore_is_covered_too(self, client, k1_bytes):
        response = client.post(
            "/restore",
            files=[("files", ("k1.pdf", k1_bytes, "application/pdf"))],
            headers={"origin": "http://evil.example"},
        )

        assert response.status_code == 403

    def test_the_apps_own_origin_is_allowed(self, client, k1_bytes):
        response = client.post(
            "/scrub",
            files=[("files", ("k1.pdf", k1_bytes, "application/pdf"))],
            headers={"origin": "http://testserver"},
        )

        assert response.status_code == 200

    def test_no_origin_at_all_is_allowed(self, client, k1_bytes):
        """A non-browser client. Browsers always send the header on a
        cross-origin form POST, so allowing this does not open the case the
        check exists for -- and it is what keeps curl and the CLI working."""
        response = client.post(
            "/scrub", files=[("files", ("k1.pdf", k1_bytes, "application/pdf"))]
        )

        assert response.status_code == 200


@pytest.fixture
def settings_client(tmp_path, monkeypatch):
    """A client where the settings tier is actually reachable.

    The plain `client` fixture sets PII_VAULT_DB, which deliberately outranks a
    saved setting -- every assertion about settings would pass vacuously under
    it. data_dir is patched rather than PII_VAULT_DIR set, for the same reason:
    that variable occupies a higher precedence slot too.
    """
    home = tmp_path / "home"
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.delenv("PII_VAULT_DB", raising=False)
    monkeypatch.delenv(paths.VAULT_DIR_ENV, raising=False)
    monkeypatch.setattr(paths, "data_dir", lambda: home)
    monkeypatch.chdir(work)
    keys.clear_cache()

    from web import app as app_module

    # client= so the loopback gate on the file picker sees a real address;
    # TestClient otherwise reports "testclient" and every browse is a 403.
    return TestClient(app_module.app, client=("127.0.0.1", 51234)), home, tmp_path


def _make_vault(db_path, filename="Smith_John_K1.pdf"):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = vault.connect(db_path)
    job_key = generate_data_key()
    job_id = vault.create_job(conn, {"pii_types": ["EIN"]})
    vault.store_key(conn, job_id, wrap(job_key))
    vault.store_document(conn, job_id, filename, job_key, status="scrubbed")
    conn.commit()
    conn.close()
    return job_id


class TestSettingsPage:
    def test_shows_the_current_vault_and_that_keys_stay_behind(self, settings_client):
        client, home, _ = settings_client

        body = client.get("/settings").text

        assert str(home / paths.DB_FILENAME) in body
        assert "keys stay on this computer" in body
        assert str(paths.env_file_path()) in body

    def test_a_preview_changes_nothing(self, settings_client):
        client, home, tmp_path = settings_client
        _make_vault(home / paths.DB_FILENAME)
        destination = tmp_path / "elsewhere" / "firm.db"

        body = client.post(
            "/settings", data={"action": "choose", "path": str(destination)}
        ).text

        assert "Before anything changes" in body
        assert not destination.exists()
        assert paths.configured_db_path() is None

    def test_a_confirmed_move_takes_effect_with_no_restart(self, settings_client):
        """The property the whole design leans on: _db() resolves per request,
        so nothing is cached and the running process follows the new setting.

        Asserting the job survives is what proves it: had resolution not moved,
        /jobs would have created a fresh empty vault at the old path and shown
        nothing, because the original is renamed as part of the move.
        """
        client, home, tmp_path = settings_client
        job_id = _make_vault(home / paths.DB_FILENAME)
        destination = tmp_path / "elsewhere" / "firm.db"
        assert job_id in client.get("/jobs").text

        response = client.post(
            "/settings", data={"action": "copy-confirm", "path": str(destination)}
        )

        assert response.status_code == 200
        assert paths.configured_db_path() == destination
        assert relocate.count_jobs(destination) == 1
        # The same running process, no reload: the job is still listed, and it
        # can only be coming from the new file because the old one was renamed.
        assert job_id in client.get("/jobs").text
        assert not (home / paths.DB_FILENAME).exists()

    def test_a_rejected_path_keeps_what_was_typed(self, settings_client):
        client, home, tmp_path = settings_client
        _make_vault(home / paths.DB_FILENAME)

        response = client.post(
            "/settings", data={"action": "choose", "path": str(tmp_path)}
        )

        assert response.status_code == 400
        assert "looks like a folder" in response.text
        assert str(tmp_path) in response.text

    def test_a_relative_path_is_refused(self, settings_client):
        """It would follow the working directory, which is the bug the fixed
        location exists to close -- and a settings page is exactly where it
        would otherwise get back in."""
        client, home, _ = settings_client
        _make_vault(home / paths.DB_FILENAME)

        response = client.post(
            "/settings", data={"action": "choose", "path": "data/vault.db"}
        )

        assert response.status_code == 400
        assert "not a full path" in response.text
        assert paths.configured_db_path() is None

    def test_adopting_a_vault_this_machine_cannot_decrypt_is_refused(
        self, settings_client, monkeypatch
    ):
        """A vault built under other key material opens and lists jobs happily.
        Accepting it would mean every restore failing later with nothing to
        explain why."""
        client, home, tmp_path = settings_client
        foreign = tmp_path / "shared" / "vault.db"
        _make_vault(foreign)
        monkeypatch.setenv(MASTER_KEY_ENV, __import__("base64").b64encode(b"z" * 32).decode())
        keys.clear_cache()

        response = client.post("/settings", data={"action": "choose", "path": str(foreign)})

        assert response.status_code == 400
        assert "do not decrypt it" in response.text
        assert paths.configured_db_path() is None

    def test_an_empty_database_with_nothing_to_move_just_starts_there(self, settings_client):
        """Previously this was a refusal telling the user to pick the other
        action. There is nothing ambiguous about it: both ends are empty, so
        there is nothing to lose and nothing to choose between."""
        client, home, tmp_path = settings_client
        empty = tmp_path / "shared" / "vault.db"
        empty.parent.mkdir(parents=True)
        vault.connect(empty).close()

        response = client.post("/settings", data={"action": "choose", "path": str(empty)})

        assert response.status_code == 200
        assert "nothing to move" in response.text
        assert "Save my work there" in response.text

    def test_an_empty_destination_copies_rather_than_asking(self, settings_client, tmp_path):
        """The common case, and the one that used to need the right verb."""
        client, home, _ = settings_client
        _make_vault(home / paths.DB_FILENAME)

        body = client.post(
            "/settings",
            data={"action": "choose", "path": str(tmp_path / "elsewhere" / "firm.db")},
        ).text

        assert "will be" in body and "copied" in body
        assert "Copy it there" in body

    def test_a_populated_destination_offers_to_switch(self, settings_client, tmp_path):
        client, home, _ = settings_client
        existing = tmp_path / "shared" / "vault.db"
        _make_vault(existing)

        body = client.post(
            "/settings", data={"action": "choose", "path": str(existing)}
        ).text

        assert "already a database at that location" in body
        assert "Switch to it" in body

    def test_two_populated_databases_is_the_one_case_that_asks(self, settings_client, tmp_path):
        """The only genuinely ambiguous situation, and it is asked with real
        numbers rather than by making someone pick a verb up front."""
        client, home, _ = settings_client
        _make_vault(home / paths.DB_FILENAME)
        other = tmp_path / "shared" / "vault.db"
        _make_vault(other)
        _make_vault(other, filename="Second.pdf")

        body = client.post("/settings", data={"action": "choose", "path": str(other)}).text

        assert "needs deciding" in body
        assert "Using now" in body and "Already there" in body
        assert "Switch to the one already there" in body

    def test_forget_clears_a_dangling_setting(self, settings_client):
        """The repair path: the drive is gone and the app will not start."""
        client, home, tmp_path = settings_client
        paths.set_configured_db(tmp_path / "removable" / "firm.db")
        assert "not there" in client.get("/settings").text

        response = client.post("/settings", data={"action": "forget"})

        assert response.status_code == 200
        assert paths.configured_db_path() is None

    def test_an_unreadable_settings_file_still_renders_a_way_out(self, settings_client):
        """Resolution refuses rather than falling through, so without this the
        app could not be repaired from its own interface."""
        client, home, _ = settings_client
        paths.config_path().parent.mkdir(parents=True, exist_ok=True)
        paths.config_path().write_text("{not json", encoding="utf-8")

        body = client.get("/settings").text

        assert "cannot be read" in body
        assert "Clear the saved location" in body

    def test_a_foreign_origin_cannot_repoint_the_vault(self, settings_client, tmp_path):
        client, home, _ = settings_client
        _make_vault(home / paths.DB_FILENAME)

        response = client.post(
            "/settings",
            data={"action": "copy-confirm", "path": str(tmp_path / "evil" / "v.db")},
            headers={"origin": "http://evil.example"},
        )

        assert response.status_code == 403
        assert paths.configured_db_path() is None


class TestFilePicker:
    """Browsing opens a dialog in the server process, which is sound only
    because the server is the machine the browser is on."""

    def test_the_chosen_path_lands_in_the_form(self, settings_client, monkeypatch, tmp_path):
        client, home, _ = settings_client
        chosen = tmp_path / "picked" / "firm.db"
        monkeypatch.setattr(picker, "choose_database_path", lambda *a, **k: str(chosen))

        body = client.post("/settings/browse", data={"path": ""}).text

        assert str(chosen) in body

    def test_browsing_changes_nothing_on_its_own(self, settings_client, monkeypatch, tmp_path):
        """It only fills the box; Move and Use still have to be pressed. A
        picker that also acted would be a one-click way to repoint the
        database with no confirmation."""
        client, home, _ = settings_client
        _make_vault(home / paths.DB_FILENAME)
        chosen = tmp_path / "picked" / "firm.db"
        monkeypatch.setattr(picker, "choose_database_path", lambda *a, **k: str(chosen))

        client.post("/settings/browse", data={"path": ""})

        assert paths.configured_db_path() is None
        assert not chosen.exists()

    def test_cancelling_keeps_what_was_already_typed(self, settings_client, monkeypatch):
        client, home, _ = settings_client
        monkeypatch.setattr(picker, "choose_database_path", lambda *a, **k: None)

        body = client.post("/settings/browse", data={"path": "D:\\typed\\vault.db"}).text

        assert "D:\\typed\\vault.db" in body

    def test_no_desktop_falls_back_to_typing_rather_than_failing(
        self, settings_client, monkeypatch
    ):
        """tkinter is absent on some Linux builds and there is no desktop under
        a service account. The page has to stay usable, since typing a path
        was the only option before this existed."""
        def unavailable(*args, **kwargs):
            raise picker.DialogUnavailable("this Python has no tkinter")

        client, home, _ = settings_client
        monkeypatch.setattr(picker, "choose_database_path", unavailable)

        response = client.post("/settings/browse", data={"path": ""})

        assert response.status_code == 200
        assert "Type the path instead" in response.text

    def test_a_remote_client_cannot_open_a_dialog(self, settings_client, monkeypatch):
        """On a shared host this would draw a modal on the server's desktop and
        block a worker thread until someone dismissed it in person."""
        client, home, _ = settings_client
        called = False

        def record(*args, **kwargs):
            nonlocal called
            called = True
            return None

        monkeypatch.setattr(picker, "choose_database_path", record)
        remote = TestClient(client.app, client=("10.0.0.7", 4444))

        assert remote.post("/settings/browse", data={"path": ""}).status_code == 403
        assert not called

    def test_a_foreign_origin_cannot_open_a_dialog(self, settings_client, monkeypatch):
        client, home, _ = settings_client
        monkeypatch.setattr(picker, "choose_database_path", lambda *a, **k: "C:\\x\\v.db")

        response = client.post(
            "/settings/browse", data={"path": ""}, headers={"origin": "http://evil.example"}
        )

        assert response.status_code == 403
