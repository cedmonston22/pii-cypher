"""The settings file: what the user chose, as opposed to what the environment says.

Deliberately knows nothing about *where* it lives. ``core.paths`` owns that and
passes the path in, because ``paths`` has to consult the config to resolve the
vault while the config sits inside ``paths.data_dir()`` -- importing each other
to find that out is a cycle. The same discipline as ``_data_dir(platform,
environ, home)``: take the inputs, compute nothing about the world.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

CONFIG_VERSION = 1
VAULT_DB_KEY = "vault_db"


class ConfigError(Exception):
    """The settings file exists and cannot be trusted."""


def read(path: Path) -> dict[str, Any]:
    """Parse the settings file. A missing file is empty; a broken one raises.

    Refusing beats falling through to the default location. This is the rule
    ``keys.read_key_file`` already follows, and for the same reason: a setting
    that silently fails to apply sends the tool to a different vault and reports
    zero jobs on a machine holding many, which is the exact bug this feature is
    built to avoid rather than deliver.
    """
    if not path.is_file():
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} does not contain a JSON object")

    stored = raw.get(VAULT_DB_KEY)
    if stored is not None:
        if not isinstance(stored, str) or not stored.strip():
            raise ConfigError(f"{path}: {VAULT_DB_KEY} must be a non-empty string")
        # A hand-edited file is the last way the working-directory bug could get
        # back in: a relative path here would follow the shell again, which is
        # what the per-user location exists to stop.
        if not Path(stored).is_absolute():
            raise ConfigError(f"{path}: {VAULT_DB_KEY} must be an absolute path, got {stored!r}")

    return raw


def write(path: Path, values: dict[str, Any]) -> None:
    """Replace the settings file atomically.

    Through a temp file in the same directory and ``os.replace``, so an
    interrupted write leaves the previous settings intact. A truncated file
    would be refused by ``read``, and since ``read`` refuses rather than falls
    through, that would leave the app unable to start at all.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": CONFIG_VERSION, **values}

    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f"{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        if os.name == "posix":
            os.chmod(handle.name, 0o600)
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
