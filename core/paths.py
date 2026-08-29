"""Where the vault lives, answered in exactly one place.

Three modules used to answer this independently and the literal "vault.db"
followed the working directory, so launching from anywhere but the checkout
created a second empty vault and reported zero jobs rather than erroring.

The directory holds both the vault and the key file that unlocks it. That is
not where the key belongs -- anything copying the directory copies both halves
-- but it is a smaller blast radius than the checkout, which is the folder most
likely to be cleaned, re-cloned or deleted. Moving the key into the OS keystore
is a later change that adds a step to the lookup chain in ``core.keys`` and
undoes nothing here.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

from core import config

APP_DIR_NAME = "pii-cypher"
DB_FILENAME = "vault.db"
ENV_FILENAME = ".env.local"
CONFIG_FILENAME = "config.json"
VAULT_DB_ENV = "PII_VAULT_DB"
VAULT_DIR_ENV = "PII_VAULT_DIR"

_LEGACY_WARNING = """warning: using the vault.db in the current directory.
  It belongs in {default}
  Run `python cli.py migrate` to move it. Until then this vault is only found
  when you launch from this directory."""


def _data_dir(platform: str, environ: Mapping[str, str], home: Path) -> Path:
    """Per-user application data directory, as a pure function of its inputs.

    Windows uses LOCALAPPDATA and not APPDATA deliberately. The roaming profile
    is synchronised to a server at logon on a domain-joined machine, which would
    carry the vault -- and the key file sitting beside it -- off the laptop as a
    side effect of logging in. That is the copy this move exists to prevent.

    Taking platform, environ and home as arguments is what makes the Windows
    branch testable on a Linux CI host.
    """
    if platform == "win32":
        base = environ.get("LOCALAPPDATA") or str(home / "AppData" / "Local")
    elif platform == "darwin":
        base = str(home / "Library" / "Application Support")
    else:
        base = environ.get("XDG_DATA_HOME") or str(home / ".local" / "share")
    return Path(base) / APP_DIR_NAME


def data_dir() -> Path:
    """The directory holding the vault and its key file.

    PII_VAULT_DIR overrides it, which is the one knob a server deployment sets
    and the one the test suite sets so no test can reach a real vault.
    """
    override = os.environ.get(VAULT_DIR_ENV)
    if override:
        return Path(override)
    return _data_dir(sys.platform, os.environ, Path.home())


def default_db_path() -> Path:
    return data_dir() / DB_FILENAME


def env_file_path() -> Path:
    return data_dir() / ENV_FILENAME


def config_path() -> Path:
    return data_dir() / CONFIG_FILENAME


def configured_db_path() -> Path | None:
    """The vault path the user chose, or None if they have not chosen one.

    Never cached. ``web/app.py:_db`` resolves per request, which is what lets a
    changed setting take effect with no restart; a module-level cache here would
    silently cost that property to save a read that happens twice a page.

    Propagates ConfigError rather than falling back: a setting that quietly
    fails to apply sends the tool to a different vault and reports zero jobs.
    """
    stored = config.read(config_path()).get(config.VAULT_DB_KEY)
    return Path(stored) if stored else None


def set_configured_db(path: str | os.PathLike[str]) -> None:
    """Record the chosen vault, preserving anything else in the file."""
    values = config.read(config_path())
    values[config.VAULT_DB_KEY] = str(Path(path).resolve())
    config.write(config_path(), values)


def clear_configured_db() -> None:
    """Forget the chosen vault and fall back to the next tier.

    Tolerates an unreadable config, because a corrupt or dangling setting is
    one of the things this exists to repair -- and ``read`` refuses rather than
    falling through, so without this the app could not be recovered in place.
    """
    try:
        values = config.read(config_path())
    except config.ConfigError:
        values = {}
    values.pop(config.VAULT_DB_KEY, None)
    config.write(config_path(), values)


def legacy_db_path() -> Path | None:
    """A vault.db in the working directory, if one is there.

    Every install before the move kept its vault beside the code, so this is
    live client data rather than a stray file, and it outranks the new default:
    creating a fresh empty vault while that one sits right there would report
    zero jobs on a machine holding many.
    """
    candidate = Path.cwd() / DB_FILENAME
    return candidate if candidate.is_file() else None


def resolve_db(explicit: str | os.PathLike[str] | None = None) -> tuple[Path, str]:
    """Return the vault path and the name of the rule that produced it.

    Reporting the rule is what lets ``cli.py status`` explain itself. The
    original bug was silent: the tool could not say why it saw no jobs.
    """
    if explicit is not None:
        return Path(explicit), "flag"
    env_db = os.environ.get(VAULT_DB_ENV)
    if env_db:
        return Path(env_db), VAULT_DB_ENV
    if os.environ.get(VAULT_DIR_ENV):
        return default_db_path(), VAULT_DIR_ENV
    # Above the legacy vault, and that ordering is load-bearing: a checkout
    # still holding a vault.db is the normal case, so if legacy won, choosing a
    # new location would have no effect at all and say nothing about it.
    chosen = configured_db_path()
    if chosen is not None:
        return chosen, "settings"
    legacy = legacy_db_path()
    if legacy is not None:
        return legacy, "legacy"
    return default_db_path(), "default"


def legacy_warning(source: str) -> str | None:
    """The message to show when a checkout vault was adopted, else None."""
    if source != "legacy":
        return None
    return _LEGACY_WARNING.format(default=default_db_path())


def ensure_dir(path: Path) -> None:
    """Create a directory for the vault if it is missing.

    0o700 on POSIX. Nothing on Windows: %LOCALAPPDATA% already carries a
    user-only inherited ACL, so calling icacls here would add a failure mode
    without changing the effective permissions.
    """
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        path.chmod(0o700)


DRIVE_REMOTE = 4

NETWORK_WARNING = (
    "That looks like a network location. SQLite's file locking is unreliable over "
    "SMB and WAL is unavailable there, so two machines writing at once risks "
    "corrupting the vault. One machine at a time is genuinely fine. Note also that "
    "the key file stays on this machine: the vault there is unreadable to anyone "
    "who has not been given the two keys `cli.py backup` prints, including you "
    "from another machine."
)


def _validate(raw: str, flavour: type[PurePath]) -> PurePath:
    """Shape checks, as a pure function of the path flavour.

    Takes the flavour explicitly for the same reason ``_data_dir`` takes its
    platform, and it matters more here: on POSIX, ``PurePosixPath("D:/x/v.db")``
    is a *relative* single-component name, so a test of the Windows drive-letter
    rules run on a Linux host would quietly assert the opposite of the truth.
    """
    text = raw.strip()
    # Explorer's "Copy as path" wraps the result in double quotes, so without
    # this the very first paste a user tries is rejected.
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1].strip()
    if not text:
        raise ValueError("Give the full path to a vault file.")

    candidate = flavour(text)
    if not candidate.is_absolute():
        raise ValueError(
            f"{text} is not a full path. Start it with a drive letter or a share "
            "name -- a relative path would follow whatever directory the app "
            "happens to start in, which is the problem the fixed location solves."
        )
    if not candidate.suffix:
        raise ValueError(
            f"{text} looks like a folder. Give the file name too, "
            f"for example {text.rstrip(chr(92) + '/')}\\{DB_FILENAME}."
        )
    return candidate


def _is_network_path(candidate: PurePath) -> bool:
    """Whether the path lives on a share.

    UNC is a string test, but a firm's shared drive is usually a mapped Z: that
    is indistinguishable from a local disk by inspection -- so the string test
    alone would miss the common real case. Any failure means "cannot tell", and
    the result only ever drives a warning, never a refusal.
    """
    drive = candidate.drive
    if drive.startswith(("\\\\", "//")):
        return True
    if sys.platform != "win32" or not drive:
        return False
    try:
        import ctypes

        return ctypes.windll.kernel32.GetDriveTypeW(f"{drive}\\") == DRIVE_REMOTE
    except Exception:
        return False


def validate_vault_path(raw: str) -> tuple[Path, list[str]]:
    """Normalise a typed vault path, or raise ValueError with a message to show.

    Returns the path and any warnings. Warnings never block: a network share is
    a real choice with real caveats, not a mistake to be refused.
    """
    flavour = PureWindowsPath if sys.platform == "win32" else PurePosixPath
    candidate = _validate(raw, flavour)
    path = Path(str(candidate))

    if path.is_dir():
        raise ValueError(f"{path} is a folder. Give the full path including the file name.")

    # Only for a plain drive letter. Probing a UNC anchor asks the network
    # whether an unreachable server exists, and that blocks rather than answers.
    drive = candidate.drive
    if len(drive) == 2 and drive[1] == ":" and not Path(candidate.anchor).exists():
        raise ValueError(
            f"There is no {drive} drive on this machine, or it is not connected."
        )

    parent = path.parent
    if not parent.exists() and not parent.parent.exists():
        raise ValueError(
            f"{parent} does not exist and neither does {parent.parent}. "
            "One missing folder can be created; two usually means a typo."
        )

    return path, [NETWORK_WARNING] if _is_network_path(candidate) else []
