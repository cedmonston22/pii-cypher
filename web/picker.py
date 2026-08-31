"""A native file dialog, opened by the server on the user's own desktop.

A browser cannot hand back a real filesystem path -- a file input yields a name
and a sandboxed blob, deliberately -- so the only way to offer a real picker is
for the process serving the page to open one. That is sound here and nowhere
else: this app runs on the same machine as the browser looking at it. The route
that calls this is restricted to loopback for exactly that reason. On a shared
server the same code would draw a modal on the server's desktop and block a
worker thread until somebody walked over and dismissed it.
"""

from __future__ import annotations

from pathlib import Path


class DialogUnavailable(Exception):
    """No GUI toolkit, or no desktop to draw a window on."""


def choose_database_path(initial: Path | None = None, filename: str = "vault.db") -> str | None:
    """Open a file dialog and return the chosen path, or None if cancelled.

    Save-style rather than open-style so that one dialog serves both actions: it
    accepts a name that does not exist yet, which Move needs, and still lets an
    existing file be selected, which Use needs. ``confirmoverwrite`` is off
    because whether an existing file may be written is Move and Use's decision,
    and they refuse with better reasons than "overwrite?" can give.

    Blocks the calling thread until the user answers, so callers must not run it
    on the event loop. There is no timeout: a native modal on Windows does not
    process Tk's ``after`` callbacks, so one could not be enforced honestly.
    """
    try:
        import tkinter
        from tkinter import filedialog
    except ImportError as exc:  # python3-tk absent on some Linux builds
        raise DialogUnavailable("this Python has no tkinter") from exc

    try:
        root = tkinter.Tk()
    except Exception as exc:
        # No display, no window station: a headless host or a service account.
        raise DialogUnavailable(f"no desktop is available ({exc})") from exc

    root.withdraw()
    # Without this the dialog opens behind the browser window, which reads as a
    # hang: the page is waiting on a dialog the user cannot see.
    root.attributes("-topmost", True)
    try:
        chosen = filedialog.asksaveasfilename(
            parent=root,
            title="Choose where the database file lives",
            initialfile=filename,
            initialdir=str(initial) if initial else None,
            defaultextension=".db",
            filetypes=[("Database files", "*.db"), ("All files", "*.*")],
            confirmoverwrite=False,
        )
    finally:
        root.destroy()
    return chosen or None
