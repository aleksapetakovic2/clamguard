"""ClamGuard's own log — not ClamAV's.

One rotating file under ~/.local/share/clamguard/logs/. We log what the app
did, especially anything privileged, so that "why did my config change?" has an
answer. Scan results do not go here; they go into the history database.
"""

from __future__ import annotations

import logging
import logging.handlers
import sys

from . import paths

_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)-22s %(message)s"
_MAX_BYTES = 2 * 1024 * 1024
_BACKUP_COUNT = 3

_configured = False


def configure(verbose: bool = False) -> logging.Logger:
    """Set up root logging. Idempotent, so calling it twice is harmless."""
    global _configured
    root = logging.getLogger("clamguard")
    if _configured:
        return root

    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.propagate = False

    paths.LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            paths.APP_LOG, maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8"
        )
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        root.addHandler(file_handler)
    except OSError as error:  # read-only home, full disk, ...
        print(f"clamguard: cannot open log file {paths.APP_LOG}: {error}", file=sys.stderr)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter("clamguard: %(levelname)s %(message)s"))
    root.addHandler(console)

    _configured = True
    return root


def get_logger(name: str) -> logging.Logger:
    """Logger for a module. Use `get_logger(__name__)`."""
    if name.startswith("clamguard."):
        return logging.getLogger(name)
    return logging.getLogger(f"clamguard.{name}")
