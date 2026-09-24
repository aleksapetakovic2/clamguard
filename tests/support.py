"""Shared test scaffolding."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

# Several tests deliberately feed ClamGuard broken input to prove it copes.
# The warnings that produces are the expected result, not test output, so the
# app's logger is silenced for the run.
import logging  # noqa: E402  - must come after sys.path is set up

logging.getLogger("clamguard").addHandler(logging.NullHandler())
logging.getLogger("clamguard").propagate = False
logging.getLogger("clamguard").setLevel(logging.CRITICAL)

_application = None


def recent_stamps(count: int, *, hours_ago: float = 1.0,
                  step_seconds: int = 1) -> list[str]:
    """``YYYY-MM-DD HH:MM:SS`` local times starting `hours_ago` before now.

    For any fixture that passes through a time range or through retention.
    Hunt opens on "Last 24 hours" and purges events older than 120 days, so a
    log line with a literal date is correct on the day it is written and wrong
    forever after. Four smoke tests went red on 2026-09-23 for exactly that
    reason, with no code change at all.
    """
    from datetime import datetime, timedelta

    first = datetime.now() - timedelta(hours=hours_ago)
    return [(first + timedelta(seconds=index * step_seconds)).strftime("%Y-%m-%d %H:%M:%S")
            for index in range(count)]


def recent_day(days_ago: int = 1) -> str:
    """``YYYY-MM-DD`` for a day comfortably inside every retention limit."""
    from datetime import date, timedelta

    return (date.today() - timedelta(days=days_ago)).isoformat()


def qt_application():
    """One Qt application object for the whole run.

    Several core classes are QObjects and a few use QProcess, which needs an
    event loop to exist. It has to be a QApplication rather than a plain
    QCoreApplication whenever QtWidgets is available: Qt allows only one
    application object per process, and creating the QCoreApplication first
    leaves the widget tests without the one they need — which crashes at
    interpreter shutdown rather than failing cleanly.
    """
    global _application
    if _application is None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        try:
            from PySide6.QtWidgets import QApplication as Application
        except ImportError:
            from PySide6.QtCore import QCoreApplication as Application

        _application = Application.instance() or Application(sys.argv[:1])
    return _application


class TempHomeTestCase(unittest.TestCase):
    """A test case with XDG directories pointed at a throwaway folder.

    ClamGuard writes to ~/.config and ~/.local/share. Redirecting the XDG
    variables means a test run never touches the real ones.
    """

    def setUp(self) -> None:
        qt_application()
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-test-"))
        self._saved = {}
        for name, subdirectory in (
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CACHE_HOME", "cache"),
        ):
            self._saved[name] = os.environ.get(name)
            os.environ[name] = str(self.tmp / subdirectory)

        # paths.py caches the XDG locations at import time, so it has to be
        # reloaded after the environment changes.
        import importlib

        from clamguard.core import paths

        importlib.reload(paths)
        self.paths = paths
        paths.ensure_directories()

    def tearDown(self) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name: str, content: str = "") -> Path:
        """Create a file under the temporary directory."""
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path


#: A real EICAR test string. Every antivirus recognises it, and it is
#: completely harmless — it is a text file, not a program.
EICAR = (
    rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

#: A realistic excerpt of clamd.conf, including the comment conventions the
#: parser relies on.
SAMPLE_CLAMD_CONF = """\
##
## Example config file for the Clam AV daemon
##

# Comment or remove the line below.
#Example

# Path to the log file.
# Default: disabled
LogFile /var/log/clamav/clamd.log

# Enable log rotation.
# Default: no
#LogRotate yes

# Log time with each message.
# Default: no
LogTime yes

# Maximum number of threads running at the same time.
# Default: 10
#MaxThreads 20

# Don't scan files and directories matching regex
# This directive can be used multiple times
# Default: scan all
#ExcludePath ^/proc/

# Set the mount point where to recursively perform the scan
OnAccessMountPath /

# Alternatively, add some directories instead of mount points
OnAccessIncludePath /home
OnAccessIncludePath /srv

OnAccessPrevention yes
"""
