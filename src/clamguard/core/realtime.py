"""Noticing what the on-access scanner finds.

`clamonacc` hands every file it sees to `clamd`, and `clamd` writes a line to
its log when one is infected. Nothing in that chain talks to ClamGuard — which
meant real-time protection could be working perfectly and the application would
still show nothing. This module closes that gap.

It follows the daemon's journal and watches for detection lines::

    Sun Sep 20 05:07:52 2026 -> /home/user/Downloads/eicar.com: Eicar-Test-Signature FOUND

and turns each one into a signal the rest of the app can act on: a desktop
notification, a history record, and an entry on the Protection page.

Reading the journal needs no privileges on any normal systemd machine, so this
works whether or not the privileged helper is installed.

What it deliberately does not do is act on a detection by itself. clamd has
already reported it; whether the file is quarantined is the user's call, made
from the same UI as every other detection.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from .logging_setup import get_logger
from .process import Command, which
from .scanner import parse_scan_line
from .services import Role, ServiceManager

log = get_logger(__name__)

#: clamd prefixes its own messages with a timestamp and an arrow, and journald
#: adds a host and unit prefix on top. Everything before the last " -> " is
#: noise as far as detection parsing is concerned.
_CLAMD_PREFIX = re.compile(r"^.*?\s->\s")

#: journald's short-iso prefix, for lines clamd wrote without its own arrow.
_JOURNAL_PREFIX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T[\d:.+-]+\s+\S+\s+\S+?(?:\[\d+\])?:\s*")

#: The same detection is logged on every access. Report it once per window.
REPEAT_WINDOW_SECONDS = 120

#: How long after one of our own scans to keep ignoring clamd's log, so its
#: detections are not counted twice.
SUPPRESS_GRACE_SECONDS = 5.0


@dataclass(frozen=True)
class RealtimeDetection:
    """One thing the on-access scanner caught."""

    path: str
    threat: str
    found_at: datetime = field(default_factory=datetime.now)

    @property
    def filename(self) -> str:
        return Path(self.path).name or self.path

    @property
    def still_exists(self) -> bool:
        return Path(self.path).exists()


class RealtimeMonitor(QObject):
    """Follows clamd's journal and reports detections as they happen."""

    #: A RealtimeDetection, the first time it is seen in the repeat window.
    detected = Signal(object)
    #: True when the journal is being followed, False when it is not.
    watching_changed = Signal(bool)
    #: Something stopped the monitor working, in words.
    problem = Signal(str)

    def __init__(self, services: ServiceManager, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.services = services
        self._command: Command | None = None
        self._recent: dict[tuple[str, str], float] = {}
        self._suppressed_until = 0.0
        #: Everything seen this session, newest first, for the Protection page.
        self.history: list[RealtimeDetection] = []

    # -- state ------------------------------------------------------------

    @property
    def watching(self) -> bool:
        return self._command is not None and self._command.is_running()

    @property
    def suppressed(self) -> bool:
        return time.monotonic() < self._suppressed_until

    def suppress(self, seconds: float = SUPPRESS_GRACE_SECONDS) -> None:
        """Ignore detections for a moment.

        clamd writes a log line for every detection it makes, including the
        ones ClamGuard asked for itself by running clamdscan. Without this, a
        scan that finds ten threats would report each one twice — once as a
        scan result and once as a "real-time" catch — and fire ten spurious
        notifications. The grace period covers clamd's log lagging slightly
        behind the scan finishing.
        """
        self._suppressed_until = max(self._suppressed_until,
                                     time.monotonic() + seconds)

    def resume_after(self, seconds: float = SUPPRESS_GRACE_SECONDS) -> None:
        """End suppression `seconds` from now rather than immediately."""
        self._suppressed_until = time.monotonic() + seconds

    def unavailable_reason(self) -> str:
        """Why the monitor cannot run, or "" if it can."""
        if not which("journalctl"):
            return ("journalctl is not available, so ClamGuard cannot watch for "
                    "real-time detections as they happen.")
        if not self.services.unit_for(Role.DAEMON):
            return ("No ClamAV daemon unit was found, so there is no log to "
                    "watch for real-time detections.")
        return ""

    def follow_command(self) -> tuple[str, list[str]]:
        """Program and arguments for tailing the daemon's log.

        Split out so a test can point the monitor at a journal it controls
        rather than at the real ClamAV daemon.
        """
        # --since now: only detections from here on. Replaying the backlog on
        # every launch would notify about files dealt with days ago.
        return which("journalctl") or "journalctl", [
            "-u", self.services.unit_for(Role.DAEMON),
            "--since", "now", "--no-pager", "--output=short-iso", "--follow",
        ]

    # -- lifecycle --------------------------------------------------------

    def start(self) -> bool:
        """Begin following. Safe to call when already running."""
        if self.watching:
            return True

        reason = self.unavailable_reason()
        if reason:
            log.info("real-time monitor not started: %s", reason)
            self.problem.emit(reason)
            return False

        program, arguments = self.follow_command()
        command = Command(program, arguments, parent=self)
        command.stdout_line.connect(self._on_line)
        command.failed.connect(self._on_failed)
        command.finished.connect(lambda _code: self.watching_changed.emit(False))

        self._command = command
        if not command.start():
            self._command = None
            return False

        log.info("watching for real-time detections: %s", " ".join(arguments[:3]))
        self.watching_changed.emit(True)
        return True

    def stop(self) -> None:
        if self._command is not None:
            self._command.stop()
            self._command.deleteLater()
            self._command = None
        self.watching_changed.emit(False)

    def refresh(self) -> None:
        """Start or stop to match whether real-time protection is running.

        Following the journal while clamonacc is stopped would be harmless but
        pointless, and it keeps a child process alive for nothing.
        """
        should_watch = self.services.status(Role.ONACCESS).running
        if should_watch and not self.watching:
            self.start()
        elif not should_watch and self.watching:
            self.stop()

    # -- parsing ----------------------------------------------------------

    def _on_line(self, line: str) -> None:
        detection = self.parse(line)
        if detection is None:
            return
        if self.suppressed:
            # A scan ClamGuard is running is already reporting this itself.
            return
        if self._is_repeat(detection):
            return

        self.history.insert(0, detection)
        del self.history[200:]
        log.warning("real-time detection: %s in %s", detection.threat, detection.path)
        self.detected.emit(detection)

    @staticmethod
    def parse(line: str) -> RealtimeDetection | None:
        """Turn one journal line into a detection, or None if it is not one."""
        if "FOUND" not in line:
            return None

        cleaned = _JOURNAL_PREFIX.sub("", line.strip())
        cleaned = _CLAMD_PREFIX.sub("", cleaned).strip()

        parsed = parse_scan_line(cleaned)
        if parsed is None or parsed[0] != "found":
            return None

        _kind, path, threat = parsed
        if not path.startswith("/"):
            # Without an absolute path there is nothing the user could act on.
            return None
        return RealtimeDetection(path=path, threat=threat)

    def _is_repeat(self, detection: RealtimeDetection) -> bool:
        """clamd logs a detection on every access; report it once."""
        key = (detection.path, detection.threat)
        now = time.monotonic()
        last = self._recent.get(key)
        self._recent[key] = now
        if len(self._recent) > 500:
            cutoff = now - REPEAT_WINDOW_SECONDS
            self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
        return last is not None and (now - last) < REPEAT_WINDOW_SECONDS

    def forget(self, path: str) -> None:
        """Drop a path from the repeat filter and the session list.

        Called after the file is quarantined or deleted, so that if it comes
        back it is reported again rather than silently suppressed.
        """
        self._recent = {k: v for k, v in self._recent.items() if k[0] != path}
        self.history = [d for d in self.history if d.path != path]

    def _on_failed(self, message: str) -> None:
        log.warning("real-time monitor failed: %s", message)
        self.problem.emit(message)
        self._command = None
        self.watching_changed.emit(False)
