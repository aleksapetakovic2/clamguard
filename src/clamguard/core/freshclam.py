"""Signature updates: running freshclam and making sense of what it says.

Updating writes to /var/lib/clamav, which belongs to the clamav user, so the
update itself goes through the privileged helper. Everything else here —
working out whether an update is needed, parsing progress, reporting what
changed — is ordinary unprivileged code.

freshclam's output is plain English and stable across versions::

    ClamAV update process started at Sun Sep 20 02:38:38 2026
    daily database available for update (local version: 28128, remote version: 28129)
    Downloading daily-28129.cdiff [100%]
    Testing database: '/var/lib/clamav/tmp.../clamav-xyz.tmp-daily.cld' ...
    daily.cld updated (version: 28129, sigs: 355901, f-level: 90, builder: ...)
    main.cvd database is up-to-date (version: 63, sigs: 3287027, ...)

A note on the updater service: if clamav-freshclam is running as a daemon it
holds the pid file, and a second freshclam refuses to start. That is a normal
and recoverable situation, so it gets its own explanation rather than a raw
error string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from PySide6.QtCore import QObject, Signal

from .logging_setup import get_logger
from .privileged import PrivilegedHelper
from .services import Role, ServiceManager

log = get_logger(__name__)


class UpdateState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    UP_TO_DATE = "up-to-date"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class DatabaseChange:
    """One database freshclam reported on."""

    name: str
    updated: bool
    version: int = 0
    signatures: int = 0
    previous_version: int = 0

    def describe(self) -> str:
        if not self.updated:
            return f"{self.name} was already current (version {self.version})."
        if self.previous_version:
            return (f"{self.name} updated from version {self.previous_version} "
                    f"to {self.version}.")
        return f"{self.name} updated to version {self.version}."


@dataclass
class UpdateResult:
    """What an update run achieved."""

    state: UpdateState = UpdateState.IDLE
    changes: list[DatabaseChange] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    message: str = ""
    output: list[str] = field(default_factory=list)

    @property
    def updated_databases(self) -> list[DatabaseChange]:
        return [change for change in self.changes if change.updated]

    def headline(self) -> str:
        if self.state is UpdateState.FAILED:
            return self.message or "The update failed."
        if self.state is UpdateState.CANCELLED:
            return "The update was cancelled."
        updated = self.updated_databases
        if not updated:
            return "Signatures are already up to date."
        if len(updated) == 1:
            return f"Updated {updated[0].name} to version {updated[0].version}."
        return f"Updated {len(updated)} databases."

    def new_signature_count(self) -> int:
        return sum(change.signatures for change in self.changes)


# --- the lines we care about ----------------------------------------------

_UP_TO_DATE = re.compile(
    r"^(?P<name>[\w.-]+?)(?:\.c[vlu]d)? database is up-to-date "
    r"\(version: (?P<version>\d+), sigs: (?P<sigs>\d+)"
)
_UPDATED = re.compile(
    r"^(?P<name>[\w.-]+?)\.c[vlu]d updated \(version: (?P<version>\d+), sigs: (?P<sigs>\d+)"
)
_AVAILABLE = re.compile(
    r"^(?P<name>[\w.-]+?) database available for update "
    r"\(local version: (?P<local>\d+), remote version: (?P<remote>\d+)\)"
)
_DOWNLOAD = re.compile(r"^Downloading (?P<file>\S+)\s*\[\s*(?P<percent>\d+)\s*%\s*\]")
_TESTING = re.compile(r"^Testing database")
_LOCKED = re.compile(r"(locked by another process|Failed to lock|already running)", re.I)


class Freshclam(QObject):
    """Runs a signature update and reports progress."""

    #: The new UpdateState.
    state_changed = Signal(object)
    #: (human-readable status, percent 0-100 or -1 when unknown)
    progress = Signal(str, int)
    #: Raw freshclam output, line by line.
    output_line = Signal(str)
    #: An UpdateResult, once per started update.
    finished = Signal(object)

    def __init__(self, privileged: PrivilegedHelper, services: ServiceManager,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.privileged = privileged
        self.services = services
        self._state = UpdateState.IDLE
        self._result = UpdateResult()
        self._call = None
        self._pending: dict[str, int] = {}   # database name -> local version

    # -- state ------------------------------------------------------------

    @property
    def state(self) -> UpdateState:
        return self._state

    @property
    def running(self) -> bool:
        return self._state is UpdateState.RUNNING

    def _set_state(self, state: UpdateState) -> None:
        if state is not self._state:
            self._state = state
            self.state_changed.emit(state)

    # -- preconditions ----------------------------------------------------

    def blocking_reason(self) -> str:
        """Why an update cannot be started right now, or "" if it can."""
        if self.running:
            return "An update is already running."
        if not self.privileged.available:
            return ("Updating signatures writes to the system database directory, "
                    "which needs administrator rights. Install the ClamGuard "
                    "helper to enable it.")
        return ""

    def updater_service_running(self) -> bool:
        """True when clamav-freshclam is running as a daemon.

        Not a blocker by itself, but it explains most "could not start" errors,
        so the UI mentions it up front.
        """
        return self.services.status(Role.UPDATER).running

    # -- running ----------------------------------------------------------

    def start(self) -> bool:
        """Begin an update. Returns False if it could not be started."""
        reason = self.blocking_reason()
        if reason:
            self._result = UpdateResult(state=UpdateState.FAILED, message=reason)
            self._set_state(UpdateState.FAILED)
            self.finished.emit(self._result)
            self._set_state(UpdateState.IDLE)
            return False

        self._result = UpdateResult(state=UpdateState.RUNNING)
        self._pending = {}
        self._set_state(UpdateState.RUNNING)
        self.progress.emit("Asking for permission…", -1)

        call = self.privileged.update_database()
        call.output_line.connect(self._on_line)
        call.error_line.connect(self._on_line)
        call.succeeded.connect(lambda _out: self._complete(UpdateState.SUCCEEDED))
        call.failed.connect(self._on_failed)
        call.cancelled.connect(lambda: self._complete(UpdateState.CANCELLED))
        self._call = call
        call.start()
        return True

    def stop(self) -> None:
        """Abandon a running update. Signatures are left as they were."""
        if self._call is not None:
            self._call.stop()

    # -- output -----------------------------------------------------------

    def _on_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        self._result.output.append(line)
        self.output_line.emit(line)

        if _LOCKED.search(line):
            self._result.message = (
                "freshclam could not start because the automatic updater is "
                "already running. Stop the signature updates service on the "
                "Protection page, then try again."
            )
            return

        match = _AVAILABLE.match(line)
        if match:
            name = match.group("name")
            self._pending[name] = int(match.group("local"))
            self.progress.emit(f"Downloading {name}…", 0)
            return

        match = _DOWNLOAD.match(line)
        if match:
            percent = int(match.group("percent"))
            self.progress.emit(f"Downloading {match.group('file')}", percent)
            return

        if _TESTING.match(line):
            self.progress.emit("Verifying the new database…", -1)
            return

        match = _UPDATED.match(line)
        if match:
            name = match.group("name")
            self._result.changes.append(DatabaseChange(
                name=name,
                updated=True,
                version=int(match.group("version")),
                signatures=int(match.group("sigs")),
                previous_version=self._pending.get(name, 0),
            ))
            self.progress.emit(f"{name} updated.", 100)
            return

        match = _UP_TO_DATE.match(line)
        if match:
            self._result.changes.append(DatabaseChange(
                name=match.group("name"),
                updated=False,
                version=int(match.group("version")),
                signatures=int(match.group("sigs")),
            ))
            self.progress.emit(f"{match.group('name')} is current.", -1)
            return

        if line.startswith("ERROR:"):
            detail = line.split(":", 1)[1].strip()
            if not self._result.message:
                self._result.message = detail

    def _on_failed(self, message: str) -> None:
        if not self._result.message:
            self._result.message = message
        self._complete(UpdateState.FAILED)

    def _complete(self, state: UpdateState) -> None:
        if self._state is not UpdateState.RUNNING:
            return
        if state is UpdateState.SUCCEEDED and not self._result.updated_databases:
            state = UpdateState.UP_TO_DATE

        self._result.state = state
        self._result.finished_at = datetime.now()
        self._call = None

        log.info("update finished: %s — %s", state.value, self._result.headline())
        self._set_state(state)
        self.finished.emit(self._result)
        self._set_state(UpdateState.IDLE)
