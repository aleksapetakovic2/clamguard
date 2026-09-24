"""systemd units: what is running, and asking the helper to change that.

Reading state needs no privileges — `systemctl show` and `journalctl -u` both
work as an ordinary user. Starting, stopping and enabling do need root, and
those go through PrivilegedHelper, never directly.

Unit names differ between distributions: Arch and Debian ship
`clamav-daemon.service`, Fedora and the upstream packaging use `clamd@scan`.
Rather than guessing, we ask systemd which clamav units exist and match them to
the three roles ClamGuard cares about.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from PySide6.QtCore import QObject, Signal

from .logging_setup import get_logger
from .process import CommandResult, run, which

log = get_logger(__name__)


class Role(str, Enum):
    """What a unit does, as far as ClamGuard is concerned."""

    DAEMON = "daemon"        # clamd: the scanning engine other tools talk to
    UPDATER = "updater"      # freshclam: signature downloads
    ONACCESS = "onaccess"    # clamonacc: real-time protection

    @property
    def title(self) -> str:
        return {
            Role.DAEMON: "Scanning daemon",
            Role.UPDATER: "Signature updates",
            Role.ONACCESS: "Real-time protection",
        }[self]

    @property
    def explanation(self) -> str:
        return {
            Role.DAEMON: "Keeps the signature database in memory so scans start instantly.",
            Role.UPDATER: "Checks for new virus signatures several times a day.",
            Role.ONACCESS: "Scans files the moment they are opened, created or moved.",
        }[self]


#: Candidate unit names per role, most likely first. The first one systemd
#: actually knows about wins.
UNIT_CANDIDATES: dict[Role, tuple[str, ...]] = {
    Role.DAEMON: ("clamav-daemon.service", "clamd.service", "clamd@scan.service",
                  "clamd@clamd.service"),
    Role.UPDATER: ("clamav-freshclam.service", "freshclam.service", "clamav-freshclamd.service"),
    Role.ONACCESS: ("clamav-clamonacc.service", "clamonacc.service"),
}

_SHOW_PROPERTIES = (
    "Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState",
    "Result", "ExecMainStatus", "ActiveEnterTimestamp", "StatusText", "FragmentPath",
)


@dataclass(frozen=True)
class ServiceStatus:
    """A snapshot of one systemd unit."""

    role: Role
    unit: str = ""
    description: str = ""
    load_state: str = ""        # loaded / not-found / masked
    active_state: str = ""      # active / inactive / failed / activating
    sub_state: str = ""         # running / dead / exited / failed
    unit_file_state: str = ""   # enabled / disabled / static / masked
    result: str = ""            # success / exit-code / timeout / signal
    exit_status: int = 0
    since: datetime | None = None
    status_text: str = ""

    # -- questions the UI asks --------------------------------------------

    @property
    def exists(self) -> bool:
        return bool(self.unit) and self.load_state not in ("", "not-found")

    @property
    def running(self) -> bool:
        return self.active_state == "active"

    @property
    def failed(self) -> bool:
        return self.active_state == "failed"

    @property
    def starting(self) -> bool:
        return self.active_state in ("activating", "deactivating", "reloading")

    @property
    def enabled(self) -> bool:
        """Starts automatically at boot."""
        return self.unit_file_state in ("enabled", "enabled-runtime", "static")

    @property
    def masked(self) -> bool:
        return self.unit_file_state == "masked" or self.load_state == "masked"

    @property
    def one_shot_ok(self) -> bool:
        """A unit that ran, succeeded and exited — normal for a timer job."""
        return self.active_state == "inactive" and self.result == "success"

    def summary(self) -> str:
        """One short line for a status badge."""
        if not self.exists:
            return "Not installed"
        if self.masked:
            return "Masked"
        if self.failed:
            return f"Failed (exit {self.exit_status})" if self.exit_status else "Failed"
        if self.running:
            return "Running"
        if self.starting:
            return self.active_state.capitalize()
        return "Stopped"

    def tone(self) -> str:
        """Badge colour: ok / warn / danger / neutral."""
        if not self.exists or self.masked:
            return "neutral"
        if self.failed:
            return "danger"
        if self.running:
            return "ok"
        return "warn"


class ServiceManager(QObject):
    """Finds the ClamAV units and reports their state.

    Changing state is not done here — it goes through PrivilegedHelper, which
    the caller already has. That keeps every privileged action funnelled
    through one confirmable path.
    """

    refreshed = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._systemctl = which("systemctl")
        self._units: dict[Role, str] = {}
        self._status: dict[Role, ServiceStatus] = {}
        self.discover_units()

    # -- discovery --------------------------------------------------------

    @property
    def available(self) -> bool:
        """False on a machine that does not use systemd."""
        return self._systemctl is not None

    def discover_units(self) -> None:
        """Match the units systemd knows about to our three roles."""
        self._units = {}
        if not self._systemctl:
            return

        result = run(self._systemctl, ["list-unit-files", "clam*", "--no-legend", "--no-pager"],
                     timeout=10)
        known = {line.split()[0] for line in result.lines() if line.split()}

        # Loaded-but-not-installed units (a running clamd started by hand) do
        # not appear above, so also consult the loaded unit list.
        loaded = run(self._systemctl, ["list-units", "clam*", "--all", "--no-legend", "--no-pager"],
                     timeout=10)
        for line in loaded.lines():
            parts = line.replace("●", " ").split()
            if parts and parts[0].endswith(".service"):
                known.add(parts[0])

        for role, candidates in UNIT_CANDIDATES.items():
            for candidate in candidates:
                if candidate in known:
                    self._units[role] = candidate
                    break

    def unit_for(self, role: Role) -> str:
        """The unit name for a role, or "" if this machine has no such unit."""
        return self._units.get(role, "")

    def all_units(self) -> dict[Role, str]:
        return dict(self._units)

    # -- state ------------------------------------------------------------

    def refresh(self) -> None:
        """Re-read every role's status. Emits :attr:`refreshed`."""
        self._status = {role: self._read_status(role) for role in Role}
        self.refreshed.emit()

    def status(self, role: Role) -> ServiceStatus:
        """Cached status, read on first use."""
        if role not in self._status:
            self._status[role] = self._read_status(role)
        return self._status[role]

    def statuses(self) -> dict[Role, ServiceStatus]:
        return {role: self.status(role) for role in Role}

    def _read_status(self, role: Role) -> ServiceStatus:
        unit = self.unit_for(role)
        if not unit or not self._systemctl:
            return ServiceStatus(role=role)

        result = run(
            self._systemctl,
            ["show", unit, "--no-pager", f"--property={','.join(_SHOW_PROPERTIES)}"],
            timeout=10,
        )
        if not result.ok:
            return ServiceStatus(role=role, unit=unit, load_state="not-found")

        fields: dict[str, str] = {}
        for line in result.lines():
            key, _, value = line.partition("=")
            fields[key] = value

        return ServiceStatus(
            role=role,
            unit=fields.get("Id", unit),
            description=fields.get("Description", ""),
            load_state=fields.get("LoadState", ""),
            active_state=fields.get("ActiveState", ""),
            sub_state=fields.get("SubState", ""),
            unit_file_state=fields.get("UnitFileState", ""),
            result=fields.get("Result", ""),
            exit_status=_safe_int(fields.get("ExecMainStatus")),
            since=_parse_systemd_time(fields.get("ActiveEnterTimestamp", "")),
            status_text=fields.get("StatusText", ""),
        )

    # -- logs -------------------------------------------------------------

    def journal(self, role: Role, lines: int = 200, since: str = "") -> CommandResult:
        """Recent journal entries for a unit.

        journalctl lets an ordinary user read their own system's unit logs on
        most distributions, which is how ClamGuard shows daemon output without
        ever needing root to read /var/log/clamav.
        """
        journalctl = which("journalctl")
        unit = self.unit_for(role)
        if not journalctl or not unit:
            return CommandResult("journalctl", (), -1, "", "", error="journalctl unavailable")
        args = ["-u", unit, "-n", str(lines), "--no-pager", "--output=short-iso"]
        if since:
            args += ["--since", since]
        return run(journalctl, args, timeout=20)

    def journal_command(self, role: Role, follow: bool = True) -> tuple[str, list[str]]:
        """Program and arguments for a live journal tail, for use with Command."""
        unit = self.unit_for(role)
        args = ["-u", unit, "-n", "300", "--no-pager", "--output=short-iso"]
        if follow:
            args.append("--follow")
        return "journalctl", args

    def last_error_lines(self, role: Role, limit: int = 6) -> list[str]:
        """The tail of the journal for a failed unit — what went wrong.

        The message that explains a failure is almost always in the last few
        lines before the unit gave up, so that is what we show.
        """
        result = self.journal(role, lines=40)
        if not result.ok:
            return []
        interesting = [
            line for line in result.lines()
            if any(word in line for word in ("ERROR", "error", "Failed", "failed", "WARNING"))
        ]
        return (interesting or result.lines())[-limit:]


def _safe_int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _parse_systemd_time(value: str) -> datetime | None:
    """systemd prints ``Sun 2026-09-20 02:44:54 CEST``."""
    if not value or value == "n/a":
        return None
    parts = value.split()
    if len(parts) < 3:
        return None
    try:
        return datetime.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
