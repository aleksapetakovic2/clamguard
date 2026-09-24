"""Where ClamAV's log output can be read from, and how.

There are three possible sources and they are not equally available:

* **journald** — ``journalctl -u clamav-daemon``. Works for an ordinary user on
  most distributions and supports live following. This is the preferred source.
* **A log file** — /var/log/clamav/clamd.log. Usually mode 0640 owned by the
  clamav user, so a desktop user cannot read it without the helper.
* **ClamGuard's own log** — always readable, because we wrote it.

The UI asks for a source by name and gets back whichever of these actually
works, with an honest explanation when none does.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from . import paths
from .logging_setup import get_logger
from .privileged import PrivilegedHelper
from .process import Command, CommandResult, run, which
from .services import Role, ServiceManager

log = get_logger(__name__)


class SourceKind(str, Enum):
    JOURNAL = "journal"
    FILE = "file"
    APP = "app"


@dataclass(frozen=True)
class LogSource:
    """One readable stream of log lines."""

    id: str
    title: str
    kind: SourceKind
    description: str = ""
    unit: str = ""
    path: Path | None = None
    needs_helper: bool = False
    available: bool = True
    unavailable_reason: str = ""

    @property
    def supports_follow(self) -> bool:
        """Can we tail it live?"""
        return self.kind in (SourceKind.JOURNAL, SourceKind.APP) and self.available


class LogReader:
    """Reads log sources, choosing the most accessible one for each unit."""

    def __init__(self, services: ServiceManager, privileged: PrivilegedHelper) -> None:
        self.services = services
        self.privileged = privileged

    # -- discovery --------------------------------------------------------

    def sources(self) -> list[LogSource]:
        """Every source worth offering, in the order the UI should list them."""
        found: list[LogSource] = []
        journalctl = which("journalctl")

        for role, path_name in (
            (Role.DAEMON, "clamd.log"),
            (Role.UPDATER, "freshclam.log"),
            (Role.ONACCESS, "clamonacc.log"),
        ):
            unit = self.services.unit_for(role)
            file_path = paths.CLAMAV_LOG_DIR / path_name

            if journalctl and unit:
                found.append(LogSource(
                    id=f"journal:{role.value}",
                    title=role.title,
                    kind=SourceKind.JOURNAL,
                    description=f"systemd journal for {unit}",
                    unit=unit,
                ))
            elif file_path.is_file():
                readable = _readable(file_path)
                found.append(LogSource(
                    id=f"file:{role.value}",
                    title=role.title,
                    kind=SourceKind.FILE,
                    description=str(file_path),
                    path=file_path,
                    needs_helper=not readable,
                    available=readable or self.privileged.available,
                    unavailable_reason="" if readable or self.privileged.available else
                        f"{file_path} can only be read by an administrator.",
                ))

        # The raw log files, offered alongside the journal when both exist.
        for path in paths.READABLE_LOG_FILES:
            if not path.is_file():
                continue
            readable = _readable(path)
            found.append(LogSource(
                id=f"file:{path.name}",
                title=f"{path.name}",
                kind=SourceKind.FILE,
                description=str(path),
                path=path,
                needs_helper=not readable,
                available=readable or self.privileged.available,
                unavailable_reason="" if readable or self.privileged.available else
                    f"{path} can only be read by an administrator.",
            ))

        found.append(LogSource(
            id="app",
            title="ClamGuard",
            kind=SourceKind.APP,
            description="What this application itself did",
            path=paths.APP_LOG,
            available=paths.APP_LOG.exists(),
            unavailable_reason="" if paths.APP_LOG.exists() else "Nothing logged yet.",
        ))
        return found

    def source(self, source_id: str) -> LogSource | None:
        return next((s for s in self.sources() if s.id == source_id), None)

    # -- reading ----------------------------------------------------------

    def read(self, source: LogSource, lines: int = 500) -> CommandResult:
        """The last `lines` of a source. Blocking, but bounded."""
        if source.kind is SourceKind.JOURNAL:
            journalctl = which("journalctl")
            if not journalctl:
                return _error("journalctl is not installed.")
            return run(journalctl,
                       ["-u", source.unit, "-n", str(lines), "--no-pager",
                        "--output=short-iso"],
                       timeout=30)

        if source.path is None:
            return _error("This source has no file behind it.")

        if _readable(source.path):
            return _tail_file(source.path, lines)

        if not self.privileged.available:
            return _error(source.unavailable_reason or
                          f"{source.path} needs administrator rights to read.")
        return _error("Reading this file needs administrator rights — "
                      "use the Read with privileges button.")

    def follow_command(self, source: LogSource) -> Command | None:
        """A Command that tails the source live, or None if it cannot."""
        if source.kind is SourceKind.JOURNAL:
            journalctl = which("journalctl")
            if not journalctl:
                return None
            return Command(journalctl, [
                "-u", source.unit, "-n", "300", "--no-pager",
                "--output=short-iso", "--follow",
            ])
        if source.kind is SourceKind.APP and source.path and source.path.is_file():
            tail = which("tail")
            if tail:
                return Command(tail, ["-n", "300", "-F", str(source.path)])
        return None


def classify(line: str) -> str:
    """Rough severity of a log line, for colouring: error/warn/info/detection."""
    lowered = line.lower()
    if "found" in lowered and ("virus" in lowered or "signature" in lowered
                               or line.rstrip().endswith("FOUND")):
        return "detection"
    if "error" in lowered or "failed" in lowered or "cannot" in lowered:
        return "error"
    if "warning" in lowered or "warn:" in lowered:
        return "warn"
    return "info"


def _readable(path: Path) -> bool:
    try:
        with path.open("rb"):
            return True
    except OSError:
        return False


def _tail_file(path: Path, lines: int) -> CommandResult:
    """Read the last `lines` of a file without loading all of it.

    Log files can be large. Seeking backwards from the end keeps this O(lines)
    rather than O(file).
    """
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            block = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= lines:
                step = min(block, size)
                size -= step
                handle.seek(size)
                data = handle.read(step) + data
        text = data.decode("utf-8", errors="replace")
        tail = "\n".join(text.splitlines()[-lines:])
        return CommandResult("tail", (str(path),), 0, tail, "")
    except OSError as error:
        return _error(f"Cannot read {path}: {error}")


def _error(message: str) -> CommandResult:
    return CommandResult("log", (), -1, "", "", error=message)
