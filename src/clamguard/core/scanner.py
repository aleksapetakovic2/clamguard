"""Running a scan: choosing an engine, feeding it, and reading it back.

A scan has two phases.

1. **Preparing.** A worker thread walks the targets and writes every file to a
   list. This is what makes an honest progress bar possible — we know how many
   files there are before the first one is scanned — and it is the only way to
   get per-file output out of ``clamdscan``, which reports one line per
   directory when handed a directory but one line per file when handed a list.

2. **Scanning.** ``clamdscan`` (fast, via the daemon) or ``clamscan`` (slower,
   but honours the scan profile) reads that list and prints one line per file.
   We parse each line as it arrives.

Output lines look like::

    /home/user/notes.txt: OK
    /home/user/eicar.com: Eicar-Test-Signature FOUND
    /root/private: Access denied.

Only one scan runs at a time. Starting another while one is going is refused
rather than queued — two scans competing for the same daemon is slower than
one, and the UI has nowhere sensible to show a queue.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from . import paths
from .clamav import ClamAV
from .logging_setup import get_logger
from .process import Command, run_in_background
from .scan_profile import ScanProfile, profile as profile_by_id
from .scan_targets import Enumeration, ScanKind, TargetWalker

log = get_logger(__name__)


class ScanState(str, Enum):
    IDLE = "idle"
    PREPARING = "preparing"
    SCANNING = "scanning"
    PAUSED = "paused"
    STOPPING = "stopping"
    FINISHED = "finished"

    @property
    def busy(self) -> bool:
        return self in (ScanState.PREPARING, ScanState.SCANNING,
                        ScanState.PAUSED, ScanState.STOPPING)


class Engine(str, Enum):
    """Which program actually does the scanning."""

    AUTO = "auto"
    DAEMON = "daemon"      # clamdscan — fast, uses clamd.conf's settings
    DIRECT = "direct"      # clamscan — slower, honours the scan profile

    @property
    def title(self) -> str:
        return {
            Engine.AUTO: "Automatic",
            Engine.DAEMON: "Through the daemon",
            Engine.DIRECT: "Directly",
        }[self]


@dataclass(frozen=True)
class Threat:
    """One detection."""

    path: str
    name: str
    size: int = 0
    found_at: datetime = field(default_factory=datetime.now)

    @property
    def filename(self) -> str:
        return Path(self.path).name or self.path


@dataclass
class ScanProgress:
    """A snapshot handed to the UI many times a second."""

    files_done: int = 0
    files_total: int = 0
    bytes_done: int = 0
    bytes_total: int = 0
    threats: int = 0
    errors: int = 0
    current_path: str = ""
    elapsed: float = 0.0

    @property
    def fraction(self) -> float:
        """0.0-1.0, by bytes when we know them, otherwise by file count."""
        if self.bytes_total > 0:
            return min(1.0, self.bytes_done / self.bytes_total)
        if self.files_total > 0:
            return min(1.0, self.files_done / self.files_total)
        return 0.0

    @property
    def percent(self) -> int:
        return int(round(self.fraction * 100))

    @property
    def files_per_second(self) -> float:
        return self.files_done / self.elapsed if self.elapsed > 0.5 else 0.0

    @property
    def bytes_per_second(self) -> float:
        return self.bytes_done / self.elapsed if self.elapsed > 0.5 else 0.0

    def eta_seconds(self) -> float | None:
        """Estimated seconds remaining, or None while it is still guesswork."""
        if self.elapsed < 2.0 or self.fraction <= 0.01:
            return None
        remaining_fraction = 1.0 - self.fraction
        return (self.elapsed / self.fraction) * remaining_fraction


@dataclass
class ScanResult:
    """Everything about a scan once it has ended."""

    kind: ScanKind = ScanKind.CUSTOM
    targets: list[str] = field(default_factory=list)
    profile_id: str = "balanced"
    engine: str = ""
    status: str = "completed"          # completed / stopped / failed
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    duration: float = 0.0
    files_scanned: int = 0
    files_total: int = 0
    bytes_scanned: int = 0
    threats: list[Threat] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_unreadable: int = 0
    skipped_too_large: int = 0
    message: str = ""

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    @property
    def clean(self) -> bool:
        return self.status == "completed" and not self.threats

    def headline(self) -> str:
        """The sentence shown at the top of the results view."""
        if self.status == "failed":
            return self.message or "The scan could not be completed."
        if self.threats:
            count = len(self.threats)
            noun = "threat" if count == 1 else "threats"
            verb = "was" if count == 1 else "were"
            return f"{count} {noun} {verb} found."
        if self.status == "stopped":
            return "Scan stopped. Nothing was found in what was checked."
        return "No threats found."

    def summary_line(self) -> str:
        files = f"{self.files_scanned:,} file{'' if self.files_scanned == 1 else 's'}"
        return f"{files} scanned in {format_duration(self.duration)}"


class Scanner(QObject):
    """Runs one scan at a time and reports what it is doing."""

    #: Emitted with a ScanState whenever the phase changes.
    state_changed = Signal(object)
    #: The initial ScanResult, the moment a scan is accepted. Lets anything
    #: that wants to record scans do so without the UI passing ids around.
    started = Signal(object)
    #: (files found so far, bytes found so far) while walking the targets.
    #: The byte count is declared as qint64, not int: Qt's `int` is 32-bit and
    #: a scan of more than 2 GB overflows it.
    preparing_progress = Signal("qint64", "qint64")
    #: A ScanProgress snapshot.
    progress = Signal(object)
    #: A Threat, the moment it is detected.
    threat_found = Signal(object)
    #: Raw output lines, for the "show details" pane.
    output_line = Signal(str)
    #: A problem that did not stop the scan (an unreadable file, say).
    warning = Signal(str)
    #: A ScanResult. Always emitted exactly once per started scan.
    finished = Signal(object)

    #: Don't flood the UI: at most this many progress signals per second.
    PROGRESS_INTERVAL = 0.1

    def __init__(self, clamav: ClamAV, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.clamav = clamav

        self._state = ScanState.IDLE
        self._command: Command | None = None
        self._walker: TargetWalker | None = None
        self._list_path = paths.CACHE_DIR / "scan-list.txt"

        self._result = ScanResult()
        self._progress = ScanProgress()
        self._started_monotonic = 0.0
        self._last_emit = 0.0
        self._in_summary = False

    # -- state ------------------------------------------------------------

    @property
    def state(self) -> ScanState:
        return self._state

    @property
    def busy(self) -> bool:
        return self._state.busy

    @property
    def current_progress(self) -> ScanProgress:
        return self._progress

    def _set_state(self, state: ScanState) -> None:
        if state is self._state:
            return
        self._state = state
        self.state_changed.emit(state)

    # -- starting ---------------------------------------------------------

    def start(
        self,
        kind: ScanKind,
        targets: list[Path],
        scan_profile: ScanProfile | str = "balanced",
        engine: Engine = Engine.AUTO,
        *,
        skip_hidden: bool = False,
    ) -> bool:
        """Begin a scan. Returns False if one is already running."""
        if self.busy:
            log.warning("refusing to start a second scan")
            return False
        if not self.clamav.installed:
            self._fail("ClamAV is not installed, so nothing can be scanned.")
            return False
        if not targets:
            self._fail("There is nothing to scan — no target was given.")
            return False

        active = scan_profile if isinstance(scan_profile, ScanProfile) \
            else profile_by_id(scan_profile)
        chosen = self._choose_engine(engine)
        if chosen is None:
            self._fail("Neither clamdscan nor clamscan is available.")
            return False

        self._result = ScanResult(
            kind=kind,
            targets=[str(t) for t in targets],
            profile_id=active.id,
            engine=chosen,
            started_at=datetime.now(),
        )
        self._progress = ScanProgress()
        self._started_monotonic = time.monotonic()
        self._last_emit = 0.0
        self._in_summary = False

        log.info("scan starting: %s via %s over %s", kind.value, chosen,
                 ", ".join(self._result.targets))
        self.started.emit(self._result)
        self._set_state(ScanState.PREPARING)
        self._prepare(targets, active, chosen, skip_hidden)
        return True

    def _choose_engine(self, preference: Engine) -> str | None:
        """Turn a preference into the name of a program we can actually run."""
        daemon_usable = self.clamav.has("clamdscan") and self.clamav.daemon.reachable
        if preference is Engine.DAEMON:
            return "clamdscan" if self.clamav.has("clamdscan") else None
        if preference is Engine.DIRECT:
            return "clamscan" if self.clamav.has("clamscan") else None
        if daemon_usable:
            return "clamdscan"
        return "clamscan" if self.clamav.has("clamscan") else None

    # -- phase 1: enumerate ----------------------------------------------

    def _prepare(self, targets: list[Path], active: ScanProfile, engine: str,
                 skip_hidden: bool) -> None:
        """Walk the targets on a worker thread, then start the engine."""
        walker = TargetWalker(
            targets,
            exclude_patterns=list(active.exclude_patterns),
            max_file_bytes=active.max_file_bytes,
            follow_symlinks=active.follow_dir_symlinks,
            cross_filesystems=active.cross_filesystems,
            skip_hidden=skip_hidden,
        )
        self._walker = walker
        list_path = self._list_path

        def walk() -> Enumeration:
            return walker.enumerate(
                list_path,
                on_progress=lambda files, size: self.preparing_progress.emit(files, size),
            )

        run_in_background(
            walk,
            on_done=lambda enumeration: self._on_prepared(enumeration, active, engine),
            on_error=lambda message: self._fail(f"Could not list files to scan: {message}"),
        )

    def _on_prepared(self, enumeration: Enumeration, active: ScanProfile,
                     engine: str) -> None:
        """The walk finished. Launch the scanner, or stop if there is nothing to do."""
        if self._state is ScanState.STOPPING or enumeration.cancelled:
            self._complete("stopped")
            return

        self._result.files_total = enumeration.files
        self._result.skipped_unreadable = enumeration.skipped_unreadable
        self._result.skipped_too_large = enumeration.skipped_too_large
        self._result.errors.extend(enumeration.errors[:50])
        self._progress.files_total = enumeration.files
        self._progress.bytes_total = enumeration.total_bytes

        if enumeration.empty:
            self._result.message = "No files matched this scan."
            self._complete("completed")
            return

        log.info("scanning %d files (%d bytes) with %s",
                 enumeration.files, enumeration.total_bytes, engine)
        self._launch(engine, active)

    # -- phase 2: scan ----------------------------------------------------

    def _launch(self, engine: str, active: ScanProfile) -> None:
        if engine == "clamdscan":
            args = active.clamdscan_args(fdpass=True, multiscan=True)
        else:
            args = active.clamscan_args()
        args += ["--file-list", str(self._list_path)]

        command = Command(engine, args, parent=self)
        command.stdout_line.connect(self._on_line)
        command.stderr_line.connect(self._on_line)
        command.finished.connect(self._on_command_finished)
        command.failed.connect(self._on_command_failed)
        self._command = command

        self._set_state(ScanState.SCANNING)
        if not command.start():
            self._fail(f"{engine} could not be started.")

    def _on_line(self, line: str) -> None:
        """Parse one line of scanner output."""
        if not line.strip():
            return
        self.output_line.emit(line)

        if line.startswith("-----------") or self._in_summary:
            self._in_summary = True
            self._read_summary_line(line)
            return

        parsed = parse_scan_line(line)
        if parsed is None:
            return

        kind, path, detail = parsed
        if kind == "found":
            self._record_threat(path, detail)
        elif kind == "ok":
            self._record_scanned(path)
        elif kind == "error":
            self._record_error(path, detail)
        self._emit_progress()

    def _record_scanned(self, path: str) -> None:
        self._progress.files_done += 1
        self._progress.current_path = path
        self._progress.bytes_done += _size_of(path)

    def _record_threat(self, path: str, name: str) -> None:
        size = _size_of(path)
        threat = Threat(path=path, name=name, size=size)
        self._result.threats.append(threat)
        self._progress.files_done += 1
        self._progress.threats += 1
        self._progress.current_path = path
        self._progress.bytes_done += size
        log.warning("detected %s in %s", name, path)
        self.threat_found.emit(threat)

    def _record_error(self, path: str, detail: str) -> None:
        self._progress.files_done += 1
        self._progress.errors += 1
        message = f"{path}: {detail}" if path else detail
        if len(self._result.errors) < 200:
            self._result.errors.append(message)
        self.warning.emit(message)

    def _read_summary_line(self, line: str) -> None:
        """ClamAV's own totals, which we trust over our line counting."""
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "scanned files" and value.isdigit():
            self._result.files_scanned = int(value)
        elif key == "infected files" and value.isdigit():
            # Our per-line count is authoritative for *which* files, but if
            # ClamAV counted more we want to know something was missed.
            counted = int(value)
            if counted > len(self._result.threats):
                self._result.errors.append(
                    f"ClamAV reported {counted} infected files but only "
                    f"{len(self._result.threats)} were captured individually."
                )

    def _emit_progress(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_emit < self.PROGRESS_INTERVAL:
            return
        self._last_emit = now
        self._progress.elapsed = now - self._started_monotonic
        self.progress.emit(self._progress)

    # -- finishing --------------------------------------------------------

    def _on_command_finished(self, exit_code: int) -> None:
        """clamscan exits 0 for clean, 1 for "found something", 2 for an error."""
        stopped = self._command is not None and self._command.was_stopped
        if stopped or self._state is ScanState.STOPPING:
            self._complete("stopped")
        elif exit_code in (0, 1):
            self._complete("completed")
        else:
            self._result.message = (
                f"The scanner exited with code {exit_code}. "
                "See the details below for what it reported."
            )
            self._complete("failed")

    def _on_command_failed(self, message: str) -> None:
        self._result.message = message
        self._complete("failed")

    def _complete(self, status: str) -> None:
        if self._state is ScanState.IDLE or self._state is ScanState.FINISHED:
            return
        self._emit_progress(force=True)

        self._result.status = status
        self._result.finished_at = datetime.now()
        self._result.duration = time.monotonic() - self._started_monotonic
        if not self._result.files_scanned:
            self._result.files_scanned = self._progress.files_done
        self._result.bytes_scanned = self._progress.bytes_done

        self._cleanup()
        self._set_state(ScanState.FINISHED)
        log.info("scan %s: %d files, %d threats, %.1fs", status,
                 self._result.files_scanned, len(self._result.threats),
                 self._result.duration)
        self.finished.emit(self._result)
        self._set_state(ScanState.IDLE)

    def _fail(self, message: str) -> None:
        self._result.message = message
        self._result.status = "failed"
        log.error("scan failed: %s", message)
        self._cleanup()
        self._set_state(ScanState.FINISHED)
        self.finished.emit(self._result)
        self._set_state(ScanState.IDLE)

    def _cleanup(self) -> None:
        self._walker = None
        if self._command is not None:
            self._command.deleteLater()
            self._command = None
        self._list_path.unlink(missing_ok=True)

    # -- controls ---------------------------------------------------------

    def pause(self) -> bool:
        """Suspend the scan.

        With ``clamscan`` this is exact — the process stops. With the daemon it
        is approximate: clamdscan stops reading, and clamd stops once its
        output buffer fills, which can be a second or two later.
        """
        if self._state is not ScanState.SCANNING or self._command is None:
            return False
        if not self._command.pause():
            return False
        self._set_state(ScanState.PAUSED)
        return True

    def resume(self) -> bool:
        if self._state is not ScanState.PAUSED or self._command is None:
            return False
        if not self._command.resume():
            return False
        self._set_state(ScanState.SCANNING)
        return True

    def stop(self) -> None:
        """Stop the scan. Whatever was found so far is kept."""
        if not self.busy:
            return
        self._set_state(ScanState.STOPPING)
        if self._walker is not None:
            self._walker.cancelled = True
        if self._command is not None:
            self._command.stop()
        elif self._state is ScanState.STOPPING:
            # Still walking; the walk will notice `cancelled` and unwind.
            pass


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

#: Suffixes that mean "this file was looked at and is fine".
_CLEAN_SUFFIXES = (": OK", ": Empty file")

#: Suffixes that mean "this file was not scanned", with the reason.
_SKIP_MARKERS = (
    ": Access denied.",
    ": Access denied",
    ": Can't open file",
    ": Can't access file",
    ": Excluded",
    ": Symbolic link",
    ": Not supported file type",
    ": Broken pipe",
    ": No such file or directory",
)


def parse_scan_line(line: str) -> tuple[str, str, str] | None:
    """Classify one line of scanner output.

    Returns ``(kind, path, detail)`` where kind is "ok", "found" or "error",
    or None for a line that is not about a file.

    Paths can contain colons, so the suffix is matched rather than splitting on
    the first ``:``. ``FOUND`` is always the last word of a detection line, and
    the threat name is the word before it.
    """
    line = line.rstrip()
    if not line:
        return None

    if line.endswith(" FOUND"):
        body = line[: -len(" FOUND")]
        path, separator, name = body.rpartition(": ")
        if not separator:
            return None
        return "found", path, name

    for suffix in _CLEAN_SUFFIXES:
        if line.endswith(suffix):
            return "ok", line[: -len(suffix)], ""

    for marker in _SKIP_MARKERS:
        if line.endswith(marker):
            return "error", line[: -len(marker)], marker.lstrip(": ").rstrip(".")

    if line.startswith("ERROR:") or line.startswith("WARNING:"):
        return "error", "", line.split(":", 1)[1].strip()

    if line.endswith(" ERROR"):
        body = line[: -len(" ERROR")]
        path, separator, detail = body.rpartition(": ")
        if separator:
            return "error", path, detail
        return "error", "", body

    return None


def _size_of(path: str) -> int:
    """File size, or 0 if it has gone. Cheap — the walk warmed the stat cache."""
    try:
        return os.stat(path).st_size
    except OSError:
        return 0


def format_duration(seconds: float) -> str:
    """Seconds as the phrase a person reads: "3 minutes 12 seconds"."""
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds} second{'' if seconds == 1 else 's'}"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        text = f"{minutes} minute{'' if minutes == 1 else 's'}"
        return f"{text} {remainder} second{'' if remainder == 1 else 's'}" if remainder else text
    hours, minutes = divmod(minutes, 60)
    text = f"{hours} hour{'' if hours == 1 else 's'}"
    return f"{text} {minutes} minute{'' if minutes == 1 else 's'}" if minutes else text


def format_rate(bytes_per_second: float) -> str:
    """Throughput for the progress display."""
    if bytes_per_second <= 0:
        return "—"
    value = bytes_per_second
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if value < 1024 or unit == "GB/s":
            return f"{value:.0f} {unit}" if unit == "B/s" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB/s"
