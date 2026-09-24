"""AppContext — the one object that owns every long-lived service.

Constructed once in app.py and handed to the main window, which hands it to
each page. There is no global singleton and no import-time state: if a page
uses a service, that service arrived through its constructor, which makes the
page testable and the dependencies visible.

AppContext also answers the single most important question in the app — "am I
protected?" — because that answer depends on almost all of the services at
once and no single page should be assembling it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from PySide6.QtCore import QObject, Signal

from .clamav import ClamAV, summarise_installation
from .database import DatabaseInfo, Freshness
from .freshclam import Freshclam
from .history import History
from .logging_setup import get_logger
from .logsource import LogReader
from .privileged import PrivilegedHelper
from .quarantine import Quarantine
from .realtime import RealtimeMonitor
from .scanner import Scanner
from .scheduler import Scheduler
from .services import Role, ServiceManager
from .settings import Settings

log = get_logger(__name__)


class ProtectionLevel(str, Enum):
    """How the dashboard's headline reads."""

    PROTECTED = "protected"
    ATTENTION = "attention"
    AT_RISK = "at-risk"
    UNKNOWN = "unknown"

    @property
    def title(self) -> str:
        return {
            ProtectionLevel.PROTECTED: "Protected",
            ProtectionLevel.ATTENTION: "Needs attention",
            ProtectionLevel.AT_RISK: "At risk",
            ProtectionLevel.UNKNOWN: "Status unknown",
        }[self]

    @property
    def tone(self) -> str:
        return {
            ProtectionLevel.PROTECTED: "ok",
            ProtectionLevel.ATTENTION: "warn",
            ProtectionLevel.AT_RISK: "danger",
            ProtectionLevel.UNKNOWN: "neutral",
        }[self]

    @property
    def icon(self) -> str:
        return {
            ProtectionLevel.PROTECTED: "shield-check",
            ProtectionLevel.ATTENTION: "shield-alert",
            ProtectionLevel.AT_RISK: "shield-off",
            ProtectionLevel.UNKNOWN: "shield",
        }[self]


@dataclass(frozen=True)
class Issue:
    """One thing standing between the user and "Protected"."""

    #: "danger" issues make the machine at risk; "warn" ones need attention.
    severity: str
    title: str
    detail: str
    #: Which page fixes it, so the card can offer a button.
    page: str = ""
    action_text: str = ""

    @property
    def blocking(self) -> bool:
        return self.severity == "danger"


@dataclass(frozen=True)
class ProtectionStatus:
    """The dashboard's headline, computed from everything else."""

    level: ProtectionLevel
    headline: str
    issues: tuple[Issue, ...] = ()

    @property
    def blocking_issues(self) -> list[Issue]:
        return [issue for issue in self.issues if issue.blocking]


class AppContext(QObject):
    """Owns the services and keeps their state in sync."""

    #: Anything that could change the protection status changed.
    status_changed = Signal()
    #: The theme or accent was changed in Settings.
    appearance_changed = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)

        self.settings = Settings()
        self.privileged = PrivilegedHelper(self)
        self.clamav = ClamAV(self)
        self.services = ServiceManager(self)
        self.database = DatabaseInfo(
            warn_after_days=self.settings.int("warn_db_age_days"), parent=self
        )
        self.history = History(parent=self)
        self.quarantine = Quarantine(self.privileged, self)
        self.scanner = Scanner(self.clamav, self)
        self.freshclam = Freshclam(self.privileged, self.services, self)
        self.scheduler = Scheduler(self)
        self.logs = LogReader(self.services, self.privileged)
        self.realtime = RealtimeMonitor(self.services, self)

        #: History row for the scan that is running, if any.
        self.current_scan_id = 0
        #: How many on-access detections this session has seen.
        self.realtime_detection_count = 0

        self._wire()
        self.refresh()

    # -- wiring -----------------------------------------------------------

    def _wire(self) -> None:
        """Anything that changes protection status re-emits status_changed."""
        for signal in (
            self.clamav.refreshed,
            self.services.refreshed,
            self.database.refreshed,
            self.quarantine.changed,
            self.privileged.availability_changed,
        ):
            signal.connect(self.status_changed)

        self.realtime.detected.connect(self._on_realtime_detection)
        self.scanner.state_changed.connect(self._on_scanner_state)
        self.realtime.watching_changed.connect(lambda _on: self.status_changed.emit())
        self.services.refreshed.connect(self.realtime.refresh)

        self.scanner.started.connect(self._on_scan_started)
        self.scanner.threat_found.connect(self._on_threat_found)
        self.scanner.finished.connect(self._on_scan_finished)
        self.freshclam.finished.connect(self._on_update_finished)
        self.settings.changed.connect(self._on_setting_changed)

    def _on_scanner_state(self, state) -> None:
        """Keep the real-time monitor quiet while we are scanning ourselves.

        A daemon scan makes clamd log every detection, which the monitor would
        otherwise report a second time as an on-access catch.
        """
        if state.busy:
            self.realtime.suppress(3600.0)     # for as long as the scan lasts
        else:
            self.realtime.resume_after()       # plus a grace period afterwards

    def _on_realtime_detection(self, detection) -> None:
        """Record what the on-access scanner caught, so it is not just a log line."""
        self.realtime_detection_count += 1
        self.history.add_detection(
            self.history.realtime_scan_id(),
            detection.path, detection.threat, action="reported",
        )
        self.status_changed.emit()

    def _on_scan_started(self, result) -> None:
        self.current_scan_id = self.history.start_scan(
            kind=result.kind.value,
            targets=result.targets,
            profile=result.profile_id,
            engine=result.engine,
        )

    def _on_threat_found(self, threat) -> None:
        if self.current_scan_id:
            self.history.add_detection(
                self.current_scan_id, threat.path, threat.name, file_size=threat.size
            )

    def _on_scan_finished(self, result) -> None:
        if self.current_scan_id:
            self.history.finish_scan(
                self.current_scan_id,
                status=result.status,
                files_scanned=result.files_scanned,
                bytes_scanned=result.bytes_scanned,
                threats_found=len(result.threats),
                errors=len(result.errors),
                duration=result.duration,
                summary=result.headline(),
            )
        self.current_scan_id = 0
        self.status_changed.emit()

    def _on_update_finished(self, _result) -> None:
        """New signatures mean the database page and the dashboard are stale."""
        self.database.refresh()
        self.clamav.refresh()

    def _on_setting_changed(self, key: str, value) -> None:
        if key in ("theme", "accent"):
            self.appearance_changed.emit()
        elif key == "warn_db_age_days":
            self.database.warn_after_days = int(value)
            self.database.refresh()

    # -- refresh ----------------------------------------------------------

    def refresh(self) -> None:
        """Re-read everything that is cheap to re-read. Safe to call often."""
        self.services.refresh()  # this also nudges the real-time monitor
        self.database.refresh()
        self.privileged.refresh()
        self.status_changed.emit()

    def refresh_deep(self) -> None:
        """Also re-probe ClamAV itself, which runs several subprocesses."""
        self.clamav.refresh()
        self.refresh()

    # -- the headline -----------------------------------------------------

    def protection_status(self) -> ProtectionStatus:
        """Work out whether this machine is protected, and why not if it is not.

        The rules, in order of how much they matter:

        * No ClamAV at all, or no signatures — at risk, nothing else matters.
        * Signatures badly out of date — at risk; an antivirus with month-old
          signatures gives false comfort.
        * Threats sitting in quarantine unreviewed, real-time protection
          failing, updates not running — attention.
        * Everything else — protected.
        """
        issues: list[Issue] = []

        if not self.clamav.installed:
            return ProtectionStatus(
                ProtectionLevel.AT_RISK,
                "ClamAV is not installed, so nothing can be scanned.",
                (Issue("danger", "ClamAV is missing",
                       "Install the clamav package for your distribution, then "
                       "restart ClamGuard.", "dashboard"),),
            )

        summary = self.database.summary
        if summary.freshness is Freshness.MISSING:
            issues.append(Issue(
                "danger", "No virus signatures",
                "ClamAV has no signature database, so a scan would find nothing. "
                "Run an update to download one.", "updates", "Update now"))
        elif summary.freshness is Freshness.STALE:
            issues.append(Issue(
                "danger", "Signatures are badly out of date",
                f"The signature database was last updated {summary.age_text()}. "
                "New threats since then will not be detected.", "updates", "Update now"))
        elif summary.freshness is Freshness.AGEING:
            issues.append(Issue(
                "warn", "Signatures are getting old",
                f"Last updated {summary.age_text()}.", "updates", "Update now"))

        updater = self.services.status(Role.UPDATER)
        if updater.exists and not updater.running and not updater.one_shot_ok:
            issues.append(Issue(
                "warn", "Automatic updates are not running",
                f"{updater.unit} is {updater.summary().lower()}, so signatures "
                "will not refresh on their own.", "protection", "Open protection"))

        onaccess = self.services.status(Role.ONACCESS)
        if onaccess.exists and onaccess.failed:
            issues.append(Issue(
                "warn", "Real-time protection is not working",
                f"{onaccess.unit} failed to start. Files are only checked when "
                "you run a scan.", "protection", "Diagnose"))
        elif onaccess.exists and not onaccess.running:
            issues.append(Issue(
                "warn", "Real-time protection is off",
                "Files are only checked when you run a scan.",
                "protection", "Turn on"))

        quarantined = self.quarantine.count()
        if quarantined:
            issues.append(Issue(
                "warn", f"{quarantined} file{'' if quarantined == 1 else 's'} in quarantine",
                "Review them and decide whether to restore or delete.",
                "quarantine", "Review"))

        daemon = self.services.status(Role.DAEMON)
        if daemon.exists and daemon.failed:
            issues.append(Issue(
                "warn", "The scanning daemon has failed",
                f"{daemon.unit} is not running. Scans will still work but will "
                "be much slower.", "protection", "Diagnose"))

        for note in summarise_installation(self.clamav):
            if "daemon is not responding" in note:
                continue  # already covered by the service check above
            issues.append(Issue("warn", "ClamAV is incomplete", note, "dashboard"))

        if any(issue.blocking for issue in issues):
            level = ProtectionLevel.AT_RISK
            headline = issues[0].detail
        elif issues:
            level = ProtectionLevel.ATTENTION
            count = len(issues)
            headline = (f"{count} thing{'' if count == 1 else 's'} to look at. "
                        "Scanning works, but this machine is not fully covered.")
        else:
            level = ProtectionLevel.PROTECTED
            headline = summary.headline()

        return ProtectionStatus(level, headline, tuple(issues))

    # -- shutdown ---------------------------------------------------------

    def shutdown(self) -> None:
        """Stop anything still running. Called once, on quit."""
        log.info("shutting down")
        self.scheduler.stop()
        self.realtime.stop()
        self.history.close_realtime_scan(self.realtime_detection_count)
        if self.scanner.busy:
            self.scanner.stop()
        if self.freshclam.running:
            self.freshclam.stop()
