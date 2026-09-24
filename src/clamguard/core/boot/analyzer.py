"""Runs the catalogue, off the UI thread, and reports what it found.

This is the only object in the package that knows about Qt, and it knows as
little as possible: it takes a :class:`~.profile.Profile`, runs every enabled
check against one shared :class:`~.probe.Probe`, applies the user's mutes and
severity overrides, and emits a :class:`~.model.Report`.

Everything slow happens on a worker thread through
:func:`core.process.run_in_background`, so the window stays responsive while
forty checks read a few hundred files. The checks themselves know nothing about
threads — they are ordinary generator functions — which is what keeps them
testable.
"""

from __future__ import annotations

import time
from datetime import datetime

from PySide6.QtCore import QObject, Signal

from ..logging_setup import get_logger
from ..process import run_in_background
from . import custom
from .model import Report, Severity, SkippedCheck
from .probe import Probe
from .profile import Profile
from .registry import Check, catalogue, run_check, skipped_record

log = get_logger(__name__)


class BootAnalyzer(QObject):
    """Runs the boot checks and hands back a Report.

    ::

        analyzer = BootAnalyzer(profile)
        analyzer.finished.connect(page.show_report)
        analyzer.start()

    One run at a time. Asking for a second while the first is going is ignored
    with a warning rather than queued — the result would be the same and the
    user would have paid twice for it.
    """

    #: A run began. The argument is how many checks will run.
    started = Signal(int)
    #: Progress: (checks completed, total, the title of the one just finished).
    progressed = Signal(int, int, str)
    #: A run completed. The argument is a Report.
    finished = Signal(object)
    #: The run could not happen at all. The argument is a sentence to show.
    failed = Signal(str)
    #: True while a run is in flight, for enabling and disabling buttons.
    busy_changed = Signal(bool)

    def __init__(self, profile: Profile | None = None,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.profile = profile or Profile()
        self._busy = False
        #: The last report, so a page reopened does not have to re-run.
        self.last_report: Report | None = None
        #: Complaints about user-written check files, shown once in the UI.
        self.custom_problems: list[str] = []

    @property
    def busy(self) -> bool:
        return self._busy

    # -- running ----------------------------------------------------------

    def start(self, only: tuple[str, ...] = ()) -> bool:
        """Analyse in the background. `only` restricts it to those check ids."""
        if self._busy:
            log.warning("a boot analysis is already running")
            return False

        checks = self._selected(only)
        if not checks:
            self.failed.emit(
                "Every check is switched off in this profile, so there is "
                "nothing to run. Turn some back on in the Checks tab.")
            return False

        self._set_busy(True)
        self.started.emit(len(checks))
        policy = self.profile.policy()

        run_in_background(
            lambda: analyse(checks, self.profile, policy, self._report_progress),
            on_done=self._on_done,
            on_error=self._on_error,
        )
        return True

    def available_checks(self) -> list[Check]:
        """The built-in catalogue plus whatever the user has written.

        Custom checks are loaded on every run rather than cached, so editing a
        file in boot-checks.d takes effect on the next Analyse without a
        restart.
        """
        extra, problems = custom.load()
        self.custom_problems = problems
        if problems:
            log.warning("custom boot checks with problems: %s", "; ".join(problems))
        return list(catalogue()) + extra

    def _selected(self, only: tuple[str, ...]) -> list[Check]:
        wanted = set(only)
        return [item for item in self.available_checks()
                if (item.id in wanted if wanted else self.profile.is_enabled(item.id))]

    def _report_progress(self, done: int, total: int, title: str) -> None:
        # Emitted from the worker thread. Qt queues it across to the UI thread
        # because the receiver lives there, which is the whole reason this goes
        # through a signal rather than a callback.
        try:
            self.progressed.emit(done, total, title)
        except RuntimeError:
            # The window closed while the analysis was still running, so the
            # C++ side of this object is gone. The run is pointless now, but
            # raising out of a pool thread is worse than stopping quietly.
            pass

    def _on_done(self, report: Report) -> None:
        self._set_busy(False)
        self.last_report = report
        log.info("boot analysis: %d findings, score %d, %.2fs",
                 len(report.findings), report.score, report.duration)
        self.finished.emit(report)

    def _on_error(self, message: str) -> None:
        self._set_busy(False)
        log.error("boot analysis failed: %s", message)
        self.failed.emit(f"The boot analysis could not finish: {message}")

    def _set_busy(self, busy: bool) -> None:
        if busy != self._busy:
            self._busy = busy
            self.busy_changed.emit(busy)


# ---------------------------------------------------------------------------
# The run itself — no Qt, so tests can call it directly
# ---------------------------------------------------------------------------


def analyse(checks, profile: Profile, policy=None, on_progress=None) -> Report:
    """Run `checks` against one shared probe and build the Report.

    Separate from :class:`BootAnalyzer` so the whole analysis can be exercised
    in a test with three lines and no event loop.
    """
    policy = policy or profile.policy()
    probe = Probe()
    started = time.monotonic()
    when = datetime.now()

    findings = []
    skipped: list[SkippedCheck] = []
    total = len(checks)

    for index, item in enumerate(checks, start=1):
        outcome = run_check(item, probe, policy)
        record = skipped_record(outcome)
        if record is not None:
            skipped.append(record)
        for result in outcome.findings:
            findings.append(profile.apply_to(result))
        if on_progress is not None:
            on_progress(index, total, item.title)

    return Report(
        findings=tuple(findings),
        skipped=tuple(skipped),
        facts=system_facts(probe, findings),
        timings=_timings(probe),
        details=_details(probe),
        started_at=when,
        duration=time.monotonic() - started,
        hostname=probe.hostname(),
        kernel=probe.kernel_release(),
        distribution=probe.os_release().get("PRETTY_NAME", ""),
        preset=profile.preset,
        probe_log=probe.log_lines(),
    )


def _details(probe: Probe) -> dict:
    """Table data for the secondary tabs, gathered from the same probe.

    Taken from the probe the checks just used rather than re-read, so the
    Startup tab and the persistence findings can never disagree about what is
    on this machine. Both calls are cached on the probe, so this costs nothing
    if the relevant checks already ran, and does the work once if they did not.
    """
    from .checks.persistence import inventory
    from .checks.services import exposure_table

    details: dict = {}
    try:
        found = inventory(probe)
        details["startup"] = list(found.entries)
        details["startup_unreadable"] = list(found.unreadable)
    except Exception:  # noqa: BLE001 - a tab losing its table is not a failed run
        log.debug("startup inventory unavailable", exc_info=True)
    try:
        details["exposure"] = exposure_table(probe)
    except Exception:  # noqa: BLE001
        log.debug("exposure table unavailable", exc_info=True)
    return details


def _timings(probe: Probe):
    """The boot timing, if the performance checks already measured it."""
    from .checks.performance import timings

    try:
        return timings(probe)
    except Exception:  # noqa: BLE001 - timing is a nicety, never a failure
        log.debug("boot timings unavailable", exc_info=True)
        return None


def system_facts(probe: Probe, findings) -> dict[str, str]:
    """The short summary strip at the top of the page.

    Assembled from findings where possible rather than re-probing, so the strip
    and the findings can never disagree with each other.
    """
    by_id = {item.id: item for item in findings}

    def value_of(finding_id: str, fallback: str = "—") -> str:
        item = by_id.get(finding_id)
        return item.value if item is not None and item.value else fallback

    facts: dict[str, str] = {}
    facts["Firmware"] = "UEFI" if probe.exists("/sys/firmware/efi") else "legacy BIOS"
    facts["Secure Boot"] = _first(by_id, ("firmware.secure-boot.enabled",
                                          "firmware.secure-boot.disabled",
                                          "firmware.secure-boot.setup-mode",
                                          "firmware.secure-boot.unknown"))
    facts["TPM"] = _first(by_id, ("firmware.tpm.measured", "firmware.tpm.not-measured",
                                  "firmware.tpm.old", "firmware.tpm.absent"))
    facts["Bootloader"] = value_of("bootchain.bootloader.detected",
                                   value_of("bootchain.bootloader.unknown"))
    facts["Lockdown"] = value_of("kernel.lockdown.on", value_of("kernel.lockdown.none"))
    facts["Kernel"] = probe.kernel_release() or "—"
    facts["Root filesystem"] = _first(by_id, ("bootchain.encryption.root",
                                              "bootchain.encryption.none"))
    return {key: value for key, value in facts.items() if value}


def _first(by_id: dict, candidates) -> str:
    for finding_id in candidates:
        item = by_id.get(finding_id)
        if item is not None:
            return item.value or item.severity.label
    return "—"


def worst_severity(report: Report) -> Severity:
    """Convenience for the sidebar badge."""
    return report.worst
