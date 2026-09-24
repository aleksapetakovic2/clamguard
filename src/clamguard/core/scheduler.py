"""Scheduled scans.

Kept inside the application rather than as systemd timers, for two reasons: a
scan has to talk to the running ClamGuard to report its results, and writing
units into the user's systemd directory is exactly the kind of thing this app
promises not to do behind their back.

The cost is that scheduled scans only run while ClamGuard is running — which is
why the tray icon and the "start at login" option exist, and why a schedule
that was missed while the app was closed can be caught up on the next launch.

Schedules live in ~/.config/clamguard/schedules.json as plain readable JSON.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, QTimer, Signal

from . import paths
from .logging_setup import get_logger
from .scan_targets import ScanKind

log = get_logger(__name__)

#: How often the scheduler wakes up to see whether anything is due.
TICK_SECONDS = 30

WEEKDAY_NAMES = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
                 "Saturday", "Sunday")


@dataclass
class Schedule:
    """One recurring scan."""

    id: str = ""
    name: str = "Scheduled scan"
    enabled: bool = True
    kind: str = ScanKind.QUICK.value
    custom_paths: list[str] = field(default_factory=list)
    profile_id: str = "balanced"
    frequency: str = "daily"          # hourly / daily / weekly / monthly
    time_of_day: str = "03:00"        # HH:MM, ignored for hourly
    day_of_week: int = 0              # 0 = Monday, used by weekly
    day_of_month: int = 1             # 1-28, used by monthly
    last_run: str = ""                # ISO timestamp
    catch_up: bool = True             # run once if the time passed while closed

    # -- derived ----------------------------------------------------------

    @property
    def scan_kind(self) -> ScanKind:
        try:
            return ScanKind(self.kind)
        except ValueError:
            return ScanKind.QUICK

    @property
    def last_run_at(self) -> datetime | None:
        try:
            return datetime.fromisoformat(self.last_run) if self.last_run else None
        except ValueError:
            return None

    def describe(self) -> str:
        """"Every day at 03:00" — the line shown under the schedule's name."""
        if self.frequency == "hourly":
            return "Every hour"
        if self.frequency == "daily":
            return f"Every day at {self.time_of_day}"
        if self.frequency == "weekly":
            day = WEEKDAY_NAMES[self.day_of_week % 7]
            return f"Every {day} at {self.time_of_day}"
        if self.frequency == "monthly":
            return f"Day {self.day_of_month} of each month at {self.time_of_day}"
        return "Never"

    def next_run_after(self, moment: datetime) -> datetime:
        """The first time this schedule fires strictly after `moment`."""
        hour, minute = self._parsed_time()

        if self.frequency == "hourly":
            candidate = moment.replace(minute=minute, second=0, microsecond=0)
            if candidate <= moment:
                candidate += timedelta(hours=1)
            return candidate

        candidate = moment.replace(hour=hour, minute=minute, second=0, microsecond=0)

        if self.frequency == "daily":
            if candidate <= moment:
                candidate += timedelta(days=1)
            return candidate

        if self.frequency == "weekly":
            days_ahead = (self.day_of_week - candidate.weekday()) % 7
            candidate += timedelta(days=days_ahead)
            if candidate <= moment:
                candidate += timedelta(days=7)
            return candidate

        if self.frequency == "monthly":
            day = max(1, min(28, self.day_of_month))
            candidate = candidate.replace(day=day)
            if candidate <= moment:
                month = candidate.month + 1
                year = candidate.year + (month > 12)
                candidate = candidate.replace(year=year, month=(month - 1) % 12 + 1)
            return candidate

        return moment + timedelta(days=36500)  # effectively never

    def next_run(self) -> datetime:
        reference = self.last_run_at or datetime.now()
        return self.next_run_after(max(reference, datetime.now() - timedelta(days=365)))

    def is_due(self, now: datetime | None = None) -> bool:
        """Should this run right now?"""
        if not self.enabled:
            return False
        now = now or datetime.now()
        last = self.last_run_at
        if last is None:
            # Never run: fire at the next scheduled moment, not immediately.
            return False
        return self.next_run_after(last) <= now

    def _parsed_time(self) -> tuple[int, int]:
        try:
            hour, _, minute = self.time_of_day.partition(":")
            return max(0, min(23, int(hour))), max(0, min(59, int(minute)))
        except (ValueError, AttributeError):
            return 3, 0


class Scheduler(QObject):
    """Holds the schedules and says when one is due."""

    #: A Schedule that should run now. The UI decides whether it can.
    due = Signal(object)
    #: The schedule list changed.
    changed = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._schedules: list[Schedule] = []
        self.load()

        self._timer = QTimer(self)
        self._timer.setInterval(TICK_SECONDS * 1000)
        self._timer.timeout.connect(self._tick)

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Begin checking. Also handles anything missed while the app was shut."""
        self._catch_up()
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    # -- persistence ------------------------------------------------------

    def load(self) -> None:
        self._schedules = []
        if not paths.SCHEDULES_FILE.is_file():
            return
        try:
            raw = json.loads(paths.SCHEDULES_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            log.warning("cannot read schedules: %s", error)
            return
        known = set(Schedule.__dataclass_fields__)
        for item in raw if isinstance(raw, list) else []:
            if isinstance(item, dict):
                self._schedules.append(
                    Schedule(**{k: v for k, v in item.items() if k in known})
                )

    def save(self) -> None:
        try:
            paths.SCHEDULES_FILE.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps([asdict(s) for s in self._schedules], indent=2)
            temporary = paths.SCHEDULES_FILE.with_suffix(".json.tmp")
            temporary.write_text(payload + "\n", encoding="utf-8")
            temporary.replace(paths.SCHEDULES_FILE)
        except OSError as error:
            log.error("cannot save schedules: %s", error)

    # -- collection -------------------------------------------------------

    def schedules(self) -> list[Schedule]:
        return list(self._schedules)

    def get(self, schedule_id: str) -> Schedule | None:
        return next((s for s in self._schedules if s.id == schedule_id), None)

    def add(self, schedule: Schedule) -> Schedule:
        if not schedule.id:
            schedule.id = secrets.token_hex(6)
        self._schedules.append(schedule)
        self.save()
        self.changed.emit()
        return schedule

    def update(self, schedule: Schedule) -> None:
        for index, existing in enumerate(self._schedules):
            if existing.id == schedule.id:
                self._schedules[index] = schedule
                break
        else:
            self._schedules.append(schedule)
        self.save()
        self.changed.emit()

    def remove(self, schedule_id: str) -> None:
        self._schedules = [s for s in self._schedules if s.id != schedule_id]
        self.save()
        self.changed.emit()

    def set_enabled(self, schedule_id: str, enabled: bool) -> None:
        schedule = self.get(schedule_id)
        if schedule is not None and schedule.enabled != enabled:
            schedule.enabled = enabled
            self.save()
            self.changed.emit()

    def mark_run(self, schedule_id: str, when: datetime | None = None) -> None:
        """Record that a schedule just fired, so it does not fire again."""
        schedule = self.get(schedule_id)
        if schedule is None:
            return
        schedule.last_run = (when or datetime.now()).isoformat(timespec="seconds")
        self.save()
        self.changed.emit()

    # -- what happens next ------------------------------------------------

    def next_due(self) -> tuple[Schedule, datetime] | None:
        """The soonest upcoming scan, or None if nothing is enabled."""
        upcoming = [(s, s.next_run()) for s in self._schedules if s.enabled]
        return min(upcoming, key=lambda pair: pair[1]) if upcoming else None

    def _tick(self) -> None:
        now = datetime.now()
        for schedule in self._schedules:
            if schedule.is_due(now):
                log.info("schedule %s (%s) is due", schedule.id, schedule.name)
                self.mark_run(schedule.id, now)
                self.due.emit(schedule)

    def _catch_up(self) -> None:
        """Fire schedules whose time passed while ClamGuard was not running.

        At most one catch-up per schedule, no matter how long the app was
        closed — nobody wants seven scans queued up after a week away.
        """
        now = datetime.now()
        for schedule in self._schedules:
            if not schedule.enabled or not schedule.catch_up:
                continue
            if schedule.last_run_at is None:
                # Never run; start the clock now rather than firing on launch.
                self.mark_run(schedule.id, now)
                continue
            if schedule.is_due(now):
                log.info("catching up missed schedule %s", schedule.name)
                self.mark_run(schedule.id, now)
                self.due.emit(schedule)
