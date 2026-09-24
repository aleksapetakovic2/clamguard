"""Scheduled scan timing and persistence."""

from __future__ import annotations

import unittest
from datetime import datetime

from .support import TempHomeTestCase

from clamguard.core.scan_targets import ScanKind


class TestScheduleTiming(unittest.TestCase):
    def setUp(self) -> None:
        from clamguard.core.scheduler import Schedule

        self.Schedule = Schedule
        # A Wednesday.
        self.now = datetime(2026, 9, 16, 14, 30)

    def test_daily_before_the_time_fires_today(self) -> None:
        schedule = self.Schedule(frequency="daily", time_of_day="18:00")
        self.assertEqual(schedule.next_run_after(self.now),
                         datetime(2026, 9, 16, 18, 0))

    def test_daily_after_the_time_fires_tomorrow(self) -> None:
        schedule = self.Schedule(frequency="daily", time_of_day="03:00")
        self.assertEqual(schedule.next_run_after(self.now),
                         datetime(2026, 9, 17, 3, 0))

    def test_hourly_uses_only_the_minutes(self) -> None:
        schedule = self.Schedule(frequency="hourly", time_of_day="00:45")
        self.assertEqual(schedule.next_run_after(self.now),
                         datetime(2026, 9, 16, 14, 45))
        later = datetime(2026, 9, 16, 14, 50)
        self.assertEqual(schedule.next_run_after(later),
                         datetime(2026, 9, 16, 15, 45))

    def test_weekly_finds_the_next_matching_weekday(self) -> None:
        # 0 = Monday. From a Wednesday, the next Monday is the 21st.
        schedule = self.Schedule(frequency="weekly", day_of_week=0, time_of_day="02:00")
        self.assertEqual(schedule.next_run_after(self.now),
                         datetime(2026, 9, 21, 2, 0))

    def test_weekly_on_today_but_later_fires_today(self) -> None:
        schedule = self.Schedule(frequency="weekly", day_of_week=2, time_of_day="20:00")
        self.assertEqual(schedule.next_run_after(self.now),
                         datetime(2026, 9, 16, 20, 0))

    def test_weekly_on_today_but_earlier_waits_a_week(self) -> None:
        schedule = self.Schedule(frequency="weekly", day_of_week=2, time_of_day="09:00")
        self.assertEqual(schedule.next_run_after(self.now),
                         datetime(2026, 9, 23, 9, 0))

    def test_monthly(self) -> None:
        schedule = self.Schedule(frequency="monthly", day_of_month=20,
                                 time_of_day="04:00")
        self.assertEqual(schedule.next_run_after(self.now),
                         datetime(2026, 9, 20, 4, 0))

    def test_monthly_rolls_over_the_year(self) -> None:
        schedule = self.Schedule(frequency="monthly", day_of_month=1,
                                 time_of_day="04:00")
        december = datetime(2026, 12, 5, 12, 0)
        self.assertEqual(schedule.next_run_after(december),
                         datetime(2027, 1, 1, 4, 0))

    def test_monthly_day_is_capped_at_28(self) -> None:
        """Avoids a schedule that silently never runs in February."""
        schedule = self.Schedule(frequency="monthly", day_of_month=31,
                                 time_of_day="04:00")
        self.assertEqual(schedule.next_run_after(self.now).day, 28)

    def test_a_malformed_time_falls_back_rather_than_crashing(self) -> None:
        schedule = self.Schedule(frequency="daily", time_of_day="not a time")
        self.assertEqual(schedule.next_run_after(self.now).hour, 3)

    def test_never_run_schedules_do_not_fire_immediately(self) -> None:
        """Otherwise adding a schedule would launch a scan on the spot."""
        schedule = self.Schedule(frequency="daily", time_of_day="03:00")
        self.assertFalse(schedule.is_due(self.now))

    def test_an_overdue_schedule_is_due(self) -> None:
        schedule = self.Schedule(frequency="daily", time_of_day="03:00")
        schedule.last_run = datetime(2026, 9, 14, 3, 0).isoformat()
        self.assertTrue(schedule.is_due(self.now))

    def test_a_schedule_that_just_ran_is_not_due(self) -> None:
        schedule = self.Schedule(frequency="daily", time_of_day="03:00")
        schedule.last_run = datetime(2026, 9, 16, 3, 0).isoformat()
        self.assertFalse(schedule.is_due(self.now))

    def test_a_disabled_schedule_is_never_due(self) -> None:
        schedule = self.Schedule(frequency="hourly", enabled=False)
        schedule.last_run = datetime(2020, 1, 1).isoformat()
        self.assertFalse(schedule.is_due(self.now))

    def test_descriptions_read_as_english(self) -> None:
        self.assertEqual(self.Schedule(frequency="hourly").describe(), "Every hour")
        self.assertEqual(
            self.Schedule(frequency="daily", time_of_day="03:00").describe(),
            "Every day at 03:00")
        self.assertEqual(
            self.Schedule(frequency="weekly", day_of_week=6,
                          time_of_day="02:30").describe(),
            "Every Sunday at 02:30")
        self.assertIn("Day 15", self.Schedule(frequency="monthly",
                                              day_of_month=15).describe())

    def test_scan_kind_falls_back_when_unknown(self) -> None:
        self.assertIs(self.Schedule(kind="nonsense").scan_kind, ScanKind.QUICK)
        self.assertIs(self.Schedule(kind="full").scan_kind, ScanKind.FULL)


class TestSchedulerPersistence(TempHomeTestCase):
    def setUp(self) -> None:
        super().setUp()
        import importlib

        from clamguard.core import scheduler

        importlib.reload(scheduler)
        self.module = scheduler
        self.scheduler = scheduler.Scheduler()

    def test_schedules_survive_a_restart(self) -> None:
        self.scheduler.add(self.module.Schedule(name="Nightly", frequency="daily"))
        self.scheduler.add(self.module.Schedule(name="Weekly", frequency="weekly"))
        reloaded = self.module.Scheduler()
        self.assertEqual([s.name for s in reloaded.schedules()], ["Nightly", "Weekly"])

    def test_added_schedules_get_an_id(self) -> None:
        added = self.scheduler.add(self.module.Schedule(name="x"))
        self.assertTrue(added.id)
        self.assertIsNotNone(self.scheduler.get(added.id))

    def test_update_replaces_by_id(self) -> None:
        added = self.scheduler.add(self.module.Schedule(name="Before"))
        added.name = "After"
        self.scheduler.update(added)
        self.assertEqual(self.scheduler.get(added.id).name, "After")
        self.assertEqual(len(self.scheduler.schedules()), 1)

    def test_remove(self) -> None:
        added = self.scheduler.add(self.module.Schedule(name="x"))
        self.scheduler.remove(added.id)
        self.assertEqual(self.scheduler.schedules(), [])

    def test_enable_and_disable(self) -> None:
        added = self.scheduler.add(self.module.Schedule(name="x", enabled=True))
        self.scheduler.set_enabled(added.id, False)
        self.assertFalse(self.scheduler.get(added.id).enabled)

    def test_next_due_picks_the_soonest_enabled_schedule(self) -> None:
        self.scheduler.add(self.module.Schedule(name="Monthly", frequency="monthly"))
        self.scheduler.add(self.module.Schedule(name="Hourly", frequency="hourly"))
        self.scheduler.add(self.module.Schedule(name="Off", frequency="hourly",
                                                enabled=False))
        schedule, _when = self.scheduler.next_due()
        self.assertEqual(schedule.name, "Hourly")

    def test_next_due_is_none_when_nothing_is_enabled(self) -> None:
        self.scheduler.add(self.module.Schedule(name="Off", enabled=False))
        self.assertIsNone(self.scheduler.next_due())

    def test_unknown_keys_in_the_file_are_ignored(self) -> None:
        self.module.paths.SCHEDULES_FILE.write_text(
            '[{"name": "From the future", "frequency": "daily", "nonsense": 1}]')
        reloaded = self.module.Scheduler()
        self.assertEqual(len(reloaded.schedules()), 1)
        self.assertEqual(reloaded.schedules()[0].name, "From the future")

    def test_a_broken_file_does_not_crash(self) -> None:
        self.module.paths.SCHEDULES_FILE.write_text("{not json")
        self.assertEqual(self.module.Scheduler().schedules(), [])

    def test_catch_up_starts_the_clock_for_a_new_schedule(self) -> None:
        """A schedule that has never run must not fire the moment it is added."""
        added = self.scheduler.add(self.module.Schedule(name="x", frequency="hourly"))
        fired = []
        self.scheduler.due.connect(fired.append)
        self.scheduler._catch_up()
        self.assertEqual(fired, [])
        self.assertTrue(self.scheduler.get(added.id).last_run)


if __name__ == "__main__":
    unittest.main()
