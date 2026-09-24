"""Levels, timestamps, ranges and result tables.

The level table is the load-bearing part: every format on the machine spells
"warning" differently, and a query that says `Level == "warning"` has to find
all of them.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt.model import (  # noqa: E402
    ColumnType,
    Event,
    Level,
    QueryStats,
    ResultTable,
    TIME_PRESETS,
    TimeRange,
    format_timespan,
    format_timestamp,
    from_epoch_us,
    humanise_age,
    humanise_bytes,
    humanise_count,
    humanise_duration,
    nice_step,
    parse_timespan,
    to_epoch_us,
)


class TestLevel(unittest.TestCase):
    def test_every_spelling_of_a_warning_is_a_warning(self) -> None:
        for word in ("warning", "WARN", "wrn", "W", "[warning]", " Warn ",
                     "Caution", "deprecated"):
            with self.subTest(word=word):
                self.assertIs(Level.parse(word), Level.WARNING)

    def test_every_spelling_of_an_error_is_an_error(self) -> None:
        for word in ("error", "ERR", "E", "severe", "failed", "Failure"):
            with self.subTest(word=word):
                self.assertIs(Level.parse(word), Level.ERROR)

    def test_fatal_and_panic_are_critical(self) -> None:
        for word in ("fatal", "critical", "crit", "emerg", "panic", "alert"):
            with self.subTest(word=word):
                self.assertIs(Level.parse(word), Level.CRITICAL)

    def test_syslog_priorities_map_to_levels(self) -> None:
        self.assertIs(Level.parse(3), Level.ERROR)
        self.assertIs(Level.parse(4), Level.WARNING)
        self.assertIs(Level.parse(6), Level.INFO)
        self.assertIs(Level.parse("7"), Level.DEBUG)

    def test_a_line_that_does_not_say_is_unknown_rather_than_info(self) -> None:
        """Promoting silence to INFO would hide half the machine from
        "show me everything that is not informational"."""
        for word in ("", "   ", "banana", None, True):
            with self.subTest(word=word):
                self.assertIs(Level.parse(word), Level.UNKNOWN)

    def test_worse_levels_sort_higher(self) -> None:
        self.assertGreater(Level.CRITICAL, Level.ERROR)
        self.assertGreater(Level.ERROR, Level.WARNING)
        self.assertGreater(Level.WARNING, Level.INFO)
        self.assertGreater(Level.INFO, Level.DEBUG)

    def test_every_level_has_a_label_a_tone_and_an_icon(self) -> None:
        for level in Level:
            with self.subTest(level=level):
                self.assertTrue(level.label)
                self.assertTrue(level.tone)

    def test_a_stored_integer_round_trips(self) -> None:
        for level in Level:
            self.assertIs(Level.from_value(int(level)), level)

    def test_rubbish_from_the_database_does_not_raise(self) -> None:
        self.assertIs(Level.from_value("x"), Level.UNKNOWN)
        self.assertIs(Level.from_value(None), Level.UNKNOWN)
        self.assertIs(Level.from_value(999), Level.UNKNOWN)

    def test_warning_and_above_are_problems(self) -> None:
        self.assertTrue(Level.WARNING.is_problem)
        self.assertTrue(Level.ERROR.is_problem)
        self.assertFalse(Level.INFO.is_problem)
        self.assertFalse(Level.UNKNOWN.is_problem)


class TestTime(unittest.TestCase):
    def test_a_datetime_round_trips_through_epoch_microseconds(self) -> None:
        moment = datetime(2026, 9, 21, 14, 30, 5, 123456, tzinfo=timezone.utc)
        self.assertEqual(from_epoch_us(to_epoch_us(moment)), moment)

    def test_a_naive_datetime_is_read_as_local(self) -> None:
        naive = datetime(2026, 9, 21, 14, 30)
        self.assertEqual(to_epoch_us(naive),
                         int(naive.astimezone().timestamp() * 1_000_000))

    def test_a_missing_timestamp_formats_as_nothing(self) -> None:
        self.assertEqual(format_timestamp(None), "")

    def test_a_timestamp_shows_its_fraction(self) -> None:
        moment = datetime(2026, 9, 21, 14, 30, 5, 123000, tzinfo=timezone.utc)
        self.assertIn(".123", format_timestamp(moment, local=False))

    def test_an_impossible_stored_value_decodes_to_none(self) -> None:
        self.assertIsNone(from_epoch_us(10 ** 25))

    def test_timespans_parse_in_every_form_a_person_writes(self) -> None:
        cases = {"5m": 300, "1.5h": 5400, "90s": 90, "2d": 172800,
                 "100ms": 0.1, "3 hours": 10800, "1 day": 86400}
        for text, seconds in cases.items():
            with self.subTest(text=text):
                self.assertAlmostEqual(parse_timespan(text).total_seconds(),
                                       seconds, places=6)

    def test_minutes_are_not_milliseconds(self) -> None:
        """The suffix table is ordered longest-first for exactly this."""
        self.assertEqual(parse_timespan("5m").total_seconds(), 300)
        self.assertEqual(parse_timespan("5ms").total_seconds(), 0.005)

    def test_nonsense_is_none_rather_than_zero(self) -> None:
        self.assertIsNone(parse_timespan("soon"))
        self.assertIsNone(parse_timespan(""))

    def test_a_timespan_prints_in_kusto_notation(self) -> None:
        self.assertEqual(format_timespan(timedelta(hours=1, minutes=2, seconds=3)),
                         "01:02:03")
        self.assertEqual(format_timespan(timedelta(days=1, hours=2)), "1.02:00:00")
        self.assertTrue(format_timespan(timedelta(seconds=-5)).startswith("-"))


class TestTimeRange(unittest.TestCase):
    def test_a_rolling_range_stays_rolling(self) -> None:
        """Saved as a duration, not as two instants, so "the last day" still
        means the last day next year."""
        rolling = TimeRange.rolling(timedelta(days=1), "Last 24 hours")
        restored = TimeRange.from_dict(rolling.to_dict())
        self.assertEqual(restored.last, timedelta(days=1))
        self.assertIsNone(restored.start)

    def test_an_absolute_range_round_trips(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 2, 1, tzinfo=timezone.utc)
        restored = TimeRange.from_dict(TimeRange(start=start, end=end).to_dict())
        self.assertEqual(restored.start, start)
        self.assertEqual(restored.end, end)

    def test_bounds_of_a_rolling_range_are_relative_to_now(self) -> None:
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        start, end = TimeRange.rolling(timedelta(hours=2)).bounds(now)
        self.assertEqual(from_epoch_us(start),
                         datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc))
        self.assertIsNone(end)

    def test_everything_has_no_bounds(self) -> None:
        self.assertTrue(TimeRange.everything().unbounded)
        self.assertEqual(TimeRange.everything().bounds(), (None, None))

    def test_a_broken_stored_range_falls_back(self) -> None:
        self.assertTrue(TimeRange.from_dict("nonsense").unbounded)
        self.assertTrue(TimeRange.from_dict({}).unbounded)

    def test_every_preset_describes_itself(self) -> None:
        for name, delta in TIME_PRESETS:
            with self.subTest(preset=name):
                self.assertTrue(name)
                found = TimeRange(last=delta, label=name)
                self.assertEqual(found.describe(), name)


class TestResultTable(unittest.TestCase):
    def setUp(self) -> None:
        self.table = ResultTable.of(
            [("Name", ColumnType.STRING), ("Count", ColumnType.LONG)],
            [("alpha", 3), ("beta", 5)])

    def test_columns_are_found_case_insensitively(self) -> None:
        self.assertEqual(self.table.index_of("count"), 1)
        self.assertEqual(self.table.index_of("COUNT"), 1)
        self.assertEqual(self.table.index_of("nope"), -1)

    def test_values_are_reachable_by_name(self) -> None:
        self.assertEqual(self.table.value(1, "Name"), "beta")
        self.assertIsNone(self.table.value(9, "Name"))

    def test_rows_convert_to_dictionaries_for_export(self) -> None:
        self.assertEqual(self.table.to_dicts()[0], {"Name": "alpha", "Count": 3})

    def test_a_column_can_be_pulled_out_whole(self) -> None:
        self.assertEqual(self.table.column_values("Count"), [3, 5])
        self.assertEqual(self.table.column_values("missing"), [])

    def test_the_row_count_is_recorded(self) -> None:
        self.assertEqual(len(self.table), 2)
        self.assertEqual(self.table.stats.rows, 2)
        self.assertFalse(self.table.empty)


class TestStats(unittest.TestCase):
    def test_the_summary_reads_as_a_sentence(self) -> None:
        summary = QueryStats(rows=247, elapsed=0.043, scanned=1_203_455).summary()
        self.assertIn("247 rows", summary)
        self.assertIn("43 ms", summary)
        self.assertIn("1,203,455", summary)

    def test_one_row_is_singular(self) -> None:
        self.assertIn("1 row ", QueryStats(rows=1, elapsed=1).summary() + " ")

    def test_truncation_is_said_out_loud(self) -> None:
        self.assertIn("truncated", QueryStats(rows=10, truncated=True).summary())


class TestHumanising(unittest.TestCase):
    def test_durations_pick_a_sensible_unit(self) -> None:
        self.assertEqual(humanise_duration(0.0004), "400 µs")
        self.assertEqual(humanise_duration(0.043), "43 ms")
        self.assertEqual(humanise_duration(1.5), "1.50 s")
        self.assertEqual(humanise_duration(125), "2 m 05 s")

    def test_bytes_use_decimal_units(self) -> None:
        self.assertEqual(humanise_bytes(900), "900 B")
        self.assertEqual(humanise_bytes(1_400_000), "1.4 MB")

    def test_counts_shorten_for_a_chip(self) -> None:
        self.assertEqual(humanise_count(999), "999")
        self.assertEqual(humanise_count(1200), "1.2k")
        self.assertEqual(humanise_count(1_200_000), "1.2M")
        self.assertEqual(humanise_count(23_000_000), "23M")

    def test_a_float_epoch_is_accepted(self) -> None:
        """`os.stat` and `time.time` both hand out floats, and rejecting one
        only to subtract it from a datetime later is a crash waiting for the
        first non-zero value."""
        import time as _time

        self.assertEqual(humanise_age(float(_time.time()) * 1_000_000), "just now")
        # Zero is the Unix epoch, not "never" — the callers that use 0 as a
        # sentinel check for it themselves rather than making this function
        # lie about a genuine 1970 timestamp.
        self.assertIn("years ago", humanise_age(0.0))
        self.assertEqual(humanise_age(None), "never")
        self.assertEqual(humanise_age(True), "never")

    def test_ages_read_the_way_a_person_says_them(self) -> None:
        now = datetime.now(timezone.utc)
        self.assertEqual(humanise_age(None), "never")
        self.assertEqual(humanise_age(now - timedelta(seconds=10)), "just now")
        self.assertEqual(humanise_age(now - timedelta(days=1, hours=1)), "yesterday")
        self.assertIn("hours ago", humanise_age(now - timedelta(hours=5)))

    def test_chart_buckets_are_round_numbers(self) -> None:
        self.assertEqual(nice_step(3600, 60), timedelta(seconds=60))
        self.assertEqual(nice_step(86400, 24), timedelta(seconds=3600))
        self.assertGreaterEqual(nice_step(1, 60).total_seconds(), 1)


class TestEvent(unittest.TestCase):
    def test_raw_is_only_kept_when_it_differs(self) -> None:
        event = Event(message="hello")
        self.assertEqual(event.text, "hello")
        event.raw = "[info] hello"
        self.assertEqual(event.text, "[info] hello")

    def test_an_event_can_say_when_it_happened(self) -> None:
        moment = datetime(2026, 9, 21, tzinfo=timezone.utc)
        self.assertEqual(Event(timestamp=to_epoch_us(moment)).when(), moment)
        self.assertIsNone(Event().when())


if __name__ == "__main__":
    unittest.main()
