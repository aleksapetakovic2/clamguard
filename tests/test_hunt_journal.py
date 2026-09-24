"""Reading the systemd journal: the command line, the cursor, and the traps.

Three behaviours of journalctl drove this module's design, and each has a test
here because each was found by measurement rather than by reading the manual:

* a stale cursor prints to stderr, prints nothing to stdout and exits
  non-zero, which is indistinguishable from "nothing new" unless somebody
  looks;
* ``--lines`` takes the *oldest* N when ``--no-tail`` is passed and the
  *newest* N without it, so the cap is only safe because of a flag that looks
  unrelated;
* ``MESSAGE`` is not always a string.

The reader takes an `opener`, so every one of those is exercised against
canned output rather than against whatever the machine's journal happens to
contain today.
"""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt import journal  # noqa: E402
from clamguard.core.hunt.formats import (  # noqa: E402
    ParseContext,
    get as get_format,
    journal_message,
    journal_unit,
    strip_ansi,
)
from clamguard.core.hunt.model import Level  # noqa: E402
from clamguard.core.hunt.store import Store  # noqa: E402

CONTEXT = ParseContext(year=2026, month=9)

CURSOR_ONE = "s=2de5e69664a940ea;i=36c2eac;b=6a4c10b1910d4317;m=c9c9d8526;t=65c08;x=58e9"
CURSOR_TWO = "s=2de5e69664a940ea;i=36c2ead;b=6a4c10b1910d4317;m=c9c9d8527;t=65c09;x=58ea"


def entry(**fields) -> str:
    """One journalctl -o json line, with sensible defaults."""
    payload = {
        "__CURSOR": CURSOR_ONE,
        "__REALTIME_TIMESTAMP": "1790041532996399",
        "PRIORITY": "6",
        "MESSAGE": "something happened",
        "_SYSTEMD_UNIT": "sshd.service",
        "_PID": "1234",
    }
    payload.update(fields)
    return json.dumps(payload)


class FakeProcess:
    """Stands in for Popen so the traps can be reproduced exactly."""

    def __init__(self, lines: list[str], *, stderr: str = "",
                 returncode: int = 0) -> None:
        self.stdout = io.StringIO("\n".join(lines) + ("\n" if lines else ""))
        self.stderr = io.StringIO(stderr)
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode


def opener_for(process: FakeProcess):
    def opener(_command):
        return process
    return opener


def read(lines, **kwargs):
    process = FakeProcess(lines, stderr=kwargs.pop("stderr", ""),
                          returncode=kwargs.pop("returncode", 0))
    options = kwargs.pop("options", journal.JournalOptions())
    result = journal.read(options, kwargs.pop("cursor", ""),
                          opener=opener_for(process), **kwargs)
    return result, process


# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


class TestArguments(unittest.TestCase):
    def test_every_argument_it_can_build_is_on_the_allow_list(self) -> None:
        """The allow-list is the boundary, so it has to cover the real
        product of every setting rather than the handful I had in mind."""
        for window in journal.WINDOWS:
            for priority in journal.PRIORITIES:
                for include_user in (True, False):
                    for cursor in ("", CURSOR_ONE):
                        options = journal.JournalOptions(
                            window=window, priority=priority,
                            include_user=include_user, max_entries=1234)
                        with self.subTest(window=window, priority=priority,
                                          user=include_user, resuming=bool(cursor)):
                            arguments = journal.build_arguments(options, cursor)
                            self.assertEqual(
                                journal.check_arguments(arguments), [])

    def test_the_output_is_always_json_and_never_paged(self) -> None:
        arguments = journal.build_arguments(journal.JournalOptions())
        self.assertIn("--output=json", arguments)
        self.assertIn("--no-pager", arguments)

    def test_no_tail_is_always_passed(self) -> None:
        """Load-bearing. With it, --lines returns the OLDEST N of the window,
        so a capped read plus its cursor resumes exactly where it stopped.
        Without it the same flag returns the NEWEST N and everything older
        than the cap is lost the moment the cursor is saved past it."""
        for cursor in ("", CURSOR_ONE):
            self.assertIn("--no-tail",
                          journal.build_arguments(journal.JournalOptions(), cursor))

    def test_a_window_is_used_only_when_not_resuming(self) -> None:
        fresh = journal.build_arguments(journal.JournalOptions(window="boot"))
        self.assertIn("--boot", fresh)
        resumed = journal.build_arguments(journal.JournalOptions(window="boot"),
                                          CURSOR_ONE)
        self.assertNotIn("--boot", resumed)
        self.assertIn(f"--after-cursor={CURSOR_ONE}", resumed)

    def test_each_window_becomes_the_flag_it_should(self) -> None:
        for window, expected in (("24h", "--since=24 hours ago"),
                                 ("7d", "--since=7 days ago"),
                                 ("30d", "--since=30 days ago")):
            with self.subTest(window=window):
                self.assertIn(expected, journal.build_arguments(
                    journal.JournalOptions(window=window)))

    def test_everything_passes_no_window_flag_at_all(self) -> None:
        arguments = journal.build_arguments(journal.JournalOptions(window="all"))
        self.assertFalse([item for item in arguments
                          if item.startswith(("--since", "--boot"))])

    def test_a_cursor_that_is_not_a_cursor_is_refused(self) -> None:
        """It round-trips through a database file the user can edit, and a
        value starting with a dash would otherwise be read as a flag."""
        for hostile in ("--vacuum-time=1s", "; rm -rf /", "--output=cat",
                        "s=abc; --merge", "", "not a cursor"):
            with self.subTest(cursor=hostile):
                arguments = journal.build_arguments(
                    journal.JournalOptions(window="boot"), hostile)
                self.assertEqual(journal.check_arguments(arguments), [])
                self.assertFalse([item for item in arguments
                                  if item.startswith("--after-cursor")])
                self.assertIn("--boot", arguments)

    def test_a_real_cursor_is_accepted(self) -> None:
        self.assertIsNotNone(journal.CURSOR.fullmatch(CURSOR_ONE))

    def test_the_allow_list_contains_nothing_that_changes_state(self) -> None:
        """journalctl can rotate, vacuum and erase the journal. None of those
        may be expressible."""
        for dangerous in ("--vacuum-size=1", "--vacuum-time=1s", "--rotate",
                          "--flush", "--sync", "--relinquish-var",
                          "--setup-keys", "--verify", "--update-catalog"):
            with self.subTest(argument=dangerous):
                self.assertEqual(journal.check_arguments([dangerous]),
                                 [dangerous])

    def test_settings_that_make_no_sense_are_normalised_away(self) -> None:
        options = journal.JournalOptions(window="../etc", priority="rm",
                                         max_entries=-5).normalised()
        self.assertEqual(options.window, journal.DEFAULT_WINDOW)
        self.assertEqual(options.priority, journal.DEFAULT_PRIORITY)
        self.assertGreaterEqual(options.max_entries, 1)

    def test_the_options_describe_themselves(self) -> None:
        self.assertIn("This boot", journal.JournalOptions().describe())


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


class TestReading(unittest.TestCase):
    def test_entries_come_back_with_their_unit(self) -> None:
        result, _process = read([entry(), entry(_SYSTEMD_UNIT="cron.service")])
        self.assertEqual(result.count, 2)
        self.assertEqual([unit for unit, _event in result.entries],
                         ["sshd.service", "cron.service"])

    def test_the_cursor_of_the_last_entry_is_kept(self) -> None:
        result, _process = read([entry(), entry(__CURSOR=CURSOR_TWO)])
        self.assertEqual(result.cursor, CURSOR_TWO)

    def test_a_stale_cursor_is_noticed_rather_than_read_as_silence(self) -> None:
        """journalctl prints the reason on stderr, prints nothing at all on
        stdout and exits non-zero. Read carelessly that looks exactly like
        "you are up to date", forever."""
        result, _process = read(
            [], stderr="Failed to seek to cursor: Invalid argument\n",
            returncode=1, cursor=CURSOR_ONE)
        self.assertTrue(result.stale_cursor)
        self.assertEqual(result.count, 0)
        self.assertEqual(result.error, "")

    def test_an_up_to_date_journal_is_not_mistaken_for_a_stale_cursor(self) -> None:
        result, _process = read([], cursor=CURSOR_ONE)
        self.assertFalse(result.stale_cursor)
        self.assertTrue(result.ok)
        self.assertEqual(result.count, 0)

    def test_another_kind_of_failure_is_reported_as_an_error(self) -> None:
        result, _process = read([], stderr="No journal files were found.\n",
                                returncode=1)
        self.assertFalse(result.ok)
        self.assertIn("No journal files", result.error)
        self.assertFalse(result.stale_cursor)

    def test_the_cap_stops_the_read_and_says_so(self) -> None:
        result, process = read([entry() for _ in range(50)],
                               options=journal.JournalOptions(max_entries=10))
        self.assertEqual(result.count, 10)
        self.assertTrue(result.truncated)
        self.assertTrue(process.terminated)

    def test_truncation_is_described_as_recoverable_because_it_is(self) -> None:
        result, _process = read([entry() for _ in range(5)],
                                options=journal.JournalOptions(max_entries=2))
        self.assertIn("next index", result.summary())

    def test_unparseable_lines_are_counted_not_fatal(self) -> None:
        result, _process = read(["not json", "", entry(), "{}"])
        self.assertEqual(result.count, 1)
        self.assertEqual(result.skipped, 3)

    def test_a_line_without_a_cursor_is_not_a_journal_entry(self) -> None:
        result, _process = read([json.dumps({"MESSAGE": "x", "PRIORITY": "6"})])
        self.assertEqual(result.count, 0)

    def test_it_can_be_cancelled(self) -> None:
        calls = {"n": 0}

        def should_stop() -> bool:
            calls["n"] += 1
            return calls["n"] > 1

        result, _process = read([entry() for _ in range(6000)],
                                should_stop=should_stop)
        self.assertTrue(result.cancelled or result.count < 6000)

    def test_a_refused_argument_stops_the_read_before_it_starts(self) -> None:
        """Cannot happen from the enums, but a loud failure beats running a
        command line nobody checked."""
        saved = journal.ALLOWED_ARGUMENTS
        try:
            journal.ALLOWED_ARGUMENTS = ()
            result, _process = read([entry()])
        finally:
            journal.ALLOWED_ARGUMENTS = saved
        self.assertFalse(result.ok)
        self.assertIn("refusing", result.error)

    def test_the_summary_reads_as_a_sentence(self) -> None:
        result, _process = read([entry(), entry()])
        self.assertIn("2 entries", result.summary())


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------


class TestAvailability(unittest.TestCase):
    def test_both_readable(self) -> None:
        found = journal.availability(runner=lambda _c: (0, "", ""))
        if not found.present:
            self.skipTest("journalctl is not installed here")
        self.assertTrue(found.usable)
        self.assertIn("readable", found.describe())

    def test_neither_readable_is_reported_not_crashed(self) -> None:
        found = journal.availability(runner=lambda _c: (1, "", "denied"))
        if not found.present:
            self.skipTest("journalctl is not installed here")
        self.assertFalse(found.usable)
        self.assertIn("cannot read", found.describe())

    def test_only_the_users_own_entries_is_explained(self) -> None:
        calls = {"n": 0}

        def runner(command):
            calls["n"] += 1
            return (0, "", "") if "--user" in command else (1, "", "")

        found = journal.availability(runner=runner)
        if not found.present:
            self.skipTest("journalctl is not installed here")
        self.assertTrue(found.usable)
        self.assertIn("systemd-journal group", found.describe())

    def test_a_missing_journalctl_is_a_sentence_not_an_exception(self) -> None:
        saved = journal.executable
        try:
            journal.executable = lambda: ""
            found = journal.availability()
        finally:
            journal.executable = saved
        self.assertFalse(found.present)
        self.assertIn("not installed", found.describe())


# ---------------------------------------------------------------------------
# The format
# ---------------------------------------------------------------------------


class TestJournalFormat(unittest.TestCase):
    def parse(self, line: str):
        return get_format("journal").parse(line, CONTEXT)

    def test_a_journal_entry_parses(self) -> None:
        event = self.parse(entry(PRIORITY="3", MESSAGE="it broke"))
        self.assertIs(event.level, Level.ERROR)
        self.assertEqual(event.message, "it broke")
        self.assertEqual(event.extra["unit"], "sshd.service")
        self.assertEqual(event.extra["pid"], "1234")

    def test_the_timestamp_is_microseconds_already(self) -> None:
        event = self.parse(entry(__REALTIME_TIMESTAMP="1790041532996399"))
        self.assertEqual(event.timestamp, 1790041532996399)

    def test_every_syslog_priority_maps_to_a_level(self) -> None:
        for priority, level in (("0", Level.CRITICAL), ("3", Level.ERROR),
                                ("4", Level.WARNING), ("5", Level.NOTICE),
                                ("6", Level.INFO), ("7", Level.DEBUG)):
            with self.subTest(priority=priority):
                self.assertIs(self.parse(entry(PRIORITY=priority)).level, level)

    def test_a_byte_array_message_is_decoded(self) -> None:
        """journald hands the message back as a list of integers whenever it
        is not valid UTF-8 — in practice, whenever it contains colour
        escapes. 26 of 20,000 entries on a real machine."""
        payload = list("hi".encode()) + [27, 91, 50, 109] + list("!".encode())
        event = self.parse(entry(MESSAGE=payload))
        self.assertEqual(event.message, "hi!")
        self.assertEqual(event.raw, "hi\x1b[2m!")

    def test_a_null_message_is_empty_rather_than_the_word_none(self) -> None:
        self.assertEqual(self.parse(entry(MESSAGE=None)).message, "")

    def test_colour_escapes_are_stripped_from_the_message(self) -> None:
        event = self.parse(entry(MESSAGE="\x1b[32m INFO\x1b[0m ready"))
        self.assertEqual(event.message, " INFO ready")
        self.assertIn("\x1b", event.raw)

    def test_a_line_that_is_not_a_journal_entry_is_refused(self) -> None:
        for line in ("not json", "", "{}",
                     json.dumps({"level": "info", "msg": "ordinary jsonl"})):
            with self.subTest(line=line):
                self.assertIsNone(self.parse(line))

    def test_it_wins_over_plain_json_lines_but_only_for_journal_entries(self) -> None:
        from clamguard.core.hunt.formats import detect

        self.assertEqual(detect([entry()] * 5, CONTEXT).format.id, "journal")
        ordinary = [json.dumps({"level": "info", "msg": "x",
                                "time": "2026-01-01T00:00:00Z"})] * 5
        self.assertEqual(detect(ordinary, CONTEXT).format.id, "jsonl")

    def test_the_unit_falls_back_through_the_fields_that_exist(self) -> None:
        self.assertEqual(journal_unit({"_SYSTEMD_UNIT": "a"}), "a")
        self.assertEqual(journal_unit({"_SYSTEMD_USER_UNIT": "b"}), "b")
        self.assertEqual(journal_unit({"SYSLOG_IDENTIFIER": "c"}), "c")
        self.assertEqual(journal_unit({"_COMM": "d"}), "d")
        self.assertEqual(journal_unit({}), "journal")

    def test_helpers_survive_rubbish(self) -> None:
        self.assertEqual(journal_message(None), "")
        self.assertEqual(journal_message(["x"]), "")
        self.assertEqual(strip_ansi("plain"), "plain")


# ---------------------------------------------------------------------------
# Storing
# ---------------------------------------------------------------------------


class TestStoringTheJournal(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-journal-"))
        self.store = Store(self.tmp / "hunt.db")

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ingest(self, lines, cursor="", **kwargs):
        result, _process = read(lines, **kwargs)
        return self.store.ingest_journal(
            result.entries, cursor=result.cursor or cursor,
            stale_cursor=result.stale_cursor, truncated=result.truncated)

    def test_each_unit_becomes_its_own_source(self) -> None:
        """Because the KQL App column reads from the source row, and a
        hundred thousand entries all saying App == "journal" would make
        `summarize count() by App` useless for half the machine."""
        self.ingest([entry(_SYSTEMD_UNIT="sshd.service"),
                     entry(_SYSTEMD_UNIT="cron.service"),
                     entry(_SYSTEMD_UNIT="sshd.service")])
        sources = {source.app: source.events
                   for source in self.store.journal_sources()}
        self.assertEqual(sources, {"sshd.service": 2, "cron.service": 1})

    def test_journal_sources_are_named_so_they_cannot_collide_with_a_path(self) -> None:
        self.ingest([entry()])
        self.assertTrue(self.store.journal_sources()[0].path.startswith("journal:"))
        self.assertEqual(self.store.journal_sources()[0].kind, "journal")
        self.assertEqual(self.store.journal_sources()[0].root, "journal")

    def test_the_cursor_is_remembered_for_next_time(self) -> None:
        self.ingest([entry(__CURSOR=CURSOR_TWO)])
        self.assertEqual(self.store.journal_cursor(), CURSOR_TWO)

    def test_a_second_pass_adds_only_what_is_new(self) -> None:
        self.ingest([entry(), entry(__CURSOR=CURSOR_TWO)])
        before = self.store.count()
        self.ingest([], cursor=CURSOR_TWO)
        self.assertEqual(self.store.count(), before)

    def test_totals_are_reported(self) -> None:
        self.ingest([entry(), entry(_SYSTEMD_UNIT="cron.service")])
        entries, units, last_read = self.store.journal_totals()
        self.assertEqual((entries, units), (2, 2))
        self.assertGreater(last_read, 0)

    def test_a_unit_switched_off_is_dropped_but_the_cursor_still_advances(self) -> None:
        """Otherwise the same entries would be re-read on every pass."""
        self.ingest([entry(_SYSTEMD_UNIT="noisy.service")])
        self.store.set_enabled("journal:noisy.service", False)
        outcome = self.ingest([entry(_SYSTEMD_UNIT="noisy.service",
                                     __CURSOR=CURSOR_TWO)])
        self.assertEqual(outcome.added, 0)
        self.assertEqual(outcome.skipped_units, 1)
        self.assertEqual(self.store.journal_cursor(), CURSOR_TWO)

    def test_forgetting_the_journal_removes_its_events_and_its_position(self) -> None:
        self.ingest([entry(), entry(_SYSTEMD_UNIT="cron.service")])
        self.assertEqual(self.store.forget_journal(), 2)
        self.assertEqual(self.store.journal_sources(), [])
        self.assertEqual(self.store.journal_cursor(), "")
        self.assertEqual(self.store.count(), 0)

    def test_forgetting_a_journal_that_was_never_read_is_not_an_error(self) -> None:
        self.assertEqual(self.store.forget_journal(), 0)

    def test_journal_events_are_queryable_like_any_other(self) -> None:
        from clamguard.core.hunt.kql import run
        from clamguard.core.hunt.kql.engine import Options
        from clamguard.core.hunt.model import TimeRange

        self.ingest([entry(PRIORITY="3", MESSAGE="it broke"),
                     entry(_SYSTEMD_UNIT="cron.service", PRIORITY="6")])
        with self.store.read_only() as connection:
            options = Options(time_range=TimeRange.everything())
            rows = run('Logs | where Location == "journal" and Level == "error" '
                       "| project App, Message", connection, options).rows
        self.assertEqual(rows, [("sshd.service", "it broke")])

    def test_the_source_is_not_expected_to_be_a_file_on_disk(self) -> None:
        self.ingest([entry()])
        self.assertTrue(self.store.journal_sources()[0].exists)


class TestMigration(unittest.TestCase):
    """An index built before the journal existed has to survive the upgrade."""

    def setUp(self) -> None:
        qt_application()
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-migrate-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_a_version_one_database_upgrades_without_losing_anything(self) -> None:
        import sqlite3

        path = self.tmp / "old.db"
        connection = sqlite3.connect(str(path))
        connection.executescript("""
            CREATE TABLE sources (
                id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE,
                app TEXT NOT NULL DEFAULT '', root TEXT NOT NULL DEFAULT '',
                format TEXT NOT NULL DEFAULT 'plain',
                confidence REAL NOT NULL DEFAULT 0,
                size INTEGER NOT NULL DEFAULT 0, mtime REAL NOT NULL DEFAULT 0,
                inode INTEGER NOT NULL DEFAULT 0, device INTEGER NOT NULL DEFAULT 0,
                byte_offset INTEGER NOT NULL DEFAULT 0,
                line_offset INTEGER NOT NULL DEFAULT 0,
                head TEXT NOT NULL DEFAULT '', events INTEGER NOT NULL DEFAULT 0,
                first_ts INTEGER, last_ts INTEGER,
                first_seen REAL NOT NULL DEFAULT 0,
                last_indexed REAL NOT NULL DEFAULT 0,
                compressed INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1, note TEXT NOT NULL DEFAULT '');
            CREATE TABLE events (
                id INTEGER PRIMARY KEY, source INTEGER NOT NULL REFERENCES sources(id)
                ON DELETE CASCADE, ts INTEGER, level INTEGER NOT NULL DEFAULT 0,
                line INTEGER NOT NULL DEFAULT 0, message TEXT NOT NULL DEFAULT '',
                extra TEXT, raw TEXT);
            INSERT INTO sources (path, app, byte_offset, events)
                VALUES ('/logs/a.log', 'alpha', 4096, 2);
            INSERT INTO events (source, ts, level, message)
                VALUES (1, 1, 30, 'one'), (1, 2, 30, 'two');
            PRAGMA user_version = 1;
        """)
        connection.commit()
        connection.close()

        store = Store(path)
        try:
            self.assertEqual(store.count(), 2)
            source = store.sources()[0]
            self.assertEqual(source.kind, "file")
            self.assertEqual(source.byte_offset, 4096,
                             "the incremental position was lost")
            self.assertEqual(
                int(store._writer().execute("PRAGMA user_version").fetchone()[0]),
                2)
            store.ingest_journal([("sshd.service", _event())],
                                 cursor=CURSOR_ONE)
            self.assertEqual(store.count(), 3)
        finally:
            store.close()

    def test_upgrading_twice_is_harmless(self) -> None:
        path = self.tmp / "twice.db"
        Store(path).close()
        store = Store(path)
        try:
            self.assertEqual(store.count(), 0)
        finally:
            store.close()


def _event():
    from clamguard.core.hunt.model import Event

    return Event(timestamp=1790041532996399, level=Level.INFO, message="x")


if __name__ == "__main__":
    unittest.main()
