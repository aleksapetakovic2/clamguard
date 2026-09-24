"""The event store: ingesting once, ingesting again, and staying bounded.

The interesting behaviour is all in the second ingest. A log grows at the end,
so re-reading it has to cost only the new bytes — unless it was rotated, in
which case reading from the old offset would produce garbage and the whole
file has to go back in.
"""

from __future__ import annotations

import gzip
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from .hunt_support import HuntTestCase
from .support import qt_application, recent_day  # noqa: F401  - sets sys.path

from clamguard.core.hunt.discovery import Candidate  # noqa: E402
from clamguard.core.hunt.model import Level  # noqa: E402
from clamguard.core.hunt.store import Retention, Store  # noqa: E402

#: A day inside every retention limit, whatever today is. These fixtures
#: go through index runs, which purge events past 120 days — a literal
#: date here was a test that would start failing in January.
DAY = recent_day()
ELECTRON = DAY + " 10:00:0{n} [info] line {n}\n"


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-store-"))
        self.store = Store(self.tmp / "hunt.db")

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def log(self, name: str = "app.log", lines: int = 5, start: int = 0) -> Candidate:
        path = self.tmp / name
        with path.open("a", encoding="utf-8") as handle:
            for index in range(start, start + lines):
                handle.write(ELECTRON.format(n=index % 10))
        info = path.stat()
        return Candidate(path=str(path), size=info.st_size, mtime=info.st_mtime,
                         root="data", app="app")


class TestIngest(StoreTestCase):
    def test_a_new_file_is_read_whole(self) -> None:
        result = self.store.ingest(self.log(lines=5))
        self.assertEqual(result.action, "new")
        self.assertEqual(result.added, 5)
        self.assertEqual(self.store.count(), 5)

    def test_the_format_is_detected_and_recorded(self) -> None:
        self.store.ingest(self.log())
        source = self.store.sources()[0]
        self.assertEqual(source.format, "electron")
        self.assertGreater(source.confidence, 0.9)

    def test_ingesting_the_same_file_twice_reads_nothing(self) -> None:
        candidate = self.log(lines=5)
        self.store.ingest(candidate)
        second = self.store.ingest(candidate)
        self.assertEqual(second.action, "unchanged")
        self.assertEqual(second.added, 0)
        self.assertEqual(second.bytes_read, 0)

    def test_appending_reads_only_the_new_bytes(self) -> None:
        candidate = self.log(lines=5)
        first = self.store.ingest(candidate)
        candidate = self.log(lines=3, start=5)
        second = self.store.ingest(candidate)
        self.assertEqual(second.action, "appended")
        self.assertEqual(second.added, 3)
        self.assertLess(second.bytes_read, first.bytes_read)
        self.assertEqual(self.store.count(), 8)

    def test_a_half_written_final_line_is_not_consumed(self) -> None:
        """A log being written to right now ends mid-line; eating that half
        would lose the other half forever."""
        path = self.tmp / "app.log"
        path.write_text(f"{DAY} 10:00:01 [info] complete\n"
                        f"{DAY} 10:00:02 [info] half")
        info = path.stat()
        candidate = Candidate(path=str(path), size=info.st_size,
                              mtime=info.st_mtime, app="app")
        self.store.ingest(candidate)
        self.assertEqual(self.store.count(), 1)

        with path.open("a", encoding="utf-8") as handle:
            handle.write(" written\n")
        info = path.stat()
        candidate.size, candidate.mtime = info.st_size, info.st_mtime
        self.store.ingest(candidate)
        messages = [row["message"] for row in
                    self.store._writer().execute("SELECT message FROM events")]
        self.assertIn("half written", messages)

    def test_a_truncated_file_is_read_from_the_start_again(self) -> None:
        candidate = self.log(lines=5)
        self.store.ingest(candidate)
        path = Path(candidate.path)
        path.write_text(f"{DAY} 11:00:00 [info] brand new\n")
        info = path.stat()
        candidate.size, candidate.mtime = info.st_size, info.st_mtime
        result = self.store.ingest(candidate)
        self.assertEqual(result.action, "rotated")
        self.assertEqual(self.store.count(), 1)

    def test_a_file_rotated_in_place_is_noticed_by_its_head_hash(self) -> None:
        """Same inode, same size, different contents — only the hash sees it."""
        candidate = self.log(lines=5)
        self.store.ingest(candidate)
        path = Path(candidate.path)
        size = path.stat().st_size
        path.write_text(f"{DAY} 11:00:00 [info] x" + " " * (size - 40) + "\n")
        info = path.stat()
        candidate.size, candidate.mtime = info.st_size, info.st_mtime
        result = self.store.ingest(candidate)
        self.assertEqual(result.action, "rotated")

    def test_a_missing_file_fails_without_raising(self) -> None:
        result = self.store.ingest(Candidate(path=str(self.tmp / "nothing.log")))
        self.assertFalse(result.ok)
        self.assertEqual(result.action, "failed")

    def test_a_gzipped_log_is_read(self) -> None:
        path = self.tmp / "old.log.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(f"{DAY} 10:00:00 [warn] compressed\n")
        info = path.stat()
        candidate = Candidate(path=str(path), size=info.st_size,
                              mtime=info.st_mtime, app="app", compressed=True)
        self.assertEqual(self.store.ingest(candidate).added, 1)
        row = self.store._writer().execute(
            "SELECT level, message FROM events").fetchone()
        self.assertEqual(row["message"], "compressed")
        self.assertEqual(Level.from_value(row["level"]), Level.WARNING)

    def test_an_unchanged_gzip_is_not_read_twice(self) -> None:
        path = self.tmp / "old.log.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            handle.write(f"{DAY} 10:00:00 [warn] compressed\n")
        info = path.stat()
        candidate = Candidate(path=str(path), size=info.st_size,
                              mtime=info.st_mtime, app="app", compressed=True)
        self.store.ingest(candidate)
        self.assertEqual(self.store.ingest(candidate).action, "unchanged")

    def test_the_time_span_of_a_source_is_recorded(self) -> None:
        self.store.ingest(self.log(lines=5))
        source = self.store.sources()[0]
        self.assertIsNotNone(source.first_ts)
        self.assertIsNotNone(source.last_ts)
        self.assertLessEqual(source.first_ts, source.last_ts)

    def test_invalid_utf8_does_not_stop_a_file(self) -> None:
        path = self.tmp / "mixed.log"
        path.write_bytes(DAY.encode() + b" 10:00:00 [info] ok\n"
                         + DAY.encode() + b" 10:00:01 [info] \xff\xfe bad bytes\n")
        info = path.stat()
        result = self.store.ingest(Candidate(path=str(path), size=info.st_size,
                                             mtime=info.st_mtime, app="app"))
        self.assertEqual(result.added, 2)


class TestIndexRuns(StoreTestCase):
    def test_a_run_summarises_itself(self) -> None:
        run = self.store.index([self.log("a.log"), self.log("b.log")])
        self.assertEqual(run.added, 10)
        self.assertIn("new events", run.summary())

    def test_progress_is_reported_per_file(self) -> None:
        seen = []
        self.store.index([self.log("a.log"), self.log("b.log")],
                         on_progress=lambda done, total, path: seen.append(done))
        self.assertEqual(seen, [1, 2])

    def test_a_run_can_be_stopped_and_keeps_what_it_read(self) -> None:
        stop = {"now": False}

        def should_stop() -> bool:
            if stop["now"]:
                return True
            stop["now"] = True
            return False

        run = self.store.index([self.log("a.log"), self.log("b.log")],
                               should_stop=should_stop)
        self.assertTrue(run.cancelled)
        self.assertEqual(self.store.count(), 5)

    def test_one_broken_file_does_not_stop_the_others(self) -> None:
        run = self.store.index([Candidate(path=str(self.tmp / "nothing.log")),
                                self.log("b.log")])
        self.assertEqual(len(run.failures), 1)
        self.assertEqual(run.added, 5)


class TestRetention(StoreTestCase):
    def fill(self, count: int = 50) -> None:
        self.store.index([self.log(lines=count)], retention=Retention(0, 0, 0))

    def test_no_limits_keeps_everything(self) -> None:
        self.fill(30)
        self.assertEqual(self.store.apply_retention(Retention(0, 0, 0)), 0)
        self.assertEqual(self.store.count(), 30)

    def test_an_event_limit_removes_the_oldest_indexed(self) -> None:
        self.fill(30)
        removed = self.store.apply_retention(Retention(max_events=10,
                                                       max_age_days=0,
                                                       max_megabytes=0))
        self.assertEqual(removed, 20)
        self.assertEqual(self.store.count(), 10)

    def test_an_age_limit_removes_only_events_that_have_a_time(self) -> None:
        """Two thirds of desktop log lines carry no timestamp. Guessing an age
        for those and deleting them on the guess would be worse than keeping
        them."""
        self.fill(10)
        connection = self.store._writer()
        connection.execute("UPDATE events SET ts = NULL WHERE id <= 5")
        # Age the timed half explicitly. This used to lean on the fixture's
        # literal date being old enough, which made the test's verdict depend
        # on the day it was run.
        ten_days_us = 10 * 86_400 * 1_000_000
        connection.execute("UPDATE events SET ts = ts - ? WHERE ts IS NOT NULL",
                           (ten_days_us,))
        connection.commit()
        self.store.apply_retention(Retention(max_events=0, max_age_days=1,
                                             max_megabytes=0))
        remaining = connection.execute(
            "SELECT COUNT(*), COUNT(ts) FROM events").fetchone()
        self.assertEqual(remaining[0], 5, "the untimed events were removed")
        self.assertEqual(remaining[1], 0, "a timed event survived its age limit")

    def test_the_per_source_count_is_corrected_after_a_purge(self) -> None:
        self.fill(30)
        self.store.apply_retention(Retention(max_events=10, max_age_days=0,
                                             max_megabytes=0))
        self.assertEqual(self.store.sources()[0].events, 10)

    def test_the_limits_describe_themselves(self) -> None:
        self.assertIn("days", Retention().describe())
        self.assertEqual(Retention(0, 0, 0).describe(), "no limits")


class TestForgetting(StoreTestCase):
    def test_forgetting_a_source_removes_its_events(self) -> None:
        candidate = self.log()
        self.store.ingest(candidate)
        self.assertEqual(self.store.forget(candidate.path), 5)
        self.assertEqual(self.store.count(), 0)
        self.assertEqual(self.store.sources(), [])

    def test_forgetting_something_unknown_is_not_an_error(self) -> None:
        self.assertEqual(self.store.forget("/nowhere"), 0)

    def test_clearing_empties_everything(self) -> None:
        self.store.ingest(self.log())
        self.store.clear()
        self.assertEqual(self.store.count(), 0)
        self.assertEqual(self.store.sources(), [])

    def test_a_source_can_be_switched_off_without_losing_its_events(self) -> None:
        candidate = self.log()
        self.store.ingest(candidate)
        self.store.set_enabled(candidate.path, False)
        self.assertEqual(len(self.store.sources(enabled_only=True)), 0)
        self.assertEqual(self.store.count(), 5)


class TestReadOnlyConnections(StoreTestCase):
    def test_a_query_connection_physically_cannot_write(self) -> None:
        """Enforced by SQLite's VFS, not by the compiler being correct."""
        self.store.ingest(self.log())
        with self.store.read_only() as connection:
            for statement in ("DELETE FROM events",
                              "INSERT INTO events (source) VALUES (1)",
                              "UPDATE sources SET path = 'x'",
                              "DROP TABLE events",
                              "CREATE TABLE evil (x)"):
                with self.subTest(sql=statement):
                    with self.assertRaises(sqlite3.DatabaseError):
                        connection.execute(statement)
        self.assertEqual(self.store.count(), 5)

    def test_a_query_connection_can_still_read(self) -> None:
        self.store.ingest(self.log())
        with self.store.read_only() as connection:
            total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(total, 5)

    def test_attaching_a_database_that_is_not_there_is_not_fatal(self) -> None:
        with self.store.read_only(attach={"history": Path("/nowhere.db")}) as conn:
            self.assertTrue(conn.execute("SELECT 1").fetchone())


class TestThreading(StoreTestCase):
    def test_the_writer_works_from_another_thread(self) -> None:
        """The store is built on the UI thread and written from a worker, and
        a SQLite connection belongs to the thread that made it."""
        errors: list[Exception] = []

        def work() -> None:
            try:
                self.store.ingest(self.log("threaded.log"))
            except Exception as error:  # noqa: BLE001 - that is the point
                errors.append(error)
            finally:
                # A thread that used the store closes its own connection,
                # which is what the indexer does at the end of a job.
                self.store.close()

        thread = threading.Thread(target=work)
        thread.start()
        thread.join(30)
        self.assertEqual(errors, [])
        self.assertEqual(self.store.count(), 5)


class TestStatistics(StoreTestCase):
    def test_it_reports_what_is_in_there(self) -> None:
        self.store.ingest(self.log())
        stats = self.store.statistics()
        self.assertEqual(stats["events"], 5)
        self.assertEqual(stats["sources"], 1)
        self.assertGreater(stats["bytes"], 0)
        self.assertIn("info", stats["levels"])
        self.assertEqual(stats["apps"][0][0], "app")

    def test_an_empty_store_reports_zeroes_rather_than_failing(self) -> None:
        stats = self.store.statistics()
        self.assertEqual(stats["events"], 0)
        self.assertEqual(stats["apps"], [])

    def test_the_span_of_the_store_is_available(self) -> None:
        self.store.ingest(self.log())
        first, last = self.store.span()
        self.assertIsNotNone(first)
        self.assertLessEqual(first, last)


class TestFullText(StoreTestCase):
    def test_the_index_is_kept_in_step_when_events_are_deleted(self) -> None:
        """An external-content FTS table has to be told before the rows go, or
        it keeps answering for text that is no longer there."""
        candidate = self.log(lines=20)
        self.store.ingest(candidate)
        self.store.apply_retention(Retention(max_events=5, max_age_days=0,
                                             max_megabytes=0))
        connection = self.store._writer()
        matches = connection.execute(
            "SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'line'"
        ).fetchone()[0]
        self.assertLessEqual(matches, 5)

    def test_it_can_be_turned_off(self) -> None:
        store = Store(self.tmp / "nofts.db", use_fts=False)
        try:
            store.ingest(self.log("b.log"))
            self.assertEqual(store.count(), 5)
        finally:
            store.close()


class TestFilePermissions(StoreTestCase):
    def test_the_database_is_private(self) -> None:
        """It holds every log line on the machine, some of which are tokens."""
        mode = os.stat(self.store.path).st_mode & 0o777
        if mode == 0:
            self.skipTest("this filesystem does not enforce modes")
        self.assertEqual(mode & 0o077, 0, f"hunt.db is mode {mode:o}")


class TestSampleData(HuntTestCase):
    """The shared fixture the query tests use has to be right."""

    def test_the_fixture_loaded(self) -> None:
        self.assertEqual(self.store.count(), 9)

    def test_it_contains_an_event_with_no_timestamp(self) -> None:
        untimed = self.store._writer().execute(
            "SELECT COUNT(*) FROM events WHERE ts IS NULL").fetchone()[0]
        self.assertEqual(untimed, 2)


if __name__ == "__main__":
    unittest.main()
