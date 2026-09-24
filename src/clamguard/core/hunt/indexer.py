"""The thread wrapper: crawling, indexing and querying, off the UI thread.

This is the only module in ``core/hunt`` that knows about Qt, and it knows as
little as possible. Everything below it — discovery, the store, the query
engine — is ordinary Python that a test can call directly with no event loop,
which is what makes the other nine hundred lines testable.

Four jobs, all of them slow enough to freeze a window if they ran on it:

``scan``    walk the filesystem looking for logs
``index``   read what is new out of each file into the store
``query``   run one KQL query
``review``  run the analytics rules

Each reports progress through signals and can be cancelled. Cancelling an
index is safe at any point: every file commits on its own, so stopping loses
nothing that has already been read, and the next index resumes from the byte
offset each source recorded.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from PySide6.QtCore import QObject, Signal

from .. import paths
from ..logging_setup import get_logger
from ..process import run_in_background
from . import discovery, journal, rules as rules_module
from .catalogue import ATTACHED_SCHEMAS
from .kql import KqlError
from .kql.engine import Options, run as run_query
from .model import ResultTable, TimeRange
from .settings import HuntSettings
from .store import Candidate, IndexRun, JournalIngest, Store

log = get_logger(__name__)


@dataclass(slots=True)
class Status:
    """Everything the page's header strip shows about the index."""

    events: int = 0
    sources: int = 0
    enabled: int = 0
    bytes: int = 0
    first: int | None = None
    last: int | None = None
    levels: dict = None
    apps: list = None
    full_text: bool = True
    last_indexed: float = 0.0
    #: Events with no timestamp, which the time-range picker cannot see.
    untimed: int = 0
    #: Journal entries indexed, and how many units they came from.
    journal_events: int = 0
    journal_units: int = 0
    journal_last_read: float = 0.0

    @property
    def empty(self) -> bool:
        return self.events == 0


class HuntIndexer(QObject):
    """Owns the store and runs everything slow in the background."""

    #: A filesystem crawl began.
    scan_started = Signal()
    #: Which directory is being walked right now.
    scan_progress = Signal(str)
    #: A crawl finished. The argument is a discovery.Crawl.
    scan_finished = Signal(object)

    #: An index began. The argument is how many files will be read.
    index_started = Signal(int)
    #: (files done, total, the path being read).
    index_progress = Signal(int, int, str)
    #: An index finished. The argument is a store.IndexRun.
    index_finished = Signal(object)

    #: A journal read began.
    journal_started = Signal()
    #: How many journal entries have been read so far.
    journal_progress = Signal(int)
    #: A journal read finished. The argument is a store.JournalIngest.
    journal_finished = Signal(object)

    #: A query finished. The argument is a model.ResultTable.
    query_finished = Signal(object)
    #: A query could not run. The argument is a kql.KqlError.
    query_failed = Signal(object)

    #: The analytics pass finished. The argument is a rules.Review.
    review_finished = Signal(object)
    #: (rules done, total, title).
    review_progress = Signal(int, int, str)

    #: True while any background work is in flight.
    busy_changed = Signal(bool)
    #: Something went wrong that the user should see.
    failed = Signal(str)

    def __init__(self, settings: HuntSettings | None = None,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.settings = settings or HuntSettings()
        self.store = Store(use_fts=self.settings.use_full_text)
        self._busy = False
        self._cancel = False
        #: The last crawl, so the Sources dialog can reopen without re-walking.
        self.last_crawl: discovery.Crawl | None = None
        #: Complaints about user-written rule files, shown once.
        self.rule_problems: list[str] = []

    # -- state ------------------------------------------------------------

    @property
    def busy(self) -> bool:
        return self._busy

    def cancel(self) -> None:
        """Ask whatever is running to stop at the next safe point."""
        self._cancel = True

    def _set_busy(self, busy: bool) -> None:
        if busy != self._busy:
            self._busy = busy
            self.busy_changed.emit(busy)
        if busy:
            self._cancel = False

    def _should_stop(self) -> bool:
        return self._cancel

    def _emit(self, signal, *args) -> None:
        """Emit from a worker thread, surviving the window closing under us.

        Qt deletes the C++ half of a QObject when its parent goes, and a pool
        thread that is halfway through indexing does not find out. Raising
        there kills the runnable with a traceback on the console instead of
        ending quietly, which is the wrong trade on shutdown.
        """
        try:
            signal.emit(*args)
        except RuntimeError:
            self._cancel = True

    def status(self) -> Status:
        """A snapshot of the index. Cheap enough to call on the UI thread."""
        try:
            data = self.store.statistics()
        except Exception as error:  # noqa: BLE001 - the header must never crash
            log.warning("hunt status unavailable: %s", error)
            return Status(levels={}, apps=[])
        levels = data.get("levels", {})
        entries, units, last_read = self.store.journal_totals()
        return Status(
            journal_events=entries, journal_units=units,
            journal_last_read=last_read,
            events=data["events"], sources=data["sources"],
            enabled=data["enabled"], bytes=data["bytes"], first=data["first"],
            last=data["last"], levels=levels, apps=data["apps"],
            full_text=data["fts"],
            last_indexed=max((source.last_indexed
                              for source in self.store.sources()), default=0.0),
            untimed=int(levels.get("__untimed__", 0)) or _untimed(self.store),
        )

    # -- crawling ---------------------------------------------------------

    def scan(self) -> bool:
        """Walk the configured roots looking for log files."""
        if self._busy:
            return False
        self._set_busy(True)
        self.scan_started.emit()
        settings = self.settings

        def work() -> discovery.Crawl:
            found = discovery.crawl(
                roots=settings.enabled_roots(),
                budget=settings.budget(),
                excluded=tuple(settings.exclusions),
                on_progress=lambda where: self._emit(self.scan_progress, where),
            )
            for extra in settings.extra_files:
                path = Path(extra).expanduser()
                if path.is_file():
                    found.candidates.append(discovery.scan_one(path))
            return found

        run_in_background(work, on_done=self._scan_done, on_error=self._on_error)
        return True

    def _scan_done(self, found: discovery.Crawl) -> None:
        self._set_busy(False)
        self.last_crawl = found
        log.info("hunt scan: %s", found.summary())
        self.scan_finished.emit(found)

    # -- indexing ---------------------------------------------------------

    def index(self, candidates: Sequence[Candidate]) -> bool:
        """Read whatever is new in each candidate into the store."""
        if self._busy:
            return False
        wanted = [item for item in candidates if item.usable]
        if not wanted:
            self.index_finished.emit(IndexRun())
            return False

        self._set_busy(True)
        self.index_started.emit(len(wanted))
        retention = self.settings.retention()
        store = self.store

        def work() -> IndexRun:
            try:
                return store.index(
                    wanted, retention=retention,
                    on_progress=lambda done, total, path:
                        self._emit(self.index_progress, done, total, path),
                    should_stop=self._should_stop)
            finally:
                # The store keeps one connection per thread, and this is a
                # pool thread that will be reused for something else. Closing
                # here rather than leaving it to interpreter exit is what
                # keeps the handle count flat over a long session.
                store.close()

        run_in_background(work, on_done=self._index_done, on_error=self._on_error)
        return True

    def reindex_known(self) -> bool:
        """Re-read the sources already in the store, without crawling again.

        This is the cheap refresh: it costs only the bytes that appeared
        since last time, which on this machine is a tenth of a second for two
        hundred megabytes of logs.
        """
        candidates = [
            Candidate(path=source.path, size=source.size, mtime=source.mtime,
                      root=source.root, app=source.app,
                      compressed=source.compressed)
            for source in self.store.sources(enabled_only=True)
            if source.exists
        ]
        return self.index(candidates)

    def _index_done(self, run: IndexRun) -> None:
        self._set_busy(False)
        log.info("hunt index: %s", run.summary())
        self.index_finished.emit(run)

    def forget(self, path: str) -> int:
        """Drop a source and its events. Fast; runs on the calling thread."""
        return self.store.forget(path)

    def clear(self) -> None:
        self.store.clear()

    # -- the systemd journal ----------------------------------------------

    def journal_availability(self) -> journal.Availability:
        """Whether the journal can be read by this account. Cheap."""
        return journal.availability()

    def index_journal(self, force_full: bool = False) -> bool:
        """Read whatever is new in the systemd journal into the store.

        Resumes from the cursor the last read left behind. When that cursor
        no longer exists — the journal was vacuumed, or the machine was
        reinstalled — journalctl says so and the configured window is read
        again instead of the read looking like "nothing happened" forever.
        """
        if self._busy:
            return False
        settings = self.settings
        if not settings.journal_enabled and not force_full:
            self.failed.emit("Journal indexing is switched off in Hunt settings.")
            return False

        available = journal.availability()
        if not available.usable:
            self.failed.emit(available.describe())
            return False

        self._set_busy(True)
        self.journal_started.emit()
        options = settings.journal_options()
        store = self.store
        cursor = "" if force_full else store.journal_cursor()

        def work() -> JournalIngest:
            try:
                read = journal.read(
                    options, cursor,
                    should_stop=self._should_stop,
                    on_progress=lambda count:
                        self._emit(self.journal_progress, count))
                if not read.ok:
                    return JournalIngest(error=read.error)
                return store.ingest_journal(
                    read.entries, cursor=read.cursor,
                    stale_cursor=read.stale_cursor, truncated=read.truncated,
                    cancelled=read.cancelled)
            finally:
                store.close()

        run_in_background(work, on_done=self._journal_done,
                          on_error=self._on_error)
        return True

    def _journal_done(self, ingest: JournalIngest) -> None:
        self._set_busy(False)
        log.info("hunt journal: %s", ingest.summary())
        self.journal_finished.emit(ingest)

    def forget_journal(self) -> int:
        """Drop every journal source and the saved cursor with it."""
        return self.store.forget_journal()

    # -- querying ---------------------------------------------------------

    def options(self, time_range: TimeRange | None = None) -> Options:
        return Options(
            row_limit=int(self.settings.row_limit),
            timeout=float(self.settings.query_timeout),
            time_range=time_range,
            full_text=self.settings.use_full_text and self.store.use_fts,
            should_stop=self._should_stop,
        )

    def attachments(self) -> dict[str, Path]:
        """The other databases a query may read, all of them read-only."""
        return {name: paths.HISTORY_DB for name in ATTACHED_SCHEMAS}

    def query(self, text: str, time_range: TimeRange | None = None) -> bool:
        """Run one query in the background."""
        if self._busy:
            return False
        self._set_busy(True)
        options = self.options(time_range)
        store = self.store
        attachments = self.attachments()

        def work() -> ResultTable:
            with store.read_only(attach=attachments) as connection:
                return run_query(text, connection, options)

        run_in_background(work, on_done=self._query_done,
                          on_error=lambda message: self._query_error(message, text))
        return True

    def query_now(self, text: str, time_range: TimeRange | None = None
                  ) -> ResultTable:
        """Run a query on the calling thread. For tests and for small lookups."""
        with self.store.read_only(attach=self.attachments()) as connection:
            return run_query(text, connection, self.options(time_range))

    def _query_done(self, table: ResultTable) -> None:
        self._set_busy(False)
        self.query_finished.emit(table)

    def _query_error(self, message: str, text: str) -> None:
        self._set_busy(False)
        self.query_failed.emit(KqlError(message, 0, 1, "", text))

    def check(self, text: str):
        """Parse and name-check a query without running it. Cheap, synchronous."""
        from .kql.engine import check as check_query

        return check_query(text)

    # -- analytics --------------------------------------------------------

    def review(self, time_range: TimeRange | None = None) -> bool:
        """Run every analytics rule and report what fired."""
        if self._busy:
            return False
        catalogue, problems = rules_module.catalogue()
        self.rule_problems = problems
        if problems:
            log.warning("hunt rules with problems: %s", "; ".join(problems))
        if not catalogue:
            self.failed.emit("There are no rules to run.")
            return False

        self._set_busy(True)
        options = self.options(time_range)
        store = self.store
        attachments = self.attachments()

        def work() -> rules_module.Review:
            with store.read_only(attach=attachments) as connection:
                return rules_module.evaluate(
                    catalogue, connection, options=options,
                    on_progress=lambda done, total, title:
                        self._emit(self.review_progress, done, total, title),
                    should_stop=self._should_stop)

        run_in_background(work, on_done=self._review_done, on_error=self._on_error)
        return True

    def _review_done(self, review) -> None:
        self._set_busy(False)
        review.problems = list(self.rule_problems)
        self.review_finished.emit(review)

    # -- housekeeping -----------------------------------------------------

    def _on_error(self, message: str) -> None:
        self._set_busy(False)
        log.error("hunt background task failed: %s", message)
        self.failed.emit(message)

    def stale_by(self) -> float:
        """Seconds since the most recent index, or 0 when nothing is indexed."""
        newest = max((source.last_indexed for source in self.store.sources()),
                     default=0.0)
        return time.time() - newest if newest else 0.0

    def close(self) -> None:
        self.store.close()


def _untimed(store: Store) -> int:
    """How many events carry no timestamp.

    Worth showing prominently: two thirds of the lines on a desktop have no
    time in them, and the time-range picker cannot see any of them, so a user
    who does not know that concludes the index is empty.
    """
    try:
        row = store._writer().execute(
            "SELECT COUNT(*) FROM events WHERE ts IS NULL").fetchone()
        return int(row[0]) if row else 0
    except Exception:  # noqa: BLE001
        return 0
