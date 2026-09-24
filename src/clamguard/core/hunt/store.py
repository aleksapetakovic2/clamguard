"""The event store: SQLite, written once, read many times, kept bounded.

Everything Hunt knows lives in one database under
``~/.local/share/clamguard/hunt.db``. Three properties drive its design.

**Re-indexing must be cheap.** Logs grow at the end. Each source remembers the
byte offset it was read up to and the SHA-256 of its first four kilobytes; a
second index reads only the bytes that appeared since, and a file whose head
hash or inode changed is recognised as rotated and re-read from the start.
Indexing 200 MB of logs twice costs 200 MB the first time and almost nothing
the second.

**Queries must never be able to write.** :meth:`Store.reader` hands out a
connection opened ``mode=ro`` with ``PRAGMA query_only``. The KQL engine is
given nothing else, so a bug in the compiler cannot modify the store — the
guarantee is enforced by SQLite rather than by the compiler being correct.

**It must not grow forever.** Retention runs after every index: an age limit,
an event-count limit and a size limit, each of which can be turned off. What
is removed is the least recently *indexed* event, which is predictable in a
way that "oldest timestamp" is not when half the formats on a desktop carry no
timestamp at all.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from .. import paths
from ..logging_setup import get_logger
from . import formats
from .discovery import Candidate
from .model import Level, now_us

log = get_logger(__name__)

SCHEMA_VERSION = 2

#: How many events go into one INSERT. Large enough that the per-statement
#: overhead disappears, small enough that a 4 GB log does not become a 4 GB
#: Python list.
BATCH = 4000

#: Bytes read per loop when tailing a file.
CHUNK = 1 << 20

#: How much of a file's head is hashed to notice a rotation in place.
HEAD_BYTES = 4096

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id           INTEGER PRIMARY KEY,
    -- For a file this is its path. For the systemd journal it is
    -- "journal:<unit>", one row per unit, which is what lets the App column
    -- name sshd.service rather than saying "journal" a hundred thousand times.
    path         TEXT    NOT NULL UNIQUE,
    kind         TEXT    NOT NULL DEFAULT 'file',
    app          TEXT    NOT NULL DEFAULT '',
    root         TEXT    NOT NULL DEFAULT '',
    format       TEXT    NOT NULL DEFAULT 'plain',
    confidence   REAL    NOT NULL DEFAULT 0,
    size         INTEGER NOT NULL DEFAULT 0,
    mtime        REAL    NOT NULL DEFAULT 0,
    inode        INTEGER NOT NULL DEFAULT 0,
    device       INTEGER NOT NULL DEFAULT 0,
    byte_offset  INTEGER NOT NULL DEFAULT 0,
    line_offset  INTEGER NOT NULL DEFAULT 0,
    head         TEXT    NOT NULL DEFAULT '',
    events       INTEGER NOT NULL DEFAULT 0,
    first_ts     INTEGER,
    last_ts      INTEGER,
    first_seen   REAL    NOT NULL DEFAULT 0,
    last_indexed REAL    NOT NULL DEFAULT 0,
    compressed   INTEGER NOT NULL DEFAULT 0,
    enabled      INTEGER NOT NULL DEFAULT 1,
    note         TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY,
    source   INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    ts       INTEGER,
    level    INTEGER NOT NULL DEFAULT 0,
    line     INTEGER NOT NULL DEFAULT 0,
    message  TEXT    NOT NULL DEFAULT '',
    extra    TEXT,
    raw      TEXT
);

-- Partial, because two thirds of the events on a real desktop have no
-- timestamp at all (Unity, Steam and every other unstructured log), and
-- indexing their NULLs costs 11 MB per million events to answer a question
-- nobody asks. Measured on this machine: 13.8 MB full, 2.9 MB partial, and
-- SQLite prefers the partial one for every range query.
-- Where the journal was read up to. One row, because a cursor is a position
-- in the journal as a whole while the source rows are per unit.
CREATE TABLE IF NOT EXISTS journal_state (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    cursor     TEXT    NOT NULL DEFAULT '',
    last_read  REAL    NOT NULL DEFAULT 0,
    entries    INTEGER NOT NULL DEFAULT 0,
    note       TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS events_ts     ON events(ts) WHERE ts IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_source ON events(source);
-- Deliberately not partial: SQLite does not infer that `level = 50` implies
-- `level > 0`, so a partial index here would simply never be used.
CREATE INDEX IF NOT EXISTS events_level  ON events(level, ts);
"""

#: An external-content FTS index over the message column. External content
#: means the text is stored once, in `events`, not twice — at the price of
#: having to tell the index explicitly when a row goes away, which
#: `_forget_events` does before the rows are deleted.
_FTS_SCHEMA = """
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    message,
    content='events',
    content_rowid='id',
    columnsize=0,
    tokenize="unicode61 remove_diacritics 2"
);
"""


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Source:
    """One indexed source — a file, or one unit of the systemd journal."""

    id: int
    path: str
    #: "file" or "journal".
    kind: str = "file"
    app: str = ""
    root: str = ""
    format: str = "plain"
    confidence: float = 0.0
    size: int = 0
    mtime: float = 0.0
    inode: int = 0
    device: int = 0
    byte_offset: int = 0
    line_offset: int = 0
    head: str = ""
    events: int = 0
    first_ts: int | None = None
    last_ts: int | None = None
    first_seen: float = 0.0
    last_indexed: float = 0.0
    compressed: bool = False
    enabled: bool = True
    note: str = ""

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def is_journal(self) -> bool:
        return self.kind == "journal"

    def display_path(self, home: str = "") -> str:
        if self.is_journal:
            return self.path
        base = home or os.path.expanduser("~")
        if base and self.path.startswith(base + os.sep):
            return "~" + self.path[len(base):]
        return self.path

    @property
    def exists(self) -> bool:
        """Whether the thing behind this source is still there.

        A journal source has no file; it exists as long as journald does, and
        the reader decides that, so this says True rather than pretending to
        stat something.
        """
        return True if self.is_journal else os.path.isfile(self.path)

    @property
    def fully_indexed(self) -> bool:
        return self.byte_offset >= self.size


@dataclass(slots=True)
class IngestResult:
    """What one file cost and produced."""

    path: str
    added: int = 0
    bytes_read: int = 0
    elapsed: float = 0.0
    #: "new", "appended", "rotated", "unchanged", "skipped", "failed"
    action: str = "unchanged"
    format: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass(slots=True)
class IndexRun:
    """The result of indexing a whole set of sources."""

    results: list[IngestResult] = field(default_factory=list)
    elapsed: float = 0.0
    purged: int = 0
    cancelled: bool = False

    @property
    def added(self) -> int:
        return sum(item.added for item in self.results)

    @property
    def bytes_read(self) -> int:
        return sum(item.bytes_read for item in self.results)

    @property
    def failures(self) -> list[IngestResult]:
        return [item for item in self.results if item.error]

    @property
    def changed(self) -> list[IngestResult]:
        return [item for item in self.results if item.added]

    def summary(self) -> str:
        if not self.results:
            return "Nothing to index."
        parts = [f"{self.added:,} new events from {len(self.changed)} files"]
        if self.bytes_read:
            parts.append(f"{self.bytes_read / 1e6:.1f} MB read")
        parts.append(f"{self.elapsed:.1f}s")
        if self.purged:
            parts.append(f"{self.purged:,} removed by retention")
        if self.failures:
            parts.append(f"{len(self.failures)} failed")
        return " · ".join(parts)


@dataclass(slots=True)
class JournalIngest:
    """What one pass over the systemd journal added."""

    added: int = 0
    units: int = 0
    cursor: str = ""
    elapsed: float = 0.0
    truncated: bool = False
    stale_cursor: bool = False
    cancelled: bool = False
    skipped_units: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def summary(self) -> str:
        if self.error:
            return f"The journal could not be read: {self.error}"
        if not self.added:
            return "The journal is already up to date."
        parts = [f"{self.added:,} journal entries from {self.units} units",
                 f"{self.elapsed:.1f}s"]
        if self.stale_cursor:
            parts.append("the saved position had expired, so the window was "
                         "read again")
        if self.truncated:
            parts.append("more is waiting for the next index")
        if self.cancelled:
            parts.append("stopped early")
        return " · ".join(parts)


@dataclass(slots=True)
class Retention:
    """The limits that keep the store from growing without bound.

    Zero means "no limit" for each of them, which is a supported choice: a
    machine with a small log footprint may as well keep everything.
    """

    max_events: int = 5_000_000
    max_age_days: int = 120
    max_megabytes: int = 2048

    def describe(self) -> str:
        parts = []
        if self.max_events:
            parts.append(f"{self.max_events:,} events")
        if self.max_age_days:
            parts.append(f"{self.max_age_days} days")
        if self.max_megabytes:
            parts.append(f"{self.max_megabytes} MB")
        return ", ".join(parts) if parts else "no limits"


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------


class Store:
    """Owns the database file. One writer, as many readers as you like."""

    def __init__(self, path: Path | None = None, *, use_fts: bool = True) -> None:
        self.path = path or (paths.DATA_DIR / "hunt.db")
        self.use_fts = use_fts
        # One write connection *per thread*. A SQLite connection belongs to
        # the thread that made it, and this store is built on the UI thread
        # but written from a worker, so a single shared handle is a
        # ProgrammingError waiting to happen. WAL is what makes the split
        # safe: a reader on the UI thread and the writer on the worker do
        # not block each other, and two writers queue on the busy timeout
        # rather than failing.
        self._local = threading.local()
        self._fts_ready = False
        self._initialise()

    # -- connections ------------------------------------------------------

    def _initialise(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not self.path.exists()
        connection = self._writer()
        if fresh:
            # Must be set before anything is stored, or SQLite ignores it and
            # the file never gives space back after a retention purge.
            connection.execute("PRAGMA auto_vacuum = INCREMENTAL")
        connection.executescript(_SCHEMA)
        if self.use_fts:
            try:
                connection.executescript(_FTS_SCHEMA)
                self._fts_ready = True
            except sqlite3.OperationalError as error:
                # FTS5 is optional in a SQLite build. Losing it costs speed on
                # `search`, not correctness — the engine falls back to LIKE.
                log.warning("hunt: full-text index unavailable (%s)", error)
                self.use_fts = False
        self._migrate(connection)
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        connection.commit()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def _migrate(self, connection: sqlite3.Connection) -> None:
        """Bring an older database up to date. Additive changes only.

        Version 1 had no `kind` column and no journal state, because the only
        thing Hunt could index was a file. Both additions are `ALTER TABLE`
        and `CREATE TABLE IF NOT EXISTS`, so an existing index survives with
        its events and its byte offsets intact — nothing is re-read.
        """
        try:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        except (sqlite3.DatabaseError, TypeError, ValueError):
            version = 0
        if version >= SCHEMA_VERSION:
            return

        columns = {row[1] for row in connection.execute("PRAGMA table_info(sources)")}
        if "kind" not in columns:
            log.info("hunt: upgrading the store from version %d to %d",
                     version, SCHEMA_VERSION)
            connection.execute(
                "ALTER TABLE sources ADD COLUMN kind TEXT NOT NULL DEFAULT 'file'")
        connection.commit()

    def _writer(self) -> sqlite3.Connection:
        """This thread's write connection, opened the first time it asks."""
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(str(self.path), timeout=30.0,
                                         isolation_level=None)
            connection.row_factory = sqlite3.Row
            for pragma in (
                "PRAGMA journal_mode = WAL",
                "PRAGMA synchronous = NORMAL",
                "PRAGMA temp_store = MEMORY",
                "PRAGMA cache_size = -32000",
                "PRAGMA mmap_size = 268435456",
                "PRAGMA foreign_keys = ON",
                "PRAGMA busy_timeout = 30000",
            ):
                try:
                    connection.execute(pragma)
                except sqlite3.DatabaseError:
                    log.debug("hunt: %s not supported", pragma)
            self._local.connection = connection
        return connection

    def reader(self) -> sqlite3.Connection:
        """A connection that physically cannot write.

        ``mode=ro`` is enforced by the VFS: an INSERT on this handle raises
        ``sqlite3.OperationalError: attempt to write a readonly database``
        before it reaches the file. ``query_only`` is belt and braces, and it
        also rejects statements SQLite would otherwise allow on a read-only
        handle, such as PRAGMA writes to temp storage.
        """
        connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True,
                                     timeout=15.0, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        for pragma in ("PRAGMA temp_store = MEMORY",
                       "PRAGMA cache_size = -16000",
                       "PRAGMA mmap_size = 268435456"):
            try:
                connection.execute(pragma)
            except sqlite3.DatabaseError:
                pass
        return connection

    @contextmanager
    def read_only(self, attach: dict[str, Path] | None = None
                  ) -> Iterator[sqlite3.Connection]:
        """A read-only connection, with other databases attached read-only.

        Used to expose ClamGuard's own scan history to KQL alongside the logs
        without ever giving the query engine a writable handle to either.
        """
        connection = self.reader()
        try:
            for name, target in (attach or {}).items():
                if not Path(target).is_file():
                    continue
                try:
                    connection.execute(
                        "ATTACH DATABASE ? AS " + _safe_identifier(name),
                        (f"file:{target}?mode=ro",))
                except sqlite3.DatabaseError as error:
                    log.debug("hunt: could not attach %s (%s)", target, error)
            try:
                connection.execute("PRAGMA query_only = ON")
            except sqlite3.DatabaseError:
                pass
            yield connection
        finally:
            connection.close()

    def close(self) -> None:
        """Close this thread's connection. Others go with their thread."""
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            try:
                connection.execute("PRAGMA optimize")
            except sqlite3.DatabaseError:
                pass
            connection.close()
            self._local.connection = None

    # -- sources ----------------------------------------------------------

    def sources(self, *, enabled_only: bool = False) -> list[Source]:
        sql = "SELECT * FROM sources"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY app COLLATE NOCASE, path"
        return [_to_source(row) for row in self._writer().execute(sql)]

    def source(self, path: str) -> Source | None:
        row = self._writer().execute(
            "SELECT * FROM sources WHERE path = ?", (str(path),)).fetchone()
        return _to_source(row) if row else None

    def set_enabled(self, path: str, enabled: bool) -> None:
        connection = self._writer()
        connection.execute("UPDATE sources SET enabled = ? WHERE path = ?",
                           (1 if enabled else 0, str(path)))
        connection.commit()

    def forget(self, path: str) -> int:
        """Remove a source and everything indexed from it."""
        connection = self._writer()
        row = connection.execute("SELECT id, events FROM sources WHERE path = ?",
                                 (str(path),)).fetchone()
        if row is None:
            return 0
        self._forget_events(connection, "source = ?", (row["id"],))
        connection.execute("DELETE FROM sources WHERE id = ?", (row["id"],))
        connection.commit()
        return int(row["events"])

    def clear(self) -> None:
        """Empty the store completely, keeping the file and its schema."""
        connection = self._writer()
        connection.execute("DELETE FROM events")
        if self._fts_ready:
            try:
                connection.execute(
                    "INSERT INTO events_fts(events_fts) VALUES('rebuild')")
            except sqlite3.DatabaseError:
                pass
        connection.execute("DELETE FROM sources")
        connection.commit()
        self.compact()

    # -- indexing ---------------------------------------------------------

    def index(self, candidates: Sequence[Candidate], *,
              retention: Retention | None = None,
              on_progress=None, should_stop=None) -> IndexRun:
        """Index every candidate, skipping the ones that have not changed.

        `on_progress(done, total, path)` is called on the calling thread —
        which is a worker thread, so a UI caller must bounce it through a
        signal. `should_stop()` is polled between files so a long index can be
        cancelled without leaving the store half-written: each file commits on
        its own, so stopping loses nothing already done.
        """
        run = IndexRun()
        started = time.monotonic()
        total = len(candidates)
        for index, candidate in enumerate(candidates, start=1):
            if should_stop is not None and should_stop():
                run.cancelled = True
                break
            result = self.ingest(candidate)
            run.results.append(result)
            if on_progress is not None:
                on_progress(index, total, candidate.path)
        run.purged = self.apply_retention(retention or Retention())
        run.elapsed = time.monotonic() - started
        log.info("hunt index: %s", run.summary())
        return run

    def ingest(self, candidate: Candidate) -> IngestResult:
        """Read whatever is new in one file into the store."""
        result = IngestResult(path=candidate.path)
        started = time.monotonic()
        path = Path(candidate.path)
        try:
            info = path.stat()
        except OSError as error:
            result.error = error.strerror or str(error)
            result.action = "failed"
            return result

        existing = self.source(candidate.path)
        rotated = False
        offset = 0
        line_offset = 0
        head = self._fingerprint(path, candidate,
                                 existing.byte_offset if existing else 0)

        if existing is not None and existing.byte_offset > 0:
            unchanged_identity = (existing.inode == info.st_ino
                                  and existing.device == info.st_dev
                                  and existing.head == head)
            if not unchanged_identity or info.st_size < existing.byte_offset:
                rotated = True
            else:
                offset = existing.byte_offset
                line_offset = existing.line_offset
                if offset >= info.st_size and existing.events:
                    result.action = "unchanged"
                    result.format = existing.format
                    self._touch(existing.id, info)
                    return result

        if candidate.compressed:
            # There is no useful byte offset into a gzip stream, so a
            # compressed log is all-or-nothing: unchanged if its head hash and
            # size match, re-read from the top otherwise.
            if existing is not None and existing.head == head and existing.size == info.st_size:
                result.action = "unchanged"
                result.format = existing.format
                return result
            rotated = existing is not None
            offset = line_offset = 0

        connection = self._writer()
        try:
            detection = self._detect(path, candidate, offset if not rotated else 0)
        except OSError as error:
            result.error = error.strerror or str(error)
            result.action = "failed"
            return result
        result.format = detection.format.id

        source_id = self._upsert_source(connection, candidate, info, head,
                                        detection, existing)
        if rotated or existing is None:
            if rotated:
                self._forget_events(connection, "source = ?", (source_id,))
                connection.execute(
                    "UPDATE sources SET events = 0, byte_offset = 0, "
                    "line_offset = 0, first_ts = NULL, last_ts = NULL WHERE id = ?",
                    (source_id,))
            offset = line_offset = 0

        try:
            added, consumed, lines, span = self._read_into(
                connection, source_id, path, candidate, detection,
                offset, line_offset)
        except OSError as error:
            result.error = error.strerror or str(error)
            result.action = "failed"
            return result

        head = self._fingerprint(path, candidate, consumed)
        connection.execute(
            "UPDATE sources SET byte_offset = ?, line_offset = ?, size = ?, "
            "mtime = ?, inode = ?, device = ?, head = ?, events = events + ?, "
            "last_indexed = ?, "
            "first_ts = CASE WHEN first_ts IS NULL THEN ? "
            "                ELSE MIN(first_ts, COALESCE(?, first_ts)) END, "
            "last_ts  = CASE WHEN last_ts IS NULL THEN ? "
            "                ELSE MAX(last_ts, COALESCE(?, last_ts)) END "
            "WHERE id = ?",
            (consumed, lines, info.st_size, info.st_mtime, info.st_ino,
             info.st_dev, head, added, time.time(),
             span[0], span[0], span[1], span[1], source_id))
        connection.commit()

        result.added = added
        result.bytes_read = max(0, consumed - offset)
        result.action = ("rotated" if rotated else
                         "new" if existing is None else
                         "appended" if added else "unchanged")
        result.elapsed = time.monotonic() - started
        return result

    def _fingerprint(self, path: Path, candidate: Candidate,
                     consumed: int) -> str:
        """A hash of the part of the file we have already read.

        It has to cover a *fixed* prefix, not "the first four kilobytes of
        whatever is there now" — a 200-byte log that grows to 300 bytes would
        otherwise hash differently and be read as a rotation, losing its whole
        history on every append. So the window is the smaller of the head size
        and the bytes already consumed, which by definition cannot change.

        A gzip is exempt: it never grows in place, and its consumed offset
        counts decompressed bytes, which says nothing about the file on disk.
        """
        if candidate.compressed:
            return _head_hash(path, HEAD_BYTES)
        return _head_hash(path, HEAD_BYTES if consumed <= 0
                          else min(HEAD_BYTES, consumed))

    def _detect(self, path: Path, candidate: Candidate,
                offset: int) -> formats.Detection:
        """Sample the file and decide what wrote it.

        Sampling starts at the point we last read to, not at the top, so a
        file that changed format mid-life (an application updated) is judged
        on its current contents.
        """
        context = formats.context_for(str(path), candidate.mtime)
        sample: list[str] = []
        with _open_text(path, candidate.compressed) as handle:
            if offset and not candidate.compressed:
                try:
                    handle.seek(max(0, offset))
                    handle.readline()      # discard a possibly partial line
                except OSError:
                    handle.seek(0)
            for _ in range(formats.SAMPLE_LINES * 3):
                line = handle.readline()
                if not line:
                    break
                sample.append(line.decode("utf-8", "replace"))
        detection = formats.detect(sample, context)
        if not sample and offset:
            # Nothing new to sample: keep whatever we decided last time.
            existing = self.source(str(path))
            if existing is not None:
                return formats.Detection(formats.get(existing.format),
                                         existing.confidence)
        return detection

    def _upsert_source(self, connection, candidate: Candidate, info: os.stat_result,
                       head: str, detection: formats.Detection,
                       existing: Source | None) -> int:
        if existing is not None:
            connection.execute(
                "UPDATE sources SET app = ?, root = ?, format = ?, "
                "confidence = ?, compressed = ? WHERE id = ?",
                (candidate.app, candidate.root, detection.format.id,
                 detection.confidence, int(candidate.compressed), existing.id))
            return existing.id
        cursor = connection.execute(
            "INSERT INTO sources (path, app, root, format, confidence, size, "
            "mtime, inode, device, head, first_seen, last_indexed, compressed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (candidate.path, candidate.app, candidate.root, detection.format.id,
             detection.confidence, info.st_size, info.st_mtime, info.st_ino,
             info.st_dev, head, time.time(), time.time(),
             int(candidate.compressed)))
        return int(cursor.lastrowid)

    def _read_into(self, connection, source_id: int, path: Path,
                   candidate: Candidate, detection: formats.Detection,
                   offset: int, line_offset: int
                   ) -> tuple[int, int, int, tuple[int | None, int | None]]:
        """Parse from `offset` to the end, inserting in batches.

        Returns (events added, byte offset reached, lines consumed, time span).
        The byte offset deliberately stops at the last complete line: a log
        being written to right now ends mid-line, and consuming that half line
        would lose its other half forever.
        """
        context = formats.context_for(str(path), candidate.mtime,
                                      detection.header)
        item = detection.format
        added = 0
        consumed = offset
        number = line_offset
        earliest: int | None = None
        latest: int | None = None
        batch: list[tuple] = []

        insert = ("INSERT INTO events (source, ts, level, line, message, extra, raw) "
                  "VALUES (?, ?, ?, ?, ?, ?, ?)")

        def flush() -> None:
            nonlocal batch
            if not batch:
                return
            first = connection.execute(
                "SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            connection.executemany(insert, batch)
            if self._fts_ready:
                connection.execute(
                    "INSERT INTO events_fts(rowid, message) "
                    "SELECT id, message FROM events WHERE id > ?", (first,))
            batch = []

        connection.execute("BEGIN")
        try:
            for event, byte_position, line_number in _stream(
                    path, candidate.compressed, offset, item, context, number):
                consumed = byte_position
                number = line_number
                if event.timestamp is not None:
                    if earliest is None or event.timestamp < earliest:
                        earliest = event.timestamp
                    if latest is None or event.timestamp > latest:
                        latest = event.timestamp
                batch.append((
                    source_id, event.timestamp, int(event.level),
                    event.line_number, event.message,
                    json.dumps(event.extra, default=str) if event.extra else None,
                    event.raw,
                ))
                added += 1
                if len(batch) >= BATCH:
                    flush()
            flush()
        except Exception:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")
        return added, consumed, number, (earliest, latest)

    def _touch(self, source_id: int, info: os.stat_result) -> None:
        connection = self._writer()
        connection.execute(
            "UPDATE sources SET last_indexed = ?, mtime = ?, size = ? WHERE id = ?",
            (time.time(), info.st_mtime, info.st_size, source_id))
        connection.commit()

    # -- the systemd journal ----------------------------------------------

    #: Journal sources are named this way so they cannot collide with a file
    #: path and are obvious in the Sources dialog.
    JOURNAL_PREFIX = "journal:"

    def journal_cursor(self) -> str:
        """Where the journal was read up to, or "" if it never has been."""
        row = self._writer().execute(
            "SELECT cursor FROM journal_state WHERE id = 1").fetchone()
        return str(row["cursor"]) if row and row["cursor"] else ""

    def journal_sources(self) -> list[Source]:
        return [item for item in self.sources() if item.is_journal]

    def journal_totals(self) -> tuple[int, int, float]:
        """(entries, units, when it was last read)."""
        row = self._writer().execute(
            "SELECT COALESCE(SUM(events), 0), COUNT(*) FROM sources "
            "WHERE kind = 'journal'").fetchone()
        state = self._writer().execute(
            "SELECT last_read FROM journal_state WHERE id = 1").fetchone()
        return (int(row[0] or 0), int(row[1] or 0),
                float(state["last_read"]) if state else 0.0)

    def ingest_journal(self, entries: Iterable[tuple[str, Any]], *,
                       cursor: str = "", stale_cursor: bool = False,
                       truncated: bool = False, cancelled: bool = False,
                       error: str = "") -> JournalIngest:
        """Write journal entries, one source row per systemd unit.

        The unit lands on the *source* rather than on the event because that
        is where the KQL `App` column reads from — which is the whole reason
        this is worth doing. Otherwise a hundred thousand entries would all
        say `App == "journal"` and `summarize count() by App` would be
        useless for exactly the half of the machine that matters.

        A unit the user switched off in the Sources dialog is dropped here
        rather than filtered in journalctl, because the cursor has to advance
        past it either way or it would be re-read forever.
        """
        result = JournalIngest(stale_cursor=stale_cursor, truncated=truncated,
                               cancelled=cancelled, error=error)
        started = time.monotonic()
        connection = self._writer()
        known = self._journal_units(connection)
        disabled = {unit for unit, (_id, enabled) in known.items() if not enabled}
        touched: set[int] = set()
        batch: list[tuple] = []
        insert = ("INSERT INTO events (source, ts, level, line, message, extra, raw) "
                  "VALUES (?, ?, ?, ?, ?, ?, ?)")

        def flush() -> None:
            nonlocal batch
            if not batch:
                return
            first = connection.execute(
                "SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            connection.executemany(insert, batch)
            if self._fts_ready:
                connection.execute(
                    "INSERT INTO events_fts(rowid, message) "
                    "SELECT id, message FROM events WHERE id > ?", (first,))
            batch = []

        connection.execute("BEGIN")
        try:
            for unit, event in entries:
                name = (unit or "journal")[:200]
                if name in disabled:
                    result.skipped_units += 1
                    continue
                entry = known.get(name)
                if entry is None:
                    entry = (self._create_journal_source(connection, name), True)
                    known[name] = entry
                source_id = entry[0]
                touched.add(source_id)
                batch.append((
                    source_id, event.timestamp, int(event.level), 0,
                    event.message,
                    json.dumps(event.extra, default=str) if event.extra else None,
                    event.raw,
                ))
                result.added += 1
                if len(batch) >= BATCH:
                    flush()
            flush()
        except Exception:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")

        if touched:
            marks = ", ".join("?" for _ in touched)
            connection.execute(
                "UPDATE sources SET "
                "  events = (SELECT COUNT(*) FROM events WHERE events.source = sources.id), "
                "  first_ts = (SELECT MIN(ts) FROM events WHERE events.source = sources.id), "
                "  last_ts = (SELECT MAX(ts) FROM events WHERE events.source = sources.id), "
                "  last_indexed = ? "
                f"WHERE id IN ({marks})",
                (time.time(), *touched))
        if cursor:
            connection.execute(
                "INSERT INTO journal_state (id, cursor, last_read, entries) "
                "VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "cursor = excluded.cursor, last_read = excluded.last_read, "
                "entries = journal_state.entries + excluded.entries",
                (cursor, time.time(), result.added))
        connection.commit()

        result.units = len(touched)
        result.cursor = cursor
        result.elapsed = time.monotonic() - started
        log.info("hunt journal ingest: %s", result.summary())
        return result

    def _journal_units(self, connection) -> dict[str, tuple[int, bool]]:
        rows = connection.execute(
            "SELECT id, app, enabled FROM sources WHERE kind = 'journal'")
        return {row["app"]: (int(row["id"]), bool(row["enabled"])) for row in rows}

    def _create_journal_source(self, connection, unit: str) -> int:
        cursor = connection.execute(
            "INSERT INTO sources (path, kind, app, root, format, confidence, "
            "first_seen, last_indexed) "
            "VALUES (?, 'journal', ?, 'journal', 'journal', 1.0, ?, ?)",
            (f"{self.JOURNAL_PREFIX}{unit}", unit, time.time(), time.time()))
        return int(cursor.lastrowid)

    def forget_journal(self) -> int:
        """Remove every journal source and forget where we had read to."""
        connection = self._writer()
        rows = list(connection.execute(
            "SELECT id FROM sources WHERE kind = 'journal'"))
        if not rows:
            connection.execute("DELETE FROM journal_state")
            connection.commit()
            return 0
        identifiers = [int(row["id"]) for row in rows]
        marks = ", ".join("?" for _ in identifiers)
        removed = self._forget_events(connection, f"source IN ({marks})",
                                      tuple(identifiers))
        connection.execute(f"DELETE FROM sources WHERE id IN ({marks})",
                           tuple(identifiers))
        connection.execute("DELETE FROM journal_state")
        connection.commit()
        self.compact()
        return removed

    # -- retention --------------------------------------------------------

    def apply_retention(self, retention: Retention) -> int:
        """Enforce the limits. Returns how many events were removed."""
        connection = self._writer()
        removed = 0

        if retention.max_age_days:
            cutoff = now_us() - retention.max_age_days * 86_400 * 1_000_000
            removed += self._forget_events(
                connection, "ts IS NOT NULL AND ts < ?", (cutoff,))

        if retention.max_events:
            total = self.count()
            excess = total - retention.max_events
            if excess > 0:
                removed += self._forget_events(
                    connection,
                    "id IN (SELECT id FROM events ORDER BY id LIMIT ?)",
                    (excess,))

        if retention.max_megabytes:
            limit = retention.max_megabytes * 1024 * 1024
            for _attempt in range(6):
                if self.file_size() <= limit:
                    break
                # Take a tenth off the front each pass rather than computing an
                # exact row count: the relationship between rows and bytes
                # depends on message length and cannot be predicted.
                tenth = max(1000, self.count() // 10)
                gone = self._forget_events(
                    connection,
                    "id IN (SELECT id FROM events ORDER BY id LIMIT ?)", (tenth,))
                if not gone:
                    break
                removed += gone
                self.compact()

        if removed:
            connection.execute(
                "UPDATE sources SET events = "
                "(SELECT COUNT(*) FROM events WHERE events.source = sources.id)")
            connection.commit()
            self.compact()
            log.info("hunt retention removed %d events", removed)
        return removed

    def _forget_events(self, connection, where: str, parameters: tuple) -> int:
        """Delete events matching `where`, keeping the text index in step.

        The FTS delete command has to run *before* the rows go, because an
        external-content index reads the original text out of the content
        table to work out what to unindex.
        """
        count = connection.execute(
            f"SELECT COUNT(*) FROM events WHERE {where}", parameters).fetchone()[0]
        if not count:
            return 0
        if self._fts_ready:
            try:
                connection.execute(
                    "INSERT INTO events_fts(events_fts, rowid, message) "
                    f"SELECT 'delete', id, message FROM events WHERE {where}",
                    parameters)
            except sqlite3.DatabaseError as error:
                log.warning("hunt: text index out of step (%s); rebuilding", error)
                connection.execute(f"DELETE FROM events WHERE {where}", parameters)
                connection.execute(
                    "INSERT INTO events_fts(events_fts) VALUES('rebuild')")
                connection.commit()
                return int(count)
        connection.execute(f"DELETE FROM events WHERE {where}", parameters)
        connection.commit()
        return int(count)

    def compact(self) -> None:
        """Give freed pages back to the filesystem, a slice at a time."""
        try:
            self._writer().execute("PRAGMA incremental_vacuum")
            self._writer().commit()
        except sqlite3.DatabaseError:
            pass

    def vacuum(self) -> None:
        """A full rebuild. Slow, and only offered from the menu."""
        try:
            self._writer().execute("VACUUM")
        except sqlite3.DatabaseError as error:
            log.warning("hunt: vacuum failed (%s)", error)

    # -- statistics -------------------------------------------------------

    def count(self) -> int:
        return int(self._writer().execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def file_size(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += os.path.getsize(str(self.path) + suffix)
            except OSError:
                pass
        return total

    def span(self) -> tuple[int | None, int | None]:
        row = self._writer().execute(
            "SELECT MIN(ts), MAX(ts) FROM events WHERE ts IS NOT NULL").fetchone()
        return (row[0], row[1]) if row else (None, None)

    def statistics(self) -> dict[str, Any]:
        """Everything the page's header strip shows, in one query each."""
        connection = self._writer()
        events = self.count()
        earliest, latest = self.span()
        by_level = {
            Level.from_value(row[0]).label: row[1]
            for row in connection.execute(
                "SELECT level, COUNT(*) FROM events GROUP BY level")
        }
        by_app = [
            (row[0] or "other", row[1])
            for row in connection.execute(
                "SELECT s.app, COUNT(e.id) FROM sources s "
                "LEFT JOIN events e ON e.source = s.id "
                "GROUP BY s.app ORDER BY COUNT(e.id) DESC")
        ]
        sources = connection.execute(
            "SELECT COUNT(*), SUM(enabled) FROM sources").fetchone()
        return {
            "events": events,
            "sources": int(sources[0] or 0),
            "enabled": int(sources[1] or 0),
            "bytes": self.file_size(),
            "first": earliest,
            "last": latest,
            "levels": by_level,
            "apps": by_app,
            "fts": self._fts_ready,
        }

    def sample(self, limit: int = 5) -> list[sqlite3.Row]:
        """A handful of recent events, for the empty-state preview."""
        return list(self._writer().execute(
            "SELECT e.*, s.path, s.app FROM events e JOIN sources s ON s.id = e.source "
            "ORDER BY e.id DESC LIMIT ?", (limit,)))


# ---------------------------------------------------------------------------
# Reading files
# ---------------------------------------------------------------------------


def _open_text(path: Path, compressed: bool):
    """A binary handle, transparently decompressing a .gz."""
    if compressed:
        return gzip.open(path, "rb")
    return path.open("rb")


def _head_hash(path: Path, size: int = HEAD_BYTES) -> str:
    """SHA-256 of a file's first few kilobytes.

    This is what notices a log that was rotated *in place* — truncated and
    written over — which leaves the inode and often the size unchanged and
    would otherwise be read as an append from the middle of a new file.
    """
    try:
        with path.open("rb") as handle:
            return hashlib.sha256(handle.read(size)).hexdigest()
    except OSError:
        return ""


def _stream(path: Path, compressed: bool, offset: int, item: formats.LogFormat,
            context: formats.ParseContext, start_line: int
            ) -> Iterator[tuple[Any, int, int]]:
    """Yield (event, byte offset after it, line number) from `offset` on.

    Reads bytes rather than text so the offset it reports is the one that can
    be seeked to next time. A partial final line is left in the buffer and
    never consumed, so its offset is not advanced past.
    """
    parse = item.parse
    joins = item.continuation
    pending = None
    pending_extra = 0
    pending_offset = offset
    number = start_line

    with closing(_open_text(path, compressed)) as handle:
        if offset and not compressed:
            handle.seek(offset)
        consumed = offset
        buffer = b""
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            buffer += chunk
            pieces = buffer.split(b"\n")
            buffer = pieces.pop()
            for piece in pieces:
                consumed += len(piece) + 1
                number += 1
                line = piece.decode("utf-8", "replace").rstrip("\r")
                if len(line) > formats.MAX_LINE:
                    line = line[: formats.MAX_LINE] + " …[truncated]"
                if not line.strip():
                    continue
                try:
                    event = parse(line, context)
                except Exception:  # noqa: BLE001 - one bad line is not a bad file
                    event = None

                if event is not None:
                    if pending is not None:
                        yield pending, pending_offset, number - 1
                    event.line_number = number
                    pending, pending_extra, pending_offset = event, 0, consumed
                    continue

                if joins and pending is not None:
                    if pending_extra < formats.MAX_CONTINUATION_LINES:
                        addition = "\n" + line
                        if len(pending.message) + len(addition) <= formats.MAX_MESSAGE:
                            if pending.raw is None:
                                pending.raw = pending.message
                            pending.message += addition
                            pending.raw += addition
                        pending_extra += 1
                    pending_offset = consumed
                    continue

                if pending is not None:
                    yield pending, pending_offset, number - 1
                    pending = None
                fallback = formats.parse_plain(line, context)
                fallback.line_number = number
                yield fallback, consumed, number

    if pending is not None:
        yield pending, pending_offset, number


def _to_source(row: sqlite3.Row) -> Source:
    return Source(
        id=row["id"], path=row["path"], kind=_column(row, "kind", "file"),
        app=row["app"], root=row["root"],
        format=row["format"], confidence=row["confidence"], size=row["size"],
        mtime=row["mtime"], inode=row["inode"], device=row["device"],
        byte_offset=row["byte_offset"], line_offset=row["line_offset"],
        head=row["head"], events=row["events"], first_ts=row["first_ts"],
        last_ts=row["last_ts"], first_seen=row["first_seen"],
        last_indexed=row["last_indexed"], compressed=bool(row["compressed"]),
        enabled=bool(row["enabled"]), note=row["note"],
    )


def _column(row: sqlite3.Row, name: str, default):
    """Read a column that may not exist yet on a database mid-upgrade."""
    try:
        value = row[name]
    except (IndexError, KeyError):
        return default
    return default if value is None else value


def _safe_identifier(name: str) -> str:
    """A SQL identifier built from a name we chose, never from user input."""
    cleaned = "".join(char for char in name if char.isalnum() or char == "_")
    if not cleaned:
        raise ValueError(f"not a usable schema name: {name!r}")
    return cleaned
