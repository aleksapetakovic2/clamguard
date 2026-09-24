"""Every scan ClamGuard has ever run, in a local SQLite file.

An antivirus without history is hard to trust: you cannot answer "when did I
last check this machine?" or "has this file been flagged before?". The database
lives at ~/.local/share/clamguard/history.db and nothing else reads it.

Two tables. `scans` is one row per scan; `detections` is one row per threat,
pointing back at the scan that found it. Deleting a scan deletes its
detections, so pruning is a single statement.

All calls are synchronous and fast enough for the UI thread at this scale
(thousands of rows). Anything that could return a large result set — the export
functions — is designed to be run through process.run_in_background.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

from PySide6.QtCore import QObject, Signal

from . import paths
from .logging_setup import get_logger

log = get_logger(__name__)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL,
    finished_at     TEXT,
    kind            TEXT    NOT NULL DEFAULT 'custom',
    profile         TEXT    NOT NULL DEFAULT '',
    engine          TEXT    NOT NULL DEFAULT '',
    targets         TEXT    NOT NULL DEFAULT '[]',
    status          TEXT    NOT NULL DEFAULT 'running',
    files_scanned   INTEGER NOT NULL DEFAULT 0,
    bytes_scanned   INTEGER NOT NULL DEFAULT 0,
    threats_found   INTEGER NOT NULL DEFAULT 0,
    errors          INTEGER NOT NULL DEFAULT 0,
    duration        REAL    NOT NULL DEFAULT 0,
    summary         TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS detections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    detected_at     TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    threat          TEXT    NOT NULL,
    action          TEXT    NOT NULL DEFAULT 'reported',
    quarantine_id   TEXT    NOT NULL DEFAULT '',
    file_size       INTEGER NOT NULL DEFAULT 0,
    sha256          TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_scans_started   ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_detect_scan     ON detections(scan_id);
CREATE INDEX IF NOT EXISTS idx_detect_path     ON detections(path);
CREATE INDEX IF NOT EXISTS idx_detect_threat   ON detections(threat);
"""


@dataclass
class ScanRecord:
    """One row of the scans table."""

    id: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    kind: str = "custom"
    profile: str = ""
    engine: str = ""
    targets: list[str] = field(default_factory=list)
    status: str = "running"       # running / completed / stopped / failed
    files_scanned: int = 0
    bytes_scanned: int = 0
    threats_found: int = 0
    errors: int = 0
    duration: float = 0.0
    summary: str = ""

    @property
    def clean(self) -> bool:
        return self.status == "completed" and self.threats_found == 0

    @property
    def tone(self) -> str:
        if self.status == "running":
            return "info"
        if self.status == "failed":
            return "danger"
        if self.threats_found:
            return "danger"
        if self.status == "stopped":
            return "warn"
        return "ok"

    @property
    def is_realtime(self) -> bool:
        """A row collecting on-access detections rather than a scan you ran."""
        return self.kind == "realtime"

    def outcome(self) -> str:
        """The one-line result shown in the history list."""
        if self.status == "running":
            return "Watching" if self.is_realtime else "In progress"
        if self.status == "failed":
            return "Failed"
        if self.threats_found == 1:
            return "1 threat found"
        if self.threats_found:
            return f"{self.threats_found} threats found"
        if self.status == "stopped":
            return "Stopped early"
        return "No threats found"

    def target_text(self) -> str:
        if not self.targets:
            return "—"
        if len(self.targets) == 1:
            return self.targets[0]
        return f"{self.targets[0]} and {len(self.targets) - 1} more"


@dataclass
class DetectionRecord:
    """One row of the detections table."""

    id: int = 0
    scan_id: int = 0
    detected_at: datetime | None = None
    path: str = ""
    threat: str = ""
    action: str = "reported"       # reported / quarantined / deleted / ignored / restored
    quarantine_id: str = ""
    file_size: int = 0
    sha256: str = ""

    @property
    def filename(self) -> str:
        return Path(self.path).name or self.path


class History(QObject):
    """The scan history database."""

    #: A scan row was inserted or updated.
    scan_recorded = Signal(int)
    #: A detection row was inserted.
    detection_recorded = Signal(int)
    #: Something was deleted; lists should reload.
    changed = Signal()

    def __init__(self, path: Path | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.path = path or paths.HISTORY_DB
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._realtime_scan_id = 0
        self._initialise()

    # -- connection -------------------------------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """A short-lived connection. SQLite is happiest this way for a GUI."""
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except sqlite3.Error:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialise(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(_SCHEMA)
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except sqlite3.Error as error:
            log.error("cannot initialise history database: %s", error)

    # -- writing ----------------------------------------------------------

    def start_scan(self, kind: str, targets: list[str], profile: str = "",
                   engine: str = "") -> int:
        """Insert a running scan and return its id."""
        now = datetime.now().isoformat(timespec="seconds")
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "INSERT INTO scans (started_at, kind, profile, engine, targets, status) "
                    "VALUES (?, ?, ?, ?, ?, 'running')",
                    (now, kind, profile, engine, json.dumps(targets)),
                )
                scan_id = int(cursor.lastrowid or 0)
        except sqlite3.Error as error:
            log.error("cannot record scan start: %s", error)
            return 0
        self.scan_recorded.emit(scan_id)
        return scan_id

    def finish_scan(self, scan_id: int, *, status: str, files_scanned: int = 0,
                    bytes_scanned: int = 0, threats_found: int = 0, errors: int = 0,
                    duration: float = 0.0, summary: str = "") -> None:
        """Mark a scan finished and store its totals."""
        if not scan_id:
            return
        try:
            with self._connect() as connection:
                connection.execute(
                    "UPDATE scans SET finished_at = ?, status = ?, files_scanned = ?, "
                    "bytes_scanned = ?, threats_found = ?, errors = ?, duration = ?, "
                    "summary = ? WHERE id = ?",
                    (datetime.now().isoformat(timespec="seconds"), status, files_scanned,
                     bytes_scanned, threats_found, errors, duration, summary, scan_id),
                )
        except sqlite3.Error as error:
            log.error("cannot record scan finish: %s", error)
            return
        self.scan_recorded.emit(scan_id)

    def realtime_scan_id(self) -> int:
        """The history row that this session's on-access detections attach to.

        Real-time detections do not belong to a scan the user started, but they
        still belong in the history. One row per session, created on the first
        detection, keeps them together without inventing a scan per file. It
        stays "running" while ClamGuard is open, which also keeps it out of
        `last_scan()` so the dashboard still reports the last *real* scan.
        """
        if self._realtime_scan_id:
            return self._realtime_scan_id
        self._realtime_scan_id = self.start_scan(
            "realtime", ["Files as they were opened"], profile="", engine="clamonacc")
        return self._realtime_scan_id

    def close_realtime_scan(self, threats: int) -> None:
        """Mark this session's real-time row finished, on shutdown."""
        if not self._realtime_scan_id:
            return
        self.finish_scan(self._realtime_scan_id, status="completed",
                         threats_found=threats,
                         summary=f"{threats} caught by real-time protection")
        self._realtime_scan_id = 0

    def add_detection(self, scan_id: int, path: str, threat: str, *,
                      action: str = "reported", quarantine_id: str = "",
                      file_size: int = 0, sha256: str = "") -> int:
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "INSERT INTO detections (scan_id, detected_at, path, threat, action, "
                    "quarantine_id, file_size, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, datetime.now().isoformat(timespec="seconds"), path, threat,
                     action, quarantine_id, file_size, sha256),
                )
                detection_id = int(cursor.lastrowid or 0)
        except sqlite3.Error as error:
            log.error("cannot record detection: %s", error)
            return 0
        self.detection_recorded.emit(detection_id)
        return detection_id

    def set_detection_action(self, detection_id: int, action: str,
                             quarantine_id: str = "") -> None:
        """Record what the user did about a threat."""
        try:
            with self._connect() as connection:
                connection.execute(
                    "UPDATE detections SET action = ?, quarantine_id = ? WHERE id = ?",
                    (action, quarantine_id, detection_id),
                )
        except sqlite3.Error as error:
            log.error("cannot update detection: %s", error)
            return
        self.changed.emit()

    def set_action_for_quarantine(self, quarantine_id: str, action: str) -> None:
        """Update every detection that produced a given quarantine entry."""
        try:
            with self._connect() as connection:
                connection.execute(
                    "UPDATE detections SET action = ? WHERE quarantine_id = ?",
                    (action, quarantine_id),
                )
        except sqlite3.Error as error:
            log.error("cannot update detections: %s", error)
            return
        self.changed.emit()

    # -- reading ----------------------------------------------------------

    def recent_scans(self, limit: int = 50, offset: int = 0) -> list[ScanRecord]:
        return self._query_scans(
            "SELECT * FROM scans ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    def last_scan(self, *, completed_only: bool = True) -> ScanRecord | None:
        clause = "WHERE status IN ('completed','stopped')" if completed_only else ""
        rows = self._query_scans(
            f"SELECT * FROM scans {clause} ORDER BY started_at DESC, id DESC LIMIT 1", ()
        )
        return rows[0] if rows else None

    def scan(self, scan_id: int) -> ScanRecord | None:
        rows = self._query_scans("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return rows[0] if rows else None

    def search_scans(self, text: str = "", kind: str = "", days: int = 0,
                     threats_only: bool = False, limit: int = 500) -> list[ScanRecord]:
        clauses: list[str] = []
        params: list[object] = []
        if text:
            clauses.append("(targets LIKE ? OR summary LIKE ? OR kind LIKE ?)")
            params += [f"%{text}%"] * 3
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if days:
            cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
            clauses.append("started_at >= ?")
            params.append(cutoff)
        if threats_only:
            clauses.append("threats_found > 0")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        return self._query_scans(
            f"SELECT * FROM scans {where} ORDER BY started_at DESC, id DESC LIMIT ?",
            tuple(params),
        )

    def detections_for(self, scan_id: int) -> list[DetectionRecord]:
        return self._query_detections(
            "SELECT * FROM detections WHERE scan_id = ? ORDER BY id", (scan_id,)
        )

    def recent_detections(self, limit: int = 100) -> list[DetectionRecord]:
        return self._query_detections(
            "SELECT * FROM detections ORDER BY detected_at DESC, id DESC LIMIT ?", (limit,)
        )

    def search_detections(self, text: str, limit: int = 500) -> list[DetectionRecord]:
        pattern = f"%{text}%"
        return self._query_detections(
            "SELECT * FROM detections WHERE path LIKE ? OR threat LIKE ? "
            "ORDER BY detected_at DESC LIMIT ?",
            (pattern, pattern, limit),
        )

    def detection_count_for_path(self, path: str) -> int:
        """Has this exact file been flagged before?"""
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM detections WHERE path = ?", (path,)
                ).fetchone()
                return int(row["n"]) if row else 0
        except sqlite3.Error:
            return 0

    # -- statistics -------------------------------------------------------

    def totals(self) -> dict[str, int]:
        """Headline numbers for the dashboard and the history page."""
        empty = {"scans": 0, "files": 0, "threats": 0, "detections": 0, "scans_30d": 0}
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT COUNT(*) AS scans, COALESCE(SUM(files_scanned),0) AS files, "
                    "COALESCE(SUM(threats_found),0) AS threats FROM scans "
                    "WHERE status != 'running'"
                ).fetchone()
                detections = connection.execute(
                    "SELECT COUNT(*) AS n FROM detections"
                ).fetchone()
                cutoff = (datetime.now() - timedelta(days=30)).isoformat(timespec="seconds")
                recent = connection.execute(
                    "SELECT COUNT(*) AS n FROM scans WHERE started_at >= ?", (cutoff,)
                ).fetchone()
                return {
                    "scans": int(row["scans"]),
                    "files": int(row["files"]),
                    "threats": int(row["threats"]),
                    "detections": int(detections["n"]),
                    "scans_30d": int(recent["n"]),
                }
        except sqlite3.Error as error:
            log.error("cannot read totals: %s", error)
            return empty

    def daily_counts(self, days: int = 30) -> list[tuple[str, int, int]]:
        """(date, scans, threats) per day — for the activity chart."""
        cutoff = (datetime.now() - timedelta(days=days)).date().isoformat()
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT substr(started_at, 1, 10) AS day, COUNT(*) AS scans, "
                    "COALESCE(SUM(threats_found),0) AS threats FROM scans "
                    "WHERE substr(started_at, 1, 10) >= ? GROUP BY day ORDER BY day",
                    (cutoff,),
                ).fetchall()
                return [(r["day"], int(r["scans"]), int(r["threats"])) for r in rows]
        except sqlite3.Error:
            return []

    # -- maintenance ------------------------------------------------------

    def delete_scan(self, scan_id: int) -> None:
        try:
            with self._connect() as connection:
                connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        except sqlite3.Error as error:
            log.error("cannot delete scan: %s", error)
            return
        self.changed.emit()

    def purge_older_than(self, days: int) -> int:
        """Delete scans older than `days`. Returns how many went."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
        try:
            with self._connect() as connection:
                cursor = connection.execute("DELETE FROM scans WHERE started_at < ?", (cutoff,))
                removed = cursor.rowcount
        except sqlite3.Error as error:
            log.error("cannot purge history: %s", error)
            return 0
        if removed:
            self._vacuum()
            self.changed.emit()
        return removed

    def clear(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("DELETE FROM detections")
                connection.execute("DELETE FROM scans")
        except sqlite3.Error as error:
            log.error("cannot clear history: %s", error)
            return
        self._vacuum()
        self.changed.emit()

    def _vacuum(self) -> None:
        """Reclaim space after a bulk delete.

        VACUUM cannot run inside a transaction, and Python's sqlite3 opens one
        implicitly for any statement that writes, so this needs its own
        autocommit connection.
        """
        try:
            connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            try:
                connection.execute("VACUUM")
            finally:
                connection.close()
        except sqlite3.Error as error:
            log.warning("could not vacuum the history database: %s", error)

    # -- row mapping ------------------------------------------------------

    def _query_scans(self, sql: str, params: tuple) -> list[ScanRecord]:
        try:
            with self._connect() as connection:
                rows = connection.execute(sql, params).fetchall()
        except sqlite3.Error as error:
            log.error("history query failed: %s", error)
            return []
        return [self._to_scan(row) for row in rows]

    def _query_detections(self, sql: str, params: tuple) -> list[DetectionRecord]:
        try:
            with self._connect() as connection:
                rows = connection.execute(sql, params).fetchall()
        except sqlite3.Error as error:
            log.error("history query failed: %s", error)
            return []
        return [self._to_detection(row) for row in rows]

    @staticmethod
    def _to_scan(row: sqlite3.Row) -> ScanRecord:
        try:
            targets = json.loads(row["targets"])
        except (json.JSONDecodeError, TypeError):
            targets = []
        return ScanRecord(
            id=row["id"],
            started_at=_parse(row["started_at"]),
            finished_at=_parse(row["finished_at"]),
            kind=row["kind"],
            profile=row["profile"],
            engine=row["engine"],
            targets=targets if isinstance(targets, list) else [],
            status=row["status"],
            files_scanned=row["files_scanned"],
            bytes_scanned=row["bytes_scanned"],
            threats_found=row["threats_found"],
            errors=row["errors"],
            duration=row["duration"],
            summary=row["summary"],
        )

    @staticmethod
    def _to_detection(row: sqlite3.Row) -> DetectionRecord:
        return DetectionRecord(
            id=row["id"],
            scan_id=row["scan_id"],
            detected_at=_parse(row["detected_at"]),
            path=row["path"],
            threat=row["threat"],
            action=row["action"],
            quarantine_id=row["quarantine_id"],
            file_size=row["file_size"],
            sha256=row["sha256"],
        )


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
