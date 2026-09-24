"""The tables a query can see, their columns, and how each maps to SQL.

This is the join between two vocabularies. KQL sees ``Logs`` with a
``Timestamp`` of type datetime and a ``Level`` of type string. SQLite sees
``events`` with a ``ts`` of type INTEGER holding microseconds and a ``level``
of type INTEGER holding a rank. A :class:`Binding` is one column's worth of
that translation, in both directions:

``encode``
    turns a value written in a query into the stored form, so that
    ``Level == "error"`` becomes ``e.level = 50`` and keeps using the index
    rather than decoding a million rows to compare strings.
``decode``
    turns a stored value back, so the grid shows a time and not an integer.

Four tables are offered. Two are the log store; the other two are ClamGuard's
own scan history, attached read-only, so a hunt can cross a detection against
what the application logs were doing at the time — which is the whole reason
this page sits inside an antivirus rather than beside one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .model import ColumnType, Level


@dataclass(frozen=True, slots=True)
class Binding:
    """One column, as KQL sees it and as SQL stores it."""

    name: str
    type: ColumnType
    #: The SQL expression that produces it, in terms of the table's FROM.
    sql: str
    description: str = ""
    #: Query value -> stored value. None means they are the same.
    encode: Callable[[Any], Any] | None = None
    #: Stored value -> query value. None means they are the same.
    decode: Callable[[Any], Any] | None = None
    #: True when SQLite has an index that a filter on this column can use.
    indexed: bool = False
    #: True when a bare `search "term"` should look here.
    searchable: bool = False
    #: True when the full-text index covers this column.
    full_text: bool = False


@dataclass(frozen=True, slots=True)
class TableDef:
    """One queryable table."""

    name: str
    title: str
    description: str
    columns: tuple[Binding, ...]
    #: Everything after FROM, including joins.
    source_sql: str
    #: Which column the page's time-range picker filters on. Empty when the
    #: table has no useful time.
    time_column: str = "Timestamp"
    #: The FTS5 table that indexes this table's text, when there is one.
    full_text_table: str = ""
    #: Which attached database this lives in, if any.
    schema: str = ""
    #: Roughly how many rows, for the "this will be slow" warning. Filled in
    #: at runtime by the engine.
    group: str = "Logs"

    def column(self, name: str) -> Binding | None:
        lowered = name.lower()
        for item in self.columns:
            if item.name.lower() == lowered:
                return item
        return None

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.columns)

    def searchable(self) -> tuple[Binding, ...]:
        return tuple(item for item in self.columns if item.searchable)


# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------


def _encode_datetime(value: Any) -> Any:
    """A query-side datetime to stored microseconds.

    Written without importing the KQL type system so that this module stays
    below the language in the import order: ``kql`` depends on the catalogue,
    never the other way round.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(moment.timestamp() * 1_000_000)
    if isinstance(value, str):
        moment = _decode_iso(value.replace("Z", "+00:00"))
        return int(moment.timestamp() * 1_000_000) if moment else None
    return None


def _decode_datetime(value: Any) -> Any:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _encode_level(value: Any) -> Any:
    """``"error"`` to 50, so the comparison stays on the indexed integer."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    found = Level.parse(value)
    # An unrecognised word must not quietly become "unknown" and match every
    # timestamp-less line on the machine.
    if found is Level.UNKNOWN and str(value).strip().lower() != "unknown":
        return -1
    return int(found)


def _decode_level(value: Any) -> Any:
    return Level.from_value(value).label


def _encode_epoch_seconds(value: Any) -> Any:
    """A query-side datetime to the float seconds `sources` stores.

    Three different tables here keep time three different ways — the event
    store in microseconds, `sources` in float seconds from ``os.stat``, and
    the scan history in ISO text — so each needs its own encoder or the time
    picker filters one of them to nothing.
    """
    microseconds = _encode_datetime(value)
    return None if microseconds is None else microseconds / 1_000_000


def _encode_iso(value: Any) -> Any:
    """A query-side datetime to the ISO text the history database stores.

    Comparing ISO-8601 as text is a correct ordering as long as every value
    has the same shape, which they do: ClamGuard writes them all with
    ``datetime.isoformat()``.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.astimezone().replace(tzinfo=None).isoformat()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1_000_000).isoformat()
    return None


def _decode_epoch_seconds(value: Any) -> Any:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _decode_iso(value: Any) -> Any:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _decode_json(value: Any) -> Any:
    import json

    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


# ---------------------------------------------------------------------------
# The tables
# ---------------------------------------------------------------------------


LOGS = TableDef(
    name="Logs",
    title="Logs",
    description="Every line indexed from every log file on this machine, "
                "normalised into one shape.",
    source_sql="events e JOIN sources s ON s.id = e.source",
    full_text_table="events_fts",
    columns=(
        Binding("Timestamp", ColumnType.DATETIME, "e.ts",
                "When the line was written. Null for the formats that do not "
                "say — Unity logs, most game logs, and Xorg, which counts "
                "seconds since the server started instead.",
                encode=_encode_datetime, decode=_decode_datetime, indexed=True),
        Binding("Level", ColumnType.STRING, "e.level",
                "trace, debug, info, notice, warning, error, critical, or "
                "unknown when the format does not say.",
                encode=_encode_level, decode=_decode_level, indexed=True,
                searchable=True),
        Binding("Message", ColumnType.STRING, "e.message",
                "The line, with whatever prefix the format used stripped off.",
                searchable=True, full_text=True),
        Binding("App", ColumnType.STRING, "s.app",
                "Which application wrote it, worked out from where the file "
                "sits.", indexed=True, searchable=True),
        Binding("Source", ColumnType.STRING, "s.path",
                "The full path of the file the line came from.",
                searchable=True),
        Binding("SourceName", ColumnType.STRING,
                "replace(s.path, rtrim(s.path, replace(s.path, '/', '')), '')",
                "Just the file name."),
        Binding("Format", ColumnType.STRING, "s.format",
                "Which log format was recognised: jsonl, chromium, abseil, "
                "syslog, and so on."),
        Binding("Location", ColumnType.STRING, "s.root",
                "Which of the searched places the file was found in: config, "
                "data, state, cache, flatpak, system."),
        Binding("LineNumber", ColumnType.LONG, "e.line",
                "Where in the file the line is, counting from 1."),
        Binding("Raw", ColumnType.STRING, "COALESCE(e.raw, e.message)",
                "The original line, exactly as it appears in the file."),
        Binding("Extra", ColumnType.DYNAMIC, "e.extra",
                "Everything else the format knew: pid, thread, logger, "
                "status, origin. Reach into it with Extra.pid.",
                decode=_decode_json),
        Binding("EventId", ColumnType.LONG, "e.id",
                "The store's own identifier for the line. Stable until the "
                "line is removed by retention."),
    ),
)


SOURCES = TableDef(
    name="Sources",
    title="Sources",
    description="One row per indexed file: where it is, what format it is, "
                "how much of it has been read and when.",
    source_sql="sources s",
    time_column="LastIndexed",
    group="Store",
    columns=(
        Binding("Path", ColumnType.STRING, "s.path", "The full path.",
                searchable=True),
        Binding("App", ColumnType.STRING, "s.app",
                "The application it belongs to.", searchable=True),
        Binding("Location", ColumnType.STRING, "s.root",
                "Which searched place it was found in."),
        Binding("Format", ColumnType.STRING, "s.format",
                "The recognised format.", searchable=True),
        Binding("Confidence", ColumnType.REAL, "s.confidence",
                "How much of the sample that format understood, 0 to 1."),
        Binding("Bytes", ColumnType.LONG, "s.size", "The file's size."),
        Binding("Indexed", ColumnType.LONG, "s.byte_offset",
                "How many bytes have been read so far."),
        Binding("Events", ColumnType.LONG, "s.events",
                "How many events came out of it."),
        Binding("Modified", ColumnType.DATETIME, "s.mtime",
                "When the file was last written.",
                encode=_encode_epoch_seconds, decode=_decode_epoch_seconds),
        Binding("FirstSeen", ColumnType.DATETIME, "s.first_seen",
                "When Hunt first noticed the file.",
                encode=_encode_epoch_seconds, decode=_decode_epoch_seconds),
        Binding("LastIndexed", ColumnType.DATETIME, "s.last_indexed",
                "When Hunt last read it.", encode=_encode_epoch_seconds,
                decode=_decode_epoch_seconds),
        Binding("FirstEvent", ColumnType.DATETIME, "s.first_ts",
                "The earliest timestamp in it.", encode=_encode_datetime,
                decode=_decode_datetime),
        Binding("LastEvent", ColumnType.DATETIME, "s.last_ts",
                "The latest timestamp in it.", encode=_encode_datetime,
                decode=_decode_datetime),
        Binding("Compressed", ColumnType.BOOL, "s.compressed",
                "True for a .gz file."),
        Binding("Enabled", ColumnType.BOOL, "s.enabled",
                "False when you have switched this source off."),
    ),
)


SCANS = TableDef(
    name="Scans",
    title="Scans",
    description="ClamGuard's own scan history, attached read-only. Join it "
                "against Logs to see what the machine was doing around a scan.",
    source_sql="history.scans sc",
    time_column="Started",
    schema="history",
    group="ClamAV",
    columns=(
        Binding("ScanId", ColumnType.LONG, "sc.id", "The scan's identifier."),
        Binding("Started", ColumnType.DATETIME, "sc.started_at",
                "When the scan began.", encode=_encode_iso, decode=_decode_iso),
        Binding("Finished", ColumnType.DATETIME, "sc.finished_at",
                "When it ended.", encode=_encode_iso, decode=_decode_iso),
        Binding("Kind", ColumnType.STRING, "sc.kind",
                "quick, full, custom, removable or realtime.", searchable=True),
        Binding("Status", ColumnType.STRING, "sc.status",
                "completed, stopped, failed or running.", searchable=True),
        Binding("Engine", ColumnType.STRING, "sc.engine",
                "clamscan or clamdscan."),
        Binding("Files", ColumnType.LONG, "sc.files_scanned",
                "How many files were looked at."),
        Binding("Bytes", ColumnType.LONG, "sc.bytes_scanned",
                "How much was read."),
        Binding("Threats", ColumnType.LONG, "sc.threats_found",
                "How many detections there were."),
        Binding("Errors", ColumnType.LONG, "sc.errors",
                "How many files could not be read."),
        Binding("Duration", ColumnType.REAL, "sc.duration",
                "How long it took, in seconds."),
        Binding("Summary", ColumnType.STRING, "sc.summary",
                "The one-line result.", searchable=True),
    ),
)


DETECTIONS = TableDef(
    name="Detections",
    title="Detections",
    description="Every threat ClamAV has found on this machine, attached "
                "read-only.",
    source_sql="history.detections d",
    time_column="Detected",
    schema="history",
    group="ClamAV",
    columns=(
        Binding("DetectionId", ColumnType.LONG, "d.id", "Its identifier."),
        Binding("ScanId", ColumnType.LONG, "d.scan_id",
                "Which scan found it. Join to Scans on this."),
        Binding("Detected", ColumnType.DATETIME, "d.detected_at",
                "When it was found.", encode=_encode_iso, decode=_decode_iso),
        Binding("Path", ColumnType.STRING, "d.path",
                "The file that was flagged.", searchable=True),
        Binding("Threat", ColumnType.STRING, "d.threat",
                "What ClamAV called it.", searchable=True),
        Binding("Action", ColumnType.STRING, "d.action",
                "reported, quarantined, deleted or ignored.", searchable=True),
        Binding("QuarantineId", ColumnType.STRING, "d.quarantine_id",
                "The vault entry, when it was quarantined."),
        Binding("Bytes", ColumnType.LONG, "d.file_size", "The file's size."),
        Binding("Sha256", ColumnType.STRING, "d.sha256",
                "The hash of the file as it was when found."),
    ),
)


TABLES: dict[str, TableDef] = {
    table.name.lower(): table for table in (LOGS, SOURCES, SCANS, DETECTIONS)
}

#: The tables that need ClamGuard's history database attached.
ATTACHED_SCHEMAS: tuple[str, ...] = ("history",)


def table(name: str) -> TableDef | None:
    return TABLES.get(name.lower())


def names() -> tuple[str, ...]:
    return tuple(item.name for item in TABLES.values())


def grouped() -> dict[str, list[TableDef]]:
    """Tables by group, for the left rail's tree."""
    groups: dict[str, list[TableDef]] = {}
    for item in TABLES.values():
        groups.setdefault(item.group, []).append(item)
    for entries in groups.values():
        entries.sort(key=lambda entry: entry.name)
    return dict(sorted(groups.items()))
