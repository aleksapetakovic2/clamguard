"""The vocabulary Hunt is written in: levels, events, columns and results.

Every log format on this machine says something different for "this line is a
warning" — ``WARN``, ``wrn``, ``[warning]``, ``W``, syslog priority 4 — and
every one of them has to end up as the same thing, or a query written against
one application's logs would silently miss another's. :class:`Level` is that
one thing.

Timestamps are stored as **microseconds since the Unix epoch, UTC**, in a
plain INTEGER column, because that is the only representation SQLite can index
and compare without parsing. A log line that carries no time zone is read as
*local* time, which is what the application that wrote it meant; the
assumption is recorded on the source so it can be seen rather than guessed at.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from typing import Any, Iterator, Sequence


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Level(IntEnum):
    """How bad one log line claims to be, normalised across every format.

    The numbers are syslog-shaped but inverted so that "worse" sorts higher,
    which is what ``| order by Level desc`` should obviously mean. They are
    stored in SQLite, so do not renumber them without a migration.
    """

    UNKNOWN = 0
    TRACE = 10
    DEBUG = 20
    INFO = 30
    NOTICE = 35
    WARNING = 40
    ERROR = 50
    CRITICAL = 60

    @property
    def label(self) -> str:
        """The lowercase name a query compares against: ``Level == "error"``."""
        return _LEVEL_LABELS[self]

    @property
    def title(self) -> str:
        return self.label.title()

    @property
    def tone(self) -> str:
        """Which palette colour shows this level."""
        return _LEVEL_TONES[self]

    @property
    def is_problem(self) -> bool:
        return self >= Level.WARNING

    @classmethod
    def parse(cls, text: Any) -> "Level":
        """Best guess at a level from whatever the log line called it.

        Accepts the word (``warn``), the letter (``W``), the syslog priority
        (``4``) and the bracketed forms. Returns UNKNOWN rather than guessing
        when the text means nothing — a line that does not say how bad it is
        must not be promoted to INFO, or "show me everything that is not
        informational" would hide half the machine.
        """
        if isinstance(text, Level):
            return text
        if isinstance(text, bool) or text is None:
            return cls.UNKNOWN
        if isinstance(text, int):
            return _SYSLOG_PRIORITIES.get(text, cls.UNKNOWN)
        if isinstance(text, float):
            return _SYSLOG_PRIORITIES.get(int(text), cls.UNKNOWN)
        word = str(text).strip().strip("[]<>():").lower()
        if not word:
            return cls.UNKNOWN
        found = _LEVEL_WORDS.get(word)
        if found is not None:
            return found
        if word.isdigit():
            return _SYSLOG_PRIORITIES.get(int(word), cls.UNKNOWN)
        return cls.UNKNOWN

    @classmethod
    def from_value(cls, value: Any) -> "Level":
        """Turn a stored integer back into a Level, tolerating rubbish."""
        try:
            return cls(int(value))
        except (TypeError, ValueError):
            return cls.UNKNOWN


_LEVEL_LABELS: dict[Level, str] = {
    Level.UNKNOWN: "unknown",
    Level.TRACE: "trace",
    Level.DEBUG: "debug",
    Level.INFO: "info",
    Level.NOTICE: "notice",
    Level.WARNING: "warning",
    Level.ERROR: "error",
    Level.CRITICAL: "critical",
}

_LEVEL_TONES: dict[Level, str] = {
    Level.UNKNOWN: "faint",
    Level.TRACE: "faint",
    Level.DEBUG: "muted",
    Level.INFO: "info",
    Level.NOTICE: "info",
    Level.WARNING: "warn",
    Level.ERROR: "danger",
    Level.CRITICAL: "danger",
}

#: Every spelling of a level seen in the logs on a real desktop, plus the
#: obvious ones that were not. Keys are lowercase and stripped of brackets.
_LEVEL_WORDS: dict[str, Level] = {}


def _register(level: Level, *words: str) -> None:
    for word in words:
        _LEVEL_WORDS[word] = level


_register(Level.TRACE, "trace", "verbose", "vrb", "v", "trc", "finest", "finer", "silly")
_register(Level.DEBUG, "debug", "dbg", "d", "fine", "diag", "diagnostic")
_register(Level.INFO, "info", "information", "informational", "inf", "i", "log",
          "message", "msg", "normal", "ok", "status")
_register(Level.NOTICE, "notice", "note", "important", "success")
_register(Level.WARNING, "warning", "warn", "wrn", "w", "caution", "deprecated")
_register(Level.ERROR, "error", "err", "e", "eror", "severe", "failure", "failed",
          "fail", "exception", "fatal_error")
_register(Level.CRITICAL, "critical", "crit", "c", "fatal", "ftl", "emerg",
          "emergency", "alert", "panic", "assert")

#: RFC 5424 priorities. Lower is worse, which is the opposite of Level.
_SYSLOG_PRIORITIES: dict[int, Level] = {
    0: Level.CRITICAL,   # emergency
    1: Level.CRITICAL,   # alert
    2: Level.CRITICAL,   # critical
    3: Level.ERROR,
    4: Level.WARNING,
    5: Level.NOTICE,
    6: Level.INFO,
    7: Level.DEBUG,
}

#: The order the UI lists levels in: worst first.
LEVEL_ORDER: tuple[Level, ...] = (
    Level.CRITICAL, Level.ERROR, Level.WARNING, Level.NOTICE,
    Level.INFO, Level.DEBUG, Level.TRACE, Level.UNKNOWN,
)


# ---------------------------------------------------------------------------
# One parsed line
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Event:
    """One log line, after a format parser has had a look at it.

    ``slots`` because ingesting a million of these is a normal afternoon and
    a dict per instance would cost more than the parsing does.

    ``raw`` holds the original line only when it differs from ``message`` —
    for a plain unstructured log those are the same string and storing both
    would double the database for nothing.
    """

    #: Microseconds since the epoch (UTC), or None when the line has no time.
    timestamp: int | None = None
    level: Level = Level.UNKNOWN
    message: str = ""
    #: Whatever else the format knew: pid, thread, logger, method, status…
    extra: dict[str, Any] = field(default_factory=dict)
    #: 1-based line number within the file, for "show me this in context".
    line_number: int = 0
    raw: str | None = None

    @property
    def text(self) -> str:
        """The original line, reconstructed when it was not worth storing."""
        return self.raw if self.raw is not None else self.message

    def when(self) -> datetime | None:
        return from_epoch_us(self.timestamp)


# ---------------------------------------------------------------------------
# Result tables
# ---------------------------------------------------------------------------


class ColumnType(str, Enum):
    """The KQL scalar types Hunt supports. Deliberately fewer than Kusto's."""

    STRING = "string"
    LONG = "long"
    REAL = "real"
    BOOL = "bool"
    DATETIME = "datetime"
    TIMESPAN = "timespan"
    DYNAMIC = "dynamic"

    @property
    def title(self) -> str:
        return self.value

    @property
    def is_numeric(self) -> bool:
        return self in (ColumnType.LONG, ColumnType.REAL)

    @property
    def is_temporal(self) -> bool:
        return self in (ColumnType.DATETIME, ColumnType.TIMESPAN)


@dataclass(frozen=True, slots=True)
class Column:
    """One column of a table or a result, with the documentation for it."""

    name: str
    type: ColumnType = ColumnType.STRING
    description: str = ""

    def __str__(self) -> str:
        return f"{self.name}: {self.type.value}"


@dataclass(slots=True)
class QueryStats:
    """What the run cost, shown in the strip under the results.

    Every number here is measured, not estimated. ``scanned`` is how many rows
    SQLite handed up to the Python pipeline, which is the number that tells
    you whether the planner managed to push your filter down or whether it
    read the store and threw most of it away.
    """

    elapsed: float = 0.0
    rows: int = 0
    #: Rows SQLite handed to the pipeline. The gap between this and `rows` is
    #: how much work the planner failed to push down.
    scanned: int = 0
    truncated: bool = False
    #: The SQL the planner produced, for the Query details panel.
    sql: str = ""
    parameters: tuple = ()
    #: Which pipeline operators were pushed into SQL, in order.
    pushed_down: tuple[str, ...] = ()
    #: Which ones had to run in Python above it.
    evaluated: tuple[str, ...] = ()
    #: Set when the run stopped early because it hit a limit.
    note: str = ""

    def summary(self) -> str:
        """``247 rows · 43 ms · 1,203,455 events scanned``."""
        parts = [f"{self.rows:,} row{'' if self.rows == 1 else 's'}",
                 humanise_duration(self.elapsed)]
        if self.scanned:
            parts.append(f"{self.scanned:,} read from the store")
        if self.truncated:
            parts.append("truncated")
        return " · ".join(parts)


@dataclass(slots=True)
class ResultTable:
    """The answer to a query: named typed columns and a list of row tuples.

    Rows are tuples rather than dicts. A result of half a million rows is
    normal and a dict per row triples the memory for no gain — the column
    index is on the table, once.
    """

    columns: tuple[Column, ...] = ()
    rows: list[tuple] = field(default_factory=list)
    stats: QueryStats = field(default_factory=QueryStats)
    #: Set by the `render` operator: ("timechart", {"title": ...}).
    visualisation: tuple[str, dict] | None = None

    def __len__(self) -> int:
        return len(self.rows)

    def __iter__(self) -> Iterator[tuple]:
        return iter(self.rows)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(column.name for column in self.columns)

    @property
    def empty(self) -> bool:
        return not self.rows

    def index_of(self, name: str) -> int:
        """Position of a column by name, case-insensitively. -1 if absent."""
        lowered = name.lower()
        for position, column in enumerate(self.columns):
            if column.name.lower() == lowered:
                return position
        return -1

    def column(self, name: str) -> Column | None:
        position = self.index_of(name)
        return self.columns[position] if position >= 0 else None

    def value(self, row: int, name: str, default: Any = None) -> Any:
        position = self.index_of(name)
        if position < 0 or row >= len(self.rows):
            return default
        return self.rows[row][position]

    def to_dicts(self) -> list[dict[str, Any]]:
        """Rows as dictionaries. For exports and tests, not for the grid."""
        names = self.names
        return [dict(zip(names, row)) for row in self.rows]

    def column_values(self, name: str) -> list[Any]:
        position = self.index_of(name)
        if position < 0:
            return []
        return [row[position] for row in self.rows]

    @classmethod
    def of(cls, columns: Sequence[tuple[str, ColumnType]],
           rows: Sequence[Sequence[Any]]) -> "ResultTable":
        """Build one in a line, for tests and for small synthetic tables."""
        materialised = [tuple(row) for row in rows]
        return cls(
            columns=tuple(Column(name, kind) for name, kind in columns),
            rows=materialised,
            stats=QueryStats(rows=len(materialised)),
        )


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------

#: Microseconds in a second. Named because the conversions read badly without.
MICROSECONDS = 1_000_000


def to_epoch_us(moment: datetime) -> int:
    """A datetime to microseconds since the epoch, UTC.

    A naive datetime is read as local time, because an application that logs
    ``2026-08-31 08:20:07`` with no offset meant the clock on the wall.
    """
    if moment.tzinfo is None:
        moment = moment.astimezone()
    return int(moment.timestamp() * MICROSECONDS)


def from_epoch_us(value: int | float | None) -> datetime | None:
    """Microseconds since the epoch back to an aware UTC datetime."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return datetime.fromtimestamp(value / MICROSECONDS, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def now_us() -> int:
    return int(datetime.now(timezone.utc).timestamp() * MICROSECONDS)


def format_timestamp(value: int | datetime | None, *, local: bool = True,
                     precision: int = 3) -> str:
    """``2026-09-21 12:43:26.859`` — what the results grid shows.

    Displayed in local time by default. The stored value is always UTC; this
    is the only place the two are allowed to differ.
    """
    moment = from_epoch_us(value) if isinstance(value, int) else value
    if moment is None:
        return ""
    if local:
        moment = moment.astimezone()
    text = moment.strftime("%Y-%m-%d %H:%M:%S")
    if precision:
        fraction = f"{moment.microsecond / MICROSECONDS:.{precision}f}"[1:]
        text += fraction
    return text


def humanise_duration(seconds: float) -> str:
    """``43 ms``, ``1.24 s``, ``2 m 05 s`` — for the query status strip."""
    if seconds < 0:
        seconds = 0.0
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f} µs"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, remainder = divmod(int(seconds), 60)
    return f"{minutes} m {remainder:02d} s"


def humanise_bytes(count: float) -> str:
    """``1.4 MB``. Decimal units, because that is what disks are sold in."""
    if count is None:
        return ""
    value = float(count)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if abs(value) < 1000 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1000.0
    return f"{value:.1f} TB"


def humanise_count(count: int) -> str:
    """``1.2M`` — for axis labels and chips, where the comma form is too wide."""
    if count < 1000:
        return str(count)
    for limit, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1000, "k")):
        if count >= limit:
            scaled = count / limit
            return f"{scaled:.0f}{suffix}" if scaled >= 10 else f"{scaled:.1f}{suffix}"
    return str(count)


def humanise_age(moment: datetime | int | float | None) -> str:
    """``3 minutes ago``, ``yesterday``, ``never``.

    A number is microseconds since the epoch. Floats count — `os.stat` and
    `time.time` both produce them, and rejecting one only to hand it to
    subtraction later is a crash waiting for the first non-zero value.
    """
    when = (from_epoch_us(moment)
            if isinstance(moment, (int, float)) and not isinstance(moment, bool)
            else moment)
    if not isinstance(when, datetime):
        # Covers None, a bool, and anything else that reached here by
        # accident. Subtracting it from `now` would raise instead.
        return "never"
    delta = datetime.now(timezone.utc) - when
    seconds = delta.total_seconds()
    if seconds < 0:
        return "in the future"
    if seconds < 90:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} minutes ago"
    if seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hour{'' if hours == 1 else 's'} ago"
    days = int(seconds // 86400)
    if days == 1:
        return "yesterday"
    if days < 30:
        return f"{days} days ago"
    if days < 365:
        return f"{days // 30} month{'' if days // 30 == 1 else 's'} ago"
    return f"{days // 365} year{'' if days // 365 == 1 else 's'} ago"


def format_timespan(delta: timedelta) -> str:
    """A timedelta in Kusto's own notation: ``1.02:03:04.5``.

    Kusto prints timespans as ``[-][d.]hh:mm:ss[.fffffff]`` and so do we, so
    that a value copied out of a result can be pasted back into a query.
    """
    total = delta.total_seconds()
    sign = "-" if total < 0 else ""
    total = abs(total)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    whole = int(seconds)
    fraction = seconds - whole
    text = f"{int(hours):02d}:{int(minutes):02d}:{whole:02d}"
    if days:
        text = f"{int(days)}.{text}"
    if fraction > 1e-9:
        text += f"{fraction:.7f}"[1:].rstrip("0")
    return sign + text


def parse_timespan(text: str) -> timedelta | None:
    """``5m``, ``1.5h``, ``90s``, ``2d``, ``100ms`` to a timedelta.

    This is the *literal* form used in queries and in the time-range picker,
    not Kusto's ``time()`` function, which the parser handles separately.
    """
    body = text.strip().lower()
    if not body:
        return None
    for suffix, seconds in _TIMESPAN_UNITS:
        if body.endswith(suffix):
            number = body[: -len(suffix)].strip()
            try:
                return timedelta(seconds=float(number) * seconds)
            except ValueError:
                return None
    try:
        return timedelta(seconds=float(body))
    except ValueError:
        return None


#: Longest suffix first, or "m" would swallow "ms" and five minutes would
#: become five milliseconds.
_TIMESPAN_UNITS: tuple[tuple[str, float], ...] = (
    ("microseconds", 1e-6), ("microsecond", 1e-6),
    ("milliseconds", 1e-3), ("millisecond", 1e-3),
    ("seconds", 1.0), ("second", 1.0),
    ("minutes", 60.0), ("minute", 60.0),
    ("hours", 3600.0), ("hour", 3600.0),
    ("days", 86400.0), ("day", 86400.0),
    ("ticks", 1e-7), ("tick", 1e-7),
    ("micro", 1e-6), ("ms", 1e-3), ("us", 1e-6), ("µs", 1e-6),
    ("s", 1.0), ("m", 60.0), ("h", 3600.0), ("d", 86400.0),
)


@dataclass(frozen=True, slots=True)
class TimeRange:
    """The window the whole page is filtered to, as Sentinel does it.

    Either a rolling window (``last``) or two absolute instants. The rolling
    form is stored rather than resolved so that a saved query means "the last
    24 hours" forever rather than "the 24 hours before the day I saved it".
    """

    #: Rolling window, e.g. timedelta(hours=24). None means absolute.
    last: timedelta | None = None
    start: datetime | None = None
    end: datetime | None = None
    label: str = ""

    @classmethod
    def rolling(cls, delta: timedelta, label: str = "") -> "TimeRange":
        return cls(last=delta, label=label or f"Last {format_timespan(delta)}")

    @classmethod
    def everything(cls) -> "TimeRange":
        return cls(label="All time")

    @property
    def unbounded(self) -> bool:
        return self.last is None and self.start is None and self.end is None

    def bounds(self, now: datetime | None = None) -> tuple[int | None, int | None]:
        """Resolve to (start, end) in epoch microseconds. Either may be None."""
        moment = now or datetime.now(timezone.utc)
        if self.last is not None:
            return to_epoch_us(moment - self.last), None
        begin = to_epoch_us(self.start) if self.start else None
        finish = to_epoch_us(self.end) if self.end else None
        return begin, finish

    def describe(self) -> str:
        if self.label:
            return self.label
        if self.last is not None:
            return f"Last {format_timespan(self.last)}"
        if self.start and self.end:
            return f"{format_timestamp(self.start)} → {format_timestamp(self.end)}"
        if self.start:
            return f"Since {format_timestamp(self.start)}"
        if self.end:
            return f"Until {format_timestamp(self.end)}"
        return "All time"

    def to_dict(self) -> dict:
        return {
            "last_seconds": self.last.total_seconds() if self.last else None,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TimeRange":
        if not isinstance(data, dict):
            return cls.everything()
        seconds = data.get("last_seconds")
        return cls(
            last=timedelta(seconds=float(seconds)) if seconds else None,
            start=_iso(data.get("start")),
            end=_iso(data.get("end")),
            label=str(data.get("label") or ""),
        )


def _iso(text: Any) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text))
    except ValueError:
        return None


#: The presets the time-range picker offers, in order.
TIME_PRESETS: tuple[tuple[str, timedelta | None], ...] = (
    ("Last 5 minutes", timedelta(minutes=5)),
    ("Last 30 minutes", timedelta(minutes=30)),
    ("Last hour", timedelta(hours=1)),
    ("Last 4 hours", timedelta(hours=4)),
    ("Last 12 hours", timedelta(hours=12)),
    ("Last 24 hours", timedelta(days=1)),
    ("Last 48 hours", timedelta(days=2)),
    ("Last 7 days", timedelta(days=7)),
    ("Last 30 days", timedelta(days=30)),
    ("Last 90 days", timedelta(days=90)),
    ("All time", None),
)

DEFAULT_TIME_RANGE = TimeRange.rolling(timedelta(days=1), "Last 24 hours")


def nice_step(span_seconds: float, buckets: int = 60) -> timedelta:
    """A round bucket width for a timechart over `span_seconds`.

    Charts with 1.37-minute buckets are unreadable, so the span is divided and
    then rounded up to the next value a person would have chosen.
    """
    if span_seconds <= 0 or buckets <= 0:
        return timedelta(minutes=1)
    target = span_seconds / buckets
    for candidate in (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600,
                      7200, 10800, 21600, 43200, 86400, 172800, 604800):
        if target <= candidate:
            return timedelta(seconds=candidate)
    weeks = max(1, math.ceil(target / 604800))
    return timedelta(weeks=weeks)
