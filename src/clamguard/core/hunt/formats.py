"""Recognising log formats, and turning their lines into events.

Desktop Linux has no log format. It has forty. On this machine alone: Discord
writes Abseil lines, Chromium writes ``[pid:tid:MMDD/HHMMSS.uuuuuu:LEVEL:…]``,
electron-log writes ``2026-08-31 08:20:07 [info]``, GitKraken writes JSON
Lines, opencode writes a level followed by logfmt pairs, pacman writes
``[ISO] [SUBSYS]``, Xorg writes seconds since server start, and Unity writes
no timestamp at all.

A format here is a *parser that admits when it does not match*. Detection is
therefore not a separate guess: we run every parser over a sample of the file
and keep the one that understood the most lines. That makes it impossible for
detection and parsing to disagree, which is the failure mode that produces a
table full of nulls.

Two things about the timestamps:

* **Formats that omit the year** (syslog, Chromium) take it from the file's
  modification time, stepping back a year when that would put the line in the
  future. It is a guess and it is labelled as one.
* **Naive timestamps are local.** The conversion caches the UTC offset per
  local hour, which is exact across daylight-saving transitions and turns one
  ``mktime`` per line into one per hour of logs. On a million-line file that
  is the difference between eight seconds and one.
"""

from __future__ import annotations

import calendar
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from typing import Any, Callable, Iterable, Iterator

from .model import Event, Level

#: Lines longer than this are truncated on the way in. A 40 MB single-line
#: JSON blob in a log file is not a log line, it is an accident, and holding
#: it in memory helps nobody.
MAX_LINE = 64 * 1024

#: A wrapped stack trace can be long; beyond this the continuation is cut and
#: the event says so, so one exception cannot become a 100 MB row.
MAX_CONTINUATION_LINES = 200
MAX_MESSAGE = 128 * 1024


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


@lru_cache(maxsize=8192)
def _local_offset(year: int, month: int, day: int, hour: int) -> int:
    """Seconds east of UTC for that local wall-clock hour.

    Keyed on the hour rather than the day because daylight saving changes on
    an hour boundary, so this is exact rather than merely fast. During the
    ambiguous repeated hour in autumn Python picks the first occurrence; being
    an hour out for those sixty minutes once a year is acceptable and is the
    reason the source records whether a format carried its own offset.
    """
    try:
        return int(datetime(year, month, day, hour).astimezone().utcoffset().total_seconds())
    except (ValueError, OverflowError, OSError):
        return 0


def epoch_us_local(year: int, month: int, day: int, hour: int, minute: int,
                   second: int, microsecond: int = 0) -> int | None:
    """Local wall-clock components to microseconds since the epoch, UTC."""
    try:
        base = calendar.timegm((year, month, day, hour, minute, second, 0, 1, -1))
    except (ValueError, OverflowError):
        return None
    return (base - _local_offset(year, month, day, hour)) * 1_000_000 + microsecond


def epoch_us_utc(year: int, month: int, day: int, hour: int, minute: int,
                 second: int, microsecond: int = 0, offset_seconds: int = 0) -> int | None:
    """The same, for a timestamp that carried its own UTC offset."""
    try:
        base = calendar.timegm((year, month, day, hour, minute, second, 0, 1, -1))
    except (ValueError, OverflowError):
        return None
    return (base - offset_seconds) * 1_000_000 + microsecond


def _fraction_us(text: str | None) -> int:
    """``.859`` or ``,123456`` or ``859`` to microseconds."""
    if not text:
        return 0
    digits = text.lstrip(".,")[:6]
    if not digits.isdigit():
        return 0
    return int(digits.ljust(6, "0"))


def _offset_seconds(text: str | None) -> int | None:
    """``+01:00``, ``-0500``, ``Z`` to seconds east of UTC. None if absent."""
    if not text:
        return None
    body = text.strip()
    if body in ("Z", "z", "UTC", "GMT"):
        return 0
    sign = 1
    if body[0] in "+-":
        sign = -1 if body[0] == "-" else 1
        body = body[1:]
    body = body.replace(":", "")
    if len(body) == 2:
        body += "00"
    if len(body) != 4 or not body.isdigit():
        return None
    return sign * (int(body[:2]) * 3600 + int(body[2:]) * 60)


_MONTH_NAMES = {name.lower(): number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
_MONTH_NAMES.update({name.lower(): number for number, name in enumerate(
    ("January", "February", "March", "April", "May", "June", "July",
     "August", "September", "October", "November", "December"), start=1)})


def month_number(name: str) -> int:
    return _MONTH_NAMES.get(name.strip().lower(), 0)


# ---------------------------------------------------------------------------
# Parse context
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParseContext:
    """What a parser needs to know that is not in the line itself.

    ``year`` and ``month`` describe when the file was last written, which is
    the only evidence available for formats that omit the year. ``header`` is
    the column list for CSV, sniffed at detection time.
    """

    year: int = 1970
    month: int = 12
    header: tuple[str, ...] = ()
    path: str = ""

    def year_for(self, month: int, day: int) -> int:
        """The year a ``Sep 21`` line most likely belongs to.

        A log file last written in January holding a line dated December is
        from the previous year, not eleven months in the future. One month of
        slack absorbs a clock that is slightly ahead.
        """
        if month == 0:
            return self.year
        return self.year - 1 if month > self.month + 1 else self.year

    def with_header(self, header: tuple[str, ...]) -> "ParseContext":
        return ParseContext(self.year, self.month, header, self.path)


def context_for(path: str = "", mtime: float | None = None,
                header: tuple[str, ...] = ()) -> ParseContext:
    """Build a context from a file's modification time."""
    when = datetime.fromtimestamp(mtime) if mtime else datetime.now()
    return ParseContext(year=when.year, month=when.month, header=header, path=path)


# ---------------------------------------------------------------------------
# The format registry
# ---------------------------------------------------------------------------

Parser = Callable[[str, ParseContext], Event | None]


@dataclass(frozen=True, slots=True)
class LogFormat:
    """One recognised way of writing a log line."""

    id: str
    title: str
    description: str
    parse: Parser
    #: Breaks ties when two formats understand the same proportion of a
    #: sample. Higher is more specific.
    priority: int = 0
    #: True when a line this parser rejects should be appended to the previous
    #: event — stack traces, pretty-printed JSON, wrapped messages.
    continuation: bool = True
    #: Shown in the Sources dialog so a misdetection is obvious.
    example: str = ""

    def understands(self, line: str, context: ParseContext) -> bool:
        return self.parse(line, context) is not None


_REGISTRY: dict[str, LogFormat] = {}
_ORDER: list[LogFormat] = []


def register(item: LogFormat) -> LogFormat:
    _REGISTRY[item.id] = item
    _ORDER.append(item)
    _ORDER.sort(key=lambda entry: -entry.priority)
    return item


def catalogue() -> tuple[LogFormat, ...]:
    """Every format, most specific first."""
    return tuple(_ORDER)


def get(format_id: str) -> LogFormat:
    """A format by id, falling back to the plain-text one."""
    return _REGISTRY.get(format_id, _REGISTRY["plain"])


def _event(timestamp: int | None, level: Level, message: str,
           extra: dict[str, Any] | None, line: str) -> Event:
    """Build an Event, storing the raw line only when it adds something."""
    text = message[:MAX_MESSAGE]
    return Event(
        timestamp=timestamp,
        level=level,
        message=text,
        extra=extra or {},
        raw=None if text == line else line[:MAX_MESSAGE],
    )


# ---------------------------------------------------------------------------
# JSON Lines
# ---------------------------------------------------------------------------

#: The keys applications use for the three things every log line has. Checked
#: in order, so an entry with both "msg" and "message" uses "message".
_MESSAGE_KEYS = ("message", "msg", "text", "log", "event", "description",
                 "short_message", "body", "@message")
_LEVEL_KEYS = ("level", "severity", "levelname", "loglevel", "lvl", "priority",
               "levelName", "log.level", "@level", "type")
_TIME_KEYS = ("timestamp", "time", "@timestamp", "ts", "datetime", "date",
              "asctime", "eventTime", "created", "start_time", "logged_at")


def _json_timestamp(value: Any) -> int | None:
    """A JSON time field to epoch microseconds, whatever shape it arrived in."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        # Heuristic on magnitude: seconds, milliseconds, microseconds or
        # nanoseconds since the epoch. The boundaries are decades apart, so
        # there is no realistic ambiguity for a log written this century.
        if number > 1e17:
            return int(number / 1000)
        if number > 1e14:
            return int(number)
        if number > 1e11:
            return int(number * 1000)
        if number > 1e8:
            return int(number * 1_000_000)
        return None
    if isinstance(value, str):
        return parse_iso8601(value)
    return None


_ISO = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
    r"([.,]\d{1,9})?\s*(Z|z|[+-]\d{2}:?\d{2})?")


def parse_iso8601(text: str) -> int | None:
    """An ISO-8601-ish timestamp anywhere at the start of `text`.

    Deliberately permissive: a space instead of ``T``, one to nine fractional
    digits, an optional offset. Anything stricter would reject half the logs
    on a real machine.
    """
    match = _ISO.match(text.strip())
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(match.group(index)) for index in range(1, 7))
    micro = _fraction_us(match.group(7))
    offset = _offset_seconds(match.group(8))
    if offset is None:
        return epoch_us_local(year, month, day, hour, minute, second, micro)
    return epoch_us_utc(year, month, day, hour, minute, second, micro, offset)


def _keep(key: str, value: Any, into: dict[str, Any]) -> None:
    """Store a field as it came, nesting and all.

    An earlier version flattened nested objects into ``http.status`` keys.
    That reads well until somebody writes ``Extra.http.status`` in a query:
    member access looks up ``http`` first, finds nothing, and the whole
    expression is null with no explanation. Keeping the structure makes the
    obvious query the working one.
    """
    into[key] = value


def parse_jsonl(line: str, context: ParseContext) -> Event | None:
    body = line.strip()
    if not body or body[0] != "{" or body[-1] != "}":
        return None
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None

    message = ""
    for key in _MESSAGE_KEYS:
        found = data.get(key)
        if isinstance(found, str) and found:
            message = found
            break
        if found is not None and not isinstance(found, (dict, list)):
            message = str(found)
            break

    level = Level.UNKNOWN
    for key in _LEVEL_KEYS:
        if key in data:
            level = Level.parse(data[key])
            if level is not Level.UNKNOWN:
                break

    timestamp = None
    for key in _TIME_KEYS:
        if key in data:
            timestamp = _json_timestamp(data[key])
            if timestamp is not None:
                break

    extra: dict[str, Any] = {}
    consumed = {key for key in _MESSAGE_KEYS if key in data and data[key] == message}
    for group, keys in (("time", _TIME_KEYS), ("level", _LEVEL_KEYS)):
        for key in keys:
            if key in data:
                consumed.add(key)
                break
    for key, value in data.items():
        if key in consumed:
            continue
        _keep(str(key), value, extra)

    if not message and extra:
        # A line with no recognised message key is still worth keeping; show
        # the JSON rather than an empty row.
        message = body
    return _event(timestamp, level, message, extra, line)


register(LogFormat(
    id="jsonl", title="JSON Lines", priority=100, parse=parse_jsonl,
    continuation=False,
    description="One JSON object per line. Used by Go services, structured "
                "loggers, and most modern CLI tools.",
    example='{"level":"warning","msg":"ending session","time":"2026-08-18T19:42:25Z"}',
))


# ---------------------------------------------------------------------------
# logfmt
# ---------------------------------------------------------------------------

_LOGFMT_PAIR = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|[^\s]*)')


def _logfmt_pairs(text: str) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for match in _LOGFMT_PAIR.finditer(text):
        key, value = match.group(1), match.group(2)
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        found[key] = value
    return found


def _consume_pairs(text: str) -> tuple[dict[str, Any], str]:
    """Split ``k=v k=v trailing words`` into the pairs and the leftover text."""
    pairs: dict[str, Any] = {}
    position = 0
    for match in _LOGFMT_PAIR.finditer(text):
        if match.start() > position and text[position:match.start()].strip():
            break
        key, value = match.group(1), match.group(2)
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        pairs[key] = value
        position = match.end()
    return pairs, text[position:].strip()


def parse_logfmt(line: str, context: ParseContext) -> Event | None:
    body = line.strip()
    if "=" not in body:
        return None
    # The pairs have to *start* the line and run contiguously. Scanning for
    # pairs anywhere would swallow lines like
    #   [Vulkan init] extensions: name=VK_KHR_surface [enabled=1, external=0]
    # which is prose with an equals sign in it, not a logfmt record.
    pairs, trailing = _consume_pairs(body)
    if len(pairs) < 2:
        return None
    if len(trailing) > len(body) * 0.5:
        return None

    message = trailing
    for key in _MESSAGE_KEYS:
        if key in pairs:
            message = str(pairs.pop(key))
            break
    level = Level.UNKNOWN
    for key in _LEVEL_KEYS:
        if key in pairs:
            level = Level.parse(pairs.pop(key))
            if level is not Level.UNKNOWN:
                break
    timestamp = None
    for key in _TIME_KEYS:
        if key in pairs:
            timestamp = _json_timestamp(pairs.pop(key))
            if timestamp is not None:
                break
    return _event(timestamp, level, message or body, dict(pairs), line)


register(LogFormat(
    id="logfmt", title="logfmt", priority=70, parse=parse_logfmt,
    continuation=False,
    description="Space-separated key=value pairs, quoted where needed.",
    example='time=2026-01-01T00:00:00Z level=info msg="request served" status=200',
))


# ---------------------------------------------------------------------------
# Level, timestamp, then logfmt pairs — opencode and friends
# ---------------------------------------------------------------------------

_LEVEL_FIRST = re.compile(
    r"^(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|FATAL|CRIT(?:ICAL)?)\s+"
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s*(\+\d+\w*)?\s*(.*)$", re.IGNORECASE)


def parse_level_first(line: str, context: ParseContext) -> Event | None:
    match = _LEVEL_FIRST.match(line)
    if match is None:
        return None
    level = Level.parse(match.group(1))
    timestamp = parse_iso8601(match.group(2))
    rest = match.group(4)
    pairs, message = _consume_pairs(rest)
    if match.group(3):
        pairs["elapsed"] = match.group(3)
    return _event(timestamp, level, message or rest, pairs, line)


register(LogFormat(
    id="level-logfmt", title="Level + logfmt", priority=85,
    parse=parse_level_first, continuation=False,
    description="A level, an ISO timestamp, key=value pairs and a message.",
    example="INFO  2026-01-31T17:12:33 +73ms service=server path=/event request",
))


# ---------------------------------------------------------------------------
# electron-log
# ---------------------------------------------------------------------------

_ELECTRON = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?"
    r"\s+\[([A-Za-z]+)\]\s*(.*)$")


def parse_electron(line: str, context: ParseContext) -> Event | None:
    match = _ELECTRON.match(line)
    if match is None:
        return None
    level = Level.parse(match.group(8))
    if level is Level.UNKNOWN:
        return None
    timestamp = epoch_us_local(
        int(match.group(1)), int(match.group(2)), int(match.group(3)),
        int(match.group(4)), int(match.group(5)), int(match.group(6)),
        _fraction_us(match.group(7)))
    return _event(timestamp, level, match.group(9), None, line)


register(LogFormat(
    id="electron", title="electron-log", priority=80, parse=parse_electron,
    description="Timestamp then a bracketed level. Electron applications: "
                "Claude, VS Code, LM Studio, CurseForge.",
    example="2026-08-31 08:20:07 [info] Starting app",
))


# ---------------------------------------------------------------------------
# [timestamp] [level] message
# ---------------------------------------------------------------------------

_BRACKET_LEVEL = re.compile(
    r"^\[(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?"
    r"\s*(Z|[+-]\d{2}:?\d{2})?\]\s*\[([A-Za-z]+)\s*\]\s*(.*)$")


def parse_bracket_level(line: str, context: ParseContext) -> Event | None:
    match = _BRACKET_LEVEL.match(line)
    if match is None:
        return None
    level = Level.parse(match.group(9))
    if level is Level.UNKNOWN:
        return None
    offset = _offset_seconds(match.group(8))
    parts = [int(match.group(index)) for index in range(1, 7)]
    micro = _fraction_us(match.group(7))
    timestamp = (epoch_us_local(*parts, micro) if offset is None
                 else epoch_us_utc(*parts, micro, offset))
    return _event(timestamp, level, match.group(10), None, line)


register(LogFormat(
    id="bracket-level", title="[time] [level]", priority=82,
    parse=parse_bracket_level,
    description="A bracketed timestamp followed by a bracketed level.",
    example="[2026-07-14 00:00:25.923] [info]  All conditions met",
))


# ---------------------------------------------------------------------------
# [timestamp]: Level: message   (Sunshine)
# ---------------------------------------------------------------------------

_BRACKET_COLON = re.compile(
    r"^\[(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\]:\s*"
    r"([A-Za-z]+):\s*(.*)$")


def parse_bracket_colon(line: str, context: ParseContext) -> Event | None:
    match = _BRACKET_COLON.match(line)
    if match is None:
        return None
    level = Level.parse(match.group(8))
    if level is Level.UNKNOWN:
        return None
    timestamp = epoch_us_local(
        *(int(match.group(index)) for index in range(1, 7)),
        _fraction_us(match.group(7)))
    return _event(timestamp, level, match.group(9), None, line)


register(LogFormat(
    id="bracket-colon", title="[time]: Level: message", priority=81,
    parse=parse_bracket_colon,
    description="Sunshine and several C++ daemons write this.",
    example="[2026-09-21 12:43:26.859]: Info: Sunshine version: 2026.914",
))


# ---------------------------------------------------------------------------
# Abseil / Discord
# ---------------------------------------------------------------------------

_ABSEIL = re.compile(
    r"^\[(\d{4})-([A-Za-z]{3})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?"
    r"\s*([+-]\d{2}:?\d{2})?\]"
    # Discord right-aligns the pid in a five-character field, so the brackets
    # can contain "[ 3670: 3670]" as well as "[12469:12469]".
    r"\[\s*(\d+):\s*(\d+)\]"
    r"\[([A-Za-z]+)\s*\]\s*(.*)$")


def parse_abseil(line: str, context: ParseContext) -> Event | None:
    match = _ABSEIL.match(line)
    if match is None:
        return None
    month = month_number(match.group(2))
    if not month:
        return None
    parts = (int(match.group(1)), month, int(match.group(3)),
             int(match.group(4)), int(match.group(5)), int(match.group(6)))
    micro = _fraction_us(match.group(7))
    offset = _offset_seconds(match.group(8))
    timestamp = (epoch_us_local(*parts, micro) if offset is None
                 else epoch_us_utc(*parts, micro, offset))
    extra = {"pid": int(match.group(9)), "tid": int(match.group(10))}
    return _event(timestamp, Level.parse(match.group(11)), match.group(12), extra, line)


register(LogFormat(
    id="abseil", title="Abseil", priority=90, parse=parse_abseil,
    description="Discord's native logs and other Abseil-based C++ programs.",
    example="[2026-Feb-19 13:40:38.726 +01:00][12469:12469][info ] Logging initialized",
))


# ---------------------------------------------------------------------------
# Chromium
# ---------------------------------------------------------------------------

_CHROMIUM = re.compile(
    r"^\[(\d+):(\d+):(\d{2})(\d{2})/(\d{2})(\d{2})(\d{2})\.(\d+):"
    r"([A-Z]+):([^\]]*?)\]\s*(.*)$")


def parse_chromium(line: str, context: ParseContext) -> Event | None:
    match = _CHROMIUM.match(line)
    if match is None:
        return None
    month, day = int(match.group(3)), int(match.group(4))
    if not 1 <= month <= 12 or not 1 <= day <= 31:
        return None
    timestamp = epoch_us_local(
        context.year_for(month, day), month, day,
        int(match.group(5)), int(match.group(6)), int(match.group(7)),
        _fraction_us(match.group(8)))
    extra: dict[str, Any] = {"pid": int(match.group(1)), "tid": int(match.group(2))}
    origin = match.group(10)
    if origin:
        extra["origin"] = origin
    return _event(timestamp, Level.parse(match.group(9)), match.group(11), extra, line)


register(LogFormat(
    id="chromium", title="Chromium", priority=92, parse=parse_chromium,
    description="Every Chromium-derived program: Chrome, Electron's native "
                "layer, Steam's embedded browser.",
    example="[19013:19013:0201/090818.844525:INFO:crash_reporting.cc(255)] enabled",
))


# ---------------------------------------------------------------------------
# pacman
# ---------------------------------------------------------------------------

_PACMAN = re.compile(
    r"^\[(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})([+-]\d{4}|Z)?\]\s*"
    r"\[([A-Z\-]+)\]\s*(.*)$")


def parse_pacman(line: str, context: ParseContext) -> Event | None:
    match = _PACMAN.match(line)
    if match is None:
        return None
    parts = [int(match.group(index)) for index in range(1, 7)]
    offset = _offset_seconds(match.group(7))
    timestamp = (epoch_us_local(*parts, 0) if offset is None
                 else epoch_us_utc(*parts, 0, offset))
    subsystem = match.group(8)
    message = match.group(9)
    level = Level.INFO
    lowered = message.lower()
    if lowered.startswith("warning"):
        level = Level.WARNING
    elif lowered.startswith("error"):
        level = Level.ERROR
    return _event(timestamp, level, message, {"subsystem": subsystem}, line)


register(LogFormat(
    id="pacman", title="pacman", priority=91, parse=parse_pacman,
    description="Arch Linux package transactions. The record of what was "
                "installed, upgraded and removed, and when.",
    example="[2026-01-31T13:10:07+0000] [ALPM] transaction started",
))


# ---------------------------------------------------------------------------
# Xorg
# ---------------------------------------------------------------------------

_XORG = re.compile(r"^\[\s*(\d+\.\d+)\]\s*(?:\((..)\)\s*)?(.*)$")

_XORG_MARKERS = {
    "EE": Level.ERROR, "WW": Level.WARNING, "II": Level.INFO,
    "NI": Level.NOTICE, "--": Level.DEBUG, "**": Level.NOTICE,
    "++": Level.DEBUG, "==": Level.DEBUG, "!!": Level.CRITICAL,
}


def parse_xorg(line: str, context: ParseContext) -> Event | None:
    match = _XORG.match(line)
    if match is None:
        return None
    marker = match.group(2)
    level = _XORG_MARKERS.get(marker or "", Level.UNKNOWN)
    if marker is not None and level is Level.UNKNOWN:
        return None
    # The number is seconds since the X server started, not since the epoch,
    # so there is no timestamp to record. The offset is kept as a field, which
    # is what the file is actually useful for.
    extra = {"uptime": float(match.group(1))}
    if marker:
        extra["marker"] = marker
    return _event(None, level, match.group(3), extra, line)


register(LogFormat(
    id="xorg", title="Xorg", priority=60, parse=parse_xorg,
    description="The X server's log. Its numbers are seconds since the server "
                "started, not wall-clock time, so these events have no "
                "timestamp — the offset is kept in Extra.uptime.",
    example="[    11.303] (EE) Failed to load module",
))


# ---------------------------------------------------------------------------
# syslog (RFC 3164 and RFC 5424)
# ---------------------------------------------------------------------------

_SYSLOG = re.compile(
    r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+"
    r"(\S+)\s+([\w\-./]+)(?:\[(\d+)\])?:\s*(.*)$")


def parse_syslog(line: str, context: ParseContext) -> Event | None:
    match = _SYSLOG.match(line)
    if match is None:
        return None
    month = month_number(match.group(1))
    if not month:
        return None
    day = int(match.group(2))
    timestamp = epoch_us_local(
        context.year_for(month, day), month, day,
        int(match.group(3)), int(match.group(4)), int(match.group(5)))
    extra: dict[str, Any] = {"host": match.group(6), "program": match.group(7)}
    if match.group(8):
        extra["pid"] = int(match.group(8))
    message = match.group(9)
    return _event(timestamp, _level_from_words(message), message, extra, line)


register(LogFormat(
    id="syslog", title="syslog (RFC 3164)", priority=75, parse=parse_syslog,
    description="The traditional format. No year, so it is taken from the "
                "file's modification date.",
    example="Sep 21 12:43:26 workstation sshd[1234]: Accepted publickey",
))


_SYSLOG_5424 = re.compile(
    r"^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:(\[.*?\]|-))?\s*(.*)$")


def parse_syslog5424(line: str, context: ParseContext) -> Event | None:
    match = _SYSLOG_5424.match(line)
    if match is None:
        return None
    priority = int(match.group(1))
    timestamp = parse_iso8601(match.group(3))
    extra = {
        "facility": priority // 8,
        "host": match.group(4),
        "program": match.group(5),
        "pid": match.group(6),
        "msgid": match.group(7),
    }
    return _event(timestamp, Level.parse(priority % 8), match.group(9), extra, line)


register(LogFormat(
    id="syslog5424", title="syslog (RFC 5424)", priority=95,
    parse=parse_syslog5424,
    description="The structured revision, with a priority and an ISO timestamp.",
    example="<34>1 2026-09-21T22:14:15.003Z host app 1234 ID47 - message",
))


# ---------------------------------------------------------------------------
# Python's logging module
# ---------------------------------------------------------------------------

_PYTHON = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s+"
    r"(?:\[([^\]]*)\]\s+)?"
    r"(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|CRITICAL|FATAL|EXCEPTION)\s+"
    r"([\w.\-]+)?\s*[:\-]?\s*(.*)$", re.IGNORECASE)


def parse_python(line: str, context: ParseContext) -> Event | None:
    match = _PYTHON.match(line)
    if match is None:
        return None
    timestamp = epoch_us_local(
        *(int(match.group(index)) for index in range(1, 7)),
        _fraction_us(match.group(7)))
    extra: dict[str, Any] = {}
    if match.group(8):
        extra["thread"] = match.group(8)
    if match.group(10):
        extra["logger"] = match.group(10)
    return _event(timestamp, Level.parse(match.group(9)), match.group(11), extra, line)


register(LogFormat(
    id="python", title="Python / log4j", priority=83, parse=parse_python,
    description="Timestamp, optional thread, level, logger name, message. "
                "Python's logging module and most JVM loggers.",
    example="2026-09-21 11:02:03,123 [main] INFO clamguard.scanner: scan started",
))


# ---------------------------------------------------------------------------
# Go's standard logger
# ---------------------------------------------------------------------------

_GO = re.compile(
    r"^(\d{4})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s+(.*)$")


def parse_go(line: str, context: ParseContext) -> Event | None:
    match = _GO.match(line)
    if match is None:
        return None
    timestamp = epoch_us_local(
        *(int(match.group(index)) for index in range(1, 7)),
        _fraction_us(match.group(7)))
    message = match.group(8)
    return _event(timestamp, _level_from_words(message), message, None, line)


register(LogFormat(
    id="go", title="Go standard logger", priority=55, parse=parse_go,
    description="Slash-separated date then time. Go's log package default.",
    example="2026/09/21 11:02:03 listening on :8080",
))


# ---------------------------------------------------------------------------
# nginx error log
# ---------------------------------------------------------------------------

_NGINX = re.compile(
    r"^(\d{4})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s+"
    r"\[(\w+)\]\s+(\d+)#(\d+):\s*(.*)$")


def parse_nginx_error(line: str, context: ParseContext) -> Event | None:
    match = _NGINX.match(line)
    if match is None:
        return None
    timestamp = epoch_us_local(*(int(match.group(index)) for index in range(1, 7)))
    extra = {"pid": int(match.group(8)), "tid": int(match.group(9))}
    return _event(timestamp, Level.parse(match.group(7)), match.group(10), extra, line)


register(LogFormat(
    id="nginx-error", title="nginx error log", priority=88,
    parse=parse_nginx_error,
    description="nginx's error log, with the worker process and thread.",
    example="2026/09/21 11:02:03 [error] 1234#0: *1 open() failed",
))


# ---------------------------------------------------------------------------
# Apache / nginx access logs
# ---------------------------------------------------------------------------

_ACCESS = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)'
    r'(?:\s+"([^"]*)"\s+"([^"]*)")?')

_CLF_TIME = re.compile(
    r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?")


def parse_access_log(line: str, context: ParseContext) -> Event | None:
    match = _ACCESS.match(line)
    if match is None:
        return None
    stamp = _CLF_TIME.match(match.group(4))
    timestamp = None
    if stamp is not None:
        month = month_number(stamp.group(2))
        if month:
            parts = (int(stamp.group(3)), month, int(stamp.group(1)),
                     int(stamp.group(4)), int(stamp.group(5)), int(stamp.group(6)))
            offset = _offset_seconds(stamp.group(7))
            timestamp = (epoch_us_local(*parts) if offset is None
                         else epoch_us_utc(*parts, 0, offset))

    status = int(match.group(6))
    request = match.group(5).split()
    extra: dict[str, Any] = {
        "client": match.group(1),
        "user": match.group(3) if match.group(3) != "-" else None,
        "status": status,
        "method": request[0] if request else "",
        "path": request[1] if len(request) > 1 else "",
        "protocol": request[2] if len(request) > 2 else "",
    }
    size = match.group(7)
    extra["size"] = int(size) if size.isdigit() else 0
    if match.group(8):
        extra["referer"] = match.group(8)
    if match.group(9):
        extra["agent"] = match.group(9)

    level = Level.INFO
    if status >= 500:
        level = Level.ERROR
    elif status >= 400:
        level = Level.WARNING
    message = f"{extra['method']} {extra['path']} {status}".strip()
    return _event(timestamp, level, message, extra, line)


register(LogFormat(
    id="access-log", title="HTTP access log", priority=89,
    parse=parse_access_log, continuation=False,
    description="Apache common and combined, and nginx's default. The status "
                "code sets the level, so 5xx responses show up as errors.",
    example='127.0.0.1 - - [21/Sep/2026:11:02:03 +0200] "GET / HTTP/1.1" 200 612',
))


# ---------------------------------------------------------------------------
# npm's debug log
# ---------------------------------------------------------------------------

_NPM = re.compile(r"^(\d+)\s+(silly|verbose|info|timing|http|notice|warn|error)\s+(.*)$")


def parse_npm(line: str, context: ParseContext) -> Event | None:
    match = _NPM.match(line)
    if match is None:
        return None
    return _event(None, Level.parse(match.group(2)), match.group(3),
                  {"seq": int(match.group(1))}, line)


register(LogFormat(
    id="npm", title="npm debug log", priority=65, parse=parse_npm,
    continuation=False,
    description="npm's failure logs. Numbered rather than timestamped, so the "
                "events take their time from the file.",
    example="0 verbose cli /usr/bin/node /usr/bin/npm",
))


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def parse_csv(line: str, context: ParseContext) -> Event | None:
    if not context.header or "," not in line:
        return None
    values = _split_csv(line.rstrip("\n"))
    if len(values) != len(context.header):
        return None
    data = dict(zip(context.header, values))
    message = ""
    for key in _MESSAGE_KEYS:
        for name, value in data.items():
            if name.lower() == key:
                message = value
                data.pop(name)
                break
        if message:
            break
    level = Level.UNKNOWN
    for key in _LEVEL_KEYS:
        for name in list(data):
            if name.lower() == key:
                level = Level.parse(data.pop(name))
                break
        if level is not Level.UNKNOWN:
            break
    timestamp = None
    for key in _TIME_KEYS:
        for name in list(data):
            if name.lower() == key:
                timestamp = _json_timestamp(data.pop(name))
                break
        if timestamp is not None:
            break
    return _event(timestamp, level, message or line.strip(), data, line)


def _split_csv(line: str) -> list[str]:
    """A small CSV splitter. `csv.reader` per line costs more than this does."""
    values: list[str] = []
    current: list[str] = []
    quoted = False
    index = 0
    while index < len(line):
        char = line[index]
        if quoted:
            if char == '"':
                if index + 1 < len(line) and line[index + 1] == '"':
                    current.append('"')
                    index += 1
                else:
                    quoted = False
            else:
                current.append(char)
        elif char == '"':
            quoted = True
        elif char == ",":
            values.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    values.append("".join(current))
    return values


register(LogFormat(
    id="csv", title="CSV", priority=50, parse=parse_csv, continuation=False,
    description="Comma-separated, with the column names on the first line.",
    example="timestamp,level,message",
))


# ---------------------------------------------------------------------------
# A timestamp and then whatever
# ---------------------------------------------------------------------------

_LEVEL_WORD = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRITICAL|CRIT|FATAL|"
    r"EMERG|ALERT|PANIC|EXCEPTION|FAILED|FAILURE)\b", re.IGNORECASE)


def _level_from_words(text: str) -> Level:
    """Find a level word in the first part of a message.

    Only the first eighty characters are searched: a message that mentions the
    word "error" halfway through a sentence is not necessarily an error, but a
    line that opens with it almost always is.
    """
    match = _LEVEL_WORD.search(text[:80])
    return Level.parse(match.group(1)) if match else Level.UNKNOWN


# ---------------------------------------------------------------------------
# The systemd journal, as exported by `journalctl -o json`
# ---------------------------------------------------------------------------

#: ANSI CSI escapes. Programs that colour their output write these into the
#: journal verbatim, and journald hands the message back as a byte array
#: because it is no longer plain text. Kept out of `message` so the grid shows
#: words rather than `[2m[32m`, and kept in `raw` so nothing is lost.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


#: journald's own fields, in the order the unit name is looked for. A user
#: unit loses to a system unit because the system one is more specific about
#: what actually ran.
JOURNAL_UNIT_KEYS = ("_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT",
                     "SYSLOG_IDENTIFIER", "_COMM")

#: Everything else worth keeping out of a journal entry, mapped to the name it
#: gets in `Extra`. journald's underscored names are an implementation detail
#: nobody should have to type in a query.
JOURNAL_EXTRA_KEYS = {
    "_SYSTEMD_UNIT": "unit",
    "_SYSTEMD_USER_UNIT": "user_unit",
    "SYSLOG_IDENTIFIER": "identifier",
    "_COMM": "comm",
    "_PID": "pid",
    "_UID": "uid",
    "_GID": "gid",
    "_TRANSPORT": "transport",
    "_HOSTNAME": "host",
    "_BOOT_ID": "boot",
    "_AUDIT_SESSION": "audit_session",
    "_AUDIT_LOGINUID": "audit_loginuid",
    "CODE_FILE": "code_file",
    "CODE_LINE": "code_line",
    "CODE_FUNC": "code_func",
    "ERRNO": "errno",
    "UNIT": "about_unit",
    "JOB_TYPE": "job_type",
}


def journal_message(value: Any) -> str:
    """journald's MESSAGE, which is not always a string.

    In a 20,000-entry sample on a real machine: 19,973 strings, 26 lists of
    integers and one null. The lists are raw bytes, used whenever the message
    is not valid UTF-8 — in practice, whenever it contains colour escapes.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        try:
            return bytes(bytearray(int(byte) & 0xFF for byte in value)).decode(
                "utf-8", "replace")
        except (TypeError, ValueError):
            return ""
    return str(value)


def journal_unit(data: dict) -> str:
    """Which unit or program wrote an entry, for the App column."""
    for key in JOURNAL_UNIT_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "journal"


def parse_journal(line: str, context: ParseContext) -> Event | None:
    """One line of ``journalctl --output=json``.

    Registered as an ordinary format, which means a saved
    ``journalctl -o json > dump.json`` is recognised and indexed like any
    other file — the live reader in :mod:`journal` and a dump on disk go
    through exactly the same parser.
    """
    body = line.strip()
    if not body or body[0] != "{":
        return None
    if "__REALTIME_TIMESTAMP" not in body and "__CURSOR" not in body:
        return None
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or "__CURSOR" not in data:
        return None

    timestamp = None
    raw_time = data.get("__REALTIME_TIMESTAMP")
    if raw_time is not None:
        try:
            timestamp = int(raw_time)
        except (TypeError, ValueError):
            timestamp = None

    message = journal_message(data.get("MESSAGE"))
    cleaned = strip_ansi(message)

    extra: dict[str, Any] = {}
    for key, name in JOURNAL_EXTRA_KEYS.items():
        value = data.get(key)
        if value is None or value == "":
            continue
        extra[name] = journal_message(value) if isinstance(value, list) else value

    event = Event(timestamp=timestamp, level=Level.parse(data.get("PRIORITY")),
                  message=cleaned[:MAX_MESSAGE], extra=extra)
    if cleaned != message:
        event.raw = message[:MAX_MESSAGE]
    return event


register(LogFormat(
    # Above `jsonl`, which also understands these lines: a journal entry is
    # valid JSON Lines, so the tie has to be broken deliberately. The reverse
    # cannot happen — parse_journal refuses anything without a __CURSOR.
    id="journal", title="systemd journal", priority=105, parse=parse_journal,
    continuation=False,
    description="One JSON object per journal entry, as `journalctl -o json` "
                "writes them. Hunt reads the live journal through this same "
                "parser, so a saved export is indexed identically.",
    example='{"__CURSOR":"s=1;i=2;b=3;m=4;t=5;x=6",'
            '"__REALTIME_TIMESTAMP":"1790041532996399","PRIORITY":"4",'
            '"MESSAGE":"a password is required","_SYSTEMD_UNIT":"sudo.service"}',
))


def parse_timestamped(line: str, context: ParseContext) -> Event | None:
    """Anything that opens with an ISO-8601 timestamp."""
    body = line.lstrip()
    if len(body) < 19 or not body[:4].isdigit():
        return None
    match = _ISO.match(body)
    if match is None:
        return None
    timestamp = parse_iso8601(body)
    if timestamp is None:
        return None
    message = body[match.end():].lstrip(" \t:-|")
    return _event(timestamp, _level_from_words(message), message, None, line)


register(LogFormat(
    id="timestamped", title="Timestamp first", priority=20,
    parse=parse_timestamped,
    description="An ISO-8601 timestamp and then free text. The fallback for "
                "anything that at least says when it happened.",
    example="2026-09-21T11:02:03.123Z something happened",
))


def parse_plain(line: str, context: ParseContext) -> Event | None:
    """Never rejects. The format of last resort."""
    return _event(None, _level_from_words(line), line.rstrip("\n"), None, line.rstrip("\n"))


register(LogFormat(
    id="plain", title="Plain text", priority=-100, parse=parse_plain,
    continuation=False,
    description="No recognised structure. Every line becomes an event with no "
                "timestamp, ordered by where it sits in the file. Unity's "
                "Player.log and most game logs land here.",
    example="Mono path[0] = '/usr/lib/mono'",
))


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

#: How many lines of a file to sample. Enough to be sure, few enough to be
#: instant on a 2 GB file.
SAMPLE_LINES = 80

#: Below this proportion of understood lines a format is not considered a
#: match at all, however much better it is than the others.
MIN_CONFIDENCE = 0.55


@dataclass(slots=True)
class Detection:
    """Which format a file is, how sure we are, and what else was close."""

    format: LogFormat
    confidence: float = 0.0
    header: tuple[str, ...] = ()
    runners_up: tuple[tuple[str, float], ...] = ()
    sampled: int = 0

    @property
    def certain(self) -> bool:
        return self.confidence >= 0.9

    def describe(self) -> str:
        if self.format.id == "plain":
            return "Plain text — no structure recognised"
        return f"{self.format.title} — {self.confidence * 100:.0f}% of the sample"


def detect(lines: Iterable[str], context: ParseContext | None = None) -> Detection:
    """Work out which format wrote these lines.

    Every parser is run over the sample and the one that understood the most
    wins, with ``priority`` breaking ties in favour of the more specific. This
    is O(formats x sample) — about twenty regex matches over eighty lines,
    which is a fraction of a millisecond.
    """
    context = context or ParseContext(year=datetime.now().year)
    sample = [line for line in lines if line.strip()][:SAMPLE_LINES]
    if not sample:
        return Detection(get("plain"), 0.0)

    header = _sniff_header(sample)
    if header:
        context = context.with_header(header)
        sample = sample[1:] or sample

    wrapped = [_looks_like_continuation(line) for line in sample]
    scores: list[tuple[float, int, LogFormat]] = []
    for item in _ORDER:
        if item.id == "plain":
            continue
        if item.id == "csv" and not header:
            continue
        understood = 0
        counted = 0
        for line, is_wrapped in zip(sample, wrapped):
            try:
                matched = item.parse(line, context) is not None
            except Exception:  # noqa: BLE001 - a broken parser must not stop detection
                matched = False
            if matched:
                understood += 1
                counted += 1
            elif not (item.continuation and is_wrapped):
                # A format that joins continuations is not penalised for the
                # indented body of a pretty-printed JSON object or a stack
                # trace, which is exactly what it is designed to absorb.
                counted += 1
        if understood:
            scores.append((understood / max(1, counted), item.priority, item))

    scores.sort(key=lambda entry: (-entry[0], -entry[1]))
    runners = tuple((item.id, round(score, 3)) for score, _priority, item in scores[:4])

    if scores and scores[0][0] >= MIN_CONFIDENCE:
        best = scores[0]
        return Detection(best[2], best[0], header, runners, len(sample))
    return Detection(get("plain"), scores[0][0] if scores else 0.0, header,
                     runners, len(sample))


#: The opening characters of a line that is plainly the continuation of the
#: one before it: an indented object body, a closing bracket, a stack frame.
_CONTINUATION_PREFIXES = ("}", "]", ")", ",", "at ", "...", "Caused by:", "|")


def _looks_like_continuation(line: str) -> bool:
    if not line[:1].strip():
        return True
    stripped = line.lstrip()
    return any(stripped.startswith(prefix) for prefix in _CONTINUATION_PREFIXES)


_HEADER_WORD = re.compile(r"^[A-Za-z_][\w \-.]*$")


def _sniff_header(sample: list[str]) -> tuple[str, ...]:
    """Is the first line a CSV header? Only then is the csv parser offered."""
    if len(sample) < 3:
        return ()
    first = sample[0].rstrip("\n")
    if first.count(",") < 2 or '"' in first:
        return ()
    names = [part.strip() for part in first.split(",")]
    if not all(name and _HEADER_WORD.match(name) for name in names):
        return ()
    width = len(names)
    matching = sum(1 for line in sample[1:6] if len(_split_csv(line.rstrip("\n"))) == width)
    if matching < min(3, len(sample) - 1):
        return ()
    return tuple(names)


# ---------------------------------------------------------------------------
# Reading a whole file
# ---------------------------------------------------------------------------


def parse_lines(lines: Iterable[str], item: LogFormat,
                context: ParseContext | None = None,
                start_line: int = 1) -> Iterator[Event]:
    """Turn an iterable of raw lines into events, joining continuations.

    A line the parser rejects is appended to the previous event when the
    format says so, which is how a Java stack trace or a pretty-printed JSON
    body stays attached to the message that introduced it instead of becoming
    forty events with no timestamp.
    """
    context = context or ParseContext(year=datetime.now().year)
    parse = item.parse
    joins = item.continuation
    pending: Event | None = None
    pending_extra = 0
    number = start_line - 1

    for raw in lines:
        number += 1
        line = raw.rstrip("\n\r")
        if len(line) > MAX_LINE:
            line = line[:MAX_LINE] + " …[truncated]"
        if not line.strip():
            continue

        try:
            event = parse(line, context)
        except Exception:  # noqa: BLE001 - one bad line must not stop a file
            event = None

        if event is not None:
            if pending is not None:
                yield pending
            event.line_number = number
            pending, pending_extra = event, 0
            continue

        if joins and pending is not None:
            if pending_extra < MAX_CONTINUATION_LINES:
                addition = "\n" + line
                if len(pending.message) + len(addition) <= MAX_MESSAGE:
                    if pending.raw is None:
                        pending.raw = pending.message
                    pending.message += addition
                    pending.raw += addition
                pending_extra += 1
            elif pending_extra == MAX_CONTINUATION_LINES:
                pending.message += f"\n…[{MAX_CONTINUATION_LINES}+ more lines]"
                pending_extra += 1
            continue

        fallback = parse_plain(line, context)
        if fallback is not None:
            if pending is not None:
                yield pending
                pending = None
            fallback.line_number = number
            yield fallback

    if pending is not None:
        yield pending


def describe_formats() -> list[tuple[str, str, str, str]]:
    """(id, title, description, example) for the documentation panel."""
    return [(item.id, item.title, item.description, item.example)
            for item in sorted(_ORDER, key=lambda entry: entry.title.lower())]
