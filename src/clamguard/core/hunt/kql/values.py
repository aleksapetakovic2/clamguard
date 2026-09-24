"""The type system: what a value is, and what happens when two meet.

Kusto is dynamically typed with static-ish columns, which means most of the
interesting behaviour lives in the coercions. The rules implemented here, and
the reasons for them:

* **Null propagates through arithmetic and is false in a filter.** ``1 + null``
  is null; ``where X > 5`` does not match a row where X is null. This is what
  makes ``| where Timestamp > ago(1h)`` do the obvious thing on the two thirds
  of desktop log lines that carry no timestamp at all.
* **Comparison coerces numbers, never strings.** ``1 == "1"`` is false. A log
  field that arrived as text stays text until something converts it, because
  guessing is how a hunt quietly stops finding things.
* **Sorting needs a total order over mixed types**, since a dynamic column can
  hold anything. Values are ranked by type first and by value within a type,
  which is arbitrary but stable — and stable is the property a result grid
  needs.

One deliberate divergence from Kusto, documented in ``docs/KQL.md``: ``"a" +
"b"`` concatenates rather than returning null. Every person who types it means
concatenation, and returning null teaches them nothing.
"""

from __future__ import annotations

import json
import math
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any

from ..model import ColumnType, format_timespan, format_timestamp

#: Sort rank per type, so that a dynamic column holding numbers, strings and
#: nulls still has one defined order.
_RANK = {type(None): 0, bool: 1, int: 2, float: 2, datetime: 3,
         timedelta: 4, str: 5, list: 6, dict: 7}


def kind_of(value: Any) -> ColumnType:
    """Which KQL type a Python value represents."""
    if isinstance(value, bool):
        return ColumnType.BOOL
    if isinstance(value, int):
        return ColumnType.LONG
    if isinstance(value, float):
        return ColumnType.REAL
    if isinstance(value, datetime):
        return ColumnType.DATETIME
    if isinstance(value, timedelta):
        return ColumnType.TIMESPAN
    if isinstance(value, (list, dict)):
        return ColumnType.DYNAMIC
    return ColumnType.STRING


def infer_type(values) -> ColumnType:
    """The type of a column, from a sample of what is in it.

    A column of numbers with some nulls is a number column. A column with two
    different non-null types is dynamic, because nothing else is honest.
    """
    seen: set[ColumnType] = set()
    for value in values:
        if value is None:
            continue
        seen.add(kind_of(value))
        if len(seen) > 2:
            break
    if not seen:
        return ColumnType.STRING
    if len(seen) == 1:
        return seen.pop()
    if seen == {ColumnType.LONG, ColumnType.REAL}:
        return ColumnType.REAL
    return ColumnType.DYNAMIC


# ---------------------------------------------------------------------------
# Truth and comparison
# ---------------------------------------------------------------------------


def truthy(value: Any) -> bool:
    """Is this value a match, for `where` and for `and`/`or`?

    Null is false. So is an empty string and a zero — which Kusto only does
    for bool columns, but which is what every person writing
    ``| where Extra.retries`` intends.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, (list, dict)):
        return bool(value)
    if isinstance(value, timedelta):
        return value != timedelta(0)
    return True


def _numeric(value: Any) -> float | int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    return None


def compare(left: Any, right: Any) -> int | None:
    """-1, 0, 1 — or None when the two are not comparable.

    None is the Kusto answer for "this comparison has no truth value", and
    every caller turns it into False rather than into an error, so a query
    over a messy dynamic column filters rather than crashes.
    """
    if left is None or right is None:
        return None

    left_number, right_number = _numeric(left), _numeric(right)
    if left_number is not None and right_number is not None:
        if isinstance(left_number, float) and math.isnan(left_number):
            return None
        if isinstance(right_number, float) and math.isnan(right_number):
            return None
        return (left_number > right_number) - (left_number < right_number)

    if isinstance(left, datetime) and isinstance(right, datetime):
        left, right = _aware(left), _aware(right)
        return (left > right) - (left < right)

    if isinstance(left, timedelta) and isinstance(right, timedelta):
        return (left > right) - (left < right)

    if isinstance(left, str) and isinstance(right, str):
        return (left > right) - (left < right)

    if isinstance(left, (list, dict)) or isinstance(right, (list, dict)):
        return 0 if left == right else None

    return None


def equal(left: Any, right: Any, *, fold_case: bool = False) -> bool | None:
    """``==`` and ``=~``. None when the comparison has no meaning."""
    if left is None or right is None:
        return None
    if fold_case and isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    if isinstance(left, str) != isinstance(right, str):
        # A string never equals a number. Coercing here would make
        # `where Status == 200` silently match the text "200" from one log
        # format and not the integer from another, which is worse than a
        # visible mismatch.
        if isinstance(left, bool) or isinstance(right, bool):
            return bool(left) == bool(right)
        return False
    result = compare(left, right)
    return None if result is None else result == 0


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def sort_key(value: Any):
    """A key that gives mixed-type columns a total order."""
    rank = _RANK.get(type(value), 8)
    if value is None:
        return (0, 0.0, "")
    if isinstance(value, bool):
        return (1, float(value), "")
    if isinstance(value, (int, float)):
        number = float(value)
        return (2, 0.0 if math.isnan(number) else number, "")
    if isinstance(value, datetime):
        return (3, _aware(value).timestamp(), "")
    if isinstance(value, timedelta):
        return (4, value.total_seconds(), "")
    if isinstance(value, str):
        return (5, 0.0, value)
    return (rank, 0.0, json.dumps(value, sort_keys=True, default=str))


# ---------------------------------------------------------------------------
# Arithmetic
# ---------------------------------------------------------------------------


def add(left: Any, right: Any) -> Any:
    if left is None or right is None:
        return None
    if isinstance(left, datetime) and isinstance(right, timedelta):
        return _aware(left) + right
    if isinstance(left, timedelta) and isinstance(right, datetime):
        return _aware(right) + left
    if isinstance(left, timedelta) and isinstance(right, timedelta):
        return left + right
    if isinstance(left, str) or isinstance(right, str):
        # Documented divergence from Kusto, which returns null here.
        return to_string(left) + to_string(right)
    return _arith(left, right, lambda a, b: a + b)


def subtract(left: Any, right: Any) -> Any:
    if left is None or right is None:
        return None
    if isinstance(left, datetime) and isinstance(right, datetime):
        return _aware(left) - _aware(right)
    if isinstance(left, datetime) and isinstance(right, timedelta):
        return _aware(left) - right
    if isinstance(left, timedelta) and isinstance(right, timedelta):
        return left - right
    return _arith(left, right, lambda a, b: a - b)


def multiply(left: Any, right: Any) -> Any:
    if left is None or right is None:
        return None
    if isinstance(left, timedelta) and _numeric(right) is not None:
        return left * _numeric(right)
    if isinstance(right, timedelta) and _numeric(left) is not None:
        return right * _numeric(left)
    return _arith(left, right, lambda a, b: a * b)


def divide(left: Any, right: Any) -> Any:
    if left is None or right is None:
        return None
    if isinstance(left, timedelta) and isinstance(right, timedelta):
        return None if right.total_seconds() == 0 else (left / right)
    if isinstance(left, timedelta) and _numeric(right) is not None:
        divisor = _numeric(right)
        return None if divisor == 0 else left / divisor
    left_number, right_number = _numeric(left), _numeric(right)
    if left_number is None or right_number is None or right_number == 0:
        return None
    # Kusto divides two integers as integers.
    if isinstance(left_number, int) and isinstance(right_number, int):
        return left_number // right_number
    return left_number / right_number


def modulo(left: Any, right: Any) -> Any:
    left_number, right_number = _numeric(left), _numeric(right)
    if left_number is None or right_number is None or right_number == 0:
        return None
    return left_number % right_number


def negate(value: Any) -> Any:
    if isinstance(value, timedelta):
        return -value
    number = _numeric(value)
    return None if number is None else -number


def _arith(left: Any, right: Any, operation) -> Any:
    left_number, right_number = _numeric(left), _numeric(right)
    if left_number is None or right_number is None:
        return None
    try:
        return operation(left_number, right_number)
    except (ArithmeticError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------


def to_string(value: Any) -> str:
    """The text of a value, in the form the results grid shows."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return format_timestamp(value, local=False, precision=6)
    if isinstance(value, timedelta):
        return format_timespan(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if value.is_integer() and abs(value) < 1e16:
            return str(int(value))
        return repr(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, default=str, ensure_ascii=False)
    return str(value)


def to_long(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return None if math.isnan(value) or math.isinf(value) else int(value)
    if isinstance(value, timedelta):
        return int(value.total_seconds() * 10_000_000)      # Kusto ticks
    if isinstance(value, datetime):
        return int(_aware(value).timestamp() * 1_000_000)
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0) if text[:2].lower() in ("0x", "0b") else int(text)
        except ValueError:
            try:
                return int(float(text))
            except ValueError:
                return None
    return None


def to_real(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def to_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes", "on"):
            return True
        if lowered in ("false", "0", "no", "off", ""):
            return False
    return None


_TIMESTAMP_PATTERNS = (
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y",
)


def to_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _aware(value)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        # Microseconds since the epoch, which is how the store holds them.
        try:
            return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            moment = datetime.fromisoformat(text)
            return _aware(moment)
        except ValueError:
            pass
        for pattern in _TIMESTAMP_PATTERNS:
            try:
                return datetime.strptime(value.strip(), pattern).replace(
                    tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def to_timespan(value: Any) -> timedelta | None:
    from ..model import parse_timespan

    if value is None:
        return None
    if isinstance(value, timedelta):
        return value
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return timedelta(seconds=value / 10_000_000)        # Kusto ticks
    if isinstance(value, str):
        from .parser import parse_timespan_literal

        return parse_timespan_literal(value) or parse_timespan(value)
    return None


def to_dynamic(value: Any) -> Any:
    """Parse a JSON string; pass anything else through unchanged."""
    if isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text[0] in "[{" or text[0] in "\"-0123456789" or text in ("true", "false", "null"):
            try:
                return json.loads(text)
            except ValueError:
                return value
        return value
    return value


# ---------------------------------------------------------------------------
# Dynamic access
# ---------------------------------------------------------------------------


def member(target: Any, name: str) -> Any:
    """``Extra.pid``. Missing is null, never an error.

    Log records are irregular by nature, so asking for a field that half the
    rows do not have is normal usage rather than a mistake.
    """
    container = to_dynamic(target)
    if isinstance(container, dict):
        if name in container:
            return container[name]
        # Try the flattened form the ingester writes for nested JSON.
        for key, value in container.items():
            if key.lower() == name.lower():
                return value
        return None
    return None


def element(target: Any, key: Any) -> Any:
    """``Extra["pid"]`` and ``items[0]``, including negative indices."""
    container = to_dynamic(target)
    if isinstance(container, dict):
        return container.get(to_string(key))
    if isinstance(container, list):
        index = to_long(key)
        if index is None:
            return None
        if -len(container) <= index < len(container):
            return container[index]
        return None
    if isinstance(container, str):
        index = to_long(key)
        if index is not None and -len(container) <= index < len(container):
            return container[index]
    return None


# ---------------------------------------------------------------------------
# String operators
# ---------------------------------------------------------------------------

#: Kusto's `has` matches whole terms, where a term is a maximal run of
#: alphanumerics. `_` is deliberately a separator, matching Kusto and matching
#: what makes `Message has "error"` find "on_error".
_TERM_SPLIT = re.compile(r"[^0-9A-Za-z]+")


def terms(text: str) -> list[str]:
    return [piece for piece in _TERM_SPLIT.split(text) if piece]


def has_term(haystack: Any, needle: Any, *, case_sensitive: bool = False) -> bool:
    text, word = to_string(haystack), to_string(needle)
    if not word:
        return False
    if not case_sensitive:
        text, word = text.casefold(), word.casefold()
    wanted = terms(word)
    if not wanted:
        return False
    if len(wanted) == 1:
        return wanted[0] in terms(text)
    found = terms(text)
    span = len(wanted)
    return any(found[start:start + span] == wanted
               for start in range(len(found) - span + 1))


def has_prefix(haystack: Any, needle: Any, *, case_sensitive: bool = False) -> bool:
    text, word = to_string(haystack), to_string(needle)
    if not word:
        return False
    if not case_sensitive:
        text, word = text.casefold(), word.casefold()
    return any(piece.startswith(word) for piece in terms(text))


def has_suffix(haystack: Any, needle: Any, *, case_sensitive: bool = False) -> bool:
    text, word = to_string(haystack), to_string(needle)
    if not word:
        return False
    if not case_sensitive:
        text, word = text.casefold(), word.casefold()
    return any(piece.endswith(word) for piece in terms(text))


def contains(haystack: Any, needle: Any, *, case_sensitive: bool = False) -> bool:
    text, word = to_string(haystack), to_string(needle)
    if not case_sensitive:
        return word.casefold() in text.casefold()
    return word in text


def starts_with(haystack: Any, needle: Any, *, case_sensitive: bool = False) -> bool:
    text, word = to_string(haystack), to_string(needle)
    if not case_sensitive:
        return text.casefold().startswith(word.casefold())
    return text.startswith(word)


def ends_with(haystack: Any, needle: Any, *, case_sensitive: bool = False) -> bool:
    text, word = to_string(haystack), to_string(needle)
    if not case_sensitive:
        return text.casefold().endswith(word.casefold())
    return text.endswith(word)


def as_list(value: Any) -> list:
    """``has_any(...)`` accepts a dynamic array or a single value."""
    resolved = to_dynamic(value)
    if isinstance(resolved, list):
        return resolved
    return [value]
