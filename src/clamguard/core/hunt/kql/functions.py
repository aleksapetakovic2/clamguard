"""The function library, and the documentation the Functions tab reads.

Two registries. :data:`SCALARS` map values to values, one row at a time.
:data:`AGGREGATES` are accumulator factories used by ``summarize``; they are
objects rather than functions over a list so that a summarize over a million
rows costs the size of its groups, not the size of its input.

Every entry carries its signature, a one-line summary and an example, because
the left rail lists them and a function nobody can find is a function nobody
uses.

A handful are marked "ClamGuard extension". They are not Kusto, they are
clearly labelled as not Kusto, and they exist because hunting through desktop
logs needs them: ``basename``, ``dirname`` and ``entropy``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import random
import re
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ..model import format_timespan
from . import values as V
from .errors import KqlError, did_you_mean

_MISSING = object()


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Function:
    """One scalar function, and everything the UI shows about it."""

    name: str
    signature: str
    summary: str
    category: str
    call: Callable[..., Any]
    min_args: int = 0
    max_args: int | None = 0
    example: str = ""
    extension: bool = False


@dataclass(frozen=True, slots=True)
class Aggregation:
    """One aggregate, as a factory for accumulators."""

    name: str
    signature: str
    summary: str
    factory: Callable[[], "Accumulator"]
    min_args: int = 0
    max_args: int | None = 0
    example: str = ""
    #: True for arg_max/arg_min, which may return several columns at once.
    projecting: bool = False


SCALARS: dict[str, Function] = {}
AGGREGATES: dict[str, Aggregation] = {}

#: Names the engine implements itself because they need the whole partition:
#: row_number, prev, next, row_cumsum.
WINDOW_FUNCTIONS: tuple[str, ...] = ("row_number", "prev", "next", "row_cumsum",
                                     "row_rank_dense")


def scalar(name: str, signature: str, summary: str, category: str,
           *, min_args: int = 1, max_args: int | None = None,
           example: str = "", extension: bool = False):
    """Register a scalar function. `max_args=None` means variadic."""
    def decorate(function):
        SCALARS[name] = Function(name, signature, summary, category, function,
                                 min_args, max_args, example, extension)
        return function
    return decorate


def aggregate(name: str, signature: str, summary: str,
              *, min_args: int = 0, max_args: int | None = 0,
              example: str = "", projecting: bool = False):
    def decorate(cls):
        AGGREGATES[name] = Aggregation(name, signature, summary, cls, min_args,
                                       max_args, example, projecting)
        return cls
    return decorate


def lookup(name: str, position: int = 0, length: int = 1, source: str = "") -> Function:
    """A scalar by name, or a KqlError that suggests what was meant."""
    found = SCALARS.get(name) or SCALARS.get(name.lower())
    if found is not None:
        return found
    if name.lower() in AGGREGATES:
        raise KqlError(
            f"`{name}()` is an aggregate function.", position, length,
            "It can only appear in `summarize`, or after `| summarize` has "
            "already grouped the rows.", source)
    if name.lower() in WINDOW_FUNCTIONS:
        raise KqlError(
            f"`{name}()` needs an ordered table.", position, length,
            "Put `| serialize` (or a `sort by`) in front of the operator that "
            "uses it.", source)
    raise KqlError(f"There is no function called `{name}`.", position, length,
                   did_you_mean(name, list(SCALARS) + list(AGGREGATES)), source)


def check_arity(function: Function, count: int, position: int = 0,
                source: str = "") -> None:
    if count < function.min_args or (function.max_args is not None
                                     and count > function.max_args):
        expected = (f"{function.min_args}" if function.max_args == function.min_args
                    else f"{function.min_args} or more" if function.max_args is None
                    else f"{function.min_args} to {function.max_args}")
        if function.max_args is not None and function.max_args < function.min_args:
            expected = f"{function.min_args} or more"
        raise KqlError(
            f"`{function.name}()` takes {expected} arguments, not {count}.",
            position, max(1, len(function.name)), function.signature, source)


def describe() -> list[Function | Aggregation]:
    """Everything, for the Functions tab, sorted by category then name."""
    order = {"string": 0, "numeric": 1, "datetime": 2, "dynamic": 3,
             "conditional": 4, "type": 5, "hash": 6, "network": 7,
             "aggregate": 8, "window": 9}
    items: list[Any] = list(SCALARS.values())
    return sorted(items, key=lambda item: (order.get(item.category, 99), item.name))


def categories() -> dict[str, list[Function]]:
    grouped: dict[str, list[Function]] = {}
    for item in SCALARS.values():
        grouped.setdefault(item.category, []).append(item)
    for entries in grouped.values():
        entries.sort(key=lambda item: item.name)
    return grouped


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------


@scalar("strcat", "strcat(a, b, ...)", "Joins its arguments into one string.",
        "string", min_args=1, example='strcat(App, ": ", Message)')
def _strcat(*args) -> str:
    return "".join(V.to_string(item) for item in args)


@scalar("strcat_delim", "strcat_delim(delimiter, a, b, ...)",
        "Joins its arguments with a separator between them.", "string",
        min_args=2, example='strcat_delim(" | ", App, Level, Message)')
def _strcat_delim(delimiter, *args) -> str:
    return V.to_string(delimiter).join(V.to_string(item) for item in args)


@scalar("strlen", "strlen(text)", "How many characters a string has.",
        "string", min_args=1, max_args=1, example="strlen(Message)")
def _strlen(text) -> int | None:
    return None if text is None else len(V.to_string(text))


@scalar("string_size", "string_size(text)", "How many bytes a string takes "
        "in UTF-8.", "string", min_args=1, max_args=1)
def _string_size(text) -> int | None:
    return None if text is None else len(V.to_string(text).encode("utf-8"))


@scalar("substring", "substring(text, start [, length])",
        "Part of a string. The first character is at 0.", "string",
        min_args=2, max_args=3, example='substring(Message, 0, 40)')
def _substring(text, start, length=None):
    if text is None:
        return None
    body = V.to_string(text)
    begin = V.to_long(start) or 0
    if begin < 0:
        begin = max(0, len(body) + begin)
    if length is None:
        return body[begin:]
    count = V.to_long(length)
    if count is None or count < 0:
        return ""
    return body[begin:begin + count]


@scalar("toupper", "toupper(text)", "Upper case.", "string",
        min_args=1, max_args=1)
def _toupper(text):
    return None if text is None else V.to_string(text).upper()


@scalar("tolower", "tolower(text)", "Lower case.", "string",
        min_args=1, max_args=1)
def _tolower(text):
    return None if text is None else V.to_string(text).lower()


@scalar("trim", "trim(pattern, text)",
        "Removes what a regular expression matches from both ends.", "string",
        min_args=1, max_args=2, example=r'trim(@"\s+", Message)')
def _trim(pattern, text=_MISSING):
    if text is _MISSING:
        return None if pattern is None else V.to_string(pattern).strip()
    return _trim_side(pattern, text, start=True, end=True)


@scalar("trim_start", "trim_start(pattern, text)",
        "Removes what a regular expression matches from the front.", "string",
        min_args=2, max_args=2)
def _trim_start(pattern, text):
    return _trim_side(pattern, text, start=True, end=False)


@scalar("trim_end", "trim_end(pattern, text)",
        "Removes what a regular expression matches from the end.", "string",
        min_args=2, max_args=2)
def _trim_end(pattern, text):
    return _trim_side(pattern, text, start=False, end=True)


def _trim_side(pattern, text, *, start: bool, end: bool):
    if text is None:
        return None
    body = V.to_string(text)
    expression = _compile(V.to_string(pattern))
    if expression is None:
        return body
    if start:
        match = expression.match(body)
        if match and match.end():
            body = body[match.end():]
    if end:
        matches = list(expression.finditer(body))
        if matches and matches[-1].end() == len(body) and matches[-1].start() < len(body):
            body = body[: matches[-1].start()]
    return body


@scalar("split", "split(text, delimiter [, index])",
        "Cuts a string into an array. With an index, returns one piece.",
        "string", min_args=2, max_args=3, example='split(Source, "/", -1)')
def _split(text, delimiter, index=None):
    if text is None:
        return None
    pieces = V.to_string(text).split(V.to_string(delimiter))
    if index is None:
        return pieces
    position = V.to_long(index)
    if position is None:
        return None
    return pieces[position] if -len(pieces) <= position < len(pieces) else None


@scalar("strrep", "strrep(text, count [, delimiter])",
        "Repeats a string.", "string", min_args=2, max_args=3)
def _strrep(text, count, delimiter=""):
    times = V.to_long(count) or 0
    if times <= 0:
        return ""
    return V.to_string(delimiter).join([V.to_string(text)] * min(times, 10_000))


@scalar("replace_string", "replace_string(text, find, replace)",
        "Replaces every occurrence of a plain string.", "string",
        min_args=3, max_args=3)
def _replace_string(text, find, replace):
    if text is None:
        return None
    return V.to_string(text).replace(V.to_string(find), V.to_string(replace))


@scalar("replace_regex", "replace_regex(text, pattern, replacement)",
        "Replaces what a regular expression matches. Use \\1 for groups.",
        "string", min_args=3, max_args=3,
        example=r'replace_regex(Message, @"\d+", "N")')
def _replace_regex(text, pattern, replacement):
    if text is None:
        return None
    expression = _compile(V.to_string(pattern))
    if expression is None:
        return V.to_string(text)
    try:
        return expression.sub(V.to_string(replacement).replace("\\0", "\\g<0>"),
                              V.to_string(text))
    except re.error:
        return V.to_string(text)


@scalar("indexof", "indexof(text, find [, start])",
        "Where a substring first appears, or -1.", "string",
        min_args=2, max_args=4)
def _indexof(text, find, start=0, _length=None):
    if text is None:
        return None
    return V.to_string(text).find(V.to_string(find), V.to_long(start) or 0)


@scalar("countof", "countof(text, pattern [, kind])",
        "How many times a substring or regular expression appears.", "string",
        min_args=2, max_args=3, example='countof(Message, "error")')
def _countof(text, pattern, kind="normal"):
    if text is None:
        return None
    body, needle = V.to_string(text), V.to_string(pattern)
    if V.to_string(kind) == "regex":
        expression = _compile(needle)
        return 0 if expression is None else len(expression.findall(body))
    return body.count(needle)


@scalar("extract", "extract(pattern, group, text)",
        "The nth capture group of a regular expression, or null.", "string",
        min_args=3, max_args=4,
        example=r'extract(@"pid=(\d+)", 1, Message)')
def _extract(pattern, group, text, _type=None):
    if text is None:
        return None
    expression = _compile(V.to_string(pattern))
    if expression is None:
        return None
    match = expression.search(V.to_string(text))
    if match is None:
        return None
    index = V.to_long(group) or 0
    try:
        return match.group(index)
    except (IndexError, re.error):
        return None


@scalar("extract_all", "extract_all(pattern, text)",
        "Every match of a regular expression, as an array.", "string",
        min_args=2, max_args=3,
        example=r'extract_all(@"\b\d+\.\d+\.\d+\.\d+\b", Message)')
def _extract_all(pattern, text, _third=None):
    body = text if _third is None else _third
    if body is None:
        return None
    expression = _compile(V.to_string(pattern))
    if expression is None:
        return []
    found = expression.findall(V.to_string(body))
    return [list(item) if isinstance(item, tuple) else item for item in found]


@scalar("reverse", "reverse(value)", "A string or array, backwards.",
        "string", min_args=1, max_args=1)
def _reverse(value):
    if value is None:
        return None
    resolved = V.to_dynamic(value)
    if isinstance(resolved, list):
        return list(reversed(resolved))
    return V.to_string(value)[::-1]


@scalar("strcmp", "strcmp(a, b)", "-1, 0 or 1, comparing two strings.",
        "string", min_args=2, max_args=2)
def _strcmp(left, right):
    a, b = V.to_string(left), V.to_string(right)
    return (a > b) - (a < b)


@scalar("url_decode", "url_decode(text)", "Percent-decodes a URL.",
        "string", min_args=1, max_args=1)
def _url_decode(text):
    return None if text is None else urllib.parse.unquote(V.to_string(text))


@scalar("url_encode", "url_encode(text)", "Percent-encodes a string.",
        "string", min_args=1, max_args=1)
def _url_encode(text):
    return None if text is None else urllib.parse.quote(V.to_string(text), safe="")


@scalar("base64_encode_tostring", "base64_encode_tostring(text)",
        "Base64 of a string's UTF-8 bytes.", "string", min_args=1, max_args=1)
def _base64_encode(text):
    if text is None:
        return None
    return base64.b64encode(V.to_string(text).encode("utf-8")).decode("ascii")


@scalar("base64_decode_tostring", "base64_decode_tostring(text)",
        "Decodes Base64 back to text, or null when it is not Base64.",
        "string", min_args=1, max_args=1,
        example="base64_decode_tostring(extract(@'-enc (\\S+)', 1, Message))")
def _base64_decode(text):
    if text is None:
        return None
    body = V.to_string(text).strip()
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None


@scalar("parse_url", "parse_url(url)",
        "Breaks a URL into scheme, host, path, port and query.", "dynamic",
        min_args=1, max_args=1, example='parse_url("https://a.test/x?y=1")')
def _parse_url(url):
    if url is None:
        return None
    parts = urllib.parse.urlsplit(V.to_string(url))
    try:
        # `.port` and `.hostname` parse the authority and raise on rubbish,
        # and a URL lifted out of a log line is frequently rubbish.
        host, port = parts.hostname or "", parts.port or ""
    except ValueError:
        host, port = parts.netloc, ""
    return {
        "Scheme": parts.scheme, "Host": host,
        "Port": port, "Path": parts.path,
        "Username": _safe_part(parts, "username"),
        "Password": _safe_part(parts, "password"),
        "Query Parameters": dict(urllib.parse.parse_qsl(parts.query)),
        "Fragment": parts.fragment,
    }


def _safe_part(parts, name: str) -> str:
    try:
        return getattr(parts, name) or ""
    except ValueError:
        return ""


@scalar("parse_urlquery", "parse_urlquery(query)",
        "A query string as a bag of parameters.", "dynamic",
        min_args=1, max_args=1)
def _parse_urlquery(query):
    if query is None:
        return None
    text = V.to_string(query)
    _, _, tail = text.partition("?")
    return {"Query Parameters": dict(urllib.parse.parse_qsl(tail or text))}


@scalar("parse_path", "parse_path(path)",
        "Breaks a filesystem path into its parts.", "dynamic",
        min_args=1, max_args=1, example="parse_path(Source)")
def _parse_path(path):
    if path is None:
        return None
    import posixpath

    text = V.to_string(path)
    directory, _, name = text.rpartition("/")
    stem, dot, extension = name.rpartition(".")
    return {
        "Scheme": "", "RootPath": "/" if text.startswith("/") else "",
        "DirectoryPath": directory, "DirectoryName": posixpath.basename(directory),
        "Filename": name, "Extension": extension if dot else "",
        "AlternateDataStreamName": "",
    }


@scalar("basename", "basename(path)",
        "The last component of a path. A ClamGuard extension, because every "
        "second query over logs wants it.", "string", min_args=1, max_args=1,
        example="basename(Source)", extension=True)
def _basename(path):
    if path is None:
        return None
    return V.to_string(path).rstrip("/").rpartition("/")[2]


@scalar("dirname", "dirname(path)",
        "Everything but the last component of a path. A ClamGuard extension.",
        "string", min_args=1, max_args=1, extension=True)
def _dirname(path):
    if path is None:
        return None
    head = V.to_string(path).rstrip("/").rpartition("/")[0]
    return head or "/"


@scalar("entropy", "entropy(text)",
        "Shannon entropy in bits per character. Around 4.5 and up means the "
        "string is random or encoded — a ClamGuard extension for spotting "
        "Base64 payloads and generated names.", "string",
        min_args=1, max_args=1,
        example='Logs | where entropy(Message) > 4.8', extension=True)
def _entropy(text):
    if text is None:
        return None
    body = V.to_string(text)
    if not body:
        return 0.0
    counts = Counter(body)
    total = len(body)
    return -sum((count / total) * math.log2(count / total)
                for count in counts.values())


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------


def _unary_number(name: str, signature: str, summary: str, operation):
    @scalar(name, signature, summary, "numeric", min_args=1, max_args=1)
    def _apply(value, _operation=operation):
        number = V.to_real(value)
        if number is None:
            return None
        try:
            return _operation(number)
        except (ValueError, OverflowError, ZeroDivisionError):
            return None
    return _apply


_unary_number("abs", "abs(x)", "Absolute value.", abs)
_unary_number("exp", "exp(x)", "e raised to x.", math.exp)
_unary_number("exp2", "exp2(x)", "2 raised to x.", lambda x: 2.0 ** x)
_unary_number("exp10", "exp10(x)", "10 raised to x.", lambda x: 10.0 ** x)
_unary_number("log", "log(x)", "Natural logarithm.", math.log)
_unary_number("log2", "log2(x)", "Base-2 logarithm.", math.log2)
_unary_number("log10", "log10(x)", "Base-10 logarithm.", math.log10)
_unary_number("sqrt", "sqrt(x)", "Square root.", math.sqrt)


@scalar("ceiling", "ceiling(x)", "Rounds up to a whole number.", "numeric",
        min_args=1, max_args=1)
def _ceiling(value):
    number = V.to_real(value)
    return None if number is None else int(math.ceil(number))


@scalar("floor", "floor(x [, roundTo])",
        "Rounds down — to a whole number, or to a multiple of roundTo.",
        "numeric", min_args=1, max_args=2)
def _floor(value, round_to=None):
    if round_to is not None:
        return _bin(value, round_to)
    number = V.to_real(value)
    return None if number is None else int(math.floor(number))


@scalar("round", "round(x [, precision])",
        "Rounds to a number of decimal places.", "numeric",
        min_args=1, max_args=2, example="round(avg_Duration, 2)")
def _round(value, precision=0):
    number = V.to_real(value)
    if number is None:
        return None
    digits = V.to_long(precision) or 0
    result = round(number, digits)
    return int(result) if digits <= 0 else result


@scalar("sign", "sign(x)", "-1, 0 or 1.", "numeric", min_args=1, max_args=1)
def _sign(value):
    number = V.to_real(value)
    if number is None:
        return None
    return (number > 0) - (number < 0)


@scalar("pow", "pow(base, exponent)", "base raised to exponent.", "numeric",
        min_args=2, max_args=2)
def _pow(base, exponent):
    left, right = V.to_real(base), V.to_real(exponent)
    if left is None or right is None:
        return None
    try:
        return left ** right
    except (ValueError, OverflowError, ZeroDivisionError):
        return None


@scalar("bin", "bin(value, roundTo)",
        "Rounds down to a multiple. The heart of every timechart.", "numeric",
        min_args=2, max_args=2,
        example="summarize count() by bin(Timestamp, 1h)")
def _bin(value, round_to):
    if value is None or round_to is None:
        return None
    if isinstance(value, datetime):
        step = V.to_timespan(round_to)
        if step is None or step.total_seconds() <= 0:
            return value
        seconds = step.total_seconds()
        stamp = value.timestamp()
        return datetime.fromtimestamp(math.floor(stamp / seconds) * seconds,
                                      tz=timezone.utc)
    if isinstance(value, timedelta):
        step = V.to_timespan(round_to)
        if step is None or step.total_seconds() <= 0:
            return value
        return timedelta(seconds=math.floor(value.total_seconds()
                                            / step.total_seconds())
                         * step.total_seconds())
    number, step = V.to_real(value), V.to_real(round_to)
    if number is None or step is None or step == 0:
        return None
    result = math.floor(number / step) * step
    if isinstance(value, int) and isinstance(round_to, int):
        return int(result)
    return result


@scalar("bin_at", "bin_at(value, roundTo, fixedPoint)",
        "Like bin(), but aligned to a point you choose rather than to the "
        "epoch.", "numeric", min_args=3, max_args=3,
        example="bin_at(Timestamp, 1d, datetime(2026-01-01))")
def _bin_at(value, round_to, fixed_point):
    if value is None:
        return None
    if isinstance(value, datetime):
        anchor = V.to_datetime(fixed_point)
        step = V.to_timespan(round_to)
        if anchor is None or step is None or step.total_seconds() <= 0:
            return value
        offset = (value - anchor).total_seconds()
        steps = math.floor(offset / step.total_seconds())
        return anchor + timedelta(seconds=steps * step.total_seconds())
    number = V.to_real(value)
    anchor = V.to_real(fixed_point)
    step = V.to_real(round_to)
    if None in (number, anchor, step) or step == 0:
        return None
    return anchor + math.floor((number - anchor) / step) * step


@scalar("rand", "rand([n])",
        "A random number: a real in [0,1), or a whole number below n.",
        "numeric", min_args=0, max_args=1)
def _rand(limit=None):
    if limit is None:
        return random.random()
    top = V.to_long(limit)
    return random.randrange(top) if top and top > 0 else 0


@scalar("max_of", "max_of(a, b, ...)", "The largest of its arguments.",
        "numeric", min_args=2)
def _max_of(*args):
    return _extreme(args, largest=True)


@scalar("min_of", "min_of(a, b, ...)", "The smallest of its arguments.",
        "numeric", min_args=2)
def _min_of(*args):
    return _extreme(args, largest=False)


def _extreme(args, *, largest: bool):
    present = [item for item in args if item is not None]
    if not present:
        return None
    return (max if largest else min)(present, key=V.sort_key)


@scalar("isnan", "isnan(x)", "True when a real number is not a number.",
        "numeric", min_args=1, max_args=1)
def _isnan(value):
    number = V.to_real(value)
    return number is not None and math.isnan(number)


@scalar("isinf", "isinf(x)", "True for positive or negative infinity.",
        "numeric", min_args=1, max_args=1)
def _isinf(value):
    number = V.to_real(value)
    return number is not None and math.isinf(number)


@scalar("isfinite", "isfinite(x)", "True for an ordinary number.", "numeric",
        min_args=1, max_args=1)
def _isfinite(value):
    number = V.to_real(value)
    return number is not None and math.isfinite(number)


def _bitwise(name: str, signature: str, summary: str, operation):
    @scalar(name, signature, summary, "numeric", min_args=2, max_args=2)
    def _apply(left, right, _operation=operation):
        a, b = V.to_long(left), V.to_long(right)
        return None if a is None or b is None else _operation(a, b)
    return _apply


_bitwise("binary_and", "binary_and(a, b)", "Bitwise AND.", lambda a, b: a & b)
_bitwise("binary_or", "binary_or(a, b)", "Bitwise OR.", lambda a, b: a | b)
_bitwise("binary_xor", "binary_xor(a, b)", "Bitwise XOR.", lambda a, b: a ^ b)
_bitwise("binary_shift_left", "binary_shift_left(a, n)", "a << n.",
         lambda a, b: a << max(0, min(b, 63)))
_bitwise("binary_shift_right", "binary_shift_right(a, n)", "a >> n.",
         lambda a, b: a >> max(0, min(b, 63)))


@scalar("binary_not", "binary_not(a)", "Bitwise NOT.", "numeric",
        min_args=1, max_args=1)
def _binary_not(value):
    number = V.to_long(value)
    return None if number is None else ~number


@scalar("bitset_count_ones", "bitset_count_ones(a)",
        "How many bits are set.", "numeric", min_args=1, max_args=1)
def _bitset_count_ones(value):
    number = V.to_long(value)
    return None if number is None else bin(abs(number)).count("1")


@scalar("tohex", "tohex(value [, width])", "A number in hexadecimal.",
        "numeric", min_args=1, max_args=2)
def _tohex(value, width=None):
    number = V.to_long(value)
    if number is None:
        return None
    text = format(number if number >= 0 else (1 << 64) + number, "x")
    size = V.to_long(width)
    return text.rjust(size, "0") if size else text


# ---------------------------------------------------------------------------
# Dates and times
# ---------------------------------------------------------------------------


@scalar("now", "now([offset])", "The current time, in UTC.", "datetime",
        min_args=0, max_args=1, example="now() - 1h")
def _now(offset=None):
    moment = datetime.now(timezone.utc)
    span = V.to_timespan(offset) if offset is not None else None
    return moment + span if span else moment


@scalar("ago", "ago(timespan)", "The time that long before now.", "datetime",
        min_args=1, max_args=1, example="where Timestamp > ago(1h)")
def _ago(span):
    delta = V.to_timespan(span)
    return None if delta is None else datetime.now(timezone.utc) - delta


@scalar("datetime_add", "datetime_add(part, amount, moment)",
        "Adds a number of seconds, minutes, hours, days, months or years.",
        "datetime", min_args=3, max_args=3,
        example='datetime_add("day", 7, Timestamp)')
def _datetime_add(part, amount, moment):
    when = V.to_datetime(moment)
    count = V.to_long(amount)
    if when is None or count is None:
        return None
    unit = V.to_string(part).lower().rstrip("s")
    if unit in _SIMPLE_UNITS:
        return when + timedelta(seconds=_SIMPLE_UNITS[unit] * count)
    if unit == "month":
        month = when.month - 1 + count
        year = when.year + month // 12
        month = month % 12 + 1
        day = min(when.day, _days_in_month(year, month))
        return when.replace(year=year, month=month, day=day)
    if unit == "year":
        try:
            return when.replace(year=when.year + count)
        except ValueError:
            return when.replace(year=when.year + count, day=28)
    if unit == "quarter":
        return _datetime_add("month", count * 3, when)
    return None


_SIMPLE_UNITS = {"microsecond": 1e-6, "millisecond": 1e-3, "second": 1.0,
                 "minute": 60.0, "hour": 3600.0, "day": 86400.0, "week": 604800.0}


def _days_in_month(year: int, month: int) -> int:
    import calendar

    return calendar.monthrange(year, month)[1]


@scalar("datetime_diff", "datetime_diff(part, later, earlier)",
        "How many whole units separate two times.", "datetime",
        min_args=3, max_args=3,
        example='datetime_diff("minute", now(), Timestamp)')
def _datetime_diff(part, later, earlier):
    end, start = V.to_datetime(later), V.to_datetime(earlier)
    if end is None or start is None:
        return None
    unit = V.to_string(part).lower().rstrip("s")
    if unit in _SIMPLE_UNITS:
        return int((end - start).total_seconds() / _SIMPLE_UNITS[unit])
    months = (end.year - start.year) * 12 + (end.month - start.month)
    if unit == "month":
        return months
    if unit == "quarter":
        return months // 3
    if unit == "year":
        return end.year - start.year
    return None


@scalar("datetime_part", "datetime_part(part, moment)",
        "One field of a time: year, month, day, hour, minute, second.",
        "datetime", min_args=2, max_args=2,
        example='datetime_part("hour", Timestamp)')
def _datetime_part(part, moment):
    when = V.to_datetime(moment)
    if when is None:
        return None
    unit = V.to_string(part).lower()
    return {
        "year": when.year, "quarter": (when.month - 1) // 3 + 1,
        "month": when.month, "week_of_year": when.isocalendar()[1],
        "day": when.day, "dayofyear": when.timetuple().tm_yday,
        "hour": when.hour, "minute": when.minute, "second": when.second,
        "millisecond": when.microsecond // 1000, "microsecond": when.microsecond,
        "nanosecond": when.microsecond * 1000,
    }.get(unit)


def _boundary(name: str, signature: str, summary: str, operation):
    @scalar(name, signature, summary, "datetime", min_args=1, max_args=2)
    def _apply(moment, offset=0, _operation=operation):
        when = V.to_datetime(moment)
        return None if when is None else _operation(when, V.to_long(offset) or 0)
    return _apply


def _start_of_day(when: datetime, offset: int) -> datetime:
    return (when + timedelta(days=offset)).replace(hour=0, minute=0, second=0,
                                                   microsecond=0)


def _start_of_week(when: datetime, offset: int) -> datetime:
    # Kusto's week starts on Sunday.
    day = _start_of_day(when, 0)
    return day - timedelta(days=(day.weekday() + 1) % 7) + timedelta(weeks=offset)


def _start_of_month(when: datetime, offset: int) -> datetime:
    month = when.month - 1 + offset
    year = when.year + month // 12
    return when.replace(year=year, month=month % 12 + 1, day=1, hour=0,
                        minute=0, second=0, microsecond=0)


def _start_of_year(when: datetime, offset: int) -> datetime:
    return when.replace(year=when.year + offset, month=1, day=1, hour=0,
                        minute=0, second=0, microsecond=0)


_boundary("startofday", "startofday(moment [, offset])",
          "Midnight at the start of that day.", _start_of_day)
_boundary("startofweek", "startofweek(moment [, offset])",
          "The Sunday that week began on.", _start_of_week)
_boundary("startofmonth", "startofmonth(moment [, offset])",
          "The first of that month.", _start_of_month)
_boundary("startofyear", "startofyear(moment [, offset])",
          "The first of January that year.", _start_of_year)
_boundary("endofday", "endofday(moment [, offset])",
          "The last microsecond of that day.",
          lambda when, offset: _start_of_day(when, offset + 1)
          - timedelta(microseconds=1))
_boundary("endofweek", "endofweek(moment [, offset])",
          "The last microsecond of that week.",
          lambda when, offset: _start_of_week(when, offset + 1)
          - timedelta(microseconds=1))
_boundary("endofmonth", "endofmonth(moment [, offset])",
          "The last microsecond of that month.",
          lambda when, offset: _start_of_month(when, offset + 1)
          - timedelta(microseconds=1))
_boundary("endofyear", "endofyear(moment [, offset])",
          "The last microsecond of that year.",
          lambda when, offset: _start_of_year(when, offset + 1)
          - timedelta(microseconds=1))


def _field(name: str, signature: str, summary: str, extract):
    @scalar(name, signature, summary, "datetime", min_args=1, max_args=1)
    def _apply(moment, _extract=extract):
        when = V.to_datetime(moment)
        return None if when is None else _extract(when)
    return _apply


_field("getyear", "getyear(moment)", "The year.", lambda when: when.year)
_field("getmonth", "getmonth(moment)", "The month, 1-12.", lambda when: when.month)
_field("dayofmonth", "dayofmonth(moment)", "The day of the month.",
       lambda when: when.day)
_field("dayofyear", "dayofyear(moment)", "The day of the year, 1-366.",
       lambda when: when.timetuple().tm_yday)
_field("hourofday", "hourofday(moment)", "The hour, 0-23. Useful for "
       "finding activity outside working hours.", lambda when: when.hour)
_field("monthofyear", "monthofyear(moment)", "The month, 1-12.",
       lambda when: when.month)
_field("weekofyear", "weekofyear(moment)", "The ISO week number.",
       lambda when: when.isocalendar()[1])


@scalar("dayofweek", "dayofweek(moment)",
        "How far into the week, as a timespan. 0d is Sunday.", "datetime",
        min_args=1, max_args=1, example="dayofweek(Timestamp) == 0d")
def _dayofweek(moment):
    when = V.to_datetime(moment)
    return None if when is None else timedelta(days=(when.weekday() + 1) % 7)


#: Kusto's .NET format specifiers, longest first, mapped onto strftime.
_FORMAT_PIECES = (
    ("yyyy", "%Y"), ("yy", "%y"), ("MMMM", "%B"), ("MMM", "%b"), ("MM", "%m"),
    ("dddd", "%A"), ("ddd", "%a"), ("dd", "%d"), ("HH", "%H"), ("hh", "%I"),
    ("mm", "%M"), ("ss", "%S"), ("tt", "%p"), ("zzz", "%z"),
)


@scalar("format_datetime", "format_datetime(moment, format)",
        "A time as text. Use yyyy, MM, dd, HH, mm, ss, fff.", "datetime",
        min_args=2, max_args=2,
        example='format_datetime(Timestamp, "yyyy-MM-dd HH:mm")')
def _format_datetime(moment, layout):
    when = V.to_datetime(moment)
    if when is None:
        return None
    pattern = V.to_string(layout)
    pieces: list[str] = []
    index = 0
    while index < len(pattern):
        for marker, replacement in _FORMAT_PIECES:
            if pattern.startswith(marker, index):
                pieces.append(when.strftime(replacement))
                index += len(marker)
                break
        else:
            if pattern.startswith("fffffff", index):
                pieces.append(f"{when.microsecond:06d}0")
                index += 7
            elif pattern.startswith("ffffff", index):
                pieces.append(f"{when.microsecond:06d}")
                index += 6
            elif pattern.startswith("fff", index):
                pieces.append(f"{when.microsecond // 1000:03d}")
                index += 3
            else:
                pieces.append(pattern[index])
                index += 1
    return "".join(pieces)


@scalar("format_timespan", "format_timespan(span [, format])",
        "A duration as text, in Kusto's d.hh:mm:ss form.", "datetime",
        min_args=1, max_args=2)
def _format_timespan(span, _layout=None):
    delta = V.to_timespan(span)
    return None if delta is None else format_timespan(delta)


@scalar("make_datetime", "make_datetime(year, month, day [, hour, minute, second])",
        "Builds a time from its parts.", "datetime", min_args=3, max_args=6)
def _make_datetime(year, month, day, hour=0, minute=0, second=0):
    try:
        whole = int(V.to_real(second) or 0)
        micro = int(round(((V.to_real(second) or 0) - whole) * 1_000_000))
        return datetime(V.to_long(year), V.to_long(month), V.to_long(day),
                        V.to_long(hour) or 0, V.to_long(minute) or 0,
                        whole, micro, tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


@scalar("make_timespan", "make_timespan(hours, minutes [, seconds])",
        "Builds a duration from its parts.", "datetime", min_args=2, max_args=3)
def _make_timespan(hours, minutes, seconds=0):
    try:
        return timedelta(hours=V.to_real(hours) or 0,
                         minutes=V.to_real(minutes) or 0,
                         seconds=V.to_real(seconds) or 0)
    except (TypeError, ValueError):
        return None


def _unixtime(name: str, divisor: float, unit: str):
    @scalar(name, f"{name}(number)",
            f"A Unix timestamp in {unit} as a datetime.", "datetime",
            min_args=1, max_args=1)
    def _apply(value, _divisor=divisor):
        number = V.to_real(value)
        if number is None:
            return None
        try:
            return datetime.fromtimestamp(number / _divisor, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    return _apply


_unixtime("unixtime_seconds_todatetime", 1.0, "seconds")
_unixtime("unixtime_milliseconds_todatetime", 1e3, "milliseconds")
_unixtime("unixtime_microseconds_todatetime", 1e6, "microseconds")
_unixtime("unixtime_nanoseconds_todatetime", 1e9, "nanoseconds")


# ---------------------------------------------------------------------------
# Dynamic values
# ---------------------------------------------------------------------------


@scalar("array_length", "array_length(array)", "How many items an array has.",
        "dynamic", min_args=1, max_args=1)
def _array_length(value):
    resolved = V.to_dynamic(value)
    return len(resolved) if isinstance(resolved, (list, dict)) else None


@scalar("array_index_of", "array_index_of(array, item)",
        "Where an item first appears in an array, or -1.", "dynamic",
        min_args=2, max_args=2)
def _array_index_of(array, item):
    resolved = V.to_dynamic(array)
    if not isinstance(resolved, list):
        return None
    for index, candidate in enumerate(resolved):
        if V.equal(candidate, item):
            return index
    return -1


@scalar("array_slice", "array_slice(array, start, end)",
        "Part of an array. Negative positions count from the end.", "dynamic",
        min_args=3, max_args=3)
def _array_slice(array, start, end):
    resolved = V.to_dynamic(array)
    if not isinstance(resolved, list):
        return None
    begin = V.to_long(start) or 0
    finish = V.to_long(end)
    if finish is None:
        return resolved[begin:]
    if finish == -1:
        return resolved[begin:]
    return resolved[begin:finish + 1 if finish >= 0 else finish + 1]


@scalar("array_concat", "array_concat(a, b, ...)", "Joins arrays end to end.",
        "dynamic", min_args=1)
def _array_concat(*arrays):
    result: list = []
    for item in arrays:
        resolved = V.to_dynamic(item)
        result.extend(resolved if isinstance(resolved, list) else [item])
    return result


@scalar("array_sum", "array_sum(array)", "Adds up the numbers in an array.",
        "dynamic", min_args=1, max_args=1)
def _array_sum(array):
    resolved = V.to_dynamic(array)
    if not isinstance(resolved, list):
        return None
    numbers = [V.to_real(item) for item in resolved]
    present = [number for number in numbers if number is not None]
    return sum(present) if present else 0


@scalar("array_sort_asc", "array_sort_asc(array)", "An array, sorted.",
        "dynamic", min_args=1, max_args=1)
def _array_sort_asc(array):
    resolved = V.to_dynamic(array)
    return sorted(resolved, key=V.sort_key) if isinstance(resolved, list) else None


@scalar("array_sort_desc", "array_sort_desc(array)",
        "An array, sorted backwards.", "dynamic", min_args=1, max_args=1)
def _array_sort_desc(array):
    resolved = V.to_dynamic(array)
    return (sorted(resolved, key=V.sort_key, reverse=True)
            if isinstance(resolved, list) else None)


@scalar("array_reverse", "array_reverse(array)", "An array, back to front.",
        "dynamic", min_args=1, max_args=1)
def _array_reverse(array):
    resolved = V.to_dynamic(array)
    return list(reversed(resolved)) if isinstance(resolved, list) else None


@scalar("bag_keys", "bag_keys(bag)", "The field names of a dynamic object.",
        "dynamic", min_args=1, max_args=1, example="bag_keys(Extra)")
def _bag_keys(bag):
    resolved = V.to_dynamic(bag)
    return list(resolved) if isinstance(resolved, dict) else None


@scalar("bag_has_key", "bag_has_key(bag, key)",
        "True when a dynamic object has that field.", "dynamic",
        min_args=2, max_args=2, example='bag_has_key(Extra, "pid")')
def _bag_has_key(bag, key):
    resolved = V.to_dynamic(bag)
    return isinstance(resolved, dict) and V.to_string(key) in resolved


@scalar("pack", "pack(key1, value1, key2, value2, ...)",
        "Builds a dynamic object.", "dynamic", min_args=2)
def _pack(*args):
    return {V.to_string(args[index]): args[index + 1]
            for index in range(0, len(args) - 1, 2)}


@scalar("pack_array", "pack_array(a, b, ...)", "Builds a dynamic array.",
        "dynamic", min_args=1)
def _pack_array(*args):
    return list(args)


@scalar("set_has_element", "set_has_element(array, value)",
        "True when an array contains a value.", "dynamic",
        min_args=2, max_args=2)
def _set_has_element(array, value):
    resolved = V.to_dynamic(array)
    if not isinstance(resolved, list):
        return False
    return any(V.equal(item, value) for item in resolved)


@scalar("set_union", "set_union(a, b, ...)",
        "Everything in any of the arrays, once each.", "dynamic", min_args=1)
def _set_union(*arrays):
    return _dedupe(_array_concat(*arrays))


@scalar("set_intersect", "set_intersect(a, b, ...)",
        "Only what appears in all of the arrays.", "dynamic", min_args=2)
def _set_intersect(*arrays):
    resolved = [V.to_dynamic(item) for item in arrays]
    if not all(isinstance(item, list) for item in resolved):
        return None
    result = _dedupe(resolved[0])
    for other in resolved[1:]:
        keys = {_hashable(item) for item in other}
        result = [item for item in result if _hashable(item) in keys]
    return result


@scalar("set_difference", "set_difference(a, b, ...)",
        "What is in the first array and not in the others.", "dynamic",
        min_args=2)
def _set_difference(*arrays):
    resolved = [V.to_dynamic(item) for item in arrays]
    if not all(isinstance(item, list) for item in resolved):
        return None
    removed: set = set()
    for other in resolved[1:]:
        removed.update(_hashable(item) for item in other)
    return [item for item in _dedupe(resolved[0])
            if _hashable(item) not in removed]


def _dedupe(items) -> list:
    seen: set = set()
    result: list = []
    for item in items or []:
        key = _hashable(item)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _hashable(value: Any):
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True, default=str)
    return value


@scalar("parse_json", "parse_json(text)",
        "Reads a JSON string into a dynamic value.", "dynamic",
        min_args=1, max_args=1, example="parse_json(Raw).user")
def _parse_json(text):
    return V.to_dynamic(text)


SCALARS["todynamic"] = Function(
    "todynamic", "todynamic(text)", "The same as parse_json().", "dynamic",
    _parse_json, 1, 1, "todynamic(Raw)")


# ---------------------------------------------------------------------------
# Conditionals and types
# ---------------------------------------------------------------------------


@scalar("iif", "iif(condition, whenTrue, whenFalse)",
        "Picks one of two values.", "conditional", min_args=3, max_args=3,
        example='iif(Level == "error", "look at me", "fine")')
def _iif(condition, when_true, when_false):
    return when_true if V.truthy(condition) else when_false


SCALARS["iff"] = Function("iff", "iff(condition, whenTrue, whenFalse)",
                          "The same as iif().", "conditional", _iif, 3, 3)


@scalar("case", "case(condition1, value1, condition2, value2, ..., default)",
        "The first value whose condition is true, or the last argument.",
        "conditional", min_args=3,
        example='case(Level == "error", "bad", Level == "warning", "hmm", "ok")')
def _case(*args):
    for index in range(0, len(args) - 1, 2):
        if V.truthy(args[index]):
            return args[index + 1]
    return args[-1] if len(args) % 2 else None


@scalar("coalesce", "coalesce(a, b, ...)", "The first argument that is not null.",
        "conditional", min_args=1)
def _coalesce(*args):
    for item in args:
        if item is not None and item != "":
            return item
    return None


@scalar("isnull", "isnull(value)", "True when a value is missing.",
        "conditional", min_args=1, max_args=1)
def _isnull(value):
    return value is None


@scalar("isnotnull", "isnotnull(value)", "True when a value is present.",
        "conditional", min_args=1, max_args=1)
def _isnotnull(value):
    return value is not None


SCALARS["notnull"] = Function("notnull", "notnull(value)",
                              "The same as isnotnull().", "conditional",
                              _isnotnull, 1, 1)


@scalar("isempty", "isempty(value)", "True for null and for an empty string.",
        "conditional", min_args=1, max_args=1)
def _isempty(value):
    return value is None or (isinstance(value, str) and value == "")


@scalar("isnotempty", "isnotempty(value)",
        "True for anything that is neither null nor empty.", "conditional",
        min_args=1, max_args=1)
def _isnotempty(value):
    return not _isempty(value)


SCALARS["notempty"] = Function("notempty", "notempty(value)",
                               "The same as isnotempty().", "conditional",
                               _isnotempty, 1, 1)


@scalar("gettype", "gettype(value)", "The name of a value's type.", "type",
        min_args=1, max_args=1)
def _gettype(value):
    return "null" if value is None else V.kind_of(value).value


def _converter(name: str, signature: str, summary: str, convert):
    @scalar(name, signature, summary, "type", min_args=1, max_args=1)
    def _apply(value, _convert=convert):
        return _convert(value)
    return _apply


_converter("tostring", "tostring(value)", "A value as text.", V.to_string)
_converter("tolong", "tolong(value)", "A value as a whole number, or null.",
           V.to_long)
_converter("toint", "toint(value)", "The same as tolong().", V.to_long)
_converter("todouble", "todouble(value)", "A value as a real number, or null.",
           V.to_real)
_converter("toreal", "toreal(value)", "The same as todouble().", V.to_real)
_converter("tobool", "tobool(value)", "A value as true/false, or null.",
           V.to_bool)
_converter("toboolean", "toboolean(value)", "The same as tobool().", V.to_bool)
_converter("todatetime", "todatetime(value)", "A value as a time, or null.",
           V.to_datetime)
_converter("totimespan", "totimespan(value)", "A value as a duration, or null.",
           V.to_timespan)


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


def _hasher(name: str, algorithm: str):
    @scalar(name, f"{name}(value)",
            f"The {algorithm.upper()} of a value's UTF-8 bytes, in hex. "
            "Useful for matching against indicator lists.", "hash",
            min_args=1, max_args=2)
    def _apply(value, _salt=None, _algorithm=algorithm):
        if value is None:
            return None
        return hashlib.new(_algorithm,
                           V.to_string(value).encode("utf-8")).hexdigest()
    return _apply


_hasher("hash_sha256", "sha256")
_hasher("hash_sha1", "sha1")
_hasher("hash_md5", "md5")


@scalar("hash", "hash(value [, mod])",
        "A fast numeric hash. Use it to bucket values, not to identify them.",
        "hash", min_args=1, max_args=2)
def _hash(value, mod=None):
    if value is None:
        return None
    digest = hashlib.blake2b(V.to_string(value).encode("utf-8"),
                             digest_size=8).digest()
    number = int.from_bytes(digest, "big", signed=True)
    modulus = V.to_long(mod)
    return number % modulus if modulus else number


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------


@scalar("parse_ipv4", "parse_ipv4(address)",
        "An IPv4 address as a number, or null when it is not one.", "network",
        min_args=1, max_args=1)
def _parse_ipv4(address):
    try:
        return int(ipaddress.IPv4Address(V.to_string(address).strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


@scalar("ipv4_is_private", "ipv4_is_private(address)",
        "True for 10.x, 172.16-31.x, 192.168.x and friends.", "network",
        min_args=1, max_args=1,
        example='Logs | where isnotnull(Extra.ip) and not(ipv4_is_private(Extra.ip))')
def _ipv4_is_private(address):
    parsed = _as_address(address)
    return None if parsed is None else parsed.is_private


@scalar("ipv4_is_in_range", "ipv4_is_in_range(address, range)",
        "True when an address falls inside a CIDR range.", "network",
        min_args=2, max_args=2,
        example='ipv4_is_in_range(Extra.ip, "192.168.0.0/16")')
def _ipv4_is_in_range(address, network):
    parsed = _as_address(address)
    if parsed is None:
        return None
    try:
        block = ipaddress.ip_network(V.to_string(network).strip(), strict=False)
    except ValueError:
        return None
    return parsed.version == block.version and parsed in block


@scalar("ipv4_is_match", "ipv4_is_match(a, b [, prefix])",
        "True when two addresses match, optionally only the first n bits.",
        "network", min_args=2, max_args=3)
def _ipv4_is_match(left, right, prefix=None):
    first, second = _as_address(left), _as_address(right)
    if first is None or second is None:
        return None
    bits = V.to_long(prefix)
    if bits is None:
        return first == second
    try:
        block = ipaddress.ip_network(f"{first}/{bits}", strict=False)
    except ValueError:
        return None
    return second in block


@scalar("ipv4_compare", "ipv4_compare(a, b)",
        "-1, 0 or 1 for two addresses in numeric order.", "network",
        min_args=2, max_args=3)
def _ipv4_compare(left, right, _prefix=None):
    first, second = _as_address(left), _as_address(right)
    if first is None or second is None:
        return None
    return (first > second) - (first < second)


@scalar("ipv6_is_match", "ipv6_is_match(a, b)",
        "True when two IPv6 addresses are the same.", "network",
        min_args=2, max_args=3)
def _ipv6_is_match(left, right, _prefix=None):
    return _ipv4_is_match(left, right, _prefix)


def _as_address(value):
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            return ipaddress.IPv4Address(value)
        except (ipaddress.AddressValueError, ValueError):
            return None
    text = V.to_string(value).strip().split("/")[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------


class Accumulator:
    """One aggregate, for one group. ``add`` per row, ``result`` at the end."""

    __slots__ = ()

    def add(self, values: tuple) -> None:
        raise NotImplementedError

    def result(self) -> Any:
        raise NotImplementedError


@aggregate("count", "count()", "How many rows are in the group.",
           min_args=0, max_args=0, example="summarize count() by App")
class _Count(Accumulator):
    __slots__ = ("total",)

    def __init__(self) -> None:
        self.total = 0

    def add(self, values: tuple) -> None:
        self.total += 1

    def result(self) -> int:
        return self.total


@aggregate("countif", "countif(condition)",
           "How many rows in the group match a condition.",
           min_args=1, max_args=1,
           example='summarize countif(Level == "error") by App')
class _CountIf(Accumulator):
    __slots__ = ("total",)

    def __init__(self) -> None:
        self.total = 0

    def add(self, values: tuple) -> None:
        if V.truthy(values[0]):
            self.total += 1

    def result(self) -> int:
        return self.total


@aggregate("dcount", "dcount(expression)",
           "How many different values appear. Exact, not estimated.",
           min_args=1, max_args=2, example="summarize dcount(Source) by App")
class _DCount(Accumulator):
    __slots__ = ("seen",)

    def __init__(self) -> None:
        self.seen: set = set()

    def add(self, values: tuple) -> None:
        if values[0] is not None:
            self.seen.add(_hashable(values[0]))

    def result(self) -> int:
        return len(self.seen)


AGGREGATES["count_distinct"] = Aggregation(
    "count_distinct", "count_distinct(expression)", "The same as dcount().",
    _DCount, 1, 1)


@aggregate("dcountif", "dcountif(expression, condition)",
           "How many different values appear among the matching rows.",
           min_args=2, max_args=2)
class _DCountIf(Accumulator):
    __slots__ = ("seen",)

    def __init__(self) -> None:
        self.seen: set = set()

    def add(self, values: tuple) -> None:
        if V.truthy(values[1]) and values[0] is not None:
            self.seen.add(_hashable(values[0]))

    def result(self) -> int:
        return len(self.seen)


class _Numeric(Accumulator):
    __slots__ = ("total", "count")

    def __init__(self) -> None:
        self.total = 0.0
        self.count = 0

    def _accept(self, value) -> None:
        number = V.to_real(value)
        if number is not None and math.isfinite(number):
            self.total += number
            self.count += 1


@aggregate("sum", "sum(expression)", "Adds up a column.", min_args=1, max_args=1)
class _Sum(_Numeric):
    __slots__ = ()

    def add(self, values: tuple) -> None:
        self._accept(values[0])

    def result(self):
        return _whole(self.total)


@aggregate("sumif", "sumif(expression, condition)",
           "Adds up a column over the matching rows.", min_args=2, max_args=2)
class _SumIf(_Numeric):
    __slots__ = ()

    def add(self, values: tuple) -> None:
        if V.truthy(values[1]):
            self._accept(values[0])

    def result(self):
        return _whole(self.total)


@aggregate("avg", "avg(expression)", "The mean of a column.",
           min_args=1, max_args=1)
class _Avg(_Numeric):
    __slots__ = ()

    def add(self, values: tuple) -> None:
        self._accept(values[0])

    def result(self):
        return self.total / self.count if self.count else None


AGGREGATES["average"] = Aggregation("average", "average(expression)",
                                    "The same as avg().", _Avg, 1, 1)


@aggregate("avgif", "avgif(expression, condition)",
           "The mean over the matching rows.", min_args=2, max_args=2)
class _AvgIf(_Numeric):
    __slots__ = ()

    def add(self, values: tuple) -> None:
        if V.truthy(values[1]):
            self._accept(values[0])

    def result(self):
        return self.total / self.count if self.count else None


def _whole(total: float):
    return int(total) if float(total).is_integer() else total


class _Extreme(Accumulator):
    __slots__ = ("best", "largest")

    def __init__(self, largest: bool = True) -> None:
        self.best = None
        self.largest = largest

    def add(self, values: tuple) -> None:
        value = values[0]
        if value is None:
            return
        if self.best is None:
            self.best = value
            return
        order = V.compare(value, self.best)
        if order is None:
            order = (V.sort_key(value) > V.sort_key(self.best)) - \
                    (V.sort_key(value) < V.sort_key(self.best))
        if (order > 0) == self.largest and order != 0:
            self.best = value

    def result(self):
        return self.best


@aggregate("min", "min(expression)", "The smallest value.", min_args=1, max_args=1)
class _Min(_Extreme):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(largest=False)


@aggregate("max", "max(expression)", "The largest value.", min_args=1, max_args=1)
class _Max(_Extreme):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(largest=True)


@aggregate("minif", "minif(expression, condition)",
           "The smallest value among the matching rows.", min_args=2, max_args=2)
class _MinIf(_Extreme):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(largest=False)

    def add(self, values: tuple) -> None:
        if V.truthy(values[1]):
            super().add(values)


@aggregate("maxif", "maxif(expression, condition)",
           "The largest value among the matching rows.", min_args=2, max_args=2)
class _MaxIf(_Extreme):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(largest=True)

    def add(self, values: tuple) -> None:
        if V.truthy(values[1]):
            super().add(values)


@aggregate("any", "any(expression)",
           "Any one value from the group. Cheap; do not expect a particular one.",
           min_args=1, max_args=1)
class _Any(Accumulator):
    __slots__ = ("value", "have")

    def __init__(self) -> None:
        self.value = None
        self.have = False

    def add(self, values: tuple) -> None:
        if not self.have and values[0] is not None:
            self.value = values[0]
            self.have = True

    def result(self):
        return self.value


AGGREGATES["take_any"] = Aggregation("take_any", "take_any(expression)",
                                     "The same as any().", _Any, 1, 1)
AGGREGATES["anyif"] = Aggregation("anyif", "anyif(expression, condition)",
                                  "Any one value from the matching rows.",
                                  lambda: _AnyIf(), 2, 2)


class _AnyIf(_Any):
    __slots__ = ()

    def add(self, values: tuple) -> None:
        if V.truthy(values[1]):
            super().add(values)


@aggregate("make_list", "make_list(expression [, limit])",
           "Every value in the group, as an array, in order.",
           min_args=1, max_args=2,
           example="summarize make_list(Message) by Source")
class _MakeList(Accumulator):
    __slots__ = ("items", "limit")

    #: Without a cap, one group over a million rows becomes a million-element
    #: array in a single cell, which no grid can draw and no person can read.
    DEFAULT_LIMIT = 1024

    def __init__(self) -> None:
        self.items: list = []
        self.limit = self.DEFAULT_LIMIT

    def add(self, values: tuple) -> None:
        if len(values) > 1 and values[1] is not None:
            self.limit = min(V.to_long(values[1]) or self.DEFAULT_LIMIT, 100_000)
        if values[0] is not None and len(self.items) < self.limit:
            self.items.append(values[0])

    def result(self) -> list:
        return self.items


@aggregate("make_list_if", "make_list_if(expression, condition [, limit])",
           "The matching values in the group, as an array.",
           min_args=2, max_args=3)
class _MakeListIf(_MakeList):
    __slots__ = ()

    def add(self, values: tuple) -> None:
        if V.truthy(values[1]):
            super().add((values[0],) + tuple(values[2:]))


@aggregate("make_set", "make_set(expression [, limit])",
           "The different values in the group, as an array.",
           min_args=1, max_args=2,
           example="summarize make_set(App) by bin(Timestamp, 1h)")
class _MakeSet(Accumulator):
    __slots__ = ("items", "seen", "limit")

    DEFAULT_LIMIT = 1024

    def __init__(self) -> None:
        self.items: list = []
        self.seen: set = set()
        self.limit = self.DEFAULT_LIMIT

    def add(self, values: tuple) -> None:
        if len(values) > 1 and values[1] is not None:
            self.limit = min(V.to_long(values[1]) or self.DEFAULT_LIMIT, 100_000)
        value = values[0]
        if value is None or len(self.items) >= self.limit:
            return
        key = _hashable(value)
        if key not in self.seen:
            self.seen.add(key)
            self.items.append(value)

    def result(self) -> list:
        return self.items


@aggregate("make_set_if", "make_set_if(expression, condition [, limit])",
           "The different matching values, as an array.",
           min_args=2, max_args=3)
class _MakeSetIf(_MakeSet):
    __slots__ = ()

    def add(self, values: tuple) -> None:
        if V.truthy(values[1]):
            super().add((values[0],) + tuple(values[2:]))


@aggregate("make_bag", "make_bag(expression [, limit])",
           "Merges dynamic objects into one.", min_args=1, max_args=2)
class _MakeBag(Accumulator):
    __slots__ = ("bag",)

    def __init__(self) -> None:
        self.bag: dict = {}

    def add(self, values: tuple) -> None:
        resolved = V.to_dynamic(values[0])
        if isinstance(resolved, dict) and len(self.bag) < 1024:
            self.bag.update(resolved)

    def result(self) -> dict:
        return self.bag


class _Samples(Accumulator):
    """Base for the aggregates that have to keep every value."""

    __slots__ = ("numbers",)

    def __init__(self) -> None:
        self.numbers: list[float] = []

    def add(self, values: tuple) -> None:
        number = V.to_real(values[0])
        if number is not None and math.isfinite(number):
            self.numbers.append(number)


@aggregate("percentile", "percentile(expression, percentage)",
           "The value below which that percentage of the group falls.",
           min_args=2, max_args=2,
           example="summarize percentile(Duration, 95) by App")
class _Percentile(_Samples):
    __slots__ = ("percent",)

    def __init__(self) -> None:
        super().__init__()
        self.percent = 50.0

    def add(self, values: tuple) -> None:
        self.percent = V.to_real(values[1]) or 50.0
        super().add(values)

    def result(self):
        return _percentile_of(self.numbers, self.percent)


@aggregate("percentiles", "percentiles(expression, p1, p2, ...)",
           "Several percentiles at once, as an array.", min_args=2)
class _Percentiles(_Samples):
    __slots__ = ("wanted",)

    def __init__(self) -> None:
        super().__init__()
        self.wanted: list[float] = []

    def add(self, values: tuple) -> None:
        if not self.wanted:
            self.wanted = [V.to_real(item) or 0.0 for item in values[1:]]
        super().add((values[0],))

    def result(self) -> list:
        return [_percentile_of(self.numbers, percent) for percent in self.wanted]


def _percentile_of(numbers: list[float], percent: float):
    """Nearest-rank, which is what Kusto's exact percentile does."""
    if not numbers:
        return None
    ordered = sorted(numbers)
    if percent <= 0:
        return _whole(ordered[0])
    if percent >= 100:
        return _whole(ordered[-1])
    rank = math.ceil(percent / 100 * len(ordered))
    return _whole(ordered[max(0, min(len(ordered) - 1, rank - 1))])


@aggregate("stdev", "stdev(expression)", "The sample standard deviation.",
           min_args=1, max_args=1)
class _Stdev(_Samples):
    __slots__ = ()

    def result(self):
        if len(self.numbers) < 2:
            return None
        mean = sum(self.numbers) / len(self.numbers)
        spread = sum((value - mean) ** 2 for value in self.numbers)
        return math.sqrt(spread / (len(self.numbers) - 1))


@aggregate("variance", "variance(expression)", "The sample variance.",
           min_args=1, max_args=1)
class _Variance(_Samples):
    __slots__ = ()

    def result(self):
        if len(self.numbers) < 2:
            return None
        mean = sum(self.numbers) / len(self.numbers)
        return sum((value - mean) ** 2 for value in self.numbers) / \
            (len(self.numbers) - 1)


class _Arg(Accumulator):
    """``arg_max(Timestamp, *)`` — the whole row where a column peaks."""

    __slots__ = ("best", "payload", "largest")

    def __init__(self, largest: bool = True) -> None:
        self.best = None
        self.payload: tuple = ()
        self.largest = largest

    def add(self, values: tuple) -> None:
        key = values[0]
        if key is None:
            return
        if self.best is None:
            self.best, self.payload = key, tuple(values[1:])
            return
        order = V.compare(key, self.best)
        if order is None:
            order = (V.sort_key(key) > V.sort_key(self.best)) - \
                    (V.sort_key(key) < V.sort_key(self.best))
        if order != 0 and (order > 0) == self.largest:
            self.best, self.payload = key, tuple(values[1:])

    def result(self) -> tuple:
        return (self.best,) + self.payload


@aggregate("arg_max", "arg_max(expression, columns...)",
           "The row where an expression is largest. Use * for every column.",
           min_args=2, max_args=None, projecting=True,
           example="summarize arg_max(Timestamp, *) by Source")
class _ArgMax(_Arg):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(largest=True)


@aggregate("arg_min", "arg_min(expression, columns...)",
           "The row where an expression is smallest. Use * for every column.",
           min_args=2, max_args=None, projecting=True)
class _ArgMin(_Arg):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(largest=False)


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

_PATTERN_CACHE: dict[str, Any] = {}

#: A regular expression longer than this is refused. Catastrophic
#: backtracking is a real risk with a pattern typed into a query box, and a
#: 2000-character pattern is never a typo worth running.
MAX_PATTERN = 2000


def _compile(pattern: str):
    """Compile once per query run, and never raise on a bad pattern."""
    if pattern in _PATTERN_CACHE:
        return _PATTERN_CACHE[pattern]
    if len(pattern) > MAX_PATTERN:
        _PATTERN_CACHE[pattern] = None
        return None
    try:
        compiled = re.compile(pattern)
    except re.error:
        compiled = None
    if len(_PATTERN_CACHE) > 512:
        _PATTERN_CACHE.clear()
    _PATTERN_CACHE[pattern] = compiled
    return compiled


def compile_pattern(pattern: str, position: int = 0, source: str = ""):
    """Compile a pattern, raising a KqlError the editor can point at."""
    if len(pattern) > MAX_PATTERN:
        raise KqlError("That regular expression is too long.", position, 1,
                       f"The limit is {MAX_PATTERN} characters.", source)
    try:
        return re.compile(pattern)
    except re.error as error:
        raise KqlError(f"That regular expression is not valid: {error.msg}.",
                       position, 1, "", source) from None
