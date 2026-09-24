"""What to offer the editor when somebody is halfway through a query.

Completion in a query language is worth more than in most places, because the
column names are not guessable: nobody knows that the application a line came
from is called ``App`` until something tells them. So the list is
context-aware rather than a flat dump of every identifier:

============================  ================================================
after ``|``                   operators
at the start                  table names
after ``summarize``           aggregates
after ``by`` / in ``where``   columns, then scalar functions
after a column name           the operators that apply to its type
after ``render``              chart kinds
inside ``dynamic(``           nothing, because it is JSON
============================  ================================================

Everything carries its one-line documentation, which is the same text the
Functions tab shows, so learning happens while typing rather than afterwards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .. import catalogue
from ..model import ColumnType
from . import ast as node
from . import functions as fn
from .parser import RENDER_KINDS, STRING_OPERATORS


@dataclass(frozen=True, slots=True)
class Completion:
    """One thing the editor can insert."""

    text: str
    label: str
    kind: str
    detail: str = ""
    documentation: str = ""
    #: Lower sorts first.
    rank: int = 50

    def __str__(self) -> str:
        return self.label


#: Operators that read well after a string column.
_STRING_HINTS = ("==", "!=", "=~", "contains", "!contains", "has", "!has",
                 "startswith", "endswith", "in", "!in", "matches regex",
                 "has_any", "has_all")
_NUMBER_HINTS = ("==", "!=", ">", ">=", "<", "<=", "between", "in", "!in")
_TIME_HINTS = (">", ">=", "<", "<=", "between", "==", "!=")

_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_]*$")
_PIPE_SPLIT = re.compile(r"\|")


def word_at(text: str, position: int) -> tuple[str, int]:
    """The identifier the cursor is inside, and where it starts."""
    head = text[:position]
    match = _WORD.search(head)
    if match is None:
        return "", position
    return match.group(0), match.start()


def table_in(text: str) -> catalogue.TableDef:
    """Which table the query reads, so the column list is the right one."""
    for match in re.finditer(r"[A-Za-z_][A-Za-z0-9_]*", text):
        found = catalogue.table(match.group(0))
        if found is not None:
            return found
    return catalogue.LOGS


def _segment(text: str, position: int) -> str:
    """The pipeline stage the cursor is in."""
    head = text[:position]
    # Ignore pipes inside strings and parentheses, which is the difference
    # between "the stage I am in" and "a pipe somewhere earlier".
    depth = 0
    quote = ""
    start = 0
    index = 0
    while index < len(head):
        character = head[index]
        if quote:
            if character == quote:
                quote = ""
            elif character == "\\":
                index += 1
        elif character in "\"'":
            quote = character
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth = max(0, depth - 1)
        elif character == "|" and depth == 0:
            start = index + 1
        elif character == ";" and depth == 0:
            start = index + 1
        index += 1
    return head[start:]


def completions(text: str, position: int, *,
                extra_columns: tuple[str, ...] = (),
                saved_names: tuple[str, ...] = ()) -> list[Completion]:
    """Everything worth offering at `position` in `text`."""
    position = max(0, min(position, len(text)))
    prefix, _start = word_at(text, position)
    segment = _segment(text, position)
    stripped = segment.strip()
    table = table_in(text[:position] or text)

    items: list[Completion]
    words = stripped.split()

    if not stripped or (len(words) == 1 and not segment.endswith((" ", "\t", "\n"))
                        and _is_first_stage(text, position)):
        if _is_first_stage(text, position):
            # A query starts with a table; after a pipe it cannot, so the
            # table list would only ever be noise there.
            items = _tables(saved_names)
            items += [
                Completion("let ", "let", "keyword", "let name = …",
                           "Name a value, a table or a function.", rank=70),
                Completion("search ", "search", "operator", 'search "term"',
                           "Full-text search across every table.", rank=70),
                Completion("union ", "union", "operator", "union A, B",
                           "Read several tables at once.", rank=70),
            ]
        else:
            items = _operators()
    elif _after_keyword(stripped, "render"):
        items = [Completion(kind, kind, "keyword", "", "A chart Hunt can draw.")
                 for kind in RENDER_KINDS]
    elif _in_summarize_aggregates(stripped):
        items = _aggregates() + _columns(table, extra_columns) + _functions()
    elif _expects_operator(segment):
        items = _operator_hints(table, segment) + _columns(table, extra_columns)
    elif words and words[0].lower() in ("project-away", "project-keep",
                                        "project-rename", "project-reorder",
                                        "distinct"):
        items = _columns(table, extra_columns)
    else:
        items = _columns(table, extra_columns) + _functions() + _aggregates_if(stripped)

    if prefix:
        lowered = prefix.lower()
        exact = [item for item in items if item.text.lower().startswith(lowered)]
        fuzzy = [item for item in items
                 if item not in exact and lowered in item.text.lower()]
        items = exact + fuzzy

    items.sort(key=lambda item: (item.rank, item.label.lower()))
    return items[:200]


def _is_first_stage(text: str, position: int) -> bool:
    head = text[:position]
    body = head.rsplit(";", 1)[-1]
    return "|" not in body


def _after_keyword(segment: str, keyword: str) -> bool:
    words = segment.split()
    return bool(words) and words[0].lower() == keyword and len(words) <= 2


def _in_summarize_aggregates(segment: str) -> bool:
    words = segment.split()
    if not words or words[0].lower() != "summarize":
        return False
    return " by " not in f" {segment.lower()} "


def _expects_operator(segment: str) -> bool:
    """True just after a bare column name, where a comparison comes next."""
    body = segment.rstrip()
    if body == segment:           # the cursor is inside a word, not after one
        return False
    words = body.split()
    if len(words) < 2 or words[0].lower() not in ("where", "filter"):
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", words[-1]))


def _tables(saved_names: tuple[str, ...]) -> list[Completion]:
    items = [
        Completion(table.name, table.name, "table",
                   f"{len(table.columns)} columns", table.description, rank=10)
        for table in catalogue.TABLES.values()
    ]
    items += [Completion(name, name, "table", "a let in this query", "", rank=15)
              for name in saved_names]
    return items


def _operators() -> list[Completion]:
    return [
        Completion(name + " ", name, "operator", _OPERATOR_FORMS.get(name, ""),
                   _OPERATOR_DOCS.get(name, ""), rank=20)
        for name in node.OPERATOR_KEYWORDS
    ]


def _columns(table: catalogue.TableDef,
             extra: tuple[str, ...] = ()) -> list[Completion]:
    items = [
        Completion(column.name, column.name, "column", column.type.value,
                   column.description, rank=5)
        for column in table.columns
    ]
    known = {column.name.lower() for column in table.columns}
    items += [Completion(name, name, "column", "computed", "", rank=4)
              for name in extra if name.lower() not in known]
    return items


def _functions() -> list[Completion]:
    return [
        Completion(f"{item.name}(", item.name, "function", item.signature,
                   item.summary + (" (a ClamGuard extension, not Kusto)"
                                   if item.extension else ""),
                   rank=40)
        for item in fn.SCALARS.values()
    ]


def _aggregates() -> list[Completion]:
    return [
        Completion(f"{item.name}(", item.name, "aggregate", item.signature,
                   item.summary, rank=25)
        for item in fn.AGGREGATES.values()
    ]


def _aggregates_if(segment: str) -> list[Completion]:
    return _aggregates() if "summarize" in segment.lower() else []


def _operator_hints(table: catalogue.TableDef, segment: str) -> list[Completion]:
    name = segment.rstrip().split()[-1]
    binding = table.column(name.split(".")[0])
    kind = binding.type if binding else ColumnType.STRING
    if kind.is_numeric:
        hints = _NUMBER_HINTS
    elif kind.is_temporal:
        hints = _TIME_HINTS
    else:
        hints = _STRING_HINTS
    return [
        Completion(hint + " ", hint, "operator", "",
                   _COMPARISON_DOCS.get(hint, ""), rank=1)
        for hint in hints
    ]


_OPERATOR_FORMS = {
    "where": "where Column == value", "extend": "extend Name = expression",
    "project": "project A, B = expr", "summarize": "summarize count() by Column",
    "sort": "sort by Column desc", "order": "order by Column desc",
    "top": "top 10 by Column", "take": "take 100", "limit": "limit 100",
    "count": "count", "distinct": "distinct Column",
    "search": 'search "term"', "join": "join kind=inner (Table) on Key",
    "union": "union A, B", "render": "render timechart",
    "mv-expand": "mv-expand Column", "parse": 'parse Message with "x" Name',
    "sample": "sample 100", "getschema": "getschema", "serialize": "serialize",
    "project-away": "project-away A, B", "project-keep": "project-keep A, B",
    "project-rename": "project-rename New = Old",
    "project-reorder": "project-reorder A, B", "filter": "filter Column == value",
}

_OPERATOR_DOCS = {
    "where": "Keep only the rows that match.",
    "filter": "The same as where.",
    "extend": "Add a computed column.",
    "project": "Choose, rename and compute columns.",
    "project-away": "Drop columns by name; wildcards allowed.",
    "project-keep": "Keep only these columns.",
    "project-rename": "Rename a column without changing its position.",
    "project-reorder": "Move columns to the front.",
    "summarize": "Group rows and compute one value per group.",
    "sort": "Order the rows. Written `sort by`.",
    "order": "The same as sort.",
    "top": "The n largest, by an expression.",
    "take": "Stop after n rows. Fast: it stops reading.",
    "limit": "The same as take.",
    "count": "How many rows there are.",
    "distinct": "One row per distinct combination.",
    "search": "Full-text search. Uses the text index when it can.",
    "join": "Match rows against another table on a key.",
    "union": "Read several tables as one.",
    "render": "Draw the result as a chart on the Chart tab.",
    "mv-expand": "One row per element of an array column.",
    "parse": "Pull fields out of a string with a pattern.",
    "sample": "A random n rows.",
    "getschema": "Describe the columns rather than the rows.",
    "serialize": "Fix the order, so row_number() and prev() work.",
}

_COMPARISON_DOCS = {
    "==": "Exactly equal. Case-sensitive for strings.",
    "!=": "Not equal.",
    "=~": "Equal, ignoring case.",
    "contains": "The text appears anywhere, ignoring case.",
    "!contains": "The text does not appear.",
    "has": "The whole word appears. Uses the text index — much faster than "
           "contains on a large index.",
    "!has": "The word does not appear.",
    "startswith": "Begins with, ignoring case.",
    "endswith": "Ends with, ignoring case.",
    "in": "One of a list: in (\"a\", \"b\").",
    "!in": "None of a list.",
    "between": "Within a range: between (ago(1d) .. now()).",
    "matches regex": "Matches a regular expression. Cannot use the index.",
    "has_any": 'Any of these words: has_any ("a", "b").',
    "has_all": "All of these words.",
    ">": "Greater than.", ">=": "At least.", "<": "Less than.", "<=": "At most.",
}


def documentation_for(word: str) -> str:
    """The hover text for an identifier, or "" if it is not one of ours."""
    table = catalogue.table(word)
    if table is not None:
        return f"{table.name} — {table.description}"
    for definition in catalogue.TABLES.values():
        column = definition.column(word)
        if column is not None:
            return (f"{definition.name}.{column.name} ({column.type.value}) — "
                    f"{column.description}")
    scalar = fn.SCALARS.get(word.lower())
    if scalar is not None:
        return f"{scalar.signature} — {scalar.summary}"
    aggregation = fn.AGGREGATES.get(word.lower())
    if aggregation is not None:
        return f"{aggregation.signature} — {aggregation.summary}"
    if word.lower() in _OPERATOR_DOCS:
        return f"{_OPERATOR_FORMS.get(word.lower(), word)} — {_OPERATOR_DOCS[word.lower()]}"
    return _COMPARISON_DOCS.get(word.lower(), "")


def signature_for(text: str, position: int) -> str:
    """The signature of the call the cursor is inside, for the status hint."""
    head = text[:max(0, position)]
    depth = 0
    index = len(head) - 1
    while index >= 0:
        character = head[index]
        if character == ")":
            depth += 1
        elif character == "(":
            if depth == 0:
                match = _WORD.search(head[:index])
                if match is None:
                    return ""
                return documentation_for(match.group(0))
            depth -= 1
        index -= 1
    return ""


#: Every word the syntax highlighter should colour as a keyword.
def keywords() -> tuple[str, ...]:
    extra = ("by", "asc", "desc", "on", "with", "kind", "nulls", "first",
             "last", "and", "or", "not", "let", "print", "regex", "typeof",
             "to", "in", "between", "true", "false", "null", "datetime",
             "timespan", "dynamic", "toscalar")
    return tuple(sorted(set(node.OPERATOR_KEYWORDS) | set(extra)
                        | set(STRING_OPERATORS) | {"matches"}))


def function_names() -> tuple[str, ...]:
    return tuple(sorted(set(fn.SCALARS) | set(fn.AGGREGATES)))


def column_names() -> tuple[str, ...]:
    names: set[str] = set()
    for table in catalogue.TABLES.values():
        names.update(table.names)
    return tuple(sorted(names))


def table_names() -> tuple[str, ...]:
    return catalogue.names()
