"""The pushdown planner: as much of the pipeline as possible becomes one SELECT.

This is where "performance is paramount" is actually cashed in. Without it,
``Logs | where Level == "error" | take 50`` would read every event in the
store into Python and throw 1,198,688 of them away. With it, SQLite answers
using an index and hands back fifty rows.

The planner is deliberately **conservative**. It translates a prefix of the
pipeline and stops at the first thing it is not certain about, leaving the
rest to the evaluator in :mod:`engine`, which implements the whole language.
So correctness depends only on the evaluator; the planner can only make a
query faster or leave it alone. ``tests/test_hunt_kql_engine.py`` asserts that
by running a corpus of queries both ways and comparing the results.

What gets pushed:

==================  =========================================================
``where``           into ``WHERE``, including ``Extra.pid`` via json_extract
``search``          into an FTS5 ``MATCH``, which is the whole reason the
                    full-text index exists
``summarize``       into ``GROUP BY``, for the aggregates with exact SQL
                    equivalents
``sort by``         into ``ORDER BY`` on stored columns
``take`` / ``top``  into ``LIMIT``
``count``           into ``COUNT(*)``
``distinct``        into ``SELECT DISTINCT``
``project``         into the select list, when every item is a plain column
==================  =========================================================
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable

from ..catalogue import Binding, TableDef
from ..model import Column, ColumnType
from . import ast as node
from . import values as V
from .errors import KqlError


class NotPushable(Exception):
    """This piece has to run in Python. Never reaches the user."""


@dataclass(slots=True)
class Plan:
    """One SQL statement and what it produces."""

    sql: str = ""
    parameters: tuple = ()
    columns: tuple[Column, ...] = ()
    #: One per column: a callable turning the stored value into a KQL value.
    decoders: tuple[Callable | None, ...] = ()
    #: How many pipeline steps this absorbed.
    consumed: int = 0
    #: Which operator keywords were pushed, in order, for the details panel.
    pushed: tuple[str, ...] = ()
    #: True when SQL applied a row limit, so "scanned" is not the whole table.
    limited: bool = False
    #: True when the statement groups, so the caller knows not to count rows
    #: read as events scanned.
    grouped: bool = False


@dataclass(slots=True)
class _Output:
    alias: str
    sql: str
    type: ColumnType
    decoder: Callable | None = None


class _Builder:
    """Accumulates one SELECT while walking the pipeline."""

    def __init__(self, table: TableDef, full_text: bool,
                 environment: Any = None) -> None:
        self.table = table
        #: The run's environment, so that constant folding can see `let`
        #: bindings. Without it, `let bad = dynamic([...]); … in (bad)` would
        #: fail to fold and the whole filter would fall back to Python.
        self.environment = environment
        self.full_text = full_text and bool(table.full_text_table)
        self.select: list[_Output] = [
            _Output(item.name, item.sql, item.type, item.decode)
            for item in table.columns
        ]
        self.where: list[str] = []
        # Parameters are collected per clause and concatenated in *statement*
        # order at build time, not in the order the pipeline happened to be
        # walked. `where` is translated before `summarize` but appears after
        # the select list, so one flat list bound
        #   SELECT SUM(CASE WHEN e.level IN (?, ?) ...) ... WHERE s.root = ?
        # as ('journal', 50, 60) and the query silently returned nothing.
        self._sections: dict[str, list[Any]] = {
            "select": [], "where": [], "order": []}
        self._current = self._sections["where"]
        self.group: list[_Output] = []
        self.aggregates: list[_Output] = []
        self.order: list[tuple[str, bool, bool | None]] = []
        self.limit: int | None = None
        self.distinct = False
        self.grouped = False
        self.pushed: list[str] = []
        #: Aliases available to later steps: name -> SQL expression.
        self.visible: dict[str, _Output] = {item.alias: item for item in self.select}

    # -- assembly ---------------------------------------------------------

    def outputs(self) -> list[_Output]:
        if self.grouped:
            return self.group + self.aggregates
        return self.select

    def build(self) -> Plan:
        outputs = self.outputs()
        pieces = ", ".join(f"{item.sql} AS {_quote(item.alias)}" for item in outputs)
        sql = [f"SELECT {'DISTINCT ' if self.distinct else ''}{pieces}",
               f"FROM {self.table.source_sql}"]
        if self.where:
            sql.append("WHERE " + " AND ".join(f"({piece})" for piece in self.where))
        if self.grouped and self.group:
            # By ordinal rather than by repeating the expression, so a group
            # key that carries a parameter is bound once instead of twice.
            sql.append("GROUP BY " + ", ".join(
                str(position + 1) for position in range(len(self.group))))
        if self.order:
            terms = []
            for expression, descending, nulls_first in self.order:
                if nulls_first is not None:
                    terms.append(f"({expression}) IS NOT NULL "
                                 f"{'ASC' if nulls_first else 'DESC'}")
                terms.append(f"{expression} {'DESC' if descending else 'ASC'}")
            sql.append("ORDER BY " + ", ".join(terms))
        if self.limit is not None:
            sql.append(f"LIMIT {int(self.limit)}")
        return Plan(
            sql="\n".join(sql),
            parameters=tuple(self._sections["select"] + self._sections["where"]
                             + self._sections["order"]),
            columns=tuple(Column(item.alias, item.type,
                                 _describe(self.table, item.alias))
                          for item in outputs),
            decoders=tuple(item.decoder for item in outputs),
            pushed=tuple(self.pushed),
            limited=self.limit is not None,
            grouped=self.grouped,
        )

    def add_parameter(self, value: Any) -> str:
        self._current.append(value)
        return "?"

    @contextmanager
    def section(self, name: str):
        """Collect the parameters added inside into one clause of the SQL."""
        previous = self._current
        self._current = self._sections[name]
        try:
            yield
        finally:
            self._current = previous

    # -- rollback ---------------------------------------------------------

    def snapshot(self) -> tuple:
        """Everything a half-finished step could have changed.

        A step is translated by mutating the builder, and it can fail in the
        middle — `summarize a=count(), b=round(avg(x))` pushes the first
        aggregate and then discovers that `round` has no SQL form. Without a
        rollback the builder keeps the bound parameter the abandoned half
        added, and SQLite is handed a statement with one placeholder and two
        values.
        """
        return (list(self.select), list(self.where),
                {name: list(values) for name, values in self._sections.items()},
                list(self.group), list(self.aggregates), list(self.order),
                self.limit, self.distinct, self.grouped, list(self.pushed),
                dict(self.visible))

    def restore(self, saved: tuple) -> None:
        current = next((name for name, values in self._sections.items()
                        if values is self._current), "where")
        (self.select, self.where, sections, self.group, self.aggregates,
         self.order, self.limit, self.distinct, self.grouped, self.pushed,
         self.visible) = ([list(saved[0]), list(saved[1]), saved[2],
                           list(saved[3]), list(saved[4]), list(saved[5])]
                          + [saved[6], saved[7], saved[8]]
                          + [list(saved[9]), dict(saved[10])])
        self._sections = {name: list(values) for name, values in sections.items()}
        self._current = self._sections[current]


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _describe(table: TableDef, alias: str) -> str:
    binding = table.column(alias)
    return binding.description if binding else ""


# ---------------------------------------------------------------------------
# The planner
# ---------------------------------------------------------------------------


def plan(table: TableDef, steps: tuple, *, full_text: bool = True,
         row_limit: int | None = None, environment: Any = None) -> Plan:
    """Translate the longest prefix of `steps` that SQL can do faithfully."""
    builder = _Builder(table, full_text, environment)
    consumed = 0

    for step in steps:
        saved = builder.snapshot()
        try:
            _push(builder, step)
        except (NotPushable, KqlError):
            builder.restore(saved)
            break
        consumed += 1
        if builder.limit is not None:
            # Anything after a LIMIT sees a different set of rows, so this is
            # where the SQL has to stop whatever comes next.
            break

    if row_limit is not None and builder.limit is None and not builder.grouped:
        # A guard rail, not a user-visible limit: the engine asks for one more
        # row than it will show so it can say "truncated" honestly.
        builder.limit = row_limit

    result = builder.build()
    result.consumed = consumed
    return result


def _push(builder: _Builder, step: node.Operator) -> None:
    handler = _HANDLERS.get(type(step))
    if handler is None:
        raise NotPushable
    handler(builder, step)


def _push_where(builder: _Builder, step: node.Where) -> None:
    if builder.limit is not None:
        raise NotPushable
    if builder.grouped:
        # A filter after summarize is a HAVING, and the expressions available
        # are the aggregate aliases rather than the base columns. Not worth
        # the complexity: the grouped result is small by construction.
        raise NotPushable
    with builder.section("where"):
        condition, _kind = _expr(builder, step.condition)
    builder.where.append(condition)
    builder.pushed.append("where")


def _push_search(builder: _Builder, step: node.Search) -> None:
    if builder.grouped or builder.limit is not None:
        raise NotPushable
    term = _constant(step.term, builder)
    if not isinstance(term, str) or not term.strip():
        raise NotPushable
    columns = ([builder.table.column(item.name) for item in step.columns]
               if step.columns else list(builder.table.searchable()))
    if any(item is None for item in columns):
        raise NotPushable

    section = builder.section("where")
    section.__enter__()

    pieces: list[str] = []
    if builder.full_text and not step.columns and not step.case_sensitive:
        text_columns = [item for item in columns if item.full_text]
        if text_columns:
            pieces.append(
                f"e.id IN (SELECT rowid FROM {builder.table.full_text_table} "
                f"WHERE {builder.table.full_text_table} MATCH "
                f"{builder.add_parameter(_fts_phrase(term))})")
            columns = [item for item in columns if not item.full_text]

    for binding in columns:
        pieces.append(_contains_sql(builder, binding.sql, term,
                                    case_sensitive=step.case_sensitive,
                                    encode=binding.encode))
    section.__exit__(None, None, None)
    if not pieces:
        raise NotPushable
    builder.where.append(" OR ".join(f"({piece})" for piece in pieces))
    builder.pushed.append("search")


def _fts_phrase(term: str) -> str:
    """Quote a term so FTS5 reads it as a phrase, not as its own syntax.

    Without this, a search for ``a OR b`` or ``NEAR`` would be interpreted as
    an FTS expression, and a search for a path with a hyphen would fail.
    """
    return '"' + term.replace('"', '""') + '"'


def _push_take(builder: _Builder, step: node.Take) -> None:
    count = _constant(step.count, builder)
    number = V.to_long(count)
    if number is None or number < 0:
        raise NotPushable
    builder.limit = number if builder.limit is None else min(builder.limit, number)
    builder.pushed.append("take")


def _push_top(builder: _Builder, step: node.Top) -> None:
    _push_sort(builder, node.SortBy(position=step.position, keys=step.keys))
    _push_take(builder, node.Take(position=step.position, count=step.count))
    builder.pushed[-2:] = ["top"]


def _push_sort(builder: _Builder, step: node.SortBy) -> None:
    if builder.limit is not None:
        raise NotPushable
    terms: list[tuple[str, bool, bool | None]] = []
    with builder.section("order"):
        for key in step.keys:
            alias = _output_alias(builder, key.expr)
            if alias is not None:
                # Order by the output name rather than repeating the
                # expression. `summarize Errors = countif(...) | sort by
                # Errors` would otherwise emit the CASE a second time and
                # bind its parameters twice.
                expression = _quote(alias)
            else:
                expression, _kind = _expr(builder, key.expr)
            terms.append((expression, key.descending, key.nulls_first))
    builder.order = terms
    builder.pushed.append("sort by")


def _output_alias(builder: _Builder, expression: Any) -> str | None:
    """The output column a sort key names, if it names one."""
    if not isinstance(expression, node.ColumnRef):
        return None
    for item in builder.outputs():
        if item.alias.lower() == expression.name.lower():
            return item.alias
    return None


def _push_count(builder: _Builder, step: node.CountRows) -> None:
    if builder.limit is not None:
        raise NotPushable
    builder.group = []
    builder.aggregates = [_Output(step.name, "COUNT(*)", ColumnType.LONG)]
    builder.grouped = True
    builder.order = []
    builder.pushed.append("count")


def _push_distinct(builder: _Builder, step: node.Distinct) -> None:
    if builder.grouped or builder.limit is not None:
        raise NotPushable
    if not step.columns:
        raise NotPushable
    chosen: list[_Output] = []
    for reference in step.columns:
        binding = builder.table.column(reference.name)
        if binding is None:
            raise NotPushable
        chosen.append(_Output(binding.name, binding.sql, binding.type, binding.decode))
    builder.select = chosen
    builder.visible = {item.alias: item for item in chosen}
    builder.distinct = True
    builder.pushed.append("distinct")


def _push_project(builder: _Builder, step: node.Project) -> None:
    if builder.grouped or builder.limit is not None:
        raise NotPushable
    if step.mode not in ("project", "project-keep", "project-away"):
        raise NotPushable

    if step.mode == "project-away":
        removed = {item.name.lower() for item in step.items}
        kept = [item for item in builder.select if item.alias.lower() not in removed]
        if len(kept) == len(builder.select):
            raise NotPushable
        builder.select = kept
    else:
        chosen: list[_Output] = []
        for assignment in step.items:
            value = assignment.value
            if not isinstance(value, node.ColumnRef):
                raise NotPushable
            existing = builder.visible.get(value.name) or _find(builder, value.name)
            if existing is None:
                raise NotPushable
            chosen.append(_Output(assignment.name, existing.sql, existing.type,
                                  existing.decoder))
        builder.select = chosen
    builder.visible = {item.alias: item for item in builder.select}
    builder.pushed.append(step.mode)


def _find(builder: _Builder, name: str) -> _Output | None:
    lowered = name.lower()
    for item in builder.select:
        if item.alias.lower() == lowered:
            return item
    return None


#: Aggregates whose SQL form is exactly the Python one. Anything not here
#: runs in Python, which is correct but reads the whole group.
_SQL_AGGREGATES: dict[str, tuple[str, ColumnType | None]] = {
    "count": ("COUNT(*)", ColumnType.LONG),
    "countif": ("SUM(CASE WHEN {0} THEN 1 ELSE 0 END)", ColumnType.LONG),
    "sum": ("SUM({0})", None),
    "sumif": ("SUM(CASE WHEN {1} THEN {0} ELSE 0 END)", None),
    "avg": ("AVG({0})", ColumnType.REAL),
    "average": ("AVG({0})", ColumnType.REAL),
    "min": ("MIN({0})", None),
    "max": ("MAX({0})", None),
    "dcount": ("COUNT(DISTINCT {0})", ColumnType.LONG),
    "count_distinct": ("COUNT(DISTINCT {0})", ColumnType.LONG),
}


def _push_summarize(builder: _Builder, step: node.Summarize) -> None:
    if builder.grouped or builder.limit is not None or builder.order:
        raise NotPushable

    section = builder.section("select")
    section.__enter__()
    groups: list[_Output] = []
    for assignment in step.by:
        expression, kind = _expr(builder, assignment.value)
        groups.append(_Output(assignment.name, expression, kind,
                              _decoder_for(builder, assignment.value)))

    aggregates: list[_Output] = []
    for assignment in step.aggregates:
        call = assignment.value
        if not isinstance(call, node.Call):
            raise NotPushable
        pattern = _SQL_AGGREGATES.get(call.name.lower())
        if pattern is None:
            raise NotPushable
        template, kind = pattern
        arguments: list[str] = []
        argument_type = ColumnType.LONG
        decoder = None
        for argument in call.args:
            if isinstance(argument, node.Star):
                raise NotPushable
            text, argument_kind = _expr(builder, argument)
            arguments.append(text)
            argument_type = argument_kind
            decoder = _decoder_for(builder, argument)
        if len(arguments) < template.count("{"):
            raise NotPushable
        aggregates.append(_Output(
            assignment.name, template.format(*arguments),
            kind or argument_type,
            decoder if kind is None and call.name.lower() in ("min", "max") else None))

    section.__exit__(None, None, None)
    builder.group = groups
    builder.aggregates = aggregates
    builder.grouped = True
    builder.visible = {item.alias: item for item in groups + aggregates}
    builder.pushed.append("summarize")


_HANDLERS: dict[type, Callable] = {
    node.Where: _push_where,
    node.Take: _push_take,
    node.Top: _push_top,
    node.SortBy: _push_sort,
    node.CountRows: _push_count,
    node.Distinct: _push_distinct,
    node.Project: _push_project,
    node.Summarize: _push_summarize,
    node.Search: _push_search,
}


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------


def _expr(builder: _Builder, expression: Any) -> tuple[str, ColumnType]:
    """One expression as SQL. Raises NotPushable for anything uncertain."""
    constant = _maybe_constant(expression, builder)
    if constant is not _NOT_CONSTANT:
        return builder.add_parameter(_store(constant)), _type_of(constant)

    if isinstance(expression, node.ColumnRef):
        found = builder.visible.get(expression.name) or _find(builder, expression.name)
        if found is None:
            binding = builder.table.column(expression.name)
            if binding is None:
                raise NotPushable
            return binding.sql, binding.type
        return found.sql, found.type

    if isinstance(expression, node.Member):
        return _json_path(builder, expression), ColumnType.STRING

    if isinstance(expression, node.Index):
        return _json_path(builder, expression), ColumnType.STRING

    if isinstance(expression, node.Unary):
        if expression.op == "not":
            inner, _kind = _expr(builder, expression.operand)
            return f"NOT ({inner})", ColumnType.BOOL
        if expression.op == "-":
            inner, kind = _expr(builder, expression.operand)
            return f"-({inner})", kind
        if expression.op == "+":
            return _expr(builder, expression.operand)
        raise NotPushable

    if isinstance(expression, node.Binary):
        return _binary(builder, expression)

    if isinstance(expression, node.InList):
        return _in_list(builder, expression)

    if isinstance(expression, node.Between):
        return _between(builder, expression)

    if isinstance(expression, node.Call):
        return _call(builder, expression)

    raise NotPushable


def _binary(builder: _Builder, expression: node.Binary) -> tuple[str, ColumnType]:
    operator = expression.op

    if operator in ("and", "or"):
        left, _a = _expr(builder, expression.left)
        right, _b = _expr(builder, expression.right)
        return f"({left}) {operator.upper()} ({right})", ColumnType.BOOL

    if operator in ("==", "!=", "<", "<=", ">", ">=", "=~", "!~"):
        return _comparison(builder, expression)

    if operator in ("+", "-", "*", "/", "%"):
        left, left_kind = _expr(builder, expression.left)
        right, _right_kind = _expr(builder, expression.right)
        if left_kind in (ColumnType.STRING, ColumnType.DYNAMIC):
            raise NotPushable
        symbol = {"+": "+", "-": "-", "*": "*", "/": "/", "%": "%"}[operator]
        return f"({left} {symbol} {right})", left_kind

    if operator in ("contains", "!contains", "contains_cs", "!contains_cs",
                    "startswith", "!startswith", "startswith_cs", "!startswith_cs",
                    "endswith", "!endswith", "endswith_cs", "!endswith_cs"):
        return _text_operator(builder, expression)

    if operator in ("has", "!has", "has_cs", "!has_cs"):
        return _has_operator(builder, expression)

    raise NotPushable


def _comparison(builder: _Builder, expression: node.Binary) -> tuple[str, ColumnType]:
    binding = _binding_of(builder, expression.left)
    right = _maybe_constant(expression.right, builder)

    if binding is not None and right is not _NOT_CONSTANT:
        encoded = binding.encode(right) if binding.encode else _store(right)
        if encoded is None and right is not None:
            # A literal the column cannot represent — such as a level name
            # that is not a level. It matches nothing, and saying so in SQL is
            # both correct and instant.
            return ("0 = 1" if expression.op in ("==", "=~") else "1 = 1",
                    ColumnType.BOOL)
        left_sql = binding.sql
        symbol = _SQL_COMPARISON[expression.op]
        if expression.op in ("=~", "!~") and binding.type is ColumnType.STRING:
            return (f"lower({left_sql}) {symbol} lower({builder.add_parameter(encoded)})",
                    ColumnType.BOOL)
        return (f"{left_sql} {symbol} {builder.add_parameter(encoded)}",
                ColumnType.BOOL)

    left, left_kind = _expr(builder, expression.left)
    right_sql, _right_kind = _expr(builder, expression.right)
    if expression.op in ("=~", "!~"):
        return (f"lower({left}) {_SQL_COMPARISON[expression.op]} lower({right_sql})",
                ColumnType.BOOL)
    return f"{left} {_SQL_COMPARISON[expression.op]} {right_sql}", ColumnType.BOOL


_SQL_COMPARISON = {"==": "=", "!=": "<>", "<": "<", "<=": "<=", ">": ">",
                   ">=": ">=", "=~": "=", "!~": "<>"}


def _text_operator(builder: _Builder, expression: node.Binary) -> tuple[str, ColumnType]:
    operator = expression.op
    negate = operator.startswith("!")
    base = operator.lstrip("!")
    case_sensitive = base.endswith("_cs")
    base = base.removesuffix("_cs")

    binding = _binding_of(builder, expression.left)
    if binding is None or binding.type is not ColumnType.STRING:
        raise NotPushable
    needle = _constant(expression.right, builder)
    if not isinstance(needle, str):
        raise NotPushable

    if base == "contains":
        sql = _contains_sql(builder, binding.sql, needle,
                            case_sensitive=case_sensitive)
    elif base == "startswith":
        if case_sensitive:
            sql = (f"substr({binding.sql}, 1, {len(needle)}) = "
                   f"{builder.add_parameter(needle)}")
        else:
            sql = (f"lower(substr({binding.sql}, 1, {len(needle)})) = "
                   f"{builder.add_parameter(needle.lower())}")
    else:
        if not needle:
            return "1 = 1", ColumnType.BOOL
        if case_sensitive:
            sql = (f"substr({binding.sql}, -{len(needle)}) = "
                   f"{builder.add_parameter(needle)}")
        else:
            sql = (f"lower(substr({binding.sql}, -{len(needle)})) = "
                   f"{builder.add_parameter(needle.lower())}")
    return (f"NOT ({sql})" if negate else sql), ColumnType.BOOL


def _contains_sql(builder: _Builder, column_sql: str, needle: str, *,
                  case_sensitive: bool, encode=None) -> str:
    if not needle:
        return "1 = 1"
    if case_sensitive:
        return f"instr({column_sql}, {builder.add_parameter(needle)}) > 0"
    return (f"instr(lower({column_sql}), "
            f"{builder.add_parameter(needle.lower())}) > 0")


def _has_operator(builder: _Builder, expression: node.Binary) -> tuple[str, ColumnType]:
    """``Message has "error"`` — pushed only through the full-text index.

    SQLite has no word-boundary operator, and ``LIKE '% error %'`` is not the
    same thing: it misses the first and last words of a line and treats
    punctuation as part of a word. Rather than push a near-miss, this pushes
    the exact equivalent when FTS5 is available and hands the whole comparison
    to Python when it is not.
    """
    operator = expression.op
    negate = operator.startswith("!")
    case_sensitive = operator.endswith("_cs")
    if case_sensitive or not builder.full_text:
        raise NotPushable

    binding = _binding_of(builder, expression.left)
    if binding is None or not binding.full_text:
        raise NotPushable
    needle = _constant(expression.right, builder)
    if not isinstance(needle, str) or not needle.strip():
        raise NotPushable

    match = (f"e.id IN (SELECT rowid FROM {builder.table.full_text_table} "
             f"WHERE {builder.table.full_text_table} MATCH "
             f"{builder.add_parameter(_fts_phrase(needle))})")
    return (f"NOT ({match})" if negate else match), ColumnType.BOOL


def _in_list(builder: _Builder, expression: node.InList) -> tuple[str, ColumnType]:
    binding = _binding_of(builder, expression.target)
    values: list[Any] = []
    for item in expression.items:
        value = _maybe_constant(item, builder)
        if value is _NOT_CONSTANT:
            raise NotPushable
        if isinstance(value, list):
            values.extend(value)
        else:
            values.append(value)
    if not values:
        return ("1 = 1" if expression.negate else "0 = 1"), ColumnType.BOOL

    if binding is not None:
        encoded = [binding.encode(item) if binding.encode else _store(item)
                   for item in values]
        encoded = [item for item in encoded if item is not None]
        if not encoded:
            return ("1 = 1" if expression.negate else "0 = 1"), ColumnType.BOOL
        column = (f"lower({binding.sql})" if expression.fold_case
                  and binding.type is ColumnType.STRING else binding.sql)
        if expression.fold_case and binding.type is ColumnType.STRING:
            encoded = [item.lower() if isinstance(item, str) else item
                       for item in encoded]
        placeholders = ", ".join(builder.add_parameter(item) for item in encoded)
        sql = f"{column} IN ({placeholders})"
        return (f"NOT ({sql})" if expression.negate else sql), ColumnType.BOOL

    left, _kind = _expr(builder, expression.target)
    placeholders = ", ".join(builder.add_parameter(_store(item)) for item in values)
    sql = f"{left} IN ({placeholders})"
    return (f"NOT ({sql})" if expression.negate else sql), ColumnType.BOOL


def _between(builder: _Builder, expression: node.Between) -> tuple[str, ColumnType]:
    binding = _binding_of(builder, expression.target)
    low = _maybe_constant(expression.low, builder)
    high = _maybe_constant(expression.high, builder)
    if low is _NOT_CONSTANT or high is _NOT_CONSTANT:
        raise NotPushable
    if binding is not None:
        encoder = binding.encode or _store
        low_value, high_value = encoder(low), encoder(high)
        if low_value is None or high_value is None:
            raise NotPushable
        sql = (f"{binding.sql} BETWEEN {builder.add_parameter(low_value)} "
               f"AND {builder.add_parameter(high_value)}")
    else:
        left, _kind = _expr(builder, expression.target)
        sql = (f"{left} BETWEEN {builder.add_parameter(_store(low))} "
               f"AND {builder.add_parameter(_store(high))}")
    return (f"NOT ({sql})" if expression.negate else sql), ColumnType.BOOL


#: Scalar functions with an exact SQLite equivalent.
_SQL_FUNCTIONS: dict[str, tuple[str, ColumnType]] = {
    "tolower": ("lower({0})", ColumnType.STRING),
    "toupper": ("upper({0})", ColumnType.STRING),
    "strlen": ("length({0})", ColumnType.LONG),
    "abs": ("abs({0})", ColumnType.REAL),
    "isnull": ("{0} IS NULL", ColumnType.BOOL),
    "isnotnull": ("{0} IS NOT NULL", ColumnType.BOOL),
    "isempty": ("({0} IS NULL OR {0} = '')", ColumnType.BOOL),
    "isnotempty": ("({0} IS NOT NULL AND {0} <> '')", ColumnType.BOOL),
    "notempty": ("({0} IS NOT NULL AND {0} <> '')", ColumnType.BOOL),
}


def _call(builder: _Builder, expression: node.Call) -> tuple[str, ColumnType]:
    name = expression.name.lower()

    if name == "bin":
        return _bin_sql(builder, expression)

    pattern = _SQL_FUNCTIONS.get(name)
    if pattern is None:
        raise NotPushable
    template, kind = pattern
    if len(expression.args) != 1:
        raise NotPushable
    inner, _inner_kind = _expr(builder, expression.args[0])
    return template.format(inner), kind


def _bin_sql(builder: _Builder, expression: node.Call) -> tuple[str, ColumnType]:
    """``bin(Timestamp, 1h)`` becomes integer division on the stored value."""
    if len(expression.args) != 2:
        raise NotPushable
    binding = _binding_of(builder, expression.args[0])
    step = _maybe_constant(expression.args[1], builder)
    if step is _NOT_CONSTANT:
        raise NotPushable

    if binding is not None and binding.type is ColumnType.DATETIME:
        if isinstance(step, timedelta):
            width = int(step.total_seconds() * 1_000_000)
        else:
            width = V.to_long(step)
        if not width or width <= 0:
            raise NotPushable
        if binding.decode is not None and binding.sql.endswith(".ts"):
            return (f"(CAST({binding.sql} / {width} AS INTEGER) * {width})",
                    ColumnType.DATETIME)
        raise NotPushable

    width = V.to_real(step)
    if width is None or width == 0:
        raise NotPushable
    inner, kind = _expr(builder, expression.args[0])
    if kind in (ColumnType.STRING, ColumnType.DYNAMIC, ColumnType.DATETIME):
        raise NotPushable
    if float(width).is_integer():
        integer_width = int(width)
        return (f"(CAST({inner} / {integer_width} AS INTEGER) * {integer_width})",
                ColumnType.LONG)
    return (f"(CAST({inner} / {width} AS INTEGER) * {width})", ColumnType.REAL)


def _json_path(builder: _Builder, expression: Any) -> str:
    """``Extra.pid`` and ``Extra["pid"]`` become json_extract on the column.

    Only one level deep and only on a genuine dynamic column: anything more
    adventurous goes to Python, where the semantics are defined by one
    implementation rather than by SQLite's JSON dialect agreeing with it.
    """
    if isinstance(expression, node.Member):
        target, key = expression.target, expression.name
    elif isinstance(expression, node.Index):
        key_value = _maybe_constant(expression.index, builder)
        if not isinstance(key_value, str):
            raise NotPushable
        target, key = expression.target, key_value
    else:
        raise NotPushable

    if not isinstance(target, node.ColumnRef):
        raise NotPushable
    binding = builder.table.column(target.name)
    if binding is None or binding.type is not ColumnType.DYNAMIC:
        raise NotPushable
    if any(character in key for character in '"$.[]'):
        raise NotPushable
    return f"json_extract({binding.sql}, '$.{key}')"


def _binding_of(builder: _Builder, expression: Any) -> Binding | None:
    """The catalogue binding a bare column reference names, if it is one."""
    if isinstance(expression, node.ColumnRef):
        return builder.table.column(expression.name)
    return None


def _decoder_for(builder: _Builder, expression: Any) -> Callable | None:
    if isinstance(expression, node.ColumnRef):
        binding = builder.table.column(expression.name)
        return binding.decode if binding else None
    if isinstance(expression, node.Call) and expression.name.lower() == "bin":
        return _decoder_for(builder, expression.args[0]) if expression.args else None
    return None


# ---------------------------------------------------------------------------
# Constant folding
# ---------------------------------------------------------------------------

_NOT_CONSTANT = object()


def _maybe_constant(expression: Any, builder: "_Builder | None" = None) -> Any:
    """Evaluate an expression that mentions no columns, or return the sentinel.

    This is what lets ``where Timestamp > ago(1h)`` push down: the right-hand
    side is worked out once, here, and becomes a bound integer rather than a
    per-row function call. A `let`-bound value counts as constant, which is
    why the builder's environment comes along.
    """
    try:
        return _constant(expression, builder)
    except NotPushable:
        return _NOT_CONSTANT


def _constant(expression: Any, builder: "_Builder | None" = None) -> Any:
    from .engine import evaluate_constant

    try:
        return evaluate_constant(
            expression, builder.environment if builder is not None else None)
    except (KqlError, ValueError, TypeError):
        raise NotPushable from None


def _store(value: Any) -> Any:
    """A KQL value as something SQLite can bind."""
    if value is None or isinstance(value, (int, float, str, bytes)):
        return value
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, datetime):
        return int(value.timestamp() * 1_000_000)
    if isinstance(value, timedelta):
        return int(value.total_seconds() * 1_000_000)
    raise NotPushable


def _type_of(value: Any) -> ColumnType:
    return V.kind_of(value)
