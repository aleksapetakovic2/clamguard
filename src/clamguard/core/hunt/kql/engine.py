"""Running a query: SQL underneath, streaming Python generators on top.

The shape of a run:

1. :func:`parse` turns the text into a tree.
2. The page's time range is injected as a ``where`` in front of everything
   else, exactly as Sentinel does, so the picker and the query agree.
3. :mod:`compiler` translates the longest prefix it is sure about into one
   SELECT, which SQLite answers using its indexes.
4. Whatever is left runs here, as generators over the cursor, so an operator
   that only needs the first fifty rows only causes fifty to be read.

Expressions are **compiled once per query**, not interpreted per row: walking
the tree for every one of a million rows costs more than everything else put
together. :func:`compile_expression` returns a closure over the column
positions it needs.

Limits are real and are reported rather than hidden. A run stops at
``Options.row_limit`` materialised rows and says so in the status strip; it
stops at ``Options.timeout`` seconds through a SQLite progress handler, which
can interrupt a scan in the middle rather than after it.
"""

from __future__ import annotations

import itertools
import random
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Iterator, Sequence

from .. import catalogue
from ..model import (
    Column,
    ColumnType,
    QueryStats,
    ResultTable,
    TimeRange,
)
from . import ast as node
from . import functions as fn
from . import values as V
from .compiler import Plan, plan as compile_plan
from .errors import KqlError, did_you_mean
from .parser import parse

#: How often the row pipeline checks the clock. Every row would cost more
#: than the work; every ten thousand would let a query run seconds past its
#: deadline on a slow filter.
_DEADLINE_EVERY = 2048

#: How many values are looked at when working out a computed column's type.
_TYPE_SAMPLE = 200


# ---------------------------------------------------------------------------
# Options and frames
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Options:
    """Everything about a run that is not the query itself."""

    #: The most rows a result may contain. Beyond this it is truncated and
    #: says so; the grid cannot usefully show more and the memory is real.
    row_limit: int = 100_000
    #: Wall-clock seconds before the run is interrupted.
    timeout: float = 60.0
    #: The page's time-range picker, applied to the leading table.
    time_range: TimeRange | None = None
    #: False forces the pure-Python path. Used by the differential tests and
    #: by the Query details panel's "compare" button.
    pushdown: bool = True
    #: False when the store has no FTS5 index.
    full_text: bool = True
    #: Set by the UI to abort a running query.
    should_stop: Callable[[], bool] | None = None


@dataclass(slots=True)
class Frame:
    """A table in flight: named columns and an iterable of row tuples."""

    columns: tuple[Column, ...]
    rows: Iterable[tuple]
    #: True when the rows are in a meaningful order (after sort/serialize).
    ordered: bool = False

    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.columns)

    def materialise(self) -> "Frame":
        if not isinstance(self.rows, list):
            self.rows = list(self.rows)
        return self


class Schema:
    """Column positions, looked up case-insensitively as Kusto does."""

    __slots__ = ("columns", "_index")

    def __init__(self, columns: Sequence[Column]) -> None:
        self.columns = tuple(columns)
        self._index = {column.name.lower(): position
                       for position, column in enumerate(self.columns)}

    def index(self, name: str) -> int | None:
        return self._index.get(name.lower())

    def column(self, name: str) -> Column | None:
        position = self.index(name)
        return self.columns[position] if position is not None else None

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(column.name for column in self.columns)

    def __len__(self) -> int:
        return len(self.columns)


class WindowState:
    """Shared position for row_number(), prev() and next().

    A mutable cell rather than an extra parameter on every compiled closure:
    the closures run once per row per expression, and one more argument on
    that path is measurable on a million rows.
    """

    __slots__ = ("index", "rows", "used", "column")

    def __init__(self) -> None:
        self.index = 0
        self.rows: list[tuple] = []
        self.used = False
        self.column = 0


@dataclass(slots=True)
class Environment:
    """What the evaluator needs that is not the query."""

    connection: sqlite3.Connection | None = None
    options: Options = field(default_factory=Options)
    lets: dict = field(default_factory=dict)
    stats: QueryStats = field(default_factory=QueryStats)
    source: str = ""
    deadline: float = 0.0
    visualisation: tuple[str, dict] | None = None
    #: True for the editor's live check, which resolves names and builds the
    #: column list without a connection and without reading a single row.
    dry_run: bool = False

    def expired(self) -> bool:
        if self.options.should_stop is not None and self.options.should_stop():
            return True
        return bool(self.deadline) and time.monotonic() > self.deadline

    def check(self) -> None:
        if self.expired():
            raise KqlError(
                "The query was stopped before it finished.", 0, 1,
                f"It hit the {self.options.timeout:.0f} second limit, or you "
                "pressed Cancel. Narrow the time range or add a filter.",
                self.source)


# ---------------------------------------------------------------------------
# The public surface
# ---------------------------------------------------------------------------


class Engine:
    """Runs queries against one read-only connection."""

    def __init__(self, connection: sqlite3.Connection | None = None,
                 options: Options | None = None) -> None:
        self.connection = connection
        self.options = options or Options()

    def run(self, text: str, options: Options | None = None) -> ResultTable:
        return run(text, self.connection, options or self.options)


def run(text: str, connection: sqlite3.Connection | None = None,
        options: Options | None = None) -> ResultTable:
    """Parse, plan and execute one query. Raises :class:`KqlError`."""
    options = options or Options()
    started = time.monotonic()
    query = parse(text)

    environment = Environment(
        connection=connection, options=options, source=text,
        deadline=started + options.timeout if options.timeout else 0.0)
    _install_guard(connection, environment)

    try:
        _bind_lets(query, environment)
        frame = _evaluate(query.body, environment)
        table = _collect(frame, environment)
    finally:
        _remove_guard(connection)

    table.stats.elapsed = time.monotonic() - started
    table.stats.sql = environment.stats.sql
    table.stats.parameters = environment.stats.parameters
    table.stats.pushed_down = environment.stats.pushed_down
    table.stats.evaluated = environment.stats.evaluated
    table.stats.scanned = environment.stats.scanned
    table.visualisation = environment.visualisation
    return table


def check(text: str, *, connection: sqlite3.Connection | None = None) -> KqlError | None:
    """Parse and resolve names without running anything.

    This is what the editor calls on every keystroke pause, so it must be
    cheap: it builds the pipeline's schema step by step and compiles each
    expression, which catches unknown tables, unknown columns, unknown
    functions and wrong argument counts, and touches no data.
    """
    try:
        query = parse(text)
        environment = Environment(connection=connection, source=text,
                                  dry_run=connection is None)
        _bind_lets(query, environment, dry_run=True)
        _describe_shape(query.body, environment)
    except KqlError as error:
        if not error.source:
            error.source = text
        return error
    except RecursionError:
        return KqlError("That query nests too deeply for me to read.", 0, 1,
                        source=text)
    return None


def describe_plan(text: str, connection: sqlite3.Connection | None = None,
                  options: Options | None = None) -> dict:
    """What the planner would do, for the Query details panel."""
    options = options or Options()
    query = parse(text)
    environment = Environment(connection=connection, options=options, source=text)
    body = query.body
    steps_above: tuple = ()
    while isinstance(body, node.Pipeline) and isinstance(body.source, node.Pipeline):
        # `search "x"` parses as a pipeline wrapping a pipeline; unwrap to the
        # table so the details panel still has SQL to show.
        steps_above = body.steps + steps_above
        body = body.source
    if not isinstance(body, node.Pipeline) or not isinstance(body.source, node.Table):
        return {"sql": "", "pushed": (), "evaluated": (), "table": ""}
    body = node.Pipeline(position=body.position, source=body.source,
                         steps=body.steps + steps_above)
    table = catalogue.table(body.source.name)
    if table is None:
        return {"sql": "", "pushed": (), "evaluated": (), "table": body.source.name}
    steps = _with_time_filter(table, body.steps, options.time_range)
    _bind_lets(query, environment, dry_run=True)
    result = compile_plan(table, steps, full_text=options.full_text,
                          environment=environment)
    return {
        "sql": result.sql,
        "parameters": result.parameters,
        "pushed": result.pushed,
        "evaluated": tuple(step.keyword for step in steps[result.consumed:]),
        "table": table.name,
    }


def evaluate_constant(expression: Any, environment: "Environment | None" = None) -> Any:
    """Evaluate an expression that mentions no columns. Used by the planner."""
    schema = Schema(())
    compiled = compile_expression(expression, schema,
                                  environment or Environment(), WindowState())
    return compiled(())


# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------


def _install_guard(connection, environment: Environment) -> None:
    """Let SQLite itself be interrupted, not only the Python loop above it.

    A ``WHERE instr(lower(message), …)`` over a million rows is a single SQL
    statement; without this the deadline could not be enforced until it
    finished, which is exactly the case the deadline exists for.
    """
    if connection is None:
        return
    try:
        connection.set_progress_handler(
            lambda: 1 if environment.expired() else 0, 20_000)
    except (AttributeError, sqlite3.DatabaseError):
        pass


def _remove_guard(connection) -> None:
    if connection is None:
        return
    try:
        connection.set_progress_handler(None, 0)
    except (AttributeError, sqlite3.DatabaseError):
        pass


# ---------------------------------------------------------------------------
# let
# ---------------------------------------------------------------------------


def _bind_lets(query: node.Query, environment: Environment,
               *, dry_run: bool = False) -> None:
    for statement in query.lets:
        value = statement.value
        if isinstance(value, node.Lambda):
            environment.lets[statement.name] = value
        elif isinstance(value, node.Pipeline) or isinstance(value, node.Union):
            environment.lets[statement.name] = _LazyTable(value)
        else:
            schema = Schema(())
            compiled = compile_expression(value, schema, environment, WindowState())
            environment.lets[statement.name] = compiled(())


class _LazyTable:
    """A tabular ``let``, evaluated at most once however often it is named."""

    __slots__ = ("definition", "frame")

    def __init__(self, definition) -> None:
        self.definition = definition
        self.frame: Frame | None = None

    def resolve(self, environment: Environment) -> Frame:
        if self.frame is None:
            self.frame = _evaluate(self.definition, environment).materialise()
        return Frame(self.frame.columns, list(self.frame.rows), self.frame.ordered)


# ---------------------------------------------------------------------------
# Tabular evaluation
# ---------------------------------------------------------------------------


def _evaluate(body: Any, environment: Environment) -> Frame:
    if isinstance(body, node.Print):
        return _evaluate_print(body, environment)
    if isinstance(body, node.Pipeline):
        return _evaluate_pipeline(body, environment)
    if isinstance(body, node.Union):
        return _apply_union(None, body, environment)
    if isinstance(body, node.Table):
        return _evaluate_pipeline(
            node.Pipeline(position=body.position, source=body, steps=()), environment)
    raise KqlError("I could not work out what this query produces.",
                   getattr(body, "position", 0), 1, source=environment.source)


def _evaluate_print(statement: node.Print, environment: Environment) -> Frame:
    schema = Schema(())
    columns: list[Column] = []
    values: list[Any] = []
    for item in statement.items:
        compiled = compile_expression(item.value, schema, environment, WindowState())
        result = compiled(())
        values.append(result)
        columns.append(Column(item.name, V.kind_of(result)))
    return Frame(tuple(columns), [tuple(values)], ordered=True)


def _evaluate_pipeline(pipeline: node.Pipeline, environment: Environment) -> Frame:
    source = pipeline.source
    steps = pipeline.steps
    frame: Frame

    if isinstance(source, node.Table):
        table = catalogue.table(source.name)
        binding = environment.lets.get(source.name)
        if table is not None:
            steps = _with_time_filter(table, steps, environment.options.time_range)
            frame, steps = _from_table(table, steps, environment)
        elif isinstance(binding, _LazyTable):
            frame = binding.resolve(environment)
        elif binding is not None:
            raise KqlError(f"`{source.name}` is a value, not a table.",
                           source.position, len(source.name),
                           "A `let` that defines a table has to end in a "
                           "pipeline, not a single value.", environment.source)
        else:
            raise KqlError(
                f"There is no table called `{source.name}`.",
                source.position, len(source.name),
                did_you_mean(source.name,
                             list(catalogue.names()) + list(environment.lets)),
                environment.source)
    elif isinstance(source, node.Pipeline):
        frame = _evaluate_pipeline(source, environment)
    elif isinstance(source, node.Union):
        frame = _apply_union(None, source, environment)
    else:
        raise KqlError("A query has to start with a table.",
                       getattr(source, "position", 0), 1, source=environment.source)

    for step in steps:
        environment.stats.evaluated = environment.stats.evaluated + (step.keyword,)
        frame = _apply(frame, step, environment)
    return frame


def _from_table(table: catalogue.TableDef, steps: tuple,
                environment: Environment) -> tuple[Frame, tuple]:
    """Open the table, pushing what the planner can into SQL."""
    options = environment.options
    if environment.connection is None:
        if environment.dry_run:
            # Name resolution only: produce the table's shape so the rest of
            # the pipeline can be checked, and no rows at all.
            shape = compile_plan(table, (), full_text=False,
                                 environment=environment)
            return Frame(shape.columns, []), steps
        raise KqlError("There is nothing indexed yet.", 0, 1,
                       "Use Scan for logs in the Sources dialog first.",
                       environment.source)

    _require_schema(table, environment)

    if options.pushdown:
        result = compile_plan(table, steps, full_text=options.full_text,
                              environment=environment)
        remaining = steps[result.consumed:]
    else:
        result = compile_plan(table, (), full_text=False, environment=environment)
        remaining = steps

    environment.stats.sql = result.sql
    environment.stats.parameters = result.parameters
    environment.stats.pushed_down = result.pushed
    return _run_sql(result, environment), remaining


def _require_schema(table: catalogue.TableDef, environment: Environment) -> None:
    """Say which database is missing rather than letting SQLite say it.

    `Scans` and `Detections` live in ClamGuard's history database, attached
    read-only. When it is not there — a fresh installation, or a test — the
    SQLite error is "no such table: history.detections", which tells the user
    nothing they can act on.
    """
    if not table.schema or environment.connection is None:
        return
    try:
        attached = {row[1] for row in
                    environment.connection.execute("PRAGMA database_list")}
    except sqlite3.DatabaseError:
        return
    if table.schema not in attached:
        raise KqlError(
            f"`{table.name}` is not available on this machine.", 0, 1,
            "It comes from ClamGuard's own scan history, which has not been "
            "created yet. Run a scan and it will appear.", environment.source)


def _run_sql(result: Plan, environment: Environment) -> Frame:
    connection = environment.connection
    try:
        cursor = connection.execute(result.sql, result.parameters)
    except sqlite3.OperationalError as error:
        raise KqlError(f"The store could not answer that: {error}.", 0, 1,
                       source=environment.source) from None

    decoders = result.decoders
    needs_decoding = any(decoder is not None for decoder in decoders)

    def stream() -> Iterator[tuple]:
        # The count is added back in `finally` rather than after the loop,
        # because an operator such as `take` abandons this generator — and a
        # run that reported "0 rows read" for the query that read the fewest
        # would be exactly backwards.
        counted = 0
        try:
            for row in cursor:
                counted += 1
                if counted % _DEADLINE_EVERY == 0:
                    environment.check()
                if needs_decoding:
                    yield tuple(decoder(value) if decoder is not None else value
                                for decoder, value in zip(decoders, row))
                else:
                    yield tuple(row)
        finally:
            environment.stats.scanned += counted

    return Frame(result.columns, stream(), ordered=bool(result.pushed
                                                        and "sort by" in result.pushed))


def _with_time_filter(table: catalogue.TableDef, steps: tuple,
                      time_range: TimeRange | None) -> tuple:
    """Put the page's time range in front of the pipeline.

    In front, not behind: it has to be the first thing SQL sees so the
    timestamp index narrows the scan before any other filter runs. A table
    with no time column, and an unbounded range, add nothing.
    """
    if time_range is None or time_range.unbounded or not table.time_column:
        return steps
    binding = table.column(table.time_column)
    if binding is None:
        return steps
    start, end = time_range.bounds()
    if start is None and end is None:
        return steps

    column = node.ColumnRef(position=0, name=table.time_column)
    condition: Any = None
    if start is not None:
        condition = node.Binary(
            position=0, op=">=", left=column,
            right=node.Literal(position=0, value=_moment(start), type="datetime"))
    if end is not None:
        upper = node.Binary(
            position=0, op="<=", left=column,
            right=node.Literal(position=0, value=_moment(end), type="datetime"))
        condition = upper if condition is None else node.Binary(
            position=0, op="and", left=condition, right=upper)
    return (node.Where(position=0, condition=condition),) + tuple(steps)


def _moment(microseconds: int) -> datetime:
    return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc)


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------


def _apply(frame: Frame, step: node.Operator, environment: Environment) -> Frame:
    handler = _OPERATORS.get(type(step))
    if handler is None:
        raise KqlError(f"`{step.keyword}` is not implemented yet.",
                       step.position, 1, source=environment.source)
    return handler(frame, step, environment)


def _apply_where(frame: Frame, step: node.Where, environment: Environment) -> Frame:
    schema = Schema(frame.columns)
    state = WindowState()
    condition = compile_expression(step.condition, schema, environment, state)
    rows = _windowed(frame, state)

    def filtered() -> Iterator[tuple]:
        truthy = V.truthy
        for position, row in enumerate(rows):
            if state.used:
                state.index = position
            if truthy(condition(row)):
                yield row

    return Frame(frame.columns, filtered(), frame.ordered)


def _apply_extend(frame: Frame, step: node.Extend, environment: Environment) -> Frame:
    schema = Schema(frame.columns)
    state = WindowState()
    additions = [(item.name, compile_expression(item.value, schema, environment, state))
                 for item in step.items]
    existing = {column.name.lower(): position
                for position, column in enumerate(frame.columns)}
    replacing = {name.lower(): existing[name.lower()]
                 for name, _compiled in additions if name.lower() in existing}

    columns = list(frame.columns)
    positions: list[int] = []
    for name, _compiled in additions:
        if name.lower() in replacing:
            positions.append(replacing[name.lower()])
        else:
            positions.append(len(columns))
            columns.append(Column(name, ColumnType.STRING))

    rows = _windowed(frame, state)

    def extended() -> Iterator[tuple]:
        for index, row in enumerate(rows):
            if state.used:
                state.index = index
            values = list(row) + [None] * (len(columns) - len(row))
            for position, (_name, compiled) in zip(positions, additions):
                values[position] = compiled(row)
            yield tuple(values)

    return _retype(Frame(tuple(columns), extended(), frame.ordered), positions)


def _apply_project(frame: Frame, step: node.Project,
                   environment: Environment) -> Frame:
    schema = Schema(frame.columns)
    state = WindowState()

    if step.mode == "project-away":
        removed = _resolve_names(step.items, schema, environment, step.position)
        keep = [position for position, column in enumerate(frame.columns)
                if position not in removed]
        return _pick(frame, keep, [frame.columns[position].name for position in keep])

    if step.mode == "project-keep":
        kept = _resolve_names(step.items, schema, environment, step.position)
        keep = [position for position in range(len(frame.columns)) if position in kept]
        return _pick(frame, keep, [frame.columns[position].name for position in keep])

    if step.mode == "project-reorder":
        wanted = list(_resolve_names(step.items, schema, environment, step.position,
                                     ordered=True))
        rest = [position for position in range(len(frame.columns))
                if position not in set(wanted)]
        order = wanted + rest
        return _pick(frame, order, [frame.columns[position].name for position in order])

    if step.mode == "project-rename":
        names = list(frame.names())
        types = list(frame.columns)
        for item in step.items:
            target = item.value
            if not isinstance(target, node.ColumnRef):
                raise KqlError("`project-rename` takes New = Old.",
                               item.position, 1, source=environment.source)
            position = schema.index(target.name)
            if position is None:
                raise _no_column(target, schema, environment)
            names[position] = item.name
        columns = tuple(Column(name, column.type, column.description)
                        for name, column in zip(names, types))
        return Frame(columns, frame.rows, frame.ordered)

    compiled = [(item.name, compile_expression(item.value, schema, environment, state))
                for item in step.items]
    columns = tuple(Column(name, ColumnType.STRING) for name, _ in compiled)
    rows = _windowed(frame, state)

    def projected() -> Iterator[tuple]:
        for index, row in enumerate(rows):
            if state.used:
                state.index = index
            yield tuple(function(row) for _name, function in compiled)

    return _retype(Frame(columns, projected(), frame.ordered),
                   list(range(len(columns))), inherit=frame, sources=step.items)


def _resolve_names(items, schema: Schema, environment: Environment,
                   position: int, *, ordered: bool = False):
    """Column positions named by a project-away/keep/reorder list."""
    found: list[int] = []
    for item in items:
        target = item.value
        if isinstance(target, node.ColumnRef):
            name = target.name
        elif isinstance(target, node.Literal):
            name = str(target.value)
        else:
            raise KqlError("This operator takes column names only.",
                           item.position, 1, source=environment.source)
        if "*" in name:
            pattern = re.compile("^" + re.escape(name).replace(r"\*", ".*") + "$",
                                 re.IGNORECASE)
            found.extend(index for index, column in enumerate(schema.columns)
                         if pattern.match(column.name))
            continue
        index = schema.index(name)
        if index is None:
            raise _no_column(target, schema, environment)
        found.append(index)
    return found if ordered else set(found)


def _pick(frame: Frame, positions: list[int], names: list[str]) -> Frame:
    columns = tuple(Column(name, frame.columns[position].type,
                           frame.columns[position].description)
                    for position, name in zip(positions, names))

    def picked() -> Iterator[tuple]:
        for row in frame.rows:
            yield tuple(row[position] for position in positions)

    return Frame(columns, picked(), frame.ordered)


def _apply_summarize(frame: Frame, step: node.Summarize,
                     environment: Environment) -> Frame:
    """Group the rows and reduce each group.

    Kusto allows arithmetic over aggregates — ``summarize Rate =
    100.0 * countif(Level == "error") / count()`` is an ordinary thing to
    write — so an output expression is not necessarily a bare aggregate call.
    Every aggregate anywhere in the expression is pulled out into its own
    accumulator and replaced by a placeholder column; once a group is
    finished, the outer expression is evaluated over one synthetic row of
    those results.
    """
    schema = Schema(frame.columns)
    state = WindowState()
    keys = [(item.name, compile_expression(item.value, schema, environment, state))
            for item in step.by]
    grouped_names = {name.lower() for name, _function in keys}

    specifications: list[_Aggregate] = []
    outputs: list[_Output] = []

    for item in step.aggregates:
        call = item.value
        definition = (fn.AGGREGATES.get(call.name.lower())
                      if isinstance(call, node.Call) else None)
        if definition is not None and definition.projecting:
            specifications.append(_projecting(call, definition, schema, frame,
                                              grouped_names, environment, state))
            outputs.append(_Output(item.name, None, (), len(specifications) - 1,
                                   specifications[-1].extra_names))
            continue

        found: list[tuple[str, node.Call, fn.Aggregation]] = []
        rewritten = _replace_aggregates(item.value, found, environment)
        if not found:
            unknown = _first_unknown_call(item.value)
            if unknown is not None:
                raise KqlError(
                    f"There is no function called `{unknown.name}`.",
                    unknown.position, len(unknown.name),
                    did_you_mean(unknown.name,
                                 list(fn.AGGREGATES) + list(fn.SCALARS)),
                    environment.source)
            raise KqlError(
                "There is no aggregate function in this expression.",
                item.position, 1,
                "`summarize` computes one value per group, so each thing it "
                "produces has to use count(), sum(), max(), and so on. "
                "Plain expressions belong in `extend` before it, or in `by`.",
                environment.source)
        indices: list[int] = []
        for placeholder, call_node, aggregation in found:
            specifications.append(_simple(call_node, aggregation, placeholder,
                                          schema, environment, state))
            indices.append(len(specifications) - 1)
        placeholder_schema = Schema(tuple(
            Column(specifications[index].placeholder, ColumnType.STRING)
            for index in indices))
        compiled = compile_expression(rewritten, placeholder_schema, environment,
                                      WindowState())
        outputs.append(_Output(item.name, compiled, tuple(indices), None, ()))

    groups: dict[tuple, list] = {}
    order: list[tuple] = []
    key_values_of: dict[tuple, tuple] = {}
    counted = 0
    rows = _windowed(frame, state)

    for index, row in enumerate(rows):
        if state.used:
            state.index = index
        counted += 1
        if counted % _DEADLINE_EVERY == 0:
            environment.check()
        key_values = tuple(function(row) for _name, function in keys)
        key = tuple(_hashable(value) for value in key_values)
        bucket = groups.get(key)
        if bucket is None:
            bucket = [item.definition.factory() for item in specifications]
            groups[key] = bucket
            order.append(key)
            key_values_of[key] = key_values
        for accumulator, specification in zip(bucket, specifications):
            accumulator.add(tuple(argument(row) for argument in specification.arguments))

    columns = [Column(name, ColumnType.STRING) for name, _function in keys]
    for output in outputs:
        columns.append(Column(output.name, ColumnType.STRING))
        columns.extend(Column(extra, ColumnType.STRING) for extra in output.extra)

    result_rows: list[tuple] = []
    for key in order:
        result_rows.append(tuple(key_values_of[key])
                           + _finish(groups[key], specifications, outputs))

    if not order and not keys:
        # `summarize count()` over nothing still answers 0 rather than saying
        # nothing at all, which is what makes "how many errors?" a question
        # with an answer.
        empty = [item.definition.factory() for item in specifications]
        result_rows.append(_finish(empty, specifications, outputs))

    return _retype(Frame(tuple(columns), result_rows), list(range(len(columns))))


@dataclass(slots=True)
class _Aggregate:
    """One accumulator to run over each group."""

    definition: fn.Aggregation
    arguments: list[Callable]
    placeholder: str = ""
    extra_names: tuple[str, ...] = ()


@dataclass(slots=True)
class _Output:
    """One column `summarize` produces, and how to build it."""

    name: str
    #: Compiled expression over the placeholder columns, or None when this
    #: output is a projecting aggregate that supplies its columns directly.
    expression: Callable | None
    #: Which specifications feed the expression, in placeholder order.
    inputs: tuple[int, ...] = ()
    #: For a projecting aggregate: which specification it is.
    projecting: int | None = None
    extra: tuple[str, ...] = ()


def _finish(accumulators: list, specifications: list[_Aggregate],
            outputs: list[_Output]) -> tuple:
    results = [accumulator.result() for accumulator in accumulators]
    values: list[Any] = []
    for output in outputs:
        if output.projecting is not None:
            outcome = results[output.projecting]
            values.extend(outcome if isinstance(outcome, tuple) else (outcome,))
            continue
        row = tuple(results[index] for index in output.inputs)
        values.append(output.expression(row))
    return tuple(values)


def _simple(call: node.Call, definition: fn.Aggregation, placeholder: str,
            schema: Schema, environment: Environment,
            state: WindowState) -> _Aggregate:
    _check_aggregate_arity(call, definition, environment)
    arguments = []
    for argument in call.args:
        if isinstance(argument, node.Star):
            raise KqlError(f"`{call.name}()` does not take `*`.",
                           argument.position, 1, source=environment.source)
        arguments.append(compile_expression(argument, schema, environment, state))
    return _Aggregate(definition, arguments, placeholder)


def _projecting(call: node.Call, definition: fn.Aggregation, schema: Schema,
                frame: Frame, grouped: set, environment: Environment,
                state: WindowState) -> _Aggregate:
    """``arg_max(Timestamp, *)`` — the whole row where a column peaks."""
    _check_aggregate_arity(call, definition, environment)
    arguments: list[Callable] = []
    extra_names: list[str] = []
    for position, argument in enumerate(call.args):
        if isinstance(argument, node.Star):
            for column in frame.columns:
                if column.name.lower() in grouped:
                    continue
                index = schema.index(column.name)
                arguments.append(lambda row, index=index:
                                 row[index] if index < len(row) else None)
                extra_names.append(column.name)
            continue
        arguments.append(compile_expression(argument, schema, environment, state))
        if position:
            extra_names.append(node_name(argument, len(extra_names)))
    return _Aggregate(definition, arguments, "", tuple(extra_names))


def _check_aggregate_arity(call: node.Call, definition: fn.Aggregation,
                           environment: Environment) -> None:
    fn.check_arity(
        fn.Function(definition.name, definition.signature, definition.summary,
                    "aggregate", lambda: None, definition.min_args,
                    definition.max_args),
        len(call.args), call.position, environment.source)


def _first_unknown_call(expression: Any) -> node.Call | None:
    """The first function call in an expression that names nothing real."""
    if isinstance(expression, node.Call):
        lowered = expression.name.lower()
        if lowered not in fn.SCALARS and lowered not in fn.AGGREGATES \
                and lowered not in fn.WINDOW_FUNCTIONS and lowered != "toscalar":
            return expression
        for argument in expression.args:
            found = _first_unknown_call(argument)
            if found is not None:
                return found
        return None
    for attribute in ("left", "right", "operand", "target", "index", "low", "high"):
        child = getattr(expression, attribute, None)
        if child is not None and not isinstance(child, (str, int, float, bool)):
            found = _first_unknown_call(child)
            if found is not None:
                return found
    for item in getattr(expression, "items", ()) or ():
        found = _first_unknown_call(item)
        if found is not None:
            return found
    return None


def _replace_aggregates(expression: Any, found: list,
                        environment: Environment) -> Any:
    """Lift every aggregate call out of an expression, leaving placeholders."""
    if isinstance(expression, node.Call):
        definition = fn.AGGREGATES.get(expression.name.lower())
        if definition is not None:
            if definition.projecting:
                raise KqlError(
                    f"`{expression.name}()` cannot be combined with anything.",
                    expression.position, len(expression.name),
                    "It returns several columns, so it has to stand on its own.",
                    environment.source)
            placeholder = f"$agg{len(found)}"
            found.append((placeholder, expression, definition))
            return node.ColumnRef(position=expression.position, name=placeholder)
        return node.Call(
            position=expression.position, name=expression.name,
            args=tuple(_replace_aggregates(argument, found, environment)
                       for argument in expression.args))
    if isinstance(expression, node.Binary):
        return node.Binary(
            position=expression.position, op=expression.op,
            left=_replace_aggregates(expression.left, found, environment),
            right=_replace_aggregates(expression.right, found, environment))
    if isinstance(expression, node.Unary):
        return node.Unary(
            position=expression.position, op=expression.op,
            operand=_replace_aggregates(expression.operand, found, environment))
    if isinstance(expression, node.Member):
        return node.Member(
            position=expression.position, name=expression.name,
            target=_replace_aggregates(expression.target, found, environment))
    if isinstance(expression, node.Index):
        return node.Index(
            position=expression.position,
            target=_replace_aggregates(expression.target, found, environment),
            index=_replace_aggregates(expression.index, found, environment))
    if isinstance(expression, node.InList):
        return node.InList(
            position=expression.position,
            target=_replace_aggregates(expression.target, found, environment),
            items=tuple(_replace_aggregates(item, found, environment)
                        for item in expression.items),
            negate=expression.negate, fold_case=expression.fold_case)
    if isinstance(expression, node.Between):
        return node.Between(
            position=expression.position,
            target=_replace_aggregates(expression.target, found, environment),
            low=_replace_aggregates(expression.low, found, environment),
            high=_replace_aggregates(expression.high, found, environment),
            negate=expression.negate)
    return expression


def node_name(expression: Any, index: int) -> str:
    from .parser import derive_name

    return derive_name(expression, index + 1)


def _apply_sort(frame: Frame, step: node.SortBy, environment: Environment) -> Frame:
    schema = Schema(frame.columns)
    state = WindowState()
    keys = [(compile_expression(key.expr, schema, environment, state),
             key.descending, key.nulls_first) for key in step.keys]
    rows = list(frame.rows)
    environment.check()

    # Sort by each key in turn, least significant first: Python's sort is
    # stable, so this gives the same answer as one composite key and copes
    # with keys whose null placement differs.
    for compiled, descending, nulls_first in reversed(keys):
        placement = (not descending) if nulls_first is None else nulls_first
        # `reverse=True` flips the whole key, marker included, so where the
        # nulls end up depends on the direction as well as on the flag. The
        # marker has to be chosen for the *sorted* order, not the requested
        # one: `sort by X desc nulls last` needs nulls to be the smallest.
        missing_marker = 1 if placement == descending else 0
        rows.sort(key=lambda row, f=compiled, m=missing_marker:
                  _order_key(f(row), m), reverse=descending)
    return Frame(frame.columns, rows, ordered=True)


def _order_key(value: Any, missing_marker: int):
    """Sort key that also decides which end the nulls go to."""
    if value is None:
        return (missing_marker, V.sort_key(None))
    return (1 - missing_marker, V.sort_key(value))


def _apply_top(frame: Frame, step: node.Top, environment: Environment) -> Frame:
    count = _count_of(step.count, environment, "top")
    sorted_frame = _apply_sort(
        frame, node.SortBy(position=step.position, keys=step.keys), environment)
    rows = list(sorted_frame.rows)[:count]
    return Frame(frame.columns, rows, ordered=True)


def _apply_take(frame: Frame, step: node.Take, environment: Environment) -> Frame:
    count = _count_of(step.count, environment, "take")
    return Frame(frame.columns, itertools.islice(frame.rows, count), frame.ordered)


def _count_of(expression: Any, environment: Environment, what: str) -> int:
    schema = Schema(())
    compiled = compile_expression(expression, schema, environment, WindowState())
    value = V.to_long(compiled(()))
    if value is None or value < 0:
        raise KqlError(f"`{what}` needs a whole number of rows.",
                       getattr(expression, "position", 0), 1,
                       source=environment.source)
    return value


def _apply_count(frame: Frame, step: node.CountRows,
                 environment: Environment) -> Frame:
    total = 0
    for _row in frame.rows:
        total += 1
        if total % (_DEADLINE_EVERY * 8) == 0:
            environment.check()
    return Frame((Column(step.name, ColumnType.LONG),), [(total,)], ordered=True)


def _apply_distinct(frame: Frame, step: node.Distinct,
                    environment: Environment) -> Frame:
    schema = Schema(frame.columns)
    if step.columns:
        positions = []
        for reference in step.columns:
            index = schema.index(reference.name)
            if index is None:
                raise _no_column(reference, schema, environment)
            positions.append(index)
    else:
        positions = list(range(len(frame.columns)))
    columns = tuple(frame.columns[position] for position in positions)

    def unique() -> Iterator[tuple]:
        seen: set = set()
        for row in frame.rows:
            values = tuple(row[position] for position in positions)
            key = tuple(_hashable(value) for value in values)
            if key not in seen:
                seen.add(key)
                yield values

    return Frame(columns, unique(), frame.ordered)


def _apply_search(frame: Frame, step: node.Search,
                  environment: Environment) -> Frame:
    schema = Schema(frame.columns)
    compiled = compile_expression(step.term, schema, environment, WindowState())
    term = compiled(())
    if not isinstance(term, str):
        term = V.to_string(term)

    if step.columns:
        positions = []
        for reference in step.columns:
            index = schema.index(reference.name)
            if index is None:
                raise _no_column(reference, schema, environment)
            positions.append(index)
    else:
        positions = [index for index, column in enumerate(frame.columns)
                     if column.type in (ColumnType.STRING, ColumnType.DYNAMIC)]

    case_sensitive = step.case_sensitive
    has_term = V.has_term
    to_string = V.to_string

    def matching() -> Iterator[tuple]:
        for row in frame.rows:
            for position in positions:
                value = row[position]
                if value is None:
                    continue
                if has_term(to_string(value), term, case_sensitive=case_sensitive):
                    yield row
                    break

    return Frame(frame.columns, matching(), frame.ordered)


def _apply_render(frame: Frame, step: node.Render,
                  environment: Environment) -> Frame:
    properties: dict[str, Any] = {}
    schema = Schema(frame.columns)
    for key, value in step.properties.items():
        compiled = compile_expression(value, schema, environment, WindowState())
        properties[key] = compiled(())
    environment.visualisation = (step.visual, properties)
    return frame


def _apply_sample(frame: Frame, step: node.Sample,
                  environment: Environment) -> Frame:
    count = _count_of(step.count, environment, "sample")
    reservoir: list[tuple] = []
    seen = 0
    for row in frame.rows:
        seen += 1
        if len(reservoir) < count:
            reservoir.append(row)
        else:
            position = random.randrange(seen)
            if position < count:
                reservoir[position] = row
        if seen % (_DEADLINE_EVERY * 8) == 0:
            environment.check()
    return Frame(frame.columns, reservoir)


def _apply_getschema(frame: Frame, step: node.GetSchema,
                     environment: Environment) -> Frame:
    columns = (Column("ColumnName", ColumnType.STRING),
               Column("ColumnOrdinal", ColumnType.LONG),
               Column("DataType", ColumnType.STRING),
               Column("Description", ColumnType.STRING))
    rows = [(column.name, position, column.type.value, column.description)
            for position, column in enumerate(frame.columns)]
    return Frame(columns, rows, ordered=True)


def _apply_serialize(frame: Frame, step: node.Serialize,
                     environment: Environment) -> Frame:
    frame = frame.materialise()
    frame.ordered = True
    if not step.items:
        return frame
    return _apply_extend(frame, node.Extend(position=step.position,
                                            items=step.items), environment)


def _apply_mv_expand(frame: Frame, step: node.MvExpand,
                     environment: Environment) -> Frame:
    schema = Schema(frame.columns)
    state = WindowState()
    targets: list[tuple[str, Callable, int]] = []
    columns = list(frame.columns)
    for item in step.items:
        compiled = compile_expression(item.value, schema, environment, state)
        position = schema.index(item.name)
        if position is None:
            position = len(columns)
            columns.append(Column(item.name, ColumnType.DYNAMIC))
        targets.append((item.name, compiled, position))

    width = len(columns)

    def expanded() -> Iterator[tuple]:
        for row in frame.rows:
            values = list(row) + [None] * (width - len(row))
            arrays: list[list] = []
            for _name, compiled, _position in targets:
                resolved = V.to_dynamic(compiled(row))
                if isinstance(resolved, dict):
                    resolved = [{key: value} for key, value in resolved.items()]
                elif not isinstance(resolved, list):
                    resolved = [] if resolved is None else [resolved]
                arrays.append(resolved)
            longest = max((len(item) for item in arrays), default=0)
            if longest == 0:
                continue
            for index in range(longest):
                copy = list(values)
                for array, (_name, _compiled, position) in zip(arrays, targets):
                    copy[position] = array[index] if index < len(array) else None
                yield tuple(copy)

    return Frame(tuple(columns), expanded(), frame.ordered)


def _apply_parse(frame: Frame, step: node.Parse, environment: Environment) -> Frame:
    schema = Schema(frame.columns)
    state = WindowState()
    source = compile_expression(step.source, schema, environment, state)
    pattern, names, casts = _build_parse_pattern(step, environment)

    columns = list(frame.columns)
    positions: list[int] = []
    for name in names:
        index = schema.index(name)
        if index is None:
            index = len(columns)
            columns.append(Column(name, ColumnType.STRING))
        positions.append(index)
    width = len(columns)

    def parsed() -> Iterator[tuple]:
        for row in frame.rows:
            values = list(row) + [None] * (width - len(row))
            text = V.to_string(source(row))
            match = pattern.search(text)
            if match is None:
                if not step.keep_unmatched:
                    continue
                for position in positions:
                    values[position] = None
            else:
                for index, position in enumerate(positions):
                    values[position] = casts[index](match.group(index + 1))
            yield tuple(values)

    return _retype(Frame(tuple(columns), parsed(), frame.ordered), positions)


def _build_parse_pattern(step: node.Parse, environment: Environment):
    """Turn a `parse ... with` pattern into one regular expression."""
    pieces: list[str] = []
    names: list[str] = []
    casts: list[Callable] = []
    capture_types = {
        "string": V.to_string, "long": V.to_long, "int": V.to_long,
        "real": V.to_real, "double": V.to_real, "datetime": V.to_datetime,
        "date": V.to_datetime, "bool": V.to_bool, "boolean": V.to_bool,
        "dynamic": V.to_dynamic, "guid": V.to_string, "timespan": V.to_timespan,
    }
    for index, (kind, payload) in enumerate(step.pattern):
        if kind == "literal":
            pieces.append(payload if step.kind == "regex" else re.escape(payload))
        elif kind == "skip":
            pieces.append(".*?")
        else:
            name, declared = payload
            names.append(name)
            cast = capture_types.get(declared)
            if cast is None:
                raise KqlError(f"`{declared}` is not a type `parse` knows.",
                               step.position, 1,
                               did_you_mean(declared, list(capture_types)),
                               environment.source)
            casts.append(cast)
            last = index == len(step.pattern) - 1
            if declared in ("long", "int"):
                pieces.append(r"([+-]?\d+)")
            elif declared in ("real", "double"):
                pieces.append(r"([+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)")
            else:
                pieces.append("(.*)" if last else "(.*?)")
    return fn.compile_pattern("".join(pieces), step.position,
                              environment.source), names, casts


def _apply_join(frame: Frame, step: node.Join, environment: Environment) -> Frame:
    left_schema = Schema(frame.columns)
    right_frame = _evaluate(step.right, environment).materialise()
    right_schema = Schema(right_frame.columns)
    state = WindowState()

    left_keys: list[Callable] = []
    right_keys: list[Callable] = []
    for key in step.keys:
        left_expression = _strip_side(key.left, "left")
        right_expression = _strip_side(key.right, "right")
        left_keys.append(compile_expression(left_expression, left_schema,
                                            environment, state))
        right_keys.append(compile_expression(right_expression, right_schema,
                                             environment, state))

    buckets: dict[tuple, list[tuple]] = {}
    for row in right_frame.rows:
        key = tuple(_hashable(function(row)) for function in right_keys)
        buckets.setdefault(key, []).append(row)

    kind = step.kind
    right_width = len(right_frame.columns)
    left_width = len(frame.columns)
    blank_right = (None,) * right_width
    blank_left = (None,) * left_width

    left_names = list(frame.names())
    right_names = _disambiguate(left_names, list(right_frame.names()))
    joined_columns = tuple(list(frame.columns)
                           + [Column(name, column.type, column.description)
                              for name, column in zip(right_names,
                                                      right_frame.columns)])

    if kind in ("leftsemi", "semi"):
        joined_columns = frame.columns
    elif kind == "rightsemi":
        joined_columns = tuple(right_frame.columns)
    elif kind in ("leftanti", "anti"):
        joined_columns = frame.columns
    elif kind == "rightanti":
        joined_columns = tuple(right_frame.columns)

    def produce() -> Iterator[tuple]:
        matched_right: set = set()
        seen_left: set = set()
        for row in frame.rows:
            key = tuple(_hashable(function(row)) for function in left_keys)
            if kind == "innerunique":
                if key in seen_left:
                    continue
                seen_left.add(key)
            partners = buckets.get(key)
            if partners:
                matched_right.add(key)
                if kind in ("leftanti", "anti", "rightanti"):
                    continue
                if kind in ("leftsemi", "semi"):
                    yield row
                    continue
                if kind == "rightsemi":
                    continue
                for partner in partners:
                    yield tuple(row) + tuple(partner)
            else:
                if kind in ("leftanti", "anti"):
                    yield row
                elif kind in ("leftouter", "fullouter"):
                    yield tuple(row) + blank_right
        if kind in ("rightouter", "fullouter"):
            for key, partners in buckets.items():
                if key in matched_right:
                    continue
                for partner in partners:
                    yield blank_left + tuple(partner)
        if kind == "rightsemi":
            for key, partners in buckets.items():
                if key in matched_right:
                    yield from (tuple(partner) for partner in partners)
        if kind == "rightanti":
            for key, partners in buckets.items():
                if key not in matched_right:
                    yield from (tuple(partner) for partner in partners)

    return Frame(joined_columns, produce())


def _strip_side(expression: Any, side: str) -> Any:
    """``$left.App`` and ``$right.App`` name a column on one side."""
    if isinstance(expression, node.Member) and isinstance(expression.target,
                                                          node.ColumnRef):
        target = expression.target.name.lower()
        if target in ("$left", "$right", "left", "right"):
            return node.ColumnRef(position=expression.position, name=expression.name)
    return expression


def _disambiguate(taken: list[str], names: list[str]) -> list[str]:
    """Kusto suffixes a clashing right-hand column with 1."""
    used = {name.lower() for name in taken}
    result: list[str] = []
    for name in names:
        candidate = name
        counter = 1
        while candidate.lower() in used:
            candidate = f"{name}{counter}"
            counter += 1
        used.add(candidate.lower())
        result.append(candidate)
    return result


def _apply_union(frame: Frame | None, step: node.Union,
                 environment: Environment) -> Frame:
    frames: list[tuple[str, Frame]] = []
    if frame is not None:
        frames.append(("", frame.materialise()))
    for item in step.sources:
        frames.append((_source_name(item), _evaluate(item, environment).materialise()))
    if not frames:
        return Frame((), [])

    if step.kind == "inner":
        common = set(frames[0][1].names())
        for _name, other in frames[1:]:
            common &= set(other.names())
        ordered_names = [name for name in frames[0][1].names() if name in common]
    else:
        ordered_names = []
        for _name, other in frames:
            for name in other.names():
                if name not in ordered_names:
                    ordered_names.append(name)

    types: dict[str, ColumnType] = {}
    for _name, other in frames:
        for column in other.columns:
            types.setdefault(column.name, column.type)

    columns = [Column(name, types.get(name, ColumnType.STRING))
               for name in ordered_names]
    if step.with_source:
        columns.insert(0, Column(step.with_source, ColumnType.STRING))

    def produce() -> Iterator[tuple]:
        for source_name, other in frames:
            other_schema = Schema(other.columns)
            positions = [other_schema.index(name) for name in ordered_names]
            for row in other.rows:
                values = [row[position] if position is not None else None
                          for position in positions]
                if step.with_source:
                    values.insert(0, source_name)
                yield tuple(values)

    return Frame(tuple(columns), produce())


def _source_name(item: Any) -> str:
    """Which table a union arm came from, for `withsource=`."""
    if isinstance(item, node.Table):
        return item.name
    if isinstance(item, node.Pipeline):
        return _source_name(item.source)
    return ""


_OPERATORS: dict[type, Callable] = {
    node.Where: _apply_where,
    node.Extend: _apply_extend,
    node.Project: _apply_project,
    node.Summarize: _apply_summarize,
    node.SortBy: _apply_sort,
    node.Top: _apply_top,
    node.Take: _apply_take,
    node.CountRows: _apply_count,
    node.Distinct: _apply_distinct,
    node.Search: _apply_search,
    node.Render: _apply_render,
    node.Sample: _apply_sample,
    node.GetSchema: _apply_getschema,
    node.Serialize: _apply_serialize,
    node.MvExpand: _apply_mv_expand,
    node.Parse: _apply_parse,
    node.Join: _apply_join,
    node.Union: lambda frame, step, environment: _apply_union(frame, step, environment),
}


# ---------------------------------------------------------------------------
# Windowing and typing
# ---------------------------------------------------------------------------


def _windowed(frame: Frame, state: WindowState) -> Iterable[tuple]:
    """Materialise only when a window function actually needs the whole table."""
    if not state.used:
        return frame.rows
    frame.materialise()
    state.rows = list(frame.rows)
    return state.rows


def _retype(frame: Frame, positions: Sequence[int], *, inherit: Frame | None = None,
            sources: Sequence[Any] = ()) -> Frame:
    """Work out the type of computed columns from the values they produce.

    A computed column has no declared type, so the first few hundred values
    decide it. The rows have to be materialised for that, which is why only
    the operators that create columns do it.
    """
    frame.materialise()
    rows = frame.rows
    columns = list(frame.columns)
    for position in positions:
        if position >= len(columns):
            continue
        sample = [row[position] for row in rows[:_TYPE_SAMPLE]
                  if position < len(row)]
        columns[position] = Column(columns[position].name, V.infer_type(sample),
                                   columns[position].description)
    if inherit is not None and sources:
        known = {column.name.lower(): column for column in inherit.columns}
        for index, item in enumerate(sources):
            if index >= len(columns):
                break
            target = getattr(item, "value", None)
            if isinstance(target, node.ColumnRef):
                original = known.get(target.name.lower())
                if original is not None:
                    columns[index] = Column(columns[index].name, original.type,
                                            original.description)
    frame.columns = tuple(columns)
    return frame


def _hashable(value: Any):
    if isinstance(value, (list, dict)):
        import json

        return json.dumps(value, sort_keys=True, default=str)
    if isinstance(value, datetime):
        return value.timestamp()
    return value


def _no_column(reference: Any, schema: Schema, environment: Environment) -> KqlError:
    name = getattr(reference, "name", str(reference))
    return KqlError(f"There is no column called `{name}` here.",
                    getattr(reference, "position", 0), max(1, len(name)),
                    did_you_mean(name, schema.names)
                    or ("The columns at this point are: "
                        + ", ".join(schema.names[:12])
                        + ("…" if len(schema.names) > 12 else "")),
                    environment.source)


# ---------------------------------------------------------------------------
# Collecting the result
# ---------------------------------------------------------------------------


def _collect(frame: Frame, environment: Environment) -> ResultTable:
    limit = environment.options.row_limit
    rows: list[tuple] = []
    truncated = False
    for index, row in enumerate(frame.rows):
        if index >= limit:
            truncated = True
            break
        rows.append(row)
        if index % _DEADLINE_EVERY == 0:
            environment.check()

    columns = list(frame.columns)
    for position, column in enumerate(columns):
        if column.type is ColumnType.STRING:
            sample = [row[position] for row in rows[:_TYPE_SAMPLE]
                      if position < len(row)]
            if sample and any(value is not None for value in sample):
                columns[position] = Column(column.name, V.infer_type(sample),
                                           column.description)

    stats = QueryStats(rows=len(rows), truncated=truncated)
    if truncated:
        stats.note = (f"Only the first {limit:,} rows are shown. Add "
                      "`| take` or narrow the time range.")
    return ResultTable(columns=tuple(columns), rows=rows, stats=stats)


def _describe_shape(body: Any, environment: Environment) -> Schema:
    """Walk a pipeline compiling every expression, without reading any rows.

    This is the editor's live check. It has to make exactly the same decisions
    about column names as a real run, so it reuses the operator machinery with
    an empty row source rather than re-implementing the rules.
    """
    frame = _evaluate(body, environment)
    if isinstance(frame.rows, list):
        return Schema(frame.columns)
    # Draining an empty generator forces the compiled expressions to have
    # been built without reading anything: the source is a SQL cursor that
    # was never executed, because check() passes no connection.
    return Schema(frame.columns)


# ---------------------------------------------------------------------------
# Expression compilation
# ---------------------------------------------------------------------------


def compile_expression(expression: Any, schema: Schema, environment: Environment,
                       state: WindowState) -> Callable[[tuple], Any]:
    """Turn one expression into a closure taking a row and returning a value."""
    if isinstance(expression, node.Literal):
        value = expression.value
        return lambda row, value=value: value

    if isinstance(expression, node.Star):
        raise KqlError("`*` cannot be used here.", expression.position, 1,
                       source=environment.source)

    if isinstance(expression, node.ColumnRef):
        return _compile_column(expression, schema, environment)

    if isinstance(expression, node.Member):
        target = compile_expression(expression.target, schema, environment, state)
        name = expression.name
        member = V.member
        return lambda row: member(target(row), name)

    if isinstance(expression, node.Index):
        target = compile_expression(expression.target, schema, environment, state)
        key = compile_expression(expression.index, schema, environment, state)
        element = V.element
        return lambda row: element(target(row), key(row))

    if isinstance(expression, node.Unary):
        return _compile_unary(expression, schema, environment, state)

    if isinstance(expression, node.Binary):
        return _compile_binary(expression, schema, environment, state)

    if isinstance(expression, node.InList):
        return _compile_in(expression, schema, environment, state)

    if isinstance(expression, node.Between):
        return _compile_between(expression, schema, environment, state)

    if isinstance(expression, node.Call):
        return _compile_call(expression, schema, environment, state)

    raise KqlError("I could not work out what this means.",
                   getattr(expression, "position", 0), 1,
                   source=environment.source)


def _compile_column(expression: node.ColumnRef, schema: Schema,
                    environment: Environment) -> Callable[[tuple], Any]:
    position = schema.index(expression.name)
    if position is not None:
        return lambda row, position=position: (row[position]
                                               if position < len(row) else None)

    if expression.name in environment.lets:
        value = environment.lets[expression.name]
        if isinstance(value, (_LazyTable, node.Lambda)):
            raise KqlError(f"`{expression.name}` is not a value.",
                           expression.position, len(expression.name),
                           "It was defined as a table or a function.",
                           environment.source)
        return lambda row, value=value: value

    raise _no_column(expression, schema, environment)


def _compile_unary(expression: node.Unary, schema: Schema,
                   environment: Environment, state: WindowState):
    operand = compile_expression(expression.operand, schema, environment, state)
    if expression.op == "not":
        truthy = V.truthy
        return lambda row: not truthy(operand(row))
    if expression.op == "-":
        negate = V.negate
        return lambda row: negate(operand(row))
    return operand


_ARITHMETIC = {"+": V.add, "-": V.subtract, "*": V.multiply,
               "/": V.divide, "%": V.modulo}


def _compile_binary(expression: node.Binary, schema: Schema,
                    environment: Environment, state: WindowState):
    operator = expression.op

    if operator == "and":
        left = compile_expression(expression.left, schema, environment, state)
        right = compile_expression(expression.right, schema, environment, state)
        truthy = V.truthy
        return lambda row: truthy(left(row)) and truthy(right(row))

    if operator == "or":
        left = compile_expression(expression.left, schema, environment, state)
        right = compile_expression(expression.right, schema, environment, state)
        truthy = V.truthy
        return lambda row: truthy(left(row)) or truthy(right(row))

    left = compile_expression(expression.left, schema, environment, state)
    right = compile_expression(expression.right, schema, environment, state)

    if operator in _ARITHMETIC:
        operation = _ARITHMETIC[operator]
        return lambda row: operation(left(row), right(row))

    # `equal` answers True, False or None, where None means "this comparison
    # has no truth value" — a null on either side. Both == and != are false
    # for null, which is why each tests against a specific answer rather than
    # negating the other.
    equal = V.equal
    if operator == "==":
        return lambda row: equal(left(row), right(row)) is True
    if operator == "!=":
        return lambda row: equal(left(row), right(row)) is False
    if operator == "=~":
        return lambda row: equal(left(row), right(row), fold_case=True) is True
    if operator == "!~":
        return lambda row: equal(left(row), right(row), fold_case=True) is False

    if operator in ("<", "<=", ">", ">="):
        compare = V.compare
        test = {"<": lambda value: value is not None and value < 0,
                "<=": lambda value: value is not None and value <= 0,
                ">": lambda value: value is not None and value > 0,
                ">=": lambda value: value is not None and value >= 0}[operator]
        return lambda row: test(compare(left(row), right(row)))

    if operator == "matches regex":
        return _compile_regex(expression, left, right, environment)

    return _compile_string_operator(expression, left, right, environment)


def _compile_regex(expression: node.Binary, left, right,
                   environment: Environment):
    pattern = None
    if isinstance(expression.right, node.Literal):
        pattern = fn.compile_pattern(V.to_string(expression.right.value),
                                     expression.position, environment.source)
    to_string = V.to_string

    def matches(row, pattern=pattern):
        expression_text = pattern
        if expression_text is None:
            expression_text = fn._compile(to_string(right(row)))
            if expression_text is None:
                return False
        value = left(row)
        return value is not None and bool(expression_text.search(to_string(value)))

    return matches


_STRING_OPERATIONS = {
    "contains": (V.contains, False, False),
    "!contains": (V.contains, False, True),
    "contains_cs": (V.contains, True, False),
    "!contains_cs": (V.contains, True, True),
    "startswith": (V.starts_with, False, False),
    "!startswith": (V.starts_with, False, True),
    "startswith_cs": (V.starts_with, True, False),
    "!startswith_cs": (V.starts_with, True, True),
    "endswith": (V.ends_with, False, False),
    "!endswith": (V.ends_with, False, True),
    "endswith_cs": (V.ends_with, True, False),
    "!endswith_cs": (V.ends_with, True, True),
    "has": (V.has_term, False, False),
    "!has": (V.has_term, False, True),
    "has_cs": (V.has_term, True, False),
    "!has_cs": (V.has_term, True, True),
    "hasprefix": (V.has_prefix, False, False),
    "!hasprefix": (V.has_prefix, False, True),
    "hassuffix": (V.has_suffix, False, False),
    "!hassuffix": (V.has_suffix, False, True),
}


def _compile_string_operator(expression: node.Binary, left, right,
                             environment: Environment):
    operator = expression.op

    if operator in ("has_any", "!has_any", "has_all", "!has_all"):
        negate = operator.startswith("!")
        require_all = "all" in operator
        has_term = V.has_term
        as_list = V.as_list
        to_string = V.to_string

        def any_all(row):
            haystack = to_string(left(row))
            needles = as_list(right(row))
            if not needles:
                return negate
            test = all if require_all else any
            found = test(has_term(haystack, item) for item in needles)
            return not found if negate else found

        return any_all

    found = _STRING_OPERATIONS.get(operator)
    if found is None:
        raise KqlError(f"`{operator}` is not an operator I know.",
                       expression.position, len(operator),
                       source=environment.source)
    operation, case_sensitive, negate = found

    def apply(row):
        value = left(row)
        if value is None:
            return negate
        result = operation(value, right(row), case_sensitive=case_sensitive)
        return not result if negate else result

    return apply


def _compile_in(expression: node.InList, schema: Schema,
                environment: Environment, state: WindowState):
    target = compile_expression(expression.target, schema, environment, state)
    items = [compile_expression(item, schema, environment, state)
             for item in expression.items]
    negate = expression.negate
    fold = expression.fold_case
    equal = V.equal
    to_dynamic = V.to_dynamic

    def contained(row):
        value = target(row)
        for function in items:
            candidate = function(row)
            resolved = to_dynamic(candidate) if isinstance(candidate, str) else candidate
            if isinstance(resolved, list) and not isinstance(candidate, list):
                resolved = candidate
            if isinstance(candidate, list):
                if any(equal(value, item, fold_case=fold) is True for item in candidate):
                    return not negate
                continue
            if equal(value, candidate, fold_case=fold) is True:
                return not negate
        return negate

    return contained


def _compile_between(expression: node.Between, schema: Schema,
                     environment: Environment, state: WindowState):
    target = compile_expression(expression.target, schema, environment, state)
    low = compile_expression(expression.low, schema, environment, state)
    high = compile_expression(expression.high, schema, environment, state)
    negate = expression.negate
    compare = V.compare

    def within(row):
        value = target(row)
        lower = compare(value, low(row))
        upper = compare(value, high(row))
        if lower is None or upper is None:
            # No truth value, which is false whether or not it is negated.
            return False
        inside = lower >= 0 and upper <= 0
        return not inside if negate else inside

    return within


def _compile_call(expression: node.Call, schema: Schema,
                  environment: Environment, state: WindowState):
    name = expression.name
    lowered = name.lower()

    lambda_definition = environment.lets.get(name)
    if isinstance(lambda_definition, node.Lambda):
        return _compile_lambda(expression, lambda_definition, schema,
                               environment, state)

    if lowered == "toscalar":
        return _compile_toscalar(expression, environment)

    if lowered in fn.WINDOW_FUNCTIONS:
        return _compile_window(expression, schema, environment, state)

    if lowered == "iif" or lowered == "iff":
        # Short-circuit so that `iif(isnotnull(x), 1/x, 0)` does not evaluate
        # the branch it did not choose.
        if len(expression.args) == 3:
            condition = compile_expression(expression.args[0], schema,
                                           environment, state)
            when_true = compile_expression(expression.args[1], schema,
                                           environment, state)
            when_false = compile_expression(expression.args[2], schema,
                                            environment, state)
            truthy = V.truthy
            return lambda row: (when_true(row) if truthy(condition(row))
                                else when_false(row))

    definition = fn.lookup(name, expression.position, len(name), environment.source)
    fn.check_arity(definition, len(expression.args), expression.position,
                   environment.source)
    arguments = [compile_expression(argument, schema, environment, state)
                 for argument in expression.args]
    call = definition.call

    if len(arguments) == 0:
        return lambda row: call()
    if len(arguments) == 1:
        first = arguments[0]
        return lambda row: call(first(row))
    if len(arguments) == 2:
        first, second = arguments
        return lambda row: call(first(row), second(row))
    return lambda row: call(*(argument(row) for argument in arguments))


def _compile_toscalar(expression: node.Call, environment: Environment):
    """Run a whole query now and keep its first cell.

    Evaluated once, when the expression is compiled, rather than once per row:
    the value cannot depend on the row, and a sub-query per row over a million
    rows is not a feature, it is an outage.
    """
    if len(expression.args) != 1:
        raise KqlError("`toscalar()` takes one query.", expression.position,
                       len(expression.name), source=environment.source)
    frame = _evaluate(expression.args[0], environment)
    value = None
    for row in frame.rows:
        value = row[0] if row else None
        break
    return lambda row, value=value: value


def _compile_lambda(expression: node.Call, definition: node.Lambda,
                    schema: Schema, environment: Environment, state: WindowState):
    """A function defined with ``let f = (x) { ... }``, inlined at the call."""
    if len(expression.args) != len(definition.parameters):
        raise KqlError(
            f"`{expression.name}()` takes {len(definition.parameters)} "
            f"argument{'' if len(definition.parameters) == 1 else 's'}, "
            f"not {len(expression.args)}.",
            expression.position, len(expression.name), "", environment.source)
    arguments = [compile_expression(argument, schema, environment, state)
                 for argument in expression.args]

    inner_columns = tuple(Column(name, ColumnType.STRING)
                          for name in definition.parameters)
    inner_schema = Schema(inner_columns)
    inner_environment = Environment(
        connection=environment.connection, options=environment.options,
        lets=environment.lets, source=environment.source)
    body = compile_expression(definition.body, inner_schema, inner_environment,
                              WindowState())

    def call(row):
        return body(tuple(argument(row) for argument in arguments))

    return call


def _compile_window(expression: node.Call, schema: Schema,
                    environment: Environment, state: WindowState):
    """row_number(), prev(), next() and row_cumsum() over a serialised table."""
    state.used = True
    name = expression.name.lower()

    if name == "row_number":
        start = 1
        if expression.args:
            first = compile_expression(expression.args[0], schema, environment, state)
            start = V.to_long(first(())) or 1
        return lambda row, start=start: state.index + start

    if name == "row_rank_dense":
        raise KqlError("`row_rank_dense()` is not implemented.",
                       expression.position, len(expression.name),
                       "Use `row_number()` after a `sort by`.", environment.source)

    if name in ("prev", "next"):
        if not expression.args:
            raise KqlError(f"`{name}()` needs a column.", expression.position,
                           len(expression.name), source=environment.source)
        target = compile_expression(expression.args[0], schema, environment, state)
        offset = 1
        if len(expression.args) > 1:
            second = compile_expression(expression.args[1], schema, environment,
                                        state)
            offset = V.to_long(second(())) or 1
        default = None
        if len(expression.args) > 2:
            third = compile_expression(expression.args[2], schema, environment, state)
            default = third(())
        direction = -1 if name == "prev" else 1

        def neighbour(row, offset=offset, default=default, direction=direction):
            position = state.index + direction * offset
            if 0 <= position < len(state.rows):
                return target(state.rows[position])
            return default

        return neighbour

    if name == "row_cumsum":
        target = compile_expression(expression.args[0], schema, environment, state)

        def cumulative(row):
            total = 0
            for index in range(state.index + 1):
                value = V.to_real(target(state.rows[index]))
                if value is not None:
                    total += value
            return int(total) if float(total).is_integer() else total

        return cumulative

    raise KqlError(f"`{expression.name}()` is not implemented.",
                   expression.position, len(expression.name),
                   source=environment.source)
