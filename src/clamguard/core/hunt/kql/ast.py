"""The shapes a parsed query takes.

Two families. **Expressions** produce a value for one row — a column
reference, a literal, a comparison, a function call. **Operators** transform a
whole table and are what the ``|`` separates. A :class:`Query` is a list of
``let`` statements followed by one pipeline.

Every node carries the character offset it started at, so an error found
during planning — an unknown column, an aggregate in the wrong place — can be
reported against the token the user typed rather than against the query as a
whole.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Node:
    position: int = 0


@dataclass(frozen=True, slots=True)
class Literal(Node):
    value: Any = None
    #: One of the ColumnType values, or "null".
    type: str = "string"


@dataclass(frozen=True, slots=True)
class ColumnRef(Node):
    name: str = ""


@dataclass(frozen=True, slots=True)
class Star(Node):
    """``*`` — every column, in ``project`` and ``count``."""


@dataclass(frozen=True, slots=True)
class Unary(Node):
    op: str = ""
    operand: Any = None


@dataclass(frozen=True, slots=True)
class Binary(Node):
    op: str = ""
    left: Any = None
    right: Any = None


@dataclass(frozen=True, slots=True)
class Call(Node):
    name: str = ""
    args: tuple = ()


@dataclass(frozen=True, slots=True)
class Member(Node):
    """``Extra.pid`` — a field of a dynamic value."""

    target: Any = None
    name: str = ""


@dataclass(frozen=True, slots=True)
class Index(Node):
    """``Extra["pid"]`` or ``items[0]``."""

    target: Any = None
    index: Any = None


@dataclass(frozen=True, slots=True)
class InList(Node):
    target: Any = None
    items: tuple = ()
    negate: bool = False
    #: True for ``in~`` and ``!in~``: compare case-insensitively.
    fold_case: bool = False


@dataclass(frozen=True, slots=True)
class Between(Node):
    target: Any = None
    low: Any = None
    high: Any = None
    negate: bool = False


@dataclass(frozen=True, slots=True)
class Assign(Node):
    """``Name = expression`` in project, extend, summarize."""

    name: str = ""
    value: Any = None
    #: True when the user did not write a name and one was derived.
    implicit: bool = False


@dataclass(frozen=True, slots=True)
class SortKey(Node):
    expr: Any = None
    descending: bool = True
    #: Kusto's default puts nulls where the ordering says; this follows.
    nulls_first: bool | None = None


# ---------------------------------------------------------------------------
# Tabular sources and operators
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Table(Node):
    name: str = ""


@dataclass(frozen=True, slots=True)
class Operator(Node):
    """Base for everything that can appear after a ``|``."""

    @property
    def keyword(self) -> str:
        return type(self).__name__.lower()


@dataclass(frozen=True, slots=True)
class Where(Operator):
    condition: Any = None

    @property
    def keyword(self) -> str:
        return "where"


@dataclass(frozen=True, slots=True)
class Extend(Operator):
    items: tuple = ()

    @property
    def keyword(self) -> str:
        return "extend"


@dataclass(frozen=True, slots=True)
class Project(Operator):
    items: tuple = ()
    #: "project", "project-away", "project-keep", "project-rename",
    #: "project-reorder"
    mode: str = "project"

    @property
    def keyword(self) -> str:
        return self.mode


@dataclass(frozen=True, slots=True)
class Summarize(Operator):
    aggregates: tuple = ()
    by: tuple = ()

    @property
    def keyword(self) -> str:
        return "summarize"


@dataclass(frozen=True, slots=True)
class SortBy(Operator):
    keys: tuple = ()

    @property
    def keyword(self) -> str:
        return "sort by"


@dataclass(frozen=True, slots=True)
class Top(Operator):
    count: Any = None
    keys: tuple = ()

    @property
    def keyword(self) -> str:
        return "top"


@dataclass(frozen=True, slots=True)
class Take(Operator):
    count: Any = None

    @property
    def keyword(self) -> str:
        return "take"


@dataclass(frozen=True, slots=True)
class CountRows(Operator):
    name: str = "Count"

    @property
    def keyword(self) -> str:
        return "count"


@dataclass(frozen=True, slots=True)
class Distinct(Operator):
    columns: tuple = ()

    @property
    def keyword(self) -> str:
        return "distinct"


@dataclass(frozen=True, slots=True)
class Search(Operator):
    term: Any = None
    columns: tuple = ()
    case_sensitive: bool = False

    @property
    def keyword(self) -> str:
        return "search"


@dataclass(frozen=True, slots=True)
class JoinKey(Node):
    left: Any = None
    right: Any = None


@dataclass(frozen=True, slots=True)
class Join(Operator):
    kind: str = "innerunique"
    right: Any = None
    keys: tuple = ()

    @property
    def keyword(self) -> str:
        return "join"


@dataclass(frozen=True, slots=True)
class Union(Operator):
    sources: tuple = ()
    kind: str = "outer"
    with_source: str = ""

    @property
    def keyword(self) -> str:
        return "union"


@dataclass(frozen=True, slots=True)
class Render(Operator):
    visual: str = "table"
    properties: dict = field(default_factory=dict)

    @property
    def keyword(self) -> str:
        return "render"


@dataclass(frozen=True, slots=True)
class MvExpand(Operator):
    items: tuple = ()

    @property
    def keyword(self) -> str:
        return "mv-expand"


@dataclass(frozen=True, slots=True)
class Parse(Operator):
    source: Any = None
    #: "simple" or "regex"
    kind: str = "simple"
    #: Alternating literals and (name, type) captures.
    pattern: tuple = ()
    keep_unmatched: bool = True

    @property
    def keyword(self) -> str:
        return "parse"


@dataclass(frozen=True, slots=True)
class Sample(Operator):
    count: Any = None

    @property
    def keyword(self) -> str:
        return "sample"


@dataclass(frozen=True, slots=True)
class GetSchema(Operator):
    @property
    def keyword(self) -> str:
        return "getschema"


@dataclass(frozen=True, slots=True)
class Serialize(Operator):
    items: tuple = ()

    @property
    def keyword(self) -> str:
        return "serialize"


@dataclass(frozen=True, slots=True)
class Pipeline(Node):
    source: Any = None
    steps: tuple = ()

    def with_step(self, step: Operator) -> "Pipeline":
        return Pipeline(self.position, self.source, self.steps + (step,))


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Lambda(Node):
    parameters: tuple = ()
    body: Any = None


@dataclass(frozen=True, slots=True)
class Let(Node):
    name: str = ""
    value: Any = None


@dataclass(frozen=True, slots=True)
class Print(Node):
    items: tuple = ()


@dataclass(frozen=True, slots=True)
class Query(Node):
    lets: tuple = ()
    body: Any = None
    #: The original text, kept for error messages and for the editor.
    source: str = ""


#: The operator keywords, for completion and for "did you mean".
OPERATOR_KEYWORDS: tuple[str, ...] = (
    "where", "filter", "extend", "project", "project-away", "project-keep",
    "project-rename", "project-reorder", "summarize", "sort", "order", "top",
    "take", "limit", "count", "distinct", "search", "join", "union", "render",
    "mv-expand", "parse", "sample", "getschema", "serialize",
)
