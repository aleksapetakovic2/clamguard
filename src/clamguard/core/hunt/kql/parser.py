"""Tokens to a syntax tree: recursive descent, with Kusto's precedence.

The grammar is Kusto's, minus everything that reaches outside the database.
``externaldata``, ``evaluate`` and the remoting operators are not merely
unimplemented — they are refused by name, with an explanation, because a user
who has read Microsoft's documentation deserves to be told *why* a thing is
missing rather than shown "unexpected identifier".

Precedence, loosest first::

    or
    and
    not                                 (prefix)
    == != < <= > >= =~ !~ in contains has startswith between matches regex
    + -
    * / %
    - +                                 (prefix)
    . [] ()                             (postfix)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from . import ast as node
from .errors import KqlError, did_you_mean
from .lexer import Kind, Token, tokenise

#: Operators whose left and right are compared. Written here rather than
#: inlined so that the completion list and the documentation can read them.
COMPARISON_OPERATORS: tuple[str, ...] = (
    "==", "!=", "<", "<=", ">", ">=", "=~", "!~",
)

STRING_OPERATORS: tuple[str, ...] = (
    "contains", "!contains", "contains_cs", "!contains_cs",
    "startswith", "!startswith", "startswith_cs", "!startswith_cs",
    "endswith", "!endswith", "endswith_cs", "!endswith_cs",
    "has", "!has", "has_cs", "!has_cs",
    "hasprefix", "!hasprefix", "hassuffix", "!hassuffix",
    "has_any", "!has_any", "has_all", "!has_all",
    "matches",
)

#: Operators Kusto has and this engine refuses on purpose, with the reason.
REFUSED_OPERATORS: dict[str, str] = {
    "evaluate": "`evaluate` loads a plugin, and Hunt runs no plugins — a "
                "query here is only ever allowed to read the local store.",
    "externaldata": "`externaldata` fetches a URL. Hunt makes no network "
                    "requests at all.",
    "invoke": "`invoke` calls a stored function on a server. There is no "
              "server; use `let` to define a function in the query instead.",
    "ingest": "Queries in Hunt cannot write. Indexing is done from the "
              "Sources dialog.",
    "set": "`set` changes engine options that this engine does not have.",
    "datatable": "`datatable` is not supported. Use `print` for a single "
                 "row, or query one of the real tables.",
}

_AGGREGATE_ONLY_HINT = ("Aggregate functions such as count() and sum() belong "
                        "in `summarize`.")


class Parser:
    """One query's worth of parsing state."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = tokenise(text)
        self.index = 0

    # -- token plumbing ---------------------------------------------------

    @property
    def current(self) -> Token:
        return self.tokens[self.index]

    def peek(self, ahead: int = 1) -> Token:
        return self.tokens[min(self.index + ahead, len(self.tokens) - 1)]

    def advance(self) -> Token:
        token = self.tokens[self.index]
        if token.kind is not Kind.END:
            self.index += 1
        return token

    def accept_punct(self, *symbols: str) -> Token | None:
        if self.current.is_punct(*symbols):
            return self.advance()
        return None

    def accept_word(self, *words: str) -> Token | None:
        if self.current.is_word(*words):
            return self.advance()
        return None

    def expect_punct(self, symbol: str, what: str = "") -> Token:
        if not self.current.is_punct(symbol):
            self.fail(f"Expected {symbol!r}{' ' + what if what else ''}, "
                      f"found {self.describe(self.current)}.")
        return self.advance()

    def expect_name(self, what: str = "a name") -> Token:
        if self.current.kind is not Kind.IDENT:
            self.fail(f"Expected {what}, found {self.describe(self.current)}.")
        return self.advance()

    def fail(self, message: str, token: Token | None = None, hint: str = "") -> None:
        spot = token or self.current
        raise KqlError(message, spot.position, max(1, spot.length), hint, self.text)

    @staticmethod
    def describe(token: Token) -> str:
        if token.kind is Kind.END:
            return "the end of the query"
        if token.kind is Kind.PIPE:
            return "'|'"
        return f"{token.text!r}"

    # -- statements -------------------------------------------------------

    def parse_query(self) -> node.Query:
        lets: list[node.Let] = []
        while self.current.is_word("let"):
            lets.append(self.parse_let())
        body = self.parse_statement()
        while self.accept_punct(";"):
            if self.current.kind is Kind.END:
                break
            if self.current.is_word("let"):
                lets.append(self.parse_let())
                continue
            body = self.parse_statement()
        if self.current.kind is not Kind.END:
            self.fail(f"I did not expect {self.describe(self.current)} here.",
                      hint="Operators after the first one need a '|' in front.")
        return node.Query(position=0, lets=tuple(lets), body=body, source=self.text)

    def parse_let(self) -> node.Let:
        start = self.advance()                      # 'let'
        name = self.expect_name("a name for the let")
        self.expect_punct("=", "after the name")
        if self.current.is_punct("("):
            saved = self.index
            lambda_node = self._try_lambda()
            if lambda_node is not None:
                self._end_statement()
                return node.Let(position=start.position, name=name.text,
                                value=lambda_node)
            self.index = saved
        value: Any
        if self._looks_tabular():
            value = self.parse_pipeline()
        else:
            value = self.parse_expression()
        self._end_statement()
        return node.Let(position=start.position, name=name.text, value=value)

    def _end_statement(self) -> None:
        if not self.accept_punct(";"):
            self.fail("A `let` has to end with ';'.",
                      hint="Put a semicolon after the definition.")

    def _try_lambda(self) -> node.Lambda | None:
        """``(x: long, y: string) { x + y }`` — a function defined in a query."""
        start = self.expect_punct("(")
        parameters: list[str] = []
        if not self.current.is_punct(")"):
            while True:
                if self.current.kind is not Kind.IDENT:
                    return None
                parameters.append(self.advance().text)
                if self.accept_punct(":"):
                    if self.current.kind is not Kind.IDENT:
                        return None
                    self.advance()               # the declared type, unused
                if not self.accept_punct(","):
                    break
        if not self.accept_punct(")"):
            return None
        if not self.current.is_punct("{"):
            return None
        self.advance()
        body = self.parse_expression()
        if not self.accept_punct("}"):
            self.fail("This function body is never closed.", start)
        return node.Lambda(position=start.position, parameters=tuple(parameters),
                           body=body)

    def _looks_tabular(self) -> bool:
        """Is what follows a table expression rather than a scalar one?"""
        token = self.current
        if token.is_word("print", "union", "search"):
            return True
        if token.kind is not Kind.IDENT:
            return False
        if token.text in REFUSED_OPERATORS:
            return True
        # An identifier followed by a pipe or the end of the statement is a
        # table; one followed by an operator or a bracket is an expression.
        return self.peek().kind is Kind.PIPE

    def parse_statement(self) -> Any:
        if self.current.is_word("print"):
            return self.parse_print()
        return self.parse_pipeline()

    def parse_print(self) -> node.Print:
        start = self.advance()
        items = [self.parse_named_expression(index=1)]
        index = 2
        while self.accept_punct(","):
            items.append(self.parse_named_expression(index=index))
            index += 1
        return node.Print(position=start.position, items=tuple(items))

    # -- pipelines --------------------------------------------------------

    def parse_pipeline(self) -> node.Pipeline:
        source = self.parse_source()
        steps: list[node.Operator] = []
        while self.current.kind is Kind.PIPE:
            self.advance()
            steps.append(self.parse_operator())
        return node.Pipeline(position=source.position, source=source,
                             steps=tuple(steps))

    def parse_source(self) -> Any:
        token = self.current
        if token.is_punct("("):
            self.advance()
            inner = self.parse_pipeline()
            self.expect_punct(")", "to close the sub-query")
            return inner
        if token.is_word("union"):
            return self.parse_union(as_source=True)
        if token.is_word("search"):
            # `search "term"` with no table in front searches everything.
            return self.parse_search(as_source=True)
        if token.kind is not Kind.IDENT:
            self.fail(f"A query starts with a table name, not "
                      f"{self.describe(token)}.",
                      hint="Try `Logs` — or open the Tables list on the left.")
        self._refuse_if_unsupported(token)
        self.advance()
        return node.Table(position=token.position, name=token.text)

    def _refuse_if_unsupported(self, token: Token) -> None:
        reason = REFUSED_OPERATORS.get(token.text.lower())
        if reason:
            raise KqlError(f"`{token.text}` is not available here.",
                           token.position, token.length, reason, self.text)

    def parse_operator(self) -> node.Operator:
        token = self.current
        if token.kind is not Kind.IDENT:
            self.fail(f"Expected an operator after '|', found "
                      f"{self.describe(token)}.")
        self._refuse_if_unsupported(token)
        word = token.text.lower()
        handler = _OPERATORS.get(word)
        if handler is None:
            raise KqlError(
                f"'{token.text}' is not an operator I know.",
                token.position, token.length,
                did_you_mean(word, node.OPERATOR_KEYWORDS), self.text)
        return handler(self)

    # -- individual operators ---------------------------------------------

    def parse_where(self) -> node.Where:
        start = self.advance()
        return node.Where(position=start.position, condition=self.parse_expression())

    def parse_extend(self) -> node.Extend:
        start = self.advance()
        return node.Extend(position=start.position,
                           items=tuple(self.parse_assignment_list()))

    def parse_project(self) -> node.Project:
        start = self.advance()
        mode = "project"
        if self.accept_punct("-"):
            suffix = self.expect_name("away, keep, rename or reorder")
            mode = f"project-{suffix.text.lower()}"
            if mode not in ("project-away", "project-keep", "project-rename",
                            "project-reorder"):
                self.fail(f"There is no `{mode}` operator.", suffix,
                          did_you_mean(suffix.text,
                                       ("away", "keep", "rename", "reorder")))
        if mode in ("project-away", "project-keep", "project-reorder"):
            columns = [self.parse_column_name()]
            while self.accept_punct(","):
                columns.append(self.parse_column_name())
            items = tuple(node.Assign(position=name.position, name=name.name,
                                      value=name) for name in columns)
            return node.Project(position=start.position, items=items, mode=mode)
        return node.Project(position=start.position,
                            items=tuple(self.parse_assignment_list()), mode=mode)

    def parse_summarize(self) -> node.Summarize:
        start = self.advance()
        aggregates: list[node.Assign] = []
        by: list[node.Assign] = []
        if self.current.kind in (Kind.END, Kind.PIPE) or self.current.is_punct(";"):
            self.fail("`summarize` needs something to compute or something to "
                      "group by.", start,
                      hint="For example: summarize count() by App")
        if not self.current.is_word("by"):
            aggregates = self.parse_assignment_list(stop_at_by=True)
        if self.accept_word("by"):
            by = self.parse_assignment_list()
        if not aggregates and not by:
            self.fail("`summarize` needs something to compute or something to "
                      "group by.", start,
                      hint='For example: summarize count() by App')
        return node.Summarize(position=start.position, aggregates=tuple(aggregates),
                              by=tuple(by))

    def parse_sort(self) -> node.SortBy:
        start = self.advance()
        if not self.accept_word("by"):
            self.fail("`sort` is written `sort by`.", start,
                      hint="For example: sort by Timestamp desc")
        return node.SortBy(position=start.position, keys=tuple(self.parse_sort_keys()))

    def parse_top(self) -> node.Top:
        start = self.advance()
        count = self.parse_expression()
        if not self.accept_word("by"):
            self.fail("`top` is written `top N by Column`.", start)
        return node.Top(position=start.position, count=count,
                        keys=tuple(self.parse_sort_keys()))

    def parse_take(self) -> node.Take:
        start = self.advance()
        return node.Take(position=start.position, count=self.parse_expression())

    def parse_count(self) -> node.CountRows:
        start = self.advance()
        name = "Count"
        if self.current.kind is Kind.IDENT and not self.current.is_word("by"):
            name = self.advance().text
            self.expect_punct("=", "after the name in `count`")
            self.expect_name("count()")
        return node.CountRows(position=start.position, name=name)

    def parse_distinct(self) -> node.Distinct:
        start = self.advance()
        if self.current.is_punct("*"):
            self.advance()
            return node.Distinct(position=start.position, columns=())
        columns = [self.parse_column_name()]
        while self.accept_punct(","):
            columns.append(self.parse_column_name())
        return node.Distinct(position=start.position, columns=tuple(columns))

    def parse_search(self, as_source: bool = False) -> node.Search:
        start = self.advance()
        case_sensitive = False
        columns: list[node.ColumnRef] = []
        while self.current.kind is Kind.IDENT and self.peek().is_punct("="):
            key = self.advance().text.lower()
            self.advance()
            value = self.advance().text.strip("\"'").lower()
            if key == "kind":
                case_sensitive = value == "case_sensitive"
        if self.accept_word("in"):
            self.expect_punct("(", "after `search in`")
            while not self.current.is_punct(")"):
                columns.append(self.parse_column_name())
                if not self.accept_punct(","):
                    break
            self.expect_punct(")", "to close `search in`")
        term = self.parse_expression()
        found = node.Search(position=start.position, term=term,
                            columns=tuple(columns), case_sensitive=case_sensitive)
        if as_source:
            return node.Pipeline(position=start.position,
                                 source=node.Table(position=start.position,
                                                   name="Logs"),
                                 steps=(found,))
        return found

    def parse_join(self) -> node.Join:
        start = self.advance()
        kind = "innerunique"
        while self.current.kind is Kind.IDENT and self.peek().is_punct("="):
            key = self.advance().text.lower()
            self.advance()
            value = self.advance().text
            if key == "kind":
                kind = value.lower()
            # hint.* settings are accepted and ignored: they tune a
            # distributed engine, and there is nothing to distribute here.
        if kind not in JOIN_KINDS:
            self.fail(f"`{kind}` is not a join kind.", start,
                      did_you_mean(kind, JOIN_KINDS))
        self.expect_punct("(", "before the right-hand table of a join")
        right = self.parse_pipeline()
        self.expect_punct(")", "to close the right-hand side of the join")
        if not self.accept_word("on"):
            self.fail("A join needs `on` and at least one key.", start,
                      hint="For example: join (Sources) on $left.Source == $right.Path")
        keys = [self.parse_join_key()]
        while self.accept_punct(","):
            keys.append(self.parse_join_key())
        return node.Join(position=start.position, kind=kind, right=right,
                         keys=tuple(keys))

    def parse_join_key(self) -> node.JoinKey:
        first = self.parse_expression()
        if isinstance(first, node.Binary) and first.op == "==":
            return node.JoinKey(position=first.position, left=first.left,
                                right=first.right)
        return node.JoinKey(position=first.position, left=first, right=first)

    def parse_union(self, as_source: bool = False) -> Any:
        start = self.advance()
        kind = "outer"
        with_source = ""
        while self.current.kind is Kind.IDENT and self.peek().is_punct("="):
            key = self.advance().text.lower()
            self.advance()
            value = self.advance().text.strip("\"'")
            if key == "kind":
                kind = value.lower()
            elif key in ("withsource", "with_source"):
                with_source = value
        sources = [self.parse_union_source()]
        while self.accept_punct(","):
            sources.append(self.parse_union_source())
        # Returned bare even when it is the whole source: the evaluator takes
        # a Union as a pipeline source directly, and wrapping it in a Pipeline
        # only buries it a level deeper for every caller that inspects it.
        return node.Union(position=start.position, sources=tuple(sources),
                          kind=kind, with_source=with_source)

    def parse_union_source(self) -> Any:
        if self.current.is_punct("("):
            self.advance()
            inner = self.parse_pipeline()
            self.expect_punct(")", "to close a union source")
            return inner
        name = self.expect_name("a table name")
        return node.Table(position=name.position, name=name.text)

    def parse_render(self) -> node.Render:
        start = self.advance()
        visual = self.expect_name("a chart kind").text.lower()
        if visual not in RENDER_KINDS:
            self.fail(f"`{visual}` is not a chart I can draw.", start,
                      did_you_mean(visual, RENDER_KINDS))
        properties: dict[str, Any] = {}
        if self.accept_word("with"):
            self.expect_punct("(", "after `with`")
            while not self.current.is_punct(")"):
                key = self.expect_name("a property name").text.lower()
                self.expect_punct("=", "after a property name")
                properties[key] = self.parse_expression()
                if not self.accept_punct(","):
                    break
            self.expect_punct(")", "to close the `with` list")
        return node.Render(position=start.position, visual=visual,
                           properties=properties)

    def parse_mv_expand(self) -> node.MvExpand:
        start = self.advance()
        self.expect_punct("-", "in `mv-expand`")
        word = self.expect_name("expand")
        if word.text.lower() != "expand":
            self.fail("`mv-expand` is the only operator that starts `mv-`.", word)
        items = self.parse_assignment_list(allow_to_typeof=True)
        return node.MvExpand(position=start.position, items=tuple(items))

    def parse_parse(self) -> node.Parse:
        start = self.advance()
        kind = "simple"
        while self.current.kind is Kind.IDENT and self.peek().is_punct("="):
            key = self.advance().text.lower()
            self.advance()
            value = self.advance().text.strip("\"'").lower()
            if key == "kind":
                kind = value
            if key == "flags":
                continue
        if kind not in ("simple", "regex", "relaxed"):
            self.fail(f"`parse kind={kind}` is not supported.", start,
                      did_you_mean(kind, ("simple", "regex", "relaxed")))
        source = self.parse_expression()
        if not self.accept_word("with"):
            self.fail("`parse` needs `with` and a pattern.", start,
                      hint='For example: parse Message with "user " User " logged in"')
        pattern: list[Any] = []
        while True:
            token = self.current
            if token.kind is Kind.STRING:
                pattern.append(("literal", self.advance().value))
            elif token.is_punct("*"):
                self.advance()
                pattern.append(("skip", None))
            elif token.kind is Kind.IDENT:
                name = self.advance().text
                declared = "string"
                if self.accept_punct(":"):
                    declared = self.expect_name("a type").text.lower()
                pattern.append(("capture", (name, declared)))
            else:
                break
        if not pattern:
            self.fail("This `parse` has no pattern after `with`.", start)
        return node.Parse(position=start.position, source=source, kind=kind,
                          pattern=tuple(pattern))

    def parse_sample(self) -> node.Sample:
        start = self.advance()
        return node.Sample(position=start.position, count=self.parse_expression())

    def parse_getschema(self) -> node.GetSchema:
        return node.GetSchema(position=self.advance().position)

    def parse_serialize(self) -> node.Serialize:
        start = self.advance()
        items: list[node.Assign] = []
        if self.current.kind is Kind.IDENT and not self.current.kind is Kind.END:
            items = self.parse_assignment_list()
        return node.Serialize(position=start.position, items=tuple(items))

    # -- lists ------------------------------------------------------------

    def parse_assignment_list(self, *, stop_at_by: bool = False,
                              allow_to_typeof: bool = False) -> list[node.Assign]:
        items = [self.parse_named_expression(allow_to_typeof=allow_to_typeof)]
        while self.accept_punct(","):
            if stop_at_by and self.current.is_word("by"):
                break
            items.append(self.parse_named_expression(allow_to_typeof=allow_to_typeof))
        return items

    def parse_named_expression(self, *, index: int = 0,
                               allow_to_typeof: bool = False) -> node.Assign:
        start = self.current
        if start.kind is Kind.IDENT and self.peek().is_punct("=") and not \
                self.peek(2).is_punct("="):
            name = self.advance().text
            self.advance()
            value = self.parse_expression()
            self._consume_to_typeof(allow_to_typeof)
            return node.Assign(position=start.position, name=name, value=value)
        value = self.parse_expression()
        self._consume_to_typeof(allow_to_typeof)
        return node.Assign(position=start.position, name=derive_name(value, index),
                           value=value, implicit=True)

    def _consume_to_typeof(self, allowed: bool) -> None:
        """``mv-expand X to typeof(long)`` — accepted and ignored.

        The declared type is advisory in Kusto and this engine infers the type
        from the values it actually finds, so honouring it would only give the
        user a way to be wrong.
        """
        if not allowed or not self.current.is_word("to"):
            return
        self.advance()
        if self.accept_word("typeof"):
            self.expect_punct("(", "after typeof")
            while not self.current.is_punct(")") and self.current.kind is not Kind.END:
                self.advance()
            self.expect_punct(")", "to close typeof")

    def parse_sort_keys(self) -> list[node.SortKey]:
        keys = [self.parse_sort_key()]
        while self.accept_punct(","):
            keys.append(self.parse_sort_key())
        return keys

    def parse_sort_key(self) -> node.SortKey:
        expression = self.parse_expression()
        descending = True
        nulls_first: bool | None = None
        if self.accept_word("asc"):
            descending = False
        elif self.accept_word("desc"):
            descending = True
        if self.accept_word("nulls"):
            if self.accept_word("first"):
                nulls_first = True
            elif self.accept_word("last"):
                nulls_first = False
            else:
                self.fail("`nulls` has to be followed by `first` or `last`.")
        return node.SortKey(position=expression.position, expr=expression,
                            descending=descending, nulls_first=nulls_first)

    def parse_column_name(self) -> node.ColumnRef:
        """A column name, or a wildcard such as ``S*`` in project-away."""
        token = self.current
        if token.kind is Kind.STRING:
            self.advance()
            return node.ColumnRef(position=token.position, name=str(token.value))
        if token.is_punct("["):
            self.advance()
            inner = self.advance()
            self.expect_punct("]", "to close a bracketed column name")
            return node.ColumnRef(position=token.position,
                                  name=str(inner.value or inner.text))
        if token.is_punct("*"):
            self.advance()
            return node.ColumnRef(position=token.position, name="*")
        name = self.expect_name("a column name")
        text = name.text
        while self.current.is_punct("*"):
            self.advance()
            text += "*"
            if self.current.kind is Kind.IDENT:
                text += self.advance().text
        return node.ColumnRef(position=name.position, name=text)

    # -- expressions ------------------------------------------------------

    def parse_expression(self) -> Any:
        return self.parse_or()

    def parse_or(self) -> Any:
        left = self.parse_and()
        while self.current.is_word("or"):
            token = self.advance()
            right = self.parse_and()
            left = node.Binary(position=token.position, op="or", left=left, right=right)
        return left

    def parse_and(self) -> Any:
        left = self.parse_not()
        while self.current.is_word("and"):
            token = self.advance()
            right = self.parse_not()
            left = node.Binary(position=token.position, op="and", left=left, right=right)
        return left

    def parse_not(self) -> Any:
        if self.current.is_word("not"):
            token = self.advance()
            if self.current.is_punct("("):
                operand = self.parse_not()
            else:
                operand = self.parse_not()
            return node.Unary(position=token.position, op="not", operand=operand)
        if self.current.is_punct("!") and self.peek().is_punct("("):
            token = self.advance()
            return node.Unary(position=token.position, op="not",
                              operand=self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> Any:
        left = self.parse_additive()
        while True:
            token = self.current
            if token.is_punct(*COMPARISON_OPERATORS):
                self.advance()
                right = self.parse_additive()
                left = node.Binary(position=token.position, op=token.text,
                                   left=left, right=right)
                continue
            if token.kind is Kind.IDENT:
                word = token.text.lower()
                if word in ("in", "!in", "in~", "!in~"):
                    self.advance()
                    left = self.parse_in(left, word, token)
                    continue
                if word in ("between", "!between"):
                    self.advance()
                    left = self.parse_between(left, word.startswith("!"), token)
                    continue
                if word in STRING_OPERATORS:
                    self.advance()
                    if word == "matches":
                        if not self.accept_word("regex"):
                            self.fail("`matches` is written `matches regex`.", token)
                        word = "matches regex"
                    if word.lstrip("!") in ("has_any", "has_all"):
                        # These take a list, the way `in` does, rather than a
                        # single value: `has_any ("a", "b", "c")`.
                        right = self.parse_value_list(word, token)
                    else:
                        right = self.parse_additive()
                    left = node.Binary(position=token.position, op=word,
                                       left=left, right=right)
                    continue
            return left

    def parse_value_list(self, word: str, token: Token) -> Any:
        """The ``("a", "b")`` after has_any / has_all, as one array value."""
        if not self.current.is_punct("("):
            return self.parse_additive()
        self.advance()
        items: list[Any] = []
        while not self.current.is_punct(")"):
            items.append(self.parse_expression())
            if not self.accept_punct(","):
                break
        self.expect_punct(")", f"to close the `{word}` list")
        if len(items) == 1:
            return items[0]
        return node.Call(position=token.position, name="pack_array",
                         args=tuple(items))

    def parse_in(self, left: Any, word: str, token: Token) -> node.InList:
        self.expect_punct("(", f"after `{word}`")
        items: list[Any] = []
        while not self.current.is_punct(")"):
            items.append(self.parse_expression())
            if not self.accept_punct(","):
                break
        self.expect_punct(")", f"to close the `{word}` list")
        return node.InList(position=token.position, target=left, items=tuple(items),
                           negate=word.startswith("!"), fold_case=word.endswith("~"))

    def parse_between(self, left: Any, negate: bool, token: Token) -> node.Between:
        self.expect_punct("(", "after `between`")
        low = self.parse_additive()
        if not self.accept_punct(".."):
            self.fail("`between` needs two values separated by '..'.", token,
                      hint="For example: between (ago(1d) .. now())")
        high = self.parse_additive()
        self.expect_punct(")", "to close `between`")
        return node.Between(position=token.position, target=left, low=low,
                            high=high, negate=negate)

    def parse_additive(self) -> Any:
        left = self.parse_multiplicative()
        while self.current.is_punct("+", "-"):
            token = self.advance()
            right = self.parse_multiplicative()
            left = node.Binary(position=token.position, op=token.text,
                               left=left, right=right)
        return left

    def parse_multiplicative(self) -> Any:
        left = self.parse_unary()
        while self.current.is_punct("*", "/", "%"):
            token = self.advance()
            right = self.parse_unary()
            left = node.Binary(position=token.position, op=token.text,
                               left=left, right=right)
        return left

    def parse_unary(self) -> Any:
        if self.current.is_punct("-", "+"):
            token = self.advance()
            return node.Unary(position=token.position, op=token.text,
                              operand=self.parse_unary())
        return self.parse_postfix()

    def parse_postfix(self) -> Any:
        value = self.parse_primary()
        while True:
            if self.current.is_punct("."):
                dot = self.advance()
                name = self.current
                if name.kind is Kind.IDENT:
                    self.advance()
                    value = node.Member(position=dot.position, target=value,
                                        name=name.text)
                    continue
                self.fail("A '.' has to be followed by a field name.", dot)
            if self.current.is_punct("["):
                bracket = self.advance()
                index = self.parse_expression()
                self.expect_punct("]", "to close an index")
                value = node.Index(position=bracket.position, target=value,
                                   index=index)
                continue
            return value

    def parse_primary(self) -> Any:
        token = self.current

        if token.kind is Kind.NUMBER:
            self.advance()
            kind = "long" if isinstance(token.value, int) else "real"
            return node.Literal(position=token.position, value=token.value, type=kind)

        if token.kind is Kind.TIMESPAN:
            self.advance()
            return node.Literal(position=token.position, value=token.value,
                                type="timespan")

        if token.kind is Kind.STRING:
            self.advance()
            return node.Literal(position=token.position, value=token.value,
                                type="string")

        if token.is_punct("("):
            self.advance()
            inner = self.parse_expression()
            self.expect_punct(")", "to close the group")
            return inner

        if token.is_punct("*"):
            self.advance()
            return node.Star(position=token.position)

        if token.kind is Kind.IDENT:
            word = token.text.lower()
            if word in ("true", "false"):
                self.advance()
                return node.Literal(position=token.position, value=word == "true",
                                    type="bool")
            if word == "null":
                self.advance()
                return node.Literal(position=token.position, value=None, type="null")
            if word == "toscalar" and self.peek().is_punct("("):
                return self.parse_toscalar()
            if word in ("datetime", "timespan", "time", "dynamic", "typeof", "guid"):
                if self.peek().is_punct("("):
                    return self.parse_typed_literal()
            if self.peek().is_punct("("):
                self.advance()
                self.advance()
                args: list[Any] = []
                while not self.current.is_punct(")"):
                    if self.current.is_punct("*"):
                        args.append(node.Star(position=self.advance().position))
                    else:
                        args.append(self.parse_expression())
                    if not self.accept_punct(","):
                        break
                self.expect_punct(")", f"to close the call to {token.text}")
                return node.Call(position=token.position, name=token.text,
                                 args=tuple(args))
            self.advance()
            if token.text.startswith("$"):
                return node.ColumnRef(position=token.position, name=token.text)
            return node.ColumnRef(position=token.position, name=token.text)

        self.fail(f"I did not expect {self.describe(token)} here.")
        raise AssertionError("unreachable")

    def parse_toscalar(self) -> node.Call:
        """``toscalar(Table | summarize max(X))`` — one cell as a value.

        Special-cased here because its argument is a whole pipeline rather
        than an expression, which the ordinary call syntax cannot hold.
        """
        token = self.advance()
        self.expect_punct("(", "after toscalar")
        inner = self.parse_pipeline()
        self.expect_punct(")", "to close toscalar(...)")
        return node.Call(position=token.position, name="toscalar", args=(inner,))

    def parse_typed_literal(self) -> Any:
        token = self.advance()
        word = token.text.lower()
        self.expect_punct("(", f"after {token.text}")

        if word == "dynamic":
            value = self.parse_dynamic_value()
            self.expect_punct(")", "to close dynamic(...)")
            return node.Literal(position=token.position, value=value, type="dynamic")

        if word == "typeof":
            name = self.expect_name("a type name").text
            self.expect_punct(")", "to close typeof(...)")
            return node.Literal(position=token.position, value=name, type="string")

        # Read the source text between the brackets rather than re-joining
        # the tokens: `datetime(2026-09-20 12:10:00)` lexes as five tokens and
        # gluing them back together loses the space, which turns a perfectly
        # ordinary date into "not a date I can read".
        begin = self.current.position
        end = begin
        depth = 0
        while not (self.current.is_punct(")") and depth == 0):
            if self.current.kind is Kind.END:
                self.fail(f"{token.text}(...) is never closed.", token)
            piece = self.advance()
            if piece.is_punct("("):
                depth += 1
            elif piece.is_punct(")"):
                depth -= 1
            end = piece.position + piece.length
        self.expect_punct(")", f"to close {token.text}(...)")
        body = self.text[begin:end].strip().strip("\"'")

        if word == "datetime":
            moment = parse_datetime_literal(body)
            if moment is None:
                raise KqlError(f"{body!r} is not a date I can read.",
                               token.position, token.length,
                               "Try datetime(2026-09-21) or datetime(2026-09-21 14:00:00Z).",
                               self.text)
            return node.Literal(position=token.position, value=moment, type="datetime")

        if word in ("timespan", "time"):
            span = parse_timespan_literal(body)
            if span is None:
                raise KqlError(f"{body!r} is not a duration I can read.",
                               token.position, token.length,
                               "Try timespan(1d), timespan(01:30:00) or 90m.",
                               self.text)
            return node.Literal(position=token.position, value=span, type="timespan")

        return node.Literal(position=token.position, value=body, type="string")

    def parse_dynamic_value(self) -> Any:
        """A JSON-shaped literal inside ``dynamic(...)``."""
        token = self.current
        if token.is_punct("["):
            self.advance()
            items: list[Any] = []
            while not self.current.is_punct("]"):
                items.append(self.parse_dynamic_value())
                if not self.accept_punct(","):
                    break
            self.expect_punct("]", "to close a dynamic array")
            return items
        if token.is_punct("{"):
            self.advance()
            mapping: dict[str, Any] = {}
            while not self.current.is_punct("}"):
                key = self.advance()
                name = str(key.value) if key.kind is Kind.STRING else key.text
                self.expect_punct(":", "after a key in a dynamic object")
                mapping[name] = self.parse_dynamic_value()
                if not self.accept_punct(","):
                    break
            self.expect_punct("}", "to close a dynamic object")
            return mapping
        if token.kind in (Kind.STRING, Kind.NUMBER, Kind.TIMESPAN):
            self.advance()
            return token.value
        if token.is_punct("-"):
            self.advance()
            inner = self.parse_dynamic_value()
            return -inner if isinstance(inner, (int, float)) else inner
        if token.is_word("true", "false"):
            return self.advance().text.lower() == "true"
        if token.is_word("null"):
            self.advance()
            return None
        self.fail(f"{self.describe(token)} cannot appear inside dynamic(...).")
        raise AssertionError("unreachable")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

JOIN_KINDS: tuple[str, ...] = (
    "inner", "innerunique", "leftouter", "rightouter", "fullouter",
    "leftanti", "rightanti", "leftsemi", "rightsemi", "anti", "semi",
)

RENDER_KINDS: tuple[str, ...] = (
    "table", "timechart", "linechart", "areachart", "barchart", "columnchart",
    "piechart", "scatterchart", "stackedareachart", "card", "anomalychart",
)


def derive_name(expression: Any, index: int = 0) -> str:
    """The column name Kusto would give an unnamed expression.

    ``Level`` stays ``Level``; ``count()`` becomes ``count_``; anything else
    becomes ``Column1``. Matching Kusto here matters because published queries
    refer to these names downstream.
    """
    if isinstance(expression, node.ColumnRef):
        return expression.name
    if isinstance(expression, node.Member):
        return expression.name
    if isinstance(expression, node.Call):
        if not expression.args:
            return f"{expression.name}_"
        inner = derive_name(expression.args[0])
        if expression.name.lower() in _NAME_PRESERVING:
            # Kusto keeps the column's own name through bin(), which is why
            # `summarize count() by bin(Timestamp, 1h) | sort by Timestamp`
            # is the form every published query uses.
            return inner
        if inner.startswith("Column"):
            return f"{expression.name}_"
        return f"{expression.name}_{inner}"
    if isinstance(expression, node.Index):
        base = derive_name(expression.target)
        if isinstance(expression.index, node.Literal):
            return f"{base}_{expression.index.value}"
        return base
    return f"Column{index if index else 1}"


#: Functions that pass their first argument's name through to the result.
_NAME_PRESERVING = frozenset({"bin", "bin_at", "floor"})


def parse_datetime_literal(body: str) -> datetime | None:
    """``2026-09-21``, ``2026-09-21 14:00:00Z``, ``now``, an epoch number."""
    text = body.strip().strip("\"'")
    if not text:
        return None
    lowered = text.lower()
    if lowered in ("now", "utcnow"):
        return datetime.now(timezone.utc)
    if lowered in ("null", "min", "datetime.min"):
        return None
    normalised = text.replace("Z", "+00:00").replace("z", "+00:00")
    for pattern in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S",
                    "%Y/%m/%d", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y"):
        try:
            moment = datetime.strptime(text, pattern)
        except ValueError:
            continue
        return moment.replace(tzinfo=timezone.utc)
    try:
        moment = datetime.fromisoformat(normalised)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def parse_timespan_literal(body: str) -> timedelta | None:
    """``1d``, ``01:30:00``, ``1.02:03:04``, or a bare number of days."""
    from ..model import parse_timespan

    text = body.strip().strip("\"'")
    if not text:
        return None
    if ":" in text:
        days = 0.0
        head = text
        if "." in text.split(":")[0]:
            day_part, _, head = text.partition(".")
            try:
                days = float(day_part)
            except ValueError:
                return None
        pieces = head.split(":")
        if len(pieces) not in (2, 3):
            return None
        try:
            numbers = [float(piece) for piece in pieces]
        except ValueError:
            return None
        while len(numbers) < 3:
            numbers.append(0.0)
        return timedelta(days=days, hours=numbers[0], minutes=numbers[1],
                         seconds=numbers[2])
    return parse_timespan(text)


_OPERATORS = {
    "where": Parser.parse_where,
    "filter": Parser.parse_where,
    "extend": Parser.parse_extend,
    "project": Parser.parse_project,
    "summarize": Parser.parse_summarize,
    "sort": Parser.parse_sort,
    "order": Parser.parse_sort,
    "top": Parser.parse_top,
    "take": Parser.parse_take,
    "limit": Parser.parse_take,
    "count": Parser.parse_count,
    "distinct": Parser.parse_distinct,
    "search": Parser.parse_search,
    "join": Parser.parse_join,
    "union": Parser.parse_union,
    "render": Parser.parse_render,
    "mv": Parser.parse_mv_expand,
    "parse": Parser.parse_parse,
    "sample": Parser.parse_sample,
    "getschema": Parser.parse_getschema,
    "serialize": Parser.parse_serialize,
}


def parse(text: str) -> node.Query:
    """Parse a whole query. Raises :class:`KqlError` with a position."""
    if not text.strip():
        raise KqlError("There is no query to run.", 0, 1,
                       "Type a table name to start — `Logs`, for instance.", text)
    return Parser(text).parse_query()
