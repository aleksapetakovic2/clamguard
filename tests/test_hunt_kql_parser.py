"""The language's front end: tokens, syntax, and the quality of its refusals.

A query language whose errors are "syntax error" is a query language nobody
learns, so half of these tests are about the message rather than the failure.
"""

from __future__ import annotations

import unittest
from datetime import timedelta

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt.kql import ast as node  # noqa: E402
from clamguard.core.hunt.kql.errors import KqlError, did_you_mean  # noqa: E402
from clamguard.core.hunt.kql.lexer import Kind, tokenise  # noqa: E402
from clamguard.core.hunt.kql.parser import (  # noqa: E402
    derive_name,
    parse,
    parse_datetime_literal,
    parse_timespan_literal,
)


def kinds(text: str) -> list[Kind]:
    return [token.kind for token in tokenise(text)][:-1]


def values(text: str) -> list:
    return [token.value for token in tokenise(text)][:-1]


class TestLexer(unittest.TestCase):
    def test_a_pipeline_lexes_into_its_parts(self) -> None:
        self.assertEqual(kinds('Logs | take 5'),
                         [Kind.IDENT, Kind.PIPE, Kind.IDENT, Kind.NUMBER])

    def test_a_timespan_is_one_token_not_two(self) -> None:
        tokens = tokenise("ago(1h)")
        span = next(token for token in tokens if token.kind is Kind.TIMESPAN)
        self.assertEqual(span.value, timedelta(hours=1))

    def test_minutes_are_not_milliseconds(self) -> None:
        self.assertEqual(tokenise("5m")[0].value, timedelta(minutes=5))
        self.assertEqual(tokenise("5ms")[0].value, timedelta(milliseconds=5))

    def test_a_number_followed_by_a_word_is_not_a_timespan(self) -> None:
        tokens = tokenise("5 minutes_ago")
        self.assertIs(tokens[0].kind, Kind.NUMBER)

    def test_negated_word_operators_lex_as_one_token(self) -> None:
        for text in ("!contains", "!has", "!in", "!startswith", "!between"):
            with self.subTest(text=text):
                tokens = tokenise(f"x {text} y")
                self.assertEqual(tokens[1].text, text)
                self.assertIs(tokens[1].kind, Kind.IDENT)

    def test_a_bang_before_anything_else_stays_punctuation(self) -> None:
        self.assertIs(tokenise("!(x)")[0].kind, Kind.PUNCT)
        self.assertEqual(tokenise("a != b")[1].text, "!=")

    def test_a_verbatim_string_keeps_its_backslashes(self) -> None:
        self.assertEqual(values(r'@"a\d+"')[0], r"a\d+")
        self.assertEqual(values(r'"a\d+"')[0], "ad+")

    def test_a_doubled_quote_inside_a_verbatim_string_is_one_quote(self) -> None:
        self.assertEqual(values('@"say ""hi"""')[0], 'say "hi"')

    def test_escapes_work_in_an_ordinary_string(self) -> None:
        self.assertEqual(values(r'"a\nb\tc\"d"')[0], 'a\nb\tc"d')

    def test_comments_run_to_the_end_of_the_line(self) -> None:
        self.assertEqual(kinds("Logs // take 5\n| count"),
                         [Kind.IDENT, Kind.PIPE, Kind.IDENT])

    def test_hexadecimal_numbers_are_understood(self) -> None:
        self.assertEqual(values("0x1F")[0], 31)

    def test_reals_and_exponents_are_understood(self) -> None:
        self.assertEqual(values("1.5e2")[0], 150.0)
        self.assertEqual(values("0.25")[0], 0.25)

    def test_dollar_identifiers_lex_as_names(self) -> None:
        """`$left.App` in a join's `on` clause."""
        tokens = tokenise("$left.App")
        self.assertEqual(tokens[0].text, "$left")
        self.assertEqual(tokens[2].text, "App")

    def test_an_unterminated_string_says_where_it_started(self) -> None:
        with self.assertRaises(KqlError) as caught:
            tokenise('Logs | where x == "unclosed')
        self.assertIn("never closed", caught.exception.message)
        self.assertGreater(caught.exception.position, 0)

    def test_an_unknown_character_is_refused_with_its_position(self) -> None:
        with self.assertRaises(KqlError) as caught:
            tokenise("Logs ` x")
        self.assertEqual(caught.exception.position, 5)

    def test_every_token_knows_where_it_came_from(self) -> None:
        text = "Logs | take 5"
        for token in tokenise(text)[:-1]:
            with self.subTest(token=token):
                self.assertEqual(text[token.position:token.position + token.length],
                                 token.text)


class TestParser(unittest.TestCase):
    def test_a_bare_table_is_a_query(self) -> None:
        query = parse("Logs")
        self.assertIsInstance(query.body.source, node.Table)
        self.assertEqual(query.body.source.name, "Logs")

    def test_each_operator_becomes_a_step(self) -> None:
        query = parse("Logs | where a == 1 | take 5 | count")
        self.assertEqual([step.keyword for step in query.body.steps],
                         ["where", "take", "count"])

    def test_operator_precedence_follows_kusto(self) -> None:
        where = parse("Logs | where a == 1 or b == 2 and c == 3").body.steps[0]
        self.assertEqual(where.condition.op, "or")
        self.assertEqual(where.condition.right.op, "and")

    def test_arithmetic_binds_tighter_than_comparison(self) -> None:
        where = parse("Logs | where a + 1 > 2 * 3").body.steps[0]
        self.assertEqual(where.condition.op, ">")
        self.assertEqual(where.condition.left.op, "+")
        self.assertEqual(where.condition.right.op, "*")

    def test_in_takes_a_list(self) -> None:
        where = parse('Logs | where Level in ("a", "b")').body.steps[0]
        self.assertIsInstance(where.condition, node.InList)
        self.assertEqual(len(where.condition.items), 2)
        self.assertFalse(where.condition.negate)

    def test_not_in_negates_and_the_tilde_folds_case(self) -> None:
        where = parse('Logs | where Level !in~ ("a")').body.steps[0]
        self.assertTrue(where.condition.negate)
        self.assertTrue(where.condition.fold_case)

    def test_has_any_takes_a_list_like_in_does(self) -> None:
        """Parsed as a single array argument, not as a parenthesised group —
        `has_any ("a", "b")` is a comma expression otherwise."""
        where = parse('Logs | where Message has_any ("a", "b", "c")').body.steps[0]
        self.assertEqual(where.condition.op, "has_any")
        self.assertEqual(where.condition.right.name, "pack_array")
        self.assertEqual(len(where.condition.right.args), 3)

    def test_between_needs_two_dots(self) -> None:
        where = parse("Logs | where x between (1 .. 5)").body.steps[0]
        self.assertIsInstance(where.condition, node.Between)
        with self.assertRaises(KqlError) as caught:
            parse("Logs | where x between (1, 5)")
        self.assertIn("'..'", caught.exception.message)

    def test_matches_needs_the_word_regex(self) -> None:
        self.assertEqual(
            parse('Logs | where x matches regex "a"').body.steps[0].condition.op,
            "matches regex")
        with self.assertRaises(KqlError) as caught:
            parse('Logs | where x matches "a"')
        self.assertIn("matches regex", caught.exception.hint
                      or caught.exception.message)

    def test_summarize_splits_aggregates_from_grouping(self) -> None:
        step = parse("Logs | summarize n = count(), s = sum(x) by App, "
                     "Hour = bin(Timestamp, 1h)").body.steps[0]
        self.assertEqual([item.name for item in step.aggregates], ["n", "s"])
        self.assertEqual([item.name for item in step.by], ["App", "Hour"])

    def test_summarize_with_nothing_in_it_is_refused(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("Logs | summarize")
        self.assertIn("needs something", caught.exception.message)

    def test_sort_is_written_sort_by(self) -> None:
        step = parse("Logs | sort by a desc, b asc").body.steps[0]
        self.assertTrue(step.keys[0].descending)
        self.assertFalse(step.keys[1].descending)
        with self.assertRaises(KqlError) as caught:
            parse("Logs | sort a")
        self.assertIn("sort by", caught.exception.message)

    def test_sorting_defaults_to_descending_as_kusto_does(self) -> None:
        self.assertTrue(parse("Logs | sort by a").body.steps[0].keys[0].descending)

    def test_nulls_first_and_last_are_understood(self) -> None:
        key = parse("Logs | sort by a asc nulls last").body.steps[0].keys[0]
        self.assertFalse(key.nulls_first)

    def test_project_away_and_friends_parse(self) -> None:
        for text, mode in (("project-away a, b", "project-away"),
                           ("project-keep a", "project-keep"),
                           ("project-rename New = Old", "project-rename"),
                           ("project-reorder a, b", "project-reorder")):
            with self.subTest(mode=mode):
                self.assertEqual(parse(f"Logs | {text}").body.steps[0].mode, mode)

    def test_a_misspelled_project_variant_suggests_the_right_one(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("Logs | project-awya a")
        self.assertIn("away", caught.exception.hint)

    def test_join_takes_a_kind_a_table_and_keys(self) -> None:
        step = parse("Logs | join kind=leftouter (Sources) on "
                     "$left.Source == $right.Path").body.steps[0]
        self.assertEqual(step.kind, "leftouter")
        self.assertEqual(len(step.keys), 1)

    def test_an_unknown_join_kind_suggests_a_real_one(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("Logs | join kind=leftout (Sources) on a")
        self.assertIn("leftouter", caught.exception.hint)

    def test_union_takes_several_sources(self) -> None:
        step = parse("union withsource=T Logs, Sources").body.source
        self.assertEqual(step.with_source, "T")
        self.assertEqual(len(step.sources), 2)

    def test_render_names_a_chart(self) -> None:
        step = parse('Logs | render timechart with (title="x")').body.steps[0]
        self.assertEqual(step.visual, "timechart")
        self.assertIn("title", step.properties)

    def test_an_unknown_chart_suggests_a_real_one(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("Logs | render timchart")
        self.assertIn("timechart", caught.exception.hint)

    def test_parse_builds_a_pattern_of_literals_and_captures(self) -> None:
        step = parse('Logs | parse Message with "user " User " did " '
                     'Action:string').body.steps[0]
        kinds = [kind for kind, _payload in step.pattern]
        self.assertEqual(kinds, ["literal", "capture", "literal", "capture"])

    def test_let_binds_a_value_a_table_and_a_function(self) -> None:
        query = parse("let n = 5; let T = Logs | take 1; "
                      "let f = (x: long) { x * 2 }; Logs | take n")
        self.assertEqual([item.name for item in query.lets], ["n", "T", "f"])
        self.assertIsInstance(query.lets[1].value, node.Pipeline)
        self.assertIsInstance(query.lets[2].value, node.Lambda)

    def test_a_let_without_a_semicolon_says_so(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("let n = 5 Logs")
        self.assertIn("semicolon", caught.exception.hint)

    def test_print_makes_a_one_row_table(self) -> None:
        query = parse("print x = 1, 2 + 3")
        self.assertIsInstance(query.body, node.Print)
        self.assertEqual(query.body.items[0].name, "x")

    def test_dynamic_literals_parse_as_json(self) -> None:
        literal = parse('print dynamic({"a": [1, 2], "b": null})').body.items[0].value
        self.assertEqual(literal.value, {"a": [1, 2], "b": None})

    def test_datetime_literals_parse_in_several_shapes(self) -> None:
        for text in ("2026-09-21", "2026-09-21 14:00:00", "2026-09-21T14:00:00Z"):
            with self.subTest(text=text):
                self.assertIsNotNone(parse_datetime_literal(text))

    def test_timespan_literals_parse_in_kusto_notation(self) -> None:
        self.assertEqual(parse_timespan_literal("01:30:00"), timedelta(minutes=90))
        self.assertEqual(parse_timespan_literal("1.02:00:00"),
                         timedelta(days=1, hours=2))
        self.assertEqual(parse_timespan_literal("2d"), timedelta(days=2))

    def test_an_unreadable_date_is_refused_with_an_example(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("Logs | where Timestamp > datetime(yesterday)")
        self.assertIn("datetime(2026", caught.exception.hint)

    def test_toscalar_takes_a_whole_query(self) -> None:
        call = parse("print toscalar(Logs | count)").body.items[0].value
        self.assertEqual(call.name, "toscalar")
        self.assertIsInstance(call.args[0], node.Pipeline)

    def test_a_subquery_in_brackets_is_a_source(self) -> None:
        query = parse("(Logs | take 5) | count")
        self.assertIsInstance(query.body.source, node.Pipeline)


class TestRefusals(unittest.TestCase):
    def test_an_unknown_operator_suggests_the_right_one(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("Logs | wher x == 1")
        self.assertIn("where", caught.exception.hint)
        self.assertEqual(caught.exception.position, 7)

    def test_the_operators_that_reach_outside_are_refused_by_name(self) -> None:
        for word, expected in (("evaluate", "plugin"),
                               ("externaldata", "network"),
                               ("invoke", "server")):
            with self.subTest(word=word):
                with self.assertRaises(KqlError) as caught:
                    parse(f"Logs | {word} something")
                self.assertIn(expected, caught.exception.hint)

    def test_an_empty_query_says_what_to_type(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("   ")
        self.assertIn("Logs", caught.exception.hint)

    def test_a_query_that_does_not_start_with_a_table_says_so(self) -> None:
        with self.assertRaises(KqlError) as caught:
            parse("| take 5")
        self.assertIn("starts with a table", caught.exception.message)

    def test_an_error_can_draw_a_caret_under_the_token(self) -> None:
        try:
            parse("Logs | wher x == 1")
        except KqlError as error:
            drawn = error.caret()
            self.assertIn("^^^^", drawn)
            self.assertIn("Logs | wher", drawn)
        else:
            self.fail("expected a KqlError")

    def test_an_error_knows_its_line_and_column(self) -> None:
        try:
            parse("Logs\n| take 5\n| wher x == 1")
        except KqlError as error:
            line, column = error.line_and_column()
            self.assertEqual(line, 3)
            self.assertEqual(column, 3)
        else:
            self.fail("expected a KqlError")

    def test_a_suggestion_is_offered_only_when_something_is_close(self) -> None:
        self.assertIn("where", did_you_mean("wher", ["where", "extend"]))
        self.assertEqual(did_you_mean("zzzzzz", ["where", "extend"]), "")

    def test_case_and_underscores_are_forgiven_in_a_suggestion(self) -> None:
        self.assertIn("make_list", did_you_mean("makelist", ["make_list", "count"]))


class TestNaming(unittest.TestCase):
    def test_an_unnamed_column_gets_the_name_kusto_would_give_it(self) -> None:
        cases = {"Logs | project App": "App",
                 "Logs | summarize count()": "count_",
                 "Logs | summarize dcount(App)": "dcount_App",
                 "Logs | project Extra.pid": "pid"}
        for text, expected in cases.items():
            with self.subTest(text=text):
                step = parse(text).body.steps[0]
                items = getattr(step, "items", None) or step.aggregates
                self.assertEqual(items[0].name, expected)

    def test_an_expression_with_no_obvious_name_gets_a_numbered_one(self) -> None:
        self.assertTrue(derive_name(parse("print 1 + 2").body.items[0].value, 1)
                        .startswith("Column"))


if __name__ == "__main__":
    unittest.main()
