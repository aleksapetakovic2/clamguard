"""Executing a query — and proving the optimiser cannot change the answer.

The planner translates a prefix of every pipeline into SQL. That is where the
speed comes from and it is also the obvious place for a subtle wrong answer to
hide, so the central test here is differential: run the same query with the
planner on and off and require identical results. If the two ever disagree the
planner is wrong, because the Python evaluator is the definition.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from .hunt_support import BASE, HuntTestCase, print_query
from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt.kql import KqlError  # noqa: E402
from clamguard.core.hunt.kql.engine import check, describe_plan  # noqa: E402
from clamguard.core.hunt.model import ColumnType, TimeRange  # noqa: E402


class TestReading(HuntTestCase):
    def test_a_bare_table_returns_everything(self) -> None:
        self.assertEqual(len(self.rows("Logs")), 9)

    def test_the_columns_are_the_catalogue_columns(self) -> None:
        names = self.run_query("Logs | take 1").names
        for expected in ("Timestamp", "Level", "Message", "App", "Source",
                         "Extra", "LineNumber", "Raw"):
            self.assertIn(expected, names)

    def test_level_comes_back_as_a_word_not_a_number(self) -> None:
        levels = set(self.run_query("Logs").column_values("Level"))
        self.assertEqual(levels, {"info", "warning", "error", "critical",
                                  "debug", "unknown"})

    def test_a_timestamp_comes_back_as_a_datetime(self) -> None:
        value = self.rows("Logs | where isnotnull(Timestamp) | take 1")[0][0]
        self.assertIsInstance(value, datetime)

    def test_extra_comes_back_as_a_dynamic_value(self) -> None:
        value = self.one('Logs | where App == "alpha" | take 1 | project Extra')
        self.assertEqual(value, {"pid": 100})

    def test_take_reads_only_what_it_takes(self) -> None:
        result = self.run_query("Logs | take 3")
        self.assertEqual(result.stats.rows, 3)
        self.assertEqual(result.stats.scanned, 3)


class TestFiltering(HuntTestCase):
    def test_equality_on_a_level(self) -> None:
        self.assertEqual(self.one('Logs | where Level == "error" | count'), 2)

    def test_a_level_that_does_not_exist_matches_nothing(self) -> None:
        self.assertEqual(self.one('Logs | where Level == "banana" | count'), 0)

    def test_in_matches_any_of_a_list(self) -> None:
        self.assertEqual(
            self.one('Logs | where Level in ("error", "critical") | count'), 3)

    def test_not_in_is_the_complement(self) -> None:
        self.assertEqual(
            self.one('Logs | where Level !in ("error", "critical") | count'), 6)

    def test_contains_is_case_insensitive(self) -> None:
        self.assertEqual(self.one('Logs | where Message contains "REFUSED" | count'), 2)

    def test_contains_cs_is_not(self) -> None:
        self.assertEqual(
            self.one('Logs | where Message contains_cs "REFUSED" | count'), 0)

    def test_has_matches_whole_words(self) -> None:
        self.assertEqual(self.one('Logs | where Message has "refused" | count'), 2)
        self.assertEqual(self.one('Logs | where Message has "refus" | count'), 0)

    def test_startswith_and_endswith(self) -> None:
        self.assertEqual(self.one('Logs | where Message startswith "conn" | count'), 2)
        self.assertEqual(self.one('Logs | where Message endswith "up" | count'), 1)

    def test_has_any_takes_a_list(self) -> None:
        self.assertEqual(
            self.one('Logs | where Message has_any ("segfault", "refused") | count'), 3)

    def test_has_all_needs_all_of_them(self) -> None:
        self.assertEqual(
            self.one('Logs | where Message has_all ("connection", "refused") | count'), 2)

    def test_a_regular_expression_matches(self) -> None:
        self.assertEqual(
            self.one(r'Logs | where Message matches regex @"\b\d+\.\d+\.\d+\.\d+\b" '
                     "| count"), 2)

    def test_between_is_inclusive(self) -> None:
        text = ("Logs | where Timestamp between (datetime({}) .. datetime({})) "
                "| count")
        early = (BASE + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        late = (BASE + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(self.one(text.format(early, late)), 3)

    def test_and_or_and_not_compose(self) -> None:
        self.assertEqual(self.one(
            'Logs | where App == "alpha" and Level == "error" | count'), 2)
        self.assertEqual(self.one(
            'Logs | where App == "alpha" or App == "beta" | count'), 7)
        self.assertEqual(self.one(
            'Logs | where not(App == "alpha") | count'), 5)

    def test_a_null_never_matches_a_comparison(self) -> None:
        """Two thirds of real log lines have no timestamp; a filter has to
        exclude them rather than guess."""
        self.assertEqual(self.one("Logs | where Timestamp > datetime(1990-01-01) "
                                  "| count"), 7)
        self.assertEqual(self.one("Logs | where Timestamp < datetime(2090-01-01) "
                                  "| count"), 7)
        self.assertEqual(self.one("Logs | where isnull(Timestamp) | count"), 2)

    def test_a_dynamic_field_can_be_filtered_on(self) -> None:
        self.assertEqual(self.one("Logs | where Extra.pid == 101 | count"), 2)
        self.assertEqual(self.one('Logs | where Extra["pid"] == 100 | count'), 2)

    def test_a_missing_dynamic_field_is_null_not_an_error(self) -> None:
        self.assertEqual(self.one("Logs | where isnull(Extra.nothing) | count"), 9)


class TestShaping(HuntTestCase):
    def test_project_chooses_and_renames(self) -> None:
        result = self.run_query('Logs | project When = Timestamp, Message | take 1')
        self.assertEqual(result.names, ("When", "Message"))

    def test_project_away_removes(self) -> None:
        names = self.run_query("Logs | project-away Raw, Extra | take 1").names
        self.assertNotIn("Raw", names)
        self.assertIn("Message", names)

    def test_project_keep_keeps_only_those(self) -> None:
        self.assertEqual(
            self.run_query("Logs | project-keep App, Level | take 1").names,
            ("App", "Level"))

    def test_project_away_accepts_a_wildcard(self) -> None:
        names = self.run_query("Logs | project-away S* | take 1").names
        self.assertNotIn("Source", names)
        self.assertNotIn("SourceName", names)

    def test_project_rename_keeps_the_position(self) -> None:
        names = self.run_query("Logs | project-rename When = Timestamp | take 1").names
        self.assertEqual(names[0], "When")

    def test_extend_adds_a_computed_column(self) -> None:
        value = self.one('Logs | where App == "alpha" | take 1 '
                         "| extend Length = strlen(Message) | project Length")
        self.assertEqual(value, len("starting up"))

    def test_extend_can_replace_a_column(self) -> None:
        result = self.run_query('Logs | take 1 | extend App = "changed"')
        self.assertEqual(result.value(0, "App"), "changed")
        self.assertEqual(len(result.columns), 12)

    def test_distinct_removes_duplicates(self) -> None:
        self.assertEqual(len(self.rows("Logs | distinct App")), 3)

    def test_sort_orders_and_respects_direction(self) -> None:
        ascending = self.run_query(
            "Logs | sort by LineNumber asc, Message asc").column_values("Message")
        descending = self.run_query(
            "Logs | sort by LineNumber desc, Message desc").column_values("Message")
        self.assertEqual(ascending, list(reversed(descending)))

    def test_top_is_a_sort_and_a_take(self) -> None:
        rows = self.rows("Logs | top 2 by Timestamp desc")
        self.assertEqual(len(rows), 2)

    def test_count_produces_one_row(self) -> None:
        result = self.run_query("Logs | count")
        self.assertEqual(result.names, ("Count",))
        self.assertEqual(result.rows, [(9,)])

    def test_getschema_describes_the_columns(self) -> None:
        result = self.run_query("Logs | getschema")
        self.assertEqual(result.names[:3],
                         ("ColumnName", "ColumnOrdinal", "DataType"))
        self.assertIn("Timestamp", result.column_values("ColumnName"))

    def test_sample_returns_at_most_what_was_asked_for(self) -> None:
        self.assertEqual(len(self.rows("Logs | sample 3")), 3)


class TestSummarize(HuntTestCase):
    def test_counting_by_a_column(self) -> None:
        result = self.run_query("Logs | summarize n = count() by App")
        self.assertEqual(dict(result.rows), {"alpha": 4, "beta": 3, "gamma": 2})

    def test_counting_with_no_grouping_gives_one_row(self) -> None:
        self.assertEqual(self.one("Logs | summarize count()"), 9)

    def test_an_empty_input_still_answers_zero(self) -> None:
        self.assertEqual(self.one('Logs | where App == "nope" | summarize count()'), 0)

    def test_countif_counts_the_matching_rows(self) -> None:
        self.assertEqual(
            self.one('Logs | summarize countif(Level == "error")'), 2)

    def test_arithmetic_over_aggregates_works(self) -> None:
        """`summarize Rate = 100.0 * countif(...) / count()` is an ordinary
        thing to write, and it is not a bare aggregate call."""
        value = self.one('Logs | summarize Rate = round(100.0 * '
                         'countif(Level == "error") / count(), 1)')
        self.assertAlmostEqual(value, round(200 / 9, 1))

    def test_several_aggregates_at_once(self) -> None:
        result = self.run_query(
            "Logs | summarize n = count(), apps = dcount(App), "
            "first = min(Timestamp), last = max(Timestamp)")
        self.assertEqual(result.value(0, "n"), 9)
        self.assertEqual(result.value(0, "apps"), 3)
        self.assertIsInstance(result.value(0, "first"), datetime)

    def test_binning_a_timestamp_groups_by_period(self) -> None:
        rows = self.rows("Logs | where isnotnull(Timestamp) "
                         "| summarize count() by bin(Timestamp, 1h)")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], 7)

    def test_make_list_and_make_set(self) -> None:
        value = self.one('Logs | where App == "alpha" | summarize make_set(Level)')
        self.assertEqual(sorted(value), ["error", "info", "warning"])

    def test_arg_max_returns_the_whole_row(self) -> None:
        result = self.run_query(
            "Logs | where isnotnull(Timestamp) | summarize arg_max(Timestamp, *)")
        self.assertIn("Message", result.names)
        self.assertIn("install.sh", result.value(0, "Message"))

    def test_arg_max_with_named_columns(self) -> None:
        result = self.run_query("Logs | where isnotnull(Timestamp) "
                                "| summarize arg_max(Timestamp, Message, App)")
        self.assertEqual(result.value(0, "App"), "beta")

    def test_percentiles_are_exact(self) -> None:
        self.assertEqual(self.one("Logs | summarize percentile(LineNumber, 50)"), 1)

    def test_a_scalar_function_alone_is_refused_with_advice(self) -> None:
        with self.assertRaises(KqlError) as caught:
            self.rows("Logs | summarize App by Level")
        self.assertIn("count()", caught.exception.hint)

    def test_a_misspelled_aggregate_suggests_the_right_one(self) -> None:
        with self.assertRaises(KqlError) as caught:
            self.rows("Logs | summarize counts() by App")
        self.assertIn("count", caught.exception.hint)


class TestJoins(HuntTestCase):
    QUERY = ("Logs | summarize n = count() by Source "
             "| join kind={kind} (Sources | project Source = Path, Format) "
             "on Source")

    def test_an_inner_join_matches(self) -> None:
        rows = self.rows(self.QUERY.format(kind="inner"))
        self.assertEqual(len(rows), 3)

    def test_a_left_outer_join_keeps_unmatched_rows(self) -> None:
        rows = self.rows(
            'Logs | take 1 | extend Source = "/nowhere" '
            "| join kind=leftouter (Sources | project Source = Path) on Source")
        self.assertEqual(len(rows), 1)

    def test_a_left_anti_join_keeps_only_the_unmatched(self) -> None:
        rows = self.rows(
            'Logs | take 1 | extend Source = "/nowhere" '
            "| join kind=leftanti (Sources | project Source = Path) on Source")
        self.assertEqual(len(rows), 1)

    def test_a_left_semi_join_keeps_left_columns_only(self) -> None:
        result = self.run_query(
            "Logs | summarize n = count() by Source "
            "| join kind=leftsemi (Sources | project Source = Path) on Source")
        self.assertEqual(result.names, ("Source", "n"))

    def test_clashing_column_names_are_suffixed(self) -> None:
        names = self.run_query(
            "Logs | summarize n = count() by Source "
            "| join kind=inner (Sources | project Source = Path, App) on Source"
        ).names
        self.assertIn("Source1", names)

    def test_explicit_sides_are_understood(self) -> None:
        rows = self.rows(
            "Logs | summarize n = count() by Source "
            "| join kind=inner (Sources) on $left.Source == $right.Path")
        self.assertEqual(len(rows), 3)


class TestUnion(HuntTestCase):
    def test_it_concatenates_tables(self) -> None:
        self.assertEqual(self.one(
            "union (Logs | take 2 | project Message), "
            "(Sources | take 2 | project Message = Path) | count"), 4)

    def test_withsource_names_where_each_row_came_from(self) -> None:
        values = set(self.run_query(
            "union withsource=T (Logs | take 1 | project Message), "
            "(Sources | take 1 | project Message = Path)").column_values("T"))
        self.assertEqual(values, {"Logs", "Sources"})

    def test_inner_keeps_only_the_shared_columns(self) -> None:
        names = self.run_query(
            "union kind=inner (Logs | take 1 | project Message, App), "
            "(Logs | take 1 | project Message) ").names
        self.assertEqual(names, ("Message",))


class TestDynamicAndParsing(HuntTestCase):
    def test_mv_expand_makes_a_row_per_element(self) -> None:
        rows = self.rows("Logs | take 1 | extend a = dynamic([1, 2, 3]) "
                         "| mv-expand a | project a")
        self.assertEqual([row[0] for row in rows], [1, 2, 3])

    def test_mv_expand_over_an_empty_array_drops_the_row(self) -> None:
        self.assertEqual(self.rows("Logs | take 1 | extend a = dynamic([]) "
                                   "| mv-expand a"), [])

    def test_parse_pulls_fields_out_of_a_message(self) -> None:
        value = self.one('Logs | where Message startswith "connection refused to" '
                         '| parse Message with * "to " Address '
                         "| where Address == \"10.0.0.5\" | count")
        self.assertEqual(value, 1)

    def test_parse_can_type_a_capture(self) -> None:
        rows = self.rows('Logs | where App == "alpha" '
                         '| parse Message with * "full" * '
                         "| project Message")
        self.assertEqual(len(rows), 4)


class TestWindowFunctions(HuntTestCase):
    def test_row_number_counts_from_one(self) -> None:
        rows = self.rows("Logs | sort by LineNumber asc | serialize "
                         "| extend n = row_number() | project n")
        self.assertEqual([row[0] for row in rows], list(range(1, 10)))

    def test_prev_reaches_backwards(self) -> None:
        rows = self.rows("Logs | where isnotnull(Timestamp) | sort by Timestamp asc "
                         "| serialize | extend gap = Timestamp - prev(Timestamp) "
                         "| project gap")
        self.assertIsNone(rows[0][0])
        self.assertEqual(rows[1][0], timedelta(minutes=5))

    def test_serialize_is_not_required_but_the_order_is_then_arbitrary(self) -> None:
        """Kusto insists on `serialize` because it distributes the work. This
        engine does not distribute anything, so it materialises on demand and
        numbers whatever order the source produced."""
        rows = self.rows("Logs | project n = row_number()")
        self.assertEqual(sorted(row[0] for row in rows), list(range(1, 10)))


class TestRender(HuntTestCase):
    def test_render_records_what_to_draw(self) -> None:
        result = self.run_query('Logs | summarize count() by App '
                                '| render piechart with (title="x")')
        self.assertEqual(result.visualisation[0], "piechart")
        self.assertEqual(result.visualisation[1]["title"], "x")

    def test_render_does_not_change_the_rows(self) -> None:
        with_render = self.rows("Logs | summarize count() by App | render barchart")
        without = self.rows("Logs | summarize count() by App")
        self.assertEqual(with_render, without)


class TestLetAndPrint(HuntTestCase):
    def test_a_scalar_let_is_usable_in_a_filter(self) -> None:
        self.assertEqual(self.one('let bad = "error"; '
                                  "Logs | where Level == bad | count"), 2)

    def test_a_dynamic_let_works_with_in(self) -> None:
        self.assertEqual(self.one('let bad = dynamic(["error", "critical"]); '
                                  "Logs | where Level in (bad) | count"), 3)

    def test_a_tabular_let_can_be_queried(self) -> None:
        self.assertEqual(self.one('let E = Logs | where Level == "error"; '
                                  "E | count"), 2)

    def test_a_function_let_is_inlined(self) -> None:
        value = self.one("let double = (x: long) { x * 2 }; "
                         "print double(21)")
        self.assertEqual(value, 42)

    def test_a_function_called_with_the_wrong_count_says_so(self) -> None:
        with self.assertRaises(KqlError) as caught:
            self.rows("let f = (x: long) { x }; print f(1, 2)")
        self.assertIn("takes 1 argument", caught.exception.message)

    def test_print_needs_no_store_at_all(self) -> None:
        result = print_query('print x = 1 + 2, y = strcat("a", "b")')
        self.assertEqual(result.rows, [(3, "ab")])

    def test_toscalar_folds_a_query_into_a_value(self) -> None:
        self.assertEqual(self.one("print n = toscalar(Logs | count)"), 9)


class TestTimeRange(HuntTestCase):
    def test_the_page_range_filters_before_anything_else(self) -> None:
        window = TimeRange(start=BASE + timedelta(minutes=4),
                           end=BASE + timedelta(minutes=16))
        self.assertEqual(self.one("Logs | count", time_range=window), 3)

    def test_the_range_excludes_events_with_no_timestamp(self) -> None:
        """Which is correct, and is why the page says how many there are."""
        window = TimeRange(start=BASE - timedelta(days=1),
                           end=BASE + timedelta(days=1))
        self.assertEqual(self.one("Logs | count", time_range=window), 7)

    def test_all_time_includes_them(self) -> None:
        self.assertEqual(self.one("Logs | count",
                                  time_range=TimeRange.everything()), 9)

    def test_a_table_with_no_time_column_is_unaffected(self) -> None:
        window = TimeRange(start=BASE, end=BASE + timedelta(minutes=1))
        self.assertEqual(self.one("Logs | count | project Count",
                                  time_range=window), 1)


class TestPushdown(HuntTestCase):
    """The optimiser may make a query faster. It may not change the answer."""

    QUERIES = (
        "Logs",
        "Logs | take 4",
        'Logs | where Level == "error"',
        'Logs | where Level != "error"',
        'Logs | where Level in ("error", "critical")',
        'Logs | where Level !in ("error")',
        'Logs | where App =~ "ALPHA"',
        'Logs | where Message contains "refused"',
        'Logs | where Message contains_cs "Refused"',
        'Logs | where Message startswith "conn"',
        'Logs | where Message endswith "up"',
        'Logs | where Message has "segfault"',
        'Logs | where Message !has "segfault"',
        "Logs | where isnull(Timestamp)",
        "Logs | where isnotempty(Message)",
        "Logs | where Timestamp > datetime(2026-09-20 12:10:00)",
        "Logs | where Timestamp between (datetime(2026-09-20 12:00:00) .. "
        "datetime(2026-09-20 12:20:00))",
        "Logs | where Extra.pid == 101",
        "Logs | where LineNumber >= 1 and LineNumber < 99",
        "Logs | where strlen(Message) > 12",
        "Logs | summarize count() by App",
        "Logs | summarize count() by Level",
        "Logs | summarize n = count(), d = dcount(Source) by App",
        "Logs | summarize m = max(Timestamp), l = min(Timestamp) by App",
        "Logs | where isnotnull(Timestamp) | summarize count() by bin(Timestamp, 1h)",
        "Logs | count",
        "Logs | distinct App",
        "Logs | distinct Level, App",
        "Logs | project App, Level",
        "Logs | project-away Raw",
        'search "refused"',
        'Logs | where App == "alpha" | summarize count() by Level | take 2',
        "Sources | where Events > 0",
        "Sources | summarize sum(Events) by Format",
        # Parameters in the select list *and* the where clause. The builder
        # collected them in the order it walked the pipeline, which is
        # `where` first, while the statement puts the select list first — so
        # they bound backwards and the query silently returned nothing.
        'Logs | where App == "alpha" | summarize n = count(), '
        'e = countif(Level == "error") by Level',
        'Logs | where Level == "error" | summarize '
        'c = countif(Message contains "refused") by App',
        'Logs | where App == "alpha" | summarize m = max(Timestamp) by Level',
        'Logs | where Message contains "refused" | distinct App, Level',
        'Logs | where App == "alpha" | project App, Message',
        'Logs | where Level != "error" | summarize '
        's = sumif(LineNumber, App == "beta") by Level',
    )

    def test_the_planner_never_changes_an_answer(self) -> None:
        for text in self.QUERIES:
            with self.subTest(query=text):
                self.assert_same_with_and_without_pushdown(text)

    def test_the_planner_never_changes_an_answer_inside_a_time_range(self) -> None:
        window = TimeRange(start=BASE, end=BASE + timedelta(minutes=20))
        for text in self.QUERIES:
            with self.subTest(query=text):
                self.assert_same_with_and_without_pushdown(text, time_range=window)

    def test_ordered_queries_keep_their_order_either_way(self) -> None:
        for text in ("Logs | sort by LineNumber asc, Message asc",
                     "Logs | sort by Timestamp desc nulls last, Message asc",
                     "Logs | top 3 by Message asc"):
            with self.subTest(query=text):
                self.assert_same_with_and_without_pushdown(text, ordered=True)


class TestPlanQuality(HuntTestCase):
    """Pushdown is not decoration; these assert it actually happened."""

    def test_a_filter_on_a_level_reaches_sql(self) -> None:
        result = self.run_query('Logs | where Level == "error" | count')
        self.assertIn("where", result.stats.pushed_down)
        self.assertIn("count", result.stats.pushed_down)
        self.assertEqual(result.stats.evaluated, ())

    def test_a_level_literal_is_compared_as_the_stored_number(self) -> None:
        """So the index is usable. Decoding a million rows to compare strings
        would be correct and useless."""
        plan = describe_plan('Logs | where Level == "error"')
        self.assertIn("e.level", plan["sql"])
        self.assertIn(50, plan["parameters"])

    def test_take_becomes_a_limit_so_the_store_is_barely_read(self) -> None:
        result = self.run_query("Logs | take 2")
        self.assertEqual(result.stats.scanned, 2)

    def test_a_search_uses_the_text_index(self) -> None:
        plan = describe_plan('search "refused"')
        self.assertIn("events_fts", plan["sql"])

    def test_has_uses_the_text_index_too(self) -> None:
        plan = describe_plan('Logs | where Message has "segfault"')
        self.assertIn("MATCH", plan["sql"])

    def test_a_dynamic_field_becomes_json_extract(self) -> None:
        plan = describe_plan("Logs | where Extra.pid == 101")
        self.assertIn("json_extract", plan["sql"])

    def test_ago_is_worked_out_once_rather_than_per_row(self) -> None:
        plan = describe_plan("Logs | where Timestamp > ago(1h)")
        self.assertIn("e.ts >", plan["sql"])
        self.assertTrue(any(isinstance(value, int) and value > 10 ** 15
                            for value in plan["parameters"]))

    def test_a_regular_expression_is_left_to_python(self) -> None:
        plan = describe_plan(r'Logs | where Message matches regex @"\d+"')
        self.assertIn("where", plan["evaluated"])

    def test_a_half_translated_operator_does_not_leave_stray_parameters(self) -> None:
        """`summarize a = count(), b = round(avg(x))` pushes the first and then
        discovers the second has no SQL form. The rollback is what stops
        SQLite being handed one placeholder and two values."""
        result = self.run_query(
            'Logs | summarize a = count(), b = round(avg(LineNumber), 1) by App')
        self.assertEqual(len(result.rows), 3)

    def test_every_placeholder_has_exactly_one_value(self) -> None:
        """A count mismatch is caught by SQLite. An *order* mismatch is not —
        it binds the wrong value to the wrong column and answers wrongly."""
        for text in TestPushdown.QUERIES:
            with self.subTest(query=text):
                plan = describe_plan(text)
                self.assertEqual(plan["sql"].count("?"), len(plan["parameters"]),
                                 plan["sql"])

    def test_parameters_are_bound_in_the_order_they_appear(self) -> None:
        """Checked positionally: the nth placeholder in the statement must be
        the nth bound value."""
        plan = describe_plan('Logs | where App == "alpha" | summarize '
                             'e = countif(Level == "error") by Level')
        select, _, where = plan["sql"].partition("WHERE")
        self.assertEqual(select.count("?"), 1, "one parameter in the select list")
        self.assertEqual(where.count("?"), 1, "one parameter in the where clause")
        # The level literal is encoded to its stored integer; the app is text.
        self.assertEqual(plan["parameters"][0], 50)
        self.assertEqual(plan["parameters"][1], "alpha")

    def test_a_group_key_is_not_repeated_in_the_group_by(self) -> None:
        """Repeating it would bind any parameter it carries twice."""
        plan = describe_plan("Logs | summarize count() by App")
        self.assertIn("GROUP BY 1", plan["sql"])

    def test_sorting_by_an_aggregate_uses_its_name_not_its_expression(self) -> None:
        plan = describe_plan('Logs | summarize e = countif(Level == "error") '
                             "by App | sort by e desc")
        self.assertIn('ORDER BY "e"', plan["sql"])
        self.assertEqual(plan["sql"].count("CASE WHEN"), 1)

    def test_the_generated_sql_only_ever_reads(self) -> None:
        for text in TestPushdown.QUERIES:
            with self.subTest(query=text):
                sql = describe_plan(text)["sql"].upper()
                for forbidden in ("INSERT", "UPDATE", "DELETE", "DROP",
                                  "ALTER", "ATTACH", "PRAGMA", "CREATE"):
                    self.assertNotIn(forbidden, sql)


class TestLimitsAndErrors(HuntTestCase):
    def test_a_result_larger_than_the_limit_is_truncated_and_says_so(self) -> None:
        result = self.run_query("Logs", row_limit=4)
        self.assertEqual(len(result.rows), 4)
        self.assertTrue(result.stats.truncated)
        self.assertIn("4 rows", result.stats.note)

    def test_an_unknown_table_suggests_a_real_one(self) -> None:
        with self.assertRaises(KqlError) as caught:
            self.rows("Log | take 1")
        self.assertIn("Logs", caught.exception.hint)

    def test_an_unknown_column_lists_what_is_available(self) -> None:
        with self.assertRaises(KqlError) as caught:
            self.rows("Logs | where Levl == 1")
        self.assertIn("Level", caught.exception.hint)

    def test_an_unknown_column_after_a_summarize_names_the_new_shape(self) -> None:
        with self.assertRaises(KqlError) as caught:
            self.rows("Logs | summarize n = count() by App | where Message == 'x'")
        self.assertIn("App, n", caught.exception.hint)

    def test_a_query_error_carries_a_position_the_editor_can_underline(self) -> None:
        error = check("Logs | where Levl == 1")
        self.assertIsNotNone(error)
        self.assertGreater(error.position, 0)
        self.assertEqual(error.length, len("Levl"))


class TestCheckingWithoutRunning(unittest.TestCase):
    """What the editor calls on every pause. It must touch no data."""

    def test_a_good_query_checks_clean(self) -> None:
        for text in ('Logs | where Level == "error" | summarize count() by App',
                     "Logs | project Timestamp | sort by Timestamp desc | take 5",
                     "let f = (x: long) { x * 2 }; Logs | take 1 "
                     "| project n = f(LineNumber)",
                     'search "x" | count',
                     "union Logs, Sources | count"):
            with self.subTest(text=text):
                self.assertIsNone(check(text), text)

    def test_the_column_list_flows_through_the_pipeline(self) -> None:
        self.assertIsNone(check("Logs | project a = App | where a == 'x'"))
        self.assertIsNotNone(check("Logs | project a = App | where App == 'x'"))

    def test_an_empty_query_is_not_an_error_to_shout_about(self) -> None:
        self.assertIsNotNone(check(""))


class TestTypes(HuntTestCase):
    def test_a_computed_column_gets_the_type_of_its_values(self) -> None:
        result = self.run_query("Logs | take 3 | extend n = strlen(Message)")
        self.assertIs(result.column("n").type, ColumnType.LONG)

    def test_a_duration_is_a_timespan(self) -> None:
        result = self.run_query("Logs | where isnotnull(Timestamp) | take 2 "
                                "| extend d = Timestamp - datetime(2026-09-20)")
        self.assertIs(result.column("d").type, ColumnType.TIMESPAN)

    def test_a_projected_column_keeps_its_declared_type(self) -> None:
        result = self.run_query("Logs | project Timestamp | take 1")
        self.assertIs(result.column("Timestamp").type, ColumnType.DATETIME)


if __name__ == "__main__":
    unittest.main()
