"""The function library, one behaviour at a time.

Also two properties of the library as a whole: everything in it is
documented, because the left rail lists it and an undocumented function is an
unusable one; and everything in it survives a null, because half the columns
in a log store are null half the time.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from .hunt_support import print_query
from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt.kql import KqlError  # noqa: E402
from clamguard.core.hunt.kql import functions as fn  # noqa: E402
from clamguard.core.hunt.kql import values as V  # noqa: E402


def value(expression: str):
    """Evaluate one scalar expression with no data behind it."""
    return print_query(f"print x = {expression}").rows[0][0]


class TestStrings(unittest.TestCase):
    def test_joining(self) -> None:
        self.assertEqual(value('strcat("a", "b", 1)'), "ab1")
        self.assertEqual(value('strcat_delim("-", "a", "b")'), "a-b")

    def test_length_counts_characters_and_size_counts_bytes(self) -> None:
        self.assertEqual(value('strlen("café")'), 4)
        self.assertEqual(value('string_size("café")'), 5)

    def test_substring_counts_from_zero(self) -> None:
        self.assertEqual(value('substring("abcdef", 0, 3)'), "abc")
        self.assertEqual(value('substring("abcdef", 3)'), "def")
        self.assertEqual(value('substring("abcdef", -2)'), "ef")

    def test_case_changes(self) -> None:
        self.assertEqual(value('toupper("aB")'), "AB")
        self.assertEqual(value('tolower("aB")'), "ab")

    def test_splitting(self) -> None:
        self.assertEqual(value('split("a/b/c", "/")'), ["a", "b", "c"])
        self.assertEqual(value('split("a/b/c", "/", -1)'), "c")
        self.assertIsNone(value('split("a", "/", 9)'))

    def test_replacing_plain_text_and_patterns(self) -> None:
        self.assertEqual(value('replace_string("a-b-c", "-", "+")'), "a+b+c")
        self.assertEqual(value(r'replace_regex("id 123 and 45", @"\d+", "N")'),
                         "id N and N")

    def test_a_broken_pattern_leaves_the_text_alone(self) -> None:
        self.assertEqual(value(r'replace_regex("abc", @"(unclosed", "x")'), "abc")

    def test_extracting_a_capture_group(self) -> None:
        self.assertEqual(value(r'extract(@"pid=(\d+)", 1, "pid=123 x")'), "123")
        self.assertIsNone(value(r'extract(@"pid=(\d+)", 1, "nothing")'))

    def test_extracting_every_match(self) -> None:
        self.assertEqual(value(r'extract_all(@"\d+", "a1 b22 c333")'),
                         ["1", "22", "333"])

    def test_indexof_and_countof(self) -> None:
        self.assertEqual(value('indexof("hello", "ll")'), 2)
        self.assertEqual(value('indexof("hello", "z")'), -1)
        self.assertEqual(value('countof("aXbXc", "X")'), 2)
        self.assertEqual(value(r'countof("a1b22", @"\d+", "regex")'), 2)

    def test_trimming(self) -> None:
        self.assertEqual(value('trim("  x  ")'), "x")
        self.assertEqual(value(r'trim_start(@"\s+", "  x")'), "x")

    def test_urls_and_base64(self) -> None:
        self.assertEqual(value('url_decode("a%20b")'), "a b")
        self.assertEqual(value('base64_encode_tostring("hi")'), "aGk=")
        self.assertEqual(value('base64_decode_tostring("aGk=")'), "hi")

    def test_base64_that_is_not_base64_is_null_rather_than_rubbish(self) -> None:
        self.assertIsNone(value('base64_decode_tostring("!!!!")'))

    def test_parse_url_breaks_an_address_apart(self) -> None:
        parts = value('parse_url("https://a.test:8080/x?y=1")')
        self.assertEqual(parts["Host"], "a.test")
        self.assertEqual(parts["Port"], 8080)
        self.assertEqual(parts["Query Parameters"], {"y": "1"})

    def test_a_malformed_url_from_a_log_line_does_not_raise(self) -> None:
        """`.port` parses the authority and throws on rubbish, and a URL
        lifted out of a log line is frequently rubbish."""
        parts = value('parse_url("https://api.test:user:profile/v1")')
        self.assertIsNotNone(parts)

    def test_parse_path_breaks_a_path_apart(self) -> None:
        parts = value('parse_path("/home/x/.config/app/main.log")')
        self.assertEqual(parts["Filename"], "main.log")
        self.assertEqual(parts["Extension"], "log")

    def test_the_clamguard_extensions(self) -> None:
        self.assertEqual(value('basename("/a/b/c.log")'), "c.log")
        self.assertEqual(value('dirname("/a/b/c.log")'), "/a/b")
        self.assertGreater(value('entropy("aGVsbG8gd29ybGQgdGhpcw==")'), 3.5)
        self.assertLess(value('entropy("aaaaaaaaaaaa")'), 0.5)

    def test_the_extensions_are_labelled_as_not_kusto(self) -> None:
        for name in ("basename", "dirname", "entropy"):
            with self.subTest(name=name):
                self.assertTrue(fn.SCALARS[name].extension)


class TestNumbers(unittest.TestCase):
    def test_rounding(self) -> None:
        self.assertEqual(value("round(3.14159, 2)"), 3.14)
        self.assertEqual(value("round(3.7)"), 4)
        self.assertEqual(value("floor(3.7)"), 3)
        self.assertEqual(value("ceiling(3.2)"), 4)

    def test_bin_rounds_down_to_a_multiple(self) -> None:
        self.assertEqual(value("bin(17, 5)"), 15)
        self.assertEqual(value("bin(-3, 5)"), -5)

    def test_bin_on_a_datetime_takes_a_timespan(self) -> None:
        result = value("bin(datetime(2026-09-21 14:47:00), 1h)")
        self.assertEqual(result.hour, 14)
        self.assertEqual(result.minute, 0)

    def test_bin_at_aligns_to_a_point_you_choose(self) -> None:
        result = value("bin_at(datetime(2026-09-21 14:47:00), 1d, "
                       "datetime(2026-09-21 06:00:00))")
        self.assertEqual(result.hour, 6)

    def test_max_of_and_min_of(self) -> None:
        self.assertEqual(value("max_of(1, 9, 3)"), 9)
        self.assertEqual(value("min_of(1, 9, 3)"), 1)

    def test_bitwise_operations(self) -> None:
        self.assertEqual(value("binary_and(12, 10)"), 8)
        self.assertEqual(value("binary_or(12, 10)"), 14)
        self.assertEqual(value("binary_xor(12, 10)"), 6)
        self.assertEqual(value("bitset_count_ones(7)"), 3)

    def test_division_by_zero_is_null_rather_than_a_crash(self) -> None:
        self.assertIsNone(value("1 / 0"))
        self.assertIsNone(value("1 % 0"))

    def test_integer_division_stays_integer_as_kusto_does(self) -> None:
        self.assertEqual(value("7 / 2"), 3)
        self.assertEqual(value("7.0 / 2"), 3.5)

    def test_hexadecimal_output(self) -> None:
        self.assertEqual(value("tohex(255)"), "ff")
        self.assertEqual(value("tohex(255, 4)"), "00ff")


class TestTimes(unittest.TestCase):
    def test_ago_is_before_now(self) -> None:
        self.assertLess(value("ago(1h)"), value("now()"))

    def test_adding_and_subtracting(self) -> None:
        self.assertEqual(value('datetime_add("day", 1, datetime(2026-09-21))').day, 22)
        self.assertEqual(value('datetime_add("month", 1, datetime(2026-01-31))').month, 2)
        self.assertEqual(value('datetime_add("year", 1, datetime(2026-09-21))').year, 2027)

    def test_differences_in_whole_units(self) -> None:
        self.assertEqual(value('datetime_diff("day", datetime(2026-09-21), '
                               "datetime(2026-09-20))"), 1)
        self.assertEqual(value('datetime_diff("hour", datetime(2026-09-21 12:00), '
                               "datetime(2026-09-21 09:00))"), 3)

    def test_boundaries(self) -> None:
        self.assertEqual(value("startofday(datetime(2026-09-21 14:00))").hour, 0)
        self.assertEqual(value("startofmonth(datetime(2026-09-21))").day, 1)
        self.assertEqual(value("startofyear(datetime(2026-09-21))").month, 1)
        self.assertEqual(value("endofday(datetime(2026-09-21))").hour, 23)

    def test_a_week_starts_on_sunday_as_kusto_says(self) -> None:
        self.assertEqual(value("startofweek(datetime(2026-09-21))").weekday(), 6)

    def test_parts_of_a_time(self) -> None:
        self.assertEqual(value("hourofday(datetime(2026-09-21 14:30))"), 14)
        self.assertEqual(value("getyear(datetime(2026-09-21))"), 2026)
        self.assertEqual(value("dayofmonth(datetime(2026-09-21))"), 21)

    def test_dayofweek_is_a_timespan_as_kusto_says(self) -> None:
        self.assertEqual(value("dayofweek(datetime(2026-09-20))"), timedelta(days=0))

    def test_formatting(self) -> None:
        self.assertEqual(
            value('format_datetime(datetime(2026-09-21 14:30:05), "yyyy-MM-dd HH:mm")'),
            "2026-09-21 14:30")
        self.assertEqual(
            value('format_datetime(datetime(2026-09-21 14:30:05), "dd/MM/yy")'),
            "21/09/26")

    def test_unix_timestamps_convert_at_each_resolution(self) -> None:
        for name, number in (("seconds", 1758369600),
                             ("milliseconds", 1758369600000),
                             ("microseconds", 1758369600000000)):
            with self.subTest(unit=name):
                found = value(f"unixtime_{name}_todatetime({number})")
                self.assertEqual(found.year, 2025)

    def test_building_a_time_from_parts(self) -> None:
        self.assertEqual(value("make_datetime(2026, 9, 21, 14, 30, 5)").minute, 30)
        self.assertEqual(value("make_timespan(1, 30)"), timedelta(minutes=90))

    def test_datetime_arithmetic(self) -> None:
        self.assertEqual(value("datetime(2026-09-21) - datetime(2026-09-20)"),
                         timedelta(days=1))
        self.assertEqual(value("datetime(2026-09-21) + 1d").day, 22)


class TestDynamic(unittest.TestCase):
    def test_array_operations(self) -> None:
        self.assertEqual(value("array_length(dynamic([1, 2, 3]))"), 3)
        self.assertEqual(value("array_index_of(dynamic([1, 2, 3]), 2)"), 1)
        self.assertEqual(value("array_slice(dynamic([1, 2, 3, 4]), 1, 2)"), [2, 3])
        self.assertEqual(value("array_sum(dynamic([1, 2, 3]))"), 6)
        self.assertEqual(value("array_sort_asc(dynamic([3, 1, 2]))"), [1, 2, 3])

    def test_set_operations(self) -> None:
        self.assertEqual(value("set_union(dynamic([1, 2]), dynamic([2, 3]))"),
                         [1, 2, 3])
        self.assertEqual(value("set_intersect(dynamic([1, 2]), dynamic([2, 3]))"),
                         [2])
        self.assertEqual(value("set_difference(dynamic([1, 2]), dynamic([2]))"), [1])
        self.assertTrue(value("set_has_element(dynamic([1, 2]), 2)"))

    def test_bags(self) -> None:
        self.assertEqual(value('bag_keys(dynamic({"a": 1, "b": 2}))'), ["a", "b"])
        self.assertTrue(value('bag_has_key(dynamic({"a": 1}), "a")'))
        self.assertEqual(value('pack("a", 1, "b", 2)'), {"a": 1, "b": 2})
        self.assertEqual(value("pack_array(1, 2)"), [1, 2])

    def test_parse_json_reads_a_string(self) -> None:
        self.assertEqual(value('parse_json(\'{"a": 1}\').a'), 1)

    def test_member_access_reaches_into_nesting(self) -> None:
        self.assertEqual(value('dynamic({"a": {"b": 7}}).a.b'), 7)

    def test_a_missing_member_is_null_not_an_error(self) -> None:
        self.assertIsNone(value('dynamic({"a": 1}).nothing'))
        self.assertIsNone(value("dynamic([1, 2])[9]"))


class TestConditional(unittest.TestCase):
    def test_iif_picks_a_branch(self) -> None:
        self.assertEqual(value('iif(1 == 1, "yes", "no")'), "yes")
        self.assertEqual(value('iff(1 == 2, "yes", "no")'), "no")

    def test_iif_does_not_evaluate_the_branch_it_did_not_choose(self) -> None:
        """Otherwise `iif(x != 0, 1 / x, 0)` fails on the rows it was written
        to protect."""
        self.assertEqual(value("iif(false, 1 / 0, 42)"), 42)

    def test_case_takes_the_first_true_branch(self) -> None:
        self.assertEqual(value('case(false, "a", true, "b", "c")'), "b")
        self.assertEqual(value('case(false, "a", false, "b", "c")'), "c")

    def test_coalesce_takes_the_first_thing_there(self) -> None:
        self.assertEqual(value('coalesce("", "", "x")'), "x")
        self.assertIsNone(value("coalesce(null, null)"))

    def test_emptiness_and_nullness(self) -> None:
        self.assertTrue(value('isempty("")'))
        self.assertTrue(value("isnull(null)"))
        self.assertTrue(value('isnotempty("x")'))
        self.assertFalse(value('isnull("")'))


class TestTypes(unittest.TestCase):
    def test_conversions(self) -> None:
        self.assertEqual(value('tolong("42")'), 42)
        self.assertEqual(value('todouble("4.5")'), 4.5)
        self.assertEqual(value("tostring(42)"), "42")
        self.assertTrue(value('tobool("true")'))

    def test_a_conversion_that_cannot_work_is_null(self) -> None:
        self.assertIsNone(value('tolong("banana")'))
        self.assertIsNone(value('todatetime("banana")'))

    def test_gettype_names_the_type(self) -> None:
        self.assertEqual(value('gettype("x")'), "string")
        self.assertEqual(value("gettype(1)"), "long")
        self.assertEqual(value("gettype(1.5)"), "real")
        self.assertEqual(value("gettype(datetime(2026-01-01))"), "datetime")
        self.assertEqual(value("gettype(dynamic([1]))"), "dynamic")
        self.assertEqual(value("gettype(null)"), "null")


class TestHashes(unittest.TestCase):
    def test_sha256_matches_the_standard(self) -> None:
        self.assertEqual(
            value('hash_sha256("abc")'),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_the_fast_hash_buckets(self) -> None:
        self.assertIsInstance(value('hash("x", 10)'), int)
        self.assertLess(value('hash("x", 10)'), 10)


class TestAddresses(unittest.TestCase):
    def test_private_ranges_are_recognised(self) -> None:
        for address in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"):
            with self.subTest(address=address):
                self.assertTrue(value(f'ipv4_is_private("{address}")'))
        self.assertFalse(value('ipv4_is_private("93.184.216.34")'))

    def test_cidr_ranges(self) -> None:
        self.assertTrue(value('ipv4_is_in_range("10.1.2.3", "10.0.0.0/8")'))
        self.assertFalse(value('ipv4_is_in_range("11.1.2.3", "10.0.0.0/8")'))

    def test_prefix_matching(self) -> None:
        self.assertTrue(value('ipv4_is_match("10.1.2.3", "10.1.9.9", 16)'))
        self.assertFalse(value('ipv4_is_match("10.1.2.3", "10.9.9.9", 16)'))

    def test_something_that_is_not_an_address_is_null(self) -> None:
        self.assertIsNone(value('ipv4_is_private("not an address")'))


class TestNullSafety(unittest.TestCase):
    def test_every_single_argument_function_survives_a_null(self) -> None:
        """Half the columns in a log store are null half the time."""
        skip = {"now", "rand"}
        for name, function in sorted(fn.SCALARS.items()):
            if name in skip or function.min_args > 1:
                continue
            with self.subTest(function=name):
                try:
                    function.call(None)
                except Exception as error:  # noqa: BLE001 - that is the assertion
                    self.fail(f"{name}(null) raised {error!r}")

    def test_arithmetic_with_a_null_is_null(self) -> None:
        for expression in ("null + 1", "1 - null", "null * 2", "null / 2"):
            with self.subTest(expression=expression):
                self.assertIsNone(value(expression))

    def test_a_comparison_with_a_null_is_false_not_an_error(self) -> None:
        self.assertIsNone(V.compare(None, 1))
        self.assertIsNone(V.equal(None, None))


class TestTheLibraryAsAWhole(unittest.TestCase):
    def test_everything_has_a_signature_and_a_summary(self) -> None:
        for name, function in fn.SCALARS.items():
            with self.subTest(function=name):
                self.assertTrue(function.signature, name)
                self.assertTrue(function.summary, name)
                self.assertTrue(function.category, name)

    def test_every_aggregate_has_a_signature_and_a_summary(self) -> None:
        for name, aggregation in fn.AGGREGATES.items():
            with self.subTest(aggregate=name):
                self.assertTrue(aggregation.signature, name)
                self.assertTrue(aggregation.summary, name)

    def test_a_signature_names_the_function_it_belongs_to(self) -> None:
        for name, function in fn.SCALARS.items():
            with self.subTest(function=name):
                self.assertTrue(function.signature.startswith(name + "("),
                                f"{name}: {function.signature}")

    def test_no_name_is_both_a_scalar_and_an_aggregate(self) -> None:
        """`summarize` lifts aggregates out of expressions by name, so an
        overlap would make one of the two unreachable."""
        self.assertEqual(set(fn.SCALARS) & set(fn.AGGREGATES), set())

    def test_the_wrong_number_of_arguments_is_explained(self) -> None:
        with self.assertRaises(KqlError) as caught:
            value("strlen()")
        self.assertIn("takes 1", caught.exception.message)
        self.assertIn("strlen(text)", caught.exception.hint)

    def test_an_aggregate_used_as_a_scalar_says_where_it_belongs(self) -> None:
        with self.assertRaises(KqlError) as caught:
            value("count()")
        self.assertIn("summarize", caught.exception.hint)

    def test_a_misspelling_is_suggested_against(self) -> None:
        with self.assertRaises(KqlError) as caught:
            value('strlenn("x")')
        self.assertIn("strlen", caught.exception.hint)

    def test_a_runaway_regular_expression_is_refused_by_length(self) -> None:
        with self.assertRaises(KqlError):
            fn.compile_pattern("a" * (fn.MAX_PATTERN + 1))

    def test_an_invalid_regular_expression_explains_itself(self) -> None:
        with self.assertRaises(KqlError) as caught:
            fn.compile_pattern("(unclosed")
        self.assertIn("not valid", caught.exception.message)

    def test_the_categories_cover_everything(self) -> None:
        grouped = fn.categories()
        self.assertEqual(sum(len(items) for items in grouped.values()),
                         len(fn.SCALARS))


class TestAggregateAccumulators(unittest.TestCase):
    def feed(self, name: str, rows) -> object:
        accumulator = fn.AGGREGATES[name].factory()
        for row in rows:
            accumulator.add(row if isinstance(row, tuple) else (row,))
        return accumulator.result()

    def test_count_and_sum(self) -> None:
        self.assertEqual(self.feed("count", [1, 2, 3]), 3)
        self.assertEqual(self.feed("sum", [1, 2, 3]), 6)
        self.assertEqual(self.feed("avg", [1, 2, 3]), 2)

    def test_nulls_are_skipped_rather_than_counted_as_zero(self) -> None:
        self.assertEqual(self.feed("avg", [1, None, 3]), 2)
        self.assertEqual(self.feed("sum", [1, None, 3]), 4)

    def test_dcount_is_exact(self) -> None:
        self.assertEqual(self.feed("dcount", ["a", "b", "a", None]), 2)

    def test_min_and_max_over_mixed_types_do_not_raise(self) -> None:
        self.assertIsNotNone(self.feed("max", [1, "a", None, 3]))

    def test_make_list_is_capped_so_one_cell_cannot_hold_a_million_rows(self) -> None:
        result = self.feed("make_list", list(range(5000)))
        self.assertEqual(len(result), fn.AGGREGATES["make_list"].factory().DEFAULT_LIMIT)

    def test_percentile_uses_nearest_rank(self) -> None:
        rows = [(value, 50) for value in range(1, 101)]
        self.assertEqual(self.feed("percentile", rows), 50)

    def test_stdev_of_one_value_is_null_rather_than_zero(self) -> None:
        self.assertIsNone(self.feed("stdev", [5]))
        self.assertAlmostEqual(self.feed("stdev", [2, 4, 4, 4, 5, 5, 7, 9]),
                               2.138, places=3)

    def test_an_empty_group_gives_a_sensible_answer(self) -> None:
        self.assertEqual(self.feed("count", []), 0)
        self.assertIsNone(self.feed("avg", []))
        self.assertEqual(self.feed("make_list", []), [])


if __name__ == "__main__":
    unittest.main()
