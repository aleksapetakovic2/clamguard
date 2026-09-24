"""Every shipped query and rule, parsed and run.

These are the tests that protect the user-facing surface. A change to the
parser or the function library that breaks one of the forty queries in the
left rail breaks the build here rather than in front of somebody hunting.
"""

from __future__ import annotations

import unittest

from .hunt_support import HuntTestCase
from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt import library, rules  # noqa: E402
from clamguard.core.hunt.kql import KqlError, parse  # noqa: E402
from clamguard.core.hunt.kql.engine import check  # noqa: E402
from clamguard.core.hunt.model import TimeRange  # noqa: E402


class TestTheLibrary(unittest.TestCase):
    def test_there_is_a_useful_number_of_them(self) -> None:
        self.assertGreater(len(library.LIBRARY), 25)

    def test_every_entry_is_described_and_categorised(self) -> None:
        for item in library.LIBRARY:
            with self.subTest(query=item.id):
                self.assertTrue(item.name)
                self.assertTrue(item.description)
                self.assertIn(item.category, library.CATEGORIES)

    def test_every_identifier_is_unique(self) -> None:
        identifiers = [item.id for item in library.LIBRARY]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_every_query_parses(self) -> None:
        for item in library.LIBRARY:
            with self.subTest(query=item.id):
                try:
                    parse(item.text)
                except KqlError as error:
                    self.fail(f"{item.id}: {error.caret(item.text)}")

    def test_every_query_resolves_its_names(self) -> None:
        """Parsing is not enough: a query naming a column that does not exist
        would still parse and then fail in front of a user."""
        for item in library.LIBRARY:
            with self.subTest(query=item.id):
                error = check(item.text)
                self.assertIsNone(error, f"{item.id}: {error}")

    def test_the_starters_are_a_short_list(self) -> None:
        self.assertTrue(library.starters())
        self.assertLessEqual(len(library.starters()), 8)

    def test_searching_finds_by_name_and_by_body(self) -> None:
        self.assertTrue(library.search("error"))
        self.assertTrue(library.search("summarize"))
        self.assertEqual(library.search("zzzz-not-a-thing"), ())
        self.assertEqual(len(library.search("")), len(library.LIBRARY))

    def test_they_group_into_the_declared_categories(self) -> None:
        grouped = library.by_category()
        self.assertTrue(set(grouped).issubset(set(library.CATEGORIES)))
        self.assertEqual(sum(len(items) for items in grouped.values()),
                         len(library.LIBRARY))

    def test_a_query_can_be_fetched_by_id(self) -> None:
        self.assertIsNotNone(library.get("recent"))
        self.assertIsNone(library.get("nope"))


class TestRunningTheLibrary(HuntTestCase):
    def test_every_query_runs_against_a_real_store(self) -> None:
        for item in library.LIBRARY:
            with self.subTest(query=item.id):
                try:
                    self.run_query(item.text, time_range=TimeRange.everything(),
                                   row_limit=500)
                except KqlError as error:
                    self.fail(f"{item.id}: {error.caret(item.text)}")

    def test_every_query_gives_the_same_answer_with_and_without_pushdown(self) -> None:
        """The optimiser is allowed to be faster. It is not allowed to be
        different — least of all on the queries people actually run."""
        for item in library.LIBRARY:
            if _is_nondeterministic(item.text):
                continue
            with self.subTest(query=item.id):
                self.assert_same_with_and_without_pushdown(
                    item.text, time_range=TimeRange.everything())


#: Functions whose value depends on when the query ran, which makes running
#: the same query twice a poor test of anything. `now()` differs by half a
#: millisecond between the two runs and the comparison fails on the noise.
NONDETERMINISTIC = ("now(", "ago(", "rand(", "sample ")


def _is_nondeterministic(text: str) -> bool:
    return any(marker in text for marker in NONDETERMINISTIC)


class TestTheRules(unittest.TestCase):
    def test_every_rule_is_documented(self) -> None:
        for rule in rules.BUILT_IN:
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.title)
                self.assertTrue(rule.question)
                self.assertTrue(rule.explanation)
                self.assertTrue(rule.category)

    def test_every_identifier_is_unique(self) -> None:
        identifiers = [rule.id for rule in rules.BUILT_IN]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_every_rule_query_parses_and_resolves(self) -> None:
        for rule in rules.BUILT_IN:
            with self.subTest(rule=rule.id):
                error = check(rule.query)
                self.assertIsNone(error, f"{rule.id}: {error}")

    def test_a_count_column_a_rule_names_is_one_its_query_produces(self) -> None:
        """Otherwise the headline silently says "3 results" forever."""
        for rule in rules.BUILT_IN:
            if not rule.count_column:
                continue
            with self.subTest(rule=rule.id):
                self.assertIn(rule.count_column, rule.query,
                              f"{rule.id} names a column its query never makes")

    def test_the_risks_describe_themselves(self) -> None:
        for risk in rules.Risk:
            with self.subTest(risk=risk):
                self.assertTrue(risk.label)
                self.assertTrue(risk.tone)
                self.assertTrue(risk.icon)

    def test_risk_parses_from_the_words_a_person_writes(self) -> None:
        self.assertIs(rules.Risk.parse("HIGH"), rules.Risk.HIGH)
        self.assertIs(rules.Risk.parse("critical"), rules.Risk.HIGH)
        self.assertIs(rules.Risk.parse("moderate"), rules.Risk.MEDIUM)
        self.assertIs(rules.Risk.parse("nonsense"), rules.Risk.LOW)

    def test_has_is_not_used_where_punctuation_matters(self) -> None:
        """`has_any("| sh")` is really `has_any("sh")`, because `has` throws
        punctuation away. It matched every pacman line mentioning python."""
        for rule in rules.BUILT_IN:
            with self.subTest(rule=rule.id):
                for fragment in ('has_any ("|', 'has_any("|', 'has ("|'):
                    self.assertNotIn(fragment, rule.query)
                self.assertNotIn('has_any (".', rule.query)


class TestRunningTheRules(HuntTestCase):
    def test_every_rule_runs_against_a_real_store(self) -> None:
        from clamguard.core.hunt.kql.engine import Options

        catalogue, problems = rules.catalogue(self.tmp / "no-rules")
        self.assertEqual(problems, [])
        with self.store.read_only(attach={'history': self.history}) as connection:
            review = rules.evaluate(
                catalogue, connection,
                options=Options(time_range=TimeRange.everything(), row_limit=100))
        self.assertEqual(review.failed, [], [item.error for item in review.failed])
        self.assertEqual(review.checked, len(catalogue))

    def test_the_seeded_shell_pipeline_is_found(self) -> None:
        """The fixture contains one `curl … | sh` line, and the rule that
        exists to find it must find it."""
        from clamguard.core.hunt.kql.engine import Options

        rule = next(item for item in rules.BUILT_IN if item.id == "shell-pipeline")
        with self.store.read_only(attach={'history': self.history}) as connection:
            review = rules.evaluate(
                [rule], connection,
                options=Options(time_range=TimeRange.everything()))
        self.assertEqual(len(review.fired), 1)
        self.assertEqual(review.fired[0].rows, 1)

    def test_a_review_summarises_itself(self) -> None:
        from clamguard.core.hunt.kql.engine import Options

        with self.store.read_only(attach={'history': self.history}) as connection:
            review = rules.evaluate(
                rules.BUILT_IN, connection,
                options=Options(time_range=TimeRange.everything()))
        self.assertIn("rules", review.summary())
        self.assertTrue(review.quiet)

    def test_one_broken_rule_does_not_cost_the_others(self) -> None:
        from clamguard.core.hunt.kql.engine import Options

        broken = rules.Rule(id="broken", title="Broken", question="?",
                            query="Logs | wher nonsense", custom=True)
        good = next(item for item in rules.BUILT_IN if item.id == "error-storm")
        with self.store.read_only(attach={'history': self.history}) as connection:
            review = rules.evaluate([broken, good], connection,
                                    options=Options(time_range=TimeRange.everything()))
        self.assertEqual(len(review.failed), 1)
        self.assertEqual(review.checked, 2)

    def test_a_review_can_be_stopped(self) -> None:
        from clamguard.core.hunt.kql.engine import Options

        with self.store.read_only(attach={'history': self.history}) as connection:
            review = rules.evaluate(rules.BUILT_IN, connection,
                                    options=Options(time_range=TimeRange.everything()),
                                    should_stop=lambda: True)
        self.assertEqual(review.checked, 0)


class TestUserRules(HuntTestCase):
    def directory(self):
        folder = self.tmp / "rules.d"
        folder.mkdir(exist_ok=True)
        return folder

    def write(self, name: str, body: str):
        path = self.directory() / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_a_well_formed_rule_loads(self) -> None:
        self.write("mine.json", '{"id": "mine", "title": "Mine", '
                                '"query": "Logs | count", "risk": "high"}')
        found, problems = rules.load_custom(self.directory())
        self.assertEqual(problems, [])
        self.assertEqual(found[0].id, "mine")
        self.assertIs(found[0].risk, rules.Risk.HIGH)
        self.assertTrue(found[0].custom)

    def test_a_list_of_rules_in_one_file_loads(self) -> None:
        self.write("many.json",
                   '[{"id": "a", "title": "A", "query": "Logs | count"},'
                   ' {"id": "b", "title": "B", "query": "Logs | count"}]')
        found, _problems = rules.load_custom(self.directory())
        self.assertEqual(len(found), 2)

    def test_a_missing_field_is_named(self) -> None:
        self.write("bad.json", '{"id": "x"}')
        _found, problems = rules.load_custom(self.directory())
        self.assertIn("'title'", problems[0])
        self.assertIn("'query'", problems[0])

    def test_a_hostile_identifier_is_refused(self) -> None:
        self.write("bad.json", '{"id": "../../etc", "title": "t", '
                               '"query": "Logs"}')
        _found, problems = rules.load_custom(self.directory())
        self.assertIn("not a usable id", problems[0])

    def test_broken_json_names_the_file(self) -> None:
        self.write("broken.json", "{{{")
        _found, problems = rules.load_custom(self.directory())
        self.assertIn("broken.json", problems[0])

    def test_one_broken_file_does_not_hide_a_good_one(self) -> None:
        self.write("broken.json", "{{{")
        self.write("good.json", '{"id": "g", "title": "G", "query": "Logs"}')
        found, problems = rules.load_custom(self.directory())
        self.assertEqual(len(found), 1)
        self.assertEqual(len(problems), 1)

    def test_a_user_rule_overrides_a_built_in_one_with_the_same_id(self) -> None:
        self.write("override.json",
                   '{"id": "error-storm", "title": "Mine instead", '
                   '"query": "Logs | count"}')
        catalogue, _problems = rules.catalogue(self.directory())
        found = next(item for item in catalogue if item.id == "error-storm")
        self.assertEqual(found.title, "Mine instead")

    def test_an_absent_directory_is_not_an_error(self) -> None:
        found, problems = rules.load_custom(self.tmp / "nowhere")
        self.assertEqual((found, problems), ([], []))

    def test_the_example_and_its_readme_are_written(self) -> None:
        rules.write_example(self.directory())
        self.assertTrue((self.directory() / "example.json").is_file())
        readme = (self.directory() / "README.txt").read_text()
        self.assertIn("cannot run a command", readme)

    def test_the_written_example_is_itself_a_valid_rule(self) -> None:
        rules.write_example(self.directory())
        found, problems = rules.load_custom(self.directory())
        self.assertEqual(problems, [])
        self.assertIsNone(check(found[0].query))


if __name__ == "__main__":
    unittest.main()
