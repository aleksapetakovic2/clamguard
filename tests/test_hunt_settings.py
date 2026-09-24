"""Hunt's settings and its saved queries — both JSON, both hand-editable.

The contract both share with the rest of ClamGuard: a broken file degrades to
the defaults with a warning rather than taking the page down.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt.model import TimeRange  # noqa: E402
from clamguard.core.hunt.saved import QueryStore  # noqa: E402
from clamguard.core.hunt.settings import (  # noqa: E402
    DEFAULT_ENABLED,
    HuntSettings,
)


class SettingsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-hunt-settings-"))
        self.path = self.tmp / "hunt.json"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def settings(self) -> HuntSettings:
        return HuntSettings(self.path)


class TestSettings(SettingsTestCase):
    def test_a_fresh_installation_has_sensible_defaults(self) -> None:
        found = self.settings()
        self.assertTrue(found.use_full_text)
        self.assertGreater(found.max_events, 0)
        self.assertIn("config", found.roots)

    def test_the_sensitive_roots_are_off(self) -> None:
        """Shell history is the most sensitive file in a home directory."""
        found = self.settings()
        self.assertFalse(found.roots["shell"])
        self.assertFalse(found.roots["tmp"])
        self.assertNotIn("shell", DEFAULT_ENABLED)

    def test_changes_survive_a_restart(self) -> None:
        found = self.settings()
        found.roots["cache"] = False
        found.max_age_days = 7
        found.time_range = TimeRange.rolling(timedelta(hours=6), "Last 6 hours")
        found.save()

        reloaded = self.settings()
        self.assertFalse(reloaded.roots["cache"])
        self.assertEqual(reloaded.max_age_days, 7)
        self.assertEqual(reloaded.time_range.last, timedelta(hours=6))

    def test_a_broken_file_falls_back_to_the_defaults(self) -> None:
        self.path.write_text("{not json")
        self.assertTrue(self.settings().use_full_text)

    def test_a_json_array_instead_of_an_object_is_ignored(self) -> None:
        self.path.write_text("[1, 2, 3]")
        self.assertGreater(self.settings().max_events, 0)

    def test_an_unknown_root_in_the_file_is_dropped(self) -> None:
        self.path.write_text(json.dumps({"roots": {"imaginary": True,
                                                   "cache": False}}))
        found = self.settings()
        self.assertNotIn("imaginary", found.roots)
        self.assertFalse(found.roots["cache"])

    def test_an_absurd_number_is_clamped_rather_than_obeyed(self) -> None:
        self.path.write_text(json.dumps({"row_limit": 10 ** 12,
                                         "query_timeout": -5}))
        found = self.settings()
        self.assertLessEqual(found.row_limit, 5_000_000)
        self.assertGreaterEqual(found.query_timeout, 1)

    def test_a_non_numeric_limit_is_ignored(self) -> None:
        self.path.write_text(json.dumps({"max_events": "lots"}))
        self.assertIsInstance(self.settings().max_events, int)

    def test_zero_means_no_limit_and_is_kept(self) -> None:
        self.path.write_text(json.dumps({"max_events": 0, "max_age_days": 0}))
        found = self.settings()
        self.assertEqual(found.retention().max_events, 0)
        self.assertEqual(found.retention().describe(), "2048 MB")

    def test_the_enabled_roots_come_back_as_root_objects(self) -> None:
        found = self.settings()
        identifiers = [root.id for root in found.enabled_roots()]
        self.assertIn("config", identifiers)
        self.assertNotIn("shell", identifiers)

    def test_a_directory_the_user_added_becomes_a_root(self) -> None:
        extra = self.tmp / "extra"
        extra.mkdir()
        found = self.settings()
        found.extra_roots = [str(extra)]
        self.assertIn(str(extra), [str(root.path) for root in found.enabled_roots()])

    def test_a_directory_that_is_not_there_is_quietly_skipped(self) -> None:
        found = self.settings()
        found.extra_roots = [str(self.tmp / "nowhere")]
        self.assertEqual(len([root for root in found.enabled_roots()
                              if root.id.startswith("custom")]), 0)

    def test_the_journal_is_off_until_it_is_asked_for(self) -> None:
        """A different kind of source — a command, not a file — and on a real
        machine ten times larger than everything else put together."""
        self.assertFalse(self.settings().journal_enabled)

    def test_journal_settings_survive_a_restart(self) -> None:
        found = self.settings()
        found.journal_enabled = True
        found.journal_window = "7d"
        found.journal_priority = "warning"
        found.journal_include_user = False
        found.save()
        reloaded = self.settings()
        self.assertTrue(reloaded.journal_enabled)
        self.assertEqual(reloaded.journal_window, "7d")
        self.assertEqual(reloaded.journal_priority, "warning")
        self.assertFalse(reloaded.journal_include_user)

    def test_a_journal_window_that_is_not_one_of_the_choices_is_dropped(self) -> None:
        """These end up on a command line, so they are enums, not text."""
        self.path.write_text(json.dumps({
            "journal_window": "; rm -rf /", "journal_priority": "--vacuum-time=1s"}))
        found = self.settings()
        self.assertEqual(found.journal_window, "boot")
        self.assertEqual(found.journal_priority, "all")

    def test_an_absurd_journal_cap_is_clamped(self) -> None:
        self.path.write_text(json.dumps({"journal_max_entries": 10 ** 12}))
        self.assertLessEqual(self.settings().journal_max_entries, 20_000_000)

    def test_the_options_it_builds_are_already_normalised(self) -> None:
        found = self.settings()
        found.journal_window = "nonsense"
        self.assertEqual(found.journal_options().window, "boot")

    def test_the_summary_says_when_the_journal_is_on(self) -> None:
        found = self.settings()
        self.assertNotIn("journal", found.summary())
        found.journal_enabled = True
        self.assertIn("journal on", found.summary())

    def test_it_summarises_itself_for_the_ui(self) -> None:
        self.assertIn("places searched", self.settings().summary())

    def test_resetting_restores_the_defaults_on_disk(self) -> None:
        found = self.settings()
        found.max_age_days = 3
        found.save()
        found.reset()
        self.assertEqual(self.settings().max_age_days, 120)


class TestSavedQueries(SettingsTestCase):
    def store(self) -> QueryStore:
        return QueryStore(self.tmp)

    def test_saving_and_reloading(self) -> None:
        store = self.store()
        saved = store.save("Errors", 'Logs | where Level == "error"',
                           description="all of them",
                           time_range=TimeRange.rolling(timedelta(days=1)))
        reloaded = self.store()
        self.assertEqual(reloaded.queries[saved.id].name, "Errors")
        self.assertEqual(reloaded.queries[saved.id].description, "all of them")
        self.assertEqual(reloaded.queries[saved.id].time_range.last,
                         timedelta(days=1))

    def test_an_empty_query_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.store().save("Nothing", "   ")

    def test_saving_over_an_existing_one_replaces_it(self) -> None:
        store = self.store()
        first = store.save("A", "Logs | take 1")
        store.save("B", "Logs | take 2", query_id=first.id)
        self.assertEqual(len(store.queries), 1)
        self.assertEqual(store.queries[first.id].name, "B")

    def test_renaming_and_deleting(self) -> None:
        store = self.store()
        saved = store.save("A", "Logs")
        store.rename(saved.id, "B")
        self.assertEqual(self.store().queries[saved.id].name, "B")
        self.assertTrue(store.delete(saved.id))
        self.assertFalse(store.delete(saved.id))
        self.assertEqual(self.store().queries, {})

    def test_use_counts_order_the_list(self) -> None:
        store = self.store()
        store.save("Quiet", "Logs | take 1")
        busy = store.save("Busy", "Logs | take 2")
        store.record_use(busy.id)
        self.assertEqual(store.all()[0].id, busy.id)

    def test_history_remembers_what_was_run(self) -> None:
        store = self.store()
        store.remember("Logs | take 1", elapsed=0.1, rows=1)
        store.remember("Logs | take 2", error="broke")
        recent = self.store().recent()
        self.assertEqual(recent[0].text, "Logs | take 2")
        self.assertFalse(recent[0].ok)
        self.assertTrue(recent[1].ok)

    def test_running_the_same_query_twice_is_one_history_entry(self) -> None:
        store = self.store()
        store.remember("Logs | take 1")
        store.remember("Logs | take 1")
        self.assertEqual(len(store.history), 1)

    def test_history_is_a_ring_buffer(self) -> None:
        store = self.store()
        for index in range(150):
            store.remember(f"Logs | take {index}")
        self.assertLessEqual(len(store.history), 100)

    def test_a_broken_file_loses_nothing_else(self) -> None:
        (self.tmp / "hunt-queries.json").write_text("{{{")
        self.assertEqual(self.store().queries, {})

    def test_a_saved_query_missing_its_text_is_dropped(self) -> None:
        (self.tmp / "hunt-queries.json").write_text(json.dumps(
            {"queries": [{"id": "a", "name": "A"},
                         {"id": "b", "name": "B", "text": "Logs"}]}))
        self.assertEqual(list(self.store().queries), ["b"])

    def test_an_enormous_query_is_truncated_rather_than_stored_whole(self) -> None:
        store = self.store()
        saved = store.save("Big", "Logs | take 1 " + "x" * 200_000)
        self.assertLessEqual(len(saved.text), 100_000)

    def test_clearing_the_history(self) -> None:
        store = self.store()
        store.remember("Logs")
        store.clear_history()
        self.assertEqual(self.store().history, [])


if __name__ == "__main__":
    unittest.main()
