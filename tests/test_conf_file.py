"""The ClamAV configuration parser.

These are the most important tests in the suite: this parser edits a file the
system depends on, and a mistake here can stop clamd from starting.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from .support import SAMPLE_CLAMD_CONF, TempHomeTestCase

from clamguard.core.conf_file import ConfFile, from_bool, to_bool


class TestParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.conf = ConfFile.parse(SAMPLE_CLAMD_CONF)

    def test_round_trip_is_byte_identical(self) -> None:
        self.assertEqual(self.conf.to_text(), SAMPLE_CLAMD_CONF)
        self.assertFalse(self.conf.is_modified())

    def test_active_options_are_found(self) -> None:
        self.assertEqual(self.conf.get("LogFile"), "/var/log/clamav/clamd.log")
        self.assertTrue(self.conf.get_bool("LogTime"))
        self.assertTrue(self.conf.get_bool("OnAccessPrevention"))

    def test_commented_options_are_not_active(self) -> None:
        self.assertFalse(self.conf.has("LogRotate"))
        self.assertIsNone(self.conf.get("MaxThreads"))
        self.assertEqual(self.conf.commented_value("MaxThreads"), "20")

    def test_prose_comments_are_not_mistaken_for_options(self) -> None:
        # "# Enable log rotation." must not parse as an option called "Enable".
        self.assertFalse(self.conf.has("Enable"))
        self.assertIsNone(self.conf.commented_value("Path"))
        self.assertIsNone(self.conf.commented_value("Log"))

    def test_repeatable_options_keep_every_value(self) -> None:
        self.assertEqual(self.conf.get_all("OnAccessIncludePath"), ["/home", "/srv"])

    def test_missing_options_use_the_default(self) -> None:
        self.assertEqual(self.conf.get("NotThere", "fallback"), "fallback")
        self.assertTrue(self.conf.get_bool("NotThere", True))
        self.assertEqual(self.conf.get_int("NotThere", 7), 7)

    def test_bare_option_means_yes(self) -> None:
        conf = ConfFile.parse("LogVerbose\n")
        self.assertTrue(conf.get_bool("LogVerbose"))

    def test_boolean_spellings(self) -> None:
        for text in ("yes", "YES", "true", "1", "on", ""):
            self.assertTrue(to_bool(text), text)
        for text in ("no", "FALSE", "0", "off"):
            self.assertFalse(to_bool(text), text)
        self.assertEqual(from_bool(True), "yes")
        self.assertEqual(from_bool(False), "no")
        # Anything unrecognised falls back rather than guessing.
        self.assertTrue(to_bool("banana", default=True))


class TestEditing(unittest.TestCase):
    def setUp(self) -> None:
        self.conf = ConfFile.parse(SAMPLE_CLAMD_CONF)

    def test_setting_an_active_option_edits_it_in_place(self) -> None:
        self.conf.set("LogTime", False)
        self.assertIn("LogTime no", self.conf.to_text())
        self.assertNotIn("LogTime yes", self.conf.to_text())
        # The surrounding comments survive.
        self.assertIn("# Log time with each message.", self.conf.to_text())

    def test_setting_a_commented_option_uncomments_it_in_place(self) -> None:
        self.conf.set("MaxThreads", 24)
        text = self.conf.to_text()
        self.assertIn("MaxThreads 24", text)
        self.assertNotIn("#MaxThreads", text)
        # It stays next to its own documentation rather than moving to the end.
        lines = text.splitlines()
        index = lines.index("MaxThreads 24")
        self.assertIn("Maximum number of threads", lines[index - 2])

    def test_a_brand_new_option_is_appended_under_a_header(self) -> None:
        self.conf.set("OnAccessExcludeUname", "clamav")
        text = self.conf.to_text()
        self.assertIn("# --- added by ClamGuard ---", text)
        self.assertIn("OnAccessExcludeUname clamav", text)

    def test_only_one_header_is_ever_added(self) -> None:
        self.conf.set("OnAccessExcludeUname", "clamav")
        self.conf.set("OnAccessDenyOnError", True)
        self.assertEqual(self.conf.to_text().count("# --- added by ClamGuard ---"), 1)

    def test_set_all_replaces_every_occurrence(self) -> None:
        self.conf.set_all("OnAccessIncludePath", ["/home", "/opt"])
        self.assertEqual(self.conf.get_all("OnAccessIncludePath"), ["/home", "/opt"])
        # Exactly two lines, not two plus the ones it replaced.
        self.assertEqual(self.conf.to_text().count("OnAccessIncludePath"), 2)

    def test_set_all_on_an_absent_option(self) -> None:
        conf = ConfFile.parse("#ExcludePath ^/proc\nLogTime yes\n")
        conf.set_all("ExcludePath", ["^/proc", "^/sys", "^/run"])
        self.assertEqual(conf.get_all("ExcludePath"), ["^/proc", "^/sys", "^/run"])

    def test_set_all_with_an_empty_list_removes_the_option(self) -> None:
        self.conf.set_all("OnAccessIncludePath", [])
        self.assertEqual(self.conf.get_all("OnAccessIncludePath"), [])

    def test_remove_deletes_only_active_lines(self) -> None:
        self.conf.remove("OnAccessMountPath")
        self.assertFalse(self.conf.has("OnAccessMountPath"))
        self.assertIn("# Set the mount point", self.conf.to_text())

    def test_comment_out_keeps_the_line_visible(self) -> None:
        self.conf.comment_out("LogTime")
        self.assertFalse(self.conf.has("LogTime"))
        self.assertIn("#LogTime yes", self.conf.to_text())

    def test_apply_handles_none_as_removal(self) -> None:
        self.conf.apply({"LogTime": False, "OnAccessMountPath": None})
        self.assertFalse(self.conf.get_bool("LogTime"))
        self.assertFalse(self.conf.has("OnAccessMountPath"))

    def test_duplicate_active_options_collapse_to_one(self) -> None:
        conf = ConfFile.parse("MaxThreads 4\nLogTime yes\nMaxThreads 8\n")
        conf.set("MaxThreads", 12)
        self.assertEqual(conf.get_all("MaxThreads"), ["12"])

    def test_changed_keys_reports_what_moved(self) -> None:
        self.conf.set("LogTime", False)
        self.conf.set("MaxThreads", 24)
        self.assertEqual(self.conf.changed_keys(), ["LogTime", "MaxThreads"])

    def test_diff_is_a_unified_diff(self) -> None:
        self.conf.set("LogTime", False)
        diff = self.conf.diff("clamd.conf")
        self.assertIn("--- clamd.conf (current)", diff)
        self.assertIn("-LogTime yes", diff)
        self.assertIn("+LogTime no", diff)

    def test_no_change_means_no_diff(self) -> None:
        self.conf.set("LogTime", True)  # already yes
        self.assertEqual(self.conf.diff(), "")
        self.assertFalse(self.conf.is_modified())

    def test_mark_saved_resets_the_baseline(self) -> None:
        self.conf.set("LogTime", False)
        self.assertTrue(self.conf.is_modified())
        self.conf.mark_saved()
        self.assertFalse(self.conf.is_modified())
        self.assertEqual(self.conf.changed_keys(), [])


class TestDocumentation(unittest.TestCase):
    def setUp(self) -> None:
        self.docs = ConfFile.parse(SAMPLE_CLAMD_CONF).documentation()

    def test_description_comes_from_the_comment_block(self) -> None:
        self.assertIn("Maximum number of threads", self.docs["maxthreads"].description)

    def test_default_is_pulled_out_of_the_block(self) -> None:
        self.assertEqual(self.docs["maxthreads"].default, "10")
        self.assertEqual(self.docs["logfile"].default, "disabled")

    def test_documentation_covers_commented_and_active_options(self) -> None:
        self.assertIn("logrotate", self.docs)     # commented out
        self.assertIn("logtime", self.docs)       # active

    def test_warnings_are_separated_from_the_description(self) -> None:
        docs = ConfFile.parse(
            "# Path to the database directory.\n"
            "# WARNING: It must match clamd.conf's directive!\n"
            "# Default: hardcoded\n"
            "#DatabaseDirectory /var/lib/clamav\n"
        ).documentation()
        entry = docs["databasedirectory"]
        self.assertEqual(entry.description, "Path to the database directory.")
        self.assertEqual(entry.warnings, ["It must match clamd.conf's directive!"])


class TestFiles(TempHomeTestCase):
    def test_load_and_load_or_empty(self) -> None:
        path = self.write("clamd.conf", SAMPLE_CLAMD_CONF)
        conf = ConfFile.load(path)
        self.assertEqual(conf.path, path)
        self.assertTrue(conf.get_bool("LogTime"))

        missing = ConfFile.load_or_empty(Path(self.tmp / "nope.conf"))
        self.assertEqual(missing.to_text(), "")
        self.assertEqual(missing.keys(), [])

    def test_load_raises_for_a_missing_file(self) -> None:
        with self.assertRaises(OSError):
            ConfFile.load(self.tmp / "definitely-not-here.conf")


class TestRealSystemConfig(unittest.TestCase):
    """If this machine has a real clamd.conf, round-trip it untouched."""

    def test_real_config_round_trips(self) -> None:
        from clamguard.core import paths

        if not paths.CLAMD_CONF.is_file():
            self.skipTest("no clamd.conf on this machine")
        conf = ConfFile.load(paths.CLAMD_CONF)
        self.assertEqual(conf.to_text(), conf.original_text)
        self.assertFalse(conf.is_modified())


if __name__ == "__main__":
    unittest.main()
