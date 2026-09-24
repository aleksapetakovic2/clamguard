"""Finding logs, and refusing the things that only look like logs.

The exclusions matter more than the inclusions. Every Electron application on
a desktop has several files called ``000003.log`` that are LevelDB
write-ahead logs, and indexing those produces a table of binary noise that
makes the whole feature look broken.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.hunt import discovery  # noqa: E402


class TestNameMatching(unittest.TestCase):
    def test_the_obvious_names_are_logs(self) -> None:
        for name in ("main.log", "app.jsonl", "trace.ndjson", "stderr.err",
                     "sunshine.log.5", "renderer.old.log", "app.log.gz",
                     "app.log.2026-09-21", "messages", "syslog"):
            with self.subTest(name=name):
                self.assertTrue(discovery.looks_like_a_log(name, "logs"))

    def test_a_leveldb_write_ahead_log_is_not(self) -> None:
        """The single most common `.log` file on a modern desktop, and never
        a log."""
        for name in ("000003.log", "000203.log", "1234567.log"):
            with self.subTest(name=name):
                self.assertFalse(discovery.looks_like_a_log(name, "Session Storage"))
                self.assertFalse(discovery.looks_like_a_log(name, "logs"))

    def test_binary_account_files_are_not_logs(self) -> None:
        for name in ("wtmp", "btmp", "lastlog", "faillog", "LOCK", "CURRENT"):
            with self.subTest(name=name):
                self.assertFalse(discovery.looks_like_a_log(name, "log"))

    def test_a_hint_has_to_be_a_whole_word(self) -> None:
        """`kwinoutputconfig.json` matched on the "output" inside it."""
        self.assertFalse(discovery.looks_like_a_log("kwinoutputconfig.json", "config"))
        self.assertTrue(discovery.looks_like_a_log("crash-report.json", "config"))
        self.assertTrue(discovery.looks_like_a_log("debug.txt", "config"))

    def test_an_icon_named_after_a_log_viewer_is_not_a_log(self) -> None:
        """`org.gnome.Logs-symbolic.svg` matched the rotation pattern."""
        self.assertFalse(discovery.looks_like_a_log("org.gnome.Logs-symbolic.svg",
                                                    "apps"))

    def test_inside_a_logs_directory_almost_anything_counts(self) -> None:
        self.assertTrue(discovery.looks_like_a_log("console-linux.txt", "logs"))
        self.assertTrue(discovery.looks_like_a_log("webhelper", "logs"))
        self.assertFalse(discovery.looks_like_a_log("state.db", "logs"))
        self.assertFalse(discovery.looks_like_a_log("app.pid", "logs"))

    def test_the_gz_suffix_is_looked_through(self) -> None:
        self.assertTrue(discovery.looks_like_a_log("app.log.gz", "anything"))
        self.assertTrue(discovery.looks_like_a_log("app.log.1.gz", "anything"))


class DiscoveryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-crawl-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, relative: str, content: bytes | str = "hello\n") -> Path:
        path = self.tmp / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content)
        else:
            path.write_bytes(content)
        return path

    def crawl(self, **kwargs) -> discovery.Crawl:
        root = discovery.Root("test", self.tmp, "Test", "", depth=6)
        return discovery.crawl((root,), home=self.tmp, **kwargs)


class TestSniffing(DiscoveryTestCase):
    def test_a_text_file_is_text(self) -> None:
        path = self.write("a.log", "line one\nline two\n")
        self.assertEqual(discovery.is_probably_text(path), (True, ""))

    def test_null_bytes_mean_binary(self) -> None:
        path = self.write("a.log", b"hello\x00\x00\x00world")
        ok, reason = discovery.is_probably_text(path)
        self.assertFalse(ok)
        self.assertIn("null bytes", reason)

    def test_mostly_control_characters_mean_binary(self) -> None:
        path = self.write("a.log", bytes(range(1, 32)) * 40)
        ok, reason = discovery.is_probably_text(path)
        self.assertFalse(ok)
        self.assertIn("non-printable", reason)

    def test_a_gzip_header_is_accepted_because_the_reader_handles_it(self) -> None:
        path = self.write("a.log.gz", b"\x1f\x8b\x08\x00rest")
        self.assertTrue(discovery.is_probably_text(path)[0])

    def test_an_empty_file_is_text(self) -> None:
        self.assertTrue(discovery.is_probably_text(self.write("a.log", ""))[0])

    def test_utf8_text_with_accents_is_text(self) -> None:
        path = self.write("a.log", "naïve café — ✓\n" * 20)
        self.assertTrue(discovery.is_probably_text(path)[0])


class TestCrawling(DiscoveryTestCase):
    def test_it_finds_a_log_and_reports_it(self) -> None:
        self.write("app/logs/main.log")
        found = self.crawl()
        self.assertEqual(len(found.usable), 1)
        self.assertTrue(found.usable[0].path.endswith("main.log"))

    def test_an_empty_file_is_skipped_with_a_reason(self) -> None:
        self.write("app/logs/main.log", "")
        found = self.crawl()
        self.assertEqual(found.usable, [])
        self.assertEqual(found.skipped[0].skipped, "empty")

    def test_a_binary_file_is_skipped_with_a_reason(self) -> None:
        self.write("app/logs/db.log", b"\x00" * 100)
        found = self.crawl()
        self.assertEqual(found.usable, [])
        self.assertIn("binary", found.skipped[0].skipped)

    def test_a_database_directory_is_never_entered(self) -> None:
        self.write("app/Session Storage/000003.log", "x")
        self.write("app/Local Storage/leveldb/000005.log", "x")
        self.write("app/GPUCache/data.log", "x")
        self.assertEqual(self.crawl().candidates, [])

    def test_a_file_over_the_size_limit_is_skipped_with_a_reason(self) -> None:
        self.write("app/logs/huge.log", "x" * 5000)
        found = self.crawl(budget=discovery.Budget(max_bytes=100))
        self.assertIn("larger than", found.skipped[0].skipped)

    def test_an_exclusion_pattern_names_itself_as_the_reason(self) -> None:
        self.write("app/logs/main.log")
        found = self.crawl(excluded=("*main.log",))
        self.assertEqual(found.skipped[0].skipped, "excluded by *main.log")

    def test_the_depth_limit_is_respected(self) -> None:
        self.write("a/b/c/d/e/f/g/deep.log")
        root = discovery.Root("test", self.tmp, "Test", "", depth=2)
        found = discovery.crawl((root,), home=self.tmp)
        self.assertEqual(found.usable, [])

    def test_a_symlinked_directory_is_not_followed(self) -> None:
        """Otherwise a loop makes the crawl run until its budget dies."""
        self.write("real/logs/main.log")
        try:
            (self.tmp / "link").symlink_to(self.tmp / "real")
        except OSError:
            self.skipTest("this filesystem has no symlinks")
        found = self.crawl()
        self.assertEqual(len(found.usable), 1)

    def test_an_unreadable_directory_is_listed_with_its_reason(self) -> None:
        """An unreadable *file* already said so. A directory going quiet was
        the one place the Skipped tab's promise did not hold — /var/log/audit
        is mode 0700 root, and it vanished without a word."""
        locked = self.tmp / "app" / "secret"
        locked.mkdir(parents=True)
        self.write("app/secret/inside.log")
        try:
            locked.chmod(0o000)
        except OSError:
            self.skipTest("this filesystem does not enforce modes")
        try:
            if os.access(locked, os.R_OK):
                self.skipTest("this filesystem does not enforce modes")
            found = self.crawl()
        finally:
            locked.chmod(0o755)

        directories = found.unreadable_directories
        self.assertEqual(len(directories), 1)
        self.assertTrue(directories[0].is_directory)
        self.assertIn("directory cannot be read", directories[0].skipped)
        self.assertIn(directories[0], found.skipped)

    def test_a_readable_directory_is_not_reported(self) -> None:
        self.write("app/logs/main.log")
        self.assertEqual(self.crawl().unreadable_directories, [])

    def test_the_list_of_unreadable_directories_is_capped(self) -> None:
        """A misconfigured machine could have thousands, and a table with
        thousands of identical rows is not an explanation."""
        found = discovery.Crawl()
        root = discovery.Root("test", self.tmp, "Test", "")
        for index in range(discovery.MAX_UNREADABLE_DIRECTORIES + 5):
            discovery._note_unreadable(
                found, f"{self.tmp}/locked{index}", root, str(self.tmp),
                PermissionError(13, "Permission denied"))
        self.assertEqual(len(found.unreadable_directories),
                         discovery.MAX_UNREADABLE_DIRECTORIES)
        self.assertEqual(found.unlisted_directories, 5)
        self.assertIn("could not be read", found.limits_hit())

    def test_a_root_that_does_not_exist_is_reported_not_fatal(self) -> None:
        root = discovery.Root("nope", self.tmp / "missing", "Missing", "")
        found = discovery.crawl((root,), home=self.tmp)
        self.assertEqual(found.missing, ("nope",))
        self.assertEqual(found.candidates, [])

    def test_the_file_budget_cuts_one_root_short_rather_than_the_crawl(self) -> None:
        """Godot's shader cache on a real machine has 453,000 files in it. One
        directory like that must not cost you /var/log."""
        for index in range(60):
            self.write(f"noise/file{index}.txt", "x")
        self.write("app/logs/main.log")
        found = self.crawl(budget=discovery.Budget(files_per_root=10))
        self.assertTrue(found.truncated)
        self.assertIn("files", found.limits_hit())

    def test_the_crawl_reports_what_it_cost(self) -> None:
        self.write("app/logs/main.log")
        found = self.crawl()
        self.assertGreater(found.directories, 0)
        self.assertGreaterEqual(found.elapsed, 0)
        self.assertIn("log files", found.summary())

    def test_results_group_by_application(self) -> None:
        self.write("alpha/logs/a.log")
        self.write("beta/logs/b.log")
        grouped = self.crawl().by_app()
        self.assertEqual(sorted(grouped), ["alpha", "beta"])


class TestNaming(unittest.TestCase):
    def test_the_application_comes_from_the_path(self) -> None:
        root = discovery.Root("config", Path("/home/x/.config"), "Config", "")
        self.assertEqual(
            discovery.app_for("/home/x/.config/discord/logs/main.log", root),
            "discord")

    def test_a_flatpak_is_named_by_its_identifier(self) -> None:
        root = discovery.Root("flatpak", Path("/home/x/.var/app"), "Flatpak", "")
        self.assertEqual(
            discovery.app_for(
                "/home/x/.var/app/com.google.Chrome/config/chrome/logs/a.log", root),
            "com.google.Chrome")

    def test_var_log_is_all_one_application(self) -> None:
        root = discovery.Root("system", Path("/var/log"), "System", "")
        self.assertEqual(discovery.app_for("/var/log/pacman.log", root), "system")

    def test_generic_directories_are_stepped_over(self) -> None:
        root = discovery.Root("data", Path("/home/x/.local/share"), "Data", "")
        self.assertEqual(
            discovery.app_for("/home/x/.local/share/logs/opencode/dev.log", root),
            "opencode")


class TestSingleFiles(DiscoveryTestCase):
    def test_a_file_the_user_chose_is_examined_the_same_way(self) -> None:
        path = self.write("anywhere.txt", "some log content\n")
        candidate = discovery.scan_one(path)
        self.assertTrue(candidate.usable)
        self.assertEqual(candidate.root, "custom")

    def test_a_binary_file_the_user_chose_is_still_refused(self) -> None:
        path = self.write("anywhere.bin", b"\x00" * 200)
        self.assertFalse(discovery.scan_one(path).usable)

    def test_a_file_that_is_not_there_says_so(self) -> None:
        candidate = discovery.scan_one(self.tmp / "nothing")
        self.assertFalse(candidate.usable)
        self.assertIn("cannot be read", candidate.skipped)


class TestRoots(unittest.TestCase):
    def test_the_sensitive_roots_are_off_by_default(self) -> None:
        optional = {root.id for root in discovery.default_roots() if root.optional}
        self.assertIn("shell", optional)
        self.assertIn("tmp", optional)

    def test_every_root_explains_itself(self) -> None:
        for root in discovery.default_roots():
            with self.subTest(root=root.id):
                self.assertTrue(root.title)
                self.assertTrue(root.description)

    def test_shell_history_is_a_fixed_list_not_a_pattern(self) -> None:
        """So that turning it on cannot pull in anything unexpected."""
        self.assertIn(".bash_history", discovery.SHELL_HISTORY_FILES)
        self.assertTrue(all(not name.startswith("/")
                            for name in discovery.SHELL_HISTORY_FILES))

    def test_journald_is_not_among_the_roots(self) -> None:
        """Hunt is explicitly for the logs other tools do not read."""
        paths = {str(root.path) for root in discovery.default_roots()}
        self.assertNotIn("/var/log/journal", paths)


class TestDisplay(DiscoveryTestCase):
    def test_a_path_under_home_shows_as_a_tilde(self) -> None:
        candidate = discovery.Candidate(path=str(self.tmp / "a" / "b.log"))
        self.assertTrue(candidate.display_path(str(self.tmp)).startswith("~/"))

    def test_a_path_elsewhere_shows_in_full(self) -> None:
        candidate = discovery.Candidate(path="/var/log/pacman.log")
        self.assertEqual(candidate.display_path("/home/x"), "/var/log/pacman.log")


if __name__ == "__main__":
    unittest.main()
