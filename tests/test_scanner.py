"""Scan output parsing, progress maths, and the profile to argument mapping."""

from __future__ import annotations

import unittest

from .support import qt_application

from clamguard.core.scan_profile import BALANCED, FAST, PRESETS, THOROUGH, profile
from clamguard.core.scanner import (
    ScanProgress,
    ScanResult,
    Threat,
    format_duration,
    format_rate,
    parse_scan_line,
)
from clamguard.core.scan_targets import ScanKind


class TestOutputParsing(unittest.TestCase):
    def test_clean_file(self) -> None:
        self.assertEqual(parse_scan_line("/home/a/x.txt: OK"),
                         ("ok", "/home/a/x.txt", ""))

    def test_empty_file_counts_as_looked_at(self) -> None:
        self.assertEqual(parse_scan_line("/home/a/x: Empty file")[0], "ok")

    def test_detection(self) -> None:
        kind, path, threat = parse_scan_line(
            "/home/a/eicar.com: Eicar-Test-Signature FOUND")
        self.assertEqual((kind, path, threat),
                         ("found", "/home/a/eicar.com", "Eicar-Test-Signature"))

    def test_paths_containing_colons(self) -> None:
        """Splitting on the first colon would mangle these, so we match suffixes."""
        line = "/home/a/weird: name: with: colons.txt: OK"
        self.assertEqual(parse_scan_line(line),
                         ("ok", "/home/a/weird: name: with: colons.txt", ""))

        line = "/tmp/a: b: Win.Trojan.Agent-1 FOUND"
        self.assertEqual(parse_scan_line(line),
                         ("found", "/tmp/a: b", "Win.Trojan.Agent-1"))

    def test_unreadable_files_are_errors_not_clean(self) -> None:
        for line, expected in (
            ("/root/secret: Access denied.", "Access denied"),
            ("/tmp/sock: Can't open file", "Can't open file"),
            ("/x/y: Excluded", "Excluded"),
        ):
            kind, _path, detail = parse_scan_line(line)
            self.assertEqual(kind, "error", line)
            self.assertEqual(detail, expected)

    def test_bare_errors(self) -> None:
        kind, path, detail = parse_scan_line("ERROR: Can't open file or directory")
        self.assertEqual(kind, "error")
        self.assertEqual(path, "")
        self.assertEqual(detail, "Can't open file or directory")

    def test_uninteresting_lines_are_ignored(self) -> None:
        for line in ("", "   ", "----------- SCAN SUMMARY -----------",
                     "Infected files: 1", "Known viruses: 8000000"):
            self.assertIsNone(parse_scan_line(line), line)


class TestProgress(unittest.TestCase):
    def test_fraction_prefers_bytes(self) -> None:
        progress = ScanProgress(files_done=1, files_total=100,
                                bytes_done=50, bytes_total=100)
        self.assertAlmostEqual(progress.fraction, 0.5)
        self.assertEqual(progress.percent, 50)

    def test_fraction_falls_back_to_files(self) -> None:
        progress = ScanProgress(files_done=25, files_total=100)
        self.assertAlmostEqual(progress.fraction, 0.25)

    def test_fraction_is_zero_when_nothing_is_known(self) -> None:
        self.assertEqual(ScanProgress().fraction, 0.0)

    def test_fraction_never_exceeds_one(self) -> None:
        progress = ScanProgress(files_done=200, files_total=100)
        self.assertEqual(progress.fraction, 1.0)

    def test_eta_is_withheld_until_it_means_something(self) -> None:
        self.assertIsNone(ScanProgress(elapsed=0.5, files_done=1,
                                       files_total=100).eta_seconds())
        self.assertIsNone(ScanProgress(elapsed=10, files_done=0,
                                       files_total=100).eta_seconds())

    def test_eta_extrapolates_from_the_rate_so_far(self) -> None:
        progress = ScanProgress(files_done=50, files_total=100, elapsed=10.0)
        self.assertAlmostEqual(progress.eta_seconds(), 10.0, places=5)

    def test_rates_need_a_moment_before_they_are_meaningful(self) -> None:
        self.assertEqual(ScanProgress(files_done=10, elapsed=0.1).files_per_second, 0.0)
        self.assertAlmostEqual(
            ScanProgress(files_done=100, elapsed=10.0).files_per_second, 10.0)


class TestResult(unittest.TestCase):
    def test_headline_counts_correctly(self) -> None:
        clean = ScanResult(status="completed")
        self.assertEqual(clean.headline(), "No threats found.")
        self.assertTrue(clean.clean)

        one = ScanResult(status="completed", threats=[Threat("/a", "X")])
        self.assertEqual(one.headline(), "1 threat was found.")

        two = ScanResult(status="completed",
                         threats=[Threat("/a", "X"), Threat("/b", "Y")])
        self.assertEqual(two.headline(), "2 threats were found.")

    def test_stopped_scan_is_not_clean(self) -> None:
        stopped = ScanResult(status="stopped")
        self.assertFalse(stopped.clean)
        self.assertIn("stopped", stopped.headline().lower())

    def test_failed_scan_reports_its_message(self) -> None:
        failed = ScanResult(status="failed", message="clamscan is missing")
        self.assertEqual(failed.headline(), "clamscan is missing")

    def test_summary_line_is_singular_for_one_file(self) -> None:
        self.assertIn("1 file scanned",
                      ScanResult(files_scanned=1, duration=2).summary_line())


class TestFormatting(unittest.TestCase):
    def test_durations(self) -> None:
        self.assertEqual(format_duration(0), "0 seconds")
        self.assertEqual(format_duration(1), "1 second")
        self.assertEqual(format_duration(59), "59 seconds")
        self.assertEqual(format_duration(60), "1 minute")
        self.assertEqual(format_duration(61), "1 minute 1 second")
        self.assertEqual(format_duration(3600), "1 hour")
        self.assertEqual(format_duration(3725), "1 hour 2 minutes")

    def test_negative_durations_do_not_explode(self) -> None:
        self.assertEqual(format_duration(-5), "0 seconds")

    def test_rates(self) -> None:
        self.assertEqual(format_rate(0), "—")
        self.assertEqual(format_rate(900), "900 B/s")
        self.assertIn("MB/s", format_rate(2_500_000))


class TestProfiles(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()

    def test_presets_have_unique_ids(self) -> None:
        ids = [preset.id for preset in PRESETS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_unknown_profile_falls_back_to_balanced(self) -> None:
        self.assertIs(profile("nonsense"), BALANCED)
        self.assertIs(profile("thorough"), THOROUGH)

    def test_clamscan_args_reflect_the_profile(self) -> None:
        args = THOROUGH.clamscan_args()
        self.assertIn("--detect-pua=yes", args)
        self.assertIn("--alert-encrypted=yes", args)
        self.assertIn("--max-filesize=500M", args)
        self.assertIn("--stdout", args)

        args = FAST.clamscan_args()
        self.assertIn("--scan-archive=no", args)
        self.assertIn("--detect-pua=no", args)

    def test_exclusions_become_repeated_flags(self) -> None:
        custom = BALANCED.with_changes(exclude_patterns=("^/proc/", "^/sys/"))
        args = custom.clamscan_args()
        self.assertIn("--exclude=^/proc/", args)
        self.assertIn("--exclude=^/sys/", args)

    def test_daemon_args_are_the_few_that_exist(self) -> None:
        args = BALANCED.clamdscan_args()
        self.assertEqual(set(args), {"--stdout", "--fdpass", "--multiscan"})
        self.assertEqual(BALANCED.clamdscan_args(fdpass=False, multiscan=False),
                         ["--stdout"])

    def test_max_file_bytes_is_parsed(self) -> None:
        self.assertEqual(BALANCED.max_file_bytes, 100 * 1024 ** 2)

    def test_summary_lines_describe_the_differences(self) -> None:
        self.assertIn("Archives are not opened", FAST.summary_lines())
        self.assertIn("Archives are unpacked and scanned", THOROUGH.summary_lines())


class TestScanKinds(unittest.TestCase):
    def test_every_kind_has_a_title_description_and_icon(self) -> None:
        for kind in ScanKind:
            self.assertTrue(kind.title)
            self.assertTrue(kind.description)
            self.assertTrue(kind.icon)


if __name__ == "__main__":
    unittest.main()
