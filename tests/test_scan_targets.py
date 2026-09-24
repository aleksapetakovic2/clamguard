"""Deciding what to scan, and the walk that enumerates it."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from .support import TempHomeTestCase

from clamguard.core.scan_targets import (
    ScanKind,
    TargetWalker,
    paths_for,
    pseudo_filesystem_mountpoints,
)


class TestTargets(TempHomeTestCase):
    def test_quick_scan_only_returns_paths_that_exist(self) -> None:
        for path in paths_for(ScanKind.QUICK):
            self.assertTrue(path.exists(), path)

    def test_an_override_replaces_the_built_in_list(self) -> None:
        (self.tmp / "custom").mkdir()
        result = paths_for(ScanKind.QUICK,
                           quick_override=[str(self.tmp / "custom"),
                                           str(self.tmp / "missing")])
        self.assertEqual(result, [self.tmp / "custom"])

    def test_full_scan_is_the_root(self) -> None:
        self.assertEqual(paths_for(ScanKind.FULL), [Path("/")])

    def test_home_scan(self) -> None:
        self.assertEqual(paths_for(ScanKind.HOME), [Path.home()])

    def test_custom_expands_a_tilde(self) -> None:
        self.assertEqual(paths_for(ScanKind.CUSTOM, custom=["~"]), [Path.home()])

    def test_pseudo_filesystems_are_detected(self) -> None:
        mounts = pseudo_filesystem_mountpoints()
        if not Path("/proc/self/mounts").exists():
            self.skipTest("not a Linux machine")
        self.assertIn("/proc", mounts)
        self.assertIn("/sys", mounts)

    def test_a_real_mount_over_a_pseudo_one_wins(self) -> None:
        """/efi is commonly an autofs trigger with vfat mounted on top."""
        mounts = pseudo_filesystem_mountpoints()
        self.assertNotIn("/", mounts)


class TestWalker(TempHomeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.tree = self.tmp / "tree"
        (self.tree / "sub").mkdir(parents=True)
        (self.tree / "a.txt").write_text("a")
        (self.tree / "b.log").write_text("b" * 100)
        (self.tree / "sub" / "c.txt").write_text("c")
        (self.tree / ".hidden").write_text("secret")
        (self.tree / ".hiddendir").mkdir()
        (self.tree / ".hiddendir" / "d.txt").write_text("d")
        self.listing = self.tmp / "list.txt"

    def walk(self, **kwargs):
        walker = TargetWalker([self.tree], **kwargs)
        return walker, walker.enumerate(self.listing)

    def listed(self) -> list[str]:
        return [line for line in self.listing.read_text().splitlines() if line]

    def test_every_regular_file_is_listed(self) -> None:
        _walker, result = self.walk()
        self.assertEqual(result.files, 5)
        self.assertEqual(result.total_bytes, 1 + 100 + 1 + 6 + 1)
        self.assertEqual(len(self.listed()), 5)

    def test_hidden_files_can_be_skipped(self) -> None:
        _walker, result = self.walk(skip_hidden=True)
        self.assertEqual(result.files, 3)
        self.assertFalse(any(".hidden" in line for line in self.listed()))

    def test_exclusions_are_regexes(self) -> None:
        _walker, result = self.walk(exclude_patterns=[r"\.log$"])
        self.assertEqual(result.files, 4)
        self.assertFalse(any(line.endswith(".log") for line in self.listed()))

    def test_an_invalid_exclusion_is_ignored_rather_than_fatal(self) -> None:
        _walker, result = self.walk(exclude_patterns=["[unclosed"])
        self.assertEqual(result.files, 5)

    def test_files_over_the_size_limit_are_skipped_and_counted(self) -> None:
        _walker, result = self.walk(max_file_bytes=50)
        self.assertEqual(result.skipped_too_large, 1)
        self.assertEqual(result.files, 4)

    def test_symlinks_are_not_followed_by_default(self) -> None:
        (self.tree / "link.txt").symlink_to(self.tree / "a.txt")
        _walker, result = self.walk()
        self.assertEqual(result.files, 5)
        self.assertGreaterEqual(result.skipped_special, 1)

    def test_fifos_and_sockets_are_never_opened(self) -> None:
        """Reading one can block forever, which would hang the whole scan."""
        os.mkfifo(self.tree / "pipe")
        _walker, result = self.walk()
        self.assertFalse(any(line.endswith("pipe") for line in self.listed()))
        self.assertGreaterEqual(result.skipped_special, 1)

    def test_a_single_file_target_works(self) -> None:
        walker = TargetWalker([self.tree / "a.txt"])
        result = walker.enumerate(self.listing)
        self.assertEqual(result.files, 1)

    def test_a_missing_target_is_reported_not_fatal(self) -> None:
        walker = TargetWalker([self.tmp / "nowhere"])
        result = walker.enumerate(self.listing)
        self.assertEqual(result.files, 0)
        self.assertTrue(result.errors)
        self.assertTrue(result.empty)

    def test_cancelling_stops_the_walk(self) -> None:
        for index in range(50):
            (self.tree / f"extra{index}.txt").write_text("x")
        walker = TargetWalker([self.tree])
        walker.cancelled = True
        result = walker.enumerate(self.listing)
        self.assertTrue(result.cancelled or result.files == 0)

    def test_the_quarantine_vault_is_never_scanned(self) -> None:
        """Otherwise every quarantined file would be re-detected on each scan."""
        walker = TargetWalker([self.tmp])
        self.assertIn(os.path.realpath(self.paths.QUARANTINE_DIR),
                      walker._always_excluded)

    def test_progress_is_reported(self) -> None:
        for index in range(1200):
            (self.tree / f"f{index}.txt").write_text("x")
        seen = []
        walker = TargetWalker([self.tree])
        walker.enumerate(self.listing, on_progress=lambda f, b: seen.append(f))
        self.assertTrue(seen)
        self.assertEqual(seen[-1], 1205)

    def test_the_same_directory_is_not_walked_twice(self) -> None:
        (self.tree / "loop").symlink_to(self.tree)
        _walker, result = self.walk(follow_symlinks=True)
        paths = self.listed()
        self.assertEqual(len(paths), len(set(paths)))


if __name__ == "__main__":
    unittest.main()
