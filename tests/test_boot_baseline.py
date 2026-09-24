"""Recording what the boot chain looks like, and spotting what changed.

The baseline is ClamGuard's substitute for measured boot on a machine that
does not have it, so the tests care about the difference between "this file
changed" and "this file changed and I could not read either version", which is
the honest limit of what an unprivileged tool can say.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.boot.baseline import (  # noqa: E402
    Baseline,
    Change,
    Drift,
    Entry,
    compare,
    record,
)


class BaselineTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-baseline-"))
        self.boot = self.tmp / "boot"
        self.boot.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name: str, content: str = "x", mode: int = 0o644) -> Path:
        path = self.boot / name
        path.write_text(content)
        try:
            path.chmod(mode)
        except OSError:
            pass
        return path

    def snapshot(self) -> Baseline:
        return record((str(self.boot),))


class TestRecording(BaselineTestCase):
    def test_a_snapshot_hashes_what_it_can_read(self) -> None:
        self.write("vmlinuz-linux", "kernel bytes")
        snapshot = self.snapshot()
        entry = snapshot.entries[str(self.boot / "vmlinuz-linux")]
        self.assertEqual(len(entry.sha256), 64)
        self.assertTrue(entry.hashed)

    def test_a_snapshot_records_the_mode_and_the_owner(self) -> None:
        path = self.write("grub.cfg", "menuentry {}", mode=0o600)
        entry = self.snapshot().entries[str(path)]
        self.assertEqual(entry.uid, os.getuid())
        if path.stat().st_mode & 0o777 == 0o600:   # skipped on NTFS and friends
            self.assertEqual(entry.mode & 0o777, 0o600)

    def test_a_snapshot_names_the_kernel_and_the_machine(self) -> None:
        self.write("a")
        snapshot = self.snapshot()
        self.assertTrue(snapshot.taken_at)
        self.assertTrue(snapshot.kernel)
        self.assertEqual(snapshot.roots, (str(self.boot),))

    def test_directories_are_walked_recursively(self) -> None:
        (self.boot / "grub").mkdir()
        (self.boot / "grub" / "grub.cfg").write_text("x")
        self.assertIn(str(self.boot / "grub" / "grub.cfg"), self.snapshot().entries)

    def test_a_root_that_does_not_exist_is_not_an_error(self) -> None:
        self.assertEqual(record((str(self.tmp / "nowhere"),)).entries, {})

    def test_only_regular_files_are_recorded(self) -> None:
        (self.boot / "subdir").mkdir()
        self.assertEqual(list(self.snapshot().entries), [])

    def test_a_single_file_root_works(self) -> None:
        path = self.write("ld.so.preload")
        self.assertIn(str(path), record((str(path),)).entries)

    def test_an_unreadable_file_is_recorded_without_a_hash(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root can read anything")
        path = self.write("initramfs.img", "secret", mode=0o000)
        if os.access(path, os.R_OK):
            self.skipTest("this filesystem does not enforce permissions")
        entry = self.snapshot().entries[str(path)]
        self.assertFalse(entry.hashed)
        self.assertEqual(entry.size, len("secret"))


class TestSaveAndLoad(BaselineTestCase):
    def test_a_baseline_round_trips_through_json(self) -> None:
        self.write("vmlinuz", "bytes")
        target = self.tmp / "baseline.json"
        original = self.snapshot()
        original.save(target)
        loaded = Baseline.load(target)
        self.assertEqual(loaded.entries.keys(), original.entries.keys())
        self.assertEqual(loaded.kernel, original.kernel)

    def test_a_missing_baseline_loads_as_empty_rather_than_raising(self) -> None:
        self.assertFalse(Baseline.load(self.tmp / "nothing.json").exists)

    def test_a_corrupt_baseline_loads_as_empty(self) -> None:
        target = self.tmp / "broken.json"
        target.write_text("{{{ not json")
        self.assertFalse(Baseline.load(target).exists)

    def test_the_file_is_json_a_person_could_read(self) -> None:
        self.write("vmlinuz", "bytes")
        target = self.tmp / "baseline.json"
        self.snapshot().save(target)
        data = json.loads(target.read_text())
        self.assertIn("entries", data)
        self.assertIn("taken_at", data)


class TestDrift(BaselineTestCase):
    def test_an_unchanged_tree_drifts_not_at_all(self) -> None:
        self.write("vmlinuz", "bytes")
        before = self.snapshot()
        self.assertTrue(compare(before, self.snapshot()).empty)

    def test_changed_contents_are_detected_by_hash(self) -> None:
        self.write("vmlinuz", "before")
        before = self.snapshot()
        self.write("vmlinuz", "after!")     # same length, different bytes
        drift = compare(before, self.snapshot())
        self.assertEqual([c.kind for c in drift.changes], ["content"])
        self.assertTrue(drift.serious)

    def test_a_new_file_is_reported_as_added(self) -> None:
        before = self.snapshot()
        self.write("backdoor.efi", "payload")
        drift = compare(before, self.snapshot())
        self.assertEqual(drift.of("added")[0].path,
                         str(self.boot / "backdoor.efi"))

    def test_a_removed_file_is_reported(self) -> None:
        path = self.write("vmlinuz", "bytes")
        before = self.snapshot()
        path.unlink()
        self.assertEqual(len(compare(before, self.snapshot()).of("removed")), 1)

    def test_a_permission_change_is_reported_separately(self) -> None:
        path = self.write("vmlinuz", "bytes", mode=0o644)
        if path.stat().st_mode & 0o777 != 0o644:
            self.skipTest("this filesystem does not enforce permissions")
        before = self.snapshot()
        path.chmod(0o666)
        drift = compare(before, self.snapshot())
        self.assertTrue(drift.of("permissions"))
        self.assertIn("0644", drift.of("permissions")[0].detail)

    def test_comparing_against_no_baseline_reports_nothing(self) -> None:
        self.write("vmlinuz")
        self.assertTrue(compare(Baseline(), self.snapshot()).empty)

    def test_a_recorded_baseline_of_an_empty_tree_still_catches_an_addition(self) -> None:
        """"Never recorded" and "recorded, found nothing" are different states."""
        before = self.snapshot()
        self.assertTrue(before.exists)
        self.write("backdoor.efi", "payload")
        self.assertEqual(len(compare(before, self.snapshot()).of("added")), 1)

    def test_the_summary_counts_each_kind_of_change(self) -> None:
        drift = Drift(changes=[
            Change("/a", "added", ""), Change("/b", "content", ""),
            Change("/c", "content", ""),
        ])
        self.assertIn("1 added", drift.summary())
        self.assertIn("2 changed", drift.summary())

    def test_an_empty_drift_says_so_plainly(self) -> None:
        self.assertIn("Nothing has changed", Drift().summary())

    def test_a_size_change_is_caught_even_without_a_hash(self) -> None:
        before = Baseline(taken_at="2026-09-01T10:00:00", entries={
            "/boot/initramfs.img": Entry("/boot/initramfs.img", size=100, mode=0o600,
                                         mtime=1.0, uid=0)})
        now = Baseline(entries={
            "/boot/initramfs.img": Entry("/boot/initramfs.img", size=200, mode=0o600,
                                         mtime=2.0, uid=0)})
        drift = compare(before, now)
        self.assertEqual(drift.of("content")[0].kind, "content")
        self.assertIn("/boot/initramfs.img", drift.unhashed)

    def test_an_unhashed_file_that_only_changed_date_is_reported_as_such(self) -> None:
        before = Baseline(taken_at="2026-09-01T10:00:00", entries={
            "/boot/initramfs.img": Entry("/boot/initramfs.img", size=100, mode=0o600,
                                         mtime=1000.0, uid=0)})
        now = Baseline(entries={
            "/boot/initramfs.img": Entry("/boot/initramfs.img", size=100, mode=0o600,
                                         mtime=99000.0, uid=0)})
        drift = compare(before, now)
        self.assertEqual(drift.of("timestamp")[0].kind, "timestamp")
        self.assertIn("could not be hashed", drift.of("timestamp")[0].detail)


class TestKernelUpdateHeuristic(unittest.TestCase):
    """A package update and a tampered bootloader look different. Roughly."""

    def test_a_kernel_and_its_initramfs_changing_together_looks_routine(self) -> None:
        now = time.time()
        drift = Drift(changes=[
            Change("/boot/vmlinuz-linux", "content", "", now),
            Change("/boot/initramfs-linux.img", "content", "", now + 30),
            Change("/boot/grub/grub.cfg", "content", "", now + 45),
        ])
        self.assertTrue(drift.looks_like_a_kernel_update())

    def test_one_file_changing_on_its_own_does_not(self) -> None:
        drift = Drift(changes=[
            Change("/boot/vmlinuz-linux", "content", "", time.time())])
        self.assertFalse(drift.looks_like_a_kernel_update())

    def test_files_changing_hours_apart_do_not(self) -> None:
        now = time.time()
        drift = Drift(changes=[
            Change("/boot/vmlinuz-linux", "content", "", now),
            Change("/boot/initramfs-linux.img", "content", "", now + 7200),
        ])
        self.assertFalse(drift.looks_like_a_kernel_update())

    def test_two_unrelated_files_changing_together_do_not(self) -> None:
        now = time.time()
        drift = Drift(changes=[
            Change("/boot/EFI/BOOT/bootx64.efi", "content", "", now),
            Change("/boot/EFI/BOOT/extra.efi", "added", "", now + 5),
        ])
        self.assertFalse(drift.looks_like_a_kernel_update())

    def test_changes_outside_boot_are_not_mistaken_for_a_kernel_update(self) -> None:
        now = time.time()
        drift = Drift(changes=[
            Change("/etc/systemd/system/vmlinuz.service", "added", "", now),
            Change("/etc/systemd/system/initramfs.service", "added", "", now + 1),
        ])
        self.assertFalse(drift.looks_like_a_kernel_update())


if __name__ == "__main__":
    unittest.main()
