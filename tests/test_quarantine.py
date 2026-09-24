"""The quarantine vault: neutralisation, restore, delete, integrity."""

from __future__ import annotations

import os
import unittest
from pathlib import Path

from .support import EICAR, REPO_ROOT, TempHomeTestCase

from clamguard.core import quarantine as vault


class TestNeutralisation(unittest.TestCase):
    def test_xor_is_its_own_inverse(self) -> None:
        data = os.urandom(5000)
        self.assertEqual(vault._xor(vault._xor(data, 0), 0), data)

    def test_xor_is_position_dependent(self) -> None:
        """Chunked processing must produce the same bytes as one pass."""
        data = os.urandom(3 * len(vault.NEUTRALISE_KEY) + 7)
        whole = vault._xor(data, 0)
        piecemeal = b"".join(
            vault._xor(data[i:i + 5], i) for i in range(0, len(data), 5)
        )
        self.assertEqual(whole, piecemeal)

    def test_xor_actually_changes_the_bytes(self) -> None:
        self.assertNotEqual(vault._xor(EICAR, 0)[:16], EICAR[:16])

    def test_leading_zero_bytes_survive(self) -> None:
        """The big-integer implementation must not drop leading zeroes."""
        data = b"\x00\x00\x00" + b"payload"
        self.assertEqual(len(vault._xor(data, 0)), len(data))
        self.assertEqual(vault._xor(vault._xor(data, 0), 0), data)

    def test_empty_input(self) -> None:
        self.assertEqual(vault._xor(b"", 0), b"")

    def test_the_helper_uses_the_same_transformation(self) -> None:
        """The GUI and the root helper must agree byte for byte.

        They are separate programs with separate copies of the code, so this
        checks the actual installed helper source rather than trusting that
        someone kept them in step.
        """
        source = (REPO_ROOT / "packaging" / "clamguard-helper").read_text()

        key_line = next(line for line in source.splitlines()
                        if line.startswith("NEUTRALISE_KEY"))
        function = source[source.index("def neutralise"):]
        function = function[:function.index("\n\ndef ")]

        namespace: dict = {}
        exec(compile(f"{key_line}\n\n{function}", "helper", "exec"), namespace)

        data = os.urandom(1000)
        self.assertEqual(namespace["NEUTRALISE_KEY"], vault.NEUTRALISE_KEY,
                         "the helper and the app must share the same key")
        self.assertEqual(namespace["neutralise"](data), vault._xor(data, 0),
                         "a file quarantined by the helper must be restorable by the app")


class TestEntryIds(unittest.TestCase):
    def test_ids_are_sortable_and_unique(self) -> None:
        ids = [vault.new_entry_id() for _ in range(50)]
        self.assertEqual(len(set(ids)), 50)
        self.assertEqual(ids, sorted(ids, key=lambda value: value[:15]) or ids)
        self.assertRegex(ids[0], r"^\d{8}-\d{6}-[0-9a-f]{6}$")


class TestVault(TempHomeTestCase):
    def setUp(self) -> None:
        super().setUp()
        from clamguard.core import quarantine as module
        from clamguard.core.privileged import PrivilegedHelper

        # quarantine.py caches the paths module, so refresh it after the
        # temporary XDG directories were installed.
        import importlib
        importlib.reload(module)
        self.module = module
        self.vault = module.Quarantine(PrivilegedHelper())

    def make_victim(self, name: str = "evil.sh", content: bytes = b"#!/bin/sh\n") -> Path:
        path = self.tmp / name
        path.write_bytes(content)
        path.chmod(0o755)
        return path

    def quarantine(self, path: Path, threat: str = "Unix.Test.Fake-1"):
        captured = {}
        self.vault.quarantine(
            path, threat, scan_id=3, engine="clamscan",
            on_success=lambda entry: captured.setdefault("entry", entry),
            on_error=lambda message: captured.setdefault("error", message))
        return captured

    def test_quarantine_moves_and_records(self) -> None:
        original = self.make_victim()
        content = original.read_bytes()
        result = self.quarantine(original)

        entry = result.get("entry")
        self.assertIsNotNone(entry, result.get("error"))
        self.assertFalse(original.exists(), "the original must be gone")
        self.assertTrue(entry.payload().is_file())
        self.assertEqual(entry.threat, "Unix.Test.Fake-1")
        self.assertEqual(entry.scan_id, 3)
        self.assertEqual(entry.mode, 0o755)
        self.assertNotEqual(entry.payload().read_bytes(), content)
        self.assertEqual(self.vault.count(), 1)

    def test_payload_is_private(self) -> None:
        entry = self.quarantine(self.make_victim())["entry"]
        self.assertEqual(entry.payload().stat().st_mode & 0o777, 0o600)

    def test_metadata_survives_a_reload(self) -> None:
        entry = self.quarantine(self.make_victim())["entry"]
        again = self.vault.entry(entry.id)
        self.assertEqual(again.original_path, entry.original_path)
        self.assertEqual(again.sha256, entry.sha256)

    def test_restore_reproduces_the_original_exactly(self) -> None:
        original = self.make_victim(content=EICAR)
        content = original.read_bytes()
        entry = self.quarantine(original)["entry"]

        restored = {}
        self.vault.restore(
            entry, on_success=lambda path: restored.setdefault("path", path),
            on_error=lambda message: restored.setdefault("error", message))

        self.assertIn("path", restored, restored.get("error"))
        self.assertEqual(original.read_bytes(), content)
        self.assertEqual(original.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.vault.count(), 0)

    def test_restore_refuses_to_overwrite(self) -> None:
        original = self.make_victim()
        entry = self.quarantine(original)["entry"]
        original.write_bytes(b"something else")

        outcome = {}
        self.vault.restore(entry, on_success=lambda p: outcome.setdefault("path", p),
                           on_error=lambda m: outcome.setdefault("error", m))
        self.assertIn("already exists", outcome.get("error", ""))
        self.assertEqual(self.vault.count(), 1, "the entry must stay in the vault")

    def test_restore_to_another_location(self) -> None:
        original = self.make_victim(content=b"payload")
        entry = self.quarantine(original)["entry"]
        elsewhere = self.tmp / "elsewhere" / "recovered.bin"

        outcome = {}
        self.vault.restore(entry, destination=elsewhere,
                           on_success=lambda p: outcome.setdefault("path", p),
                           on_error=lambda m: outcome.setdefault("error", m))
        self.assertIn("path", outcome, outcome.get("error"))
        self.assertEqual(elsewhere.read_bytes(), b"payload")

    def test_delete_removes_everything(self) -> None:
        entry = self.quarantine(self.make_victim())["entry"]
        payload, metadata = entry.payload(), entry.metadata_path()
        self.vault.delete(entry)
        self.assertFalse(payload.exists())
        self.assertFalse(metadata.exists())
        self.assertEqual(self.vault.count(), 0)

    def test_delete_all(self) -> None:
        for index in range(3):
            self.quarantine(self.make_victim(f"sample{index}.bin"))
        self.assertEqual(self.vault.count(), 3)
        self.assertEqual(self.vault.delete_all(), 3)
        self.assertEqual(self.vault.count(), 0)

    def test_verify_detects_tampering(self) -> None:
        entry = self.quarantine(self.make_victim(content=b"a" * 500))["entry"]
        ok, message = self.vault.verify(entry)
        self.assertTrue(ok, message)

        entry.payload().write_bytes(b"tampered")
        ok, message = self.vault.verify(entry)
        self.assertFalse(ok)
        self.assertIn("checksum", message)

    def test_verify_reports_a_missing_payload(self) -> None:
        entry = self.quarantine(self.make_victim())["entry"]
        entry.payload().unlink()
        ok, message = self.vault.verify(entry)
        self.assertFalse(ok)
        self.assertIn("missing", message)

    def test_quarantining_a_directory_is_refused(self) -> None:
        directory = self.tmp / "a-directory"
        directory.mkdir()
        result = self.quarantine(directory)
        self.assertIn("error", result)
        self.assertEqual(self.vault.count(), 0)

    def test_quarantining_a_symlink_is_refused(self) -> None:
        target = self.make_victim("real.bin")
        link = self.tmp / "link.bin"
        link.symlink_to(target)
        result = self.quarantine(link)
        self.assertIn("symlink", result.get("error", ""))
        self.assertTrue(target.exists())

    def test_contains_path(self) -> None:
        original = self.make_victim()
        self.quarantine(original)
        self.assertTrue(self.vault.contains_path(str(original)))
        self.assertFalse(self.vault.contains_path("/somewhere/else"))

    def test_total_bytes(self) -> None:
        self.quarantine(self.make_victim("a.bin", b"x" * 100))
        self.quarantine(self.make_victim("b.bin", b"y" * 250))
        self.assertEqual(self.vault.total_bytes(), 350)

    def test_unreadable_metadata_is_skipped_not_fatal(self) -> None:
        self.quarantine(self.make_victim())
        (self.module.paths.QUARANTINE_META / "broken.json").write_text("{not json")
        self.assertEqual(len(self.vault.entries()), 1)

    def test_large_file_round_trips(self) -> None:
        big = self.make_victim("big.bin", os.urandom(3 * 1024 * 1024 + 13))
        content = big.read_bytes()
        entry = self.quarantine(big)["entry"]
        self.vault.restore(entry, on_success=lambda p: None)
        self.assertEqual(big.read_bytes(), content)


if __name__ == "__main__":
    unittest.main()
