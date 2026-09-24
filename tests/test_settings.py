"""Application preferences."""

from __future__ import annotations

import json

from .support import TempHomeTestCase

from clamguard.core.settings import DEFAULTS, Settings


class TestSettings(TempHomeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.path = self.tmp / "settings.json"
        self.settings = Settings(self.path)

    def test_defaults_apply_when_nothing_is_stored(self) -> None:
        self.assertEqual(self.settings.str("theme"), DEFAULTS["theme"])
        self.assertEqual(self.settings.bool("close_to_tray"), DEFAULTS["close_to_tray"])
        self.assertEqual(self.settings.int("warn_db_age_days"),
                         DEFAULTS["warn_db_age_days"])

    def test_setting_persists_immediately(self) -> None:
        self.settings.set("theme", "dark")
        self.assertEqual(json.loads(self.path.read_text())["theme"], "dark")
        self.assertEqual(Settings(self.path).str("theme"), "dark")

    def test_setting_the_same_value_changes_nothing(self) -> None:
        seen = []
        self.settings.changed.connect(lambda key, value: seen.append(key))
        self.settings.set("theme", "dark")
        self.settings.set("theme", "dark")
        self.assertEqual(seen, ["theme"])

    def test_update_emits_once_per_changed_key(self) -> None:
        seen = []
        self.settings.changed.connect(lambda key, value: seen.append(key))
        self.settings.update({"theme": "dark", "accent": "teal",
                              "close_to_tray": DEFAULTS["close_to_tray"]})
        self.assertEqual(sorted(seen), ["accent", "theme"])

    def test_reset_restores_the_default(self) -> None:
        self.settings.set("theme", "dark")
        self.settings.reset("theme")
        self.assertEqual(self.settings.str("theme"), DEFAULTS["theme"])

    def test_typed_accessors_survive_a_wrong_type_in_the_file(self) -> None:
        self.path.write_text('{"warn_db_age_days": "not a number", "theme": 42,'
                             ' "quick_scan_paths": "oops"}')
        settings = Settings(self.path)
        self.assertEqual(settings.int("warn_db_age_days"),
                         DEFAULTS["warn_db_age_days"])
        self.assertEqual(settings.str("theme"), DEFAULTS["theme"])
        self.assertEqual(settings.list("quick_scan_paths"), [])

    def test_unknown_keys_in_the_file_are_preserved(self) -> None:
        """So downgrading ClamGuard does not silently discard newer settings."""
        self.path.write_text('{"from_a_newer_version": true}')
        settings = Settings(self.path)
        settings.set("theme", "dark")
        stored = json.loads(self.path.read_text())
        self.assertIn("from_a_newer_version", stored)

    def test_a_corrupt_file_falls_back_to_defaults(self) -> None:
        self.path.write_text("{not json at all")
        self.assertEqual(Settings(self.path).str("theme"), DEFAULTS["theme"])

    def test_a_non_object_file_falls_back_to_defaults(self) -> None:
        self.path.write_text("[1, 2, 3]")
        self.assertEqual(Settings(self.path).str("theme"), DEFAULTS["theme"])

    def test_as_dict_merges_defaults_with_stored_values(self) -> None:
        self.settings.set("theme", "dark")
        merged = self.settings.as_dict()
        self.assertEqual(merged["theme"], "dark")
        self.assertEqual(len(merged), len(DEFAULTS))

    def test_writes_are_atomic(self) -> None:
        """A crash mid-save must not leave a truncated settings file."""
        self.settings.set("theme", "dark")
        self.assertFalse(self.path.with_suffix(".json.tmp").exists())
        json.loads(self.path.read_text())  # parses, so it was written whole
