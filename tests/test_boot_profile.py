"""The profile: presets, overrides, mutes, and the JSON they live in.

The profile is the answer to "highly customisable" and it is also the thing
that decides what the score says, so these tests care about two properties:
a change the user makes has to survive a restart, and a broken file has to
degrade to defaults rather than taking the page down.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.boot.model import Category, Finding, Severity  # noqa: E402
from clamguard.core.boot.profile import (  # noqa: E402
    BASE_SEVERITIES,
    BASE_THRESHOLDS,
    DEFAULT_PRESET,
    PRESETS,
    Policy,
    Profile,
)


def finding(finding_id: str = "a.b", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(id=finding_id, check_id="a", category=Category.KERNEL,
                   severity=severity, title="t")


class ProfileTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-profile-"))
        self.path = self.tmp / "boot-profile.json"
        self.profile = Profile(self.path)

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def reloaded(self) -> Profile:
        return Profile(self.path)


class TestPresets(unittest.TestCase):
    def test_every_preset_has_a_title_and_an_explanation(self) -> None:
        for name, preset in PRESETS.items():
            with self.subTest(preset=name):
                self.assertTrue(preset.title)
                self.assertTrue(preset.blurb)
                self.assertEqual(preset.name, name)

    def test_a_preset_only_names_thresholds_and_policies_that_exist(self) -> None:
        for name, preset in PRESETS.items():
            with self.subTest(preset=name):
                self.assertEqual(set(preset.thresholds) - set(BASE_THRESHOLDS), set())
                self.assertEqual(set(preset.severities) - set(BASE_SEVERITIES), set())

    def test_the_default_preset_changes_nothing(self) -> None:
        preset = PRESETS[DEFAULT_PRESET]
        self.assertEqual(dict(preset.thresholds), {})
        self.assertEqual(dict(preset.severities), {})

    def test_presets_get_progressively_harsher(self) -> None:
        """The whole point of four presets is that they are ordered."""
        order = ("relaxed", "balanced", "strict", "paranoid")
        for key in ("secure_boot_off", "no_root_encryption", "sysctl_weak",
                    "lockdown_none", "no_mac_lsm"):
            severities = [Policy.for_preset(name).severity(key) for name in order]
            with self.subTest(policy=key):
                self.assertEqual(severities, sorted(severities),
                                 f"{key} is not monotonic across the presets")

    def test_stricter_presets_have_tighter_time_budgets(self) -> None:
        budgets = [Policy.for_preset(name).threshold("boot_total_seconds")
                   for name in ("relaxed", "balanced", "strict", "paranoid")]
        self.assertEqual(budgets, sorted(budgets, reverse=True))

    def test_an_unknown_preset_falls_back_rather_than_raising(self) -> None:
        self.assertEqual(Policy.for_preset("hyperbolic").preset, DEFAULT_PRESET)


class TestPolicy(unittest.TestCase):
    def test_every_policy_key_resolves(self) -> None:
        policy = Policy.for_preset("balanced")
        for key in BASE_SEVERITIES:
            self.assertIsInstance(policy.severity(key), Severity)

    def test_an_unknown_policy_key_is_a_programming_error(self) -> None:
        with self.assertRaises(KeyError):
            Policy.for_preset("balanced").severity("no_such_thing")

    def test_an_unknown_threshold_is_a_programming_error(self) -> None:
        with self.assertRaises(KeyError):
            Policy.for_preset("balanced").threshold("no_such_thing")

    def test_at_least_raises_a_floor_but_never_lowers_one(self) -> None:
        policy = Policy.for_preset("relaxed")
        self.assertIs(policy.at_least("secure_boot_off", Severity.CRITICAL),
                      Severity.CRITICAL)
        self.assertGreaterEqual(policy.at_least("ld_preload", Severity.INFO),
                                Severity.HIGH)

    def test_the_persistence_policies_are_equal_by_design(self) -> None:
        """Where an entry lives says nothing about how bad its command is."""
        policy = Policy.for_preset("balanced")
        severities = {policy.severity(key) for key in
                      ("suspicious_exec", "autostart_suspicious",
                       "cron_suspicious", "profile_script_suspicious")}
        self.assertEqual(len(severities), 1)


class TestPersistence(ProfileTestCase):
    def test_a_fresh_profile_is_not_customised(self) -> None:
        self.assertFalse(self.profile.customised)
        self.assertEqual(self.profile.preset, DEFAULT_PRESET)

    def test_a_preset_change_survives_a_restart(self) -> None:
        self.profile.set_preset("paranoid")
        self.assertEqual(self.reloaded().preset, "paranoid")

    def test_an_unknown_preset_is_not_stored(self) -> None:
        self.profile.set_preset("hyperbolic")
        self.assertEqual(self.profile.preset, DEFAULT_PRESET)

    def test_disabling_a_check_survives_a_restart(self) -> None:
        self.profile.enable_check("kernel.taint", False)
        self.assertFalse(self.reloaded().is_enabled("kernel.taint"))
        self.assertTrue(self.reloaded().is_enabled("kernel.lockdown"))

    def test_a_mute_survives_a_restart_with_its_reason(self) -> None:
        self.profile.mute("firmware.secure-boot.disabled", "no TPM on this board")
        reloaded = self.reloaded()
        self.assertTrue(reloaded.is_muted("firmware.secure-boot.disabled"))
        self.assertEqual(reloaded.mutes["firmware.secure-boot.disabled"].reason,
                         "no TPM on this board")

    def test_a_mute_records_when_it_was_made(self) -> None:
        self.profile.mute("a.b")
        self.assertTrue(self.profile.mutes["a.b"].muted_at)

    def test_unmuting_removes_it(self) -> None:
        self.profile.mute("a.b")
        self.profile.unmute("a.b")
        self.assertFalse(self.reloaded().is_muted("a.b"))

    def test_a_severity_override_survives_a_restart(self) -> None:
        self.profile.override_severity("a.b", Severity.LOW)
        self.assertIs(self.reloaded().severity_overrides["a.b"], Severity.LOW)

    def test_clearing_a_severity_override_removes_it(self) -> None:
        self.profile.override_severity("a.b", Severity.LOW)
        self.profile.override_severity("a.b", None)
        self.assertEqual(self.reloaded().severity_overrides, {})

    def test_a_policy_override_survives_a_restart(self) -> None:
        self.profile.override_policy("secure_boot_off", Severity.CRITICAL)
        self.assertIs(self.reloaded().policy().severity("secure_boot_off"),
                      Severity.CRITICAL)

    def test_an_unknown_policy_cannot_be_overridden(self) -> None:
        with self.assertRaises(KeyError):
            self.profile.override_policy("imaginary", Severity.HIGH)

    def test_a_threshold_override_survives_a_restart(self) -> None:
        self.profile.override_threshold("boot_total_seconds", 12.5)
        self.assertEqual(self.reloaded().policy().threshold("boot_total_seconds"),
                         12.5)

    def test_an_override_wins_over_the_preset(self) -> None:
        self.profile.set_preset("relaxed")
        self.profile.override_policy("secure_boot_off", Severity.CRITICAL)
        self.assertIs(self.profile.policy().severity("secure_boot_off"),
                      Severity.CRITICAL)

    def test_resetting_clears_everything_the_user_changed(self) -> None:
        self.profile.set_preset("paranoid")
        self.profile.enable_check("kernel.taint", False)
        self.profile.mute("a.b")
        self.profile.override_threshold("boot_total_seconds", 10.0)
        self.profile.reset()
        self.assertFalse(self.profile.customised)
        self.assertFalse(self.reloaded().customised)

    def test_the_file_is_readable_json_a_person_could_edit(self) -> None:
        self.profile.set_preset("strict")
        self.profile.mute("a.b", "because")
        data = json.loads(self.path.read_text())
        self.assertEqual(data["preset"], "strict")
        self.assertEqual(data["muted"]["a.b"]["reason"], "because")


class TestBrokenFiles(ProfileTestCase):
    def test_invalid_json_falls_back_to_defaults(self) -> None:
        self.path.write_text("{not json at all")
        self.assertEqual(Profile(self.path).preset, DEFAULT_PRESET)

    def test_a_json_array_instead_of_an_object_is_ignored(self) -> None:
        self.path.write_text("[1, 2, 3]")
        self.assertFalse(Profile(self.path).customised)

    def test_an_unknown_threshold_in_the_file_is_dropped(self) -> None:
        self.path.write_text(json.dumps(
            {"threshold_overrides": {"imaginary": 5, "boot_total_seconds": 30}}))
        loaded = Profile(self.path)
        self.assertNotIn("imaginary", loaded.threshold_overrides)
        self.assertEqual(loaded.threshold_overrides["boot_total_seconds"], 30.0)

    def test_an_unknown_policy_in_the_file_is_dropped(self) -> None:
        self.path.write_text(json.dumps(
            {"policy_overrides": {"imaginary": "high", "secure_boot_off": "low"}}))
        loaded = Profile(self.path)
        self.assertNotIn("imaginary", loaded.policy_overrides)
        self.assertIs(loaded.policy_overrides["secure_boot_off"], Severity.LOW)

    def test_a_non_numeric_threshold_is_dropped(self) -> None:
        self.path.write_text(json.dumps(
            {"threshold_overrides": {"boot_total_seconds": "soon"}}))
        self.assertEqual(Profile(self.path).threshold_overrides, {})

    def test_a_mute_stored_as_a_bare_string_still_loads(self) -> None:
        """An older format, and something a person might write by hand."""
        self.path.write_text(json.dumps({"muted": {"a.b": "because"}}))
        loaded = Profile(self.path)
        self.assertTrue(loaded.is_muted("a.b"))
        self.assertEqual(loaded.mutes["a.b"].reason, "because")


class TestApplyingToFindings(ProfileTestCase):
    def test_an_untouched_finding_comes_back_unchanged(self) -> None:
        original = finding()
        self.assertIs(self.profile.apply_to(original), original)

    def test_a_muted_finding_stops_counting(self) -> None:
        self.profile.mute("a.b", "accepted")
        applied = self.profile.apply_to(finding())
        self.assertTrue(applied.muted)
        self.assertEqual(applied.mute_reason, "accepted")
        self.assertFalse(applied.counts_towards_score)

    def test_an_overridden_finding_remembers_what_it_was(self) -> None:
        self.profile.override_severity("a.b", Severity.INFO)
        applied = self.profile.apply_to(finding("a.b", Severity.CRITICAL))
        self.assertIs(applied.severity, Severity.INFO)
        self.assertIs(applied.original_severity, Severity.CRITICAL)

    def test_a_finding_can_be_both_overridden_and_muted(self) -> None:
        self.profile.override_severity("a.b", Severity.LOW)
        self.profile.mute("a.b", "known")
        applied = self.profile.apply_to(finding())
        self.assertIs(applied.severity, Severity.LOW)
        self.assertTrue(applied.muted)


class TestSummary(ProfileTestCase):
    def test_a_stock_profile_summarises_as_its_preset(self) -> None:
        self.assertEqual(self.profile.summary(), "Balanced")

    def test_the_summary_counts_what_was_changed(self) -> None:
        self.profile.enable_check("kernel.taint", False)
        self.profile.mute("a.b")
        self.profile.override_threshold("boot_total_seconds", 30)
        summary = self.profile.summary()
        self.assertIn("1 check off", summary)
        self.assertIn("1 muted", summary)
        self.assertIn("1 tuned", summary)


if __name__ == "__main__":
    unittest.main()
