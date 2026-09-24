"""The vocabulary: kinds, enablement, state summaries and the inventory index."""

from __future__ import annotations

import unittest

from .support import REPO_ROOT  # noqa: F401  (puts src/ on the path)

from clamguard.core.units.inventory import build_unit
from clamguard.core.units.model import (
    Enablement,
    Exposure,
    Inventory,
    ListeningPort,
    UnitKind,
    as_int,
    as_list,
    clean,
    human_bytes,
    human_duration,
)


class TestUnitKind(unittest.TestCase):
    def test_the_suffix_decides(self) -> None:
        for name, kind in (("a.service", UnitKind.SERVICE),
                           ("a.socket", UnitKind.SOCKET),
                           ("a.timer", UnitKind.TIMER),
                           ("-.mount", UnitKind.MOUNT),
                           ("session-2.scope", UnitKind.SCOPE),
                           ("dev-sda.device", UnitKind.DEVICE)):
            self.assertIs(UnitKind.of(name), kind, name)

    def test_an_unknown_suffix_is_other_not_an_error(self) -> None:
        self.assertIs(UnitKind.of("a.wat"), UnitKind.OTHER)
        self.assertIs(UnitKind.of("nosuffix"), UnitKind.OTHER)

    def test_every_kind_has_a_title_and_all_but_other_a_blurb(self) -> None:
        for kind in UnitKind:
            self.assertTrue(kind.title, kind)
            if kind is not UnitKind.OTHER:
                self.assertTrue(kind.blurb, kind)


class TestEnablement(unittest.TestCase):
    def test_known_and_unknown_values(self) -> None:
        self.assertIs(Enablement.of("enabled"), Enablement.ENABLED)
        self.assertIs(Enablement.of("generated"), Enablement.GENERATED)
        self.assertIs(Enablement.of(""), Enablement.UNKNOWN)
        self.assertIs(Enablement.of("something-new"), Enablement.UNKNOWN)

    def test_which_ones_come_up_on_their_own(self) -> None:
        for value in ("enabled", "enabled-runtime", "static", "generated", "indirect"):
            self.assertTrue(Enablement.of(value).starts_itself, value)
        for value in ("disabled", "masked", "alias", ""):
            self.assertFalse(Enablement.of(value).starts_itself, value)

    def test_every_member_explains_itself(self) -> None:
        for member in Enablement:
            if member is not Enablement.UNKNOWN:
                self.assertTrue(member.explanation, member)


class TestStateSummary(unittest.TestCase):
    def test_running(self) -> None:
        unit = build_unit({"Id": "a.service", "LoadState": "loaded",
                           "ActiveState": "active", "SubState": "running"})
        self.assertEqual(unit.state_summary(), "Running")
        self.assertEqual(unit.tone(), "ok")

    def test_failed_reports_its_exit_code(self) -> None:
        unit = build_unit({"Id": "a.service", "LoadState": "loaded",
                           "ActiveState": "failed", "ExecMainStatus": "3"})
        self.assertEqual(unit.state_summary(), "Failed (exit 3)")
        self.assertEqual(unit.tone(), "danger")

    def test_masked(self) -> None:
        unit = build_unit({"Id": "a.service", "LoadState": "masked",
                           "UnitFileState": "masked"})
        self.assertTrue(unit.masked)
        self.assertEqual(unit.state_summary(), "Masked")

    def test_a_missing_unit_is_neutral_not_alarming(self) -> None:
        unit = build_unit({"Id": "a.service", "LoadState": "not-found"})
        self.assertEqual(unit.state_summary(), "Not found")
        self.assertEqual(unit.tone(), "neutral")

    def test_a_finished_oneshot_is_not_a_failure(self) -> None:
        unit = build_unit({"Id": "a.service", "LoadState": "loaded",
                           "ActiveState": "inactive", "SubState": "dead",
                           "Result": "success", "Type": "oneshot"})
        self.assertEqual(unit.state_summary(), "Inactive")
        self.assertFalse(unit.failed)


class TestPresetDeviation(unittest.TestCase):
    def make(self, state: str, preset: str):
        return build_unit({"Id": "a.service", "LoadState": "loaded",
                           "UnitFileState": state, "UnitFilePreset": preset})

    def test_enabled_against_a_disabled_preset(self) -> None:
        self.assertTrue(self.make("enabled", "disabled").deviates_from_preset)

    def test_disabled_against_an_enabled_preset(self) -> None:
        self.assertTrue(self.make("disabled", "enabled").deviates_from_preset)

    def test_agreement_is_not_a_deviation(self) -> None:
        self.assertFalse(self.make("enabled", "enabled").deviates_from_preset)
        self.assertFalse(self.make("disabled", "disabled").deviates_from_preset)

    def test_static_and_generated_units_cannot_deviate(self) -> None:
        """They have no [Install] section, so a preset is meaningless."""
        for state in ("static", "generated", "transient", "alias", "indirect"):
            self.assertFalse(self.make(state, "disabled").deviates_from_preset, state)

    def test_no_preset_means_no_verdict(self) -> None:
        self.assertFalse(self.make("enabled", "").deviates_from_preset)


class TestExposure(unittest.TestCase):
    def test_tone_bands(self) -> None:
        self.assertEqual(Exposure("a", 1.0, "OK").tone, "ok")
        self.assertEqual(Exposure("a", 5.0, "EXPOSED").tone, "warn")
        self.assertEqual(Exposure("a", 9.6, "UNSAFE").tone, "danger")

    def test_the_explanation_says_which_way_is_better(self) -> None:
        text = Exposure("a", 9.6, "UNSAFE").explanation
        self.assertIn("9.6", text)
        self.assertIn("Lower is better", text)


class TestListeningPort(unittest.TestCase):
    def test_world_reachable_addresses(self) -> None:
        for address in ("0.0.0.0", "*", "::", "[::]"):
            self.assertTrue(ListeningPort("tcp", address, "22").world_reachable, address)

    def test_loopback_is_not_world_reachable(self) -> None:
        self.assertFalse(ListeningPort("tcp", "127.0.0.1", "631").world_reachable)


class TestInventory(unittest.TestCase):
    def setUp(self) -> None:
        self.units = (
            build_unit({"Id": "dbus-broker.service",
                        "Names": "dbus-broker.service dbus.service",
                        "LoadState": "loaded", "ActiveState": "active",
                        "SubState": "running", "UnitFileState": "disabled"}),
            build_unit({"Id": "bad.service", "LoadState": "loaded",
                        "ActiveState": "failed"}),
            build_unit({"Id": "a.timer", "LoadState": "loaded",
                        "ActiveState": "active", "UnitFileState": "enabled"}),
        )
        self.inventory = Inventory(units=self.units,
                                   aliases={"dbus.service": "dbus-broker.service"})

    def test_lookup_by_id(self) -> None:
        self.assertIsNotNone(self.inventory.get("bad.service"))

    def test_lookup_by_alias(self) -> None:
        found = self.inventory.get("dbus.service")
        self.assertIsNotNone(found)
        self.assertEqual(found.id, "dbus-broker.service")

    def test_an_unknown_name_is_none_not_an_error(self) -> None:
        self.assertIsNone(self.inventory.get("nope.service"))

    def test_length_and_iteration(self) -> None:
        self.assertEqual(len(self.inventory), 3)
        self.assertEqual(len(list(self.inventory)), 3)

    def test_filters(self) -> None:
        self.assertEqual([u.id for u in self.inventory.failed()], ["bad.service"])
        self.assertEqual(len(self.inventory.running()), 2)
        self.assertEqual([u.id for u in self.inventory.of_kind(UnitKind.TIMER)],
                         ["a.timer"])

    def test_counts(self) -> None:
        counts = self.inventory.counts()
        self.assertEqual(counts["total"], 3)
        self.assertEqual(counts["running"], 2)
        self.assertEqual(counts["failed"], 1)

    def test_an_empty_inventory_is_usable(self) -> None:
        empty = Inventory()
        self.assertEqual(len(empty), 0)
        self.assertIsNone(empty.get("anything"))
        self.assertEqual(empty.counts()["total"], 0)


class TestHelpers(unittest.TestCase):
    def test_clean_collapses_systemds_dialects_of_nothing(self) -> None:
        for value in ("", "n/a", "[not set]", "(null)", "infinity", "  "):
            self.assertEqual(clean(value), "", repr(value))
        self.assertEqual(clean(" real "), "real")

    def test_as_int_never_raises(self) -> None:
        self.assertEqual(as_int("42"), 42)
        for value in ("", "infinity", "[not set]", "n/a", "abc", None):
            self.assertEqual(as_int(value), 0, repr(value))

    def test_as_list_splits_on_whitespace(self) -> None:
        self.assertEqual(as_list("a.service  b.target"), ("a.service", "b.target"))
        self.assertEqual(as_list(""), ())

    def test_human_bytes(self) -> None:
        self.assertEqual(human_bytes(0), "—")
        self.assertEqual(human_bytes(-1), "—")
        self.assertEqual(human_bytes(512), "512 B")
        self.assertIn("MB", human_bytes(8_069_120))

    def test_human_duration(self) -> None:
        self.assertEqual(human_duration(0), "—")
        self.assertEqual(human_duration(0.5), "500 ms")
        self.assertEqual(human_duration(24.447), "24.4 s")
        self.assertEqual(human_duration(90), "1m 30s")
        self.assertIn("h", human_duration(3700))
        self.assertIn("d", human_duration(90000))


if __name__ == "__main__":
    unittest.main()


class TestScopeAwareness(unittest.TestCase):
    """A session unit is not a system unit with an empty User=.

    36 unit names exist in both trees on an ordinary desktop, so anything that
    turns a unit into a command, or into a privilege judgement, has to know
    which manager it belongs to.
    """

    def system(self, **fields):
        return build_unit({"Id": "dbus-broker.service", **fields})

    def session(self, **fields):
        unit = build_unit({"Id": "dbus-broker.service", **fields})
        unit.user_manager = True
        return unit

    def test_a_session_unit_command_uses_user_and_never_sudo(self) -> None:
        """Without --user, copying "restart dbus-broker.service" off the
        session list would restart the system message bus."""
        command = self.session().systemctl_command("restart")
        self.assertEqual(command, "systemctl --user restart dbus-broker.service")
        self.assertNotIn("sudo", command)

    def test_a_system_unit_change_needs_sudo(self) -> None:
        self.assertEqual(self.system().systemctl_command("restart"),
                         "sudo systemctl restart dbus-broker.service")

    def test_reading_never_needs_sudo(self) -> None:
        for verb in ("status", "cat"):
            self.assertEqual(self.system().systemctl_command(verb),
                             f"systemctl {verb} dbus-broker.service")

    def test_the_journal_command_follows_the_scope(self) -> None:
        self.assertIn("-u dbus-broker.service", self.system().journal_command())
        self.assertIn("--user-unit dbus-broker.service", self.session().journal_command())

    def test_an_empty_user_is_root_only_on_the_system_manager(self) -> None:
        self.assertTrue(self.system().runs_as_root)
        self.assertTrue(self.system(User="root").runs_as_root)
        self.assertFalse(self.system(User="nobody").runs_as_root)
        self.assertFalse(self.session().runs_as_root,
                         "a session unit runs as the person logged in")


class TestManCommand(unittest.TestCase):
    def test_the_section_goes_first(self) -> None:
        """`man clamd.conf 5` asks for a second page called "5" and fails."""
        from clamguard.core.units.model import man_command

        self.assertEqual(man_command("man:clamd.conf(5)"), "man 5 clamd.conf")
        self.assertEqual(man_command("man:systemd.exec(5)"), "man 5 systemd.exec")
        self.assertEqual(man_command("man:clamonacc"), "man clamonacc")


class TestProvenanceAcrossScopes(unittest.TestCase):
    def make(self, path, state="", package="", checked=True):
        unit = build_unit({"Id": "a.service", "FragmentPath": path,
                           "UnitFileState": state})
        unit.package = package
        unit.package_checked = checked
        return unit

    def test_a_unit_in_the_home_directory_is_local(self) -> None:
        from pathlib import Path

        from clamguard.core.units.model import Provenance

        path = str(Path.home() / ".config/systemd/user/a.service")
        self.assertIs(self.make(path).provenance, Provenance.LOCAL)

    def test_the_session_managers_transient_and_generated_units(self) -> None:
        from clamguard.core.units.model import Provenance

        self.assertIs(self.make("/run/user/1000/systemd/transient/app.scope").provenance,
                      Provenance.TRANSIENT)
        self.assertIs(self.make("/run/user/1000/systemd/generator.late/app.service").provenance,
                      Provenance.GENERATED)

    def test_without_a_package_manager_nothing_is_called_unpackaged(self) -> None:
        """On a distribution ClamGuard cannot query, every unit in /usr/lib
        would otherwise be reported as added by hand."""
        from clamguard.core.units.model import Provenance

        unasked = self.make("/usr/lib/systemd/system/a.service", checked=False)
        self.assertIs(unasked.provenance, Provenance.UNKNOWN)
        self.assertFalse(unasked.is_unpackaged)
        asked = self.make("/usr/lib/systemd/system/a.service", checked=True)
        self.assertIs(asked.provenance, Provenance.UNPACKAGED)

    def test_etc_is_local_whether_or_not_anyone_was_asked(self) -> None:
        from clamguard.core.units.model import Provenance

        self.assertIs(self.make("/etc/systemd/system/a.service", checked=False).provenance,
                      Provenance.LOCAL)

    def test_local_drop_ins_include_the_home_directory(self) -> None:
        from pathlib import Path

        home_drop_in = str(Path.home() / ".config/systemd/user/a.service.d/override.conf")
        unit = build_unit({"Id": "a.service", "DropInPaths":
                           f"/usr/lib/systemd/system/a.service.d/vendor.conf "
                           f"/etc/systemd/system/a.service.d/mine.conf {home_drop_in}"})
        self.assertEqual(unit.local_drop_ins,
                         ("/etc/systemd/system/a.service.d/mine.conf", home_drop_in))


class TestSkipped(unittest.TestCase):
    def test_exec_condition_is_a_skip_not_a_failure(self) -> None:
        unit = build_unit({"Id": "app-gnome-keyring@autostart.service",
                           "LoadState": "loaded", "ActiveState": "inactive",
                           "Result": "exec-condition"})
        self.assertTrue(unit.skipped)
        self.assertFalse(unit.failed)

    def test_a_real_bad_result_is_still_a_failure(self) -> None:
        unit = build_unit({"Id": "a.service", "LoadState": "loaded",
                           "ActiveState": "inactive", "Result": "exit-code"})
        self.assertFalse(unit.skipped)
        self.assertTrue(unit.failed)
