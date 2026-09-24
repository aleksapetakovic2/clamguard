"""The synthesis: headlines, structural notes, and which flags actually fire.

The thresholds here were tuned against a real machine's 627 units, and the
numbers in the comments are why they are where they are. A flag that fires on
two thirds of the list conveys nothing, so several of these tests exist to
assert that the *common* case stays quiet.
"""

from __future__ import annotations

import unittest

from .support import REPO_ROOT  # noqa: F401  (puts src/ on the path)

from clamguard.core.units.inventory import build_unit
from clamguard.core.units.model import Exposure, Inventory
from clamguard.core.units.purpose import (
    SLOW_BOOT_SECONDS,
    UNSANDBOXED_SCORE,
    _join,
    describe,
    describe_all,
)


def unit(**fields):
    """A loaded, running service unless told otherwise."""
    base = {"Id": "a.service", "LoadState": "loaded", "ActiveState": "active",
            "SubState": "running"}
    base.update(fields)
    return build_unit(base)


class TestHeadline(unittest.TestCase):
    def test_the_unit_files_own_description_wins(self) -> None:
        item = unit(Description="ClamAV On-Access Scanner")
        item.man_summary = "an anti-virus on-access scanning daemon"
        item.package_summary = "Anti-virus toolkit for Unix"
        purpose = describe(item)
        self.assertEqual(purpose.headline, "ClamAV On-Access Scanner")
        self.assertEqual(purpose.headline_source, "the unit file")

    def test_the_man_page_is_the_fallback(self) -> None:
        item = unit()
        item.man_summary = "network management daemon"
        item.package_summary = "Network connection manager"
        purpose = describe(item)
        self.assertEqual(purpose.headline, "network management daemon")
        self.assertEqual(purpose.headline_source, "its man page")

    def test_the_package_is_the_last_resort(self) -> None:
        item = unit()
        item.package = "networkmanager"
        item.package_summary = "Network connection manager"
        purpose = describe(item)
        self.assertEqual(purpose.headline, "Network connection manager")
        self.assertIn("networkmanager", purpose.headline_source)

    def test_a_description_that_merely_repeats_the_id_is_not_used(self) -> None:
        item = unit(Description="a.service")
        item.man_summary = "the real explanation"
        self.assertEqual(describe(item).headline, "the real explanation")

    def test_a_missing_unit_explains_itself(self) -> None:
        item = build_unit({"Id": "nope.service", "LoadState": "not-found",
                           "LoadError": 'x "Unit nope.service not found."'})
        self.assertIn("not found", describe(item).headline)


class TestStructuralNotes(unittest.TestCase):
    def note_text(self, item) -> str:
        return " ".join(describe(item).notes)

    def test_a_getty_is_explained_as_a_login_prompt(self) -> None:
        self.assertIn("login prompt", self.note_text(unit(Id="getty@tty1.service")))

    def test_a_login_session_scope_is_explained(self) -> None:
        text = self.note_text(unit(Id="session-2.scope"))
        self.assertIn("login session", text)

    def test_a_dbus_activation_alias_is_explained(self) -> None:
        text = self.note_text(unit(Id="dbus-org.freedesktop.login1.service"))
        self.assertIn("activation alias", text)

    def test_a_systemd_unit_is_attributed_to_systemd(self) -> None:
        self.assertIn("systemd itself", self.note_text(unit(Id="systemd-journald.service")))

    def test_a_template_instance_names_its_template(self) -> None:
        text = self.note_text(unit(Id="getty@tty1.service"))
        self.assertIn("getty@.service", text)
        self.assertIn("tty1", text)

    def test_a_socket_activated_service_says_it_is_on_demand(self) -> None:
        text = self.note_text(unit(TriggeredBy="dbus.socket"))
        self.assertIn("on demand", text)
        self.assertIn("dbus.socket", text)

    def test_a_oneshot_says_inactive_is_success(self) -> None:
        text = self.note_text(unit(Type="oneshot", ActiveState="inactive"))
        self.assertIn("success", text)

    def test_only_one_family_note_is_added(self) -> None:
        """A getty is also a template instance; both patterns match, but the
        families list is first-hit-wins so the note is not doubled."""
        notes = describe(unit(Id="getty@tty1.service")).notes
        family_notes = [n for n in notes if "login prompt" in n or "one instance" in n.lower()]
        self.assertEqual(len(family_notes), 1)


class TestReasonsAndDependents(unittest.TestCase):
    def test_wanted_by_is_a_soft_dependency(self) -> None:
        purpose = describe(unit(WantedBy="multi-user.target"))
        joined = " ".join(purpose.reasons)
        self.assertIn("Wanted by", joined)
        self.assertIn("would not stop it", joined)

    def test_required_by_is_a_hard_dependency(self) -> None:
        purpose = describe(unit(RequiredBy="other.service"))
        self.assertIn("cannot start without", " ".join(purpose.reasons))
        self.assertIn("would fail", " ".join(purpose.dependents))

    def test_nothing_depending_on_it_is_said_plainly(self) -> None:
        purpose = describe(unit())
        self.assertIn("Nothing on this machine depends on it",
                      " ".join(purpose.dependents))

    def test_singular_and_plural_agree(self) -> None:
        one = " ".join(describe(unit(WantedBy="a.target")).dependents)
        self.assertIn("1 unit asks for it", one)
        two = " ".join(describe(unit(WantedBy="a.target b.target")).dependents)
        self.assertIn("2 units ask for it", two)

    def test_a_running_orphan_is_called_out(self) -> None:
        reasons = " ".join(describe(unit()).reasons)
        self.assertIn("started by hand", reasons)


class TestFlags(unittest.TestCase):
    def texts(self, item, inventory=None) -> str:
        return " ".join(text for text, _tone in describe(item, inventory).flags)

    def test_a_failed_unit_is_flagged(self) -> None:
        item = unit(ActiveState="failed", ExecMainStatus="1", Result="exit-code")
        self.assertIn("failed", self.texts(item).lower())

    def test_a_deviation_from_the_preset_is_flagged(self) -> None:
        item = unit(UnitFileState="enabled", UnitFilePreset="disabled")
        self.assertIn("Someone changed this", self.texts(item))

    def test_a_local_override_is_flagged(self) -> None:
        item = unit(DropInPaths="/etc/systemd/system/a.service.d/override.conf")
        self.assertIn("Locally modified", self.texts(item))

    def test_a_drop_in_shipped_by_the_package_is_not_flagged(self) -> None:
        item = unit(DropInPaths="/usr/lib/systemd/system/a.service.d/vendor.conf")
        self.assertNotIn("Locally modified", self.texts(item))

    def test_a_hand_added_unit_is_flagged(self) -> None:
        item = unit(FragmentPath="/etc/systemd/system/a.service")
        self.assertIn("No package owns", self.texts(item))

    def test_a_packaged_unit_is_not(self) -> None:
        item = unit(FragmentPath="/usr/lib/systemd/system/a.service")
        item.package = "somepackage"
        self.assertNotIn("No package owns", self.texts(item))

    def test_a_slow_boot_is_flagged_and_a_fast_one_is_not(self) -> None:
        slow = unit()
        slow.boot_seconds = SLOW_BOOT_SECONDS + 1
        self.assertIn("boot", self.texts(slow))
        fast = unit()
        fast.boot_seconds = SLOW_BOOT_SECONDS - 0.1
        self.assertNotIn("of your last boot", self.texts(fast))

    def test_sandboxing_is_flagged_only_for_a_running_root_service(self) -> None:
        """The median scored unit on a desktop is 9.4, so this has to be narrow
        or it fires on most of the list and stops meaning anything."""
        bad = unit(User="root")
        bad.exposure = Exposure("a.service", UNSANDBOXED_SCORE + 0.5, "UNSAFE")
        self.assertIn("sandboxing", self.texts(bad))

        stopped = unit(ActiveState="inactive", User="root")
        stopped.exposure = Exposure("a.service", 9.6, "UNSAFE")
        self.assertNotIn("sandboxing", self.texts(stopped),
                         "a stopped unit's blast radius is theoretical")

        as_user = unit(User="nobody")
        as_user.exposure = Exposure("a.service", 9.6, "UNSAFE")
        self.assertNotIn("sandboxing", self.texts(as_user))

        middling = unit(User="root")
        middling.exposure = Exposure("a.service", UNSANDBOXED_SCORE - 1, "EXPOSED")
        self.assertNotIn("sandboxing", self.texts(middling))

    def test_an_unmet_condition_is_quiet_for_a_static_unit(self) -> None:
        """182 of one machine's units are static with an unmet condition. That
        is how systemd works, not a finding."""
        item = unit(ActiveState="inactive", ConditionResult="no",
                    UnitFileState="static")
        self.assertNotIn("Condition=", self.texts(item))

    def test_an_unmet_condition_is_flagged_when_the_unit_was_enabled(self) -> None:
        item = unit(ActiveState="inactive", ConditionResult="no",
                    UnitFileState="enabled")
        self.assertIn("Condition=", self.texts(item))

    def test_a_healthy_packaged_running_unit_has_no_flags_at_all(self) -> None:
        item = unit(Description="A normal service", UnitFileState="enabled",
                    UnitFilePreset="enabled",
                    FragmentPath="/usr/lib/systemd/system/a.service")
        item.package = "somepackage"
        self.assertEqual(describe(item).flags, (),
                         "the ordinary case must stay silent")


class TestReading(unittest.TestCase):
    def test_man_pages_and_urls_are_both_offered(self) -> None:
        item = unit(Documentation='"man:clamonacc(8)" https://docs.clamav.net/')
        targets = [target for _label, target in describe(item).reading]
        self.assertIn("man:clamonacc(8)", targets)
        self.assertIn("https://docs.clamav.net/", targets)

    def test_the_package_homepage_is_added_once(self) -> None:
        item = unit()
        item.package, item.package_url = "clamav", "https://www.clamav.net/"
        targets = [t for _l, t in describe(item).reading]
        self.assertEqual(targets.count("https://www.clamav.net/"), 1)

    def test_a_homepage_already_in_documentation_is_not_repeated(self) -> None:
        item = unit(Documentation="https://www.clamav.net/")
        item.package, item.package_url = "clamav", "https://www.clamav.net/"
        targets = [t for _l, t in describe(item).reading]
        self.assertEqual(targets.count("https://www.clamav.net/"), 1)


class TestJoin(unittest.TestCase):
    def test_one_two_and_many(self) -> None:
        self.assertEqual(_join(()), "")
        self.assertEqual(_join(("a",)), "a")
        self.assertEqual(_join(("a", "b")), "a and b")
        self.assertEqual(_join(("a", "b", "c")), "a, b and c")

    def test_a_long_list_is_truncated_with_a_count(self) -> None:
        self.assertEqual(_join(tuple("abcdefg"), limit=3), "a, b, c and 4 more")


class TestDescribeAll(unittest.TestCase):
    def test_every_unit_gets_a_purpose(self) -> None:
        inventory = Inventory(units=(unit(Id="a.service"), unit(Id="b.timer")))
        describe_all(inventory)
        for item in inventory:
            self.assertTrue(item.purpose.notes, item.id)


class TestFalseAlarmsFoundOnARealSession(unittest.TestCase):
    """Each of these fired on a real KDE session's 336 units before it was fixed."""

    def texts(self, item) -> str:
        return " ".join(text for text, _tone in describe(item).flags)

    def test_an_exec_condition_skip_is_not_flagged_as_a_failed_run(self) -> None:
        item = unit(Id="app-gnome\\x2dkeyring\\x2dsecrets@autostart.service",
                    ActiveState="inactive", Result="exec-condition")
        self.assertNotIn("rather than success", self.texts(item))
        self.assertIn("Skipped on purpose", " ".join(describe(item).notes))

    def test_a_generated_unit_is_not_flagged(self) -> None:
        """Every fstab mount and desktop autostart entry is generated; 17 of
        them sat under "Worth knowing" with an explanation about /etc/fstab."""
        item = unit(Id="app-blueman@autostart.service", UnitFileState="generated",
                    FragmentPath="/run/user/1000/systemd/generator.late/"
                                 "app-blueman@autostart.service",
                    SourcePath="/etc/xdg/autostart/blueman.desktop")
        self.assertEqual(describe(item).flags, ())
        notes = " ".join(describe(item).notes)
        self.assertIn("desktop autostart entry", notes)
        self.assertIn("/etc/xdg/autostart/blueman.desktop", notes)

    def test_a_session_service_is_not_flagged_as_running_as_root(self) -> None:
        from clamguard.core.units.model import Exposure

        item = unit(Id="dbus-broker.service")
        item.user_manager = True
        item.exposure = Exposure("dbus-broker.service", 9.6, "UNSAFE")
        self.assertNotIn("sandboxing", self.texts(item))

    def test_a_launched_application_is_explained(self) -> None:
        notes = " ".join(describe(unit(Id="app-org.kde.konsole-1234.scope")).notes)
        self.assertIn("application your desktop started", notes)


class TestReadingUsesTheRightManSyntax(unittest.TestCase):
    def test_the_label_puts_the_section_first(self) -> None:
        labels = [label for label, _t in
                  describe(unit(Documentation='"man:clamd.conf(5)"')).reading]
        self.assertIn("man 5 clamd.conf", labels)


if __name__ == "__main__":
    unittest.main()
