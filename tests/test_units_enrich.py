"""The five optional helpers, and what happens when they are missing.

Every sample here is verbatim output from the real tool. None of these tests
run a command: `run` and `which` are replaced, so the suite behaves the same on
a machine with pacman, one with dpkg, and one with neither.
"""

from __future__ import annotations

import importlib
import unittest
from unittest import mock

from .support import REPO_ROOT  # noqa: F401  (puts src/ on the path)

from clamguard.core.process import CommandResult

# `from clamguard.core.units import enrich` gives the *function*: the package's
# __init__ re-exports it, which shadows the submodule of the same name. The
# tests need the module, to replace `run` and `which` inside it.
enrich_module = importlib.import_module("clamguard.core.units.enrich")

from clamguard.core.units.enrich import (
    _colon_fields,
    _duration,
    _man_pages,
    enrich,
)
from clamguard.core.units.inventory import build_unit
from clamguard.core.units.model import Inventory

PACMAN_QO = """\
/usr/lib/systemd/system/ModemManager.service is owned by modemmanager 1.24.2-1
/usr/lib/systemd/system/clamav-daemon.service is owned by clamav 1.5.4-1
"""

PACMAN_QI = """\
Name            : clamav
Version         : 1.5.4-1
Description     : Anti-virus toolkit for Unix
URL             : https://www.clamav.net/

Name            : modemmanager
Version         : 1.24.2-1
Description     : Mobile broadband modem management service
URL             : https://www.freedesktop.org/wiki/Software/ModemManager/
"""

SECURITY = """\
NetworkManager.service                     6.8 MEDIUM    :-|
clamav-clamonacc.service                   9.6 UNSAFE    :-(
systemd-journald.service                   1.0 OK        :-)
"""

BLAME = """\
24.447s archlinux-keyring-wkd-sync.service
 1min 4.552s slow-thing.service
  812ms quick.service
   2.717s dev-nvme0n1p3.device
"""

SS = """\
tcp   LISTEN 0 4096 127.0.0.1:631  0.0.0.0:* users:(("cupsd",pid=4242,fd=7))
tcp   LISTEN 0 4096 0.0.0.0:22     0.0.0.0:* users:(("sshd",pid=999,fd=3))
udp   UNCONN 0 0    127.0.0.54:53  0.0.0.0:*
"""


def ok(stdout: str, code: int = 0) -> CommandResult:
    return CommandResult("x", (), code, stdout, "")


class EnrichCase(unittest.TestCase):
    """Runs `enrich` with a scripted set of tools and captured commands."""

    def run_enrich(self, units, *, tools, outputs, user=False):
        self.calls: list[tuple[str, tuple[str, ...]]] = []

        def fake_which(program):
            return f"/usr/bin/{program}" if program in tools else None

        def fake_run(program, args=(), **kwargs):
            name = program.rpartition("/")[2]
            self.calls.append((name, tuple(args)))
            for key, text in outputs.items():
                if key == name or (isinstance(key, tuple) and key[0] == name
                                   and key[1] in args):
                    return ok(text)
            return ok("")

        inventory = Inventory(units=tuple(units))
        with mock.patch.object(enrich_module, "which", fake_which), \
                mock.patch.object(enrich_module, "run", fake_run):
            found = enrich(inventory, user=user)
        return inventory, found


class TestPackageOwnership(EnrichCase):
    def make_units(self):
        return [
            build_unit({"Id": "clamav-daemon.service",
                        "FragmentPath": "/usr/lib/systemd/system/clamav-daemon.service"}),
            build_unit({"Id": "mine.service",
                        "FragmentPath": "/etc/systemd/system/mine.service"}),
        ]

    def test_pacman_owner_and_description_land_on_the_unit(self) -> None:
        units, found = self.run_enrich(
            self.make_units(), tools={"pacman"},
            outputs={("pacman", "-Qo"): PACMAN_QO, ("pacman", "-Qi"): PACMAN_QI})
        self.assertEqual(units.get("clamav-daemon.service").package, "clamav")
        self.assertEqual(units.get("clamav-daemon.service").package_version, "1.5.4-1")
        self.assertEqual(units.get("clamav-daemon.service").package_summary,
                         "Anti-virus toolkit for Unix")
        self.assertEqual(units.get("clamav-daemon.service").package_url,
                         "https://www.clamav.net/")

    def test_a_path_no_package_claims_stays_empty(self) -> None:
        """pacman exits non-zero when any path is unowned. That is normal, and
        the absence is the finding: nobody installed this unit."""
        units, _ = self.run_enrich(
            self.make_units(), tools={"pacman"},
            outputs={("pacman", "-Qo"): PACMAN_QO, ("pacman", "-Qi"): PACMAN_QI})
        self.assertEqual(units.get("mine.service").package, "")
        self.assertTrue(units.get("mine.service").is_unpackaged)

    def test_dpkg_is_parsed_too(self) -> None:
        units, _ = self.run_enrich(
            self.make_units(), tools={"dpkg", "dpkg-query"},
            outputs={"dpkg": "clamav-daemon: "
                             "/usr/lib/systemd/system/clamav-daemon.service\n",
                     "dpkg-query": "clamav-daemon\t1.5.4\thttps://clamav.net\tAV\n"})
        unit = units.get("clamav-daemon.service")
        self.assertEqual(unit.package, "clamav-daemon")
        self.assertEqual(unit.package_summary, "AV")

    def test_a_diverted_dpkg_path_takes_the_first_package(self) -> None:
        units, _ = self.run_enrich(
            self.make_units(), tools={"dpkg"},
            outputs={"dpkg": "pkg-a, pkg-b: "
                             "/usr/lib/systemd/system/clamav-daemon.service\n"})
        self.assertEqual(units.get("clamav-daemon.service").package, "pkg-a")

    def test_with_no_package_manager_the_page_says_so(self) -> None:
        units, found = self.run_enrich(self.make_units(), tools=set(), outputs={})
        self.assertEqual(units.get("clamav-daemon.service").package, "")
        self.assertTrue(any("package manager" in note for note in found.missing))


class TestManualSummaries(EnrichCase):
    def test_whatis_output_is_attached(self) -> None:
        unit = build_unit({"Id": "clamav-clamonacc.service",
                           "Documentation": '"man:clamonacc(8)"'})
        units, _ = self.run_enrich(
            [unit], tools={"whatis"},
            outputs={"whatis": "clamonacc (8)  - an anti-virus on-access "
                               "scanning daemon and clamd client\n"})
        self.assertEqual(units.get("clamav-clamonacc.service").man_summary,
                         "an anti-virus on-access scanning daemon and clamd client")

    def test_missing_whatis_is_reported_not_hidden(self) -> None:
        _units, found = self.run_enrich(
            [build_unit({"Id": "a.service"})], tools=set(), outputs={})
        self.assertTrue(any("whatis" in note for note in found.missing))


class TestManPageCandidates(unittest.TestCase):
    def test_documentation_comes_first(self) -> None:
        unit = build_unit({
            "Id": "clamav-clamonacc.service",
            "Documentation": '"man:clamonacc(8)" "man:clamd.conf(5)"',
            "ExecStart": "{ path=/usr/sbin/clamonacc ; argv[]=/usr/sbin/clamonacc ; "
                         "ignore_errors=no }"})
        self.assertEqual(_man_pages(unit)[0], "clamonacc")

    def test_the_binary_name_is_the_fallback(self) -> None:
        unit = build_unit({"Id": "sshd.service",
                           "ExecStart": "{ path=/usr/bin/sshd ; argv[]=/usr/bin/sshd "
                                        "-D ; ignore_errors=no }"})
        self.assertIn("sshd", _man_pages(unit))

    def test_the_unit_name_is_the_last_resort(self) -> None:
        self.assertIn("cups", _man_pages(build_unit({"Id": "cups.service"})))

    def test_a_template_instance_drops_its_parameter(self) -> None:
        self.assertIn("getty", _man_pages(build_unit({"Id": "getty@tty1.service"})))


class TestExposureAndBoot(EnrichCase):
    def test_security_scores_are_attached(self) -> None:
        unit = build_unit({"Id": "clamav-clamonacc.service"})
        units, _ = self.run_enrich(
            [unit], tools={"systemd-analyze"},
            outputs={("systemd-analyze", "security"): SECURITY})
        exposure = units.get("clamav-clamonacc.service").exposure
        self.assertIsNotNone(exposure)
        self.assertEqual(exposure.score, 9.6)
        self.assertEqual(exposure.rating, "UNSAFE")
        self.assertEqual(exposure.tone, "danger")

    def test_boot_times_are_attached(self) -> None:
        unit = build_unit({"Id": "archlinux-keyring-wkd-sync.service"})
        units, _ = self.run_enrich(
            [unit], tools={"systemd-analyze"},
            outputs={("systemd-analyze", "blame"): BLAME})
        self.assertAlmostEqual(
            units.get("archlinux-keyring-wkd-sync.service").boot_seconds, 24.447)

    def test_missing_systemd_analyze_is_reported(self) -> None:
        _units, found = self.run_enrich(
            [build_unit({"Id": "a.service"})], tools=set(), outputs={})
        self.assertTrue(any("systemd-analyze" in note for note in found.missing))


class TestDurationParsing(unittest.TestCase):
    def test_every_shape_systemd_analyze_prints(self) -> None:
        self.assertAlmostEqual(_duration("24.447s"), 24.447)
        self.assertAlmostEqual(_duration("812ms"), 0.812)
        self.assertAlmostEqual(_duration("1min 4.552s"), 64.552)
        self.assertAlmostEqual(_duration("2.717s"), 2.717)

    def test_nonsense_is_zero(self) -> None:
        self.assertEqual(_duration(""), 0.0)
        self.assertEqual(_duration("nope"), 0.0)


class TestListeningPorts(EnrichCase):
    def test_ports_are_matched_to_the_units_main_pid(self) -> None:
        unit = build_unit({"Id": "sshd.service", "MainPID": "999"})
        units, _ = self.run_enrich([unit], tools={"ss"}, outputs={"ss": SS})
        ports = units.get("sshd.service").ports
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0].port, "22")
        self.assertTrue(ports[0].world_reachable)

    def test_a_loopback_port_is_not_world_reachable(self) -> None:
        unit = build_unit({"Id": "cups.service", "MainPID": "4242"})
        units, _ = self.run_enrich([unit], tools={"ss"}, outputs={"ss": SS})
        self.assertFalse(units.get("cups.service").ports[0].world_reachable)

    def test_sockets_with_no_attributable_process_say_root_is_needed(self) -> None:
        """Unprivileged, `ss` lists the sockets but names no process for any of
        them. An empty row would read as "nothing is listening"."""
        _units, found = self.run_enrich(
            [build_unit({"Id": "a.service"})], tools={"ss"},
            outputs={"ss": "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n"})
        self.assertTrue(any("needs root" in note for note in found.missing),
                        found.missing)


class TestColonFields(unittest.TestCase):
    def test_pacman_blocks_are_parsed(self) -> None:
        fields = _colon_fields(PACMAN_QI.split("\n\n")[0])
        self.assertEqual(fields["Name"], "clamav")
        self.assertEqual(fields["Description"], "Anti-virus toolkit for Unix")

    def test_a_wrapped_continuation_line_is_joined(self) -> None:
        fields = _colon_fields("Name            : x\n"
                               "Description     : first part\n"
                               "                  second part\n")
        self.assertEqual(fields["Description"], "first part second part")


class TestEnrichIsCheap(EnrichCase):
    def test_one_call_per_tool_not_one_per_unit(self) -> None:
        """The whole point of the batching. 200 units must not be 200 forks."""
        units = [build_unit({"Id": f"u{n}.service",
                             "FragmentPath": f"/usr/lib/systemd/system/u{n}.service"})
                 for n in range(200)]
        _inv, _found = self.run_enrich(
            units, tools={"pacman", "whatis", "systemd-analyze", "ss"},
            outputs={("pacman", "-Qo"): PACMAN_QO})
        by_tool: dict[str, int] = {}
        for name, _args in self.calls:
            by_tool[name] = by_tool.get(name, 0) + 1
        self.assertLessEqual(by_tool.get("pacman", 0), 2, by_tool)
        self.assertLessEqual(by_tool.get("ss", 0), 1, by_tool)
        self.assertLessEqual(by_tool.get("systemd-analyze", 0), 2, by_tool)
        self.assertLess(sum(by_tool.values()), 10, by_tool)


class TestScope(EnrichCase):
    def test_a_session_inventory_asks_the_session_manager(self) -> None:
        """Sandboxing and boot figures are per manager. 36 names exist in both
        trees, so asking the system manager about a session inventory handed
        the session's dbus-broker the system one's numbers."""
        self.run_enrich([build_unit({"Id": "dbus-broker.service"})],
                        tools={"systemd-analyze"}, outputs={}, user=True)
        analyze = [args for name, args in self.calls if name == "systemd-analyze"]
        self.assertTrue(analyze)
        for args in analyze:
            self.assertEqual(args[0], "--user", args)

    def test_a_system_inventory_does_not(self) -> None:
        self.run_enrich([build_unit({"Id": "dbus-broker.service"})],
                        tools={"systemd-analyze"}, outputs={}, user=False)
        for name, args in self.calls:
            if name == "systemd-analyze":
                self.assertNotIn("--user", args)


class TestPackageChecked(EnrichCase):
    def test_units_are_marked_checked_when_a_manager_answered(self) -> None:
        units, found = self.run_enrich(
            [build_unit({"Id": "a.service",
                         "FragmentPath": "/usr/lib/systemd/system/a.service"})],
            tools={"pacman"}, outputs={})
        self.assertEqual(found.package_manager, "pacman")
        self.assertTrue(units.get("a.service").package_checked)
        self.assertTrue(units.get("a.service").is_unpackaged)

    def test_without_a_manager_nothing_is_marked_checked(self) -> None:
        units, found = self.run_enrich(
            [build_unit({"Id": "a.service",
                         "FragmentPath": "/usr/lib/systemd/system/a.service"})],
            tools=set(), outputs={})
        self.assertEqual(found.package_manager, "")
        self.assertFalse(units.get("a.service").package_checked)
        self.assertFalse(units.get("a.service").is_unpackaged,
                         "a unit we could not ask about was called hand-written")


class TestDebianMergedUsr(EnrichCase):
    def test_a_file_dpkg_knows_under_lib_is_found_from_usr_lib(self) -> None:
        """After the /usr merge systemd reports /usr/lib/... while dpkg's
        database still says /lib/..., and `dpkg -S` does not resolve that."""
        units, _ = self.run_enrich(
            [build_unit({"Id": "ssh.service",
                         "FragmentPath": "/usr/lib/systemd/system/ssh.service"})],
            tools={"dpkg"},
            outputs={"dpkg": "openssh-server: /lib/systemd/system/ssh.service\n"})
        self.assertEqual(units.get("ssh.service").package, "openssh-server")
        asked = [args for name, args in self.calls if name == "dpkg"][0]
        self.assertIn("/usr/lib/systemd/system/ssh.service", asked)
        self.assertIn("/lib/systemd/system/ssh.service", asked)

    def test_diversion_lines_are_not_owners(self) -> None:
        units, _ = self.run_enrich(
            [build_unit({"Id": "a.service",
                         "FragmentPath": "/usr/lib/systemd/system/a.service"})],
            tools={"dpkg"},
            outputs={"dpkg": "diversion by foo from: /usr/lib/systemd/system/a.service\n"
                             "diversion by foo to: /usr/lib/systemd/system/a.service.real\n"
                             "realpkg: /usr/lib/systemd/system/a.service\n"})
        self.assertEqual(units.get("a.service").package, "realpkg")


if __name__ == "__main__":
    unittest.main()


class TestPresetRules(unittest.TestCase):
    """Only a rule that names a unit makes its preset a decision.

    The session manager reports "enabled" for any unit no rule mentions, so
    without reading the rules 37 untouched session units on one desktop were
    reported as "someone changed this".
    """

    def setUp(self) -> None:
        import tempfile
        from pathlib import Path

        self.root = Path(tempfile.mkdtemp(prefix="clamguard-preset-"))
        self.etc = self.root / "etc"
        self.usr = self.root / "usr"
        self.etc.mkdir()
        self.usr.mkdir()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.root, ignore_errors=True)

    def patterns(self):
        from clamguard.core.units.enrich import preset_patterns

        return preset_patterns(directories=(str(self.etc), str(self.usr)))

    def test_rules_are_collected_with_their_patterns(self) -> None:
        (self.usr / "90-systemd.preset").write_text(
            "# comment\nenable systemd-tmpfiles-*.service\ndisable *\n\n")
        self.assertEqual(self.patterns(), ["systemd-tmpfiles-*.service", "*"])

    def test_a_file_in_etc_hides_the_same_name_in_usr(self) -> None:
        (self.usr / "50-x.preset").write_text("enable from-usr.service\n")
        (self.etc / "50-x.preset").write_text("enable from-etc.service\n")
        self.assertEqual(self.patterns(), ["from-etc.service"])

    def test_no_readable_directory_means_unknown_not_empty(self) -> None:
        from clamguard.core.units.enrich import preset_patterns

        self.assertIsNone(preset_patterns(directories=(str(self.root / "absent"),)))
        self.assertEqual(self.patterns(), [])     # present, merely empty

    def test_a_unit_no_rule_names_cannot_deviate(self) -> None:
        from clamguard.core.units.enrich import _preset_names

        unit = build_unit({"Id": "dbus-broker.service", "UnitFileState": "disabled",
                           "UnitFilePreset": "enabled"})
        unit.preset_ruled = _preset_names(unit, ["fumon.service"])
        self.assertFalse(unit.preset_ruled)
        self.assertFalse(unit.deviates_from_preset)

    def test_a_catch_all_rule_is_a_real_decision(self) -> None:
        """Arch's system presets end in `disable *`: enabling anything against
        that is exactly the change worth pointing out."""
        from clamguard.core.units.enrich import _preset_names

        unit = build_unit({"Id": "sshd.service", "UnitFileState": "enabled",
                           "UnitFilePreset": "disabled"})
        unit.preset_ruled = _preset_names(unit, ["*"])
        self.assertTrue(unit.deviates_from_preset)

    def test_a_template_rule_covers_its_instances(self) -> None:
        from clamguard.core.units.enrich import _preset_names

        unit = build_unit({"Id": "getty@tty1.service"})
        self.assertTrue(_preset_names(unit, ["getty@.service"]))

    def test_unknown_keeps_the_old_behaviour(self) -> None:
        unit = build_unit({"Id": "a.service", "UnitFileState": "enabled",
                           "UnitFilePreset": "disabled"})
        self.assertIsNone(unit.preset_ruled)
        self.assertTrue(unit.deviates_from_preset)
