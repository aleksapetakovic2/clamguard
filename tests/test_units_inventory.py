"""Parsing `systemctl show`, including every trap a real machine set.

The samples below are verbatim from `systemctl show` on an Arch system running
systemd 261. Each of the awkward ones is here because it broke the parser
first: the root mount that looks like a command-line option, the alias that
answers under a different name, the template with no state, and the ExecStart
whose argv contains bare semicolons.
"""

from __future__ import annotations

import unittest

from .support import REPO_ROOT  # noqa: F401  (puts src/ on the path)

from clamguard.core.units.inventory import (
    PROPERTIES,
    _alias_index,
    _deduplicate,
    _show_arguments,
    build_unit,
    parse_documentation,
    parse_exec,
    parse_show_output,
    parse_timestamp,
)
from clamguard.core.units.model import Enablement, Provenance, UnitKind

CLAMONACC = """\
Id=clamav-clamonacc.service
Names=clamav-clamonacc.service
Requires=sysinit.target system.slice clamav-daemon.service
WantedBy=multi-user.target
Conflicts=shutdown.target
After=basic.target system.slice clamav-daemon.service
Documentation="man:clamonacc(8)" "man:clamd.conf(5)" https://docs.clamav.net/
Description=ClamAV On-Access Scanner
LoadState=loaded
ActiveState=active
SubState=running
FragmentPath=/usr/lib/systemd/system/clamav-clamonacc.service
DropInPaths=/etc/systemd/system/clamav-clamonacc.service.d/override.conf
UnitFileState=enabled
UnitFilePreset=disabled
ActiveEnterTimestamp=Mon 2026-09-21 12:42:56 CEST
ConditionResult=yes
Type=simple
MainPID=901
Result=success
NRestarts=0
ExecMainStatus=0
ExecStart={ path=/usr/sbin/clamonacc ; argv[]=/usr/sbin/clamonacc -F --fdpass \
--log=/var/log/clamav/clamonacc.log ; ignore_errors=no ; start_time=[n/a] ; pid=0 }
MemoryCurrent=8069120
TasksCurrent=7
User=root
"""

#: The one that defeats splitting on ";" — the shell command contains two.
BASH_EXEC = ("{ path=/bin/bash ; argv[]=/bin/bash -c while [ ! -S "
             "/run/clamav/clamd.ctl ]; do sleep 1; done ; ignore_errors=no ; "
             "start_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }")


class TestShowParsing(unittest.TestCase):
    def test_a_record_is_split_on_blank_lines(self) -> None:
        text = "Id=a.service\nDescription=A\n\nId=b.service\nDescription=B\n"
        records = parse_show_output(text)
        self.assertEqual([r["Id"] for r in records], ["a.service", "b.service"])

    def test_a_trailing_record_without_a_blank_line_is_kept(self) -> None:
        records = parse_show_output("Id=only.service\nDescription=X")
        self.assertEqual(len(records), 1)

    def test_empty_output_yields_nothing(self) -> None:
        self.assertEqual(parse_show_output(""), [])
        self.assertEqual(parse_show_output("\n\n\n"), [])

    def test_a_value_may_be_empty(self) -> None:
        records = parse_show_output("Id=a.service\nUser=\n")
        self.assertEqual(records[0]["User"], "")

    def test_a_continuation_line_is_appended_to_the_previous_key(self) -> None:
        """A value containing a newline must not be dropped or become a key."""
        records = parse_show_output("Id=a.service\nDescription=one\n two\n")
        self.assertEqual(records[0]["Description"], "one\n two")
        self.assertEqual(set(records[0]), {"Id", "Description"})


class TestExecParsing(unittest.TestCase):
    def test_a_simple_command_is_unpacked(self) -> None:
        commands = parse_exec(
            "{ path=/usr/bin/true ; argv[]=/usr/bin/true --flag ; ignore_errors=no }")
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].path, "/usr/bin/true")
        self.assertEqual(commands[0].argv, ("/usr/bin/true", "--flag"))

    def test_semicolons_inside_argv_do_not_end_it(self) -> None:
        """The trap. `do sleep 1; done` is argv, not the next struct field."""
        commands = parse_exec(BASH_EXEC)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].path, "/bin/bash")
        self.assertIn("done", commands[0].argv)
        self.assertIn("/run/clamav/clamd.ctl", " ".join(commands[0].argv))
        # And nothing from the struct's own fields leaked into the command.
        self.assertNotIn("ignore_errors=no", commands[0].display)
        self.assertNotIn("start_time=[n/a]", commands[0].display)

    def test_several_commands_in_one_property(self) -> None:
        commands = parse_exec(
            "{ path=/bin/a ; argv[]=/bin/a ; ignore_errors=no } "
            "{ path=/bin/b ; argv[]=/bin/b -x ; ignore_errors=yes }")
        self.assertEqual([c.path for c in commands], ["/bin/a", "/bin/b"])
        self.assertEqual([c.ignore_errors for c in commands], [False, True])

    def test_nothing_in_means_nothing_out(self) -> None:
        self.assertEqual(parse_exec(""), ())
        self.assertEqual(parse_exec("not a struct"), ())


class TestDocumentationParsing(unittest.TestCase):
    def test_quoted_and_bare_entries_mix(self) -> None:
        self.assertEqual(
            parse_documentation('"man:clamonacc(8)" "man:clamd.conf(5)" '
                                'https://docs.clamav.net/'),
            ("man:clamonacc(8)", "man:clamd.conf(5)", "https://docs.clamav.net/"))

    def test_empty_is_empty(self) -> None:
        self.assertEqual(parse_documentation(""), ())


class TestTimestampParsing(unittest.TestCase):
    def test_systemd_format(self) -> None:
        moment = parse_timestamp("Mon 2026-09-21 12:42:56 CEST")
        self.assertIsNotNone(moment)
        self.assertEqual((moment.year, moment.month, moment.day), (2026, 9, 21))
        self.assertEqual((moment.hour, moment.minute, moment.second), (12, 42, 56))

    def test_absent_values_are_none(self) -> None:
        for value in ("", "n/a", "garbage", "Mon"):
            self.assertIsNone(parse_timestamp(value), value)


class TestBuildUnit(unittest.TestCase):
    def setUp(self) -> None:
        self.unit = build_unit(parse_show_output(CLAMONACC)[0])

    def test_the_obvious_fields(self) -> None:
        self.assertEqual(self.unit.id, "clamav-clamonacc.service")
        self.assertEqual(self.unit.description, "ClamAV On-Access Scanner")
        self.assertIs(self.unit.kind, UnitKind.SERVICE)
        self.assertTrue(self.unit.running)
        self.assertFalse(self.unit.failed)
        self.assertEqual(self.unit.main_pid, 901)
        self.assertEqual(self.unit.memory_bytes, 8069120)

    def test_lists_are_split(self) -> None:
        self.assertIn("clamav-daemon.service", self.unit.requires)
        self.assertEqual(self.unit.wanted_by, ("multi-user.target",))

    def test_a_local_drop_in_is_recorded(self) -> None:
        self.assertEqual(
            self.unit.drop_in_paths,
            ("/etc/systemd/system/clamav-clamonacc.service.d/override.conf",))

    def test_enabled_against_a_disabled_preset_is_a_deviation(self) -> None:
        self.assertIs(self.unit.enablement, Enablement.ENABLED)
        self.assertIs(self.unit.preset, Enablement.DISABLED)
        self.assertTrue(self.unit.deviates_from_preset)

    def test_an_absent_numeric_property_is_zero_not_a_crash(self) -> None:
        unit = build_unit({"Id": "x.service", "MemoryCurrent": "[not set]",
                           "CPUUsageNSec": "infinity", "TasksCurrent": ""})
        self.assertEqual((unit.memory_bytes, unit.cpu_nsec, unit.tasks), (0, 0, 0))

    def test_a_missing_unit_reports_its_error_in_plain_words(self) -> None:
        unit = build_unit({
            "Id": "nope.service", "LoadState": "not-found",
            "LoadError": 'org.freedesktop.systemd1.NoSuchUnit "Unit nope.service '
                         'not found."',
        })
        self.assertFalse(unit.exists)
        self.assertEqual(unit.load_error, "Unit nope.service not found.")

    def test_a_record_with_no_id_still_builds(self) -> None:
        unit = build_unit({"Names": "fallback.service"})
        self.assertEqual(unit.id, "fallback.service")
        self.assertEqual(build_unit({}).id, "?")


class TestTemplatesAndInstances(unittest.TestCase):
    def test_an_instance_knows_its_template_and_parameter(self) -> None:
        unit = build_unit({"Id": "getty@tty1.service",
                           "Names": "getty@tty1.service autovt@tty1.service"})
        self.assertEqual(unit.template, "getty@.service")
        self.assertEqual(unit.instance, "tty1")
        self.assertFalse(unit.is_template)
        self.assertEqual(unit.aliases, ("autovt@tty1.service",))

    def test_a_template_itself_is_recognised(self) -> None:
        self.assertTrue(build_unit({"Id": "getty@.service"}).is_template)

    def test_a_plain_unit_has_no_template(self) -> None:
        unit = build_unit({"Id": "sshd.service"})
        self.assertEqual(unit.template, "")
        self.assertEqual(unit.instance, "")


class TestShowArguments(unittest.TestCase):
    def test_the_separator_is_present(self) -> None:
        """Without `--`, `-.mount` is read as an option and the batch fails."""
        arguments = _show_arguments(["-.mount", "a.service"], user=False)
        self.assertIn("--", arguments)
        self.assertLess(arguments.index("--"), arguments.index("-.mount"))

    def test_the_user_scope_is_first(self) -> None:
        arguments = _show_arguments(["a.service"], user=True)
        self.assertEqual(arguments[0], "--user")

    def test_every_property_is_requested_in_one_call(self) -> None:
        arguments = _show_arguments(["a.service"], user=False)
        requested = [a for a in arguments if a.startswith("--property=")]
        self.assertEqual(len(requested), 1)
        for name in ("Id", "Description", "ExecStart", "WantedBy", "UnitFilePreset"):
            self.assertIn(name, requested[0])
        self.assertEqual(len(set(PROPERTIES)), len(PROPERTIES), "duplicate property")


class TestDeduplication(unittest.TestCase):
    def test_a_unit_reached_by_two_names_appears_once(self) -> None:
        """`systemctl show dbus-org.freedesktop.nm-dispatcher.service` answers
        with Id=NetworkManager-dispatcher.service, so a roster holding both
        names produced two identical rows."""
        units = [build_unit({"Id": "NetworkManager-dispatcher.service"}),
                 build_unit({"Id": "NetworkManager-dispatcher.service"}),
                 build_unit({"Id": "other.service"})]
        kept = _deduplicate(units)
        self.assertEqual(sorted(u.id for u in kept),
                         ["NetworkManager-dispatcher.service", "other.service"])

    def test_the_alias_index_points_at_the_canonical_id(self) -> None:
        units = [build_unit({"Id": "dbus-broker.service",
                             "Names": "dbus-broker.service dbus.service"})]
        index = _alias_index(units)
        self.assertEqual(index["dbus.service"], "dbus-broker.service")
        self.assertNotIn("dbus-broker.service", index, "a unit is not its own alias")


class TestProvenance(unittest.TestCase):
    def test_a_packaged_unit(self) -> None:
        unit = build_unit({"Id": "a.service",
                           "FragmentPath": "/usr/lib/systemd/system/a.service"})
        unit.package = "somepackage"
        self.assertIs(unit.provenance, Provenance.PACKAGE)
        self.assertFalse(unit.is_unpackaged)

    def test_a_hand_written_unit_in_etc(self) -> None:
        unit = build_unit({"Id": "a.service",
                           "FragmentPath": "/etc/systemd/system/a.service"})
        self.assertIs(unit.provenance, Provenance.LOCAL)
        self.assertTrue(unit.is_unpackaged)

    def test_a_generated_unit(self) -> None:
        unit = build_unit({"Id": "-.mount", "UnitFileState": "generated",
                           "FragmentPath": "/run/systemd/generator/-.mount"})
        self.assertIs(unit.provenance, Provenance.GENERATED)
        self.assertFalse(unit.is_unpackaged)

    def test_a_login_session_scope_is_transient_not_hand_added(self) -> None:
        """It has a FragmentPath under /run/systemd/transient and no package,
        which classified every logged-in session as "added by hand"."""
        unit = build_unit({"Id": "session-2.scope", "UnitFileState": "transient",
                           "FragmentPath": "/run/systemd/transient/session-2.scope"})
        self.assertIs(unit.provenance, Provenance.TRANSIENT)
        self.assertFalse(unit.is_unpackaged)

    def test_a_device_unit_has_no_file_and_no_verdict(self) -> None:
        unit = build_unit({"Id": "dev-sda.device"})
        self.assertIs(unit.provenance, Provenance.UNKNOWN)
        self.assertFalse(unit.is_unpackaged)


if __name__ == "__main__":
    unittest.main()


class TestQuotedListEntries(unittest.TestCase):
    """`systemctl show` shell-quotes list entries with escaped characters.

    Verbatim from `systemctl show -- -.mount`. Splitting on whitespace kept the
    quotes and the doubled backslash: 87 dependency edges on one desktop named
    units that do not exist, and 98 units listed themselves as their own alias.
    """

    AFTER = ('-.slice "blockdev@dev-disk-by\\\\x2duuid-1d5dc1bc\\\\x2d4d0f'
             '\\\\x2d4992\\\\x2d9864\\\\x2d2445ad3a6e36.target"')

    def test_quotes_and_escapes_are_undone(self) -> None:
        from clamguard.core.units.model import as_list

        self.assertEqual(as_list(self.AFTER), (
            "-.slice",
            "blockdev@dev-disk-by\\x2duuid-1d5dc1bc\\x2d4d0f\\x2d4992\\x2d9864"
            "\\x2d2445ad3a6e36.target"))

    def test_a_unit_is_not_its_own_alias(self) -> None:
        unit = build_unit({
            "Id": "run-user-1000-kio\\x2dfuse\\x2dTLRPGh.mount",
            "Names": '"run-user-1000-kio\\\\x2dfuse\\\\x2dTLRPGh.mount"'})
        self.assertEqual(unit.names, ("run-user-1000-kio\\x2dfuse\\x2dTLRPGh.mount",))
        self.assertEqual(unit.aliases, ())

    def test_plain_lists_are_untouched(self) -> None:
        from clamguard.core.units.model import as_list

        self.assertEqual(as_list("a.service  b.target\tc.socket"),
                         ("a.service", "b.target", "c.socket"))

    def test_unbalanced_quoting_degrades_instead_of_raising(self) -> None:
        from clamguard.core.units.model import as_list

        self.assertEqual(as_list('a.service "broken'), ("a.service", '"broken'))
