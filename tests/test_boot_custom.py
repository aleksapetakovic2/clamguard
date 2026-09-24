"""Checks the user writes, and the one thing they must never be able to do.

A JSON file in the checks folder becomes a check. The tests below cover each
of the six kinds, the validation messages a person gets when they typo one,
and — most importantly — that there is no way to express "run this command".
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.boot import custom  # noqa: E402
from clamguard.core.boot.model import Category, Severity  # noqa: E402
from clamguard.core.boot.probe import FakeProbe  # noqa: E402
from clamguard.core.boot.profile import Policy  # noqa: E402
from clamguard.core.boot.registry import run_check  # noqa: E402

POLICY = Policy.for_preset("balanced")


def evaluate(definition_dict: dict, probe) -> list:
    definition = custom.parse(definition_dict, source="test.json")
    check = custom.build(definition)
    outcome = run_check(check, probe, POLICY)
    assert not outcome.error, outcome.error
    return list(outcome.findings), outcome


class TestValidation(unittest.TestCase):
    BASE = {"id": "site.thing", "title": "A thing", "kind": "file_exists",
            "path": "/etc/thing"}

    def test_a_valid_definition_parses(self) -> None:
        definition = custom.parse(self.BASE)
        self.assertEqual(definition.id, "site.thing")
        self.assertIs(definition.category, Category.HARDENING)
        self.assertIs(definition.severity, Severity.MEDIUM)

    def test_a_missing_id_is_named_in_the_error(self) -> None:
        with self.assertRaises(custom.DefinitionError) as caught:
            custom.parse({k: v for k, v in self.BASE.items() if k != "id"})
        self.assertIn("'id'", str(caught.exception))

    def test_an_id_with_spaces_or_capitals_is_refused(self) -> None:
        for bad in ("Site Thing", "site thing", "site/thing", "SITE.THING"):
            with self.subTest(id=bad):
                with self.assertRaises(custom.DefinitionError):
                    custom.parse({**self.BASE, "id": bad})

    def test_an_unknown_kind_lists_the_ones_that_exist(self) -> None:
        with self.assertRaises(custom.DefinitionError) as caught:
            custom.parse({**self.BASE, "kind": "run_command"})
        message = str(caught.exception)
        self.assertIn("sysctl", message)
        self.assertIn("file_contains", message)

    def test_an_unknown_category_is_refused(self) -> None:
        with self.assertRaises(custom.DefinitionError):
            custom.parse({**self.BASE, "category": "quantum"})

    def test_each_kind_insists_on_the_field_it_needs(self) -> None:
        for kind, missing in (("sysctl", "key"), ("file_mode", "path"),
                              ("file_contains", "pattern"),
                              ("cmdline", "parameter"), ("unit_state", "unit")):
            with self.subTest(kind=kind):
                with self.assertRaises(custom.DefinitionError) as caught:
                    custom.parse({"id": "a.b", "title": "t", "kind": kind})
                self.assertIn(missing, str(caught.exception))

    def test_an_invalid_regex_is_reported_rather_than_raised_at_run_time(self) -> None:
        with self.assertRaises(custom.DefinitionError) as caught:
            custom.parse({"id": "a.b", "title": "t", "kind": "file_contains",
                          "path": "/etc/x", "pattern": "([unclosed", "regex": True})
        self.assertIn("regex", str(caught.exception))

    def test_an_enormous_pattern_is_refused(self) -> None:
        with self.assertRaises(custom.DefinitionError) as caught:
            custom.parse({"id": "a.b", "title": "t", "kind": "file_contains",
                          "path": "/etc/x", "pattern": "x" * 500, "regex": True})
        self.assertIn("limit", str(caught.exception))

    def test_a_mode_may_be_written_as_an_octal_string(self) -> None:
        definition = custom.parse({"id": "a.b", "title": "t", "kind": "file_mode",
                                   "path": "/etc/x", "mode": "0600"})
        self.assertEqual(definition.mode, 0o600)

    def test_a_nonsense_mode_is_refused(self) -> None:
        with self.assertRaises(custom.DefinitionError):
            custom.parse({"id": "a.b", "title": "t", "kind": "file_mode",
                          "path": "/etc/x", "mode": "rwxr-xr-x"})

    def test_expect_only_takes_present_or_absent(self) -> None:
        with self.assertRaises(custom.DefinitionError):
            custom.parse({**self.BASE, "expect": "maybe"})

    def test_a_non_object_definition_is_refused(self) -> None:
        with self.assertRaises(custom.DefinitionError):
            custom.parse("just a string")


class TestNoExecution(unittest.TestCase):
    """The property the whole design exists to guarantee."""

    def test_there_is_no_kind_that_runs_a_command(self) -> None:
        for kind in custom.KINDS:
            with self.subTest(kind=kind):
                self.assertNotIn("command", kind)
                self.assertNotIn("exec", kind)
                self.assertNotIn("shell", kind)
                self.assertNotIn("script", kind)

    def test_a_definition_cannot_smuggle_in_a_command(self) -> None:
        definition = custom.parse({
            "id": "a.b", "title": "t", "kind": "file_exists", "path": "/etc/x",
            "command": "rm -rf /", "exec": "rm -rf /", "shell": "rm -rf /",
        })
        for field in ("command", "exec", "shell"):
            self.assertFalse(hasattr(definition, field))

    def test_the_fix_command_is_only_ever_shown(self) -> None:
        findings, _outcome = evaluate(
            {"id": "a.b", "title": "t", "kind": "file_exists",
             "path": "/definitely/not/here", "expect": "present",
             "fix_command": "echo would have run"},
            FakeProbe())
        self.assertEqual(findings[0].fixes[0].command, "echo would have run")

    def test_the_evaluators_only_read(self) -> None:
        """No evaluator may reach for anything that changes state."""
        source = (Path(custom.__file__)).read_text(encoding="utf-8")
        for forbidden in ("subprocess", "os.system", "os.remove", "os.unlink",
                          "open(.*[\"']w", "shutil"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden.replace("(.*[\"']w", "(w"), source)


class TestEvaluation(unittest.TestCase):
    def test_a_satisfied_sysctl_passes(self) -> None:
        findings, _ = evaluate(
            {"id": "a.b", "title": "kptr", "kind": "sysctl",
             "key": "kernel.kptr_restrict", "compare": "ge", "value": "1"},
            FakeProbe(files={"/proc/sys/kernel/kptr_restrict": "2"}))
        self.assertIs(findings[0].severity, Severity.PASS)

    def test_an_unsatisfied_sysctl_fails_at_the_declared_severity(self) -> None:
        findings, _ = evaluate(
            {"id": "a.b", "title": "kptr", "kind": "sysctl", "severity": "high",
             "key": "kernel.kptr_restrict", "compare": "ge", "value": "1"},
            FakeProbe(files={"/proc/sys/kernel/kptr_restrict": "0"}))
        self.assertIs(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].value, "0")

    def test_a_sysctl_this_kernel_does_not_have_is_skipped(self) -> None:
        _findings, outcome = evaluate(
            {"id": "a.b", "title": "x", "kind": "sysctl",
             "key": "kernel.nope", "value": "1"}, FakeProbe())
        self.assertIn("kernel.nope", outcome.skipped)

    def test_file_exists_both_ways_round(self) -> None:
        probe = FakeProbe(files={"/etc/ld.so.preload": "x"})
        present, _ = evaluate({"id": "a.b", "title": "t", "kind": "file_exists",
                               "path": "/etc/ld.so.preload", "expect": "absent"},
                              probe)
        self.assertIs(present[0].severity, Severity.MEDIUM)
        absent, _ = evaluate({"id": "a.c", "title": "t", "kind": "file_exists",
                              "path": "/etc/ld.so.preload", "expect": "present"},
                             probe)
        self.assertIs(absent[0].severity, Severity.PASS)

    def test_file_mode_passes_when_no_extra_bits_are_granted(self) -> None:
        findings, _ = evaluate(
            {"id": "a.b", "title": "t", "kind": "file_mode",
             "path": "/etc/shadow", "mode": "0640"},
            FakeProbe(modes={"/etc/shadow": 0o100600}))
        self.assertIs(findings[0].severity, Severity.PASS)

    def test_file_mode_fails_when_the_file_is_looser(self) -> None:
        findings, _ = evaluate(
            {"id": "a.b", "title": "t", "kind": "file_mode",
             "path": "/etc/shadow", "mode": "0640", "severity": "critical"},
            FakeProbe(modes={"/etc/shadow": 0o100666}))
        self.assertIs(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].value, "0666")

    def test_file_contains_as_plain_text(self) -> None:
        findings, _ = evaluate(
            {"id": "a.b", "title": "t", "kind": "file_contains",
             "path": "/etc/ssh/sshd_config", "pattern": "PermitRootLogin no"},
            FakeProbe(files={"/etc/ssh/sshd_config":
                             "Port 22\nPermitRootLogin no\n"}))
        self.assertIs(findings[0].severity, Severity.PASS)

    def test_file_contains_as_a_regex(self) -> None:
        findings, _ = evaluate(
            {"id": "a.b", "title": "t", "kind": "file_contains",
             "path": "/etc/ssh/sshd_config", "regex": True,
             "pattern": r"^PermitRootLogin\s+no"},
            FakeProbe(files={"/etc/ssh/sshd_config":
                             "Port 22\nPermitRootLogin    no\n"}))
        self.assertIs(findings[0].severity, Severity.PASS)

    def test_the_matching_line_becomes_the_evidence(self) -> None:
        findings, _ = evaluate(
            {"id": "a.b", "title": "t", "kind": "file_contains",
             "path": "/etc/x", "pattern": "needle"},
            FakeProbe(files={"/etc/x": "hay\nthe needle here\nhay\n"}))
        self.assertIn("the needle here", findings[0].evidence[0].content)

    def test_an_unreadable_file_is_skipped_rather_than_failed(self) -> None:
        _findings, outcome = evaluate(
            {"id": "a.b", "title": "t", "kind": "file_contains",
             "path": "/etc/shadow", "pattern": "root"},
            FakeProbe(denied={"/etc/shadow"}))
        self.assertTrue(outcome.skipped)

    def test_a_kernel_parameter_can_be_required_or_forbidden(self) -> None:
        probe = FakeProbe(files={"/proc/cmdline": "root=UUID=x mitigations=off"})
        forbidden, _ = evaluate(
            {"id": "a.b", "title": "t", "kind": "cmdline",
             "parameter": "mitigations", "value": "off", "expect": "absent",
             "severity": "high"}, probe)
        self.assertIs(forbidden[0].severity, Severity.HIGH)
        required, _ = evaluate(
            {"id": "a.c", "title": "t", "kind": "cmdline",
             "parameter": "lockdown", "expect": "present"}, probe)
        self.assertIs(required[0].severity, Severity.MEDIUM)

    def test_a_unit_state_can_be_asserted(self) -> None:
        probe = FakeProbe(commands={
            ("systemctl", "is-active", "firewalld.service"): "active"})
        findings, _ = evaluate(
            {"id": "a.b", "title": "t", "kind": "unit_state",
             "unit": "firewalld.service", "value": "active"}, probe)
        self.assertIs(findings[0].severity, Severity.PASS)

    def test_a_custom_finding_says_where_it_came_from(self) -> None:
        findings, _ = evaluate(
            {"id": "site.x", "title": "Site rule", "kind": "file_exists",
             "path": "/nope", "expect": "present"}, FakeProbe())
        self.assertIn("test.json", findings[0].impact)
        self.assertIn("custom", findings[0].tags)

    def test_a_custom_finding_id_is_derived_from_the_check_id(self) -> None:
        findings, _ = evaluate(
            {"id": "site.x", "title": "t", "kind": "file_exists",
             "path": "/nope", "expect": "present"}, FakeProbe())
        self.assertTrue(findings[0].id.startswith("site.x"))
        self.assertEqual(findings[0].check_id, "site.x")


class TestLoading(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-custom-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_an_empty_directory_loads_nothing_and_complains_about_nothing(self) -> None:
        checks, problems = custom.load(self.tmp)
        self.assertEqual(checks, [])
        self.assertEqual(problems, [])

    def test_a_missing_directory_is_not_an_error(self) -> None:
        checks, problems = custom.load(self.tmp / "nowhere")
        self.assertEqual((checks, problems), ([], []))

    def test_the_shipped_example_is_valid(self) -> None:
        custom.write_example(self.tmp)
        checks, problems = custom.load(self.tmp)
        self.assertEqual(problems, [])
        self.assertEqual(len(checks), 2)

    def test_the_example_is_not_overwritten_if_it_was_edited(self) -> None:
        sample = custom.write_example(self.tmp)
        sample.write_text("[]")
        custom.write_example(self.tmp)
        self.assertEqual(sample.read_text(), "[]")

    def test_a_file_may_hold_one_check_or_a_list_of_them(self) -> None:
        (self.tmp / "one.json").write_text(json.dumps(
            {"id": "a.b", "title": "t", "kind": "file_exists", "path": "/x"}))
        (self.tmp / "many.json").write_text(json.dumps([
            {"id": "c.d", "title": "t", "kind": "file_exists", "path": "/x"},
            {"id": "e.f", "title": "t", "kind": "file_exists", "path": "/x"},
        ]))
        checks, problems = custom.load(self.tmp)
        self.assertEqual(problems, [])
        self.assertEqual({check.id for check in checks}, {"a.b", "c.d", "e.f"})

    def test_a_broken_file_names_itself_and_does_not_stop_the_others(self) -> None:
        (self.tmp / "good.json").write_text(json.dumps(
            {"id": "a.b", "title": "t", "kind": "file_exists", "path": "/x"}))
        (self.tmp / "broken.json").write_text("{not json")
        checks, problems = custom.load(self.tmp)
        self.assertEqual(len(checks), 1)
        self.assertEqual(len(problems), 1)
        self.assertIn("broken.json", problems[0])

    def test_an_invalid_check_inside_a_good_file_is_reported_individually(self) -> None:
        (self.tmp / "mixed.json").write_text(json.dumps([
            {"id": "a.b", "title": "t", "kind": "file_exists", "path": "/x"},
            {"id": "Bad Id", "title": "t", "kind": "file_exists", "path": "/x"},
        ]))
        checks, problems = custom.load(self.tmp)
        self.assertEqual(len(checks), 1)
        self.assertIn("mixed.json", problems[0])

    def test_a_loaded_check_carries_the_metadata_the_checks_tab_shows(self) -> None:
        (self.tmp / "one.json").write_text(json.dumps(
            {"id": "a.b", "title": "A rule", "kind": "sysctl",
             "key": "kernel.kptr_restrict", "value": "1"}))
        check = custom.load(self.tmp)[0][0]
        self.assertEqual(check.title, "A rule")
        self.assertIn("kernel.kptr_restrict", check.inspects)
        self.assertIn("custom", check.tags)


if __name__ == "__main__":
    unittest.main()
