"""The four exports, and the one property that matters most about them.

The shell-script export is the interesting one. It contains commands that edit
bootloaders and sysctls, so every single line of it has to arrive commented
out. That is asserted here in three different ways, because it is the sort of
thing a well-meant refactor could quietly undo.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from .support import qt_application  # noqa: F401  - sets sys.path

from clamguard.core.boot import report as export  # noqa: E402
from clamguard.core.boot.model import (  # noqa: E402
    BootPhase,
    BootTimings,
    Category,
    Evidence,
    Finding,
    Fix,
    Reference,
    Report,
    Severity,
    SkippedCheck,
)


def sample_report() -> Report:
    return Report(
        findings=(
            Finding(
                id="firmware.secure-boot.disabled",
                check_id="firmware.secure-boot",
                category=Category.FIRMWARE,
                severity=Severity.HIGH,
                title="Secure Boot is off",
                summary="The firmware will run any bootloader it finds.",
                impact="A bootkit runs before the kernel.",
                value="disabled",
                expected="enabled",
                evidence=(Evidence("/sys/firmware/efi/efivars/SecureBoot", "value = 0",
                                   kind="sysfs"),),
                fixes=(Fix("Turn it on", "In firmware setup.",
                           command="mokutil --sb-state",
                           risk="Unsigned drivers stop loading.",
                           reboot_required=True, recommended=True),),
                references=(Reference("UEFI spec", "https://uefi.org/specifications"),),
            ),
            Finding(
                id="kernel.lockdown.on", check_id="kernel.lockdown",
                category=Category.KERNEL, severity=Severity.PASS,
                title="Kernel lockdown is on", summary="integrity mode",
                value="integrity",
            ),
            Finding(
                id="services.state.degraded", check_id="services.state",
                category=Category.SERVICES, severity=Severity.MEDIUM,
                title="systemd reports the system as degraded",
                summary="A unit failed.",
                fixes=(Fix("List them", command="systemctl --failed"),),
            ),
        ),
        skipped=(SkippedCheck("firmware.revocation", "Revoked signature list",
                              "Secure Boot is off"),),
        facts={"Firmware": "UEFI", "Secure Boot": "disabled"},
        timings=BootTimings(
            phases=(BootPhase("firmware", 24.3), BootPhase("userspace", 33.7)),
            total_seconds=58.0,
            slowest_units=(("slow.service", 20.0),),
        ),
        started_at=datetime(2026, 9, 21, 11, 30),
        duration=2.7,
        hostname="workstation",
        kernel="6.18.52-1-lts",
        distribution="Arch Linux",
        preset="balanced",
    )


class TestMarkdown(unittest.TestCase):
    def setUp(self) -> None:
        self.report = sample_report()
        self.text = export.to_markdown(self.report)

    def test_it_leads_with_the_machine_and_the_score(self) -> None:
        self.assertIn("# Boot analysis — workstation", self.text)
        self.assertIn("Score 83/100", self.text)

    def test_the_arithmetic_is_shown(self) -> None:
        self.assertIn(self.report.score_explanation(), self.text)

    def test_findings_are_grouped_by_area(self) -> None:
        self.assertIn("## Firmware & Secure Boot", self.text)
        self.assertIn("## Services & units", self.text)

    def test_a_fix_arrives_as_a_fenced_command(self) -> None:
        self.assertIn("```bash\nmokutil --sb-state\n```", self.text)

    def test_the_risk_travels_with_the_fix(self) -> None:
        self.assertIn("Unsigned drivers stop loading", self.text)

    def test_evidence_is_included_but_folded_away(self) -> None:
        self.assertIn("<details><summary>Evidence", self.text)
        self.assertIn("value = 0", self.text)

    def test_passes_are_left_out_unless_asked_for(self) -> None:
        self.assertNotIn("Kernel lockdown is on", self.text)
        self.assertIn("Kernel lockdown is on",
                      export.to_markdown(self.report, include_passes=True))

    def test_skipped_checks_are_listed_rather_than_implied_to_have_passed(self) -> None:
        self.assertIn("Checks that did not run", self.text)
        self.assertIn("Secure Boot is off", self.text)

    def test_it_states_that_nothing_was_changed(self) -> None:
        self.assertIn("nothing on this machine was changed", self.text)


class TestJson(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(export.to_json(sample_report()))

    def test_it_is_valid_json_with_the_expected_top_level_keys(self) -> None:
        for key in ("generated", "hostname", "kernel", "score", "grade",
                    "counts", "facts", "findings", "skipped"):
            self.assertIn(key, self.data)

    def test_every_finding_survives_with_its_evidence_and_fixes(self) -> None:
        finding = self.data["findings"][0]
        self.assertEqual(finding["id"], "firmware.secure-boot.disabled")
        self.assertEqual(finding["evidence"][0]["content"], "value = 0")
        self.assertEqual(finding["fixes"][0]["command"], "mokutil --sb-state")

    def test_the_boot_timing_is_included(self) -> None:
        self.assertEqual(self.data["boot_time"]["total_seconds"], 58.0)
        self.assertEqual(self.data["boot_time"]["phases"][0]["name"], "firmware")

    def test_a_report_with_no_timing_says_null_rather_than_zero(self) -> None:
        data = json.loads(export.to_json(Report()))
        self.assertIsNone(data["boot_time"])


class TestHtml(unittest.TestCase):
    def setUp(self) -> None:
        self.html = export.to_html(sample_report())

    def test_it_is_a_complete_document(self) -> None:
        self.assertTrue(self.html.startswith("<!doctype html>"))
        self.assertIn("</html>", self.html)

    def test_it_pulls_in_nothing_from_the_network(self) -> None:
        for marker in ("http://", "https://cdn", "<script", "<link "):
            with self.subTest(marker=marker):
                if marker == "http://":
                    # A reference URL in the body text is fine; a fetched
                    # resource is not.
                    self.assertNotIn('src="http', self.html)
                    self.assertNotIn('href="http://cdn', self.html)
                else:
                    self.assertNotIn(marker, self.html)

    def test_finding_text_is_escaped(self) -> None:
        report = Report(findings=(Finding(
            id="a.b", check_id="a", category=Category.KERNEL,
            severity=Severity.HIGH, title="<script>alert(1)</script>",
            summary="x"),))
        html = export.to_html(report)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_it_works_in_both_light_and_dark(self) -> None:
        self.assertIn("prefers-color-scheme: dark", self.html)

    def test_the_boot_phase_bar_is_drawn(self) -> None:
        self.assertIn('class="bar"', self.html)
        self.assertIn("firmware", self.html)


class TestScript(unittest.TestCase):
    """The export that contains commands. Every one must arrive inert."""

    def setUp(self) -> None:
        self.script = export.to_script(sample_report())

    def test_every_line_is_a_comment_a_blank_or_a_harmless_preamble(self) -> None:
        allowed = {"#!/bin/bash", "set -euo pipefail"}
        for number, line in enumerate(self.script.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped in allowed:
                continue
            with self.subTest(line=number):
                self.assertTrue(
                    stripped.startswith("echo "),
                    f"line {number} would actually run: {line!r}")

    def test_the_suggested_commands_are_present_but_commented(self) -> None:
        self.assertIn("# mokutil --sb-state", self.script)
        self.assertIn("# systemctl --failed", self.script)
        self.assertNotIn("\nmokutil --sb-state", self.script)

    def test_running_it_as_written_does_nothing(self) -> None:
        import subprocess

        path = Path(tempfile.mkdtemp()) / "suggestions.sh"
        try:
            path.write_text(self.script)
            result = subprocess.run(["bash", path], capture_output=True, text=True,
                                    timeout=20, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertIn("Nothing happened", result.stdout)
        finally:
            shutil.rmtree(path.parent, ignore_errors=True)

    def test_it_says_loudly_that_it_is_a_worksheet(self) -> None:
        self.assertIn("EVERY COMMAND BELOW IS COMMENTED OUT", self.script)
        self.assertIn("ClamGuard did not run any of this", self.script)

    def test_each_command_carries_its_reason_and_its_risk(self) -> None:
        self.assertIn("# [High] Secure Boot is off", self.script)
        self.assertIn("RISK:", self.script)

    def test_a_manual_only_fix_appears_as_a_manual_step(self) -> None:
        report = Report(findings=(Finding(
            id="a.b", check_id="a", category=Category.FIRMWARE,
            severity=Severity.HIGH, title="t", summary="s",
            fixes=(Fix("Do it in firmware", manual="Press F2."),
                   Fix("Or this", command="true")),
        ),))
        script = export.to_script(report)
        self.assertIn("Manual step: Press F2.", script)

    def test_a_report_with_nothing_to_suggest_says_so(self) -> None:
        self.assertIn("Nothing to suggest", export.to_script(Report()))


class TestWriting(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-report-"))
        self.report = sample_report()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_every_advertised_format_writes_a_file(self) -> None:
        for name, extension, _description in export.describe_formats():
            with self.subTest(format=name):
                path = export.write(self.report, self.tmp, name)
                self.assertTrue(path.is_file())
                self.assertEqual(path.suffix, f".{extension}")
                self.assertGreater(path.stat().st_size, 100)

    def test_the_filename_names_the_machine_and_the_time(self) -> None:
        path = export.write(self.report, self.tmp, "markdown")
        self.assertIn("workstation", path.name)
        self.assertIn("20260921", path.name)

    def test_an_unknown_format_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            export.write(self.report, self.tmp, "powerpoint")

    def test_every_described_format_can_actually_be_written(self) -> None:
        described = {name for name, _ext, _blurb in export.describe_formats()}
        self.assertEqual(described, set(export.FORMATS))


if __name__ == "__main__":
    unittest.main()
