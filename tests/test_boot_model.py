"""The Boot Analyzer's vocabulary: severities, findings, scores, reports.

Nothing here touches the machine. These are the rules the rest of the package
relies on, and the score in particular is the one number a user is likely to
quote at someone, so its arithmetic is pinned down here.
"""

from __future__ import annotations

import unittest
from datetime import datetime

from .support import REPO_ROOT  # noqa: F401  - puts src/ on sys.path

from clamguard.core.boot.model import (  # noqa: E402
    CATEGORY_ORDER,
    BootPhase,
    BootTimings,
    Category,
    Evidence,
    Finding,
    Fix,
    Report,
    Severity,
    SkippedCheck,
    format_age,
    format_duration,
    sort_findings,
)


def make_finding(finding_id: str, severity: Severity,
                 category: Category = Category.KERNEL, **extra) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit(".", 1)[0],
        category=category,
        severity=severity,
        title=extra.pop("title", finding_id),
        **extra,
    )


class TestSeverity(unittest.TestCase):
    def test_severities_order_from_pass_to_critical(self) -> None:
        self.assertLess(Severity.PASS, Severity.INFO)
        self.assertLess(Severity.INFO, Severity.LOW)
        self.assertLess(Severity.LOW, Severity.MEDIUM)
        self.assertLess(Severity.MEDIUM, Severity.HIGH)
        self.assertLess(Severity.HIGH, Severity.CRITICAL)

    def test_only_low_and_above_count_as_a_problem(self) -> None:
        self.assertFalse(Severity.PASS.is_problem)
        self.assertFalse(Severity.INFO.is_problem)
        self.assertTrue(Severity.LOW.is_problem)
        self.assertTrue(Severity.CRITICAL.is_problem)

    def test_every_severity_has_a_label_a_tone_and_an_icon(self) -> None:
        for level in Severity:
            self.assertTrue(level.label)
            self.assertIn(level.tone, ("ok", "info", "warn", "danger"))
            self.assertTrue(level.icon)

    def test_parsing_a_severity_from_a_settings_file(self) -> None:
        self.assertIs(Severity.parse("high"), Severity.HIGH)
        self.assertIs(Severity.parse("  Critical "), Severity.CRITICAL)

    def test_parsing_nonsense_falls_back_rather_than_raising(self) -> None:
        self.assertIs(Severity.parse("catastrophic", Severity.LOW), Severity.LOW)
        self.assertIs(Severity.parse(""), Severity.INFO)


class TestCategory(unittest.TestCase):
    def test_every_category_is_in_the_display_order(self) -> None:
        self.assertEqual(set(Category), set(CATEGORY_ORDER))

    def test_every_category_has_a_title_a_blurb_and_an_icon(self) -> None:
        for category in Category:
            self.assertTrue(category.title)
            self.assertTrue(category.blurb)
            self.assertTrue(category.icon)

    def test_parsing_an_unknown_category_gives_none(self) -> None:
        self.assertIs(Category.parse("firmware"), Category.FIRMWARE)
        self.assertIsNone(Category.parse("quantum"))


class TestFinding(unittest.TestCase):
    def test_a_finding_needs_a_stable_id(self) -> None:
        with self.assertRaises(ValueError):
            make_finding("", Severity.LOW)

    def test_muting_stops_it_counting_but_keeps_it(self) -> None:
        finding = make_finding("a.b", Severity.HIGH).muted_as("known")
        self.assertTrue(finding.muted)
        self.assertFalse(finding.is_problem)
        self.assertFalse(finding.counts_towards_score)
        self.assertEqual(finding.mute_reason, "known")

    def test_changing_severity_remembers_the_original(self) -> None:
        finding = make_finding("a.b", Severity.HIGH).with_severity(Severity.LOW)
        self.assertIs(finding.severity, Severity.LOW)
        self.assertIs(finding.original_severity, Severity.HIGH)

    def test_changing_to_the_same_severity_is_not_recorded_as_an_override(self) -> None:
        finding = make_finding("a.b", Severity.HIGH).with_severity(Severity.HIGH)
        self.assertIsNone(finding.original_severity)

    def test_search_covers_the_id_the_text_and_the_evidence_source(self) -> None:
        finding = make_finding(
            "firmware.secure-boot.disabled", Severity.HIGH,
            title="Secure Boot is off",
            summary="The firmware will run any bootloader.",
            evidence=(Evidence("/sys/firmware/efi/efivars/SecureBoot", "0"),),
        )
        for term in ("secure boot", "SECURE-BOOT", "bootloader", "efivars", "high"):
            with self.subTest(term=term):
                self.assertTrue(finding.matches(term))
        self.assertFalse(finding.matches("apparmor"))

    def test_an_empty_search_matches_everything(self) -> None:
        self.assertTrue(make_finding("a.b", Severity.LOW).matches("   "))

    def test_the_recommended_fix_is_preferred_over_the_first(self) -> None:
        finding = make_finding(
            "a.b", Severity.LOW,
            fixes=(Fix("first"), Fix("second", recommended=True)))
        self.assertEqual(finding.recommended_fix().title, "second")

    def test_a_finding_serialises_every_part_of_itself(self) -> None:
        finding = make_finding(
            "a.b", Severity.MEDIUM, title="t", summary="s", impact="i",
            value="v", expected="e",
            evidence=(Evidence("/proc/cmdline", "quiet"),),
            fixes=(Fix("do it", command="true"),),
        )
        data = finding.to_dict()
        self.assertEqual(data["severity"], "Medium")
        self.assertEqual(data["evidence"][0]["source"], "/proc/cmdline")
        self.assertEqual(data["fixes"][0]["command"], "true")


class TestEvidence(unittest.TestCase):
    def test_short_evidence_is_shown_whole(self) -> None:
        self.assertEqual(Evidence("x", "one\ntwo").preview(), "one\ntwo")

    def test_long_evidence_says_how_much_it_hid(self) -> None:
        preview = Evidence("x", "\n".join(str(n) for n in range(40))).preview()
        self.assertIn("more lines", preview)
        self.assertLess(len(preview.splitlines()), 20)


class TestScoring(unittest.TestCase):
    def test_a_clean_report_scores_one_hundred(self) -> None:
        report = Report(findings=(make_finding("a.b", Severity.PASS),))
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "Solid")

    def test_each_severity_costs_its_published_weight(self) -> None:
        for severity, cost in ((Severity.CRITICAL, 25), (Severity.HIGH, 12),
                               (Severity.MEDIUM, 5), (Severity.LOW, 2),
                               (Severity.INFO, 0)):
            with self.subTest(severity=severity):
                report = Report(findings=(make_finding("a.b", severity),))
                self.assertEqual(report.score, 100 - cost)

    def test_the_score_never_goes_below_zero(self) -> None:
        findings = tuple(make_finding(f"a.{n}", Severity.CRITICAL) for n in range(20))
        self.assertEqual(Report(findings=findings).score, 0)

    def test_muted_findings_cost_nothing(self) -> None:
        report = Report(findings=(
            make_finding("a.b", Severity.CRITICAL).muted_as("accepted"),))
        self.assertEqual(report.score, 100)

    def test_the_arithmetic_shown_adds_up_to_the_score(self) -> None:
        report = Report(findings=(
            make_finding("a.1", Severity.HIGH),
            make_finding("a.2", Severity.HIGH),
            make_finding("a.3", Severity.LOW),
        ))
        total = 100 + sum(change for _label, change in report.score_working())
        self.assertEqual(total, report.score)
        self.assertIn("2 high", report.score_explanation())
        self.assertTrue(report.score_explanation().endswith(str(report.score)))

    def test_the_explanation_is_honest_when_nothing_was_found(self) -> None:
        self.assertEqual(Report().score_explanation(), "100 − nothing = 100")

    def test_grades_follow_the_score(self) -> None:
        for penalty, grade in ((0, "Solid"), (20, "Good"), (40, "Fair"),
                               (50, "Weak"), (80, "Poor")):
            findings = tuple(make_finding(f"a.{n}", Severity.MEDIUM)
                             for n in range(penalty // 5))
            with self.subTest(grade=grade):
                self.assertEqual(Report(findings=findings).grade, grade)


class TestReport(unittest.TestCase):
    def setUp(self) -> None:
        self.report = Report(
            findings=(
                make_finding("k.1", Severity.LOW, Category.KERNEL),
                make_finding("f.1", Severity.CRITICAL, Category.FIRMWARE),
                make_finding("f.2", Severity.PASS, Category.FIRMWARE),
                make_finding("s.1", Severity.HIGH, Category.SERVICES).muted_as("ok"),
            ),
            skipped=(SkippedCheck("x.y", "X", "no UEFI"),),
            started_at=datetime(2026, 9, 21, 10, 0),
        )

    def test_problems_exclude_passes_and_mutes(self) -> None:
        self.assertEqual([item.id for item in self.report.problems()],
                         ["f.1", "k.1"])

    def test_passes_and_mutes_are_still_reachable(self) -> None:
        self.assertEqual([item.id for item in self.report.passes()], ["f.2"])
        self.assertEqual([item.id for item in self.report.muted()], ["s.1"])

    def test_counting_ignores_muted_findings(self) -> None:
        self.assertEqual(self.report.count(Severity.HIGH), 0)
        self.assertEqual(self.report.count(Severity.CRITICAL), 1)

    def test_the_worst_severity_ignores_muted_findings(self) -> None:
        self.assertIs(self.report.worst, Severity.CRITICAL)

    def test_findings_can_be_taken_one_category_at_a_time(self) -> None:
        self.assertEqual([item.id for item in self.report.by_category(Category.FIRMWARE)],
                         ["f.1", "f.2"])

    def test_the_headline_leads_with_the_worst_thing(self) -> None:
        self.assertIn("critical", self.report.headline())

    def test_a_clean_report_says_so_plainly(self) -> None:
        clean = Report(findings=(make_finding("a.b", Severity.PASS),))
        self.assertIn("Nothing to act on", clean.headline())

    def test_an_empty_report_does_not_claim_success(self) -> None:
        self.assertIn("Nothing has been analysed", Report().headline())

    def test_skipped_checks_survive_serialisation(self) -> None:
        data = self.report.to_dict()
        self.assertEqual(data["skipped"][0]["reason"], "no UEFI")

    def test_serialisation_names_the_machine(self) -> None:
        report = Report(hostname="box", kernel="6.1", distribution="Arch")
        data = report.to_dict()
        self.assertEqual(data["hostname"], "box")
        self.assertEqual(data["kernel"], "6.1")


class TestSorting(unittest.TestCase):
    def setUp(self) -> None:
        self.findings = [
            make_finding("p.1", Severity.LOW, Category.PERFORMANCE),
            make_finding("f.1", Severity.LOW, Category.FIRMWARE),
            make_finding("k.1", Severity.HIGH, Category.KERNEL),
        ]

    def test_by_severity_puts_the_worst_first(self) -> None:
        order = [item.id for item in sort_findings(self.findings, "severity")]
        self.assertEqual(order[0], "k.1")

    def test_equal_severities_fall_back_to_category_order(self) -> None:
        order = [item.id for item in sort_findings(self.findings, "severity")]
        self.assertLess(order.index("f.1"), order.index("p.1"))

    def test_by_category_follows_the_display_order(self) -> None:
        order = [item.category for item in sort_findings(self.findings, "category")]
        ranks = [CATEGORY_ORDER.index(category) for category in order]
        self.assertEqual(ranks, sorted(ranks))

    def test_by_check_is_alphabetical(self) -> None:
        order = [item.check_id for item in sort_findings(self.findings, "check")]
        self.assertEqual(order, sorted(order))


class TestBootTimings(unittest.TestCase):
    def test_an_unmeasured_boot_says_so(self) -> None:
        self.assertFalse(BootTimings().measured)

    def test_a_phase_that_was_not_reported_is_zero(self) -> None:
        timings = BootTimings(phases=(BootPhase("kernel", 4.0),), total_seconds=4.0)
        self.assertEqual(timings.phase("firmware"), 0.0)
        self.assertEqual(timings.phase("kernel"), 4.0)

    def test_unit_labels_mention_folded_aliases(self) -> None:
        timings = BootTimings(slowest_units=(("dev-sda.device", 120.0),),
                              unit_aliases={"dev-sda.device": 18})
        self.assertIn("+18 more names", timings.unit_label("dev-sda.device"))
        self.assertEqual(timings.unit_label("other.service"), "other.service")


class TestFormatting(unittest.TestCase):
    def test_durations_read_the_way_a_person_says_them(self) -> None:
        self.assertEqual(format_duration(0.25), "250ms")
        self.assertEqual(format_duration(4.0), "4.0s")
        self.assertEqual(format_duration(91.9), "1m 31s")
        self.assertEqual(format_duration(3700), "1h 01m")

    def test_a_negative_duration_is_not_pretended_to_be_real(self) -> None:
        self.assertEqual(format_duration(-1), "—")

    def test_ages_are_relative(self) -> None:
        import time

        self.assertEqual(format_age(time.time()), "just now")
        self.assertIn("day", format_age(time.time() - 3 * 86400))


if __name__ == "__main__":
    unittest.main()
