"""The on-access diagnosis rules.

These encode facts from ClamAV's documentation, so each test names the rule it
is checking rather than just the function.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from .support import qt_application

from clamguard.core.conf_file import ConfFile
from clamguard.core.diagnostics import (
    Remedy,
    diagnose_on_access,
    diagnose_service,
)
from clamguard.core.services import Role, ServiceStatus

CONF_PATH = Path("/etc/clamav/clamd.conf")

RUNNING = ServiceStatus(role=Role.DAEMON, unit="clamav-daemon.service",
                        load_state="loaded", active_state="active",
                        sub_state="running", unit_file_state="enabled")
ONACC_FAILED = ServiceStatus(role=Role.ONACCESS, unit="clamav-clamonacc.service",
                             load_state="loaded", active_state="failed",
                             sub_state="failed", unit_file_state="enabled",
                             result="exit-code", exit_status=2)


def diagnose(conf_text: str, journal=None, daemon=RUNNING):
    return diagnose_on_access(ConfFile.parse(conf_text), ONACC_FAILED, daemon,
                              journal or [], CONF_PATH)


def ids(found) -> set[str]:
    return {item.id for item in found}


class TestOnAccessRules(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()

    def test_missing_exclusion_is_the_blocking_problem(self) -> None:
        """clamonacc exits 2 unless one of the three exclusions is set."""
        found = diagnose("OnAccessIncludePath /home\n")
        self.assertIn("onaccess-no-exclusion", ids(found))
        problem = next(d for d in found if d.id == "onaccess-no-exclusion")
        self.assertEqual(problem.severity, "danger")
        self.assertTrue(problem.fixable)

    def test_any_of_the_three_exclusions_satisfies_the_check(self) -> None:
        for line in ("OnAccessExcludeUname clamav",
                     "OnAccessExcludeUID 64",
                     "OnAccessExcludeRootUID yes"):
            found = diagnose(f"OnAccessIncludePath /home\n{line}\n")
            self.assertNotIn("onaccess-no-exclusion", ids(found), line)

    def test_the_recommended_fix_excludes_the_daemon_user(self) -> None:
        found = diagnose("User clamav\nOnAccessIncludePath /home\n")
        problem = next(d for d in found if d.id == "onaccess-no-exclusion")
        remedy = problem.recommended_remedy()
        self.assertEqual(remedy.changes, {"OnAccessExcludeUname": ["clamav"]})
        self.assertIn(Role.ONACCESS, remedy.restart)

    def test_the_fix_uses_the_configured_user_not_a_hard_coded_one(self) -> None:
        found = diagnose("User scanner\nOnAccessIncludePath /home\n")
        remedy = next(d for d in found
                      if d.id == "onaccess-no-exclusion").recommended_remedy()
        self.assertEqual(remedy.changes, {"OnAccessExcludeUname": ["scanner"]})

    def test_watching_nothing_is_reported(self) -> None:
        found = diagnose("OnAccessExcludeUname clamav\n")
        self.assertIn("onaccess-nothing-watched", ids(found))

    def test_prevention_does_not_work_with_mount_paths(self) -> None:
        """ClamAV's own config says so; blocking silently does nothing there."""
        found = diagnose(
            "OnAccessExcludeUname clamav\n"
            "OnAccessMountPath /\n"
            "OnAccessIncludePath /home\n"
            "OnAccessPrevention yes\n")
        self.assertIn("onaccess-prevention-mountpath", ids(found))

    def test_no_mount_path_means_no_such_warning(self) -> None:
        found = diagnose(
            "OnAccessExcludeUname clamav\n"
            "OnAccessIncludePath /home\n"
            "OnAccessPrevention yes\n")
        self.assertNotIn("onaccess-prevention-mountpath", ids(found))

    def test_blocking_on_system_directories_is_flagged(self) -> None:
        found = diagnose(
            "OnAccessExcludeUname clamav\n"
            "OnAccessIncludePath /usr\n"
            "OnAccessPrevention yes\n")
        self.assertIn("onaccess-risky-prevention", ids(found))

    def test_home_only_blocking_is_not_flagged(self) -> None:
        found = diagnose(
            "OnAccessExcludeUname clamav\n"
            "OnAccessIncludePath /home/user\n"
            "OnAccessPrevention yes\n")
        self.assertNotIn("onaccess-risky-prevention", ids(found))

    def test_report_only_is_noted_as_information(self) -> None:
        found = diagnose(
            "OnAccessExcludeUname clamav\n"
            "OnAccessIncludePath /home/user\n"
            "OnAccessPrevention no\n")
        problem = next(d for d in found if d.id == "onaccess-report-only")
        self.assertEqual(problem.severity, "info")
        self.assertTrue(problem.recommended_remedy().recommended)

    def test_a_stopped_daemon_is_reported(self) -> None:
        stopped = ServiceStatus(role=Role.DAEMON, unit="clamav-daemon.service",
                                load_state="loaded", active_state="inactive")
        found = diagnose("OnAccessExcludeUname clamav\nOnAccessIncludePath /home\n",
                         daemon=stopped)
        self.assertIn("onaccess-daemon-down", ids(found))

    def test_a_correct_configuration_produces_no_danger(self) -> None:
        found = diagnose(
            "User clamav\n"
            "OnAccessExcludeUname clamav\n"
            "OnAccessIncludePath /home/user\n"
            "OnAccessPrevention yes\n")
        self.assertEqual([d.id for d in found if d.severity == "danger"], [])

    def test_evidence_includes_the_matching_journal_lines(self) -> None:
        journal = [
            "clamonacc: ERROR: Clamonacc: at least one of OnAccessExcludeUID, ...",
            "systemd: clamav-clamonacc.service: Failed with result 'exit-code'.",
        ]
        found = diagnose("OnAccessIncludePath /home\n", journal=journal)
        problem = next(d for d in found if d.id == "onaccess-no-exclusion")
        self.assertTrue(any("at least one of" in line for line in problem.evidence))


class TestRemedyApplication(unittest.TestCase):
    def test_a_remedy_produces_the_configuration_it_promises(self) -> None:
        conf = ConfFile.parse("OnAccessIncludePath /home\nOnAccessPrevention yes\n")
        remedy = Remedy(title="t", explanation="e", file=CONF_PATH,
                        changes={"OnAccessExcludeUname": ["clamav"],
                                 "OnAccessPrevention": False})
        remedy.apply_to(conf)
        self.assertEqual(conf.get_all("OnAccessExcludeUname"), ["clamav"])
        self.assertFalse(conf.get_bool("OnAccessPrevention"))

    def test_a_none_change_removes_the_option(self) -> None:
        conf = ConfFile.parse("OnAccessMountPath /\nOnAccessIncludePath /home\n")
        Remedy(title="t", explanation="e", file=CONF_PATH,
               changes={"OnAccessMountPath": None}).apply_to(conf)
        self.assertFalse(conf.has("OnAccessMountPath"))
        self.assertTrue(conf.has("OnAccessIncludePath"))


class TestServiceDiagnosis(unittest.TestCase):
    def test_a_failed_unit_reports_its_journal(self) -> None:
        found = diagnose_service(Role.DAEMON, ONACC_FAILED,
                                 ["line one", "the actual error"])
        self.assertEqual(found[0].severity, "danger")
        self.assertIn("the actual error", found[0].evidence)

    def test_a_missing_unit_is_information_not_an_error(self) -> None:
        missing = ServiceStatus(role=Role.ONACCESS)
        self.assertEqual(diagnose_service(Role.ONACCESS, missing, [])[0].severity,
                         "info")

    def test_a_masked_unit_is_reported_without_a_fix(self) -> None:
        masked = ServiceStatus(role=Role.DAEMON, unit="clamav-daemon.service",
                               load_state="loaded", active_state="inactive",
                               unit_file_state="masked")
        found = diagnose_service(Role.DAEMON, masked, [])
        self.assertIn("masked", found[0].title)
        self.assertFalse(found[0].fixable)

    def test_a_healthy_unit_produces_nothing(self) -> None:
        self.assertEqual(diagnose_service(Role.DAEMON, RUNNING, []), [])

    def test_a_one_shot_unit_that_succeeded_is_not_a_problem(self) -> None:
        one_shot = ServiceStatus(role=Role.UPDATER, unit="freshclam-once.service",
                                 load_state="loaded", active_state="inactive",
                                 result="success")
        self.assertEqual(diagnose_service(Role.UPDATER, one_shot, []), [])


if __name__ == "__main__":
    unittest.main()
