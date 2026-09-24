"""Parsing freshclam's output."""

from __future__ import annotations

import unittest

from .support import qt_application

from clamguard.core.freshclam import Freshclam, UpdateState
from clamguard.core.privileged import PrivilegedHelper
from clamguard.core.services import ServiceManager

TRANSCRIPT = [
    "ClamAV update process started at Sun Sep 20 02:38:38 2026",
    "daily database available for update (local version: 28128, remote version: 28129)",
    "Downloading daily-28129.cdiff [ 45%]",
    "Downloading daily-28129.cdiff [100%]",
    "Testing database: '/var/lib/clamav/tmp.x/clamav-a.tmp-daily.cld' ...",
    "daily.cld updated (version: 28129, sigs: 355901, f-level: 90, builder: svc)",
    "main.cvd database is up-to-date (version: 63, sigs: 3287027, f-level: 90, "
    "builder: tomjudge)",
    "bytecode.cvd database is up-to-date (version: 339, sigs: 80, f-level: 90, "
    "builder: nrandolp)",
]


class TestOutputParsing(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()
        self.freshclam = Freshclam(PrivilegedHelper(), ServiceManager())
        self.progress: list[tuple[str, int]] = []
        self.freshclam.progress.connect(
            lambda text, percent: self.progress.append((text, percent)))
        self.freshclam._set_state(UpdateState.RUNNING)

    def feed(self, lines) -> None:
        for line in lines:
            self.freshclam._on_line(line)

    def test_a_full_update_run(self) -> None:
        self.feed(TRANSCRIPT)
        self.freshclam._complete(UpdateState.SUCCEEDED)
        result = self.freshclam._result

        self.assertIs(result.state, UpdateState.SUCCEEDED)
        self.assertEqual(len(result.changes), 3)
        self.assertEqual(len(result.updated_databases), 1)

        daily = result.updated_databases[0]
        self.assertEqual(daily.name, "daily")
        self.assertEqual(daily.version, 28129)
        self.assertEqual(daily.previous_version, 28128)
        self.assertEqual(daily.signatures, 355901)
        self.assertEqual(result.headline(), "Updated daily to version 28129.")

    def test_download_percentages_reach_the_progress_bar(self) -> None:
        self.feed(TRANSCRIPT)
        percentages = [percent for _text, percent in self.progress if percent >= 0]
        self.assertIn(45, percentages)
        self.assertIn(100, percentages)

    def test_an_up_to_date_run_says_so(self) -> None:
        self.feed(TRANSCRIPT[-2:])
        self.freshclam._complete(UpdateState.SUCCEEDED)
        result = self.freshclam._result
        self.assertIs(result.state, UpdateState.UP_TO_DATE)
        self.assertEqual(result.headline(), "Signatures are already up to date.")

    def test_several_updates_are_summarised(self) -> None:
        self.feed([
            "daily.cld updated (version: 2, sigs: 10, f-level: 90, builder: x)",
            "main.cvd updated (version: 64, sigs: 20, f-level: 90, builder: y)",
        ])
        self.freshclam._complete(UpdateState.SUCCEEDED)
        self.assertEqual(self.freshclam._result.headline(), "Updated 2 databases.")

    def test_a_lock_error_gets_its_own_explanation(self) -> None:
        self.feed(["ERROR: Failed to lock the log file /var/log/clamav/freshclam.log"])
        message = self.freshclam._result.message
        self.assertIn("automatic updater is already running", message)
        self.assertIn("Protection page", message)

    def test_a_plain_error_is_kept_verbatim(self) -> None:
        self.feed(["ERROR: Can't download daily.cvd from database.clamav.net"])
        self.assertIn("Can't download", self.freshclam._result.message)

    def test_describing_each_database_change(self) -> None:
        self.feed(TRANSCRIPT)
        described = [change.describe() for change in self.freshclam._result.changes]
        self.assertIn("daily updated from version 28128 to 28129.", described)
        self.assertIn("main was already current (version 63).", described)

    def test_blocking_reason_when_the_helper_is_absent(self) -> None:
        reason = Freshclam(PrivilegedHelper(), ServiceManager()).blocking_reason()
        from clamguard.core import paths

        if paths.HELPER_PATH.is_file():
            self.skipTest("the helper is installed on this machine")
        self.assertIn("administrator rights", reason)


if __name__ == "__main__":
    unittest.main()
