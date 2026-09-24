"""Noticing what the on-access scanner finds.

The pipeline these cover is: a line in clamd's journal -> a parsed detection
-> the repeat filter -> the signal the UI and the history listen to.
"""

from __future__ import annotations

import time
import unittest

from .support import TempHomeTestCase, qt_application

from clamguard.core.realtime import (
    REPEAT_WINDOW_SECONDS,
    RealtimeDetection,
    RealtimeMonitor,
)
from clamguard.core.services import ServiceManager

#: Lines exactly as journald renders them for the clamav-daemon unit.
DETECTION = ("2026-09-20T05:07:52+0200 workstation clamd[107226]: Sun Sep 20 05:07:52 "
             "2026 -> /home/user/Downloads/eicar.com.txt: Eicar-Test-Signature FOUND")
SELFCHECK = ("2026-09-20T05:10:38+0200 workstation clamd[107226]: Sun Sep 20 05:10:38 "
             "2026 -> SelfCheck: Database status OK.")
VIRUS_EVENT = ("2026-09-20T05:07:52+0200 workstation sudo[255207]:     clamav : PWD=/ ; "
               "USER=user ; COMMAND=/usr/bin/notify-send -u critical 'Virus found!' "
               "'Signature detected by clamav: Eicar-Test-Signature in /home/a/x' FOUND")


class TestParsing(unittest.TestCase):
    def test_a_real_detection_line(self) -> None:
        detection = RealtimeMonitor.parse(DETECTION)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.path, "/home/user/Downloads/eicar.com.txt")
        self.assertEqual(detection.threat, "Eicar-Test-Signature")
        self.assertEqual(detection.filename, "eicar.com.txt")

    def test_a_line_without_the_journal_prefix(self) -> None:
        detection = RealtimeMonitor.parse(
            "Sun Sep 20 05:07:52 2026 -> /home/a/x.exe: Win.Trojan.Agent-1 FOUND")
        self.assertEqual(detection.threat, "Win.Trojan.Agent-1")

    def test_a_path_containing_colons(self) -> None:
        detection = RealtimeMonitor.parse(
            "Sun Sep 20 05:07:52 2026 -> /home/a/od: ds: f.bin: Win.Trojan.X-1 FOUND")
        self.assertEqual(detection.path, "/home/a/od: ds: f.bin")
        self.assertEqual(detection.threat, "Win.Trojan.X-1")

    def test_ordinary_daemon_chatter_is_ignored(self) -> None:
        self.assertIsNone(RealtimeMonitor.parse(SELFCHECK))
        self.assertIsNone(RealtimeMonitor.parse(""))
        self.assertIsNone(RealtimeMonitor.parse("Starting ClamAV daemon"))

    def test_the_virus_event_notification_is_not_a_second_detection(self) -> None:
        """clamd's VirusEvent script shells out, and sudo logs to the same unit."""
        self.assertIsNone(RealtimeMonitor.parse(VIRUS_EVENT))

    def test_a_relative_path_is_ignored(self) -> None:
        """Nothing actionable can be shown for a path the user cannot locate."""
        self.assertIsNone(RealtimeMonitor.parse("x.txt: Some.Threat-1 FOUND"))


class TestMonitor(TempHomeTestCase):
    def setUp(self) -> None:
        super().setUp()
        qt_application()
        self.monitor = RealtimeMonitor(ServiceManager())
        self.seen: list[RealtimeDetection] = []
        self.monitor.detected.connect(self.seen.append)

    def test_a_detection_reaches_the_signal(self) -> None:
        self.monitor._on_line(DETECTION)
        self.assertEqual(len(self.seen), 1)
        self.assertEqual(self.seen[0].threat, "Eicar-Test-Signature")

    def test_the_session_list_records_it(self) -> None:
        self.monitor._on_line(DETECTION)
        self.assertEqual(len(self.monitor.history), 1)

    def test_the_same_file_is_reported_once(self) -> None:
        """clamd logs a detection on every single access to the file."""
        for _ in range(5):
            self.monitor._on_line(DETECTION)
        self.assertEqual(len(self.seen), 1)

    def test_a_different_file_is_reported_separately(self) -> None:
        self.monitor._on_line(DETECTION)
        self.monitor._on_line(DETECTION.replace("eicar.com.txt", "other.txt"))
        self.assertEqual(len(self.seen), 2)

    def test_the_repeat_filter_expires(self) -> None:
        self.monitor._on_line(DETECTION)
        key = ("/home/user/Downloads/eicar.com.txt", "Eicar-Test-Signature")
        self.monitor._recent[key] = time.monotonic() - REPEAT_WINDOW_SECONDS - 1
        self.monitor._on_line(DETECTION)
        self.assertEqual(len(self.seen), 2)

    def test_forget_lets_a_file_be_reported_again(self) -> None:
        """After quarantining, a file coming back should raise a fresh alert."""
        self.monitor._on_line(DETECTION)
        self.monitor.forget("/home/user/Downloads/eicar.com.txt")
        self.assertEqual(self.monitor.history, [])
        self.monitor._on_line(DETECTION)
        self.assertEqual(len(self.seen), 2)

    def test_our_own_scans_do_not_count_as_real_time_catches(self) -> None:
        """A daemon scan ClamGuard started reports its own results already."""
        self.monitor.suppress(60)
        self.monitor._on_line(DETECTION)
        self.assertEqual(self.seen, [])

    def test_suppression_lifts_after_the_grace_period(self) -> None:
        self.monitor.suppress(60)
        self.monitor.resume_after(0.0)
        self.monitor._on_line(DETECTION)
        self.assertEqual(len(self.seen), 1)

    def test_the_session_list_is_bounded(self) -> None:
        for index in range(260):
            self.monitor._on_line(DETECTION.replace("eicar.com.txt", f"f{index}.txt"))
        self.assertEqual(len(self.monitor.history), 200)

    def test_the_repeat_filter_is_bounded(self) -> None:
        for index in range(700):
            self.monitor._on_line(DETECTION.replace("eicar.com.txt", f"f{index}.txt"))
        self.assertLessEqual(len(self.monitor._recent), 700)

    def test_it_reports_why_it_cannot_run(self) -> None:
        reason = self.monitor.unavailable_reason()
        if reason:
            self.assertTrue(reason.endswith("."), reason)

    def test_the_follow_command_names_the_daemon_unit(self) -> None:
        unit = self.monitor.services.unit_for(
            __import__("clamguard.core.services", fromlist=["Role"]).Role.DAEMON)
        if not unit:
            self.skipTest("no ClamAV daemon unit on this machine")
        _program, arguments = self.monitor.follow_command()
        self.assertIn("--follow", arguments)
        self.assertIn(unit, arguments)
        self.assertIn("--since", arguments)


class TestHistoryIntegration(TempHomeTestCase):
    def setUp(self) -> None:
        super().setUp()
        qt_application()
        from clamguard.core.history import History

        self.history = History(self.tmp / "history.db")

    def test_detections_collect_under_one_session_row(self) -> None:
        first = self.history.realtime_scan_id()
        second = self.history.realtime_scan_id()
        self.assertEqual(first, second, "one row per session, not one per detection")

        self.history.add_detection(first, "/home/a/x", "Threat.One")
        self.history.add_detection(first, "/home/a/y", "Threat.Two")
        self.assertEqual(len(self.history.detections_for(first)), 2)

    def test_the_realtime_row_is_marked_as_such(self) -> None:
        record = self.history.scan(self.history.realtime_scan_id())
        self.assertTrue(record.is_realtime)
        self.assertEqual(record.outcome(), "Watching")

    def test_it_does_not_masquerade_as_the_last_scan(self) -> None:
        """The dashboard must still report the last scan the user actually ran."""
        scan_id = self.history.start_scan("quick", ["/home"])
        self.history.finish_scan(scan_id, status="completed")
        self.history.realtime_scan_id()
        self.assertEqual(self.history.last_scan().id, scan_id)

    def test_closing_the_session_records_the_total(self) -> None:
        realtime_id = self.history.realtime_scan_id()
        self.history.add_detection(realtime_id, "/home/a/x", "T")
        self.history.close_realtime_scan(1)
        record = self.history.scan(realtime_id)
        self.assertEqual(record.status, "completed")
        self.assertEqual(record.threats_found, 1)

    def test_closing_with_nothing_open_is_harmless(self) -> None:
        self.history.close_realtime_scan(0)


if __name__ == "__main__":
    unittest.main()
