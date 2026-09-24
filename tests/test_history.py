"""The scan history database."""

from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timedelta

from .support import TempHomeTestCase

from clamguard.core.history import History


class TestHistory(TempHomeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.history = History(self.tmp / "history.db")

    def record(self, *, threats: int = 0, kind: str = "quick",
               targets=None, status: str = "completed") -> int:
        scan_id = self.history.start_scan(kind, targets or ["/home/test"],
                                          profile="balanced", engine="clamdscan")
        for index in range(threats):
            self.history.add_detection(scan_id, f"/home/test/bad{index}",
                                       "Eicar-Test-Signature", file_size=68)
        self.history.finish_scan(scan_id, status=status, files_scanned=100,
                                 bytes_scanned=4096, threats_found=threats,
                                 duration=1.5, summary="done")
        return scan_id

    # -- writing ----------------------------------------------------------

    def test_a_scan_round_trips(self) -> None:
        scan_id = self.record(threats=2)
        record = self.history.scan(scan_id)
        self.assertEqual(record.kind, "quick")
        self.assertEqual(record.engine, "clamdscan")
        self.assertEqual(record.threats_found, 2)
        self.assertEqual(record.files_scanned, 100)
        self.assertEqual(record.targets, ["/home/test"])
        self.assertEqual(record.status, "completed")

    def test_a_running_scan_is_visible_before_it_finishes(self) -> None:
        scan_id = self.history.start_scan("full", ["/"])
        record = self.history.scan(scan_id)
        self.assertEqual(record.status, "running")
        self.assertEqual(record.outcome(), "In progress")
        self.assertEqual(record.tone, "info")

    def test_detections_are_linked_to_their_scan(self) -> None:
        scan_id = self.record(threats=3)
        detections = self.history.detections_for(scan_id)
        self.assertEqual(len(detections), 3)
        self.assertEqual(detections[0].threat, "Eicar-Test-Signature")
        self.assertEqual(detections[0].filename, "bad0")

    def test_deleting_a_scan_removes_its_detections(self) -> None:
        scan_id = self.record(threats=2)
        self.history.delete_scan(scan_id)
        self.assertEqual(self.history.detections_for(scan_id), [])
        self.assertEqual(self.history.totals()["detections"], 0)

    def test_recording_an_action_on_a_detection(self) -> None:
        scan_id = self.record(threats=1)
        detection = self.history.detections_for(scan_id)[0]
        self.history.set_detection_action(detection.id, "quarantined", "abc123")
        updated = self.history.detections_for(scan_id)[0]
        self.assertEqual(updated.action, "quarantined")
        self.assertEqual(updated.quarantine_id, "abc123")

    # -- reading ----------------------------------------------------------

    def test_last_scan_is_the_most_recent_finished_one(self) -> None:
        self.record(kind="quick")
        latest = self.record(kind="full")
        self.history.start_scan("home", ["/home"])  # still running
        self.assertEqual(self.history.last_scan().id, latest)

    def test_totals(self) -> None:
        self.record(threats=1)
        self.record(threats=2)
        totals = self.history.totals()
        self.assertEqual(totals["scans"], 2)
        self.assertEqual(totals["threats"], 3)
        self.assertEqual(totals["detections"], 3)
        self.assertEqual(totals["files"], 200)

    def test_empty_database_reports_zeroes(self) -> None:
        self.assertEqual(self.history.totals()["scans"], 0)
        self.assertIsNone(self.history.last_scan())
        self.assertEqual(self.history.recent_scans(), [])

    def test_search_by_kind(self) -> None:
        self.record(kind="quick")
        self.record(kind="full")
        self.assertEqual(len(self.history.search_scans(kind="full")), 1)
        self.assertEqual(len(self.history.search_scans()), 2)

    def test_search_by_text_matches_targets(self) -> None:
        self.record(targets=["/srv/uploads"])
        self.record(targets=["/home/other"])
        found = self.history.search_scans(text="uploads")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].targets, ["/srv/uploads"])

    def test_search_for_scans_with_detections(self) -> None:
        self.record(threats=0)
        self.record(threats=1)
        self.assertEqual(len(self.history.search_scans(threats_only=True)), 1)

    def test_detection_search(self) -> None:
        self.record(threats=1)
        self.assertEqual(len(self.history.search_detections("Eicar")), 1)
        self.assertEqual(len(self.history.search_detections("bad0")), 1)
        self.assertEqual(len(self.history.search_detections("nothing")), 0)

    def test_detection_count_for_a_repeated_path(self) -> None:
        for _ in range(3):
            scan_id = self.history.start_scan("quick", ["/tmp"])
            self.history.add_detection(scan_id, "/tmp/recurring", "X")
            self.history.finish_scan(scan_id, status="completed", threats_found=1)
        self.assertEqual(self.history.detection_count_for_path("/tmp/recurring"), 3)
        self.assertEqual(self.history.detection_count_for_path("/tmp/other"), 0)

    def test_daily_counts(self) -> None:
        self.record(threats=1)
        self.record(threats=0)
        counts = self.history.daily_counts()
        self.assertEqual(len(counts), 1)
        _day, scans, threats = counts[0]
        self.assertEqual((scans, threats), (2, 1))

    # -- maintenance ------------------------------------------------------

    def test_purge_removes_only_old_records(self) -> None:
        old = self.record()
        recent = self.record()
        connection = sqlite3.connect(self.tmp / "history.db")
        connection.execute("UPDATE scans SET started_at = ? WHERE id = ?",
                           ((datetime.now() - timedelta(days=200)).isoformat(), old))
        connection.commit()
        connection.close()

        self.assertEqual(self.history.purge_older_than(90), 1)
        remaining = [record.id for record in self.history.recent_scans()]
        self.assertEqual(remaining, [recent])

    def test_clear_empties_everything(self) -> None:
        self.record(threats=2)
        self.history.clear()
        self.assertEqual(self.history.totals()["scans"], 0)
        self.assertEqual(self.history.totals()["detections"], 0)

    def test_a_corrupt_database_does_not_crash_the_app(self) -> None:
        path = self.tmp / "corrupt.db"
        path.write_bytes(b"this is not a database")
        history = History(path)
        self.assertEqual(history.totals()["scans"], 0)
        self.assertEqual(history.recent_scans(), [])


class TestRecordFormatting(TempHomeTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.history = History(self.tmp / "history.db")

    def outcome(self, threats: int, status: str = "completed") -> str:
        scan_id = self.history.start_scan("quick", ["/x"])
        self.history.finish_scan(scan_id, status=status, threats_found=threats)
        return self.history.scan(scan_id).outcome()

    def test_outcome_wording(self) -> None:
        self.assertEqual(self.outcome(0), "No threats found")
        self.assertEqual(self.outcome(1), "1 threat found")
        self.assertEqual(self.outcome(5), "5 threats found")
        self.assertEqual(self.outcome(0, status="stopped"), "Stopped early")
        self.assertEqual(self.outcome(0, status="failed"), "Failed")

    def test_target_text_summarises_many_paths(self) -> None:
        scan_id = self.history.start_scan("custom", ["/a", "/b", "/c"])
        self.history.finish_scan(scan_id, status="completed")
        self.assertEqual(self.history.scan(scan_id).target_text(), "/a and 2 more")

    def test_tone_reflects_the_outcome(self) -> None:
        scan_id = self.history.start_scan("quick", ["/x"])
        self.history.finish_scan(scan_id, status="completed", threats_found=1)
        self.assertEqual(self.history.scan(scan_id).tone, "danger")


if __name__ == "__main__":
    unittest.main()
