"""Signature database inspection."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from .support import TempHomeTestCase

from clamguard.core.database import (
    DatabaseInfo,
    Freshness,
    format_bytes,
    humanise_age,
    read_cvd_header,
)

#: A real CVD header, padded to the 512 bytes ClamAV writes.
REAL_HEADER = (
    b"ClamAV-VDB:19 Sep 2026 06-24 +0000:28128:355666:90:"
    b"99f8125fa8445b20bdbe5847f3d69020:dsigdsigdsig:svc.clamav-publisher:1758263064:"
)


class TestCvdHeader(TempHomeTestCase):
    def write_cvd(self, name: str, header: bytes = REAL_HEADER, body: int = 4096):
        path = self.tmp / name
        path.write_bytes(header.ljust(512, b":") + b"\x00" * body)
        return path

    def test_parsing_a_real_header(self) -> None:
        header = read_cvd_header(self.write_cvd("daily.cvd"))
        self.assertIsNotNone(header)
        self.assertEqual(header.version, 28128)
        self.assertEqual(header.signatures, 355666)
        self.assertEqual(header.functionality_level, 90)
        self.assertEqual(header.md5, "99f8125fa8445b20bdbe5847f3d69020")
        self.assertEqual(header.builder, "svc.clamav-publisher")
        self.assertEqual(header.built,
                         datetime(2026, 9, 19, 6, 24, tzinfo=timezone.utc))

    def test_a_file_that_is_not_a_cvd(self) -> None:
        path = self.tmp / "notes.txt"
        path.write_bytes(b"just some text")
        self.assertIsNone(read_cvd_header(path))

    def test_a_truncated_header(self) -> None:
        self.assertIsNone(read_cvd_header(self.write_cvd("bad.cvd", b"ClamAV-VDB:19 Sep")))

    def test_a_missing_file(self) -> None:
        self.assertIsNone(read_cvd_header(self.tmp / "nope.cvd"))


class TestFreshness(TempHomeTestCase):
    def write_daily(self, days_old: float) -> None:
        built = datetime.now(timezone.utc) - timedelta(days=days_old)
        header = (f"ClamAV-VDB:{built.strftime('%d %b %Y %H-%M')} +0000:"
                  "28128:355666:90:abc:dsig:builder:1").encode()
        (self.tmp / "daily.cvd").write_bytes(header.ljust(512, b":"))

    def info(self) -> DatabaseInfo:
        return DatabaseInfo(self.tmp, warn_after_days=3)

    def test_recent_signatures_are_current(self) -> None:
        self.write_daily(0.5)
        summary = self.info().read()
        self.assertIs(summary.freshness, Freshness.CURRENT)
        self.assertEqual(summary.freshness.tone, "ok")
        self.assertIn("355,666 signatures", summary.headline())

    def test_slightly_old_signatures_are_ageing(self) -> None:
        self.write_daily(5)
        self.assertIs(self.info().read().freshness, Freshness.AGEING)

    def test_very_old_signatures_are_stale(self) -> None:
        self.write_daily(40)
        summary = self.info().read()
        self.assertIs(summary.freshness, Freshness.STALE)
        self.assertEqual(summary.freshness.tone, "danger")

    def test_an_empty_directory_reports_missing(self) -> None:
        summary = self.info().read()
        self.assertIs(summary.freshness, Freshness.MISSING)
        self.assertIn("No virus signatures", summary.headline())

    def test_a_directory_that_does_not_exist(self) -> None:
        summary = DatabaseInfo(self.tmp / "nowhere").read()
        self.assertIs(summary.freshness, Freshness.MISSING)
        self.assertFalse(summary.readable)

    def test_custom_signature_files_are_listed_separately(self) -> None:
        self.write_daily(1)
        (self.tmp / "my-rules.ndb").write_text("Custom:0:*:deadbeef\n")
        summary = self.info().read()
        self.assertEqual([entry.name for entry in summary.official()], ["daily"])
        self.assertEqual([entry.path.name for entry in summary.custom()],
                         ["my-rules.ndb"])

    def test_unrelated_files_are_ignored(self) -> None:
        self.write_daily(1)
        (self.tmp / "freshclam.dat").write_bytes(b"binary")
        (self.tmp / "daily.cvd.sign").write_bytes(b"signature")
        summary = self.info().read()
        self.assertEqual(len(summary.files), 1)

    def test_totals_add_up(self) -> None:
        self.write_daily(1)
        summary = self.info().read()
        self.assertEqual(summary.total_signatures, 355666)
        self.assertGreater(summary.total_bytes, 0)


class TestFormatting(unittest.TestCase):
    def test_humanise_age(self) -> None:
        self.assertEqual(humanise_age(None), "at an unknown time")
        self.assertEqual(humanise_age(timedelta(seconds=30)), "moments ago")
        self.assertEqual(humanise_age(timedelta(minutes=30)), "30 minutes ago")
        self.assertEqual(humanise_age(timedelta(hours=1)), "1 hour ago")
        self.assertEqual(humanise_age(timedelta(hours=5)), "5 hours ago")
        self.assertEqual(humanise_age(timedelta(days=1)), "1 day ago")
        self.assertEqual(humanise_age(timedelta(days=3)), "3 days ago")
        self.assertEqual(humanise_age(timedelta(days=21)), "3 weeks ago")
        self.assertEqual(humanise_age(timedelta(days=90)), "3 months ago")

    def test_a_clock_skew_into_the_future_reads_sensibly(self) -> None:
        self.assertEqual(humanise_age(timedelta(seconds=-60)), "just now")

    def test_format_bytes(self) -> None:
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(512), "512 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(89_000_000), "84.9 MB")
        self.assertIn("GB", format_bytes(5 * 1024 ** 3))


class TestRealDatabase(unittest.TestCase):
    def test_this_machine(self) -> None:
        from clamguard.core import paths

        if not paths.CLAMAV_DB_DIR.is_dir():
            self.skipTest("no ClamAV database directory on this machine")
        summary = DatabaseInfo(paths.CLAMAV_DB_DIR).read()
        self.assertIsNot(summary.freshness, Freshness.UNKNOWN)
        if summary.official():
            self.assertGreater(summary.total_signatures, 0)


if __name__ == "__main__":
    unittest.main()
