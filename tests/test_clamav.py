"""Discovering the installed ClamAV."""

from __future__ import annotations

import unittest
from datetime import datetime

from .support import TempHomeTestCase, qt_application

from clamguard.core.clamav import ClamAV, Version, summarise_installation


class TestVersionParsing(unittest.TestCase):
    def test_a_full_version_string(self) -> None:
        version = Version.parse("ClamAV 1.5.4/28128/Sat Sep 19 08:24:24 2026")
        self.assertEqual(version.engine, "1.5.4")
        self.assertEqual(version.signature_version, 28128)
        self.assertEqual(version.built, datetime(2026, 9, 19, 8, 24, 24))
        self.assertEqual(str(version), "1.5.4")

    def test_engine_only(self) -> None:
        version = Version.parse("ClamAV 0.103.11")
        self.assertEqual(version.engine, "0.103.11")
        self.assertEqual(version.signature_version, 0)
        self.assertIsNone(version.built)

    def test_unrecognised_text_is_kept_verbatim(self) -> None:
        version = Version.parse("something else entirely")
        self.assertEqual(version.engine, "")
        self.assertEqual(str(version), "something else entirely")

    def test_empty_input(self) -> None:
        self.assertEqual(str(Version.parse("")), "unknown")


class TestEndpointDiscovery(TempHomeTestCase):
    def build(self, conf_text: str) -> ClamAV:
        qt_application()
        path = self.write("clamd.conf", conf_text)
        clamav = ClamAV()
        # Point the probe at our temporary config rather than the real one.
        self.paths.CLAMD_CONF = path
        import clamguard.core.clamav as module
        module.paths.CLAMD_CONF = path
        return clamav

    def test_a_unix_socket(self) -> None:
        clamav = self.build("LocalSocket /run/clamav/clamd.ctl\n")
        local, tcp = clamav.configured_endpoints()
        self.assertEqual(str(local), "/run/clamav/clamd.ctl")
        self.assertIsNone(tcp)

    def test_a_tcp_socket_defaults_to_loopback(self) -> None:
        clamav = self.build("TCPSocket 3310\n")
        local, tcp = clamav.configured_endpoints()
        self.assertIsNone(local)
        self.assertEqual(tcp, "127.0.0.1:3310")

    def test_an_explicit_tcp_address(self) -> None:
        clamav = self.build("TCPSocket 3310\nTCPAddr 10.0.0.5\n")
        _local, tcp = clamav.configured_endpoints()
        self.assertEqual(tcp, "10.0.0.5:3310")

    def test_no_endpoint_configured(self) -> None:
        clamav = self.build("LogTime yes\n")
        self.assertEqual(clamav.configured_endpoints(), (None, None))

    def test_commented_out_options_are_not_used(self) -> None:
        clamav = self.build("#LocalSocket /run/clamav/clamd.ctl\nLogTime yes\n")
        self.assertEqual(clamav.configured_endpoints(), (None, None))


class TestThisMachine(unittest.TestCase):
    """Light checks against whatever ClamAV is actually installed."""

    def setUp(self) -> None:
        qt_application()
        self.clamav = ClamAV()

    def test_probing_does_not_raise(self) -> None:
        self.assertIsInstance(self.clamav.installed, bool)
        self.assertIsInstance(self.clamav.missing_tools(), list)

    def test_notes_are_empty_or_explain_themselves(self) -> None:
        for note in summarise_installation(self.clamav):
            self.assertTrue(note.endswith("."), note)

    def test_version_is_read_when_clamav_is_installed(self) -> None:
        if not self.clamav.installed:
            self.skipTest("ClamAV is not installed")
        self.assertTrue(self.clamav.version.engine)

    def test_daemon_status_is_always_answerable(self) -> None:
        status = self.clamav.daemon
        self.assertIsInstance(status.reachable, bool)
        self.assertTrue(status.endpoint)
        if not status.reachable:
            self.assertTrue(status.detail, "an unreachable daemon must say why")


if __name__ == "__main__":
    unittest.main()
