"""Starting ClamGuard: the command line, the desktop file, and one instance.

Every test here is a bug that shipped. "Open with ClamGuard" on a folder
passed the folder as a positional argument the parser did not accept, so the
launch died with a usage error before a window appeared. The desktop file's
"Quick scan" action ran `--scan %f`, and from the application menu %f expands
to nothing, which `--scan` refused. The application called itself
org.clamguard.clamguard while the installer wrote clamguard.desktop, so on
Wayland the compositor could not match the window to its entry. And every one
of those launches, made while ClamGuard sat in the tray, started a complete
second instance with a second scheduler.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from .support import REPO_ROOT, qt_application

from clamguard import APP_ID  # noqa: E402
from clamguard.app import parse_arguments, request_from  # noqa: E402
from clamguard.core.single_instance import (  # noqa: E402
    MAX_PATHS,
    SingleInstance,
    clean_request,
)

DESKTOP = REPO_ROOT / "packaging" / "clamguard.desktop"
INSTALLER = REPO_ROOT / "install.sh"


class TestCommandLine(unittest.TestCase):
    def request(self, *argv: str) -> dict:
        return request_from(parse_arguments(list(argv)))

    def test_no_arguments_just_shows_the_window(self) -> None:
        self.assertEqual(self.request(), {"show": True})

    def test_a_folder_from_open_with_is_scanned(self) -> None:
        """The desktop file passes %F: bare paths, no flag."""
        request = self.request("/home/someone/Downloads")
        self.assertEqual(request["scan"], ["/home/someone/Downloads"])

    def test_scan_with_no_paths_is_a_quick_scan(self) -> None:
        """The desktop file's Quick scan action."""
        request = self.request("--scan")
        self.assertTrue(request.get("quick"))
        self.assertNotIn("scan", request)

    def test_scan_with_paths_scans_them(self) -> None:
        request = self.request("--scan", "/a", "/b")
        self.assertEqual(request["scan"], ["/a", "/b"])
        self.assertNotIn("quick", request)

    def test_relative_paths_are_made_absolute_before_they_travel(self) -> None:
        """A running instance would resolve "./x" against its own directory."""
        request = self.request("./report.pdf", "--scan", "~/thing")
        self.assertEqual(request["scan"][0], os.path.join(os.getcwd(), "report.pdf"))
        self.assertEqual(request["scan"][1], os.path.join(str(Path.home()), "thing"))

    def test_a_page_can_be_asked_for(self) -> None:
        self.assertEqual(self.request("--page", "updates")["page"], "updates")

    def test_autostart_does_not_raise_the_window(self) -> None:
        self.assertFalse(self.request("--minimised")["show"])


class TestDesktopFile(unittest.TestCase):
    """Every Exec line in the desktop file must be something the app accepts."""

    def exec_lines(self) -> list[str]:
        return [line.partition("=")[2] for line in DESKTOP.read_text().splitlines()
                if line.startswith("Exec=")]

    def test_every_exec_line_parses(self) -> None:
        lines = self.exec_lines()
        self.assertGreaterEqual(len(lines), 3)
        for line in lines:
            with self.subTest(exec=line):
                argv = shlex.split(line.replace("@LAUNCHER@", "/opt/My Checkout/clamguard"))
                self.assertEqual(argv[0], "/opt/My Checkout/clamguard",
                                 "the launcher path must be quoted: checkouts can have spaces")
                # A field code with nothing to substitute expands to nothing —
                # which is exactly the case that broke `--scan %f`.
                arguments = [a for a in argv[1:] if a not in ("%f", "%F", "%u", "%U")]
                try:
                    parse_arguments(arguments)
                except SystemExit as exit:
                    self.fail(f"{line!r} exits with a usage error ({exit.code})")

    def test_the_folder_handler_takes_paths(self) -> None:
        """MimeType=inode/directory means file managers will pass folders."""
        text = DESKTOP.read_text()
        self.assertIn("inode/directory", text)
        main_exec = self.exec_lines()[0]
        self.assertIn("%F", main_exec)
        parse_arguments(["/tmp/one", "/tmp/two"])  # must not exit

    def test_the_application_is_named_after_its_desktop_file(self) -> None:
        """On Wayland the app_id is the desktop file name, and it is how the
        compositor finds the icon for the window."""
        from clamguard.app import create_application  # noqa: F401 - reads the source below

        source = (REPO_ROOT / "src" / "clamguard" / "app.py").read_text()
        self.assertIn("setDesktopFileName(APP_ID)", source)
        self.assertIn(f'DESKTOP_FILE="$DESKTOP_DIR/{APP_ID}.desktop"', INSTALLER.read_text())

    def test_the_autostart_entry_quotes_its_launcher(self) -> None:
        from clamguard.ui.pages.settings_page import _autostart_entry

        exec_line = next(line for line in _autostart_entry().splitlines()
                         if line.startswith("Exec="))
        argv = shlex.split(exec_line.partition("=")[2])
        self.assertTrue(argv[0].endswith("/clamguard"))
        self.assertEqual(argv[1:], ["--minimised"])


class TestCleanRequest(unittest.TestCase):
    """The socket is private to the user, but what arrives on it is still
    input from outside the process, and is treated that way."""

    def test_only_known_fields_survive(self) -> None:
        cleaned = clean_request({"show": True, "scan": ["/a"], "page": "updates",
                                 "quick": True, "exec": "rm -rf /", "eval": 1})
        self.assertEqual(set(cleaned), {"show", "scan", "page", "quick"})

    def test_types_are_enforced(self) -> None:
        self.assertEqual(clean_request({"show": "yes", "quick": 1}), {})
        self.assertEqual(clean_request({"scan": "/a"}), {})
        self.assertEqual(clean_request({"scan": ["/a", 3, None, "", "/b\0c"]}),
                         {"scan": ["/a"]})

    def test_page_names_are_plain_identifiers(self) -> None:
        self.assertEqual(clean_request({"page": "updates"}), {"page": "updates"})
        self.assertEqual(clean_request({"page": "../../etc"}), {})
        self.assertEqual(clean_request({"page": "a b"}), {})

    def test_the_path_list_is_capped(self) -> None:
        cleaned = clean_request({"scan": [f"/p{n}" for n in range(MAX_PATHS * 3)]})
        self.assertEqual(len(cleaned["scan"]), MAX_PATHS)

    def test_not_a_dict_is_nothing(self) -> None:
        for raw in (None, [], "show", 5):
            self.assertEqual(clean_request(raw), {})


class TestSingleInstance(unittest.TestCase):
    def setUp(self) -> None:
        self.app = qt_application()
        self.tmp = Path(tempfile.mkdtemp(prefix="clamguard-instance-"))
        self.path = str(self.tmp / "clamguard.sock")
        self.first = SingleInstance(self.path)
        self.received: list[dict] = []
        self.first.request_received.connect(self.received.append)

    def tearDown(self) -> None:
        self.first.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def pump(self, until, seconds: float = 3.0) -> None:
        deadline = time.monotonic() + seconds
        while not until() and time.monotonic() < deadline:
            self.app.processEvents()
            time.sleep(0.01)

    def test_with_nobody_listening_forward_says_so(self) -> None:
        self.assertFalse(SingleInstance.forward({"show": True}, self.path))

    def test_a_second_launch_hands_its_request_over(self) -> None:
        self.assertTrue(self.first.listen())
        request = {"show": True, "scan": ["/home/someone/file"], "page": "scan"}
        # forward() blocks for the write, so the listener's side runs as the
        # event loop is pumped afterwards.
        self.assertTrue(SingleInstance.forward(request, self.path))
        self.pump(lambda: self.received)
        self.assertEqual(self.received, [request])

    def test_a_second_listener_is_refused_while_the_first_lives(self) -> None:
        self.assertTrue(self.first.listen())
        second = SingleInstance(self.path)
        try:
            self.assertFalse(second.listen())
        finally:
            second.close()

    def test_a_socket_left_by_a_crash_does_not_block_the_next_start(self) -> None:
        import socket as unix

        stale = unix.socket(unix.AF_UNIX, unix.SOCK_STREAM)
        stale.bind(self.path)          # a socket file with no one behind it
        stale.close()
        self.assertTrue(Path(self.path).exists())
        self.assertTrue(self.first.listen())

    def test_garbage_on_the_socket_is_ignored(self) -> None:
        from PySide6.QtNetwork import QLocalSocket

        self.assertTrue(self.first.listen())
        client = QLocalSocket()
        client.connectToServer(self.path)
        self.assertTrue(client.waitForConnected(1000))
        client.write(b"{not json\n")
        client.waitForBytesWritten(1000)
        self.pump(lambda: False, seconds=0.3)
        client.abort()
        self.assertEqual(self.received, [])
        # And the server is still there for the next, well-formed request.
        self.assertTrue(SingleInstance.forward({"show": True}, self.path))
        self.pump(lambda: self.received)
        self.assertEqual(self.received, [{"show": True}])

    def test_a_path_too_long_for_a_socket_falls_back(self) -> None:
        """sockaddr_un holds 108 bytes; past that listen() fails with only
        "Name error" and the launch ran unguarded without saying why."""
        from unittest import mock

        from clamguard.core import single_instance

        long_runtime = self.tmp / ("r" * 120)
        long_runtime.mkdir()
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(long_runtime)}):
            path = single_instance.socket_path()
        self.assertFalse(path.startswith(str(long_runtime)))
        self.assertLessEqual(len(os.fsencode(path)), single_instance.MAX_SOCKET_PATH)

    def test_no_usable_path_means_no_single_instance_not_a_crash(self) -> None:
        empty = SingleInstance("")
        self.assertFalse(empty.listen())
        self.assertFalse(SingleInstance.forward({"show": True}, ""))
        self.assertFalse(SingleInstance.is_running(""))

    def test_the_socket_lives_somewhere_private(self) -> None:
        """The login's runtime directory, else ClamGuard's own data directory.

        Both branches are pinned rather than read from the environment: a CI
        runner or a container has no login session, so no XDG_RUNTIME_DIR,
        and the fallback is the branch that then runs.
        """
        from unittest import mock

        from clamguard.core import paths, single_instance
        from clamguard.core.single_instance import socket_path

        runtime = self.tmp / "runtime"
        runtime.mkdir()
        with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(runtime)}):
            self.assertEqual(socket_path(), str(runtime / "clamguard.sock"))

        fallback = str(paths.DATA_DIR / "clamguard.sock")
        if len(os.fsencode(fallback)) > single_instance.MAX_SOCKET_PATH:
            fallback = ""
        for unset in ({"XDG_RUNTIME_DIR": ""}, {"XDG_RUNTIME_DIR": str(self.tmp / "gone")}):
            with mock.patch.dict(os.environ, unset):
                self.assertEqual(socket_path(), fallback)

    def test_the_payload_is_one_json_line(self) -> None:
        """Documented here because the listener reads up to the first newline."""
        line = json.dumps(clean_request({"show": True})) + "\n"
        self.assertEqual(line.count("\n"), 1)


class TestTwoRealLaunches(unittest.TestCase):
    """The real program, twice, as two processes.

    Only `--minimised` and `--page` are ever passed: if the hand-over failed,
    the second copy would start in full, and it must not then go and scan
    anything. Both processes get a private runtime directory and home, so this
    can never reach — or be reached by — a ClamGuard the person running the
    tests has open.
    """

    def setUp(self) -> None:
        self.runtime = tempfile.mkdtemp(prefix="cg-")
        self.home = Path(tempfile.mkdtemp(prefix="cg-home-"))
        self.socket = Path(self.runtime) / "clamguard.sock"
        if len(os.fsencode(str(self.socket))) > 90:
            self.skipTest("the temporary directory's path is too long for a socket")
        self.env = dict(os.environ,
                        XDG_RUNTIME_DIR=self.runtime,
                        XDG_CONFIG_HOME=str(self.home / "config"),
                        XDG_DATA_HOME=str(self.home / "data"),
                        XDG_CACHE_HOME=str(self.home / "cache"),
                        XDG_STATE_HOME=str(self.home / "state"),
                        QT_QPA_PLATFORM="offscreen",
                        PYTHONPATH=str(REPO_ROOT / "src"))
        self.log = self.home / "data" / "clamguard" / "logs" / "clamguard.log"

    def tearDown(self) -> None:
        shutil.rmtree(self.runtime, ignore_errors=True)
        shutil.rmtree(self.home, ignore_errors=True)

    def launch(self, *arguments: str):
        import subprocess
        import sys

        return subprocess.Popen([sys.executable, "-m", "clamguard", *arguments],
                                env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)

    def wait_for(self, condition, seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if condition():
                return True
            time.sleep(0.05)
        return False

    def test_a_second_launch_hands_over_and_exits(self) -> None:
        first = self.launch("--minimised")

        def stop_first() -> None:
            first.terminate()
            try:
                first.wait(10)
            except Exception:  # noqa: BLE001 - a test must never leave it running
                first.kill()
                first.wait(10)
            first.stdout.close()

        self.addCleanup(stop_first)
        if not self.wait_for(self.socket.exists, 30):
            stop_first()
            self.fail("the first instance never listened:\n"
                      + first.stdout.read().decode(errors="replace")[-2000:])

        started = time.monotonic()
        second = self.launch("--page", "updates")
        try:
            code = second.wait(20)
        finally:
            if second.poll() is None:
                second.kill()
                second.wait(10)
            second.stdout.close()
        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 15,
                        "the second launch should hand over, not start up in full")
        self.assertIsNone(first.poll(), "the first instance should still be running")

        received = self.wait_for(
            lambda: self.log.exists()
            and "another launch asked for ['page', 'show']" in self.log.read_text(errors="replace"),
            10)
        self.assertTrue(received, "the first instance never saw the request")


if __name__ == "__main__":
    unittest.main()
