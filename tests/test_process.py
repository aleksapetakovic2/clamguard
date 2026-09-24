"""The subprocess layer."""

from __future__ import annotations

import unittest

from PySide6.QtCore import QTimer

from .support import qt_application

from clamguard.core.process import Command, environment, run, which


class TestRun(unittest.TestCase):
    def setUp(self) -> None:
        qt_application()

    def test_a_successful_command(self) -> None:
        result = run("echo", ["hello world"])
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout.strip(), "hello world")
        self.assertEqual(result.exit_code, 0)

    def test_a_failing_command_is_not_an_exception(self) -> None:
        result = run("sh", ["-c", "echo oops >&2; exit 3"])
        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, 3)
        self.assertEqual(result.stderr.strip(), "oops")

    def test_a_missing_program(self) -> None:
        result = run("definitely-not-a-real-program-xyz")
        self.assertFalse(result.ok)
        self.assertIn("not found", result.error)

    def test_a_timeout_is_reported_not_raised(self) -> None:
        result = run("sleep", ["5"], timeout=0.2)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)

    def test_output_prefers_stdout_but_falls_back_to_stderr(self) -> None:
        self.assertEqual(run("sh", ["-c", "echo out"]).output, "out")
        self.assertEqual(run("sh", ["-c", "echo err >&2"]).output, "err")

    def test_lines_skips_blanks(self) -> None:
        self.assertEqual(run("printf", ["a\\n\\nb\\n"]).lines(), ["a", "b"])

    def test_the_locale_is_pinned_so_output_can_be_parsed(self) -> None:
        self.assertEqual(environment()["LC_ALL"], "C")
        self.assertEqual(run("sh", ["-c", "echo $LC_ALL"]).stdout.strip(), "C")

    def test_which_finds_sbin_programs(self) -> None:
        """clamd and clamonacc live in /usr/sbin on several distributions."""
        self.assertIsNotNone(which("sh"))
        self.assertIsNone(which("definitely-not-a-real-program-xyz"))


class TestCommand(unittest.TestCase):
    def setUp(self) -> None:
        self.app = qt_application()

    def drive(self, command: Command, timeout_ms: int = 8000) -> dict:
        """Run a Command to completion on a nested event loop."""
        from PySide6.QtCore import QEventLoop

        captured = {"out": [], "err": [], "code": None, "failed": None}
        loop = QEventLoop()
        command.stdout_line.connect(captured["out"].append)
        command.stderr_line.connect(captured["err"].append)
        command.failed.connect(lambda message: captured.update(failed=message))
        command.finished.connect(lambda code: (captured.update(code=code), loop.quit()))
        QTimer.singleShot(timeout_ms, loop.quit)
        command.start()
        loop.exec()
        return captured

    def test_lines_arrive_individually(self) -> None:
        command = Command("sh", ["-c", "for i in 1 2 3; do echo line $i; done"])
        captured = self.drive(command)
        self.assertEqual(captured["out"], ["line 1", "line 2", "line 3"])
        self.assertEqual(captured["code"], 0)

    def test_stderr_is_separate(self) -> None:
        command = Command("sh", ["-c", "echo out; echo problem >&2; exit 2"])
        captured = self.drive(command)
        self.assertEqual(captured["out"], ["out"])
        self.assertEqual(captured["err"], ["problem"])
        self.assertEqual(captured["code"], 2)

    def test_a_final_line_without_a_newline_is_still_emitted(self) -> None:
        command = Command("printf", ["no trailing newline"])
        captured = self.drive(command)
        self.assertEqual(captured["out"], ["no trailing newline"])

    def test_carriage_returns_count_as_line_breaks(self) -> None:
        """Progress output sometimes uses \\r instead of \\n."""
        command = Command("printf", ["a\\rb\\rc\\n"])
        captured = self.drive(command)
        self.assertEqual(captured["out"], ["a", "b", "c"])

    def test_a_missing_program_reports_and_finishes(self) -> None:
        command = Command("definitely-not-a-real-program-xyz")
        captured = self.drive(command)
        self.assertIsNotNone(captured["failed"])
        self.assertEqual(captured["code"], -1)

    def test_stopping_a_running_command(self) -> None:
        command = Command("sh", ["-c", "sleep 30"])
        QTimer.singleShot(300, command.stop)
        captured = self.drive(command, timeout_ms=6000)
        self.assertIsNotNone(captured["code"])
        self.assertTrue(command.was_stopped)
        self.assertFalse(command.is_running())

    def test_pause_and_resume(self) -> None:
        command = Command("sh", ["-c", "for i in $(seq 1 40); do echo $i; sleep 0.05; done"])
        QTimer.singleShot(200, command.pause)
        QTimer.singleShot(400, lambda: self.assertTrue(command.paused))
        QTimer.singleShot(600, command.resume)
        captured = self.drive(command, timeout_ms=9000)
        self.assertEqual(captured["code"], 0)
        self.assertEqual(len(captured["out"]), 40)
        self.assertFalse(command.paused)


if __name__ == "__main__":
    unittest.main()
