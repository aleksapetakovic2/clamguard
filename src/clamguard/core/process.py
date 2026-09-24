"""Running external commands without ever freezing the window.

Two tools, and you should not need a third:

``Command``
    A long-running program whose output you want line by line as it appears —
    clamscan, freshclam, journalctl -f. Built on QProcess, so nothing blocks
    and nothing needs a thread.

``run()``
    A short query whose answer you need right now — ``systemctl is-active``,
    ``sigtool --info``. It blocks, so it is only for commands that finish in
    milliseconds, and it always has a timeout.

For slow *Python* work (hashing, directory walks, big SQLite queries) use
``run_in_background``, which hands the job to a thread pool and gives you the
result back on the UI thread.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from PySide6.QtCore import (
    QObject,
    QProcess,
    QProcessEnvironment,
    QRunnable,
    QThreadPool,
    Signal,
)

from .logging_setup import get_logger

log = get_logger(__name__)

#: Commands inherit a deliberately boring environment. ClamAV tools localise
#: their output, and we parse that output, so we pin the locale to C.
_FORCED_ENVIRONMENT = {
    "LC_ALL": "C",
    "LANG": "C",
    "LANGUAGE": "C",
}


# ---------------------------------------------------------------------------
# Blocking one-shot commands
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandResult:
    """What a finished command left behind."""

    program: str
    args: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.error

    @property
    def output(self) -> str:
        """stdout, or stderr when stdout is empty — what a human wants to see."""
        return self.stdout.strip() or self.stderr.strip()

    def lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]


def environment() -> dict[str, str]:
    """A copy of our environment with the locale pinned."""
    env = dict(os.environ)
    env.update(_FORCED_ENVIRONMENT)
    return env


def run(
    program: str,
    args: Sequence[str] = (),
    *,
    timeout: float = 10.0,
    input_text: str | None = None,
) -> CommandResult:
    """Run a fast command and wait for it.

    Never raises: failure to start, a non-zero exit and a timeout all come back
    as a CommandResult you can inspect. Keep `timeout` small — this blocks the
    calling thread, which is usually the UI thread.
    """
    argv = [program, *args]
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            env=environment(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning("timed out after %ss: %s", timeout, " ".join(argv))
        return CommandResult(program, tuple(args), -1, "", "", timed_out=True,
                             error=f"timed out after {timeout:g}s")
    except FileNotFoundError:
        return CommandResult(program, tuple(args), -1, "", "", error=f"{program} not found")
    except OSError as exc:
        return CommandResult(program, tuple(args), -1, "", "", error=str(exc))

    return CommandResult(
        program, tuple(args), completed.returncode, completed.stdout, completed.stderr
    )


def which(program: str) -> str | None:
    """Absolute path to `program`, including the sbin directories.

    Some ClamAV tools (clamd, clamonacc) live in /usr/sbin, which is not always
    on a desktop session's PATH.
    """
    found = shutil.which(program)
    if found:
        return found
    for directory in ("/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin"):
        candidate = os.path.join(directory, program)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


# ---------------------------------------------------------------------------
# Streaming commands
# ---------------------------------------------------------------------------


class Command(QObject):
    """One external program, with its output delivered line by line.

    ::

        self.job = Command("clamscan", ["-r", "/home"])
        self.job.stdout_line.connect(self._on_line)
        self.job.finished.connect(self._on_done)
        self.job.start()

    Keep a reference to the object; if it is garbage collected the process is
    killed with it.
    """

    #: One complete line of standard output, newline stripped.
    stdout_line = Signal(str)
    #: One complete line of standard error.
    stderr_line = Signal(str)
    #: Exit code. -1 means it never started or was killed.
    finished = Signal(int)
    #: A human-readable reason the command could not run.
    failed = Signal(str)
    #: Emitted on start() and on stop(), so a UI can flip a button.
    state_changed = Signal(bool)  # True while running

    def __init__(self, program: str, args: Sequence[str] = (), parent: QObject | None = None):
        super().__init__(parent)
        self.program = program
        self.args = list(args)
        self._process: QProcess | None = None
        self._stdout_buffer = ""
        self._stderr_buffer = ""
        self._paused = False
        self._stopping = False

    # -- lifecycle --------------------------------------------------------

    def start(self, working_directory: str | None = None) -> bool:
        """Launch the process. Returns False if the program is missing."""
        if self.is_running():
            log.warning("start() on an already running command: %s", self.program)
            return False

        executable = which(self.program) if not os.path.isabs(self.program) else self.program
        if not executable:
            self.failed.emit(f"{self.program} is not installed or not on PATH")
            self.finished.emit(-1)
            return False

        self._stdout_buffer = self._stderr_buffer = ""
        self._paused = self._stopping = False

        process = QProcess(self)
        env = QProcessEnvironment.systemEnvironment()
        for key, value in _FORCED_ENVIRONMENT.items():
            env.insert(key, value)
        process.setProcessEnvironment(env)
        if working_directory:
            process.setWorkingDirectory(working_directory)

        process.readyReadStandardOutput.connect(self._drain_stdout)
        process.readyReadStandardError.connect(self._drain_stderr)
        process.finished.connect(self._on_finished)
        process.errorOccurred.connect(self._on_error)

        self._process = process
        log.debug("running: %s %s", executable, " ".join(self.args))
        process.start(executable, self.args)
        self.state_changed.emit(True)
        return True

    def is_running(self) -> bool:
        return self._process is not None and self._process.state() != QProcess.ProcessState.NotRunning

    @property
    def paused(self) -> bool:
        return self._paused

    def pause(self) -> bool:
        """Suspend the process with SIGSTOP. Returns True if it worked."""
        if not self.is_running() or self._paused:
            return False
        return self._signal(signal.SIGSTOP, paused=True)

    def resume(self) -> bool:
        """Wake a paused process with SIGCONT."""
        if not self.is_running() or not self._paused:
            return False
        return self._signal(signal.SIGCONT, paused=False)

    def _signal(self, sig: int, *, paused: bool) -> bool:
        pid = self._process.processId() if self._process else 0
        if pid <= 0:
            return False
        try:
            os.kill(pid, sig)
        except OSError as exc:
            log.warning("cannot signal pid %s: %s", pid, exc)
            return False
        self._paused = paused
        return True

    def stop(self, grace_ms: int = 3000) -> None:
        """Ask nicely with SIGTERM, then insist with SIGKILL."""
        if not self.is_running() or self._process is None:
            return
        self._stopping = True
        if self._paused:
            # A stopped process cannot handle SIGTERM until it runs again.
            self.resume()
        self._process.terminate()
        if not self._process.waitForFinished(grace_ms):
            log.warning("%s ignored SIGTERM, killing it", self.program)
            self._process.kill()
            self._process.waitForFinished(1000)

    @property
    def was_stopped(self) -> bool:
        """True when the last run ended because someone called stop()."""
        return self._stopping

    # -- output -----------------------------------------------------------

    def _drain_stdout(self) -> None:
        if self._process is None:
            return
        chunk = bytes(self._process.readAllStandardOutput()).decode("utf-8", errors="replace")
        self._stdout_buffer = self._emit_lines(self._stdout_buffer + chunk, self.stdout_line)

    def _drain_stderr(self) -> None:
        if self._process is None:
            return
        chunk = bytes(self._process.readAllStandardError()).decode("utf-8", errors="replace")
        self._stderr_buffer = self._emit_lines(self._stderr_buffer + chunk, self.stderr_line)

    @staticmethod
    def _emit_lines(buffer: str, sig: Signal) -> str:
        """Emit every complete line in `buffer`, return the unfinished tail.

        Progress output sometimes uses a carriage return instead of a newline,
        so we treat both as line breaks.
        """
        buffer = buffer.replace("\r\n", "\n").replace("\r", "\n")
        *complete, tail = buffer.split("\n")
        for line in complete:
            sig.emit(line)
        return tail

    def _flush(self) -> None:
        """Emit whatever was left in the buffers when the process ended."""
        if self._stdout_buffer.strip():
            self.stdout_line.emit(self._stdout_buffer)
        if self._stderr_buffer.strip():
            self.stderr_line.emit(self._stderr_buffer)
        self._stdout_buffer = self._stderr_buffer = ""

    # -- signals from QProcess -------------------------------------------

    def _on_finished(self, exit_code: int, _status) -> None:
        self._drain_stdout()
        self._drain_stderr()
        self._flush()
        self._paused = False
        self.state_changed.emit(False)
        self.finished.emit(exit_code)

    def _on_error(self, error: QProcess.ProcessError) -> None:
        if self._stopping and error == QProcess.ProcessError.Crashed:
            return  # we killed it on purpose
        messages = {
            QProcess.ProcessError.FailedToStart: f"{self.program} could not be started",
            QProcess.ProcessError.Crashed: f"{self.program} crashed",
            QProcess.ProcessError.Timedout: f"{self.program} timed out",
            QProcess.ProcessError.WriteError: f"could not write to {self.program}",
            QProcess.ProcessError.ReadError: f"could not read from {self.program}",
        }
        message = messages.get(error, f"{self.program} failed")
        log.error("%s", message)
        self.failed.emit(message)


# ---------------------------------------------------------------------------
# Background Python work
# ---------------------------------------------------------------------------


class _Signals(QObject):
    done = Signal(object)
    error = Signal(str)


class _Task(QRunnable):
    """Runs `function` off the UI thread and reports back through signals."""

    def __init__(self, function: Callable[[], Any]) -> None:
        super().__init__()
        self.function = function
        self.signals = _Signals()

    def run(self) -> None:  # called on a pool thread
        try:
            result = self.function()
        except Exception as exc:  # noqa: BLE001 - a worker must never take the app down
            log.exception("background task failed")
            self._emit(self.signals.error, str(exc))
        else:
            self._emit(self.signals.done, result)

    @staticmethod
    def _emit(signal, payload) -> None:
        """Deliver the result, unless nobody is left to receive it.

        A task that finishes after the window has closed is emitting into a
        QObject whose C++ half is already gone. Raising there prints a
        traceback on the way out of an otherwise clean shutdown.
        """
        try:
            signal.emit(payload)
        except RuntimeError:
            log.debug("background result discarded: the receiver is gone")


@dataclass
class _Holder:
    """Keeps a task alive until it finishes, so Qt does not collect it early."""

    tasks: list[_Task] = field(default_factory=list)


_holder = _Holder()


def run_in_background(
    function: Callable[[], Any],
    on_done: Callable[[Any], None] | None = None,
    on_error: Callable[[str], None] | None = None,
) -> None:
    """Run `function` on a worker thread; call `on_done` with its return value.

    The callbacks run on the UI thread, so they may touch widgets. `function`
    must not.
    """
    task = _Task(function)
    _holder.tasks.append(task)

    def cleanup(*_args) -> None:
        if task in _holder.tasks:
            _holder.tasks.remove(task)

    if on_done:
        task.signals.done.connect(on_done)
    if on_error:
        task.signals.error.connect(on_error)
    task.signals.done.connect(cleanup)
    task.signals.error.connect(cleanup)
    QThreadPool.globalInstance().start(task)
