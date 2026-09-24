"""The bridge to the one thing that runs as root.

ClamGuard itself is an ordinary user process. When it needs to write
/etc/clamav/clamd.conf, restart a service or run freshclam, it asks pkexec to
run `packaging/clamguard-helper`, which the user installed by hand and can
read in full.

Two rules this module exists to enforce:

1. **Nothing privileged happens without a running :class:`HelperCall`.** There
   is no quiet path to root anywhere else in the codebase.
2. **Nothing here blocks.** pkexec puts a password dialog on screen; waiting
   for it synchronously would freeze the window behind it. Every call is a
   :class:`Command` and reports back through signals.

If the helper is not installed the app keeps working — it just reports every
privileged feature as unavailable and shows the one-line install command.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from . import paths
from .logging_setup import get_logger
from .process import Command, which

log = get_logger(__name__)

#: pkexec's own exit codes, which are not the helper's.
PKEXEC_DISMISSED = 126   # the user closed the password dialog
PKEXEC_NOT_AUTHORISED = 127

#: The helper's exit codes.
HELPER_FAILED = 1
HELPER_REFUSED = 2


@dataclass(frozen=True)
class HelperAvailability:
    """Why privileged actions are or are not possible right now."""

    helper_installed: bool
    policy_installed: bool
    pkexec_found: bool

    @property
    def usable(self) -> bool:
        """The helper can be invoked. The polkit policy is a nicety, not a need."""
        return self.helper_installed and self.pkexec_found

    def reason(self) -> str:
        """A sentence explaining what is missing."""
        if not self.pkexec_found:
            return ("pkexec is not installed, so ClamGuard cannot ask for "
                    "administrator rights. Install polkit to enable this.")
        if not self.helper_installed:
            return ("The ClamGuard privileged helper is not installed, so system "
                    "settings, services and signature updates cannot be changed "
                    "from here.")
        if not self.policy_installed:
            return ("The helper is installed but its polkit policy is missing, so "
                    "the password prompt will be a generic one.")
        return "Privileged actions are available."


class HelperCall(QObject):
    """One invocation of the helper, from click to result.

    ::

        call = context.privileged.call("service", ["restart", "clamav-daemon.service"])
        call.succeeded.connect(lambda out: self.refresh())
        call.failed.connect(self.show_error)
        call.start()
    """

    #: Complete stdout, once the call succeeded.
    succeeded = Signal(str)
    #: A human-readable failure message.
    failed = Signal(str)
    #: The user dismissed the authentication dialog. Not an error.
    cancelled = Signal()
    #: Every stdout line as it arrives — useful for a long update.
    output_line = Signal(str)
    #: Every stderr line as it arrives.
    error_line = Signal(str)
    #: Emitted exactly once, after any of the above.
    finished = Signal()

    def __init__(self, verb: str, args: list[str], stdin_text: str | None = None,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.verb = verb
        self.args = args
        self.stdin_text = stdin_text
        self._stdout: list[str] = []
        self._stderr: list[str] = []
        self._command: Command | None = None

    @property
    def description(self) -> str:
        """What the user is being asked to authorise, in plain words."""
        return describe(self.verb, self.args)

    def start(self) -> None:
        pkexec = which("pkexec")
        if not pkexec:
            self._fail("pkexec is not installed, so ClamGuard cannot request "
                       "administrator rights.")
            return
        if not paths.HELPER_PATH.is_file():
            self._fail("The ClamGuard privileged helper is not installed.\n\n"
                       f"Install it with:\n    {install_command()}")
            return

        argv = [str(paths.HELPER_PATH), self.verb, *self.args]
        command = Command(pkexec, argv, parent=self)
        command.stdout_line.connect(self._on_stdout)
        command.stderr_line.connect(self._on_stderr)
        command.finished.connect(self._on_finished)
        command.failed.connect(self._fail)
        self._command = command

        log.info("privileged: %s %s", self.verb, " ".join(self.args))
        if not command.start():
            return

        if self.stdin_text is not None:
            self._write_stdin(self.stdin_text)

    def _write_stdin(self, text: str) -> None:
        """Feed the helper its input and close the pipe so it stops reading."""
        process = getattr(self._command, "_process", None)
        if process is None:
            return
        process.write(text.encode("utf-8"))
        process.closeWriteChannel()

    def stop(self) -> None:
        if self._command:
            self._command.stop()

    # -- signal plumbing --------------------------------------------------

    def _on_stdout(self, line: str) -> None:
        self._stdout.append(line)
        self.output_line.emit(line)

    def _on_stderr(self, line: str) -> None:
        self._stderr.append(line)
        self.error_line.emit(line)

    def _on_finished(self, exit_code: int) -> None:
        stdout = "\n".join(self._stdout)
        stderr = "\n".join(self._stderr).strip()

        if exit_code == 0:
            self.succeeded.emit(stdout)
        elif exit_code == PKEXEC_DISMISSED:
            log.info("privileged call cancelled by the user")
            self.cancelled.emit()
        elif exit_code == PKEXEC_NOT_AUTHORISED:
            self.failed.emit("Not authorised to perform this action.")
        elif exit_code == HELPER_REFUSED:
            self.failed.emit(_clean(stderr) or "The helper refused this request.")
        else:
            self.failed.emit(_clean(stderr) or f"The helper exited with code {exit_code}.")
        self.finished.emit()

    def _fail(self, message: str) -> None:
        self.failed.emit(message)
        self.finished.emit()


class PrivilegedHelper(QObject):
    """Knows whether privileged actions are possible, and starts them.

    The availability check never runs the helper, because running it would pop
    a password dialog. It only looks at the filesystem.
    """

    availability_changed = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._availability = self._probe()
        #: Calls are kept here until they finish so Qt does not collect them.
        self._live: list[HelperCall] = []

    # -- availability -----------------------------------------------------

    def _probe(self) -> HelperAvailability:
        return HelperAvailability(
            helper_installed=paths.HELPER_PATH.is_file(),
            policy_installed=paths.HELPER_POLICY_PATH.is_file(),
            pkexec_found=which("pkexec") is not None,
        )

    def refresh(self) -> None:
        """Re-check the filesystem. Call this after the user installs the helper."""
        previous = self._availability
        self._availability = self._probe()
        if previous != self._availability:
            self.availability_changed.emit()

    @property
    def availability(self) -> HelperAvailability:
        return self._availability

    @property
    def available(self) -> bool:
        return self._availability.usable

    # -- calls ------------------------------------------------------------

    def call(self, verb: str, args: list[str] | None = None,
             stdin_text: str | None = None) -> HelperCall:
        """Build a call. It does not run until you call ``start()``.

        Returning it unstarted is deliberate: the caller must connect its
        signals, and in most cases show a confirmation dialog, first.
        """
        call = HelperCall(verb, list(args or []), stdin_text, parent=self)
        self._live.append(call)
        call.finished.connect(lambda: self._live.remove(call) if call in self._live else None)
        return call

    # -- convenience wrappers --------------------------------------------

    def write_config(self, path: Path, content: str) -> HelperCall:
        return self.call("write-config", [str(path)], stdin_text=content)

    def service_action(self, action: str, unit: str) -> HelperCall:
        return self.call("service", [action, unit])

    def update_database(self) -> HelperCall:
        return self.call("update-db")

    def read_file(self, path: Path) -> HelperCall:
        return self.call("read-file", [str(path)])

    def quarantine_file(self, source: Path, payload: Path) -> HelperCall:
        return self.call("quarantine", [str(source), str(payload)])

    def restore_file(self, entry_id: str) -> HelperCall:
        """Ask the helper to restore one entry it quarantined itself.

        Only the entry id is sent. Where the file goes and what permissions it
        gets come from the helper's own root-owned record, so nothing the GUI
        says can redirect a root-owned write.
        """
        return self.call("restore", [entry_id])


# ---------------------------------------------------------------------------
# Helpers for the UI
# ---------------------------------------------------------------------------


def install_command() -> str:
    """The exact command the user should run to enable privileged actions."""
    script = Path(__file__).resolve().parents[3] / "packaging" / "install-helper.sh"
    return f"sudo {shlex.quote(str(script))}"


def describe(verb: str, args: list[str]) -> str:
    """Plain-language description of a privileged action, for a dialog."""
    if verb == "write-config" and args:
        return f"Replace {args[0]} with a new configuration"
    if verb == "service" and len(args) == 2:
        action, unit = args
        return f"{action.capitalize()} the {unit} service"
    if verb == "update-db":
        return "Download the latest virus signatures"
    if verb == "read-file" and args:
        return f"Read {args[0]}"
    if verb == "quarantine" and args:
        return f"Move {args[0]} into quarantine"
    if verb == "restore":
        return "Restore a file out of quarantine"
    return f"Run the ClamGuard helper ({verb})"


def parse_json_output(text: str) -> dict:
    """The helper prints JSON on success for some verbs. Never raises."""
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}


def _clean(message: str) -> str:
    """Strip the helper's own prefix so dialogs read naturally."""
    lines = [
        line.replace("clamguard-helper: refused: ", "").replace("clamguard-helper: ", "")
        for line in message.splitlines()
        if line.strip()
    ]
    return "\n".join(lines).strip()
