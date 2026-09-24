"""Applying a configuration change, from confirmation to restart.

Both the Protection page (one-click fixes) and the Configuration page (manual
editing) need the same sequence:

    show the diff  ->  get agreement  ->  write via the helper  ->  restart

Putting it here means the confirmation step cannot be skipped by accident in
one place and not the other, and that the wording of the prompt is identical
wherever a system file is about to change.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QWidget

from ..core.context import AppContext
from ..core.logging_setup import get_logger
from ..core.privileged import install_command
from ..core.services import Role
from .dialogs import confirm
from .theme import resolve_palette

log = get_logger(__name__)


class ConfigApplier(QObject):
    """Writes a ClamAV config file and restarts what needs restarting.

    ::

        applier = ConfigApplier(self.context, self)
        applier.finished.connect(self._on_applied)
        applier.apply(paths.CLAMD_CONF, new_text, diff,
                      "Enable on-access exclusions", restart=(Role.DAEMON,))
    """

    #: (succeeded, message) — always emitted exactly once per apply().
    finished = Signal(bool, str)
    #: A human-readable step, for a status line.
    progress = Signal(str)

    def __init__(self, context: AppContext, parent: QWidget) -> None:
        super().__init__(parent)
        self.context = context
        self._parent = parent
        self._pending_restarts: list[Role] = []
        self._restart_failures: list[str] = []

    # -- entry point ------------------------------------------------------

    def apply(
        self,
        path: Path,
        new_text: str,
        diff: str,
        description: str,
        *,
        restart: tuple[Role, ...] = (),
        extra_warning: str = "",
    ) -> bool:
        """Confirm and apply. Returns False if it never started."""
        if not diff.strip():
            self.finished.emit(True, "Nothing to change.")
            return False

        if not self.context.privileged.available:
            self._explain_missing_helper(path, diff)
            self.finished.emit(False, "The privileged helper is not installed.")
            return False

        units = [self.context.services.unit_for(role) for role in restart]
        units = [unit for unit in units if unit]
        restart_note = (
            "\n\nAfterwards ClamGuard will restart: " + ", ".join(units)
            if units else ""
        )

        message = (
            f"{description}\n\n"
            f"ClamGuard will replace {path} with the version on the right. "
            "The current file is backed up next to it first, with a timestamp in "
            "the name, and the new one is checked with clamconf before it is "
            "installed."
            f"{restart_note}"
        )
        if extra_warning:
            message = f"{message}\n\n{extra_warning}"

        if not confirm(
            self._parent, "Change ClamAV's configuration", message,
            detail=diff, detail_kind="diff", detail_label="WHAT WILL CHANGE",
            confirm_text="Apply this change", tone="warn",
            palette=resolve_palette(self.context.settings.str("theme")),
        ):
            self.finished.emit(False, "Cancelled.")
            return False

        self._pending_restarts = list(restart)
        self._restart_failures = []
        self.progress.emit(f"Writing {path.name}…")

        call = self.context.privileged.write_config(path, new_text)
        call.succeeded.connect(lambda _output: self._on_written(path))
        call.failed.connect(lambda message: self.finished.emit(False, message))
        call.cancelled.connect(
            lambda: self.finished.emit(False, "Cancelled at the password prompt."))
        call.start()
        return True

    # -- restart chain ----------------------------------------------------

    def _on_written(self, path: Path) -> None:
        log.info("wrote %s", path)
        self._restart_next()

    def _restart_next(self) -> None:
        """Restart the pending units one at a time, in order.

        Sequential rather than parallel because clamonacc needs clamd's socket
        to exist before it will start, and firing both at once loses that race.
        """
        if not self._pending_restarts:
            if self._restart_failures:
                self.finished.emit(
                    True,
                    "The configuration was saved, but restarting failed: "
                    + "; ".join(self._restart_failures),
                )
            else:
                self.finished.emit(True, "Configuration saved.")
            self.context.refresh()
            return

        role = self._pending_restarts.pop(0)
        unit = self.context.services.unit_for(role)
        if not unit:
            self._restart_next()
            return

        self.progress.emit(f"Restarting {unit}…")
        call = self.context.privileged.service_action("restart", unit)
        call.succeeded.connect(lambda _output: self._restart_next())
        call.failed.connect(lambda message, u=unit: self._restart_failed(u, message))
        call.cancelled.connect(
            lambda u=unit: self._restart_failed(u, "cancelled"))
        call.start()

    def _restart_failed(self, unit: str, message: str) -> None:
        log.warning("restart of %s failed: %s", unit, message)
        self._restart_failures.append(f"{unit} ({message})")
        self._restart_next()

    # -- when the helper is missing ---------------------------------------

    def _explain_missing_helper(self, path: Path, diff: str) -> None:
        confirm(
            self._parent, "This change needs administrator rights",
            f"ClamGuard runs as you, not as root, so it cannot write to {path} "
            "on its own. A small helper script does the privileged work, and you "
            "install it yourself — ClamGuard will never do that for you.\n\n"
            "Run this in a terminal and then try again:\n\n"
            f"    {install_command()}\n\n"
            "The change that would have been made is shown below, so you can "
            "apply it by hand instead if you prefer.",
            detail=diff, detail_kind="diff", detail_label="THE CHANGE",
            confirm_text="Close", cancel_text="Cancel", tone="info",
            palette=resolve_palette(self.context.settings.str("theme")),
        )


class ServiceController(QObject):
    """Start, stop and enable ClamAV units, always with confirmation."""

    finished = Signal(bool, str)

    def __init__(self, context: AppContext, parent: QWidget) -> None:
        super().__init__(parent)
        self.context = context
        self._parent = parent

    def act(self, action: str, role: Role, *, ask: bool = True) -> bool:
        """Run one systemctl action on a role's unit."""
        unit = self.context.services.unit_for(role)
        if not unit:
            self.finished.emit(False, "There is no such unit on this machine.")
            return False

        if not self.context.privileged.available:
            confirm(
                self._parent, "This needs administrator rights",
                f"Controlling {unit} needs root. Install the ClamGuard helper to do "
                "it from here, or run this yourself:",
                detail=f"sudo systemctl {action} {unit}",
                detail_label="COMMAND",
                confirm_text="Close", cancel_text="Cancel", tone="info",
            )
            self.finished.emit(False, "The privileged helper is not installed.")
            return False

        if ask and not self._confirm(action, role, unit):
            self.finished.emit(False, "Cancelled.")
            return False

        call = self.context.privileged.service_action(action, unit)
        call.succeeded.connect(
            lambda _output: self._succeeded(action, unit))
        call.failed.connect(lambda message: self.finished.emit(False, message))
        call.cancelled.connect(
            lambda: self.finished.emit(False, "Cancelled at the password prompt."))
        call.start()
        return True

    def _succeeded(self, action: str, unit: str) -> None:
        log.info("%s %s", action, unit)
        self.context.services.refresh()
        self.finished.emit(True, f"{unit} {_past_tense(action)}.")

    def _confirm(self, action: str, role: Role, unit: str) -> bool:
        consequences = {
            "stop": {
                Role.DAEMON: "Scans will still work but will be much slower, and "
                             "real-time protection will stop too.",
                Role.UPDATER: "Virus signatures will stop updating automatically.",
                Role.ONACCESS: "Files will no longer be checked as they are opened. "
                               "Only scans you run yourself will find anything.",
            },
            "disable": {
                Role.DAEMON: "It will not start again after a reboot.",
                Role.UPDATER: "Signatures will not update after a reboot.",
                Role.ONACCESS: "Real-time protection will not come back after a reboot.",
            },
        }.get(action, {})

        detail = consequences.get(role, "")
        if not detail:
            return True  # starting or enabling something needs no warning

        return confirm(
            self._parent, f"{action.capitalize()} {unit}?",
            f"{detail}\n\nClamGuard will run: systemctl {action} {unit}",
            confirm_text=action.capitalize(), tone="warn", destructive=True,
        )


def _past_tense(action: str) -> str:
    return {
        "start": "started", "stop": "stopped", "restart": "restarted",
        "reload": "reloaded", "enable": "enabled", "disable": "disabled",
    }.get(action, action + "ed")
