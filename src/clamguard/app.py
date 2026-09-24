"""Application bootstrap: build the context, build the window, run the loop.

Deliberately thin. Everything it does is arrange for other things to exist in
the right order:

1. configure logging, so a crash during start-up is recorded;
2. create the QApplication and set the Qt attributes that must be set early;
3. build the AppContext, which constructs every service;
4. build the MainWindow, which builds the pages;
5. start the scheduler and run.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from . import APP_ID, APP_NAME, __version__
from .core import paths
from .core.logging_setup import configure, get_logger

log = get_logger(__name__)


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="clamguard",
        description=f"{APP_NAME} — a desktop antivirus for Linux, built on ClamAV.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log debug output to the terminal as well as the log file")
    parser.add_argument("--minimised", "--minimized", dest="minimised",
                        action="store_true",
                        help="start hidden in the system tray")
    parser.add_argument("paths", metavar="PATH", nargs="*",
                        help="scan these files or folders — what \"Open with "
                             "ClamGuard\" in a file manager passes")
    parser.add_argument("--scan", metavar="PATH", nargs="*",
                        help="scan these paths straight away; with no paths, "
                             "run a quick scan")
    parser.add_argument("--page", metavar="PAGE",
                        help="open on this page: dashboard, scan, quarantine, "
                             "updates, protection, services, boot, hunt, "
                             "history, logs, configuration or settings")
    parser.add_argument("--write-icon", metavar="FILE",
                        help="write the application icon as SVG and exit "
                             "(used by install.sh)")
    return parser.parse_args(argv)


def create_application(argv: list[str]) -> QApplication:
    """A QApplication with the attributes Qt wants set before any widget exists."""
    application = QApplication(argv)
    application.setApplicationName(APP_NAME)
    application.setApplicationDisplayName(APP_NAME)
    application.setApplicationVersion(__version__)
    # Must match the installed .desktop file's name. On Wayland this becomes
    # the window's app_id, which is how the compositor finds the menu entry and
    # its icon; "org.clamguard.clamguard" against an installed clamguard.desktop
    # left the taskbar showing a generic icon.
    application.setDesktopFileName(APP_ID)
    application.setOrganizationName(APP_NAME)
    # Closing the window to the tray must not end the process.
    application.setQuitOnLastWindowClosed(False)
    return application


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv if argv is not None else sys.argv[1:])

    if arguments.write_icon:
        return _write_icon(arguments.write_icon)

    paths.ensure_directories()
    configure(verbose=arguments.verbose)
    log.info("%s %s starting", APP_NAME, __version__)

    application = create_application(sys.argv[:1])

    # A second launch hands its request to the running instance and leaves.
    # See core/single_instance.py for why a second copy is the normal case.
    from .core.single_instance import SingleInstance

    request = request_from(arguments)
    if SingleInstance.forward(request):
        log.info("handed the request to the ClamGuard that is already running")
        return 0
    instance = SingleInstance()
    if not instance.listen():
        log.warning("could not claim the single-instance socket; continuing anyway")

    # Ctrl-C in a terminal should end the app, which Qt otherwise swallows.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    keep_alive = QTimer()
    keep_alive.start(250)
    keep_alive.timeout.connect(lambda: None)

    try:
        from .core.context import AppContext
        from .ui.main_window import MainWindow

        context = AppContext()
        window = MainWindow(context)
    except Exception as error:  # noqa: BLE001 - a start-up crash must be explained
        log.exception("could not start")
        QMessageBox.critical(
            None, f"{APP_NAME} could not start",
            f"{error}\n\nThe details are in:\n{paths.APP_LOG}",
        )
        return 1

    if not context.clamav.installed:
        QMessageBox.warning(
            window, "ClamAV is not installed",
            "ClamGuard drives ClamAV, and ClamAV does not appear to be installed.\n\n"
            "Install the 'clamav' package for your distribution, then restart "
            "ClamGuard.\n\nYou can still look around, but nothing can be scanned.",
        )

    start_minimised = arguments.minimised or context.settings.bool("start_minimised")
    if start_minimised and context.settings.bool("show_tray_icon"):
        log.info("starting minimised to the tray")
    else:
        window.show()

    context.scheduler.start()

    instance.request_received.connect(lambda forwarded: apply_request(window, forwarded))
    application.aboutToQuit.connect(instance.close)
    if request.get("scan") or request.get("quick") or request.get("page"):
        QTimer.singleShot(400, lambda: apply_request(window, request))

    return application.exec()


def request_from(arguments: argparse.Namespace) -> dict:
    """What this launch is asking for, in the form a running instance takes."""
    # Absolute here, in the process that was given them: a relative path
    # forwarded to the running instance would be resolved against *its*
    # working directory and name a different file, or none.
    targets = [os.path.abspath(os.path.expanduser(target))
               for target in list(arguments.paths or []) + list(arguments.scan or [])]
    request: dict = {"show": not arguments.minimised}
    if targets:
        request["scan"] = targets
    elif arguments.scan is not None:
        # `--scan` on its own: the desktop file's "Quick scan" action. It used
        # to be `--scan %f`, and from the application menu %f expands to
        # nothing, so the action died with an argparse error.
        request["quick"] = True
    if arguments.page:
        request["page"] = arguments.page
    return request


def apply_request(window, request: dict) -> None:
    """Carry out a launch's request — this one's own, or a later launch's."""
    if request.get("show") or request.get("scan") or request.get("quick") or request.get("page"):
        if window.isMinimized():
            window.showNormal()
        else:
            window.show()
        window.raise_()
        window.activateWindow()
    if request.get("page"):
        window.show_page(request["page"])
    if request.get("scan"):
        _scan_from_command_line(window, request["scan"])
    elif request.get("quick"):
        from .core.scan_targets import ScanKind

        window.start_scan(ScanKind.QUICK)


def _write_icon(destination: str) -> int:
    """Write the app icon to a file. Used by install.sh, never by the GUI."""
    from pathlib import Path

    from .ui.icons import logo_svg

    try:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(logo_svg("blue"), encoding="utf-8")
    except OSError as error:
        print(f"clamguard: cannot write {destination}: {error}", file=sys.stderr)
        return 1
    return 0


def _scan_from_command_line(window, targets: list[str]) -> None:
    """Handle `clamguard --scan /some/path`."""
    from pathlib import Path

    paths_to_scan = [Path(target).expanduser() for target in targets]
    existing = [path for path in paths_to_scan if path.exists()]
    if not existing:
        window.toasts.show_message("None of those paths exist.", "danger")
        return
    window.show()
    window.show_page("scan")
    page = window._pages.get("scan")
    starter = getattr(page, "start_custom_scan", None)
    if callable(starter):
        starter(existing)


if __name__ == "__main__":
    sys.exit(main())
