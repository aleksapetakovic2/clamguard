"""The application window: sidebar, page stack, tray icon.

The window owns three things and delegates everything else:

* **Navigation.** One registry (:data:`PAGES`) maps a page id to its class.
  Adding a screen is one entry here plus one file in ui/pages/.
* **Appearance.** It applies the stylesheet and re-applies it when the user
  changes theme or accent, or when the desktop switches between light and dark.
* **Presence.** The tray icon, the close-to-tray behaviour, and drag-and-drop
  of files onto the window to scan them.

Pages never reach into the window. They emit `navigate`, `notify` and
`badge_changed`, and the window acts on those.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, QTimer
from PySide6.QtGui import QAction, QCloseEvent, QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QMenu,
    QMessageBox,
    QStackedWidget,
    QSystemTrayIcon,
    QWidget,
)

from .. import APP_NAME
from ..core.context import AppContext
from ..core.logging_setup import get_logger
from ..core.scan_targets import ScanKind
from . import icons, theme
from .pages.base import Page
from .sidebar import NavItem, Sidebar
from .widgets import ToastHost

log = get_logger(__name__)

#: Every page, in sidebar order. "section" inserts a divider when it changes.
NAV_ITEMS: tuple[NavItem, ...] = (
    NavItem("dashboard", "Dashboard", "dashboard"),
    NavItem("scan", "Scan", "scan"),
    NavItem("quarantine", "Quarantine", "quarantine"),
    NavItem("updates", "Updates", "updates"),
    NavItem("protection", "Protection", "protection"),
    NavItem("services", "Services", "services"),
    NavItem("boot", "Boot Analyzer", "boot"),
    NavItem("hunt", "Hunt", "hunt"),
    NavItem("history", "History", "history"),
    NavItem("logs", "Logs", "logs"),
    NavItem("configuration", "Configuration", "wrench", section="system"),
    NavItem("settings", "Preferences", "settings", section="system"),
)


def _page_classes() -> dict[str, type[Page]]:
    """Import the page classes.

    Done inside a function so that a syntax error in one page produces a clear
    message at start-up rather than a confusing import cycle, and so that
    ui.main_window can be imported by tests without pulling in every screen.
    """
    from .pages.boot import BootPage
    from .pages.configuration import ConfigurationPage
    from .pages.dashboard import DashboardPage
    from .pages.history import HistoryPage
    from .pages.hunt import HuntPage
    from .pages.logs import LogsPage
    from .pages.protection import ProtectionPage
    from .pages.quarantine import QuarantinePage
    from .pages.scan import ScanPage
    from .pages.services import ServicesPage
    from .pages.settings_page import SettingsPage
    from .pages.updates import UpdatesPage

    return {
        "dashboard": DashboardPage,
        "scan": ScanPage,
        "quarantine": QuarantinePage,
        "updates": UpdatesPage,
        "protection": ProtectionPage,
        "services": ServicesPage,
        "boot": BootPage,
        "hunt": HuntPage,
        "history": HistoryPage,
        "logs": LogsPage,
        "configuration": ConfigurationPage,
        "settings": SettingsPage,
    }


class MainWindow(QMainWindow):
    """The one window."""

    MINIMUM_SIZE = (940, 620)
    DEFAULT_SIZE = (1180, 780)

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self._pages: dict[str, Page] = {}
        self._current_page_id = ""
        self._really_quitting = False

        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(*self.MINIMUM_SIZE)
        self.setAcceptDrops(True)

        self._build()
        self.apply_theme()
        self._build_tray()
        self._connect()
        self._restore_geometry()

        self.show_page("dashboard")
        self._refresh_chrome()

    # -- construction -----------------------------------------------------

    def _build(self) -> None:
        root = QWidget()
        root.setObjectName("rootSurface")
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = Sidebar(list(NAV_ITEMS))
        self.sidebar.selected.connect(self.show_page)
        layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        self.setCentralWidget(root)
        self.toasts = ToastHost(root)

        classes = _page_classes()
        for item in NAV_ITEMS:
            page_class = classes.get(item.page_id)
            if page_class is None:
                continue
            page = page_class(self.context, self)
            page.navigate.connect(self.show_page)
            page.notify.connect(self.toasts.show_message)
            page.badge_changed.connect(
                lambda text, pid=item.page_id: self.sidebar.set_badge(pid, text)
            )
            page.request_scan.connect(self.start_scan)
            page.theme_refresh_requested.connect(
                lambda pg=page: self.apply_palette_to(pg))
            self._pages[item.page_id] = page
            self.stack.addWidget(page)

        self._add_shortcuts()

    def _add_shortcuts(self) -> None:
        """Keyboard access to the things people do most."""
        for key, page_id in (
            ("Ctrl+1", "dashboard"), ("Ctrl+2", "scan"), ("Ctrl+3", "quarantine"),
            ("Ctrl+4", "updates"), ("Ctrl+5", "protection"), ("Ctrl+6", "boot"),
            ("Ctrl+7", "hunt"), ("Ctrl+8", "history"), ("Ctrl+9", "logs"),
            ("Ctrl+0", "services"), ("Ctrl+,", "settings"),
        ):
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.activated.connect(lambda pid=page_id: self.show_page(pid))

        refresh = QShortcut(QKeySequence("F5"), self)
        refresh.activated.connect(self._refresh_everything)

    def _connect(self) -> None:
        self.context.status_changed.connect(self._refresh_chrome)
        self.context.appearance_changed.connect(self.apply_theme)
        self.context.scheduler.due.connect(self._on_schedule_due)
        self.context.scanner.threat_found.connect(self._on_threat_found)
        self.context.realtime.detected.connect(self._on_realtime_detection)
        self.context.scanner.finished.connect(self._on_scan_finished)
        self.context.quarantine.changed.connect(self._refresh_chrome)

        hints = QGuiApplication.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(self._on_system_theme_changed)

    # -- appearance -------------------------------------------------------

    def apply_theme(self) -> None:
        """Rebuild and apply the stylesheet from the current preferences."""
        palette = theme.resolve_palette(self.context.settings.str("theme"))
        accent = self.context.settings.str("accent")
        icons.configure(palette, accent)

        application = QApplication.instance()
        if application is not None:
            application.setStyleSheet(theme.build_stylesheet(palette, accent))

        self.sidebar.set_accent(accent)
        self.sidebar.refresh_icons()
        self.setWindowIcon(icons.logo(64, accent))
        if hasattr(self, "tray"):
            self._refresh_tray_icon()

        self.apply_palette_to(self)
        self._refresh_chrome()
        self._fit_minimum_size()

    def _fit_minimum_size(self) -> None:
        """Never let the window be shorter than the sidebar.

        An explicit setMinimumSize overrides the layout's minimum in Qt, so a
        fixed MINIMUM_SIZE silently goes stale: adding the Services page made
        the sidebar 639px tall against a 620px floor, and at the minimum size
        its status card slid under "Preferences". Re-derived whenever the theme
        — and so every padding — changes.

        Height only, and only from the sidebar. The pages are built lazily, so
        deriving the width from their minimums as well made the window's floor
        depend on which pages had been opened before the theme last changed.
        Pages are instead required to lay out inside MINIMUM_SIZE; the UI smoke
        test measures every one of them at that size.
        """
        needed = self.sidebar.minimumSizeHint().height()
        self.setMinimumSize(self.MINIMUM_SIZE[0], max(self.MINIMUM_SIZE[1], needed))

    def apply_palette_to(self, root: QWidget) -> None:
        """Hand the palette to every self-painting widget under `root`.

        ProgressRing and ToggleSwitch draw themselves, so a stylesheet cannot
        reach them. Pages that build widgets lazily emit
        `theme_refresh_requested` and land here.
        """
        palette = theme.resolve_palette(self.context.settings.str("theme"))
        accent = self.context.settings.str("accent")
        targets = [root, *root.findChildren(QWidget)]
        for widget in targets:
            apply = getattr(widget, "apply_palette", None)
            if callable(apply):
                apply(palette, accent)

    def _on_system_theme_changed(self, _scheme) -> None:
        if self.context.settings.str("theme") == "auto":
            self.apply_theme()

    # -- navigation -------------------------------------------------------

    def show_page(self, page_id: str) -> None:
        page = self._pages.get(page_id)
        if page is None:
            log.warning("no such page: %s", page_id)
            return

        if self._current_page_id and self._current_page_id != page_id:
            previous = self._pages.get(self._current_page_id)
            if previous is not None:
                previous.on_hidden()

        page.ensure_built()
        self.stack.setCurrentWidget(page)
        self.sidebar.select(page_id)
        self._current_page_id = page_id
        page.on_shown()
        self.sidebar.set_badge(page_id, page.badge())

    def current_page(self) -> Page | None:
        return self._pages.get(self._current_page_id)

    def start_scan(self, kind: ScanKind, targets: list[Path] | None = None) -> None:
        """Run a scan on behalf of whichever page asked for one."""
        self.show_page("scan")
        page = self._pages.get("scan")
        if targets:
            starter = getattr(page, "start_custom_scan", None)
            if callable(starter):
                starter(targets)
            return
        starter = getattr(page, "start_preset_scan", None)
        if callable(starter):
            starter(kind)

    # -- status chrome ----------------------------------------------------

    def _refresh_chrome(self) -> None:
        """Update the sidebar footer, badges and tray tooltip."""
        status = self.context.protection_status()
        detail = f"{len(status.issues)} to review" if status.issues else "Everything checks out"
        self.sidebar.set_status(status.level.title, detail, status.level.tone,
                                status.level.icon)

        version = self.context.clamav.version
        self.sidebar.set_engine_text(f"ClamAV {version}" if version.engine else "ClamAV")

        quarantined = self.context.quarantine.count()
        self.sidebar.set_badge("quarantine", str(quarantined) if quarantined else "")

        caught = len(self.context.realtime.history)
        if self._current_page_id != "protection":
            self.sidebar.set_badge("protection", str(caught) if caught else "")

        if hasattr(self, "tray"):
            self.tray.setToolTip(f"{APP_NAME} — {status.level.title}")
            self._refresh_tray_icon()

    def _refresh_everything(self) -> None:
        self.context.refresh_deep()
        page = self.current_page()
        if page is not None:
            page.on_shown()
        self.toasts.show_message("Refreshed.", "info")

    # -- tray -------------------------------------------------------------

    def _build_tray(self) -> None:
        self.tray = QSystemTrayIcon(self)
        self._refresh_tray_icon()

        menu = QMenu(self)
        open_action = QAction("Open ClamGuard", self)
        open_action.triggered.connect(self._restore_window)
        menu.addAction(open_action)
        menu.addSeparator()

        quick = QAction("Quick scan", self)
        quick.triggered.connect(lambda: self._start_scan_from_tray(ScanKind.QUICK))
        menu.addAction(quick)

        update = QAction("Update signatures", self)
        update.triggered.connect(lambda: self.show_page("updates"))
        menu.addAction(update)
        menu.addSeparator()

        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.quit_application)
        menu.addAction(quit_action)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        self._update_tray_visibility()
        self.context.settings.changed.connect(self._on_setting_changed)

    def _refresh_tray_icon(self) -> None:
        accent = self.context.settings.str("accent")
        self.tray.setIcon(icons.logo(64, accent))

    def _update_tray_visibility(self) -> None:
        wanted = self.context.settings.bool("show_tray_icon")
        if wanted and QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()
        else:
            self.tray.hide()

    def _on_setting_changed(self, key: str, _value) -> None:
        if key == "show_tray_icon":
            self._update_tray_visibility()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._restore_window()

    def _restore_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _start_scan_from_tray(self, kind: ScanKind) -> None:
        self._restore_window()
        self.start_scan(kind)

    # -- notifications ----------------------------------------------------

    def notify_desktop(self, title: str, message: str,
                       level: QSystemTrayIcon.MessageIcon | None = None) -> None:
        """A desktop notification through the tray, when one is available."""
        if not self.tray.isVisible():
            return
        icon = level or QSystemTrayIcon.MessageIcon.Information
        self.tray.showMessage(title, message, icon, 8000)

    def _on_threat_found(self, threat) -> None:
        if self.context.settings.bool("notify_on_threat"):
            self.notify_desktop(
                "Threat detected",
                f"{threat.name}\n{threat.path}",
                QSystemTrayIcon.MessageIcon.Critical,
            )

    def _on_realtime_detection(self, detection) -> None:
        """Real-time protection caught something while the user was elsewhere."""
        self.toasts.show_message(
            f"Real-time protection caught {detection.threat} in {detection.filename}.",
            "danger")
        if self.context.settings.bool("notify_on_threat"):
            self.notify_desktop(
                "Threat blocked in real time",
                f"{detection.threat}\n{detection.path}",
                QSystemTrayIcon.MessageIcon.Critical,
            )
        page = self._pages.get("protection")
        if page is not None and page is not self.current_page():
            self.sidebar.set_badge("protection", str(len(self.context.realtime.history)))

    def _on_scan_finished(self, result) -> None:
        if result.threats and self.context.settings.bool("notify_on_threat"):
            count = len(result.threats)
            self.notify_desktop(
                "Scan finished",
                f"{count} threat{'' if count == 1 else 's'} found. "
                "Open ClamGuard to deal with them.",
                QSystemTrayIcon.MessageIcon.Critical,
            )

    def _on_schedule_due(self, schedule) -> None:
        """A scheduled scan came due. Run it unless something else is going on."""
        if self.context.scanner.busy:
            log.info("skipping scheduled scan %s: another scan is running", schedule.name)
            self.toasts.show_message(
                f"Skipped the scheduled scan “{schedule.name}” — a scan was already running.",
                "warn")
            return
        page = self._pages.get("scan")
        runner = getattr(page, "start_scheduled_scan", None)
        if callable(runner):
            self.show_page("scan")
            runner(schedule)
            self.toasts.show_message(f"Started the scheduled scan “{schedule.name}”.", "info")

    # -- drag and drop ----------------------------------------------------

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt naming
        paths = [
            Path(url.toLocalFile())
            for url in event.mimeData().urls()
            if url.isLocalFile()
        ]
        paths = [path for path in paths if path.exists()]
        if not paths:
            return
        event.acceptProposedAction()

        page = self._pages.get("scan")
        starter = getattr(page, "start_custom_scan", None)
        if callable(starter):
            self.show_page("scan")
            starter(paths)

    # -- window lifecycle -------------------------------------------------

    def _restore_geometry(self) -> None:
        stored = self.context.settings.str("window_geometry")
        if stored:
            try:
                self.restoreGeometry(QByteArray.fromBase64(stored.encode("ascii")))
                return
            except (ValueError, TypeError):
                pass
        self.resize(*self.DEFAULT_SIZE)

    def _save_geometry(self) -> None:
        encoded = bytes(self.saveGeometry().toBase64()).decode("ascii")
        self.context.settings.set("window_geometry", encoded)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt naming
        """Closing hides to the tray unless the user asked otherwise."""
        if self._really_quitting:
            self._save_geometry()
            event.accept()
            return

        if self.context.scanner.busy:
            answer = QMessageBox.question(
                self, "A scan is running",
                "A scan is still running. Stop it and quit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.context.scanner.stop()

        if self.context.settings.bool("close_to_tray") and self.tray.isVisible():
            self._save_geometry()
            self.hide()
            event.ignore()
            QTimer.singleShot(200, lambda: self.notify_desktop(
                APP_NAME, "Still running in the tray. Scheduled scans continue."))
            return

        self._save_geometry()
        event.accept()
        self.quit_application()

    def quit_application(self) -> None:
        """Really quit, whatever close-to-tray says."""
        self._really_quitting = True
        self._save_geometry()
        for page in self._pages.values():
            try:
                page.shutdown()
            except Exception:  # noqa: BLE001 - a bad page must not block quitting
                log.exception("page %s failed to shut down", page.PAGE_ID)
        self.context.shutdown()
        self.tray.hide()
        application = QApplication.instance()
        if application is not None:
            application.quit()
