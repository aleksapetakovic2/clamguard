"""ClamGuard's own preferences — not ClamAV's.

Everything here writes to ~/.config/clamguard/. The one exception is the
"Start ClamGuard when I log in" switch, which writes a .desktop file to
~/.config/autostart/; that is still inside the user's own configuration and it
says so on the switch.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import QTime

from ... import APP_NAME, __version__
from ...core import paths
from ...core.database import format_bytes
from ...core.privileged import install_command
from ...core.scan_profile import PRESETS
from ...core.scan_targets import ScanKind
from ...core.scheduler import WEEKDAY_NAMES, Schedule
from .. import icons
from ..theme import ACCENTS, SPACE_MD, SPACE_SM
from ..dialogs import confirm
from ..widgets import (
    Badge,
    Card,
    KeyValueRow,
    Separator,
    ToggleSwitch,
    flow_row,
    label,
)
from .base import Page

#: The autostart entry ClamGuard writes when asked to start at login.
AUTOSTART_FILE = Path(
    os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
) / "autostart" / "clamguard.desktop"


class AccentSwatch(QPushButton):
    """A clickable colour circle for picking the accent."""

    SIZE = 26

    def __init__(self, name: str, colour: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.name = name
        self.colour = colour
        self.setCheckable(True)
        self.setFixedSize(QSize(self.SIZE, self.SIZE))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(name.capitalize())
        self.setStyleSheet("QPushButton { border: none; background: transparent; }")

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(self.colour))
        inset = 3 if self.isChecked() else 1
        painter.drawEllipse(inset, inset, self.SIZE - inset * 2, self.SIZE - inset * 2)
        if self.isChecked():
            pen = painter.pen()
            pen.setColor(QColor(self.colour))
            pen.setWidth(2)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(1, 1, self.SIZE - 2, self.SIZE - 2)
        painter.end()


class ScheduleDialog(QDialog):
    """Create or edit one scheduled scan."""

    def __init__(self, schedule: Schedule, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Scheduled scan")
        self.setMinimumWidth(480)
        self.schedule = schedule

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_MD * 2, SPACE_MD * 2, SPACE_MD * 2, SPACE_MD)
        column.setSpacing(SPACE_MD)

        form = QFormLayout()
        form.setSpacing(SPACE_SM)

        self.name_box = QLineEdit(schedule.name)
        form.addRow("Name", self.name_box)

        self.kind_box = QComboBox()
        for kind in (ScanKind.QUICK, ScanKind.HOME, ScanKind.FULL,
                     ScanKind.REMOVABLE, ScanKind.CUSTOM):
            self.kind_box.addItem(kind.title, kind.value)
        index = self.kind_box.findData(schedule.kind)
        self.kind_box.setCurrentIndex(max(0, index))
        self.kind_box.currentIndexChanged.connect(self._refresh_custom)
        form.addRow("What to scan", self.kind_box)

        self.custom_box = QPlainTextEdit("\n".join(schedule.custom_paths))
        self.custom_box.setPlaceholderText("One path per line")
        self.custom_box.setMaximumHeight(80)
        form.addRow("Paths", self.custom_box)
        self._custom_label_row = form.rowCount() - 1

        self.profile_box = QComboBox()
        for preset in PRESETS:
            self.profile_box.addItem(preset.name, preset.id)
        self.profile_box.setCurrentIndex(
            max(0, self.profile_box.findData(schedule.profile_id)))
        form.addRow("Depth", self.profile_box)

        self.frequency_box = QComboBox()
        for title, value in (("Every hour", "hourly"), ("Every day", "daily"),
                             ("Every week", "weekly"), ("Every month", "monthly")):
            self.frequency_box.addItem(title, value)
        self.frequency_box.setCurrentIndex(
            max(0, self.frequency_box.findData(schedule.frequency)))
        self.frequency_box.currentIndexChanged.connect(self._refresh_frequency)
        form.addRow("How often", self.frequency_box)

        self.time_box = QTimeEdit()
        hour, _, minute = schedule.time_of_day.partition(":")
        self.time_box.setTime(QTime(int(hour or 3), int(minute or 0)))
        self.time_box.setDisplayFormat("HH:mm")
        form.addRow("At", self.time_box)

        self.weekday_box = QComboBox()
        self.weekday_box.addItems(list(WEEKDAY_NAMES))
        self.weekday_box.setCurrentIndex(schedule.day_of_week % 7)
        form.addRow("Day of the week", self.weekday_box)

        self.monthday_box = QSpinBox()
        self.monthday_box.setRange(1, 28)
        self.monthday_box.setValue(schedule.day_of_month)
        form.addRow("Day of the month", self.monthday_box)

        column.addLayout(form)

        self.catch_up = ToggleSwitch("Run it late if ClamGuard was closed at the time")
        self.catch_up.setChecked(schedule.catch_up)
        column.addWidget(self.catch_up)

        column.addWidget(label(
            "Scheduled scans only run while ClamGuard is running. Keep the tray icon "
            "on, or switch on “Start when I log in”, so they actually happen.",
            role="caption", wrap=True))

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        column.addWidget(buttons)

        self._refresh_frequency()
        self._refresh_custom()

    def _refresh_frequency(self) -> None:
        frequency = self.frequency_box.currentData()
        self.time_box.setEnabled(frequency != "hourly")
        self.weekday_box.setEnabled(frequency == "weekly")
        self.monthday_box.setEnabled(frequency == "monthly")

    def _refresh_custom(self) -> None:
        self.custom_box.setEnabled(self.kind_box.currentData() == ScanKind.CUSTOM.value)

    def result_schedule(self) -> Schedule:
        self.schedule.name = self.name_box.text().strip() or "Scheduled scan"
        self.schedule.kind = self.kind_box.currentData()
        self.schedule.custom_paths = [
            line.strip() for line in self.custom_box.toPlainText().splitlines()
            if line.strip()
        ]
        self.schedule.profile_id = self.profile_box.currentData()
        self.schedule.frequency = self.frequency_box.currentData()
        self.schedule.time_of_day = self.time_box.time().toString("HH:mm")
        self.schedule.day_of_week = self.weekday_box.currentIndex()
        self.schedule.day_of_month = self.monthday_box.value()
        self.schedule.catch_up = self.catch_up.isChecked()
        return self.schedule


class SettingsPage(Page):
    PAGE_ID = "settings"
    TITLE = "Preferences"
    SUBTITLE = "How ClamGuard itself behaves"
    ICON = "settings"

    def build(self) -> None:
        self.body.addWidget(self._build_appearance())
        self.body.addWidget(self._build_behaviour())
        self.body.addWidget(self._build_scanning())
        self.body.addWidget(self._build_schedules())
        self.body.addWidget(self._build_data())
        self.body.addWidget(self._build_about())
        self.add_stretch()
        self.context.scheduler.changed.connect(self._refresh_schedules)

    # -- appearance -------------------------------------------------------

    def _build_appearance(self) -> Card:
        card = Card("Appearance", icon="sun")

        theme_row = QHBoxLayout()
        theme_row.setSpacing(SPACE_MD)
        theme_row.addWidget(label("Theme", role="body"), 1)
        self.theme_box = QComboBox()
        for title, value in (("Follow the desktop", "auto"), ("Light", "light"),
                             ("Dark", "dark")):
            self.theme_box.addItem(title, value)
        self.theme_box.setCurrentIndex(
            max(0, self.theme_box.findData(self.context.settings.str("theme"))))
        self.theme_box.currentIndexChanged.connect(
            lambda: self.context.settings.set("theme", self.theme_box.currentData()))
        theme_row.addWidget(self.theme_box, 1)
        card.body.addLayout(theme_row)

        accent_row = QHBoxLayout()
        accent_row.setSpacing(SPACE_MD)
        accent_row.addWidget(label("Highlight colour", role="body"), 1)
        swatches = QHBoxLayout()
        swatches.setSpacing(SPACE_SM)
        current = self.context.settings.str("accent")
        self._swatches: list[AccentSwatch] = []
        for name, (base, _hover, _pressed) in ACCENTS.items():
            swatch = AccentSwatch(name, base)
            swatch.setChecked(name == current)
            swatch.clicked.connect(lambda _=False, n=name: self._pick_accent(n))
            self._swatches.append(swatch)
            swatches.addWidget(swatch)
        swatches.addStretch(1)
        accent_row.addLayout(swatches, 1)
        card.body.addLayout(accent_row)
        return card

    def _pick_accent(self, name: str) -> None:
        for swatch in self._swatches:
            swatch.setChecked(swatch.name == name)
            swatch.update()
        self.context.settings.set("accent", name)

    # -- behaviour --------------------------------------------------------

    def _build_behaviour(self) -> Card:
        card = Card("Behaviour", icon="cpu")

        self.tray_toggle = self._switch_row(
            card, "Show an icon in the system tray",
            "Lets ClamGuard keep running when the window is closed, which is what "
            "scheduled scans need.", "show_tray_icon")
        self.close_toggle = self._switch_row(
            card, "Closing the window hides it instead of quitting",
            "Use Quit in the tray menu to stop ClamGuard completely.",
            "close_to_tray")
        self.minimised_toggle = self._switch_row(
            card, "Start hidden in the tray",
            "The window does not appear when ClamGuard launches.", "start_minimised")

        card.body.addWidget(Separator())
        autostart_row = QHBoxLayout()
        autostart_row.setSpacing(SPACE_MD)
        texts = QVBoxLayout()
        texts.setSpacing(1)
        texts.addWidget(label("Start ClamGuard when I log in", role="body"))
        texts.addWidget(label(
            f"Writes a desktop entry to {AUTOSTART_FILE}. Nothing outside your own "
            "configuration is touched.", role="caption", wrap=True))
        autostart_row.addLayout(texts, 1)
        self.autostart_toggle = ToggleSwitch()
        self.autostart_toggle.setChecked(AUTOSTART_FILE.is_file())
        self.autostart_toggle.clicked.connect(self._toggle_autostart)
        autostart_row.addWidget(self.autostart_toggle, 0)
        card.body.addLayout(autostart_row)

        card.body.addWidget(Separator())
        self.notify_threat_toggle = self._switch_row(
            card, "Notify me when a threat is found", "", "notify_on_threat")
        self.notify_update_toggle = self._switch_row(
            card, "Notify me when signatures are updated", "", "notify_on_update")
        self.confirm_delete_toggle = self._switch_row(
            card, "Ask before deleting a file for good", "", "confirm_before_delete")
        return card

    def _switch_row(self, card: Card, title: str, description: str,
                    key: str) -> ToggleSwitch:
        row = QHBoxLayout()
        row.setSpacing(SPACE_MD)
        texts = QVBoxLayout()
        texts.setSpacing(1)
        texts.addWidget(label(title, role="body"))
        if description:
            texts.addWidget(label(description, role="caption", wrap=True))
        row.addLayout(texts, 1)

        toggle = ToggleSwitch()
        toggle.setChecked(self.context.settings.bool(key))
        toggle.toggled.connect(lambda checked: self.context.settings.set(key, checked))
        row.addWidget(toggle, 0)
        card.body.addLayout(row)
        return toggle

    def _toggle_autostart(self) -> None:
        wanted = self.autostart_toggle.isChecked()
        try:
            if wanted:
                AUTOSTART_FILE.parent.mkdir(parents=True, exist_ok=True)
                AUTOSTART_FILE.write_text(_autostart_entry(), encoding="utf-8")
                self.notify.emit("ClamGuard will start when you log in.", "ok")
            else:
                AUTOSTART_FILE.unlink(missing_ok=True)
                self.notify.emit("ClamGuard will no longer start at login.", "info")
        except OSError as error:
            self.autostart_toggle.setChecked(not wanted)
            self.notify.emit(f"Could not change the autostart entry: {error}", "danger")

    # -- scanning ---------------------------------------------------------

    def _build_scanning(self) -> Card:
        card = Card("Scanning", "Defaults for new scans", icon="scan")

        depth_row = QHBoxLayout()
        depth_row.setSpacing(SPACE_MD)
        depth_row.addWidget(label("Default depth", role="body"), 1)
        self.profile_box = QComboBox()
        for preset in PRESETS:
            self.profile_box.addItem(preset.name, preset.id)
        self.profile_box.setCurrentIndex(max(0, self.profile_box.findData(
            self.context.settings.str("default_profile"))))
        self.profile_box.currentIndexChanged.connect(
            lambda: self.context.settings.set(
                "default_profile", self.profile_box.currentData()))
        depth_row.addWidget(self.profile_box, 1)
        card.body.addLayout(depth_row)

        action_row = QHBoxLayout()
        action_row.setSpacing(SPACE_MD)
        action_row.addWidget(label("When a threat is found", role="body"), 1)
        self.action_box = QComboBox()
        self.action_box.addItem("List it and let me decide", "report")
        self.action_box.addItem("Move it to quarantine straight away", "quarantine")
        self.action_box.setCurrentIndex(max(0, self.action_box.findData(
            self.context.settings.str("on_threat_action"))))
        self.action_box.currentIndexChanged.connect(
            lambda: self.context.settings.set(
                "on_threat_action", self.action_box.currentData()))
        action_row.addWidget(self.action_box, 1)
        card.body.addLayout(action_row)

        self.hidden_toggle = self._switch_row(
            card, "Include hidden files and folders",
            "Malware in a dot-directory is still malware.", "scan_hidden_files")

        card.body.addWidget(Separator())
        card.body.addWidget(label("What a quick scan covers", role="sectionLabel"))
        card.body.addWidget(label(
            "Leave this empty to use the built-in list: Downloads, Desktop, "
            "Documents, the trash, /tmp and /var/tmp.", role="caption", wrap=True))
        self.quick_paths = QPlainTextEdit(
            "\n".join(self.context.settings.list("quick_scan_paths")))
        self.quick_paths.setPlaceholderText("One path per line")
        self.quick_paths.setMaximumHeight(90)
        self.quick_paths.textChanged.connect(self._save_quick_paths)
        card.body.addWidget(self.quick_paths)

        add_row = QHBoxLayout()
        add_row.setSpacing(SPACE_SM)
        add_button = QPushButton("Add a folder…")
        add_button.setIcon(icons.icon("plus", tone="muted", size=16))
        add_button.clicked.connect(self._add_quick_path)
        add_row.addWidget(add_button)
        add_row.addStretch(1)
        card.body.addLayout(add_row)

        card.body.addWidget(Separator())
        card.body.addWidget(label("Never scan paths matching", role="sectionLabel"))
        card.body.addWidget(label(
            "Regular expressions, one per line. These apply to every scan ClamGuard "
            "runs. ClamAV's own ExcludePath setting is on the Configuration page.",
            role="caption", wrap=True))
        self.exclusions = QPlainTextEdit(
            "\n".join(self.context.settings.list("excluded_paths")))
        self.exclusions.setPlaceholderText(r"e.g.  ^/home/[^/]+/\.cache/")
        self.exclusions.setMaximumHeight(90)
        self.exclusions.textChanged.connect(self._save_exclusions)
        card.body.addWidget(self.exclusions)

        card.body.addWidget(Separator())
        age_row = QHBoxLayout()
        age_row.setSpacing(SPACE_MD)
        age_row.addWidget(label("Warn when signatures are older than", role="body"), 1)
        self.age_box = QSpinBox()
        self.age_box.setRange(1, 90)
        self.age_box.setSuffix(" days")
        self.age_box.setValue(self.context.settings.int("warn_db_age_days"))
        self.age_box.valueChanged.connect(
            lambda value: self.context.settings.set("warn_db_age_days", value))
        age_row.addWidget(self.age_box, 1)
        card.body.addLayout(age_row)
        return card

    def _save_quick_paths(self) -> None:
        self.context.settings.set("quick_scan_paths", [
            line.strip() for line in self.quick_paths.toPlainText().splitlines()
            if line.strip()
        ])

    def _save_exclusions(self) -> None:
        self.context.settings.set("excluded_paths", [
            line.strip() for line in self.exclusions.toPlainText().splitlines()
            if line.strip()
        ])

    def _add_quick_path(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Add a folder to the quick scan", str(Path.home()))
        if not chosen:
            return
        existing = self.quick_paths.toPlainText().strip()
        self.quick_paths.setPlainText(f"{existing}\n{chosen}" if existing else chosen)

    # -- schedules --------------------------------------------------------

    def _build_schedules(self) -> Card:
        card = Card("Scheduled scans", "Run automatically while ClamGuard is open",
                    icon="schedule")
        add = QPushButton("Add a schedule")
        add.setProperty("variant", "primary")
        add.setIcon(icons.icon("plus", "#ffffff", size=16))
        add.clicked.connect(self._add_schedule)
        card.add_action(add)

        self.schedule_list = QListWidget()
        self.schedule_list.setMaximumHeight(190)
        self.schedule_list.itemDoubleClicked.connect(
            lambda item: self._edit_schedule(item.data(Qt.ItemDataRole.UserRole)))
        card.body.addWidget(self.schedule_list)

        buttons = QHBoxLayout()
        buttons.setSpacing(SPACE_SM)
        edit = QPushButton("Edit")
        edit.clicked.connect(self._edit_selected_schedule)
        remove = QPushButton("Remove")
        remove.setProperty("variant", "danger")
        remove.clicked.connect(self._remove_selected_schedule)
        self.toggle_schedule = QPushButton("Turn on or off")
        self.toggle_schedule.clicked.connect(self._toggle_selected_schedule)
        buttons.addWidget(edit)
        buttons.addWidget(self.toggle_schedule)
        buttons.addStretch(1)
        buttons.addWidget(remove)
        card.body.addLayout(buttons)

        self.next_due_label = label("", role="caption")
        card.body.addWidget(self.next_due_label)
        self.schedules_card = card
        return card

    def _refresh_schedules(self) -> None:
        self.schedule_list.clear()
        for schedule in self.context.scheduler.schedules():
            state = "on" if schedule.enabled else "off"
            item = QListWidgetItem(
                f"{schedule.name}   ·   {schedule.describe()}   ·   {state}")
            item.setData(Qt.ItemDataRole.UserRole, schedule)
            self.schedule_list.addItem(item)

        upcoming = self.context.scheduler.next_due()
        if upcoming:
            schedule, when = upcoming
            self.next_due_label.setText(
                f"Next: {schedule.name} at {when:%A %d %B, %H:%M}")
        elif self.context.scheduler.schedules():
            self.next_due_label.setText("Nothing is enabled.")
        else:
            self.next_due_label.setText(
                "No schedules yet. A nightly quick scan is a good default.")

    def _selected_schedule(self) -> Schedule | None:
        item = self.schedule_list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _add_schedule(self) -> None:
        dialog = ScheduleDialog(Schedule(name="Nightly quick scan"), self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.context.scheduler.add(dialog.result_schedule())
            self.notify.emit("Schedule added.", "ok")

    def _edit_selected_schedule(self) -> None:
        schedule = self._selected_schedule()
        if schedule is not None:
            self._edit_schedule(schedule)

    def _edit_schedule(self, schedule: Schedule) -> None:
        dialog = ScheduleDialog(schedule, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.context.scheduler.update(dialog.result_schedule())
            self.notify.emit("Schedule saved.", "ok")

    def _remove_selected_schedule(self) -> None:
        schedule = self._selected_schedule()
        if schedule is None:
            return
        if confirm(self, "Remove this schedule?",
                   f"“{schedule.name}” will no longer run automatically.",
                   confirm_text="Remove", tone="warn", destructive=True):
            self.context.scheduler.remove(schedule.id)

    def _toggle_selected_schedule(self) -> None:
        schedule = self._selected_schedule()
        if schedule is not None:
            self.context.scheduler.set_enabled(schedule.id, not schedule.enabled)

    # -- data -------------------------------------------------------------

    def _build_data(self) -> Card:
        card = Card("Your data", "Everything ClamGuard stores, and how to remove it",
                    icon="database")
        self.data_box = QVBoxLayout()
        self.data_box.setSpacing(0)
        card.body.addLayout(self.data_box)

        purge = QPushButton("Delete scans older than 90 days")
        purge.clicked.connect(self._purge_history)
        open_folder = QPushButton("Open the data folder")
        open_folder.setIcon(icons.icon("folder", tone="muted", size=16))
        open_folder.clicked.connect(self._open_data_folder)
        reset = QPushButton("Reset all preferences")
        reset.setProperty("variant", "danger")
        reset.clicked.connect(self._reset_settings)
        # Wrapping, not a fixed row: side by side the three are wider than the
        # card at the window's minimum size once the font is DejaVu Sans, the
        # default on Debian and Ubuntu.
        card.body.addWidget(flow_row(purge, open_folder, reset, spacing=SPACE_SM))
        self.data_card = card
        return card

    def _refresh_data(self) -> None:
        _clear(self.data_box)
        totals = self.context.history.totals()
        self.data_box.addWidget(KeyValueRow("Settings", str(paths.SETTINGS_FILE),
                                            mono=True))
        self.data_box.addWidget(KeyValueRow("Scan history",
                                            f"{paths.HISTORY_DB}  ·  "
                                            f"{totals['scans']:,} scans", mono=True))
        self.data_box.addWidget(KeyValueRow(
            "Quarantine", f"{paths.QUARANTINE_VAULT}  ·  "
                          f"{self.context.quarantine.count()} files, "
                          f"{format_bytes(self.context.quarantine.total_bytes())}",
            mono=True))
        self.data_box.addWidget(KeyValueRow("Application log", str(paths.APP_LOG),
                                            mono=True))

    def _purge_history(self) -> None:
        removed = self.context.history.purge_older_than(90)
        self.notify.emit(
            f"Removed {removed} old scan record{'' if removed == 1 else 's'}."
            if removed else "Nothing was old enough to remove.", "ok")
        self._refresh_data()

    def _open_data_folder(self) -> None:
        import subprocess

        try:
            subprocess.Popen(["xdg-open", str(paths.DATA_DIR)], start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as error:
            self.notify.emit(f"Could not open the folder: {error}", "danger")

    def _reset_settings(self) -> None:
        if not confirm(
            self, "Reset all preferences?",
            "Every preference goes back to its default. Your scan history, the "
            "quarantine and your schedules are left alone.",
            confirm_text="Reset", tone="warn", destructive=True,
        ):
            return
        try:
            paths.SETTINGS_FILE.unlink(missing_ok=True)
        except OSError as error:
            self.notify.emit(f"Could not remove the settings file: {error}", "danger")
            return
        self.context.settings.reload()
        self.notify.emit("Preferences reset. Restart ClamGuard to see all of it.", "ok")

    # -- about ------------------------------------------------------------

    def _build_about(self) -> Card:
        card = Card("About", icon="info")
        self.about_box = QVBoxLayout()
        self.about_box.setSpacing(0)
        card.body.addLayout(self.about_box)
        self.about_card = card
        return card

    def _refresh_about(self) -> None:
        _clear(self.about_box)
        version = self.context.clamav.version
        daemon = self.context.clamav.daemon
        availability = self.context.privileged.availability

        self.about_box.addWidget(KeyValueRow(APP_NAME, __version__))
        self.about_box.addWidget(KeyValueRow(
            "ClamAV engine", version.raw or "not detected"))
        self.about_box.addWidget(KeyValueRow(
            "Daemon", daemon.endpoint if daemon.reachable
            else f"not reachable — {daemon.detail}",
            tone="" if daemon.reachable else "warn", mono=True))
        self.about_box.addWidget(KeyValueRow(
            "Configuration", str(paths.CLAMAV_CONFIG_DIR), mono=True))
        self.about_box.addWidget(KeyValueRow(
            "Signature database", str(paths.CLAMAV_DB_DIR), mono=True))

        helper_row = QHBoxLayout()
        helper_row.setSpacing(SPACE_MD)
        helper_row.addWidget(label("Privileged helper", role="muted"), 0)
        helper_row.addWidget(Badge(
            "Installed" if availability.usable else "Not installed",
            "ok" if availability.usable else "neutral"), 0)
        helper_row.addStretch(1)
        holder = QWidget()
        holder.setLayout(helper_row)
        self.about_box.addWidget(holder)

        if not availability.usable:
            self.about_box.addWidget(label(availability.reason(), role="caption",
                                           wrap=True))
            self.about_box.addWidget(label(install_command(), role="mono",
                                           selectable=True))

        self.about_box.addWidget(Separator())
        self.about_box.addWidget(label(
            "ClamGuard never sends anything anywhere. The only network traffic is "
            "ClamAV downloading its own signature updates.", role="caption", wrap=True))

    # -- lifecycle --------------------------------------------------------

    def on_shown(self) -> None:
        self.context.privileged.refresh()
        self._refresh_schedules()
        self._refresh_data()
        self._refresh_about()
        self.autostart_toggle.setChecked(AUTOSTART_FILE.is_file())


def _autostart_entry() -> str:
    """A .desktop file that launches this copy of ClamGuard, minimised."""
    launcher = Path(__file__).resolve().parents[4] / "clamguard"
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        "Comment=Antivirus protection, powered by ClamAV\n"
        f'Exec="{launcher}" --minimised\n'
        "Icon=clamguard\n"
        "Terminal=false\n"
        "Categories=System;Security;\n"
        "X-GNOME-Autostart-enabled=true\n"
    )


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
