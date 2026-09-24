"""A live view of what ClamAV is reporting.

The awkward part is that ClamAV's log files are mode 0640 owned by the clamav
user, so a desktop user cannot read them. On any machine running systemd the
journal has the same content and *is* readable, so that is the default source
and the files are offered as a fallback. When neither works the page says so
and offers the privileged read rather than showing an empty box.
"""

from __future__ import annotations

from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
)

from ...core.logsource import LogSource, classify
from ...core.process import Command
from .. import icons, theme
from ..theme import SPACE_SM
from ..widgets import Badge, MessageBar, ToggleSwitch, label
from .base import Page

#: How many lines the view keeps. Old ones fall off the top.
MAX_LINES = 5000


class LogsPage(Page):
    PAGE_ID = "logs"
    TITLE = "Logs"
    SUBTITLE = "What ClamAV is reporting, as it happens"
    ICON = "logs"
    SCROLLABLE = False

    def build(self) -> None:
        self._sources: list[LogSource] = []
        self._tail: Command | None = None
        self._filter = ""

        self.notice = MessageBar("", "info")
        self.body.addWidget(self.notice)
        self.body.addLayout(self._build_toolbar())

        self.view = QPlainTextEdit()
        self.view.setProperty("role", "log")
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(MAX_LINES)
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.body.addWidget(self.view, 1)

        self.status = label("", role="caption")
        self.body.addWidget(self.status)

    def _build_toolbar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(SPACE_SM)

        self.source_box = QComboBox()
        self.source_box.currentIndexChanged.connect(self._on_source_changed)
        row.addWidget(self.source_box, 2)

        self.filter_box = QLineEdit()
        self.filter_box.setPlaceholderText("Filter lines…")
        self.filter_box.setClearButtonEnabled(True)
        self.filter_box.textChanged.connect(self._on_filter_changed)
        row.addWidget(self.filter_box, 2)

        self.errors_only = QPushButton("Problems only")
        self.errors_only.setCheckable(True)
        self.errors_only.setToolTip("Show only lines containing an error or a detection.")
        self.errors_only.toggled.connect(lambda: self._reload())
        row.addWidget(self.errors_only)

        self.refresh_button = QPushButton("Reload")
        self.refresh_button.setIcon(icons.icon("refresh", tone="muted", size=16))
        self.refresh_button.clicked.connect(self._reload)
        row.addWidget(self.refresh_button)

        self.privileged_button = QPushButton("Read as administrator")
        self.privileged_button.setIcon(icons.icon("lock", tone="muted", size=16))
        self.privileged_button.clicked.connect(self._read_privileged)
        self.privileged_button.setVisible(False)
        row.addWidget(self.privileged_button)

        row.addStretch(1)
        row.addWidget(label("Follow", role="muted"))
        self.follow_toggle = ToggleSwitch()
        self.follow_toggle.toggled.connect(self._on_follow_toggled)
        row.addWidget(self.follow_toggle)

        self.live_badge = Badge("Live", "ok")
        self.live_badge.setVisible(False)
        row.addWidget(self.live_badge)
        return row

    # -- lifecycle --------------------------------------------------------

    def on_shown(self) -> None:
        self._rebuild_sources()
        self._reload()

    def on_hidden(self) -> None:
        """Stop following when the user navigates away.

        A journalctl --follow left running in the background is a process that
        never exits, so it is stopped the moment the page is not visible.
        """
        self._stop_tail()

    # -- sources ----------------------------------------------------------

    def _rebuild_sources(self) -> None:
        previous = self.source_box.currentData()
        self._sources = self.context.logs.sources()
        self.source_box.blockSignals(True)
        self.source_box.clear()
        for source in self._sources:
            suffix = "" if source.available else "  (needs administrator)"
            self.source_box.addItem(f"{source.title}{suffix}", source.id)
        if previous:
            index = self.source_box.findData(previous)
            if index >= 0:
                self.source_box.setCurrentIndex(index)
        self.source_box.blockSignals(False)

    def _current_source(self) -> LogSource | None:
        identifier = self.source_box.currentData()
        return next((s for s in self._sources if s.id == identifier), None)

    def _on_source_changed(self) -> None:
        self._stop_tail()
        self._reload()

    # -- reading ----------------------------------------------------------

    def _reload(self) -> None:
        source = self._current_source()
        if source is None:
            self.view.setPlainText("")
            self.status.setText("No log sources were found.")
            return

        self.privileged_button.setVisible(
            source.needs_helper and self.context.privileged.available)
        self.follow_toggle.setEnabled(source.supports_follow)
        self.follow_toggle.setToolTip(
            "" if source.supports_follow
            else "This source cannot be followed live; press Reload instead.")

        self.notice.set_message(
            f"Reading {source.description}.",
            "info" if source.available else "warn")
        if not source.available:
            self.notice.set_message(source.unavailable_reason, "warn")

        result = self.context.logs.read(source, lines=1500)
        if not result.ok and not result.stdout:
            self.view.setPlainText("")
            self.status.setText(result.error or "Nothing could be read.")
            return

        self._set_text(result.stdout)
        self.status.setText(
            f"{len(result.stdout.splitlines()):,} lines from {source.description}")

        if self.follow_toggle.isChecked():
            self._start_tail(source)

    def _read_privileged(self) -> None:
        source = self._current_source()
        if source is None or source.path is None:
            return
        call = self.context.privileged.read_file(source.path)
        call.succeeded.connect(lambda text: (self._set_text(text),
                                             self.status.setText(
                                                 f"Read {source.path} as administrator")))
        call.failed.connect(lambda message: self.notify.emit(message, "danger"))
        call.start()

    # -- live following ---------------------------------------------------

    def _on_follow_toggled(self, following: bool) -> None:
        source = self._current_source()
        if following and source is not None:
            self._start_tail(source)
        else:
            self._stop_tail()

    def _start_tail(self, source: LogSource) -> None:
        self._stop_tail()
        command = self.context.logs.follow_command(source)
        if command is None:
            self.follow_toggle.setChecked(False)
            self.notify.emit("This source cannot be followed live.", "warn")
            return
        command.setParent(self)
        command.stdout_line.connect(self._append_line)
        command.stderr_line.connect(self._append_line)
        command.failed.connect(lambda message: self.notify.emit(message, "warn"))
        self._tail = command
        self.view.clear()
        command.start()
        self.live_badge.setVisible(True)

    def _stop_tail(self) -> None:
        if self._tail is not None:
            self._tail.stop()
            self._tail.deleteLater()
            self._tail = None
        self.live_badge.setVisible(False)

    # -- text -------------------------------------------------------------

    def _on_filter_changed(self, text: str) -> None:
        self._filter = text.strip().lower()
        self._reload()

    def _keep(self, line: str) -> bool:
        if self._filter and self._filter not in line.lower():
            return False
        if self.errors_only.isChecked() and classify(line) not in ("error", "warn",
                                                                   "detection"):
            return False
        return True

    def _set_text(self, text: str) -> None:
        self.view.clear()
        for line in text.splitlines():
            if self._keep(line):
                self._write(line)
        self._scroll_to_end()

    def _append_line(self, line: str) -> None:
        if self._keep(line):
            self._write(line)
            self._scroll_to_end()

    def _write(self, line: str) -> None:
        """Append one line, coloured by what kind of line it is."""
        palette = theme.resolve_palette(self.context.settings.str("theme"))
        colours = {
            "error": palette.danger,
            "warn": palette.warn,
            "detection": palette.danger,
            "info": palette.text_dim,
        }
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(colours.get(classify(line), palette.text_dim)))

        cursor = self.view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(line + "\n", fmt)

    def _scroll_to_end(self) -> None:
        bar = self.view.verticalScrollBar()
        bar.setValue(bar.maximum())
