"""The four dialogs Hunt needs: time range, sources, query details, settings.

None of them asks "are you sure?". Each shows the thing it is about — the
window being chosen, the files that will be read and the ones that will not,
the SQL the planner produced, the limits that will be applied — and lets the
decision follow from that. Which is the same rule the rest of ClamGuard
follows, applied to a page whose subject is other people's log files.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from PySide6.QtCore import QDateTime, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.hunt.discovery import Candidate, Crawl, default_roots
from ...core.hunt.journal import PRIORITIES, WINDOWS
from ...core.hunt.model import (
    TIME_PRESETS,
    QueryStats,
    TimeRange,
    format_timestamp,
    humanise_age,
    humanise_bytes,
)
from ...core.hunt.settings import HuntSettings
from ...core.hunt.store import Source
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM
from ..widgets import MessageBar, label


# ---------------------------------------------------------------------------
# Time range
# ---------------------------------------------------------------------------


class TimeRangeDialog(QDialog):
    """The picker behind the clock button, with the honest caveat attached."""

    def __init__(self, parent, current: TimeRange, *, untimed: int = 0) -> None:
        super().__init__(parent)
        self.setWindowTitle("Time range")
        self.setMinimumWidth(460)
        self._range = current

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_MD)
        column.setSpacing(SPACE_SM)

        column.addWidget(label("Every query is filtered to this window before "
                               "anything else runs, so a narrow range is also "
                               "the fastest one.", role="muted", wrap=True))

        self.presets = QListWidget()
        self.presets.setAlternatingRowColors(False)
        for name, delta in TIME_PRESETS:
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, delta)
            self.presets.addItem(item)
            if current.last is not None and delta == current.last:
                self.presets.setCurrentItem(item)
            elif delta is None and current.unbounded:
                self.presets.setCurrentItem(item)
        self.presets.itemDoubleClicked.connect(lambda _item: self.accept())
        self.presets.currentItemChanged.connect(
            lambda *_args: self.custom.setChecked(False))
        column.addWidget(self.presets, 1)

        self.custom = QRadioButton("A specific window")
        self.custom.setChecked(current.last is None and not current.unbounded)
        column.addWidget(self.custom)

        form = QFormLayout()
        form.setContentsMargins(SPACE_LG, 0, 0, 0)
        now = datetime.now()
        self.start = QDateTimeEdit(QDateTime(current.start.astimezone().replace(tzinfo=None))
                                   if current.start else
                                   QDateTime(now - timedelta(days=1)))
        self.end = QDateTimeEdit(QDateTime(current.end.astimezone().replace(tzinfo=None))
                                 if current.end else QDateTime(now))
        for field in (self.start, self.end):
            field.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
            field.setCalendarPopup(True)
            field.dateTimeChanged.connect(lambda *_args: self.custom.setChecked(True))
        form.addRow("From", self.start)
        form.addRow("To", self.end)
        column.addLayout(form)

        if untimed:
            column.addWidget(MessageBar(
                f"{untimed:,} indexed events carry no timestamp — the formats "
                "that wrote them do not record one. A time range cannot see "
                "those; choose All time to include them.",
                tone="info"))

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        column.addWidget(buttons)

    def selected(self) -> TimeRange:
        if self.custom.isChecked():
            start = self.start.dateTime().toPython().astimezone()
            end = self.end.dateTime().toPython().astimezone()
            if start > end:
                start, end = end, start
            return TimeRange(start=start, end=end,
                             label=f"{format_timestamp(start, precision=0)} → "
                                   f"{format_timestamp(end, precision=0)}")
        item = self.presets.currentItem()
        if item is None:
            return self._range
        delta = item.data(Qt.ItemDataRole.UserRole)
        if delta is None:
            return TimeRange.everything()
        return TimeRange(last=delta, label=item.text())


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


class SourcesDialog(QDialog):
    """What Hunt found, what it indexed, and what it refused — with reasons."""

    #: Crawl the filesystem again.
    scan_requested = Signal()
    #: Index the checked candidates.
    index_requested = Signal(list)
    #: Stop indexing one source and forget its events.
    forget_requested = Signal(str)
    #: Read the systemd journal now.
    journal_requested = Signal()
    #: Drop every journal source and the saved cursor.
    forget_journal_requested = Signal()

    def __init__(self, parent, *, crawl: Crawl | None, sources: list[Source],
                 journal=None, home: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Log sources")
        self.resize(980, 620)
        self._home = home or str(Path.home())
        self._crawl = crawl
        self._sources = sources

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_MD)
        column.setSpacing(SPACE_SM)

        self.summary = label("", role="muted", wrap=True)
        column.addWidget(self.summary)

        self.tabs = QTabWidget()
        self.found = _CandidateTable(self._home)
        self.indexed = _SourceTable(self._home)
        self.skipped = _SkippedTable(self._home)
        self.journal = _JournalPanel()
        self.journal.index_requested.connect(self.journal_requested)
        self.journal.forget_requested.connect(self.forget_journal_requested)
        self.tabs.addTab(self.found, "Found")
        self.tabs.addTab(self.indexed, "Indexed")
        self.tabs.addTab(self.skipped, "Skipped")
        self.tabs.addTab(self.journal, "Journal")
        column.addWidget(self.tabs, 1)

        row = QHBoxLayout()
        row.setSpacing(SPACE_SM)
        self.scan_button = QPushButton("Search again")
        self.scan_button.clicked.connect(self.scan_requested)
        row.addWidget(self.scan_button)

        self.add_file_button = QPushButton("Add a file…")
        self.add_file_button.clicked.connect(self._add_file)
        row.addWidget(self.add_file_button)

        self.select_all = QPushButton("Select all")
        self.select_all.clicked.connect(lambda: self.found.set_all(True))
        row.addWidget(self.select_all)
        self.clear_selection = QPushButton("Select none")
        self.clear_selection.clicked.connect(lambda: self.found.set_all(False))
        row.addWidget(self.clear_selection)

        row.addStretch(1)
        self.forget_button = QPushButton("Forget selected")
        self.forget_button.setProperty("variant", "danger")
        self.forget_button.clicked.connect(self._forget)
        row.addWidget(self.forget_button)

        self.index_button = QPushButton("Index selected")
        self.index_button.setProperty("variant", "primary")
        self.index_button.clicked.connect(self._index)
        row.addWidget(self.index_button)

        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        column.addLayout(row)

        self.tabs.currentChanged.connect(self._update_buttons)
        self.refresh(crawl, sources, journal)

    def refresh(self, crawl: Crawl | None, sources: list[Source],
                journal=None) -> None:
        self._crawl = crawl
        self._sources = sources
        known = {source.path for source in sources}
        files = [source for source in sources if not source.is_journal]
        self.found.fill(crawl.usable if crawl else [], known)
        self.indexed.fill(files)
        self.skipped.fill(crawl.skipped if crawl else [])
        if journal is not None:
            self.journal.show_state(*journal)

        parts: list[str] = []
        if crawl:
            parts.append(f"{len(crawl.usable):,} log files found in "
                         f"{crawl.directories:,} directories "
                         f"({crawl.elapsed:.1f}s)")
            if crawl.limits_hit():
                parts.append(crawl.limits_hit())
        if sources:
            total = sum(source.events for source in sources)
            parts.append(f"{len(sources):,} indexed, {total:,} events")
        self.summary.setText(" · ".join(parts) or
                             "Nothing has been searched for yet.")
        self.tabs.setTabText(0, f"Found ({len(crawl.usable) if crawl else 0})")
        self.tabs.setTabText(1, f"Indexed ({len(files)})")
        self.tabs.setTabText(2, f"Skipped ({len(crawl.skipped) if crawl else 0})")
        self._update_buttons()

    def _update_buttons(self) -> None:
        """The footer follows the tab. The Journal tab has its own buttons and
        none of the file ones mean anything there."""
        tab = self.tabs.currentIndex()
        on_found, on_journal = tab == 0, tab == 3
        self.index_button.setVisible(on_found)
        self.select_all.setVisible(on_found)
        self.clear_selection.setVisible(on_found)
        self.forget_button.setVisible(tab == 1)
        self.scan_button.setVisible(not on_journal)
        self.add_file_button.setVisible(not on_journal)

    def _index(self) -> None:
        chosen = self.found.checked()
        if chosen:
            self.index_requested.emit(chosen)

    def _forget(self) -> None:
        for path in self.indexed.selected_paths():
            self.forget_requested.emit(path)

    def _add_file(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, "Choose a log file", str(Path.home()),
            "Log files (*.log *.txt *.jsonl *.out *.err);;Every file (*)")
        if not path:
            return
        from ...core.hunt.discovery import scan_one

        candidate = scan_one(Path(path))
        self.found.add(candidate, checked=candidate.usable)
        self.tabs.setCurrentIndex(0)


class _JournalPanel(QWidget):
    """The systemd journal, which is not a file and so is not in the crawl.

    It gets its own tab rather than a row in Found because everything about
    it is different: it is read by running a command, it resumes from a
    cursor instead of a byte offset, and on a normal desktop it is larger
    than every log file put together.
    """

    index_requested = Signal()
    forget_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_LG)
        column.setSpacing(SPACE_SM)

        self.headline = label("", role="heading", wrap=True)
        column.addWidget(self.headline)
        self.detail = label("", role="body", wrap=True)
        column.addWidget(self.detail)

        self.notice = MessageBar("", tone="info")
        self.notice.setVisible(False)
        column.addWidget(self.notice)

        self.units = QTableWidget(0, 2)
        self.units.setHorizontalHeaderLabels(("Unit", "Entries"))
        self.units.verticalHeader().setVisible(False)
        self.units.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.units.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.units.setAlternatingRowColors(True)
        self.units.setSortingEnabled(True)
        self.units.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self.units.setColumnWidth(1, 110)
        column.addWidget(self.units, 1)

        row = QHBoxLayout()
        row.setSpacing(SPACE_SM)
        self.index_button = QPushButton("Read the journal now")
        self.index_button.setProperty("variant", "primary")
        self.index_button.clicked.connect(self.index_requested)
        row.addWidget(self.index_button)
        self.forget_button = QPushButton("Forget the journal")
        self.forget_button.setProperty("variant", "danger")
        self.forget_button.clicked.connect(self.forget_requested)
        row.addWidget(self.forget_button)
        row.addStretch(1)
        column.addLayout(row)

        column.addWidget(label(
            "Hunt reads the journal with `journalctl --output=json`, resuming "
            "from where it left off. It never runs as root, so it sees "
            "exactly what you would see typing the same command.",
            role="caption", wrap=True))

    def show_state(self, availability, options, entries: int, units: int,
                   last_read: float, enabled: bool, unit_rows=()) -> None:
        usable = availability.usable
        self.headline.setText(
            f"{entries:,} journal entries indexed from {units} units"
            if entries else "The journal has not been read yet")
        self.detail.setText(
            f"{availability.describe()}\n"
            f"It will read: {options.describe()}, at most "
            f"{options.max_entries:,} entries per pass."
            + (f"\nLast read {humanise_age(int(last_read * 1_000_000))}."
               if entries and last_read else ""))

        if not usable:
            self.notice.set_message(availability.describe(), "warn")
            self.notice.setVisible(True)
        elif not enabled:
            self.notice.set_message(
                "Journal indexing is switched off in Hunt settings. Reading "
                "it now turns it on for this machine.", "info")
            self.notice.setVisible(True)
        else:
            self.notice.setVisible(False)

        self.index_button.setEnabled(usable)
        self.forget_button.setEnabled(bool(entries))

        self.units.setSortingEnabled(False)
        self.units.setRowCount(0)
        for name, count in unit_rows:
            position = self.units.rowCount()
            self.units.insertRow(position)
            self.units.setItem(position, 0, QTableWidgetItem(name))
            self.units.setItem(position, 1, _numeric(f"{count:,}", count))
        self.units.setSortingEnabled(True)


class _CandidateTable(QTableWidget):
    """Files that could be indexed, with a checkbox each."""

    HEADERS = ("", "Application", "File", "Size", "Changed", "Status")

    def __init__(self, home: str) -> None:
        super().__init__(0, len(self.HEADERS))
        self._home = home
        self._candidates: list[Candidate] = []
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.setColumnWidth(0, 34)
        self.setColumnWidth(1, 150)
        for column, width in ((3, 90), (4, 130), (5, 90)):
            self.setColumnWidth(column, width)

    def fill(self, candidates, known: set[str]) -> None:
        self.setSortingEnabled(False)
        self.setRowCount(0)
        self._candidates = []
        for candidate in candidates:
            self.add(candidate, checked=True, known=candidate.path in known)
        self.setSortingEnabled(True)

    def add(self, candidate: Candidate, *, checked: bool = True,
            known: bool = False) -> None:
        row = self.rowCount()
        self.insertRow(row)
        self._candidates.append(candidate)

        tick = QTableWidgetItem()
        tick.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        tick.setCheckState(Qt.CheckState.Checked if checked
                           else Qt.CheckState.Unchecked)
        tick.setData(Qt.ItemDataRole.UserRole, len(self._candidates) - 1)
        self.setItem(row, 0, tick)

        self.setItem(row, 1, QTableWidgetItem(candidate.app))
        path_item = QTableWidgetItem(candidate.display_path(self._home))
        path_item.setToolTip(candidate.path)
        self.setItem(row, 2, path_item)
        self.setItem(row, 3, _numeric(humanise_bytes(candidate.size), candidate.size))
        self.setItem(row, 4, _numeric(humanise_age(
            datetime.fromtimestamp(candidate.mtime, tz=timezone.utc)),
            candidate.mtime))
        self.setItem(row, 5, QTableWidgetItem("indexed" if known else "new"))

    def set_all(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for row in range(self.rowCount()):
            item = self.item(row, 0)
            if item is not None:
                item.setCheckState(state)

    def checked(self) -> list[Candidate]:
        chosen: list[Candidate] = []
        for row in range(self.rowCount()):
            item = self.item(row, 0)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                index = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(index, int) and index < len(self._candidates):
                    chosen.append(self._candidates[index])
        return chosen


class _SourceTable(QTableWidget):
    """What is already in the store."""

    HEADERS = ("Application", "File", "Format", "Events", "Read", "Last indexed")

    def __init__(self, home: str) -> None:
        super().__init__(0, len(self.HEADERS))
        self._home = home
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.setColumnWidth(0, 150)
        for column, width in ((2, 160), (3, 90), (4, 90), (5, 130)):
            self.setColumnWidth(column, width)

    def fill(self, sources: list[Source]) -> None:
        self.setSortingEnabled(False)
        self.setRowCount(0)
        for source in sources:
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem(source.app))
            path_item = QTableWidgetItem(source.display_path(self._home))
            path_item.setToolTip(source.path)
            path_item.setData(Qt.ItemDataRole.UserRole, source.path)
            self.setItem(row, 1, path_item)
            confidence = (f"{source.format}  ({source.confidence * 100:.0f}%)"
                          if source.confidence else source.format)
            self.setItem(row, 2, QTableWidgetItem(confidence))
            self.setItem(row, 3, _numeric(f"{source.events:,}", source.events))
            self.setItem(row, 4, _numeric(humanise_bytes(source.byte_offset),
                                          source.byte_offset))
            self.setItem(row, 5, _numeric(
                humanise_age(datetime.fromtimestamp(source.last_indexed,
                                                    tz=timezone.utc))
                if source.last_indexed else "never", source.last_indexed))
        self.setSortingEnabled(True)

    def selected_paths(self) -> list[str]:
        paths: list[str] = []
        for index in self.selectionModel().selectedRows(1):
            value = index.data(Qt.ItemDataRole.UserRole)
            if value:
                paths.append(str(value))
        return paths


class _SkippedTable(QTableWidget):
    """Everything that matched but was not indexed, and why.

    This tab is the reason a user can trust the Found tab. A log that is
    missing and unexplained reads as a bug; a log that is missing with
    "binary (contains null bytes)" next to it reads as a decision.
    """

    HEADERS = ("Application", "File", "Reason", "Size")

    def __init__(self, home: str) -> None:
        super().__init__(0, len(self.HEADERS))
        self._home = home
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        header = self.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        # The reason is the entire point of this tab; eliding it to
        # "binary ..." tells the reader nothing they did not already know.
        self.setColumnWidth(0, 150)
        self.setColumnWidth(2, 280)
        self.setColumnWidth(3, 90)

    def fill(self, candidates) -> None:
        self.setSortingEnabled(False)
        self.setRowCount(0)
        for candidate in candidates:
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem(candidate.app))
            item = QTableWidgetItem(candidate.display_path(self._home))
            item.setToolTip(candidate.path)
            self.setItem(row, 1, item)
            self.setItem(row, 2, QTableWidgetItem(candidate.skipped))
            self.setItem(row, 3, _numeric(humanise_bytes(candidate.size),
                                          candidate.size))
        self.setSortingEnabled(True)


def _numeric(text: str, value) -> QTableWidgetItem:
    """A cell that sorts by its number rather than by its text."""
    item = QTableWidgetItem()
    item.setData(Qt.ItemDataRole.DisplayRole, text)
    item.setData(Qt.ItemDataRole.UserRole + 5, value)
    return item


# ---------------------------------------------------------------------------
# Query details
# ---------------------------------------------------------------------------


class QueryDetailsDialog(QDialog):
    """What the planner did with the query. For the savvy half of the audience.

    Showing the generated SQL is not a debugging leftover. It is the only way
    a user can tell whether their filter was pushed into the index or whether
    the engine read a million rows and discarded them, which is the difference
    between forty milliseconds and seven seconds.
    """

    def __init__(self, parent, query: str, stats: QueryStats,
                 plan: dict | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Query details")
        self.resize(760, 560)

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_MD)
        column.setSpacing(SPACE_SM)

        column.addWidget(label(stats.summary(), role="heading"))
        pushed = ", ".join(stats.pushed_down) or "nothing"
        evaluated = ", ".join(stats.evaluated) or "nothing"
        column.addWidget(label(
            f"Pushed into the index: {pushed}.\n"
            f"Run in Python above it: {evaluated}.", role="muted", wrap=True))

        if stats.scanned and stats.rows and stats.scanned > stats.rows * 50:
            column.addWidget(MessageBar(
                f"This read {stats.scanned:,} rows to return {stats.rows:,}. "
                "Something in the query could not be turned into a lookup — "
                "usually a regular expression, or a filter on a computed "
                "column. Filtering on Timestamp, Level, App or Source first "
                "makes it much faster.", tone="info"))

        column.addWidget(label("The query", role="sectionLabel"))
        source = QPlainTextEdit(query)
        source.setReadOnly(True)
        source.setMaximumHeight(140)
        source.setProperty("role", "log")
        column.addWidget(source)

        column.addWidget(label("The SQL it became", role="sectionLabel"))
        statement = QPlainTextEdit(stats.sql or
                                   "This query did not reach the store.")
        statement.setReadOnly(True)
        statement.setProperty("role", "log")
        column.addWidget(statement, 1)

        if stats.parameters:
            column.addWidget(label("Bound values", role="sectionLabel"))
            values = QPlainTextEdit(
                "\n".join(f"{index + 1}. {value!r}"
                          for index, value in enumerate(stats.parameters)))
            values.setReadOnly(True)
            values.setMaximumHeight(110)
            values.setProperty("role", "log")
            column.addWidget(values)

        note = label("Everything above ran on a connection opened read-only. "
                     "A query cannot change the store even if this planner "
                     "has a bug in it.", role="caption", wrap=True)
        column.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        copy = buttons.addButton("Copy the SQL",
                                 QDialogButtonBox.ButtonRole.ActionRole)
        copy.clicked.connect(lambda: _copy(stats.sql))
        column.addWidget(buttons)


def _copy(text: str) -> None:
    from PySide6.QtGui import QGuiApplication

    clipboard = QGuiApplication.clipboard()
    if clipboard is not None:
        clipboard.setText(text or "")


# ---------------------------------------------------------------------------
# Saving a query
# ---------------------------------------------------------------------------


class SaveQueryDialog(QDialog):
    """Name a query so it comes back in the rail."""

    def __init__(self, parent, text: str, *, name: str = "",
                 description: str = "", time_range: TimeRange | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Save this query")
        self.setMinimumWidth(520)

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_MD)
        column.setSpacing(SPACE_SM)

        form = QFormLayout()
        self.name = QLineEdit(name or _suggest_name(text))
        self.name.selectAll()
        form.addRow("Name", self.name)
        self.description = QLineEdit(description)
        self.description.setPlaceholderText("What question does it answer?")
        form.addRow("Note", self.description)
        column.addLayout(form)

        self.keep_range = QCheckBox(
            f"Remember the time range ({time_range.describe()})"
            if time_range else "Remember the time range")
        self.keep_range.setChecked(True)
        self.keep_range.setToolTip(
            "A rolling range is saved as rolling: 'Last 24 hours' still means "
            "the last 24 hours when you open it next year.")
        column.addWidget(self.keep_range)

        preview = QPlainTextEdit(text)
        preview.setReadOnly(True)
        preview.setProperty("role", "log")
        preview.setMaximumHeight(160)
        column.addWidget(preview)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        column.addWidget(buttons)


def _suggest_name(text: str) -> str:
    """A first guess at a name, from the query's own shape."""
    words = " ".join(text.split())
    for marker in ("| where ", "| summarize ", "| search "):
        if marker in words:
            tail = words.split(marker, 1)[1]
            return (words.split("|", 1)[0].strip() + ": "
                    + tail[:48].strip()).strip(": ")
    return words[:60] or "Untitled query"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class HuntSettingsDialog(QDialog):
    """Where Hunt looks, how much it keeps, and how hard it tries."""

    def __init__(self, parent, settings: HuntSettings) -> None:
        super().__init__(parent)
        self.setWindowTitle("Hunt settings")
        self.setMinimumWidth(620)
        self.settings = settings

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_MD)
        column.setSpacing(SPACE_MD)

        places = QGroupBox("Where to look")
        places_column = QVBoxLayout(places)
        places_column.setSpacing(SPACE_SM)
        self._roots: dict[str, QCheckBox] = {}
        for root in default_roots():
            box = QCheckBox(f"{root.title} — {root.path}")
            box.setChecked(settings.roots.get(root.id, not root.optional))
            box.setToolTip(root.description)
            if root.optional:
                box.setText(f"{root.title} — {root.path}   (off by default)")
            places_column.addWidget(box)
            self._roots[root.id] = box
        column.addWidget(places)

        limits = QGroupBox("Limits")
        form = QFormLayout(limits)
        self.max_file = _spin(1, 65536, settings.max_file_megabytes, " MB")
        form.addRow("Skip files larger than", self.max_file)
        self.crawl_seconds = _spin(1, 600, int(settings.crawl_seconds), " s")
        form.addRow("Give up searching after", self.crawl_seconds)
        self.row_limit = _spin(100, 5_000_000, settings.row_limit, " rows", step=1000)
        form.addRow("Most rows in a result", self.row_limit)
        self.timeout = _spin(1, 3600, int(settings.query_timeout), " s")
        form.addRow("Stop a query after", self.timeout)
        column.addWidget(limits)

        keeping = QGroupBox("How much to keep")
        keep_form = QFormLayout(keeping)
        self.max_events = _spin(0, 500_000_000, settings.max_events, " events",
                                step=100_000, zero="no limit")
        keep_form.addRow("Most events", self.max_events)
        self.max_age = _spin(0, 3650, settings.max_age_days, " days",
                             zero="no limit")
        keep_form.addRow("Discard events older than", self.max_age)
        self.max_size = _spin(0, 1_000_000, settings.max_store_megabytes, " MB",
                              step=128, zero="no limit")
        keep_form.addRow("Most disk", self.max_size)
        keep_form.addRow("", label(
            "Retention removes the events that were indexed longest ago. Two "
            "thirds of desktop log lines carry no timestamp, so 'oldest "
            "first' would be a guess; 'indexed first' is not.",
            role="caption", wrap=True))
        column.addWidget(keeping)

        journal = QGroupBox("The systemd journal")
        journal_form = QFormLayout(journal)
        self.journal_enabled = QCheckBox(
            "Index the systemd journal as well as log files")
        self.journal_enabled.setChecked(settings.journal_enabled)
        journal_form.addRow("", self.journal_enabled)
        self.journal_window = QComboBox()
        for key, (title, blurb) in WINDOWS.items():
            self.journal_window.addItem(title, key)
            self.journal_window.setItemData(self.journal_window.count() - 1,
                                            blurb, Qt.ItemDataRole.ToolTipRole)
        self.journal_window.setCurrentIndex(
            max(0, list(WINDOWS).index(settings.journal_window)
                if settings.journal_window in WINDOWS else 0))
        journal_form.addRow("How far back", self.journal_window)
        self.journal_priority = QComboBox()
        for key, (title, blurb) in PRIORITIES.items():
            self.journal_priority.addItem(title, key)
            self.journal_priority.setItemData(self.journal_priority.count() - 1,
                                              blurb, Qt.ItemDataRole.ToolTipRole)
        self.journal_priority.setCurrentIndex(
            max(0, list(PRIORITIES).index(settings.journal_priority)
                if settings.journal_priority in PRIORITIES else 0))
        journal_form.addRow("Keep", self.journal_priority)
        self.journal_max = _spin(1000, 20_000_000, settings.journal_max_entries,
                                 " entries", step=10_000)
        journal_form.addRow("Most per pass", self.journal_max)
        self.journal_user = QCheckBox("Include your own user units")
        self.journal_user.setChecked(settings.journal_include_user)
        journal_form.addRow("", self.journal_user)
        journal_form.addRow("", label(
            "The journal is usually far larger than every log file put "
            "together. A pass that hits the limit is not a loss — the rest "
            "is read the next time, from where it stopped.",
            role="caption", wrap=True))
        column.addWidget(journal)

        behaviour = QGroupBox("Behaviour")
        behaviour_column = QVBoxLayout(behaviour)
        self.full_text = QCheckBox(
            "Keep a full-text index (makes `search` and `has` much faster, "
            "costs about a quarter of the store's size)")
        self.full_text.setChecked(settings.use_full_text)
        behaviour_column.addWidget(self.full_text)
        self.index_on_open = QCheckBox(
            "Re-read changed log files when the page is opened")
        self.index_on_open.setChecked(settings.index_on_open)
        behaviour_column.addWidget(self.index_on_open)
        column.addWidget(behaviour)

        column.addWidget(label("Excluded patterns, one per line", role="sectionLabel"))
        self.exclusions = QPlainTextEdit("\n".join(settings.exclusions))
        self.exclusions.setMaximumHeight(80)
        self.exclusions.setPlaceholderText("*/Crashpad/*")
        column.addWidget(self.exclusions)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save
                                   | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        column.addWidget(buttons)

    def apply(self) -> None:
        """Copy the dialog's values back into the settings and save them."""
        for identifier, box in self._roots.items():
            self.settings.roots[identifier] = box.isChecked()
        self.settings.max_file_megabytes = self.max_file.value()
        self.settings.crawl_seconds = float(self.crawl_seconds.value())
        self.settings.row_limit = self.row_limit.value()
        self.settings.query_timeout = float(self.timeout.value())
        self.settings.max_events = self.max_events.value()
        self.settings.max_age_days = self.max_age.value()
        self.settings.max_store_megabytes = self.max_size.value()
        self.settings.use_full_text = self.full_text.isChecked()
        self.settings.journal_enabled = self.journal_enabled.isChecked()
        self.settings.journal_window = self.journal_window.currentData()
        self.settings.journal_priority = self.journal_priority.currentData()
        self.settings.journal_max_entries = self.journal_max.value()
        self.settings.journal_include_user = self.journal_user.isChecked()
        self.settings.index_on_open = self.index_on_open.isChecked()
        self.settings.exclusions = [
            line.strip() for line in self.exclusions.toPlainText().splitlines()
            if line.strip()]
        self.settings.save()


def _spin(low: int, high: int, value: int, suffix: str, *, step: int = 1,
          zero: str = "") -> QSpinBox:
    box = QSpinBox()
    box.setRange(low, high)
    box.setValue(int(value))
    box.setSuffix(suffix)
    box.setSingleStep(step)
    box.setGroupSeparatorShown(True)
    if zero:
        box.setSpecialValueText(zero)
    return box
