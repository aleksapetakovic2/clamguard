"""The Hunt page: find every log on this machine, then query it in KQL.

Laid out the way the Azure Sentinel Logs blade is, because that layout is
correct and because muscle memory is worth more than novelty: a rail of
tables, queries and functions on the left; a query editor at the top with Run
and a time-range picker; results and a chart below.

Three things here are ours rather than Sentinel's, and each is a consequence
of running on a desktop rather than in a data centre.

**The index is local and honest about it.** The status strip says how many
events there are, how much disk they take, and — the number that surprises
people — how many of them have no timestamp at all, because two thirds of the
log formats on a Linux desktop do not write one. A time range cannot see
those, and the page says so rather than letting the user conclude the index is
empty.

**Every result can show its own SQL.** The Query details dialog prints the
statement the planner produced and how many rows it read, which is the only
way to tell a filter that used an index from one that scanned a million rows.

**Nothing leaves the machine.** The store is mode 0600, queries run on a
connection opened read-only, and the only way anything gets out is a file
dialog the user opened.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QMenu,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...core import paths
from ...core.hunt import export as hunt_export
from ...core.hunt import library, rules as hunt_rules
from ...core.hunt.discovery import Crawl
from ...core.hunt.indexer import HuntIndexer
from ...core.hunt.kql import KqlError
from ...core.hunt.model import (
    DEFAULT_TIME_RANGE,
    ResultTable,
    TimeRange,
    humanise_age,
    humanise_bytes,
    humanise_count,
)
from ...core.hunt.saved import QueryStore
from ...core.hunt.settings import HuntSettings
from ...core.hunt.store import IndexRun
from .. import icons
from ..dialogs import confirm
from ..theme import SPACE_MD, SPACE_SM, SPACE_XS
from ..widgets import (
    Badge,
    EmptyState,
    IconButton,
    MessageBar,
    Separator,
    label,
)
from ..widgets.chart import Chart
from ..widgets.kql_editor import KqlEditor
from ..widgets.results_grid import ResultsGrid
from .base import Page
from .hunt_dialogs import (
    HuntSettingsDialog,
    QueryDetailsDialog,
    SaveQueryDialog,
    SourcesDialog,
    TimeRangeDialog,
)
from .hunt_insights import InsightsPanel
from .hunt_rail import HuntRail

#: The query a brand new installation opens on.
FIRST_QUERY = (
    "Logs\n"
    "| where isnotnull(Timestamp)\n"
    "| sort by Timestamp desc\n"
    "| take 200"
)


class HuntPage(Page):
    """Log discovery, indexing, querying and analysis, in one screen."""

    PAGE_ID = "hunt"
    TITLE = "Hunt"
    SUBTITLE = "Every log on this machine, in one query language"
    ICON = "hunt"
    SCROLLABLE = False

    def __init__(self, context, parent=None) -> None:
        super().__init__(context, parent)
        self.settings = HuntSettings()
        self.queries = QueryStore()
        self.indexer = HuntIndexer(self.settings, self)
        self.time_range: TimeRange = self.settings.time_range or DEFAULT_TIME_RANGE
        self._sources_dialog: SourcesDialog | None = None
        self._last_result: ResultTable | None = None
        self._last_query = ""
        self._mode = "query"

    # -- construction -----------------------------------------------------

    def build(self) -> None:
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(0)

        self._build_header_actions()
        self.body.addWidget(self._build_toolbar())

        self.notice = MessageBar("", tone="info", dismissible=True)
        self.notice.setVisible(False)
        self.body.addWidget(self.notice)

        self.body.addWidget(self._build_workspace(), 1)
        self.body.addWidget(self._build_status())

        self._connect()
        self._add_shortcuts()
        self.editor.set_query(self.settings.last_query or FIRST_QUERY)
        self._refresh_status()

    def _build_header_actions(self) -> None:
        self.sources_button = QPushButton("Sources")
        self.sources_button.setIcon(icons.icon("folder", tone="muted", size=16))
        self.sources_button.clicked.connect(self.open_sources)
        self.add_header_action(self.sources_button)

        self.more_button = IconButton("more-vertical", "More", tone="muted")
        self.more_button.clicked.connect(self._show_menu)
        self.add_header_action(self.more_button)

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setObjectName("huntToolbar")
        row = QHBoxLayout(bar)
        row.setContentsMargins(SPACE_MD, SPACE_SM, SPACE_MD, SPACE_SM)
        row.setSpacing(SPACE_SM)

        self.run_button = QPushButton("Run")
        self.run_button.setIcon(icons.icon("play", tone="on_accent", size=15))
        self.run_button.setProperty("variant", "primary")
        self.run_button.setToolTip("Run the query  (Ctrl+Enter)")
        self.run_button.clicked.connect(self.run_query)
        row.addWidget(self.run_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setVisible(False)
        self.cancel_button.clicked.connect(self.indexer.cancel)
        row.addWidget(self.cancel_button)

        self.time_button = QPushButton(self.time_range.describe())
        self.time_button.setIcon(icons.icon("clock", tone="muted", size=15))
        self.time_button.setToolTip("Which window every query is filtered to.")
        self.time_button.clicked.connect(self.open_time_range)
        row.addWidget(self.time_button)

        row.addWidget(Separator(vertical=True))

        self.save_button = QPushButton("Save")
        self.save_button.setIcon(icons.icon("save", tone="muted", size=15))
        self.save_button.setToolTip("Keep this query in the rail  (Ctrl+S)")
        self.save_button.clicked.connect(self.save_query)
        row.addWidget(self.save_button)

        self.export_button = QPushButton("Export")
        self.export_button.setIcon(icons.icon("download", tone="muted", size=15))
        self.export_button.clicked.connect(self._show_export_menu)
        row.addWidget(self.export_button)

        row.addStretch(1)

        self.index_chip = Badge("", "neutral")
        self.index_chip.setToolTip("What is in the index. Click Sources to "
                                   "change it.")
        row.addWidget(self.index_chip)

        self.untimed_chip = Badge("", "info")
        self.untimed_chip.setVisible(False)
        row.addWidget(self.untimed_chip)

        self.progress = QProgressBar()
        self.progress.setMaximumWidth(240)
        self.progress.setVisible(False)
        row.addWidget(self.progress)

        return bar

    def _build_workspace(self) -> QWidget:
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setChildrenCollapsible(True)

        self.rail = HuntRail(self.queries)
        self.rail.setMinimumWidth(210)
        self.rail.setMaximumWidth(420)
        self.splitter.addWidget(self.rail)

        right = QSplitter(Qt.Orientation.Vertical)
        right.setChildrenCollapsible(False)

        self.editor = KqlEditor()
        self.editor.setMinimumHeight(96)
        right.addWidget(self.editor)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.grid = ResultsGrid()
        self.results_host = QWidget()
        host_column = QVBoxLayout(self.results_host)
        host_column.setContentsMargins(0, 0, 0, 0)
        host_column.setSpacing(0)
        host_column.addWidget(self.grid)
        self.empty = EmptyState(
            "hunt", "Nothing indexed yet",
            "Hunt looks in the places logs actually hide — ~/.config, "
            "~/.local/share, ~/.local/state, ~/.cache, flatpak's ~/.var/app "
            "and the readable half of /var/log — recognises about twenty "
            "formats, and puts every line into one table you can query. It "
            "can read the systemd journal too: Sources → Journal.",
            "Search for logs")
        self.empty.actioned.connect(self.scan_for_logs)
        host_column.addWidget(self.empty)
        self.tabs.addTab(self.results_host,
                         icons.icon("table", tone="muted", size=15), "Results")

        self.chart = Chart()
        self.tabs.addTab(self.chart, icons.icon("chart", tone="muted", size=15),
                         "Chart")

        self.insights = InsightsPanel()
        self.tabs.addTab(self.insights,
                         icons.icon("sparkle", tone="muted", size=15), "Insights")

        right.addWidget(self.tabs)
        right.setSizes([170, 520])
        self.splitter.addWidget(right)
        self.splitter.setSizes([260, 940])
        self.splitter.setStretchFactor(1, 1)
        return self.splitter

    def _build_status(self) -> QWidget:
        strip = QWidget()
        strip.setObjectName("huntStatus")
        row = QHBoxLayout(strip)
        row.setContentsMargins(SPACE_MD, SPACE_XS, SPACE_MD, SPACE_XS)
        row.setSpacing(SPACE_SM)

        self.status_label = label("", role="muted")
        row.addWidget(self.status_label)

        self.details_button = QPushButton("Query details")
        self.details_button.setProperty("variant", "link")
        self.details_button.setVisible(False)
        self.details_button.clicked.connect(self._show_query_details)
        row.addWidget(self.details_button)

        row.addStretch(1)
        self.hint_label = label("", role="caption")
        row.addWidget(self.hint_label, 0)
        return strip

    def _connect(self) -> None:
        self.editor.run_requested.connect(self.run_query)
        self.editor.checked.connect(self._on_checked)
        self.editor.hint_changed.connect(self._on_hint)

        self.rail.insert_requested.connect(self.editor.insert_at_cursor)
        self.rail.query_requested.connect(self._load_query)
        self.rail.favourite_toggled.connect(self._on_favourite)
        self.rail.source_activated.connect(self._show_source)

        self.grid.filter_requested.connect(self._append_stage)
        self.grid.copied.connect(
            lambda _text: self.notify.emit("Copied.", "info"))

        self.insights.analyse_requested.connect(self.run_analysis)
        self.insights.query_requested.connect(self._load_query)
        self.insights.rules_folder_requested.connect(self._open_rules_folder)

        self.indexer.busy_changed.connect(self._on_busy)
        self.indexer.scan_started.connect(lambda: self._set_mode("scan"))
        self.indexer.scan_progress.connect(self._on_scan_progress)
        self.indexer.scan_finished.connect(self._on_scan_finished)
        self.indexer.index_started.connect(self._on_index_started)
        self.indexer.index_progress.connect(self._on_index_progress)
        self.indexer.index_finished.connect(self._on_index_finished)
        self.indexer.journal_progress.connect(self._on_journal_progress)
        self.indexer.journal_finished.connect(self._on_journal_finished)
        self.indexer.query_finished.connect(self._on_query_finished)
        self.indexer.query_failed.connect(self._on_query_failed)
        self.indexer.review_progress.connect(
            lambda done, total, title:
                self.insights.set_busy(True, done, total, title))
        self.indexer.review_finished.connect(self._on_review_finished)
        self.indexer.failed.connect(lambda message: self._warn(message, "danger"))

        self.rail.set_favourites(self.settings.favourites)

    def _add_shortcuts(self) -> None:
        for key, handler in (
            ("Ctrl+Return", self.run_query),
            ("Ctrl+S", self.save_query),
            ("Ctrl+K", self.rail.focus_search),
            ("Ctrl+E", self.editor.setFocus),
            ("Ctrl+Shift+F", self.scan_for_logs),
        ):
            shortcut = QShortcut(QKeySequence(key), self)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(handler)

    # -- lifecycle --------------------------------------------------------

    def on_shown(self) -> None:
        if not self._built:
            return
        self._refresh_status()
        self.rail.set_sources(self.indexer.store.sources())
        if self.settings.index_on_open and not self.indexer.busy:
            stale = self.indexer.stale_by()
            if stale > self.settings.stale_after_minutes * 60:
                self.indexer.reindex_known()

    def on_hidden(self) -> None:
        if not self._built:
            return
        self.settings.last_query = self.editor.toPlainText()
        self.settings.time_range = self.time_range
        self.settings.save()

    def shutdown(self) -> None:
        """Save what the user was doing and let go of the database."""
        if self._built:
            self.on_hidden()
        self.indexer.cancel()
        self.indexer.close()

    def badge(self) -> str:
        if not self._built:
            return ""
        count = self.insights.badge_count()
        return str(count) if count else ""

    # -- indexing ---------------------------------------------------------

    def scan_for_logs(self) -> None:
        """Walk the configured places looking for log files."""
        if self.indexer.busy:
            self._warn("Something is already running. Cancel it first.", "warn")
            return
        self.indexer.scan()

    def _on_scan_progress(self, directory: str) -> None:
        self.status_label.setText(f"Searching {_short_path(directory)}…")

    def _on_scan_finished(self, crawl: Crawl) -> None:
        self.status_label.setText(crawl.summary())
        if crawl.limits_hit():
            self._warn(crawl.limits_hit(), "warn")
        dialog = self._sources_dialog
        if dialog is not None and dialog.isVisible():
            dialog.refresh(crawl, self.indexer.store.sources())
            return
        self.open_sources()

    def _on_index_started(self, total: int) -> None:
        self._set_mode("index")
        self.progress.setRange(0, total)
        self.progress.setValue(0)
        self.progress.setVisible(True)

    def _on_index_progress(self, done: int, total: int, path: str) -> None:
        self.progress.setValue(done)
        self.status_label.setText(f"Reading {_short_path(path)}  ({done}/{total})")

    def _on_index_finished(self, run: IndexRun) -> None:
        self._refresh_status()
        self.rail.set_sources(self.indexer.store.sources())
        dialog = self._sources_dialog
        if dialog is not None and dialog.isVisible():
            dialog.refresh(self.indexer.last_crawl, self.indexer.store.sources())
        self.status_label.setText(run.summary())
        if run.cancelled:
            self._warn("Indexing stopped. Everything read so far was kept — "
                       "the next index carries on from where each file left "
                       "off.", "info")
        elif run.failures:
            self._warn(f"{len(run.failures)} files could not be read. The "
                       "Sources dialog says why.", "warn")
        elif run.added:
            self.notify.emit(run.summary(), "ok")
            if self._last_result is None:
                self.run_query()

    def open_sources(self) -> None:
        """Show what was found, what is indexed, and what was skipped."""
        dialog = SourcesDialog(self, crawl=self.indexer.last_crawl,
                               sources=self.indexer.store.sources(),
                               journal=self._journal_state())
        dialog.scan_requested.connect(self.scan_for_logs)
        dialog.index_requested.connect(self._index_selected)
        dialog.forget_requested.connect(self._forget_source)
        dialog.journal_requested.connect(self.index_journal)
        dialog.forget_journal_requested.connect(self._forget_journal)
        self._sources_dialog = dialog
        dialog.exec()
        self._sources_dialog = None
        self._refresh_status()
        self.rail.set_sources(self.indexer.store.sources())

    def _journal_state(self) -> tuple:
        """Everything the Journal tab shows, gathered in one place."""
        store = self.indexer.store
        entries, units, last_read = store.journal_totals()
        rows = sorted(((source.app, source.events)
                       for source in store.journal_sources()),
                      key=lambda pair: -pair[1])
        return (self.indexer.journal_availability(),
                self.settings.journal_options(), entries, units, last_read,
                self.settings.journal_enabled, rows)

    # -- the systemd journal ----------------------------------------------

    def index_journal(self) -> None:
        """Read whatever is new in the journal.

        Asking for it explicitly turns it on: somebody who presses the button
        in the Sources dialog has said what they want more clearly than a
        setting does.
        """
        if self.indexer.busy:
            self._warn("Something is already running.", "warn")
            return
        available = self.indexer.journal_availability()
        if not available.usable:
            self._warn(available.describe(), "warn")
            return
        if not self.settings.journal_enabled:
            self.settings.journal_enabled = True
            self.settings.save()
        self._set_mode("journal")
        self.status_label.setText("Reading the journal…")
        self.indexer.index_journal()

    def _on_journal_progress(self, count: int) -> None:
        self.status_label.setText(f"Reading the journal… {count:,} entries")

    def _on_journal_finished(self, ingest) -> None:
        self._refresh_status()
        self.rail.set_sources(self.indexer.store.sources())
        dialog = self._sources_dialog
        if dialog is not None and dialog.isVisible():
            dialog.refresh(self.indexer.last_crawl,
                           self.indexer.store.sources(), self._journal_state())
        self.status_label.setText(ingest.summary())
        if not ingest.ok:
            self._warn(ingest.summary(), "danger")
        elif ingest.stale_cursor:
            self._warn("The saved position in the journal had expired — the "
                       "journal was rotated or vacuumed since the last read — "
                       "so the configured window was read again. Some entries "
                       "may now appear twice.", "info")
        elif ingest.added:
            self.notify.emit(ingest.summary(), "ok")

    def _forget_journal(self) -> None:
        removed = self.indexer.forget_journal()
        self._refresh_status()
        self.rail.set_sources(self.indexer.store.sources())
        dialog = self._sources_dialog
        if dialog is not None and dialog.isVisible():
            dialog.refresh(self.indexer.last_crawl,
                           self.indexer.store.sources(), self._journal_state())
        self.notify.emit(f"Forgot {removed:,} journal entries.", "info")

    def _index_selected(self, candidates: list) -> None:
        self.indexer.index(candidates)

    def _forget_source(self, path: str) -> None:
        removed = self.indexer.forget(path)
        self.notify.emit(f"Forgot {os.path.basename(path)} and "
                         f"{removed:,} events.", "info")
        self._refresh_status()

    # -- querying ---------------------------------------------------------

    def run_query(self) -> None:
        text = self.editor.toPlainText().strip()
        if not text:
            return
        if self.indexer.busy:
            self._warn("Something is already running.", "warn")
            return
        if self.indexer.status().empty:
            self._warn("Nothing is indexed yet, so there is nothing to query.",
                       "info")
            return

        self._set_mode("query")
        self._last_query = text
        self.status_label.setText("Running…")
        self.editor.set_error(None)
        self.indexer.query(text, self.time_range)

    def _on_query_finished(self, table: ResultTable) -> None:
        self._last_result = table
        self.grid.set_table(table)
        self.empty.setVisible(False)
        self.grid.setVisible(True)
        self.editor.set_result_columns(table.names)
        self.queries.remember(self._last_query, elapsed=table.stats.elapsed,
                              rows=table.stats.rows)
        self.rail.refresh()

        if table.visualisation:
            kind, properties = table.visualisation
            self.chart.set_table(table, kind, properties)
            self.tabs.setCurrentWidget(self.chart)
        else:
            self.chart.set_table(table, "columnchart")
            if self.tabs.currentWidget() is self.chart:
                self.tabs.setCurrentWidget(self.results_host)

        summary = table.stats.summary()
        if table.stats.truncated:
            summary += f" — {table.stats.note}"
        self.status_label.setText(summary)
        self.details_button.setVisible(True)
        if not table.rows:
            self._explain_empty_result()

    def _explain_empty_result(self) -> None:
        """An empty result is usually the time range, so say which way it missed.

        The common case is not exotic: index last week's logs, run a first
        query against the default "Last 24 hours", and see nothing. A bare "No
        rows matched" reads as Hunt being broken, when the answer is one click
        on the time picker — so when every timed event falls outside the
        window, the notice says where they actually are.
        """
        if self.time_range.unbounded:
            self._warn("No rows matched.", "info")
            return

        status = self.indexer.status()
        start, end = self.time_range.bounds()
        window = self.time_range.describe()
        untimed = (f" {status.untimed:,} events carry no timestamp at all, and "
                   "no time range can match those."
                   if status.untimed else "")

        if status.last is not None and start is not None and status.last < start:
            self._warn(
                f"No rows in the time range ({window}). The newest indexed "
                f"event is from {humanise_age(status.last)} — widen the time "
                f"range or choose All time.{untimed}", "info")
        elif status.first is not None and end is not None and status.first > end:
            self._warn(
                f"No rows in the time range ({window}). Every indexed event is "
                f"newer than that — the oldest is from "
                f"{humanise_age(status.first)}.{untimed}", "info")
        elif status.untimed:
            self._warn(
                f"No rows. {status.untimed:,} of the {status.events:,} indexed "
                "events carry no timestamp, and a time range cannot match "
                "those — try All time.", "info")
        else:
            self._warn("No rows matched.", "info")

    def _on_query_failed(self, error: KqlError) -> None:
        self.editor.set_error(error)
        self.status_label.setText("")
        self.details_button.setVisible(False)
        self.queries.remember(self._last_query, error=str(error))
        self._warn(error.full_message(), "danger")

    def _on_checked(self, error: KqlError | None) -> None:
        if error is None and self.notice.isVisible():
            self.notice.setVisible(False)

    def _on_hint(self, text: str) -> None:
        self.hint_label.setText(text[:160])

    def _load_query(self, text: str, run: bool) -> None:
        self.editor.set_query(text)
        if run:
            self.tabs.setCurrentWidget(self.results_host)
            self.run_query()

    def _append_stage(self, stage: str) -> None:
        self.editor.append_stage(stage)
        self.run_query()

    def _show_query_details(self) -> None:
        if self._last_result is None:
            return
        QueryDetailsDialog(self, self._last_query, self._last_result.stats).exec()

    # -- analysis ---------------------------------------------------------

    def run_analysis(self) -> None:
        if self.indexer.busy:
            self._warn("Something is already running.", "warn")
            return
        if self.indexer.status().empty:
            self._warn("Index some logs first.", "info")
            return
        self._set_mode("review")
        self.insights.set_busy(True)
        self.tabs.setCurrentWidget(self.insights)
        self.indexer.review(self.time_range)

    def _on_review_finished(self, review) -> None:
        self.insights.set_busy(False)
        self.insights.show_review(review)
        self.badge_changed.emit(self.badge())
        self.status_label.setText(review.summary())

    def _open_rules_folder(self) -> None:
        target = hunt_rules.write_example()
        _open_directory(target.parent)
        self.notify.emit(f"Rule files live in {target.parent}.", "info")

    # -- saving and exporting ---------------------------------------------

    def save_query(self) -> None:
        text = self.editor.toPlainText().strip()
        if not text:
            return
        dialog = SaveQueryDialog(self, text, time_range=self.time_range)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.queries.save(dialog.name.text().strip() or "Untitled",
                          text, description=dialog.description.text().strip(),
                          time_range=self.time_range
                          if dialog.keep_range.isChecked() else None)
        self.rail.refresh()
        self.notify.emit("Saved. It is in the Queries tab on the left.", "ok")

    def _show_export_menu(self) -> None:
        menu = QMenu(self)
        if self._last_result is None or not self._last_result.rows:
            action = menu.addAction("Run a query first")
            action.setEnabled(False)
        else:
            for name, extension, description in hunt_export.describe_formats():
                action = menu.addAction(f"{description}  (.{extension})")
                action.triggered.connect(
                    lambda _checked=False, chosen=name: self._export(chosen))
            menu.addSeparator()
            menu.addAction("Copy everything as TSV", self.grid.copy_all)
        menu.exec(self.export_button.mapToGlobal(
            self.export_button.rect().bottomLeft()))

    def _export(self, format_id: str) -> None:
        if self._last_result is None:
            return
        extension = next((item[1] for item in hunt_export.describe_formats()
                          if item[0] == format_id), "txt")
        paths.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        suggested = str(paths.REPORTS_DIR / f"hunt.{extension}")
        target, _filter = QFileDialog.getSaveFileName(
            self, "Export results", suggested, f"*.{extension}")
        if not target:
            return
        try:
            Path(target).write_text(
                hunt_export.render(self._last_result, format_id,
                                   query=self._last_query),
                encoding="utf-8")
        except OSError as error:
            self._warn(f"Could not write {target}: {error}", "danger")
            return
        self.notify.emit(f"Exported {len(self._last_result.rows):,} rows to "
                         f"{os.path.basename(target)}.", "ok")

    # -- settings and menu ------------------------------------------------

    def open_time_range(self) -> None:
        status = self.indexer.status()
        dialog = TimeRangeDialog(self, self.time_range, untimed=status.untimed)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.time_range = dialog.selected()
        self.time_button.setText(self.time_range.describe())
        self.settings.time_range = self.time_range
        self.settings.save()
        if self._last_result is not None:
            self.run_query()

    def _show_menu(self) -> None:
        menu = QMenu(self)
        menu.addAction("Re-read changed log files", self.indexer.reindex_known)
        menu.addAction("Read the systemd journal", self.index_journal)
        menu.addAction("Search for new log files", self.scan_for_logs)
        menu.addAction("Sources…", self.open_sources)
        menu.addSeparator()
        menu.addAction("Run the analysis rules", self.run_analysis)
        menu.addAction("Where rules live…", self._open_rules_folder)
        menu.addSeparator()
        menu.addAction("Format this query", self._format_query)
        menu.addAction("Clear the editor", lambda: self.editor.set_query(""))
        menu.addAction("Query details…", self._show_query_details)
        menu.addSeparator()
        menu.addAction("Hunt settings…", self.open_settings)
        menu.addAction("Forget everything indexed…", self._clear_index)
        menu.addSeparator()
        menu.addAction("What this page can do…", self._show_help)
        menu.exec(self.more_button.mapToGlobal(
            self.more_button.rect().bottomLeft()))

    def open_settings(self) -> None:
        dialog = HuntSettingsDialog(self, self.settings)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        dialog.apply()
        self._refresh_status()
        self.notify.emit("Saved. " + self.settings.summary(), "ok")

    def _clear_index(self) -> None:
        status = self.indexer.status()
        if status.empty:
            return
        if not confirm(
                self, "Forget everything indexed",
                f"This removes all {status.events:,} indexed events and the "
                f"{status.sources} files Hunt knows about, freeing "
                f"{humanise_bytes(status.bytes)}.",
                detail="Your log files are not touched. Nothing is deleted "
                       "outside ClamGuard's own database at "
                       f"{self.indexer.store.path}.\n\n"
                       "Searching for logs again re-reads them from the start.",
                confirm_text="Forget them", destructive=True):
            return
        self.indexer.clear()
        self._last_result = None
        self.grid.set_table(ResultTable())
        self._refresh_status()
        self.rail.set_sources([])
        self.notify.emit("The index is empty.", "info")

    def _format_query(self) -> None:
        """Put each pipeline stage on its own line."""
        text = self.editor.toPlainText()
        if not text.strip():
            return
        pieces = [piece for piece in _split_stages(text) if piece]
        self.editor.set_query("\n| ".join(pieces))

    def _show_help(self) -> None:
        from ..dialogs import ConfirmDialog

        starters = "\n".join(f"  {item.name}\n    {item.one_line[:110]}"
                             for item in library.starters())
        ConfirmDialog(
            self, "Hunt",
            "Hunt indexes the log files on this machine and lets you query "
            "them in KQL — the same language Azure Sentinel uses.",
            detail=(
                "WHERE IT LOOKS\n"
                "  ~/.config, ~/.local/share, ~/.local/state, ~/.cache,\n"
                "  ~/.var/app (flatpak), ~/snap, ~/.npm/_logs, /var/log.\n"
                "  The systemd journal too, if you switch it on in Sources.\n"
                "  Not auditd: /var/log/audit is root-only and ClamGuard\n"
                "  never runs as root.\n\n"
                "WHAT IT UNDERSTANDS\n"
                "  About twenty formats — JSON Lines, logfmt, syslog, Chromium,\n"
                "  Abseil, electron-log, pacman, Xorg, Apache, nginx and more —\n"
                "  all normalised into one table with Timestamp, Level and Message.\n\n"
                "KEYS\n"
                "  Ctrl+Enter   run        Ctrl+S   save the query\n"
                "  Ctrl+Space   complete   Ctrl+K   search the rail\n\n"
                "QUERIES TO START WITH\n" + starters),
            confirm_text="Close", cancel_text="", tone="info").exec()

    def _on_favourite(self, identifier: str, wanted: bool) -> None:
        favourites = set(self.settings.favourites)
        if wanted:
            favourites.add(identifier)
        else:
            favourites.discard(identifier)
        self.settings.favourites = sorted(favourites)
        self.settings.save()
        self.rail.set_favourites(self.settings.favourites)

    def _show_source(self, path: str) -> None:
        self._load_query(f'Sources\n| where Path == "{path}"', True)

    # -- chrome -----------------------------------------------------------

    def _set_mode(self, mode: str) -> None:
        self._mode = mode

    def _on_busy(self, busy: bool) -> None:
        self.run_button.setEnabled(not busy)
        self.cancel_button.setVisible(busy)
        self.sources_button.setEnabled(not busy)
        if busy and self._mode in ("scan", "query", "review", "journal"):
            self.progress.setRange(0, 0)
            self.progress.setVisible(True)
        elif not busy:
            self.progress.setVisible(False)
            self.insights.set_busy(False)

    def _refresh_status(self) -> None:
        status = self.indexer.status()
        empty = status.empty
        self.empty.setVisible(empty)
        self.grid.setVisible(not empty)
        self.insights.analyse.setEnabled(not empty)

        if empty:
            self.index_chip.set_state("nothing indexed", "warn")
            self.untimed_chip.setVisible(False)
            self.status_label.setText(
                "Search for logs to get started — it takes a couple of seconds.")
            return

        self.index_chip.set_state(
            f"{humanise_count(status.events)} events · {status.sources} files · "
            f"{humanise_bytes(status.bytes)}", "neutral")
        when = humanise_age(int(status.last_indexed * 1_000_000)
                            if status.last_indexed else None)
        journal_note = (f"\n{status.journal_events:,} of them are journal "
                        f"entries, from {status.journal_units} units."
                        if status.journal_events else
                        "\nThe systemd journal is not indexed — Sources → "
                        "Journal turns it on.")
        self.index_chip.setToolTip(
            f"{status.events:,} events from {status.sources} sources.\n"
            f"Last indexed {when}." + journal_note + "\n"
            f"{'Full-text index on' if status.full_text else 'No full-text index'}.")

        if status.untimed:
            share = status.untimed / max(1, status.events) * 100
            self.untimed_chip.set_state(
                f"{humanise_count(status.untimed)} without a timestamp", "info")
            self.untimed_chip.setToolTip(
                f"{status.untimed:,} events ({share:.0f}%) came from formats "
                "that do not record a time — Unity and Steam logs, most game "
                "logs, Xorg. A time range cannot match them; choose All time "
                "to include them.")
            self.untimed_chip.setVisible(True)
        else:
            self.untimed_chip.setVisible(False)

    def _warn(self, message: str, tone: str = "warn") -> None:
        self.notice.set_message(message, tone)
        self.notice.setVisible(True)

    def apply_palette(self, palette, accent: str) -> None:
        """Hand the palette to the three widgets that paint themselves."""
        for name in ("editor", "grid", "chart"):
            widget = getattr(self, name, None)
            if widget is not None:
                widget.apply_palette(palette, accent)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split_stages(text: str) -> list[str]:
    """Split a query on its top-level pipes, ignoring the ones in strings."""
    pieces: list[str] = []
    current: list[str] = []
    depth = 0
    quote = ""
    index = 0
    while index < len(text):
        character = text[index]
        if quote:
            current.append(character)
            if character == quote:
                quote = ""
            elif character == "\\":
                index += 1
                if index < len(text):
                    current.append(text[index])
        elif character in "\"'":
            quote = character
            current.append(character)
        elif character in "([{":
            depth += 1
            current.append(character)
        elif character in ")]}":
            depth = max(0, depth - 1)
            current.append(character)
        elif character == "|" and depth == 0:
            pieces.append("".join(current))
            current = []
        else:
            current.append(character)
        index += 1
    pieces.append("".join(current))
    return [" ".join(piece.split()) for piece in pieces]


def _short_path(path: str, limit: int = 58) -> str:
    home = str(Path.home())
    if path.startswith(home):
        path = "~" + path[len(home):]
    return path if len(path) <= limit else "…" + path[-(limit - 1):]


def _open_directory(directory: Path) -> None:
    """Open a folder in the desktop's file manager, if it has one."""
    from ...core.process import which

    for candidate, arguments in (("xdg-open", [str(directory)]),
                                 ("gio", ["open", str(directory)]),
                                 ("kde-open", [str(directory)])):
        found = which(candidate)
        if not found:
            continue
        try:
            subprocess.Popen([found, *arguments], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            continue
        return
