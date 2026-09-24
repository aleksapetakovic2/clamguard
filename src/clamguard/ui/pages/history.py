"""Every scan this machine has run, and what each one found.

Reads the SQLite database in ~/.local/share/clamguard/. Nothing here talks to
ClamAV: a scan's results were recorded when it happened, and this page is the
record.
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.database import format_bytes, humanise_age
from ...core.scanner import format_duration
from .. import icons
from ..dialogs import confirm
from ..theme import SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    Card,
    EmptyState,
    KeyValueRow,
    Separator,
    fit_table,
    label,
)
from .base import Page

PERIODS = (("Any time", 0), ("Last 7 days", 7), ("Last 30 days", 30),
           ("Last 90 days", 90))
KINDS = (("All scans", ""), ("Quick", "quick"), ("Full system", "full"),
         ("Home folder", "home"), ("Removable media", "removable"),
         ("Custom", "custom"))


class HistoryPage(Page):
    PAGE_ID = "history"
    TITLE = "History"
    SUBTITLE = "Every scan this machine has run"
    ICON = "history"

    def build(self) -> None:
        self._scans: list = []

        self.body.addWidget(self._build_stats_card())

        self.empty = EmptyState(
            "history", "No scans yet",
            "Once you run a scan it is recorded here, with everything it found, "
            "for as long as you keep it.",
            "Run a scan")
        self.empty.actioned.connect(lambda: self.navigate.emit("scan"))
        self.body.addWidget(self.empty)

        self.list_card = Card("Scans", icon="history")
        self.list_card.body.addLayout(self._build_filters())

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["When", "Type", "Scope", "Files", "Duration", "Result"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._refresh_detail)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for column in (0, 1, 3, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        # The Result column holds a Badge widget, and Qt does not measure cell
        # widgets when it sizes a column, so it gets a width of its own.
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(5, 168)
        self.list_card.body.addWidget(self.table)
        self.body.addWidget(self.list_card)

        self.detail_card = Card("Scan details", icon="info")
        self.export_button = QPushButton("Export report…")
        self.export_button.setProperty("variant", "ghost")
        self.export_button.setIcon(icons.icon("download", tone="muted", size=16))
        self.export_button.clicked.connect(self._export_selected)
        self.detail_card.add_action(self.export_button)

        self.delete_button = QPushButton("Delete this record")
        self.delete_button.setProperty("variant", "ghost")
        self.delete_button.clicked.connect(self._delete_selected)
        self.detail_card.add_action(self.delete_button)

        self.detail_box = QVBoxLayout()
        self.detail_box.setSpacing(0)
        self.detail_card.body.addLayout(self.detail_box)
        self.body.addWidget(self.detail_card)

        self.add_stretch()
        self.context.history.changed.connect(self.refresh)
        self.context.history.scan_recorded.connect(lambda _id: self.refresh())

    # -- construction -----------------------------------------------------

    def _build_stats_card(self) -> Card:
        card = Card("Totals", icon="activity")
        clear = QPushButton("Clear history…")
        clear.setProperty("variant", "ghost")
        clear.clicked.connect(self._clear_history)
        card.add_action(clear)

        self.stats_row = QHBoxLayout()
        self.stats_row.setSpacing(SPACE_MD * 3)
        card.body.addLayout(self.stats_row)
        self.stats_card = card
        return card

    def _build_filters(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(SPACE_SM)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search by path or result…")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.textChanged.connect(self.refresh)
        row.addWidget(self.search_box, 2)

        self.kind_box = QComboBox()
        for title, value in KINDS:
            self.kind_box.addItem(title, value)
        self.kind_box.currentIndexChanged.connect(self.refresh)
        row.addWidget(self.kind_box, 1)

        self.period_box = QComboBox()
        for title, days in PERIODS:
            self.period_box.addItem(title, days)
        self.period_box.currentIndexChanged.connect(self.refresh)
        row.addWidget(self.period_box, 1)

        self.threats_only = QPushButton("Only with detections")
        self.threats_only.setCheckable(True)
        self.threats_only.toggled.connect(self.refresh)
        row.addWidget(self.threats_only, 0)
        return row

    # -- refresh ----------------------------------------------------------

    def on_shown(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        self._refresh_stats()

        history = self.context.history
        self._scans = history.search_scans(
            text=self.search_box.text().strip(),
            kind=self.kind_box.currentData() or "",
            days=self.period_box.currentData() or 0,
            threats_only=self.threats_only.isChecked(),
        )

        any_scans = history.totals()["scans"] > 0
        self.empty.setVisible(not any_scans)
        self.list_card.setVisible(any_scans)
        self.detail_card.setVisible(any_scans)
        self.stats_card.setVisible(any_scans)

        self.table.setRowCount(0)
        for record in self._scans:
            row = self.table.rowCount()
            self.table.insertRow(row)
            when = record.started_at
            when_item = QTableWidgetItem(
                when.strftime("%d %b %Y %H:%M") if when else "—")
            when_item.setData(Qt.ItemDataRole.UserRole, record)
            if when:
                when_item.setToolTip(humanise_age(datetime.now() - when))
            self.table.setItem(row, 0, when_item)
            self.table.setItem(row, 1, QTableWidgetItem(record.kind.capitalize()))
            scope_item = QTableWidgetItem(record.target_text())
            scope_item.setToolTip("\n".join(record.targets))
            self.table.setItem(row, 2, scope_item)
            self.table.setItem(row, 3, QTableWidgetItem(f"{record.files_scanned:,}"))
            self.table.setItem(row, 4,
                               QTableWidgetItem(format_duration(record.duration)))

            holder = QWidget()
            box = QHBoxLayout(holder)
            box.setContentsMargins(6, 2, 6, 2)
            box.addWidget(Badge(record.outcome(), record.tone))
            box.addStretch(1)
            self.table.setCellWidget(row, 5, holder)

        fit_table(self.table, row_height=42, maximum=460, minimum=140)
        self.list_card.set_title(
            f"Scans — {len(self._scans)} shown" if self._scans else "Scans")
        if self._scans:
            self.table.selectRow(0)
        self._refresh_detail()

    def _refresh_stats(self) -> None:
        _clear(self.stats_row)
        totals = self.context.history.totals()
        entries = (
            (f"{totals['scans']:,}", "scans", ""),
            (f"{totals['scans_30d']:,}", "in the last 30 days", ""),
            (f"{totals['files']:,}", "files checked", ""),
            (f"{totals['detections']:,}", "detections",
             "danger" if totals["detections"] else ""),
        )
        for value, caption, tone in entries:
            holder = QWidget()
            box = QVBoxLayout(holder)
            box.setContentsMargins(0, 0, 0, 0)
            box.setSpacing(0)
            box.addWidget(label(value, role="metric", tone=tone))
            box.addWidget(label(caption, role="caption"))
            self.stats_row.addWidget(holder)
        self.stats_row.addStretch(1)

    def _selected(self):
        model = self.table.selectionModel()
        rows = model.selectedRows() if model else []
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _refresh_detail(self) -> None:
        _clear(self.detail_box)
        record = self._selected()
        self.export_button.setEnabled(record is not None)
        self.delete_button.setEnabled(record is not None)

        if record is None:
            self.detail_box.addWidget(
                label("Select a scan above to see what it found.", role="muted"))
            return

        rows = [
            ("Started", record.started_at.strftime("%A %d %B %Y, %H:%M:%S")
             if record.started_at else "—"),
            ("Finished", record.finished_at.strftime("%H:%M:%S")
             if record.finished_at else "did not finish"),
            ("Duration", format_duration(record.duration)),
            ("Type", record.kind.capitalize()),
            ("Scope", "\n".join(record.targets) or "—"),
            ("Depth", record.profile.capitalize() or "—"),
            ("Engine", record.engine or "—"),
            ("Files scanned", f"{record.files_scanned:,}"),
            ("Data read", format_bytes(record.bytes_scanned)),
            ("Outcome", record.outcome()),
        ]
        for key, value in rows:
            self.detail_box.addWidget(KeyValueRow(key, value))

        detections = self.context.history.detections_for(record.id)
        if not detections:
            return

        self.detail_box.addWidget(Separator())
        self.detail_box.addWidget(label(
            f"{len(detections)} detection{'' if len(detections) == 1 else 's'}",
            role="sectionLabel"))

        for detection in detections:
            row = QHBoxLayout()
            row.setSpacing(SPACE_SM)
            row.addWidget(Badge(detection.action.capitalize(),
                                _action_tone(detection.action)), 0)
            row.addWidget(label(detection.threat, role="body", tone="danger"), 0)
            path_label = label(detection.path, role="mono", wrap=True)
            row.addWidget(path_label, 1)
            holder = QWidget()
            holder.setLayout(row)
            self.detail_box.addWidget(holder)

    # -- actions ----------------------------------------------------------

    def _export_selected(self) -> None:
        record = self._selected()
        if record is None:
            return
        suggested = f"clamguard-scan-{record.id}.txt"
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Export this scan report", str(Path.home() / suggested),
            "Text report (*.txt);;CSV of detections (*.csv)")
        if not chosen:
            return

        detections = self.context.history.detections_for(record.id)
        try:
            if chosen.endswith(".csv"):
                self._write_csv(Path(chosen), detections)
            else:
                Path(chosen).write_text(self._report_text(record, detections),
                                        encoding="utf-8")
        except OSError as error:
            self.notify.emit(f"Could not write the report: {error}", "danger")
            return
        self.notify.emit(f"Exported to {chosen}.", "ok")

    @staticmethod
    def _write_csv(path: Path, detections) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["detected_at", "threat", "path", "action", "size_bytes",
                             "sha256"])
            for detection in detections:
                writer.writerow([
                    detection.detected_at.isoformat() if detection.detected_at else "",
                    detection.threat, detection.path, detection.action,
                    detection.file_size, detection.sha256,
                ])

    @staticmethod
    def _report_text(record, detections) -> str:
        lines = [
            "ClamGuard scan report",
            "=" * 60,
            f"Scan id      : {record.id}",
            f"Started      : {record.started_at}",
            f"Finished     : {record.finished_at}",
            f"Duration     : {format_duration(record.duration)}",
            f"Type         : {record.kind}",
            f"Depth        : {record.profile}",
            f"Engine       : {record.engine}",
            f"Scope        : {', '.join(record.targets)}",
            f"Files scanned: {record.files_scanned:,}",
            f"Data read    : {format_bytes(record.bytes_scanned)}",
            f"Outcome      : {record.outcome()}",
            "",
        ]
        if detections:
            lines.append(f"Detections ({len(detections)})")
            lines.append("-" * 60)
            for detection in detections:
                lines.append(f"{detection.threat}")
                lines.append(f"    path   : {detection.path}")
                lines.append(f"    action : {detection.action}")
                if detection.sha256:
                    lines.append(f"    sha256 : {detection.sha256}")
                lines.append("")
        else:
            lines.append("No threats were found.")
        return "\n".join(lines) + "\n"

    def _delete_selected(self) -> None:
        record = self._selected()
        if record is None:
            return
        if not confirm(
            self, "Delete this record?",
            "The scan and its detections are removed from the history database. "
            "Files on disk are not touched, and anything in quarantine stays there.",
            confirm_text="Delete the record", tone="warn", destructive=True,
        ):
            return
        self.context.history.delete_scan(record.id)
        self.notify.emit("Record deleted.", "ok")

    def _clear_history(self) -> None:
        totals = self.context.history.totals()
        if not totals["scans"]:
            return
        if not confirm(
            self, "Clear the scan history?",
            f"All {totals['scans']:,} scan records and {totals['detections']:,} "
            "detection records will be deleted.\n\nFiles on disk are not touched, and "
            "the quarantine is left alone.",
            confirm_text="Clear everything", tone="warn", destructive=True,
        ):
            return
        self.context.history.clear()
        self.notify.emit("History cleared.", "ok")


def _action_tone(action: str) -> str:
    return {
        "quarantined": "ok",
        "deleted": "ok",
        "restored": "warn",
        "ignored": "warn",
        "reported": "danger",
    }.get(action, "neutral")


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
