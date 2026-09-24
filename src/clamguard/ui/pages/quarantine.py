"""The quarantine vault: what was isolated, and what you can do about it.

Two things this page has to get right.

First, **restoring must always be possible**. Antivirus false positives are
common and a vault you cannot get files out of is a shredder. So Restore is a
first-class button, not buried.

Second, **restoring must be understood**. Putting a file back means putting
live malware back on the disk. The confirmation says exactly that, names the
file and the threat, and does not have a default "yes".
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.database import format_bytes
from ...core import paths
from .. import icons
from ..dialogs import confirm
from ..theme import SPACE_SM
from ..widgets import (
    Card,
    EmptyState,
    KeyValueRow,
    MessageBar,
    Separator,
    fit_table,
    label,
)
from .base import Page

#: Rows are tall enough to hold a row of buttons.
ROW_HEIGHT = 48


class QuarantinePage(Page):
    PAGE_ID = "quarantine"
    TITLE = "Quarantine"
    SUBTITLE = "Files that were isolated so they cannot run"
    ICON = "quarantine"

    def build(self) -> None:
        self._entries: list = []

        self.notice = MessageBar(
            "Files here have been moved out of their original location and scrambled "
            "so they cannot be opened or run. They are still on your disk until you "
            "delete them.", "info")
        self.body.addWidget(self.notice)

        self.empty = EmptyState(
            "quarantine", "Nothing is in quarantine",
            "When a scan finds a threat and you choose to quarantine it, the file is "
            "moved here. Nothing has been quarantined yet.",
            "Run a scan")
        self.empty.actioned.connect(lambda: self.navigate.emit("scan"))
        self.body.addWidget(self.empty)

        self.list_card = Card("Quarantined files", icon="quarantine")
        actions = QHBoxLayout()
        actions.setSpacing(SPACE_SM)
        self.verify_button = QPushButton("Check the vault")
        self.verify_button.setIcon(icons.icon("check-circle", tone="muted", size=16))
        self.verify_button.setToolTip(
            "Re-hash every quarantined file and compare it with what was recorded.")
        self.verify_button.clicked.connect(self._verify_all)
        self.export_button = QPushButton("Export list…")
        self.export_button.setIcon(icons.icon("download", tone="muted", size=16))
        self.export_button.clicked.connect(self._export_list)
        self.empty_button = QPushButton("Delete everything")
        self.empty_button.setProperty("variant", "danger")
        self.empty_button.setIcon(icons.icon("trash", "#ffffff", size=16))
        self.empty_button.clicked.connect(self._delete_all)
        actions.addWidget(self.verify_button)
        actions.addWidget(self.export_button)
        actions.addStretch(1)
        actions.addWidget(self.empty_button)
        self.list_card.body.addLayout(actions)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["File", "Threat", "Quarantined", "Size", ""])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.itemSelectionChanged.connect(self._refresh_detail)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 3):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(4, 184)
        self.list_card.body.addWidget(self.table)
        self.body.addWidget(self.list_card)

        self.detail_card = Card("Details", icon="info")
        self.detail_box = QVBoxLayout()
        self.detail_box.setSpacing(0)
        self.detail_card.body.addLayout(self.detail_box)
        self.body.addWidget(self.detail_card)

        self.vault_card = Card("The vault", icon="lock")
        self.vault_box = QVBoxLayout()
        self.vault_box.setSpacing(0)
        self.vault_card.body.addLayout(self.vault_box)
        self.body.addWidget(self.vault_card)

        self.add_stretch()
        self.context.quarantine.changed.connect(self.refresh)

    # -- lifecycle --------------------------------------------------------

    def on_shown(self) -> None:
        self.refresh()

    def badge(self) -> str:
        count = self.context.quarantine.count()
        return str(count) if count else ""

    # -- rendering --------------------------------------------------------

    def refresh(self) -> None:
        self._entries = self.context.quarantine.entries()
        has_entries = bool(self._entries)

        self.empty.setVisible(not has_entries)
        self.notice.setVisible(has_entries)
        self.list_card.setVisible(has_entries)
        self.detail_card.setVisible(has_entries)
        self.vault_card.setVisible(has_entries)

        self.list_card.set_title(
            f"Quarantined files — {len(self._entries)}" if has_entries
            else "Quarantined files")

        self.table.setRowCount(0)
        for entry in self._entries:
            row = self.table.rowCount()
            self.table.insertRow(row)

            name_item = QTableWidgetItem(entry.filename)
            name_item.setToolTip(entry.original_path)
            name_item.setData(Qt.ItemDataRole.UserRole, entry)
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, QTableWidgetItem(entry.threat))

            when = entry.when
            self.table.setItem(row, 2, QTableWidgetItem(
                when.strftime("%d %b %H:%M") if when else "—"))
            self.table.setItem(row, 3, QTableWidgetItem(format_bytes(entry.size)))

            holder = QWidget()
            buttons = QHBoxLayout(holder)
            buttons.setContentsMargins(4, 2, 4, 2)
            buttons.setSpacing(SPACE_SM)
            restore = QPushButton("Restore")
            restore.clicked.connect(lambda _=False, e=entry: self._restore(e))
            delete = QPushButton("Delete")
            delete.setProperty("variant", "danger")
            delete.clicked.connect(lambda _=False, e=entry: self._delete(e))
            buttons.addWidget(restore)
            buttons.addWidget(delete)
            self.table.setCellWidget(row, 4, holder)

        fit_table(self.table, row_height=ROW_HEIGHT)
        if self._entries:
            self.table.selectRow(0)
        self._refresh_detail()
        self._refresh_vault()
        self.badge_changed.emit(self.badge())

    def _refresh_detail(self) -> None:
        _clear(self.detail_box)
        entry = self._selected_entry()
        if entry is None:
            self.detail_box.addWidget(
                label("Select a file above to see where it came from.", role="muted"))
            return

        when = entry.when
        rows = [
            ("Original location", entry.original_path),
            ("Threat name", entry.threat),
            ("Quarantined", f"{when:%A %d %B %Y, %H:%M}" if when else "—"),
            ("Size", format_bytes(entry.size)),
            ("Owned by", f"{entry.owner or entry.uid}:{entry.group or entry.gid}"),
            ("Permissions", oct(entry.mode)[2:] if entry.mode else "—"),
            ("SHA-256", entry.sha256 or "not recorded"),
            ("Found by", entry.engine or "—"),
        ]
        for key, value in rows:
            self.detail_box.addWidget(
                KeyValueRow(key, value, mono=key in ("SHA-256", "Original location")))

        seen = self.context.history.detection_count_for_path(entry.original_path)
        if seen > 1:
            self.detail_box.addWidget(Separator())
            self.detail_box.addWidget(label(
                f"This exact path has been flagged {seen} times. If it keeps coming "
                "back, something is putting it there.", role="muted", tone="warn",
                wrap=True))

        if entry.privileged:
            self.detail_box.addWidget(Separator())
            self.detail_box.addWidget(label(
                "This file was owned by another user, so restoring it to its original "
                "place needs administrator rights.", role="muted", wrap=True))

    def _refresh_vault(self) -> None:
        _clear(self.vault_box)
        total = self.context.quarantine.total_bytes()
        self.vault_box.addWidget(KeyValueRow("Location", str(paths.QUARANTINE_VAULT),
                                             mono=True))
        self.vault_box.addWidget(KeyValueRow("Files", str(len(self._entries))))
        self.vault_box.addWidget(KeyValueRow("Space used", format_bytes(total)))
        self.vault_box.addWidget(KeyValueRow(
            "Protection", "Readable only by you, and XOR-scrambled so it cannot run"))
        self.vault_box.addWidget(Separator())
        self.vault_box.addWidget(label(
            "Scrambling is not encryption — it stops accidental execution and stops "
            "ClamGuard finding the same file again on the next scan. Anyone with "
            "access to your account could unscramble it.",
            role="caption", wrap=True))

    # -- actions ----------------------------------------------------------

    def _selected_entry(self):
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() \
            else []
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _restore(self, entry) -> None:
        if not confirm(
            self, "Put this file back?",
            f"{entry.filename} was detected as {entry.threat}.\n\n"
            f"Restoring writes the original file back to:\n{entry.original_path}\n\n"
            "If the detection was correct, the file is malware and it will be live "
            "again. Only do this if you are confident it was a false positive.",
            confirm_text="Restore it", tone="danger", destructive=True,
        ):
            return

        def done(target: Path) -> None:
            self.notify.emit(f"Restored to {target}.", "ok")
            self.context.history.set_action_for_quarantine(entry.id, "restored")
            self.refresh()

        self.context.quarantine.restore(
            entry, on_success=done,
            on_error=lambda message: self.notify.emit(message, "danger"))

    def _restore_elsewhere(self, entry) -> None:
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Restore to…", str(Path.home() / entry.filename))
        if not chosen:
            return
        if not confirm(
            self, "Restore to a different place?",
            f"{entry.filename} ({entry.threat}) will be written to:\n{chosen}\n\n"
            "The file will be live again wherever you put it.",
            confirm_text="Restore it", tone="danger", destructive=True,
        ):
            return
        self.context.quarantine.restore(
            entry, destination=Path(chosen),
            on_success=lambda target: (self.notify.emit(f"Restored to {target}.", "ok"),
                                       self.refresh()),
            on_error=lambda message: self.notify.emit(message, "danger"))

    def _delete(self, entry) -> None:
        if not confirm(
            self, "Delete permanently?",
            f"{entry.filename} will be overwritten and removed from the vault.\n\n"
            "This cannot be undone. On an SSD or a copy-on-write filesystem the "
            "overwrite is best-effort rather than a guarantee.",
            detail=f"Original location: {entry.original_path}\n"
                   f"Threat: {entry.threat}\n"
                   f"Size: {format_bytes(entry.size)}",
            confirm_text="Delete for good", tone="danger", destructive=True,
        ):
            return
        self.context.quarantine.delete(entry)
        self.context.history.set_action_for_quarantine(entry.id, "deleted")
        self.notify.emit(f"{entry.filename} deleted.", "ok")
        self.refresh()

    def _delete_all(self) -> None:
        count = len(self._entries)
        if not count:
            return
        if not confirm(
            self, "Empty the quarantine?",
            f"All {count} quarantined file{'' if count == 1 else 's'} will be "
            "overwritten and removed. This cannot be undone.",
            detail="\n".join(f"{e.threat}  {e.original_path}" for e in self._entries),
            detail_label="WHAT WILL BE DELETED",
            confirm_text=f"Delete all {count}", tone="danger", destructive=True,
        ):
            return
        removed = self.context.quarantine.delete_all()
        self.notify.emit(f"Deleted {removed} file{'' if removed == 1 else 's'}.", "ok")
        self.refresh()

    def _verify_all(self) -> None:
        """Re-hash every payload and report anything that does not match."""
        bad: list[str] = []
        for entry in self._entries:
            ok, _message = self.context.quarantine.verify(entry)
            if not ok:
                bad.append(entry.filename)
        if not self._entries:
            return
        if bad:
            self.notify.emit(
                f"{len(bad)} vault file{'' if len(bad) == 1 else 's'} did not match "
                f"the recorded checksum: {', '.join(bad[:4])}", "danger")
        else:
            self.notify.emit(
                f"All {len(self._entries)} quarantined files are intact.", "ok")

    def _export_list(self) -> None:
        chosen, _ = QFileDialog.getSaveFileName(
            self, "Export the quarantine list",
            str(Path.home() / "clamguard-quarantine.csv"), "CSV files (*.csv)")
        if not chosen:
            return
        lines = ["quarantined_at,threat,original_path,size_bytes,sha256"]
        for entry in self._entries:
            lines.append(",".join([
                entry.quarantined_at,
                _csv(entry.threat),
                _csv(entry.original_path),
                str(entry.size),
                entry.sha256,
            ]))
        try:
            Path(chosen).write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError as error:
            self.notify.emit(f"Could not write the file: {error}", "danger")
            return
        self.notify.emit(f"Exported to {chosen}.", "ok")

    def _context_menu(self, position) -> None:
        item = self.table.itemAt(position)
        if item is None:
            return
        entry = self.table.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
        if entry is None:
            return
        menu = QMenu(self)
        menu.addAction("Restore to the original location", lambda: self._restore(entry))
        menu.addAction("Restore somewhere else…", lambda: self._restore_elsewhere(entry))
        menu.addSeparator()
        menu.addAction("Copy the original path",
                       lambda: self._copy(entry.original_path))
        menu.addAction("Copy the SHA-256", lambda: self._copy(entry.sha256))
        menu.addAction("Copy the threat name", lambda: self._copy(entry.threat))
        menu.addSeparator()
        menu.addAction("Delete permanently", lambda: self._delete(entry))
        menu.exec(self.table.viewport().mapToGlobal(position))

    def _copy(self, text: str) -> None:
        from PySide6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
            self.notify.emit("Copied.", "info")


def _csv(value: str) -> str:
    """Quote a CSV field if it needs it."""
    if any(character in value for character in ',"\n'):
        return '"' + value.replace('"', '""') + '"'
    return value


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
