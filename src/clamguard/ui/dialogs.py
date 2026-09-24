"""Dialogs that ask before something irreversible happens.

The rule this file exists to enforce: **ClamGuard never changes a system file,
a service, or deletes anything without showing exactly what will happen.** So
there is no generic "Are you sure?" here. Each dialog shows the actual content
of the change — the unified diff, the unit name, the file path.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from .theme import MONO_FONT_STACK, SPACE_LG, SPACE_MD, SPACE_SM, Palette, pick_font
from .widgets import IconLabel, label


class ConfirmDialog(QDialog):
    """A confirmation that shows the change, not just a question.

    ::

        dialog = ConfirmDialog(
            self, "Save configuration",
            "ClamGuard will replace /etc/clamav/clamd.conf.",
            detail=diff_text, detail_kind="diff",
            confirm_text="Save and back up", tone="warn",
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ...
    """

    def __init__(
        self,
        parent: QWidget | None,
        title: str,
        message: str,
        *,
        detail: str = "",
        detail_kind: str = "text",       # "text" | "diff"
        detail_label: str = "",
        confirm_text: str = "Continue",
        cancel_text: str = "Cancel",
        tone: str = "warn",
        destructive: bool = False,
        palette: Palette | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(680 if detail else 460)
        self._palette = palette

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_MD)
        column.setSpacing(SPACE_MD)

        top = QHBoxLayout()
        top.setSpacing(SPACE_MD)
        icon = {"warn": "alert-triangle", "danger": "alert-circle",
                "info": "info", "ok": "check-circle"}.get(tone, "alert-triangle")
        top.addWidget(IconLabel(icon, tone=tone, size=28), 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(SPACE_SM)
        heading = label(title, role="heading")
        texts.addWidget(heading)
        body = label(message, role="body", wrap=True)
        body.setMinimumWidth(380)
        texts.addWidget(body)
        top.addLayout(texts, 1)
        column.addLayout(top)

        if detail:
            if detail_label:
                column.addWidget(label(detail_label, role="sectionLabel"))
            viewer = QPlainTextEdit()
            viewer.setReadOnly(True)
            viewer.setProperty("role", "log")
            viewer.setFont(QFont(pick_font(MONO_FONT_STACK, "monospace"), 9))
            viewer.setMinimumHeight(240)
            viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            viewer.setPlainText(detail)
            if detail_kind == "diff":
                _colour_diff(viewer, palette)
            column.addWidget(viewer, 1)

        buttons = QDialogButtonBox()
        cancel = buttons.addButton(cancel_text, QDialogButtonBox.ButtonRole.RejectRole)
        confirm = buttons.addButton(confirm_text, QDialogButtonBox.ButtonRole.AcceptRole)
        confirm.setProperty("variant", "danger" if destructive else "primary")
        confirm.setDefault(not destructive)
        cancel.setDefault(destructive)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        column.addWidget(buttons)


def confirm(parent, title: str, message: str, **kwargs) -> bool:
    """Show a ConfirmDialog and return True if the user agreed."""
    dialog = ConfirmDialog(parent, title, message, **kwargs)
    return dialog.exec() == QDialog.DialogCode.Accepted


def _colour_diff(viewer: QPlainTextEdit, palette: Palette | None) -> None:
    """Tint added and removed lines in a unified diff.

    Done with text formats rather than HTML so the viewer stays a plain text
    widget the user can select and copy from.
    """
    added = QColor(palette.ok if palette else "#16a34a")
    removed = QColor(palette.danger if palette else "#dc2626")
    header = QColor(palette.info if palette else "#2563eb")

    document = viewer.document()
    cursor = QTextCursor(document)
    block = document.begin()
    while block.isValid():
        text = block.text()
        colour = None
        if text.startswith("+++") or text.startswith("---") or text.startswith("@@"):
            colour = header
        elif text.startswith("+"):
            colour = added
        elif text.startswith("-"):
            colour = removed

        if colour is not None:
            cursor.setPosition(block.position())
            cursor.setPosition(block.position() + block.length() - 1,
                               QTextCursor.MoveMode.KeepAnchor)
            fmt = QTextCharFormat()
            fmt.setForeground(colour)
            cursor.mergeCharFormat(fmt)
        block = block.next()


class BusyDialog(QDialog):
    """A modal "working on it" while a privileged call is on screen.

    pkexec puts its own password prompt in front of everything, and when it
    closes there can be several seconds of work left. Without this the window
    looks frozen.
    """

    def __init__(self, parent: QWidget | None, title: str, message: str) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(420)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, False)

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_LG)
        column.setSpacing(SPACE_MD)
        column.addWidget(label(title, role="heading"))
        self._message = label(message, role="muted", wrap=True)
        column.addWidget(self._message)

        self._log = QLabel()
        self._log.setTextFormat(Qt.TextFormat.PlainText)   # may carry a file path
        self._log.setProperty("role", "mono")
        self._log.setWordWrap(True)
        column.addWidget(self._log)

    def set_message(self, text: str) -> None:
        self._message.setText(text)

    def set_detail(self, text: str) -> None:
        self._log.setText(text)
