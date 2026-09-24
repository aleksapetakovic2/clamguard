"""Transient messages that appear over the page and fade away.

Used for "Quarantined 3 files" or "Could not restore: permission denied" —
things worth saying once that do not deserve a dialog. Anything the user must
act on goes in a MessageBar inside the page instead, where it stays put.
"""

from __future__ import annotations

from PySide6.QtCore import (
    QEasingCurve,
    QPoint,
    QPropertyAnimation,
    Qt,
    QTimer,
)
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from ..theme import SPACE_MD, SPACE_SM
from .common import IconButton, IconLabel, label, restyle

_ICONS = {"ok": "check-circle", "info": "info", "warn": "alert-triangle",
          "danger": "alert-circle"}


class Toast(QFrame):
    """A single floating message."""

    VISIBLE_MS = 4500
    FADE_MS = 180

    def __init__(self, text: str, tone: str = "info", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("card", f"tint-{tone if tone in _ICONS else 'info'}")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setMaximumWidth(460)

        row = QHBoxLayout(self)
        row.setContentsMargins(SPACE_MD, SPACE_SM + 2, SPACE_SM, SPACE_SM + 2)
        row.setSpacing(SPACE_SM)

        row.addWidget(IconLabel(_ICONS.get(tone, "info"), tone=tone, size=18), 0,
                      Qt.AlignmentFlag.AlignTop)

        message = label(text, role="body", wrap=True)
        row.addWidget(message, 1)

        close = IconButton("x", "Dismiss", tone="muted", size=14)
        close.clicked.connect(self.dismiss)
        row.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)

        self._opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity)
        self._fade = QPropertyAnimation(self._opacity, b"opacity", self)
        self._fade.setDuration(self.FADE_MS)
        self._fade.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._dismissing = False

        self._life = QTimer(self)
        self._life.setSingleShot(True)
        self._life.setInterval(self.VISIBLE_MS)
        self._life.timeout.connect(self.dismiss)

    def show_now(self) -> None:
        self.show()
        self.raise_()
        self._fade.stop()
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.start()
        self._life.start()

    def dismiss(self) -> None:
        """Fade out and delete. Safe to call twice — the timer and a click race."""
        if self._dismissing:
            return
        self._dismissing = True
        self._life.stop()
        self._fade.stop()
        self._fade.setStartValue(self._opacity.opacity())
        self._fade.setEndValue(0.0)
        self._fade.finished.connect(self.deleteLater)
        self._fade.start()


class ToastHost(QWidget):
    """Positions toasts in the bottom-right corner of its parent.

    It is a transparent overlay rather than a layout member, so adding a
    message never reflows the page underneath it.
    """

    MARGIN = 18
    GAP = 8
    MAX_VISIBLE = 3

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
        self._toasts: list[Toast] = []
        parent.installEventFilter(self)
        self.hide()

    def show_message(self, text: str, tone: str = "info") -> None:
        toast = Toast(text, tone, self.parentWidget())
        toast.destroyed.connect(lambda: self._forget(toast))
        self._toasts.append(toast)
        while len(self._toasts) > self.MAX_VISIBLE:
            self._toasts[0].dismiss()
            self._toasts.pop(0)
        toast.adjustSize()
        toast.show_now()
        self._reposition()

    def _forget(self, toast: Toast) -> None:
        """A toast finished fading. Runs from Qt's destroyed signal.

        That signal can arrive after the window — and this host with it — has
        already been torn down, so everything here has to tolerate being dead.
        """
        if not isValid(self):
            return
        if toast in self._toasts:
            self._toasts.remove(toast)
        self._reposition()

    def _reposition(self) -> None:
        if not isValid(self):
            return
        parent = self.parentWidget()
        if parent is None or not isValid(parent):
            return
        y = parent.height() - self.MARGIN
        for toast in reversed(self._toasts):
            if not isValid(toast):
                continue
            toast.adjustSize()
            size = toast.size()
            y -= size.height()
            toast.move(QPoint(parent.width() - size.width() - self.MARGIN, y))
            toast.raise_()
            y -= self.GAP

    def eventFilter(self, watched, event):  # noqa: N802 - Qt naming
        if not isValid(self):
            return False
        if watched is self.parentWidget() and event.type() in (
            event.Type.Resize, event.Type.Move
        ):
            self._reposition()
        return False


def apply_tone(widget: QWidget, tone: str) -> None:
    """Change a toast-styled widget's colour after construction."""
    widget.setProperty("card", f"tint-{tone}")
    restyle(widget)
