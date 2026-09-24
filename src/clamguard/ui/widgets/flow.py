"""A layout that wraps its items onto new lines, like words in a paragraph.

Qt has no built-in flow layout. A row of badges in a QHBoxLayout demands the
width of every badge side by side, and in a narrow panel that minimum is what
forces the whole panel wider than its viewport — which, with horizontal
scrolling off, means content is silently cut off at the right edge. This lays
the same badges out left to right and starts a new line when the next one
would not fit, so its minimum width is only that of the widest single item.

The implementation follows Qt's own "Flow Layout" example.
"""

from __future__ import annotations

from PySide6.QtCore import QPoint, QRect, QSize, Qt
from PySide6.QtWidgets import QLayout, QLayoutItem, QSizePolicy, QWidget


class FlowLayout(QLayout):
    """Left-to-right, wrapping. Height depends on width, so it says so."""

    def __init__(self, parent: QWidget | None = None, *, spacing: int = 6) -> None:
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self._spacing = spacing
        self.setContentsMargins(0, 0, 0, 0)

    # -- QLayout -----------------------------------------------------------

    def addItem(self, item: QLayoutItem) -> None:  # noqa: N802 - Qt API
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> QLayoutItem | None:  # noqa: N802
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int) -> QLayoutItem | None:  # noqa: N802
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self) -> Qt.Orientation:  # noqa: N802
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:  # noqa: N802
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802
        return self._arrange(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect: QRect) -> None:  # noqa: N802
        super().setGeometry(rect)
        self._arrange(rect, apply=True)

    def sizeHint(self) -> QSize:  # noqa: N802
        return self.minimumSize()

    def minimumSize(self) -> QSize:  # noqa: N802
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(),
                            margins.top() + margins.bottom())

    # -- placement ---------------------------------------------------------

    def _arrange(self, rect: QRect, *, apply: bool) -> int:
        margins = self.contentsMargins()
        area = rect.adjusted(margins.left(), margins.top(),
                             -margins.right(), -margins.bottom())
        x, y, line_height = area.x(), area.y(), 0
        for item in self._items:
            widget = item.widget()
            if widget is not None and widget.isHidden():
                # Explicitly hidden widgets take no room, as in a box layout.
                continue
            hint = item.sizeHint()
            next_x = x + hint.width() + self._spacing
            if next_x - self._spacing > area.right() + 1 and line_height > 0:
                x = area.x()
                y += line_height + self._spacing
                next_x = x + hint.width() + self._spacing
                line_height = 0
            if apply:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x = next_x
            line_height = max(line_height, hint.height())
        return y + line_height - rect.y() + margins.bottom()


def flow_row(*widgets: QWidget, spacing: int = 6) -> QWidget:
    """A holder widget whose children wrap. Height follows width."""
    holder = QWidget()
    layout = FlowLayout(holder, spacing=spacing)
    for widget in widgets:
        layout.addWidget(widget)
    policy = holder.sizePolicy()
    policy.setHeightForWidth(True)
    policy.setHorizontalPolicy(QSizePolicy.Policy.Preferred)
    holder.setSizePolicy(policy)
    return holder
