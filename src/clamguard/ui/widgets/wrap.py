"""A label that wraps at word boundaries, and anywhere at all if it must.

QLabel's word wrap breaks only where Unicode allows a line break: spaces,
hyphens, slashes. systemd escapes the hyphens *inside* a name component, so a
device unit is called

    dev-disk-by\\x2dpartuuid-5fdd951e\\x2d3973\\x2d4d18\\x2d8670\\x2d8ab69ea1e657.device

and its last fifty characters contain no break opportunity at all. As a panel
title that one run was 600px of minimum width; measured across a real
machine, titles like it were 93 of the 106 units whose detail pane overflowed.

This paints with QTextLayout and WrapAtWordBoundaryOrAnywhere, so ordinary
text still breaks between words and only an unbreakable run is split.

Why not insert zero-width spaces into an ordinary QLabel instead: because a
selectable label copies them. A unit name pasted into a terminal with an
invisible character inside it names a unit that does not exist, and nothing on
screen says why. This label is not selectable; offer the exact text through a
copy button where copying matters.
"""

from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QSize, Qt
from PySide6.QtGui import QPainter, QTextLayout, QTextOption
from PySide6.QtWidgets import QLabel, QSizePolicy, QWidget


class BreakAnywhereLabel(QLabel):
    """Plain text, wrapped at words where possible and anywhere where not.

    Subclasses QLabel so every ``QLabel[role=…]`` rule in the stylesheet — the
    font size of a title, the colour of a tone — still applies to it.
    """

    #: The narrowest the label will ask to be, in average characters.
    MINIMUM_CHARACTERS = 6

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setWordWrap(True)
        self.setText(text)
        policy = self.sizePolicy()
        policy.setHeightForWidth(True)
        policy.setHorizontalPolicy(QSizePolicy.Policy.Preferred)
        self.setSizePolicy(policy)

    # -- geometry ----------------------------------------------------------

    def _lay_out(self, width: float) -> tuple[QTextLayout, float]:
        layout = QTextLayout(self.text(), self.font())
        option = QTextOption()
        option.setWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        layout.setTextOption(option)
        layout.beginLayout()
        height = 0.0
        while True:
            line = layout.createLine()
            if not line.isValid():
                break
            line.setLineWidth(max(1.0, width))
            line.setPosition(QPointF(0.0, height))
            height += line.height()
        layout.endLayout()
        return layout, height

    def _horizontal_margins(self) -> int:
        margins = self.contentsMargins()
        return margins.left() + margins.right() + 2 * self.margin()

    def _vertical_margins(self) -> int:
        margins = self.contentsMargins()
        return margins.top() + margins.bottom() + 2 * self.margin()

    def hasHeightForWidth(self) -> bool:  # noqa: N802 - Qt API
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802
        _layout, height = self._lay_out(width - self._horizontal_margins())
        return math.ceil(height) + self._vertical_margins()

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        metrics = self.fontMetrics()
        width = metrics.averageCharWidth() * self.MINIMUM_CHARACTERS + self._horizontal_margins()
        return QSize(width, metrics.height() + self._vertical_margins())

    def sizeHint(self) -> QSize:  # noqa: N802
        natural = self.fontMetrics().horizontalAdvance(self.text()) + self._horizontal_margins()
        return QSize(natural, self.heightForWidth(natural))

    # -- painting ----------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802
        area = self.contentsRect().adjusted(self.margin(), self.margin(),
                                            -self.margin(), -self.margin())
        layout, _height = self._lay_out(area.width())
        painter = QPainter(self)
        painter.setPen(self.palette().color(self.foregroundRole()))
        layout.draw(painter, QPointF(area.topLeft()))
        painter.end()


def break_anywhere_label(text: str = "", *, role: str = "body",
                         tone: str = "") -> BreakAnywhereLabel:
    """The BreakAnywhereLabel counterpart of `label()`: same role and tone."""
    item = BreakAnywhereLabel(text)
    item.setProperty("role", role)
    if tone:
        item.setProperty("tone", tone)
    return item
