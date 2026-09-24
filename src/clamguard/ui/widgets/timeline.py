"""Two charts for the Boot Analyzer: a phase bar and a ranked bar list.

Both paint themselves, so neither can be styled by the stylesheet — they take
the palette through ``apply_palette()`` like ProgressRing and ToggleSwitch, and
the page emits ``theme_refresh_requested`` after building them.

They are here rather than in the boot page because they are generic: a stacked
proportion bar and a horizontal ranked bar chart are useful anywhere, and
keeping them out of the page keeps the page about layout.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from ..theme import ACCENTS, DARK, DEFAULT_ACCENT, Palette, mix


@dataclass(frozen=True)
class Segment:
    """One slice of a StackedBar."""

    label: str
    value: float
    #: A #rrggbb colour, or "" to take one from the default sequence.
    colour: str = ""
    #: What to show instead of the raw number — "1m 32s" rather than "91.9".
    text: str = ""

    def caption(self) -> str:
        return self.text or f"{self.value:g}"


#: The phase colours, chosen to run cool → warm in boot order so the bar reads
#: left to right as "time passing" even before you read the legend.
DEFAULT_SEQUENCE = ("#8b5cf6", "#3b82f6", "#14b8a6", "#f59e0b", "#22a55a",
                    "#e11d48", "#6366f1", "#0ea5e9")


class StackedBar(QWidget):
    """A single horizontal bar split into proportional, labelled segments.

    ::

        bar.set_segments([Segment("firmware", 24.3, text="24.3s"), ...])

    Segments too narrow to hold their own label are still drawn — the legend
    below carries the names — because dropping them would misrepresent the
    total.
    """

    #: A segment was clicked, by label.
    activated = Signal(str)

    BAR_HEIGHT = 30
    LEGEND_HEIGHT = 22
    GAP = 2

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._segments: list[Segment] = []
        self._palette: Palette = DARK
        self._accent = ACCENTS[DEFAULT_ACCENT][0]
        self._hovered = -1
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(self.BAR_HEIGHT + self.LEGEND_HEIGHT + 6)

    def apply_palette(self, palette: Palette, accent_name: str) -> None:
        self._palette = palette
        self._accent = ACCENTS.get(accent_name, ACCENTS[DEFAULT_ACCENT])[0]
        self.update()

    def set_segments(self, segments) -> None:
        self._segments = [item for item in segments if item.value > 0]
        self.setVisible(bool(self._segments))
        self.update()

    @property
    def total(self) -> float:
        return sum(item.value for item in self._segments)

    def _colour(self, index: int, segment: Segment) -> QColor:
        return QColor(segment.colour or DEFAULT_SEQUENCE[index % len(DEFAULT_SEQUENCE)])

    def _rects(self) -> list[tuple[Segment, QRectF, int]]:
        total = self.total
        if total <= 0:
            return []
        width = self.width()
        gaps = self.GAP * max(0, len(self._segments) - 1)
        usable = max(1.0, width - gaps)
        placed: list[tuple[Segment, QRectF, int]] = []
        x = 0.0
        for index, segment in enumerate(self._segments):
            # Every segment gets at least three pixels, or a 40ms phase beside
            # a two-minute one would vanish and the bar would lie about the total.
            span = max(3.0, usable * segment.value / total)
            placed.append((segment, QRectF(x, 0, span, self.BAR_HEIGHT), index))
            x += span + self.GAP
        return placed

    # -- interaction ------------------------------------------------------

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt naming
        position = event.position()
        found = -1
        if position.y() <= self.BAR_HEIGHT:
            for segment, box, index in self._rects():
                if box.contains(position.x(), position.y()):
                    found = index
                    self.setToolTip(f"{segment.label}: {segment.caption()}")
                    break
        if found == -1:
            self.setToolTip("")
        if found != self._hovered:
            self._hovered = found
            self.update()

    def leaveEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._hovered = -1
        self.setToolTip("")
        self.update()
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt naming
        for segment, box, _index in self._rects():
            if box.contains(event.position().x(), event.position().y()):
                self.activated.emit(segment.label)
                return

    # -- painting ---------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt naming
        if not self._segments:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)

        label_font = QFont(self.font())
        label_font.setPointSizeF(max(7.0, self.font().pointSizeF() - 1.5))
        metrics = QFontMetrics(label_font)

        for segment, box, index in self._rects():
            colour = self._colour(index, segment)
            if index == self._hovered:
                colour = QColor(mix(colour.name(), "#ffffff", 0.25))
            painter.setBrush(colour)
            painter.drawRoundedRect(box, 4, 4)

            text = segment.caption()
            if box.width() > metrics.horizontalAdvance(text) + 12:
                painter.setFont(label_font)
                painter.setPen(QColor("#ffffff"))
                painter.drawText(box, int(Qt.AlignmentFlag.AlignCenter), text)
                painter.setPen(Qt.PenStyle.NoPen)

        self._paint_legend(painter, label_font, metrics)
        painter.end()

    def _paint_legend(self, painter: QPainter, font: QFont,
                      metrics: QFontMetrics) -> None:
        painter.setFont(font)
        y = self.BAR_HEIGHT + 6
        x = 0.0
        for index, segment in enumerate(self._segments):
            swatch = QRectF(x, y + 5, 8, 8)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(self._colour(index, segment))
            painter.drawRoundedRect(swatch, 2, 2)

            text = f"{segment.label} {segment.caption()}"
            painter.setPen(QColor(self._palette.text_dim))
            painter.drawText(QRectF(x + 12, y, metrics.horizontalAdvance(text) + 4,
                                    self.LEGEND_HEIGHT),
                             int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                             text)
            x += 12 + metrics.horizontalAdvance(text) + 16
            if x > self.width() - 40:
                break


@dataclass(frozen=True)
class Bar:
    """One row of a BarList."""

    label: str
    value: float
    text: str = ""
    #: "ok" | "warn" | "danger" | "info" | "" for the accent colour.
    tone: str = ""

    def caption(self) -> str:
        return self.text or f"{self.value:g}"


class BarList(QWidget):
    """A ranked horizontal bar chart: the slowest units, the worst scores.

    Sized to its content, so it drops straight into a card's layout without a
    scroll area. Rows are drawn longest-first by the caller, not sorted here —
    the caller knows what order means.
    """

    #: A row was clicked, by label.
    activated = Signal(str)

    ROW_HEIGHT = 26
    LABEL_WIDTH = 260
    VALUE_WIDTH = 74

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._bars: list[Bar] = []
        self._palette: Palette = DARK
        self._accent = ACCENTS[DEFAULT_ACCENT][0]
        self._hovered = -1
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def apply_palette(self, palette: Palette, accent_name: str) -> None:
        self._palette = palette
        self._accent = ACCENTS.get(accent_name, ACCENTS[DEFAULT_ACCENT])[0]
        self.update()

    def set_bars(self, bars) -> None:
        self._bars = list(bars)
        self.setFixedHeight(max(1, len(self._bars) * self.ROW_HEIGHT))
        self.setVisible(bool(self._bars))
        self.update()

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt naming
        return QSize(520, max(1, len(self._bars) * self.ROW_HEIGHT))

    def _tone_colour(self, tone: str) -> QColor:
        return QColor({
            "ok": self._palette.ok,
            "warn": self._palette.warn,
            "danger": self._palette.danger,
            "info": self._palette.info,
        }.get(tone, self._accent))

    def _row_at(self, y: float) -> int:
        index = int(y // self.ROW_HEIGHT)
        return index if 0 <= index < len(self._bars) else -1

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt naming
        index = self._row_at(event.position().y())
        if index != self._hovered:
            self._hovered = index
            self.setToolTip(self._bars[index].label if index >= 0 else "")
            self.update()

    def leaveEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._hovered = -1
        self.update()
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt naming
        index = self._row_at(event.position().y())
        if index >= 0:
            self.activated.emit(self._bars[index].label)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt naming
        if not self._bars:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        font = QFont(self.font())
        font.setPointSizeF(max(7.5, self.font().pointSizeF() - 1))
        painter.setFont(font)
        metrics = QFontMetrics(font)

        biggest = max((bar.value for bar in self._bars), default=1.0) or 1.0
        label_width = min(self.LABEL_WIDTH, max(120, self.width() // 3))
        track_left = label_width + 10
        track_width = max(20, self.width() - track_left - self.VALUE_WIDTH)

        for index, bar in enumerate(self._bars):
            top = index * self.ROW_HEIGHT
            if index == self._hovered:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(QColor(self._palette.surface_2))
                painter.drawRoundedRect(QRectF(0, top, self.width(), self.ROW_HEIGHT),
                                        5, 5)

            painter.setPen(QPen(QColor(self._palette.text_dim)))
            painter.drawText(
                QRectF(2, top, label_width, self.ROW_HEIGHT),
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                metrics.elidedText(bar.label, Qt.TextElideMode.ElideMiddle,
                                   int(label_width) - 6))

            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(self._palette.surface_3))
            painter.drawRoundedRect(
                QRectF(track_left, top + 9, track_width, self.ROW_HEIGHT - 18), 3, 3)

            filled = max(3.0, track_width * (bar.value / biggest))
            painter.setBrush(self._tone_colour(bar.tone))
            painter.drawRoundedRect(
                QRectF(track_left, top + 9, filled, self.ROW_HEIGHT - 18), 3, 3)

            painter.setPen(QPen(QColor(self._palette.text)))
            painter.drawText(
                QRectF(self.width() - self.VALUE_WIDTH, top,
                       self.VALUE_WIDTH - 4, self.ROW_HEIGHT),
                int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter),
                bar.caption())
        painter.end()
