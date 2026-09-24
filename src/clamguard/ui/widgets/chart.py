"""Charts for the `render` operator, painted rather than pulled in.

Qt Charts is installed on this machine, but drawing these by hand costs about
four hundred lines and buys three things worth having: the charts match the
application's palette exactly, they have no dependency that a user installing
ClamGuard has to also have, and the hover behaviour can be the one this page
wants rather than the one a general-purpose library offers.

The data contract is Kusto's. The first column is the x axis — a time for a
timechart, a label for everything else — and every numeric column after it is
a series. A third column that is not numeric is read as a series *name*, which
is what makes ``summarize count() by App, bin(Timestamp, 1h)`` draw one line
per application.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from PySide6.QtCore import QPoint, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QPainter,
    QPainterPath,
    QPen,
    QPolygonF,
)
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from ...core.hunt.model import (
    ColumnType,
    ResultTable,
    humanise_count,
    format_timestamp,
)
from ..theme import Palette

#: The charts `render` can ask for.
KINDS = ("timechart", "linechart", "areachart", "stackedareachart",
         "columnchart", "barchart", "piechart", "scatterchart", "card",
         "anomalychart", "table")

#: Series colours, in order. Chosen to stay distinguishable in both themes
#: and to survive the common forms of colour blindness.
SERIES_COLOURS = (
    "#4c9aff", "#2ed47a", "#ffb020", "#ff5c5c", "#c792ea", "#00bcd4",
    "#f78c6c", "#8bc34a", "#e91e63", "#7986cb", "#ffd54f", "#4db6ac",
)

#: More points than this on one line are averaged down: a chart 900 pixels
#: wide cannot show 50,000 of them and painting them all is what makes a
#: chart widget feel slow.
MAX_POINTS = 2000


@dataclass(slots=True)
class Series:
    """One line, bar set or slice group."""

    name: str
    points: list[tuple[float, float]] = field(default_factory=list)
    colour: str = SERIES_COLOURS[0]
    #: Labels for a category axis, parallel to `points`.
    labels: list[str] = field(default_factory=list)

    @property
    def total(self) -> float:
        return sum(value for _x, value in self.points)


class Chart(QWidget):
    """One chart. Call :meth:`set_table` with a result and a kind."""

    #: A point was clicked: (series name, x label, value).
    point_clicked = Signal(str, str, float)

    MARGIN_LEFT = 62
    MARGIN_RIGHT = 16
    MARGIN_TOP = 14
    MARGIN_BOTTOM = 46
    LEGEND_HEIGHT = 26

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("huntChart")
        self.setMinimumHeight(220)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMouseTracking(True)

        self._kind = "columnchart"
        self._series: list[Series] = []
        self._x_labels: list[str] = []
        self._x_is_time = False
        self._title = ""
        self._y_title = ""
        self._message = "Add `| render timechart` to a query to draw it here."
        self._hover = -1
        self._hover_series = -1

        self._text = QColor("#e8ecf4")
        self._dim = QColor("#97a1b2")
        self._faint = QColor("#6b7688")
        self._grid = QColor(255, 255, 255, 22)
        self._surface = QColor("#171b24")
        self._accent = QColor("#3b82f6")

    # -- theme ------------------------------------------------------------

    def apply_palette(self, palette: Palette, accent: str) -> None:
        self._text = QColor(palette.text)
        self._dim = QColor(palette.text_dim)
        self._faint = QColor(palette.text_faint)
        self._surface = QColor(palette.surface)
        self._grid = QColor(palette.border)
        self._accent = QColor(accent)
        self.update()

    # -- data -------------------------------------------------------------

    def clear(self, message: str = "") -> None:
        self._series = []
        self._x_labels = []
        self._message = message or "Nothing to draw."
        self.update()

    @property
    def kind(self) -> str:
        return self._kind

    def set_table(self, table: ResultTable, kind: str = "",
                  properties: dict | None = None) -> None:
        """Read a result into series, following Kusto's column conventions."""
        properties = properties or {}
        self._kind = kind if kind in KINDS else "columnchart"
        self._title = str(properties.get("title") or "")
        self._y_title = str(properties.get("ytitle") or "")
        self._hover = -1

        if not table.columns or not table.rows:
            self.clear("The query returned no rows, so there is nothing to draw.")
            return

        numeric = [position for position, column in enumerate(table.columns)
                   if column.type.is_numeric]
        if not numeric:
            self.clear("A chart needs a number. Add a `summarize` with "
                       "count(), sum() or avg().")
            return

        x_position = _x_axis(table, numeric)
        self._x_is_time = (x_position >= 0
                           and table.columns[x_position].type is ColumnType.DATETIME)
        splitter = self._split_column(table, x_position, numeric)

        if splitter is not None:
            self._series = self._split_series(table, x_position, numeric[0], splitter)
        else:
            self._series = self._plain_series(table, x_position, numeric)

        for index, series in enumerate(self._series):
            series.colour = SERIES_COLOURS[index % len(SERIES_COLOURS)]
        self._message = "" if self._series else "Nothing to draw."
        self.update()

    def _split_column(self, table: ResultTable, x_position: int,
                      numeric: list[int]) -> int | None:
        """A second non-numeric column names the series, as Kusto does."""
        if len(numeric) != 1:
            return None
        for position, column in enumerate(table.columns):
            if position != x_position and position not in numeric \
                    and column.type is not ColumnType.DYNAMIC:
                return position
        return None

    def _plain_series(self, table: ResultTable, x_position: int,
                      numeric: list[int]) -> list[Series]:
        labels: list[str] = []
        series = [Series(table.columns[position].name) for position in numeric]
        for index, row in enumerate(table.rows[:MAX_POINTS * 4]):
            x_value = self._x_of(row, x_position, index)
            labels.append(self._label_of(row, x_position, index))
            for slot, position in enumerate(numeric):
                value = row[position] if position < len(row) else None
                series[slot].points.append((x_value, _number(value)))
        self._x_labels = labels
        for item in series:
            item.labels = labels
        return [item for item in series if item.points]

    def _split_series(self, table: ResultTable, x_position: int,
                      value_position: int, split_position: int) -> list[Series]:
        grouped: dict[str, Series] = {}
        labels: dict[float, str] = {}
        for index, row in enumerate(table.rows[:MAX_POINTS * 8]):
            name = str(row[split_position]) if split_position < len(row) else ""
            x_value = self._x_of(row, x_position, index)
            labels[x_value] = self._label_of(row, x_position, index)
            series = grouped.get(name)
            if series is None:
                series = Series(name or "(none)")
                grouped[name] = series
            series.points.append(
                (x_value, _number(row[value_position]
                                  if value_position < len(row) else None)))
        self._x_labels = [labels[key] for key in sorted(labels)]
        ordered = sorted(grouped.values(), key=lambda item: -item.total)
        for item in ordered:
            item.points.sort(key=lambda point: point[0])
        return ordered[:12]

    def _x_of(self, row: Sequence, position: int, index: int) -> float:
        if position < 0 or position >= len(row):
            return float(index)
        value = row[position]
        if isinstance(value, datetime):
            return value.timestamp()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        return float(index)

    def _label_of(self, row: Sequence, position: int, index: int) -> str:
        if position < 0 or position >= len(row):
            return str(index)
        value = row[position]
        if isinstance(value, datetime):
            return format_timestamp(value, precision=0)
        if value is None:
            return "(none)"
        return str(value)

    # -- painting ---------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)

        if not self._series:
            painter.setPen(self._faint)
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self._message)
            painter.end()
            return

        if self._kind == "piechart":
            self._paint_pie(painter)
        elif self._kind == "card":
            self._paint_card(painter)
        elif self._kind == "barchart":
            self._paint_bars(painter, horizontal=True)
        elif self._kind == "columnchart":
            self._paint_bars(painter, horizontal=False)
        else:
            self._paint_lines(painter)

        self._paint_legend(painter)
        if self._title:
            painter.setPen(self._text)
            font = QFont(self.font())
            font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(font)
            painter.drawText(QRectF(self.MARGIN_LEFT, 0, self.width(), self.MARGIN_TOP),
                             Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                             self._title)
        painter.end()

    def _plot_area(self) -> QRectF:
        legend = self.LEGEND_HEIGHT if len(self._series) > 1 else 0
        top = self.MARGIN_TOP + (12 if self._title else 0)
        return QRectF(self.MARGIN_LEFT, top,
                      max(10.0, self.width() - self.MARGIN_LEFT - self.MARGIN_RIGHT),
                      max(10.0, self.height() - top - self.MARGIN_BOTTOM - legend))

    def _bounds(self) -> tuple[float, float, float, float]:
        xs = [x for series in self._series for x, _y in series.points]
        ys = [y for series in self._series for _x, y in series.points]
        if not xs:
            return 0.0, 1.0, 0.0, 1.0
        low_y = min(0.0, min(ys))
        high_y = max(ys) if ys else 1.0
        if high_y == low_y:
            high_y = low_y + 1
        return min(xs), max(xs), low_y, high_y

    def _paint_lines(self, painter: QPainter) -> None:
        area = self._plot_area()
        x_min, x_max, y_min, y_max = self._bounds()
        ticks = _nice_ticks(y_min, y_max, 5)
        self._paint_grid(painter, area, ticks, y_min, y_max)
        self._paint_x_axis(painter, area, x_min, x_max)

        filled = self._kind in ("areachart", "stackedareachart")
        scatter = self._kind == "scatterchart"

        for series in self._series:
            points = _downsample(series.points, int(area.width()))
            if not points:
                continue
            polygon = QPolygonF([
                QPointF(_map(x, x_min, x_max, area.left(), area.right()),
                        _map(value, y_min, y_max, area.bottom(), area.top()))
                for x, value in points])
            colour = QColor(series.colour)

            if filled:
                path = QPainterPath(polygon[0])
                for point in list(polygon)[1:]:
                    path.lineTo(point)
                path.lineTo(polygon[-1].x(), area.bottom())
                path.lineTo(polygon[0].x(), area.bottom())
                path.closeSubpath()
                fill = QColor(colour)
                fill.setAlpha(60)
                painter.fillPath(path, fill)

            if scatter:
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(colour)
                for point in polygon:
                    painter.drawEllipse(point, 3.0, 3.0)
            else:
                painter.setBrush(Qt.BrushStyle.NoBrush)
                painter.setPen(QPen(colour, 1.8, Qt.PenStyle.SolidLine,
                                    Qt.PenCapStyle.RoundCap,
                                    Qt.PenJoinStyle.RoundJoin))
                painter.drawPolyline(polygon)
                if len(polygon) <= 60:
                    painter.setBrush(colour)
                    painter.setPen(Qt.PenStyle.NoPen)
                    for point in polygon:
                        painter.drawEllipse(point, 2.4, 2.4)

        self._paint_crosshair(painter, area, x_min, x_max, y_min, y_max)

    def _paint_bars(self, painter: QPainter, *, horizontal: bool) -> None:
        area = self._plot_area()
        series = self._series
        categories = max(len(item.points) for item in series)
        if not categories:
            return
        _x_min, _x_max, y_min, y_max = self._bounds()
        ticks = _nice_ticks(y_min, y_max, 5)

        if horizontal:
            self._paint_value_axis_horizontal(painter, area, ticks, y_min, y_max)
        else:
            self._paint_grid(painter, area, ticks, y_min, y_max)

        span = (area.height() if horizontal else area.width()) / categories
        group = max(2.0, span * 0.74)
        each = group / max(1, len(series))

        metrics = QFontMetrics(self.font())
        for index in range(categories):
            base = (area.top() if horizontal else area.left()) + index * span \
                + (span - group) / 2
            for slot, item in enumerate(series):
                if index >= len(item.points):
                    continue
                value = item.points[index][1]
                colour = QColor(item.colour)
                if self._hover == index:
                    colour = colour.lighter(125)
                if horizontal:
                    length = _map(value, y_min, y_max, 0, area.width())
                    painter.fillRect(
                        QRectF(area.left(), base + slot * each, max(1.0, length),
                               max(1.0, each - 1.5)), colour)
                else:
                    length = _map(value, y_min, y_max, 0, area.height())
                    painter.fillRect(
                        QRectF(base + slot * each, area.bottom() - length,
                               max(1.0, each - 1.5), max(1.0, length)), colour)

        painter.setPen(self._faint)
        step = max(1, categories // (12 if not horizontal else 20))
        for index in range(0, categories, step):
            label = self._x_labels[index] if index < len(self._x_labels) else ""
            if horizontal:
                box = QRectF(0, area.top() + index * span, self.MARGIN_LEFT - 8, span)
                painter.drawText(box, int(Qt.AlignmentFlag.AlignRight
                                          | Qt.AlignmentFlag.AlignVCenter),
                                 metrics.elidedText(label, Qt.TextElideMode.ElideRight,
                                                    int(box.width())))
            else:
                box = QRectF(area.left() + index * span - span, area.bottom() + 6,
                             span * 3, 18)
                painter.drawText(box, int(Qt.AlignmentFlag.AlignHCenter
                                          | Qt.AlignmentFlag.AlignTop),
                                 metrics.elidedText(label, Qt.TextElideMode.ElideRight,
                                                    int(box.width())))

    def _paint_pie(self, painter: QPainter) -> None:
        area = self._plot_area()
        series = self._series[0]
        total = sum(abs(value) for _x, value in series.points) or 1.0
        diameter = min(area.width(), area.height()) - 16
        box = QRectF(area.center().x() - diameter / 2,
                     area.center().y() - diameter / 2, diameter, diameter)
        start = 90 * 16
        painter.setPen(QPen(self._surface, 1.5))
        for index, (_x, value) in enumerate(series.points[:16]):
            sweep = -int(abs(value) / total * 360 * 16)
            colour = QColor(SERIES_COLOURS[index % len(SERIES_COLOURS)])
            if self._hover == index:
                colour = colour.lighter(120)
            painter.setBrush(colour)
            painter.drawPie(box, start, sweep)
            start += sweep

        painter.setPen(self._dim)
        metrics = QFontMetrics(self.font())
        line = area.top()
        for index, (_x, value) in enumerate(series.points[:16]):
            label = self._x_labels[index] if index < len(self._x_labels) else ""
            painter.setBrush(QColor(SERIES_COLOURS[index % len(SERIES_COLOURS)]))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRect(QRectF(area.right() - 168, line + 4, 9, 9))
            painter.setPen(self._dim)
            share = abs(value) / total * 100
            painter.drawText(
                QRectF(area.right() - 152, line, 152, 18),
                int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                metrics.elidedText(f"{label} — {share:.0f}%",
                                   Qt.TextElideMode.ElideRight, 150))
            line += 18
            if line > area.bottom() - 18:
                break

    def _paint_card(self, painter: QPainter) -> None:
        series = self._series[0]
        value = series.points[0][1] if series.points else 0
        painter.setPen(self._text)
        font = QFont(self.font())
        font.setPointSizeF(max(22.0, self.height() / 5))
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.drawText(self.rect().adjusted(0, -14, 0, -14),
                         Qt.AlignmentFlag.AlignCenter, f"{value:,.0f}")
        painter.setFont(self.font())
        painter.setPen(self._dim)
        painter.drawText(self.rect().adjusted(0, int(self.height() / 3), 0, 0),
                         Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                         series.name)

    def _paint_grid(self, painter: QPainter, area: QRectF, ticks: list[float],
                    y_min: float, y_max: float) -> None:
        painter.setPen(QPen(self._grid, 1, Qt.PenStyle.SolidLine))
        for value in ticks:
            y = _map(value, y_min, y_max, area.bottom(), area.top())
            painter.setPen(QPen(self._grid, 1))
            painter.drawLine(QPointF(area.left(), y), QPointF(area.right(), y))
            painter.setPen(self._faint)
            painter.drawText(QRectF(0, y - 9, self.MARGIN_LEFT - 8, 18),
                             int(Qt.AlignmentFlag.AlignRight
                                 | Qt.AlignmentFlag.AlignVCenter),
                             humanise_count(int(value)) if abs(value) >= 1000
                             else _tidy(value))
        if self._y_title:
            painter.setPen(self._faint)
            painter.drawText(QRectF(0, area.top() - 18, self.MARGIN_LEFT + 40, 16),
                             int(Qt.AlignmentFlag.AlignLeft), self._y_title)

    def _paint_value_axis_horizontal(self, painter: QPainter, area: QRectF,
                                     ticks: list[float], y_min: float,
                                     y_max: float) -> None:
        for value in ticks:
            x = _map(value, y_min, y_max, area.left(), area.right())
            painter.setPen(QPen(self._grid, 1))
            painter.drawLine(QPointF(x, area.top()), QPointF(x, area.bottom()))
            painter.setPen(self._faint)
            painter.drawText(QRectF(x - 40, area.bottom() + 4, 80, 18),
                             int(Qt.AlignmentFlag.AlignHCenter),
                             humanise_count(int(value)) if abs(value) >= 1000
                             else _tidy(value))

    def _paint_x_axis(self, painter: QPainter, area: QRectF, x_min: float,
                      x_max: float) -> None:
        painter.setPen(self._faint)
        count = 6
        for index in range(count + 1):
            fraction = index / count
            x = area.left() + fraction * area.width()
            value = x_min + fraction * (x_max - x_min)
            label = (_time_label(value, x_max - x_min) if self._x_is_time
                     else _tidy(value))
            painter.drawText(QRectF(x - 60, area.bottom() + 6, 120, 18),
                             int(Qt.AlignmentFlag.AlignHCenter
                                 | Qt.AlignmentFlag.AlignTop), label)

    def _paint_legend(self, painter: QPainter) -> None:
        if len(self._series) < 2:
            return
        metrics = QFontMetrics(self.font())
        x = self.MARGIN_LEFT
        y = self.height() - self.LEGEND_HEIGHT + 4
        for series in self._series:
            label = metrics.elidedText(series.name, Qt.TextElideMode.ElideRight, 150)
            width = metrics.horizontalAdvance(label) + 26
            if x + width > self.width() - 8:
                break
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(series.colour))
            painter.drawRect(QRectF(x, y + 5, 9, 9))
            painter.setPen(self._dim)
            painter.drawText(QRectF(x + 15, y, width, 18),
                             int(Qt.AlignmentFlag.AlignLeft
                                 | Qt.AlignmentFlag.AlignVCenter), label)
            x += width

    def _paint_crosshair(self, painter: QPainter, area: QRectF, x_min: float,
                         x_max: float, y_min: float, y_max: float) -> None:
        if self._hover < 0 or not self._series:
            return
        series = self._series[max(0, self._hover_series)]
        if self._hover >= len(series.points):
            return
        x_value, value = series.points[self._hover]
        x = _map(x_value, x_min, x_max, area.left(), area.right())
        painter.setPen(QPen(self._accent, 1, Qt.PenStyle.DashLine))
        painter.drawLine(QPointF(x, area.top()), QPointF(x, area.bottom()))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(self._accent)
        painter.drawEllipse(
            QPointF(x, _map(value, y_min, y_max, area.bottom(), area.top())), 4, 4)

    # -- interaction ------------------------------------------------------

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if not self._series:
            return
        area = self._plot_area()
        position = event.position()
        if not area.adjusted(-4, -4, 4, 4).contains(position):
            if self._hover != -1:
                self._hover = -1
                self.update()
            return

        if self._kind in ("columnchart", "barchart", "piechart"):
            categories = max(len(item.points) for item in self._series)
            if self._kind == "barchart":
                index = int((position.y() - area.top()) / max(1.0, area.height())
                            * categories)
            else:
                index = int((position.x() - area.left()) / max(1.0, area.width())
                            * categories)
            index = max(0, min(categories - 1, index))
            series_index = 0
        else:
            x_min, x_max, _y_min, _y_max = self._bounds()
            wanted = x_min + (position.x() - area.left()) / max(1.0, area.width()) \
                * (x_max - x_min)
            index, series_index = self._nearest(wanted, position, area)

        if index != self._hover or series_index != self._hover_series:
            self._hover = index
            self._hover_series = series_index
            self.update()
        self._show_tooltip(event.globalPosition().toPoint(), index, series_index)

    def _nearest(self, wanted: float, position: QPointF,
                 area: QRectF) -> tuple[int, int]:
        best = (0, 0)
        closest = None
        for slot, series in enumerate(self._series):
            for index, (x_value, _value) in enumerate(series.points):
                distance = abs(x_value - wanted)
                if closest is None or distance < closest:
                    closest = distance
                    best = (index, slot)
        return best

    def _show_tooltip(self, where: QPoint, index: int, series_index: int) -> None:
        label = self._x_labels[index] if index < len(self._x_labels) else ""
        lines = [label] if label else []
        for series in self._series[:8]:
            if index < len(series.points):
                lines.append(f"{series.name}: {series.points[index][1]:,.0f}")
        if lines:
            QToolTip.showText(where, "\n".join(lines), self)

    def leaveEvent(self, _event) -> None:  # noqa: N802 - Qt naming
        self._hover = -1
        self.update()

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if self._hover < 0 or not self._series:
            return
        series = self._series[max(0, self._hover_series)]
        if self._hover < len(series.points):
            label = (self._x_labels[self._hover]
                     if self._hover < len(self._x_labels) else "")
            self.point_clicked.emit(series.name, label,
                                    series.points[self._hover][1])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _x_axis(table: ResultTable, numeric: list[int]) -> int:
    """Which column goes along the bottom.

    A time column wins whenever there is one, whatever order the columns came
    out in. ``summarize count() by App, bin(Timestamp, 1h)`` puts App first,
    and reading that literally draws applications along the x axis with one
    series per hour — which is technically what was asked for and never what
    was meant.
    """
    for position, column in enumerate(table.columns):
        if position not in numeric and column.type is ColumnType.DATETIME:
            return position
    for position, _column in enumerate(table.columns):
        if position not in numeric:
            return position
    return -1


def _number(value: Any) -> float:
    if isinstance(value, bool) or value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, timedelta):
        return value.total_seconds()
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _map(value: float, low: float, high: float, start: float, end: float) -> float:
    if high == low:
        return start
    return start + (value - low) / (high - low) * (end - start)


def _nice_ticks(low: float, high: float, count: int) -> list[float]:
    """Round axis values a person would have chosen."""
    if high <= low:
        return [low, low + 1]
    span = high - low
    raw = span / max(1, count)
    magnitude = 10 ** math.floor(math.log10(raw)) if raw > 0 else 1
    for multiple in (1, 2, 2.5, 5, 10):
        step = magnitude * multiple
        if raw <= step:
            break
    start = math.floor(low / step) * step
    ticks = []
    value = start
    while value <= high + step * 0.5 and len(ticks) < 20:
        ticks.append(value)
        value += step
    return ticks


def _downsample(points: list[tuple[float, float]], width: int
                ) -> list[tuple[float, float]]:
    """Average a long series down to roughly one point per pixel.

    Drawing fifty thousand points into nine hundred pixels wastes the time and
    hides the shape; averaging keeps the shape and makes the chart instant.
    """
    limit = max(64, min(MAX_POINTS, width * 2))
    if len(points) <= limit:
        return points
    bucket = len(points) / limit
    reduced: list[tuple[float, float]] = []
    for index in range(limit):
        start = int(index * bucket)
        end = max(start + 1, int((index + 1) * bucket))
        slice_ = points[start:end]
        reduced.append((slice_[0][0],
                        sum(value for _x, value in slice_) / len(slice_)))
    return reduced


def _tidy(value: float) -> str:
    if abs(value) >= 1000:
        return f"{value:,.0f}"
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}".rstrip("0").rstrip(".")


def _time_label(stamp: float, span: float) -> str:
    """An axis label at a resolution that suits the range being shown."""
    try:
        moment = datetime.fromtimestamp(stamp, tz=timezone.utc).astimezone()
    except (ValueError, OverflowError, OSError):
        return ""
    if span <= 7200:
        return moment.strftime("%H:%M:%S")
    if span <= 172800:
        return moment.strftime("%d %b %H:%M")
    if span <= 31536000:
        return moment.strftime("%d %b")
    return moment.strftime("%b %Y")
