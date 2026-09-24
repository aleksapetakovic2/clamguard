"""The results table: a hundred thousand rows, none of them a widget.

The reference this is built against shows a chevron on every row that opens
into the full record. Doing that with one widget per row would allocate a
quarter of a million objects for a normal result; doing it with a
``QTreeView`` over a model costs whatever is on screen and nothing else.

The shape of the model is the trick. Each result row is a top-level node, and
its fields are its children — one child per column, each spanning the full
width and painted as ``name  value``. That keeps every row the same height, so
``setUniformRowHeights`` can stay on, which is the difference between
scrolling a hundred thousand rows smoothly and not.

Cells are painted, not formatted into HTML. Every value here came out of a log
file written by something else, so nothing is ever interpreted as markup.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from PySide6.QtCore import (
    QAbstractItemModel,
    QModelIndex,
    QPoint,
    QRect,
    QSize,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QFontMetrics, QGuiApplication, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QMenu,
    QStyle,
    QStyledItemDelegate,
    QTreeView,
    QWidget,
)

from ...core.hunt.model import (
    ColumnType,
    Level,
    ResultTable,
    format_timespan,
    format_timestamp,
)
from ..theme import MONO_FONT_STACK, Palette, pick_font

#: Extra roles the delegate reads.
FIELD_ROLE = Qt.ItemDataRole.UserRole + 1
RAW_ROLE = Qt.ItemDataRole.UserRole + 2
LEVEL_ROLE = Qt.ItemDataRole.UserRole + 3

#: How wide the field-name column is inside an expanded row.
NAME_WIDTH = 150

#: Columns wider than this are truncated; the tooltip has the whole value.
MAX_CELL = 600

#: The narrowest a column of each type may be, whatever the sample says.
MIN_WIDTHS = {
    ColumnType.DATETIME: 178,
    ColumnType.TIMESPAN: 110,
    ColumnType.STRING: 80,
    ColumnType.LONG: 90,
    ColumnType.REAL: 90,
    ColumnType.BOOL: 70,
    ColumnType.DYNAMIC: 140,
}


def cell_text(value: Any) -> str:
    """One value as the single line the grid shows."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return format_timestamp(value)
    if isinstance(value, timedelta):
        return format_timespan(value)
    if isinstance(value, float):
        if value.is_integer() and abs(value) < 1e15:
            return f"{int(value):,}"
        return f"{value:,.4f}".rstrip("0").rstrip(".")
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, default=str)[:MAX_CELL]
    text = str(value)
    return text[:MAX_CELL]


def one_line(text: str) -> str:
    """Collapse a multi-line value, saying how much was left out."""
    if "\n" not in text:
        return text
    first, _, rest = text.partition("\n")
    extra = rest.count("\n") + 1
    return f"{first}  ⏎ {extra} more line{'' if extra == 1 else 's'}"


class ResultModel(QAbstractItemModel):
    """A ResultTable as a two-level tree: rows, then their fields."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._table = ResultTable()
        self._names: tuple[str, ...] = ()
        self._numeric: tuple[bool, ...] = ()
        self._level_column = -1

    # -- content ----------------------------------------------------------

    def set_table(self, table: ResultTable) -> None:
        self.beginResetModel()
        self._table = table
        self._names = table.names
        self._numeric = tuple(column.type.is_numeric for column in table.columns)
        self._level_column = table.index_of("Level")
        self.endResetModel()

    @property
    def table(self) -> ResultTable:
        return self._table

    def row_values(self, row: int) -> tuple:
        return self._table.rows[row] if 0 <= row < len(self._table.rows) else ()

    def column_name(self, column: int) -> str:
        return self._names[column] if 0 <= column < len(self._names) else ""

    # -- the tree ---------------------------------------------------------

    def index(self, row: int, column: int,
              parent: QModelIndex = QModelIndex()) -> QModelIndex:
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        if not parent.isValid():
            return self.createIndex(row, column, 0)
        if parent.internalId():
            return QModelIndex()
        return self.createIndex(row, column, parent.row() + 1)

    def parent(self, index: QModelIndex) -> QModelIndex:  # type: ignore[override]
        if not index.isValid():
            return QModelIndex()
        identifier = index.internalId()
        if identifier == 0:
            return QModelIndex()
        return self.createIndex(int(identifier) - 1, 0, 0)

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        if not parent.isValid():
            return len(self._table.rows)
        if parent.internalId() == 0:
            return len(self._names)
        return 0

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return max(1, len(self._names))

    def hasChildren(self, parent: QModelIndex = QModelIndex()) -> bool:  # noqa: N802
        if not parent.isValid():
            return bool(self._table.rows)
        return parent.internalId() == 0 and bool(self._names)

    # -- data -------------------------------------------------------------

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        if index.internalId():
            return self._detail_data(index, role)
        return self._row_data(index, role)

    def _row_data(self, index: QModelIndex, role: int) -> Any:
        row = self.row_values(index.row())
        column = index.column()
        if column >= len(row):
            return None
        value = row[column]

        if role == Qt.ItemDataRole.DisplayRole:
            return one_line(cell_text(value))
        if role == RAW_ROLE:
            return value
        if role == Qt.ItemDataRole.ToolTipRole:
            text = cell_text(value)
            return text if len(text) > 60 or "\n" in text else None
        if role == LEVEL_ROLE and column == self._level_column:
            return Level.parse(value)
        if role == Qt.ItemDataRole.TextAlignmentRole and column < len(self._numeric):
            if self._numeric[column]:
                return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return None

    def _detail_data(self, index: QModelIndex, role: int) -> Any:
        parent_row = int(index.internalId()) - 1
        field = index.row()
        row = self.row_values(parent_row)
        if field >= len(self._names):
            return None
        value = row[field] if field < len(row) else None

        if role == Qt.ItemDataRole.DisplayRole:
            return cell_text(value)
        if role == FIELD_ROLE:
            return self._names[field]
        if role == RAW_ROLE:
            return value
        if role == Qt.ItemDataRole.ToolTipRole:
            return cell_text(value) or None
        return None

    def headerData(self, section: int, orientation: Qt.Orientation,  # noqa: N802
                   role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if orientation is not Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole and section < len(self._names):
            return self._names[section]
        if role == Qt.ItemDataRole.ToolTipRole and section < len(self._table.columns):
            column = self._table.columns[section]
            return f"{column.name}: {column.type.value}\n{column.description}".strip()
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable


class _Delegate(QStyledItemDelegate):
    """Paints the level pill on a row, and the whole of a detail line."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._name_colour = QColor("#97a1b2")
        self._value_colour = QColor("#e8ecf4")
        self._tones: dict[str, QColor] = {}
        self._mono = QFont(pick_font(MONO_FONT_STACK, "monospace"))
        self._mono.setPointSizeF(9.0)

    def apply_palette(self, palette: Palette, accent: str) -> None:
        self._name_colour = QColor(palette.text_dim)
        self._value_colour = QColor(palette.text)
        self._tones = {
            "ok": QColor(palette.ok), "warn": QColor(palette.warn),
            "danger": QColor(palette.danger), "info": QColor(palette.info),
            "muted": QColor(palette.text_dim), "faint": QColor(palette.text_faint),
            "accent": QColor(accent),
        }

    def paint(self, painter: QPainter, option, index: QModelIndex) -> None:
        if index.parent().isValid():
            self._paint_detail(painter, option, index)
            return
        level = index.data(LEVEL_ROLE)
        if isinstance(level, Level):
            self._paint_level(painter, option, index, level)
            return
        super().paint(painter, option, index)

    def _paint_level(self, painter: QPainter, option, index: QModelIndex,
                     level: Level) -> None:
        style = option.widget.style() if option.widget else None
        if style is not None:
            style.drawPrimitive(QStyle.PrimitiveElement.PE_PanelItemViewItem,
                                option, painter, option.widget)
        colour = self._tones.get(level.tone, self._name_colour)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        box = option.rect.adjusted(8, 0, -4, 0)
        radius = 3
        centre = box.top() + box.height() // 2
        painter.setBrush(colour)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(QPoint(box.left() + radius, centre), radius, radius)
        painter.setPen(colour)
        text_box = box.adjusted(radius * 2 + 8, 0, 0, 0)
        painter.drawText(text_box, int(Qt.AlignmentFlag.AlignLeft
                                       | Qt.AlignmentFlag.AlignVCenter),
                         str(index.data(Qt.ItemDataRole.DisplayRole) or ""))
        painter.restore()

    def _paint_detail(self, painter: QPainter, option, index: QModelIndex) -> None:
        style = option.widget.style() if option.widget else None
        if style is not None:
            style.drawPrimitive(QStyle.PrimitiveElement.PE_PanelItemViewItem,
                                option, painter, option.widget)
        name = index.data(FIELD_ROLE) or ""
        value = one_line(str(index.data(Qt.ItemDataRole.DisplayRole) or ""))

        painter.save()
        box = option.rect.adjusted(10, 0, -6, 0)
        metrics = QFontMetrics(option.font)
        painter.setPen(self._name_colour)
        painter.drawText(QRect(box.left(), box.top(), NAME_WIDTH, box.height()),
                         int(Qt.AlignmentFlag.AlignLeft
                             | Qt.AlignmentFlag.AlignVCenter),
                         metrics.elidedText(str(name), Qt.TextElideMode.ElideRight,
                                            NAME_WIDTH - 8))
        painter.setFont(self._mono)
        painter.setPen(self._value_colour)
        rest = QRect(box.left() + NAME_WIDTH, box.top(),
                     max(20, box.width() - NAME_WIDTH), box.height())
        painter.drawText(rest, int(Qt.AlignmentFlag.AlignLeft
                                   | Qt.AlignmentFlag.AlignVCenter),
                         QFontMetrics(self._mono).elidedText(
                             value, Qt.TextElideMode.ElideRight, rest.width()))
        painter.restore()

    def sizeHint(self, option, index: QModelIndex) -> QSize:  # noqa: N802
        size = super().sizeHint(option, index)
        size.setHeight(max(size.height(), 26))
        return size


class ResultsGrid(QTreeView):
    """The table under the editor."""

    #: The user asked to add a filter: the argument is a pipeline stage.
    filter_requested = Signal(str)
    #: A cell was copied, for the toast.
    copied = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("resultsGrid")
        self._model = ResultModel(self)
        self.setModel(self._model)
        self._delegate = _Delegate(self)
        self.setItemDelegate(self._delegate)

        self.setRootIsDecorated(True)
        self.setUniformRowHeights(True)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setExpandsOnDoubleClick(False)
        self.setAllColumnsShowFocus(True)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_menu)
        self.expanded.connect(self._on_expanded)

        header = self.header()
        header.setSectionsMovable(True)
        header.setStretchLastSection(True)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft
                                   | Qt.AlignmentFlag.AlignVCenter)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self._show_header_menu)

        self._hidden: set[str] = set()

    # -- content ----------------------------------------------------------

    def set_table(self, table: ResultTable) -> None:
        self._model.set_table(table)
        self._hidden.clear()
        self._size_columns()
        if table.rows:
            self.setCurrentIndex(self._model.index(0, 0))

    def result(self) -> ResultTable:
        return self._model.table

    def apply_palette(self, palette: Palette, accent: str) -> None:
        self._delegate.apply_palette(palette, accent)
        self.viewport().update()

    def _size_columns(self) -> None:
        """Give each column a sensible width without measuring every row.

        ``resizeColumnToContents`` reads the whole model, which on a hundred
        thousand rows takes longer than the query did. The first two hundred
        rows are a good enough sample and cost nothing.
        """
        table = self._model.table
        if not table.columns:
            return
        metrics = QFontMetrics(self.font())
        sample = table.rows[:200]
        for position, column in enumerate(table.columns):
            widest = metrics.horizontalAdvance(column.name) + 44
            for row in sample:
                if position < len(row):
                    text = one_line(cell_text(row[position]))[:120]
                    widest = max(widest, metrics.horizontalAdvance(text) + 28)
            # A timestamp that is elided to "2026-09-22 01:53:38…" is useless,
            # and it is the column people read first, so it gets a floor of
            # its own rather than being sampled like the rest.
            floor = MIN_WIDTHS.get(column.type, 80)
            self.setColumnWidth(position, max(floor, min(460, widest)))

    def _on_expanded(self, index: QModelIndex) -> None:
        """Make each field line span the whole width when a row opens."""
        for row in range(self._model.rowCount(index)):
            self.setFirstColumnSpanned(row, index, True)

    # -- menus ------------------------------------------------------------

    def _show_menu(self, point: QPoint) -> None:
        index = self.indexAt(point)
        if not index.isValid():
            return
        menu = QMenu(self)
        value = index.data(RAW_ROLE)
        if index.parent().isValid():
            name = index.data(FIELD_ROLE) or ""
        else:
            name = self._model.column_name(index.column())
        literal = _literal(value)

        menu.addAction("Copy value", lambda: self._copy(cell_text(value)))
        menu.addAction("Copy row as JSON",
                       lambda: self._copy(self._row_json(index)))
        menu.addAction("Copy everything as TSV", self.copy_all)
        menu.addSeparator()

        if name and literal is not None:
            menu.addAction(f"Add filter: {name} == {_short(literal)}",
                           lambda: self.filter_requested.emit(
                               f"where {name} == {literal}"))
            menu.addAction(f"Exclude: {name} != {_short(literal)}",
                           lambda: self.filter_requested.emit(
                               f"where {name} != {literal}"))
            if isinstance(value, str) and len(value) > 3:
                menu.addAction(f"Rows containing {_short(literal)}",
                               lambda: self.filter_requested.emit(
                                   f"where {name} has {literal}"))
        if name:
            menu.addSeparator()
            menu.addAction(f"Group by {name}",
                           lambda: self.filter_requested.emit(
                               f"summarize Count = count() by {name}"))
            menu.addAction(f"Show only {name}",
                           lambda: self.filter_requested.emit(f"project {name}"))
            menu.addAction(f"Hide {name} from this table",
                           lambda: self._hide_column(name))
        menu.addSeparator()
        menu.addAction("Expand all rows", self.expandAll)
        menu.addAction("Collapse all rows", self.collapseAll)
        menu.exec(self.viewport().mapToGlobal(point))

    def _show_header_menu(self, point: QPoint) -> None:
        menu = QMenu(self)
        menu.addAction("Fit columns to contents", self._size_columns)
        menu.addSeparator()
        for position, column in enumerate(self._model.table.columns):
            action = menu.addAction(column.name)
            action.setCheckable(True)
            action.setChecked(not self.isColumnHidden(position))
            action.toggled.connect(
                lambda shown, index=position: self.setColumnHidden(index, not shown))
        menu.exec(self.header().mapToGlobal(point))

    def _hide_column(self, name: str) -> None:
        position = self._model.table.index_of(name)
        if position >= 0:
            self.setColumnHidden(position, True)
            self._hidden.add(name)

    # -- clipboard --------------------------------------------------------

    def _copy(self, text: str) -> None:
        clipboard = QGuiApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
        self.copied.emit(text)

    def _row_json(self, index: QModelIndex) -> str:
        row = index.parent().row() if index.parent().isValid() else index.row()
        values = self._model.row_values(row)
        table = self._model.table
        payload = {
            column.name: (value.isoformat() if isinstance(value, datetime)
                          else value.total_seconds() if isinstance(value, timedelta)
                          else value)
            for column, value in zip(table.columns, values)
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)

    def copy_all(self) -> None:
        from ...core.hunt.export import to_tsv

        self._copy(to_tsv(self._model.table))

    def copy_selection(self) -> None:
        """Copy the selected cells as TSV, keeping their layout."""
        indexes = [index for index in self.selectedIndexes()
                   if not index.parent().isValid()]
        if not indexes:
            self.copy_all()
            return
        rows: dict[int, dict[int, str]] = {}
        for index in indexes:
            rows.setdefault(index.row(), {})[index.column()] = cell_text(
                index.data(RAW_ROLE))
        lines = []
        for row in sorted(rows):
            columns = rows[row]
            lines.append("\t".join(columns[key].replace("\t", " ").replace("\n", " ")
                                   for key in sorted(columns)))
        self._copy("\n".join(lines))

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if event.matches(Qt.Key.Key_Copy) or (
                event.key() == Qt.Key.Key_C
                and event.modifiers() & Qt.KeyboardModifier.ControlModifier):
            self.copy_selection()
            return
        super().keyPressEvent(event)


def _literal(value: Any) -> str | None:
    """A value written the way a query would write it, or None if it cannot be."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, datetime):
        return f'datetime({value.strftime("%Y-%m-%d %H:%M:%S")})'
    if isinstance(value, timedelta):
        return f"{value.total_seconds():g}s"
    if isinstance(value, str):
        if len(value) > 300:
            return None
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return None


def _short(literal: str, limit: int = 32) -> str:
    return literal if len(literal) <= limit else literal[:limit - 1] + "…"
