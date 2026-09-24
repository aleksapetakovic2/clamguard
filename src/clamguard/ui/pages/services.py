"""Every unit on the machine, and what each one is for.

A master/detail page. The list is deliberately plain — name, state, whether it
starts itself, and one line of what it is — because the interesting material is
all in :mod:`.services_detail`, and a table with fourteen columns helps nobody.

The filters are the other half of the feature. "Show me what is failing" is
easy anywhere; "show me what somebody enabled against the distribution's
default", "show me the units no package owns" and "show me what cost the most
at boot" are the questions that actually find things, and each is one click.
"""

from __future__ import annotations

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
    Signal,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QWidget,
)

from ...core.units.manager import UnitManager
from ...core.units.model import Inventory, Unit, UnitKind
from ...core.units.purpose import SLOW_BOOT_SECONDS
from ..theme import SPACE_MD, SPACE_SM, Palette
from ..widgets import Badge, MessageBar, StatTile, label, restyle
from .base import Page
from .services_detail import UnitDetail

#: (label, predicate) for the state filter. The interesting ones are the last
#: four: they are the questions that find something rather than confirm it.
FILTERS: tuple[tuple[str, object], ...] = (
    ("Everything", lambda unit: True),
    ("Running", lambda unit: unit.running),
    ("Failed", lambda unit: unit.active_state == "failed"),
    ("Stopped", lambda unit: unit.exists and not unit.running),
    ("Starts at boot", lambda unit: unit.enablement.starts_itself),
    ("Masked", lambda unit: unit.masked),
    ("Changed from the distribution default", lambda unit: unit.deviates_from_preset),
    ("No package owns it", lambda unit: unit.is_unpackaged),
    ("Locally overridden", lambda unit: bool(unit.local_drop_ins)),
    ("Slow at boot", lambda unit: unit.boot_seconds >= SLOW_BOOT_SECONDS),
    ("Listening on a port", lambda unit: bool(unit.ports)),
    ("Worth a look", lambda unit: bool(unit.purpose.flags)),
)

COLUMNS = ("Unit", "State", "Startup", "What it is")

#: The narrowest the detail pane can be and still lay out without clipping,
#: measured: the widest unbreakable line is a drop-in path next to its key.
DETAIL_MINIMUM_WIDTH = 330
TABLE_MINIMUM_WIDTH = 240


class UnitModel(QAbstractTableModel):
    """643 rows, so a model rather than a widget-per-cell table."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._units: list[Unit] = []
        self._tones: dict[str, QColor] = {}

    def set_units(self, units: list[Unit]) -> None:
        self.beginResetModel()
        self._units = units
        self.endResetModel()

    def unit_at(self, row: int) -> Unit | None:
        return self._units[row] if 0 <= row < len(self._units) else None

    def apply_palette(self, palette: Palette, accent: str) -> None:
        """Store the colours. Deliberately emits nothing.

        An earlier version emitted `dataChanged` here, which segfaulted: the
        palette is handed out from `theme_refresh_requested`, a row selection
        can raise that signal, and a selection change happens *during*
        `QSortFilterProxyModel.invalidateFilter`. Emitting a source-model
        signal while the proxy is rebuilding its mapping corrupts it. The view
        repaints its own viewport instead — see `_UnitTable.apply_palette`.
        """
        self._tones = {
            "ok": QColor(palette.ok), "warn": QColor(palette.warn),
            "danger": QColor(palette.danger), "info": QColor(palette.info),
            "neutral": QColor(palette.text_dim),
        }

    # -- Qt ---------------------------------------------------------------

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._units)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (orientation is Qt.Orientation.Horizontal
                and role == Qt.ItemDataRole.DisplayRole):
            return COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        unit = self.unit_at(index.row())
        if unit is None:
            return None
        column = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return unit.id
            if column == 1:
                return unit.state_summary()
            if column == 2:
                return unit.enablement.value or "—"
            return unit.purpose.headline or unit.description

        if role == Qt.ItemDataRole.ForegroundRole and column == 1:
            return self._tones.get(unit.tone())

        if role == Qt.ItemDataRole.ToolTipRole:
            return unit.purpose.headline or unit.id

        # Used by the proxy for both sorting and filtering, so neither has to
        # reach back through the model for the object itself.
        if role == Qt.ItemDataRole.UserRole:
            return unit
        return None


class UnitFilter(QSortFilterProxyModel):
    """Search text plus a kind and a state filter."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.text = ""
        self.kind: UnitKind | None = None
        self.predicate = FILTERS[0][1]

    def set_filters(self, *, text: str, kind: UnitKind | None, predicate) -> None:
        """Change all three at once, so a keystroke re-filters the list once.

        An earlier version had a setter per field and re-filtered on each, so
        every change to the search box walked the 627 rows three times.
        """
        text = text.strip().lower()
        predicate = predicate if callable(predicate) else self.predicate
        if (text, kind, predicate) == (self.text, self.kind, self.predicate):
            return
        self._change(lambda: self._assign(text, kind, predicate))

    def _assign(self, text, kind, predicate) -> None:
        self.text, self.kind, self.predicate = text, kind, predicate

    def _change(self, apply) -> None:
        """Qt 6.9 added begin/endFilterChange and 6.11 deprecated
        invalidateFilter() in their favour. ClamGuard runs on whatever PySide6
        the distribution ships, so the new pair is used where it exists and
        invalidateRowsFilter() — present in every Qt 6 — where it does not."""
        begin = getattr(self, "beginFilterChange", None)
        if begin is not None:
            begin()
            apply()
            self.endFilterChange(QSortFilterProxyModel.Direction.Rows)
        else:
            apply()
            self.invalidateRowsFilter()

    def filterAcceptsRow(self, row, parent) -> bool:
        model = self.sourceModel()
        unit = model.unit_at(row) if isinstance(model, UnitModel) else None
        if unit is None:
            return False
        if self.kind is not None and unit.kind is not self.kind:
            return False
        if not self.predicate(unit):
            return False
        if not self.text:
            return True
        # Searching the package name as well is what makes "cups" find
        # everything the printing stack installed, not just the unit called cups.
        haystack = (f"{unit.id} {unit.description} {unit.package} "
                    f"{unit.purpose.headline} {unit.man_summary}").lower()
        return self.text in haystack


class ServicesPage(Page):
    """What is on this machine, and what each piece is for."""

    PAGE_ID = "services"
    TITLE = "Services"
    SUBTITLE = "Every systemd unit on this machine, and what each one is for"
    ICON = "services"
    #: A master/detail page scrolls its own list and its own pane. Inside the
    #: base page's scroll area it had three nested scrollers at small sizes.
    SCROLLABLE = False

    #: Emitted once a refresh lands, so tests can wait on it.
    inventory_ready = Signal(object)

    def __init__(self, context, parent=None) -> None:
        super().__init__(context, parent)
        self.manager = UnitManager(self)
        self.inventory: Inventory | None = None

    # -- construction -----------------------------------------------------

    def build(self) -> None:
        self._build_header_actions()

        self.notice = MessageBar("", "info", dismissible=True)
        self.notice.setVisible(False)
        self.body.addWidget(self.notice)

        self.body.addWidget(self._build_summary())
        self.body.addWidget(self._build_filters())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_table())
        self.detail = UnitDetail()
        # Below this the pane's cards cannot lay out even with everything
        # wrapping, so the splitter takes the room from the list instead — the
        # list scrolls sideways gracefully, the cards did not.
        self.detail.setMinimumWidth(DETAIL_MINIMUM_WIDTH)
        self.table.setMinimumWidth(TABLE_MINIMUM_WIDTH)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 11)
        splitter.setStretchFactor(1, 9)
        splitter.setChildrenCollapsible(False)
        # A proportional starting split: 55/45 at any window size. Fixed pixel
        # sizes looked right at 1560px and clipped the detail pane at the
        # default 1180.
        splitter.setSizes([550, 450])
        self.body.addWidget(splitter, 1)

        self.manager.refreshed.connect(self._on_refreshed)
        self.manager.failed.connect(self._on_failed)
        self.manager.busy_changed.connect(self._on_busy)

    def _build_header_actions(self) -> None:
        self.scope = QComboBox()
        self.scope.addItem("System units", False)
        self.scope.addItem("My session's units", True)
        self.scope.setToolTip(
            "System units are the machine's own. Session units are the ones "
            "your login runs — on a desktop that is most of your session.")
        self.scope.currentIndexChanged.connect(lambda _i: self.refresh())
        self.add_header_action(self.scope)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setProperty("variant", "primary")
        self.refresh_button.clicked.connect(self.refresh)
        self.add_header_action(self.refresh_button)

    def _build_summary(self) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(SPACE_MD * 2)
        self.tiles: dict[str, StatTile] = {}
        for key, caption, tone in (
            ("total", "units", ""),
            ("running", "running", "ok"),
            ("failed", "failed", "danger"),
            ("enabled", "start at boot", ""),
            ("masked", "masked", "warn"),
            ("unpackaged", "not from a package", "warn"),
        ):
            tile = StatTile("—", caption, tone=tone)
            self.tiles[key] = tile
            row.addWidget(tile)
        row.addStretch(1)
        self.elapsed_badge = Badge("", "neutral")
        row.addWidget(self.elapsed_badge, 0, Qt.AlignmentFlag.AlignBottom)
        return holder

    def _build_filters(self) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(SPACE_SM)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, description or package…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._on_filter_changed)
        row.addWidget(self.search, 2)

        self.kind_picker = QComboBox()
        self.kind_picker.addItem("Every kind", None)
        for kind in (UnitKind.SERVICE, UnitKind.SOCKET, UnitKind.TIMER,
                     UnitKind.TARGET, UnitKind.MOUNT, UnitKind.PATH,
                     UnitKind.SLICE, UnitKind.SCOPE):
            self.kind_picker.addItem(kind.title + "s", kind)
        self.kind_picker.currentIndexChanged.connect(self._on_filter_changed)
        row.addWidget(self.kind_picker, 1)

        self.state_picker = QComboBox()
        for title, predicate in FILTERS:
            self.state_picker.addItem(title, predicate)
        self.state_picker.currentIndexChanged.connect(self._on_filter_changed)
        row.addWidget(self.state_picker, 1)

        self.count_label = label("", role="caption", tone="muted")
        row.addWidget(self.count_label)
        return holder

    def _build_table(self) -> QWidget:
        self.model = UnitModel(self)
        self.proxy = UnitFilter(self)
        self.proxy.setSourceModel(self.model)

        self.table = _UnitTable()
        self.table.setModel(self.proxy)
        self.table.selectionModel().currentRowChanged.connect(self._on_selected)
        return self.table

    # -- data -------------------------------------------------------------

    def on_shown(self) -> None:
        if self.inventory is None and not self.manager.busy:
            self.refresh()

    def _wanted_scope(self) -> bool:
        """True when the picker asks for the session's units."""
        return bool(self.scope.currentData()) if hasattr(self, "scope") else False

    def refresh(self) -> None:
        # A request while a read is in flight is not lost: `_on_refreshed`
        # compares the scope that arrived with the scope now wanted and reads
        # again if they differ. Before, switching the picker mid-read left it
        # saying "My session's units" over a list of system units.
        self.count_label.setText("reading…")
        self.manager.refresh(user=self._wanted_scope())

    def _on_refreshed(self, inventory: Inventory) -> None:
        if self.manager.user_scope != self._wanted_scope():
            self.refresh()
            return

        previous = self._selected_unit_id()
        self.inventory = inventory
        self.model.set_units(list(inventory))
        counts = inventory.counts()
        for key, tile in self.tiles.items():
            tile.set_value(f"{counts.get(key, 0):,}")
        # "Boot" is the system manager's word. The session manager starts its
        # units at login, and saying boot there would be wrong.
        self.tiles["enabled"].caption_label.setText(
            "start at login" if self.manager.user_scope else "start at boot")
        self.elapsed_badge.set_state(f"read in {inventory.elapsed:.1f}s", "neutral")

        # Enrichment notes are shown, not swallowed: "ports need root" and "no
        # package manager found" both explain a row that is missing from the
        # detail pane, and an unexplained gap reads as a bug.
        enrichment = self.manager.enrichment()
        notes = list(inventory.problems) + list(enrichment.missing if enrichment else ())
        if notes:
            self.notice.set_message(" ".join(notes), "info")
            self.notice.setVisible(True)
        else:
            self.notice.setVisible(False)

        self._on_filter_changed()
        # Keep the unit the person was reading. A refresh used to jump back to
        # the first row every time, which on a 600-row list loses your place.
        if not self._select_unit(previous) and self.proxy.rowCount():
            self.table.selectRow(0)
        self.theme_refresh_requested.emit()
        self.inventory_ready.emit(inventory)
        self.badge_changed.emit(str(counts.get("failed", 0)) if counts.get("failed") else "")

    def _on_failed(self, message: str) -> None:
        self.notice.set_message(message, "danger")
        self.notice.setVisible(True)
        self.count_label.setText("")

    def _on_busy(self, busy: bool) -> None:
        self.refresh_button.setEnabled(not busy)
        self.refresh_button.setText("Reading…" if busy else "Refresh")

    # -- interaction ------------------------------------------------------

    def _on_filter_changed(self, *_args) -> None:
        self.proxy.set_filters(text=self.search.text(),
                               kind=self.kind_picker.currentData(),
                               predicate=self.state_picker.currentData())

        shown, total = self.proxy.rowCount(), self.model.rowCount()
        self.count_label.setText(
            f"{shown:,} of {total:,}" if shown != total else f"{total:,}")

    def _selected_unit_id(self) -> str:
        if not hasattr(self, "table"):
            return ""
        current = self.table.currentIndex()
        if not current.isValid():
            return ""
        unit = self.model.unit_at(self.proxy.mapToSource(current).row())
        return unit.id if unit is not None else ""

    def _select_unit(self, unit_id: str) -> bool:
        """Select a unit by id if it is visible. Returns whether it was."""
        if not unit_id:
            return False
        for row in range(self.proxy.rowCount()):
            if self.proxy.index(row, 0).data() == unit_id:
                self.table.selectRow(row)
                self.table.scrollTo(self.proxy.index(row, 0))
                return True
        return False

    def _on_selected(self, current, _previous) -> None:
        if not current.isValid():
            self.detail.show_nothing()
            return
        source = self.proxy.mapToSource(current)
        unit = self.model.unit_at(source.row())
        if unit is None:
            self.detail.show_nothing()
        else:
            # No theme_refresh_requested here. Nothing the detail pane builds
            # paints itself — Card, Badge, KeyValueRow and CommandBlock are all
            # stylesheet-driven — and raising it from a selection change is
            # what re-entered the model mid-filter and crashed Qt.
            self.detail.show_unit(unit)

    def badge(self) -> str:
        if self.inventory is None:
            return ""
        failed = self.inventory.counts().get("failed", 0)
        return str(failed) if failed else ""


class _UnitTable(QTableView):
    """A table sized and configured for this one list.

    Subclassed rather than configured inline so it can forward the palette to
    its model: `apply_palette_to` walks widgets, and a model is not one.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(28)
        self.horizontalHeader().setStretchLastSection(True)

    #: The unit column's preferred and smallest automatic widths.
    NAME_WIDTH = 310
    NAME_MINIMUM = 180
    #: What the description column should keep before the name gives way.
    DESCRIPTION_MINIMUM = 100

    def setModel(self, model) -> None:
        """Qt discards column widths when a model is attached, so they are
        applied here rather than in __init__ — where an earlier version set
        them and silently lost them, leaving every unit name elided."""
        super().setModel(model)
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.setColumnWidth(1, 85)
        self.setColumnWidth(2, 80)
        self._user_sized = False
        self._sizing = False
        header.sectionResized.connect(self._on_section_resized)
        self._fit_name_column()

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt API
        super().resizeEvent(event)
        self._fit_name_column()

    def _fit_name_column(self) -> None:
        """Give the unit name the room, but not all of it.

        A fixed 310px name column at the default window size pushed "What it
        is" entirely off-screen. This shrinks the name toward NAME_MINIMUM so
        the description keeps some space, and leaves the column alone once the
        person has dragged it themselves.
        """
        if getattr(self, "_user_sized", True):
            return
        spare = (self.viewport().width() - self.columnWidth(1) - self.columnWidth(2)
                 - self.DESCRIPTION_MINIMUM)
        width = max(self.NAME_MINIMUM, min(self.NAME_WIDTH, spare))
        if width != self.columnWidth(0):
            self._sizing = True
            self.setColumnWidth(0, width)
            self._sizing = False

    def _on_section_resized(self, index: int, _old: int, _new: int) -> None:
        if index == 0 and not self._sizing:
            self._user_sized = True

    def apply_palette(self, palette: Palette, accent: str) -> None:
        model = self.model()
        source = model.sourceModel() if isinstance(model, QSortFilterProxyModel) else model
        forward = getattr(source, "apply_palette", None)
        if callable(forward):
            forward(palette, accent)
        restyle(self)
        # The model stores the new colours without signalling, so ask for the
        # repaint here where it is always safe.
        self.viewport().update()
