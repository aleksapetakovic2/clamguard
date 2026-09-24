"""The left rail: Tables, Queries and Functions, searchable and collapsible.

This is the part of the reference layout that does the teaching. Sentinel's
rail is how anybody learns what columns exist, and the same is true here — the
column names in this store are not guessable, and a function library of a
hundred and thirty entries is useless if it is not browsable.

Three tabs over one tree:

``Tables``     the four queryable tables and their columns, then every indexed
               log file grouped by the application that wrote it
``Queries``    the built-in hunting library by category, the user's saved
               queries, and the last few that were run
``Functions``  every scalar and aggregate, by category, with its signature

Double-clicking does the obvious thing for whatever was clicked: a column name
is inserted at the cursor, a query is loaded and run, a function is inserted
with its bracket open. Favourites are starred through the context menu and
persist in the settings file.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QTabBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.hunt import catalogue, library
from ...core.hunt.kql import functions as kql_functions
from ...core.hunt.saved import QueryStore
from ...core.hunt.store import Source
from .. import icons
from ..theme import SPACE_SM, SPACE_XS
from ..widgets import IconButton, label

#: What an item is, stored on it so the double-click knows what to do.
KIND_ROLE = Qt.ItemDataRole.UserRole + 1
#: The text to insert or run.
PAYLOAD_ROLE = Qt.ItemDataRole.UserRole + 2
#: A stable id for favouriting.
ID_ROLE = Qt.ItemDataRole.UserRole + 3

TABS = ("Tables", "Queries", "Functions")

#: How the Tables tab can be grouped, matching the reference's "Group by".
GROUPINGS = ("Group by: Solution", "Group by: Application", "Group by: Format",
             "No grouping")


class HuntRail(QWidget):
    """The navigation column to the left of the editor."""

    #: Insert text at the editor's cursor.
    insert_requested = Signal(str)
    #: Load a whole query, and run it when the second argument is True.
    query_requested = Signal(str, bool)
    #: Show a source's details.
    source_activated = Signal(str)
    #: A favourite was added or removed: (id, now favourite).
    favourite_toggled = Signal(str, bool)

    def __init__(self, queries: QueryStore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("huntRail")
        self.queries = queries
        self._sources: list[Source] = []
        self._favourites: set[str] = set()
        self._tab = 0

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_SM, SPACE_SM, SPACE_SM, SPACE_SM)
        column.setSpacing(SPACE_XS)

        self.tabs = QTabBar()
        self.tabs.setObjectName("railTabs")
        self.tabs.setDrawBase(False)
        self.tabs.setExpanding(False)
        for name in TABS:
            self.tabs.addTab(name)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        column.addWidget(self.tabs)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search")
        self.search.setClearButtonEnabled(True)
        self.search.addAction(icons.icon("search", tone="faint", size=14),
                              QLineEdit.ActionPosition.LeadingPosition)
        self.search.textChanged.connect(self._on_search)
        column.addWidget(self.search)

        controls = QHBoxLayout()
        controls.setSpacing(SPACE_XS)
        self.grouping = QComboBox()
        self.grouping.addItems(GROUPINGS)
        self.grouping.setToolTip("How the Tables tab arranges what it lists.")
        self.grouping.currentIndexChanged.connect(lambda _index: self.refresh())
        controls.addWidget(self.grouping, 1)
        # Takes the space the grouping box leaves behind on the tabs where it
        # is hidden, so the collapse button stays on the right either way.
        controls.addStretch(1)

        self.collapse_button = IconButton("chevron-up", "Collapse everything",
                                          tone="muted", size=14)
        self.collapse_button.clicked.connect(self._collapse_all)
        controls.addWidget(self.collapse_button)
        column.addLayout(controls)

        self.tree = QTreeWidget()
        self.tree.setObjectName("railTree")
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(14)
        self.tree.setUniformRowHeights(True)
        self.tree.setAnimated(False)
        self.tree.setExpandsOnDoubleClick(False)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_menu)
        self.tree.itemDoubleClicked.connect(self._on_activated)
        self.tree.itemClicked.connect(self._on_clicked)
        column.addWidget(self.tree, 1)

        self.hint = label("", role="caption", wrap=True)
        self.hint.setMinimumHeight(34)
        column.addWidget(self.hint)

        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(180)
        self._search_timer.timeout.connect(self.refresh)

        self.refresh()

    # -- state ------------------------------------------------------------

    def set_sources(self, sources: list[Source]) -> None:
        self._sources = sources
        if self._tab == 0:
            self.refresh()

    def set_favourites(self, favourites) -> None:
        self._favourites = set(favourites or ())
        self.refresh()

    def _on_tab_changed(self, index: int) -> None:
        self._tab = index
        self.grouping.setVisible(index == 0)
        self.refresh()

    def _on_search(self, _text: str) -> None:
        self._search_timer.start()

    def _collapse_all(self) -> None:
        self.tree.collapseAll()

    # -- building ---------------------------------------------------------

    def refresh(self) -> None:
        """Rebuild the tree for the current tab, search and grouping."""
        needle = self.search.text().strip().lower()
        expanded = self._expanded_names()
        self.tree.setUpdatesEnabled(False)
        self.tree.clear()

        if self._tab == 0:
            self._build_tables(needle)
        elif self._tab == 1:
            self._build_queries(needle)
        else:
            self._build_functions(needle)

        if needle:
            self.tree.expandAll()
        else:
            self._restore_expanded(expanded)
        self.tree.setUpdatesEnabled(True)

    def _expanded_names(self) -> set[str]:
        names: set[str] = set()
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            if item.isExpanded():
                names.add(item.text(0))
        return names

    def _restore_expanded(self, names: set[str]) -> None:
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            item.setExpanded(item.text(0) in names or index == 0)

    # -- tabs -------------------------------------------------------------

    def _build_tables(self, needle: str) -> None:
        self._favourites_group(needle)

        for group, tables in catalogue.grouped().items():
            parent = self._group(group, "database")
            for table in tables:
                matched = not needle or needle in table.name.lower() \
                    or needle in table.description.lower()
                columns = [column for column in table.columns
                           if not needle or needle in column.name.lower()
                           or needle in column.description.lower()]
                if not matched and not columns:
                    continue
                node = self._item(parent, table.name, "table", table.name,
                                  f"table:{table.name}", icon="layers",
                                  tip=table.description)
                for column in (table.columns if matched else columns):
                    self._item(node, column.name, "column", column.name,
                               f"column:{table.name}.{column.name}",
                               detail=column.type.value, icon="",
                               tip=column.description)
            if parent.childCount() == 0:
                self._remove(parent)

        if self._sources:
            self._build_sources(needle)

    def _build_sources(self, needle: str) -> None:
        grouping = self.grouping.currentIndex()
        buckets: dict[str, list[Source]] = {}
        for source in self._sources:
            if needle and needle not in source.path.lower() \
                    and needle not in source.app.lower():
                continue
            if grouping == 2:
                key = source.format
            elif grouping == 3:
                key = "All files"
            elif grouping == 0:
                key = source.root or "other"
            else:
                key = source.app or "other"
            buckets.setdefault(key, []).append(source)

        if not buckets:
            return
        root = self._group(f"Log sources ({len(self._sources)} files)", "file")
        for name in sorted(buckets, key=str.lower):
            entries = sorted(buckets[name], key=lambda item: -item.events)
            parent = self._item(root, f"{name}", "group", "", f"sources:{name}",
                                detail=f"{sum(item.events for item in entries):,}")
            for source in entries[:400]:
                self._item(parent, source.name, "source",
                           f'Logs\n| where Source == "{source.path}"\n'
                           "| sort by Timestamp desc\n| take 200",
                           f"source:{source.path}",
                           detail=f"{source.events:,}", icon="",
                           tip=f"{source.path}\n{source.format} · "
                               f"{source.events:,} events")

    def _build_queries(self, needle: str) -> None:
        self._favourites_group(needle)

        saved = self.queries.all()
        if saved:
            parent = self._group(f"Saved ({len(saved)})", "save")
            for item in saved:
                if needle and needle not in item.name.lower() \
                        and needle not in item.text.lower():
                    continue
                self._item(parent, item.name, "saved", item.text,
                           f"saved:{item.id}", icon="",
                           tip=item.description or item.text[:300])
            if parent.childCount() == 0:
                self._remove(parent)

        for category, entries in library.by_category().items():
            matching = [item for item in entries
                        if not needle or needle in item.name.lower()
                        or needle in item.description.lower()
                        or needle in item.text.lower()]
            if not matching:
                continue
            parent = self._group(category, "search")
            for item in matching:
                self._item(parent, item.name, "example", item.text,
                           f"example:{item.id}", icon="",
                           tip=item.description or item.one_line[:300])

        recent = self.queries.recent(20)
        if recent:
            parent = self._group("Recently run", "history")
            for record in recent:
                one_line = " ".join(record.text.split())
                if needle and needle not in one_line.lower():
                    continue
                self._item(parent, one_line[:70], "history", record.text,
                           f"history:{one_line[:40]}", icon="",
                           detail=f"{record.rows:,}" if record.ok else "failed",
                           tip=record.text[:400])
            if parent.childCount() == 0:
                self._remove(parent)

    def _build_functions(self, needle: str) -> None:
        self._favourites_group(needle)

        for category, entries in sorted(kql_functions.categories().items()):
            matching = [item for item in entries
                        if not needle or needle in item.name.lower()
                        or needle in item.summary.lower()]
            if not matching:
                continue
            parent = self._group(category.title(), "terminal")
            for item in matching:
                self._item(parent, item.name, "function", f"{item.name}(",
                           f"function:{item.name}", icon="",
                           detail="ClamGuard" if item.extension else "",
                           tip=f"{item.signature}\n\n{item.summary}")

        aggregates = [item for item in kql_functions.AGGREGATES.values()
                      if not needle or needle in item.name.lower()
                      or needle in item.summary.lower()]
        if aggregates:
            parent = self._group("Aggregates", "gauge")
            for item in sorted(aggregates, key=lambda entry: entry.name):
                self._item(parent, item.name, "function", f"{item.name}(",
                           f"function:{item.name}", icon="",
                           tip=f"{item.signature}\n\n{item.summary}")

    def _favourites_group(self, needle: str) -> None:
        """The starred section, exactly where the reference puts it."""
        parent = self._group("Favourites", "pin")
        for identifier in sorted(self._favourites):
            resolved = self._resolve(identifier)
            if resolved is None:
                continue
            name, payload, kind, tip = resolved
            if needle and needle not in name.lower():
                continue
            self._item(parent, name, kind, payload, identifier, icon="pin", tip=tip)
        if parent.childCount() == 0:
            self._remove(parent)
            if not self._favourites and not needle:
                empty = self._group("Favourites", "pin")
                note = QTreeWidgetItem(empty)
                note.setText(0, "Right-click anything here to star it.")
                note.setForeground(0, self.palette().placeholderText())
                note.setFlags(Qt.ItemFlag.ItemIsEnabled)
                empty.setExpanded(True)
        else:
            parent.setExpanded(True)

    def _resolve(self, identifier: str):
        """A favourite id back into something showable."""
        kind, _, rest = identifier.partition(":")
        if kind == "example":
            item = library.get(rest)
            return (item.name, item.text, "example", item.description) if item else None
        if kind == "saved":
            item = self.queries.queries.get(rest)
            return (item.name, item.text, "saved", item.description) if item else None
        if kind == "table":
            table = catalogue.table(rest)
            return (table.name, table.name, "table", table.description) if table else None
        if kind == "column":
            _table, _, name = rest.partition(".")
            return (name, name, "column", "") if name else None
        if kind == "function":
            found = kql_functions.SCALARS.get(rest) or kql_functions.AGGREGATES.get(rest)
            return ((found.name, f"{found.name}(", "function", found.summary)
                    if found else None)
        if kind == "source":
            return (rest.rsplit("/", 1)[-1],
                    f'Logs\n| where Source == "{rest}"\n| take 200', "source", rest)
        return None

    # -- items ------------------------------------------------------------

    def _group(self, title: str, icon: str) -> QTreeWidgetItem:
        item = QTreeWidgetItem(self.tree)
        item.setText(0, title)
        item.setIcon(0, icons.icon(icon, tone="muted", size=15))
        font = item.font(0)
        font.setBold(True)
        item.setFont(0, font)
        item.setData(0, KIND_ROLE, "group")
        return item

    def _item(self, parent: QTreeWidgetItem, title: str, kind: str, payload: str,
              identifier: str, *, detail: str = "", icon: str = "",
              tip: str = "") -> QTreeWidgetItem:
        item = QTreeWidgetItem(parent)
        item.setText(0, f"{title}   {detail}" if detail else title)
        if icon:
            item.setIcon(0, icons.icon(icon, tone="muted", size=14))
        item.setData(0, KIND_ROLE, kind)
        item.setData(0, PAYLOAD_ROLE, payload)
        item.setData(0, ID_ROLE, identifier)
        if tip:
            item.setToolTip(0, tip)
        if identifier in self._favourites:
            font = item.font(0)
            font.setItalic(True)
            item.setFont(0, font)
        return item

    @staticmethod
    def _remove(item: QTreeWidgetItem) -> None:
        tree = item.treeWidget()
        if tree is not None:
            tree.takeTopLevelItem(tree.indexOfTopLevelItem(item))

    # -- interaction ------------------------------------------------------

    def _on_clicked(self, item: QTreeWidgetItem, _column: int) -> None:
        self.hint.setText(item.toolTip(0) or "")
        if item.data(0, KIND_ROLE) == "group":
            item.setExpanded(not item.isExpanded())

    def _on_activated(self, item: QTreeWidgetItem, _column: int) -> None:
        kind = item.data(0, KIND_ROLE)
        payload = item.data(0, PAYLOAD_ROLE) or ""
        if kind in ("group", None) or not payload:
            item.setExpanded(not item.isExpanded())
            return
        if kind in ("example", "saved", "history", "source"):
            self.query_requested.emit(payload, True)
            if kind == "saved":
                identifier = (item.data(0, ID_ROLE) or "").partition(":")[2]
                if identifier:
                    self.queries.record_use(identifier)
            return
        self.insert_requested.emit(payload)

    def _show_menu(self, point) -> None:
        item = self.tree.itemAt(point)
        if item is None:
            return
        kind = item.data(0, KIND_ROLE)
        payload = item.data(0, PAYLOAD_ROLE) or ""
        identifier = item.data(0, ID_ROLE) or ""
        menu = QMenu(self)

        if kind in ("example", "saved", "history", "source"):
            menu.addAction("Run it", lambda: self.query_requested.emit(payload, True))
            menu.addAction("Load it without running",
                           lambda: self.query_requested.emit(payload, False))
        elif payload:
            menu.addAction("Insert at the cursor",
                           lambda: self.insert_requested.emit(payload))
        if kind == "table":
            menu.addAction("Show the first 100 rows",
                           lambda: self.query_requested.emit(
                               f"{payload}\n| take 100", True))
            menu.addAction("Describe its columns",
                           lambda: self.query_requested.emit(
                               f"{payload}\n| getschema", True))
        if kind == "column":
            menu.addAction("Count by this column",
                           lambda: self.insert_requested.emit(
                               f"\n| summarize Count = count() by {payload}"))
        if kind == "source":
            menu.addSeparator()
            menu.addAction("Show this file's details",
                           lambda: self.source_activated.emit(identifier.partition(":")[2]))

        if identifier and kind != "group":
            menu.addSeparator()
            starred = identifier in self._favourites
            menu.addAction("Remove from favourites" if starred else "Add to favourites",
                           lambda: self.favourite_toggled.emit(identifier, not starred))
        if payload:
            menu.addSeparator()
            menu.addAction("Copy", lambda: _copy(payload))
        menu.exec(self.tree.viewport().mapToGlobal(point))

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()


def _copy(text: str) -> None:
    from PySide6.QtGui import QGuiApplication

    clipboard = QGuiApplication.clipboard()
    if clipboard is not None:
        clipboard.setText(text)
