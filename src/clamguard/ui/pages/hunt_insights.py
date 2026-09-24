"""The Insights tab: what the rules found, and the query that found it.

The Results tab answers what you asked. This answers what you did not think to
ask — sixteen built-in rules plus whatever the user has written, each of them
a query with a threshold and an explanation.

Every finding shows the query that produced it and offers to open it in the
editor. That is the point: a tool that says "suspicious activity detected" and
will not say how is asking to be believed, and this one would rather be
checked.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.hunt.rules import Finding, Review, Risk
from ...core.hunt.rules import RULES_DIRECTORY
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    Card,
    EmptyState,
    IconLabel,
    MessageBar,
    Separator,
    label,
)
from ..widgets.results_grid import cell_text, one_line

#: How many rows of evidence a finding shows inline.
PREVIEW_ROWS = 6


class InsightsPanel(QWidget):
    """The Insights tab."""

    #: Run the rules over the current time range.
    analyse_requested = Signal()
    #: Put a rule's query into the editor and run it.
    query_requested = Signal(str, bool)
    #: Open the directory where user rules live.
    rules_folder_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._review: Review | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        bar = QWidget()
        bar.setObjectName("insightsBar")
        row = QHBoxLayout(bar)
        row.setContentsMargins(SPACE_MD, SPACE_SM, SPACE_MD, SPACE_SM)
        row.setSpacing(SPACE_SM)

        self.analyse = QPushButton("Run the rules")
        self.analyse.setProperty("variant", "primary")
        self.analyse.clicked.connect(self.analyse_requested)
        row.addWidget(self.analyse)

        self.summary = label("", role="body")
        row.addWidget(self.summary, 1)

        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setVisible(False)
        row.addWidget(self.progress)

        folder = QPushButton("Write your own…")
        folder.setProperty("variant", "ghost")
        folder.setToolTip(f"Rules are JSON files in {RULES_DIRECTORY}. A rule "
                          "is a query and a threshold; it cannot run anything.")
        folder.clicked.connect(self.rules_folder_requested)
        row.addWidget(folder)
        outer.addWidget(bar)
        outer.addWidget(Separator())

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(self.scroll, 1)

        self._body_host = QWidget()
        self.body = QVBoxLayout(self._body_host)
        self.body.setContentsMargins(SPACE_LG, SPACE_MD, SPACE_LG, SPACE_LG)
        self.body.setSpacing(SPACE_MD)
        self.scroll.setWidget(self._body_host)

        self.show_idle()

    # -- state ------------------------------------------------------------

    @property
    def review(self) -> Review | None:
        return self._review

    def set_busy(self, busy: bool, done: int = 0, total: int = 0,
                 title: str = "") -> None:
        self.analyse.setEnabled(not busy)
        self.progress.setVisible(busy)
        if busy and total:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
            self.summary.setText(f"{title}  ({done}/{total})")
        elif busy:
            self.progress.setRange(0, 0)

    def show_idle(self, indexed: bool = False) -> None:
        self._clear()
        message = ("Run the rules to have Hunt look through the index for the "
                   "things people usually miss: downloads piped into a shell, "
                   "repeated crashes, authentication failures, log files that "
                   "appeared this week, gaps where a log stopped."
                   if indexed else
                   "Index some logs first, then run the rules over them.")
        empty = EmptyState("search", "Nothing analysed yet", message,
                           "Run the rules" if indexed else "")
        empty.actioned.connect(self.analyse_requested)
        self.body.addWidget(empty)
        self.body.addStretch(1)
        self.summary.setText("")

    def show_review(self, review: Review) -> None:
        self._review = review
        self._clear()
        self.summary.setText(review.summary())

        if review.problems:
            self.body.addWidget(MessageBar(
                "Some of your own rule files could not be read: "
                + "; ".join(review.problems[:3]), tone="warn"))

        fired = review.fired
        if not fired:
            empty = EmptyState(
                "shield-check", "Nothing stood out",
                f"All {review.checked} rules ran against "
                f"{(review.range.describe().lower() if review.range else 'the index')} "
                "and none of them matched. That is a real answer, not an "
                "absence of one — the rules that ran are listed below.")
            self.body.addWidget(empty)
        else:
            for finding in fired:
                self.body.addWidget(_FindingCard(finding, self))

        quiet = review.quiet
        if quiet:
            self.body.addWidget(_QuietList(quiet, review.failed, self))
        self.body.addStretch(1)

    def _clear(self) -> None:
        while self.body.count():
            item = self.body.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def badge_count(self) -> int:
        """How many findings deserve the sidebar's attention."""
        if self._review is None:
            return 0
        return sum(1 for item in self._review.fired
                   if item.rule.risk >= Risk.MEDIUM)


class _FindingCard(Card):
    """One rule that matched, with its evidence and its query."""

    def __init__(self, finding: Finding, panel: InsightsPanel) -> None:
        super().__init__(finding.rule.title, tone=_tone_for(finding.rule.risk))
        self._finding = finding
        rule = finding.rule

        badge = Badge(rule.risk.label, _tone_for(rule.risk))
        self.add_action(badge)
        self.set_icon(rule.risk.icon, _tone_for(rule.risk))

        header = QHBoxLayout()
        header.setSpacing(SPACE_SM)
        header.addWidget(label(finding.headline, role="body", tone="accent"))
        header.addWidget(label(f"· {rule.category} · {rule.source}", role="caption"))
        header.addStretch(1)
        self.body.addLayout(header)

        if rule.question:
            self.body.addWidget(label(rule.question, role="muted", wrap=True))
        if rule.explanation:
            self.body.addWidget(label(rule.explanation, role="body", wrap=True))

        if finding.table is not None and finding.table.rows:
            self.body.addWidget(_evidence_table(finding))

        if rule.advice:
            advice = QHBoxLayout()
            advice.setSpacing(SPACE_SM)
            advice.addWidget(IconLabel("arrow-right", tone="muted", size=14), 0,
                             Qt.AlignmentFlag.AlignTop)
            advice.addWidget(label(rule.advice, role="muted", wrap=True), 1)
            self.body.addLayout(advice)

        buttons = QHBoxLayout()
        buttons.setSpacing(SPACE_SM)
        open_query = QPushButton("Open this in the editor")
        open_query.clicked.connect(
            lambda: panel.query_requested.emit(rule.query, True))
        buttons.addWidget(open_query)

        copy = QPushButton("Copy the query")
        copy.setProperty("variant", "ghost")
        copy.clicked.connect(lambda: _copy(rule.query))
        buttons.addWidget(copy)
        buttons.addStretch(1)
        buttons.addWidget(label(f"{finding.elapsed * 1000:.0f} ms",
                                role="caption"))
        self.body.addLayout(buttons)


def _evidence_table(finding: Finding) -> QTableWidget:
    """The first few rows that made the rule fire."""
    table = finding.table
    columns = list(table.columns)[:6]
    rows = table.rows[:PREVIEW_ROWS]

    widget = QTableWidget(len(rows), len(columns))
    widget.setHorizontalHeaderLabels([column.name for column in columns])
    widget.verticalHeader().setVisible(False)
    widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    widget.setAlternatingRowColors(True)
    widget.setWordWrap(False)
    widget.horizontalHeader().setSectionResizeMode(
        QHeaderView.ResizeMode.Interactive)
    if columns:
        widget.horizontalHeader().setSectionResizeMode(
            len(columns) - 1, QHeaderView.ResizeMode.Stretch)

    for row_index, row in enumerate(rows):
        for column_index in range(len(columns)):
            value = row[column_index] if column_index < len(row) else None
            item = QTableWidgetItem(one_line(cell_text(value))[:200])
            item.setToolTip(cell_text(value)[:2000])
            widget.setItem(row_index, column_index, item)

    widget.resizeColumnsToContents()
    height = widget.horizontalHeader().height() + 8
    for index in range(widget.rowCount()):
        widget.setRowHeight(index, 26)
        height += 26
    widget.setFixedHeight(min(240, height))
    widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    if len(table.rows) > PREVIEW_ROWS:
        widget.setToolTip(f"{len(table.rows) - PREVIEW_ROWS:,} more rows — "
                          "open the query to see them all.")
    return widget


class _QuietList(Card):
    """The rules that ran and matched nothing, and the ones that broke."""

    def __init__(self, quiet, failed, panel: InsightsPanel) -> None:
        super().__init__(f"{len(quiet)} rules matched nothing")
        self.set_subtitle("Listed so that a clean result is visible rather "
                          "than merely implied.")
        for finding in quiet:
            row = QHBoxLayout()
            row.setSpacing(SPACE_SM)
            row.addWidget(IconLabel("check", tone="ok", size=13), 0,
                          Qt.AlignmentFlag.AlignTop)
            row.addWidget(label(finding.rule.title, role="muted"), 1)
            open_button = QPushButton("Check it yourself")
            open_button.setProperty("variant", "link")
            open_button.clicked.connect(
                lambda _checked=False, rule=finding.rule:
                panel.query_requested.emit(rule.query, True))
            row.addWidget(open_button)
            self.body.addLayout(row)

        if failed:
            self.body.addWidget(Separator())
            self.body.addWidget(label(f"{len(failed)} rules could not run",
                                      role="sectionLabel"))
            for finding in failed:
                self.body.addWidget(label(
                    f"{finding.rule.title}: {finding.error}", role="caption",
                    wrap=True))


def _tone_for(risk: Risk) -> str:
    return {Risk.HIGH: "danger", Risk.MEDIUM: "warn",
            Risk.LOW: "info", Risk.INFO: "info"}[risk]


def _copy(text: str) -> None:
    from PySide6.QtGui import QGuiApplication

    clipboard = QGuiApplication.clipboard()
    if clipboard is not None:
        clipboard.setText(text)
