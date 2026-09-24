"""The shape every page shares: a header, and a scrollable body.

Subclass :class:`Page`, set the three class attributes, and fill ``self.body``
in ``build()``. The main window takes care of the rest.

::

    class UpdatesPage(Page):
        PAGE_ID = "updates"
        TITLE = "Updates"
        SUBTITLE = "Virus signature downloads"
        ICON = "updates"

        def build(self):
            self.body.addWidget(Card("Databases"))

Pages talk to the rest of the app through two signals — :attr:`navigate` to
send the user somewhere else, and :attr:`notify` to raise a toast — and never
by reaching for the main window directly.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QBoxLayout,
    QHBoxLayout,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ...core.context import AppContext
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XL
from ..widgets import label

#: Horizontal room kept free for the page's vertical scrollbar when deciding
#: whether a responsive row fits. Slightly generous, so a row never sits
#: exactly on the edge and flips back and forth as the scrollbar appears.
RESPONSIVE_SCROLLBAR_ALLOWANCE = 18


class Page(QWidget):
    """Base class for every screen in the application."""

    #: Identifier used by navigate() and by the sidebar.
    PAGE_ID = "page"
    TITLE = "Page"
    SUBTITLE = ""
    ICON = "dashboard"
    #: Set False for pages that fill their own space (the log viewer).
    SCROLLABLE = True

    #: Ask the main window to show another page, by PAGE_ID.
    navigate = Signal(str)
    #: Raise a transient message: (text, tone) where tone is ok/warn/danger/info.
    notify = Signal(str, str)
    #: Ask the window to update the badge next to this page's sidebar entry.
    badge_changed = Signal(str)
    #: Ask the window to run a scan: (ScanKind, list[Path] | None).
    request_scan = Signal(object, object)
    #: Emit after creating custom-painted widgets (ProgressRing, ToggleSwitch)
    #: so the window can hand them the current palette. Stylesheet-styled
    #: widgets do not need this; widgets that paint themselves do.
    theme_refresh_requested = Signal()

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        self._built = False
        #: Rows registered with make_responsive(), and the extra horizontal
        #: inset each sits at (a row inside a card has the card's margins too).
        self._responsive_rows: list[tuple[QBoxLayout, int]] = []
        self._responsive_pending = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_header())

        #: Put page content here.
        self.body = QVBoxLayout()
        self.body.setContentsMargins(SPACE_XL, SPACE_LG, SPACE_XL, SPACE_XL)
        self.body.setSpacing(SPACE_MD)

        content = QWidget()
        content.setLayout(self.body)
        content.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        # Watched so responsive rows are re-decided when their *content*
        # changes, not only when the window is resized — see make_responsive.
        self._content = content
        content.installEventFilter(self)

        if self.SCROLLABLE:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QScrollArea.Shape.NoFrame)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setWidget(content)
            outer.addWidget(scroll, 1)
        else:
            outer.addWidget(content, 1)

    # -- header -----------------------------------------------------------

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setObjectName("pageHeader")
        row = QHBoxLayout(header)
        row.setContentsMargins(SPACE_XL, SPACE_LG, SPACE_XL, SPACE_MD)
        row.setSpacing(SPACE_SM)

        titles = QVBoxLayout()
        titles.setSpacing(1)
        self._title_label = label(self.TITLE, role="title")
        titles.addWidget(self._title_label)
        # Wrapped, because some pages put live status here ("myhost · Arch
        # Linux · analysed just now in 2.5s · Balanced") and a subtitle that
        # cannot wrap is part of the header's minimum width. On the Boot
        # Analyzer that minimum was 791px against 724 available at the window's
        # smallest size, so the preset picker slid over the Savvy toggle.
        self._subtitle_label = label(self.SUBTITLE, role="muted", wrap=True)
        self._subtitle_label.setVisible(bool(self.SUBTITLE))
        titles.addWidget(self._subtitle_label)
        # The titles take the spare width themselves rather than leaving it to
        # a spacer. A wrapped QLabel beside a stretch is given its own guess at
        # a comfortable width, which is narrow, so "Virus signature downloads"
        # broke onto two lines with half the header empty beside it.
        row.addLayout(titles, 1)

        #: Add header buttons with `self.header_actions.addWidget(...)`.
        self.header_actions = QHBoxLayout()
        self.header_actions.setSpacing(SPACE_SM)
        row.addLayout(self.header_actions)
        return header

    def set_subtitle(self, text: str) -> None:
        self._subtitle_label.setText(text)
        self._subtitle_label.setVisible(bool(text))

    def add_header_action(self, widget: QWidget) -> None:
        self.header_actions.addWidget(widget)

    # -- lifecycle --------------------------------------------------------

    def ensure_built(self) -> None:
        """Build the page's content the first time it is shown.

        Pages are constructed eagerly but built lazily, so start-up does not
        pay for eight screens the user may never open.
        """
        if not self._built:
            self._built = True
            self.build()
            self.theme_refresh_requested.emit()

    def build(self) -> None:
        """Create the page's widgets. Called once, on first display."""

    def on_shown(self) -> None:
        """Called every time this page becomes visible. Refresh here."""

    def on_hidden(self) -> None:
        """Called when the user navigates away. Stop timers and tails here."""

    def shutdown(self) -> None:
        """Called once, when the application is quitting.

        Release anything that outlives a widget — an open database handle, a
        file being tailed. Most pages need nothing here; the ones that own a
        connection do, or Python complains about it at interpreter exit.
        """

    def badge(self) -> str:
        """Text for the sidebar badge, or "" for none."""
        return ""

    # -- helpers ----------------------------------------------------------

    def make_responsive(self, row: QBoxLayout, *, inset: int = 0) -> None:
        """Lay `row` out side by side while its items fit, and stacked when not.

        A QHBoxLayout of cards has a minimum width equal to all of their
        minimums added together, and inside a scroll area with no horizontal
        scrollbar anything past the viewport is simply cut off. At the window's
        minimum size that cut the Updates page's third signature card in half
        and clipped the right edge of every Dashboard card. This flips the
        row's direction instead, decided from the minimum widths the items
        actually report — not a guessed breakpoint that goes stale.

        `inset` is any extra horizontal space the row sits inside beyond the
        page body's own margins, such as a card's padding.
        """
        self._responsive_rows.append((row, inset))
        self._apply_responsive()

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt API
        super().resizeEvent(event)
        self._apply_responsive()

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt API
        # A card filling with data grows its minimum width without resizing
        # anything, so a row decided "side by side" while its cards were empty
        # stayed that way — which is exactly how the Updates page kept clipping
        # after its row was made responsive. Qt posts LayoutRequest whenever
        # the content's layout needs redoing; re-decide then, once per burst.
        if (watched is self._content and self._responsive_rows
                and event.type() == QEvent.Type.LayoutRequest
                and not self._responsive_pending):
            self._responsive_pending = True
            # With `self` as the context object, Qt cancels the call if the
            # page is destroyed first. A bare bound method ran against a
            # deleted page whenever the window closed with a re-check pending.
            QTimer.singleShot(0, self, self._run_pending_responsive)
        return super().eventFilter(watched, event)

    def _run_pending_responsive(self) -> None:
        self._responsive_pending = False
        self._apply_responsive()

    def _apply_responsive(self) -> None:
        if not self._responsive_rows:
            return
        # The body's side margins, and room for the vertical scrollbar.
        available = self.width() - 2 * SPACE_XL - RESPONSIVE_SCROLLBAR_ALLOWANCE
        for row, inset in self._responsive_rows:
            widgets = []
            for index in range(row.count()):
                widget = row.itemAt(index).widget()
                if widget is not None and not widget.isHidden():
                    widgets.append(widget)
            if not widgets:
                continue
            needed = (sum(widget.minimumSizeHint().width() for widget in widgets)
                      + row.spacing() * (len(widgets) - 1))
            direction = (QBoxLayout.Direction.LeftToRight
                         if needed <= available - inset
                         else QBoxLayout.Direction.TopToBottom)
            if row.direction() != direction:
                row.setDirection(direction)

    def add_stretch(self) -> None:
        """Push everything above to the top of the page."""
        self.body.addStretch(1)

    def clear_body(self) -> None:
        """Remove every widget from the body layout."""
        while self.body.count():
            item = self.body.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
