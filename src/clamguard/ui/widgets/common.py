"""The building blocks: cards, badges, labels, message bars, empty states.

Everything here is a thin wrapper over a Qt widget whose look comes from the
stylesheet in ui/theme.py via dynamic properties. Nothing paints itself, so
changing the theme restyles all of it at once.

Dynamic properties are how a widget picks a style:

    label("Ready", role="muted")          -> QLabel[role="muted"]
    Badge("Running", tone="ok")           -> QLabel[badge="ok"]
    button.setProperty("variant", "primary")

If you change a property *after* a widget is shown, call restyle() or Qt will
keep the old look.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QFontMetrics, QPainter
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import icons
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XS


def restyle(widget: QWidget) -> None:
    """Re-apply the stylesheet after a dynamic property changed."""
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def label(text: str = "", *, role: str = "body", tone: str = "",
          wrap: bool = False, selectable: bool = False) -> QLabel:
    """A styled QLabel. `role` picks the size, `tone` picks the colour."""
    item = QLabel()
    # Plain text, always. Qt's default auto-detects HTML, and almost every
    # string this application shows is attacker-influenced: file paths, threat
    # names, log lines. A file called `<img src="http://x/">` would otherwise
    # make ClamGuard fetch that URL, which is both a beacon and a flat
    # contradiction of "this app makes no network requests".
    item.setTextFormat(Qt.TextFormat.PlainText)
    item.setText(text)
    item.setProperty("role", role)
    if tone:
        item.setProperty("tone", tone)
    item.setWordWrap(wrap)
    if wrap:
        # A word-wrapped QLabel knows its height only once it knows its width,
        # and Qt layouts ignore that unless the size policy says to ask. Without
        # this, long text is silently clipped to however many lines fitted the
        # width the layout first guessed.
        policy = item.sizePolicy()
        policy.setHeightForWidth(True)
        item.setSizePolicy(policy)
    if selectable:
        item.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
    return item


def heading(text: str, subtitle: str = "") -> QWidget:
    """A heading with optional secondary line under it."""
    holder = QWidget()
    layout = QVBoxLayout(holder)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(2)
    layout.addWidget(label(text, role="heading"))
    if subtitle:
        layout.addWidget(label(subtitle, role="muted", wrap=True))
    return holder


def spacer(horizontal: bool = False) -> QWidget:
    """An expanding blank widget, for pushing things apart in a layout."""
    item = QWidget()
    if horizontal:
        item.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    else:
        item.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
    return item


class IconLabel(QWidget):
    """An icon at a fixed size, painted rather than pixmap'd.

    Use this anywhere you would have written ``QLabel`` + ``setPixmap`` for an
    icon. It is always crisp, it re-colours in one call when the theme changes,
    and it does not suffer QLabel's off-by-a-few placement of high-DPI pixmaps.
    """

    def __init__(self, name: str, *, tone: str = "default", colour: str | None = None,
                 size: int = 18, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._name = name
        self._tone = tone
        self._colour = colour
        self._size = size
        self.setFixedSize(QSize(size, size))

    def set_icon(self, name: str, *, tone: str | None = None,
                 colour: str | None = None) -> None:
        self._name = name
        if tone is not None:
            self._tone = tone
            self._colour = None
        if colour is not None:
            self._colour = colour
        self.update()

    def set_size(self, size: int) -> None:
        self._size = size
        self.setFixedSize(QSize(size, size))
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        icons.render(painter, QRectF(0, 0, self.width(), self.height()),
                     self._name, self._colour, tone=self._tone)
        painter.end()


class Separator(QFrame):
    """A one-pixel divider."""

    def __init__(self, vertical: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("vLine" if vertical else "hLine")
        if vertical:
            self.setFixedWidth(1)
            self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        else:
            self.setFixedHeight(1)
            self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)


class Badge(QLabel):
    """A small coloured pill: Running, Failed, 3 threats."""

    TONES = ("ok", "warn", "danger", "info", "accent", "neutral")

    def __init__(self, text: str = "", tone: str = "neutral", parent: QWidget | None = None):
        super().__init__(parent)
        self.setTextFormat(Qt.TextFormat.PlainText)   # see label()
        self.setText(text)
        self.setProperty("badge", tone if tone in self.TONES else "neutral")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)

    def set_state(self, text: str, tone: str = "neutral") -> None:
        """Change both the text and the colour in one call."""
        self.setText(text)
        self.setProperty("badge", tone if tone in self.TONES else "neutral")
        restyle(self)


class Card(QFrame):
    """A titled panel. The unit most pages are assembled from.

    ::

        card = Card("Signatures", "Everything ClamAV knows about", icon="database")
        card.body.addWidget(some_widget)
        card.add_action(QPushButton("Refresh"))

    The header always exists even when the card starts untitled, so
    ``set_title()`` works on a card whose title is only known once data has
    loaded. It hides itself while there is nothing in it.
    """

    def __init__(self, title: str = "", subtitle: str = "", icon: str = "",
                 tone: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("card", f"tint-{tone}" if tone else "true")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(SPACE_LG, SPACE_MD, SPACE_LG, SPACE_MD)
        outer.setSpacing(SPACE_MD)

        self._header_widget = QWidget()
        #: Header row — add extra controls with `card.add_action(...)`.
        self.header = QHBoxLayout(self._header_widget)
        self.header.setContentsMargins(0, 0, 0, 0)
        self.header.setSpacing(SPACE_SM)

        self._icon = IconLabel(icon or "info", tone=tone or "accent", size=18)
        self._icon.setVisible(bool(icon))
        self.header.addWidget(self._icon, 0, Qt.AlignmentFlag.AlignTop)

        titles = QVBoxLayout()
        titles.setSpacing(1)
        self._title_label = label(title, role="heading")
        self._title_label.setVisible(bool(title))
        titles.addWidget(self._title_label)
        self._subtitle_label = label(subtitle, role="muted", wrap=True)
        self._subtitle_label.setVisible(bool(subtitle))
        titles.addWidget(self._subtitle_label)
        self.header.addLayout(titles, 1)

        outer.addWidget(self._header_widget)
        self._header_widget.setVisible(bool(title or icon or subtitle))

        #: The content area. Add your widgets here.
        self.body = QVBoxLayout()
        self.body.setSpacing(SPACE_SM)
        outer.addLayout(self.body)

    def set_title(self, text: str) -> None:
        self._title_label.setText(text)
        self._title_label.setVisible(bool(text))
        self._refresh_header_visibility()

    def set_subtitle(self, text: str) -> None:
        self._subtitle_label.setText(text)
        self._subtitle_label.setVisible(bool(text))
        self._refresh_header_visibility()

    def set_icon(self, name: str, tone: str = "accent") -> None:
        self._icon.set_icon(name, tone=tone)
        self._icon.setVisible(bool(name))
        self._refresh_header_visibility()

    def add_action(self, widget: QWidget) -> None:
        """Put a button (or anything) at the right of the card's header."""
        self.header.addWidget(widget, 0, Qt.AlignmentFlag.AlignTop)
        self._header_widget.setVisible(True)

    def _refresh_header_visibility(self) -> None:
        has_content = (self._title_label.isVisible() or self._icon.isVisible()
                       or self._subtitle_label.isVisible()
                       or self.header.count() > 2)
        self._header_widget.setVisible(has_content)


class SectionHeader(QWidget):
    """An uppercase label used to break a long page into parts."""

    def __init__(self, text: str, action: QWidget | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, SPACE_SM, 0, 0)
        row.setSpacing(SPACE_SM)
        row.addWidget(label(text, role="sectionLabel"))
        row.addStretch(1)
        if action is not None:
            row.addWidget(action)


class KeyValueRow(QWidget):
    """``Label ............ value`` — the workhorse of every detail panel."""

    #: The key column's width. Wide enough for "Distribution ships it".
    KEY_WIDTH = 150

    def __init__(self, key: str, value: str = "", tone: str = "",
                 mono: bool = False, parent: QWidget | None = None, *,
                 key_width: int | None = None, break_anywhere: bool = False) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 2, 0, 2)
        row.setSpacing(SPACE_MD)

        self.key_label = label(key, role="muted")
        # A narrow panel can ask for less: this minimum is part of the row's
        # own minimum width, and in a 300px detail pane 150px of it was what
        # pushed the content past the viewport's edge.
        self.key_label.setMinimumWidth(self.KEY_WIDTH if key_width is None else key_width)
        self.key_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        row.addWidget(self.key_label, 0)

        role = "mono" if mono else "body"
        if break_anywhere:
            # For values that can hold one enormous unbreakable token — a list
            # of escaped device unit names — at the cost of mouse selection.
            # See widgets/wrap.py for why that trade is made deliberately.
            from .wrap import break_anywhere_label

            self.value_label = break_anywhere_label(value, role=role, tone=tone)
        else:
            self.value_label = label(value, role=role, tone=tone, wrap=True,
                                     selectable=True)
        self.value_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        row.addWidget(self.value_label, 1)

    def set_value(self, value: str, tone: str = "") -> None:
        self.value_label.setText(value)
        self.value_label.setProperty("tone", tone)
        restyle(self.value_label)


class StatTile(QWidget):
    """A big number with a caption. Used in rows of three or four."""

    def __init__(self, value: str, caption: str, tone: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        self.value_label = label(value, role="metric", tone=tone)
        self.caption_label = label(caption, role="caption")
        column.addWidget(self.value_label)
        column.addWidget(self.caption_label)

    def set_value(self, value: str, tone: str = "") -> None:
        self.value_label.setText(value)
        self.value_label.setProperty("tone", tone)
        restyle(self.value_label)


class IconButton(QToolButton):
    """A square icon-only button with a tooltip."""

    def __init__(self, icon_name: str, tooltip: str = "", tone: str = "muted",
                 size: int = 18, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._icon_name = icon_name
        self._tone = tone
        self._size = size
        self.setIcon(icons.icon(icon_name, tone=tone, size=size))
        self.setIconSize(QSize(size, size))
        self.setToolTip(tooltip)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAutoRaise(True)

    def set_icon_name(self, icon_name: str, tone: str | None = None) -> None:
        self._icon_name = icon_name
        if tone:
            self._tone = tone
        self.setIcon(icons.icon(self._icon_name, tone=self._tone, size=self._size))


class ElidedLabel(QLabel):
    """A label that shows ``/very/long/…/path.txt`` instead of overflowing.

    File paths are the main thing ClamGuard displays and they are frequently
    longer than the window, so the truncation happens in the middle where the
    least information is lost.
    """

    def __init__(self, text: str = "", mode: Qt.TextElideMode = Qt.TextElideMode.ElideMiddle,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._full_text = text
        self._mode = mode
        # See label(): these hold file paths, so never interpret them as markup.
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setMinimumWidth(40)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setText(text)

    def setText(self, text: str) -> None:  # noqa: N802 - Qt naming
        self._full_text = text
        self.setToolTip(text)
        super().setText(self._elided())

    def full_text(self) -> str:
        return self._full_text

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        super().resizeEvent(event)
        super().setText(self._elided())

    def _elided(self) -> str:
        metrics = QFontMetrics(self.font())
        return metrics.elidedText(self._full_text, self._mode, max(40, self.width() - 4))


class MessageBar(QFrame):
    """An inline notice with an optional action button.

    This is how ClamGuard reports problems: in the page, next to the thing that
    is wrong, with the fix attached. Not in a modal dialog.
    """

    #: The action button was clicked.
    actioned = Signal()
    #: The dismiss button was clicked.
    dismissed = Signal()

    ICONS = {
        "ok": "check-circle",
        "info": "info",
        "warn": "alert-triangle",
        "danger": "alert-circle",
    }

    def __init__(self, text: str = "", tone: str = "info", action_text: str = "",
                 dismissible: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._tone = tone
        self.setProperty("card", f"tint-{tone}")

        row = QHBoxLayout(self)
        row.setContentsMargins(SPACE_MD, SPACE_SM + 2, SPACE_MD, SPACE_SM + 2)
        row.setSpacing(SPACE_MD)

        self._icon = IconLabel(self.ICONS.get(tone, "info"), tone=tone, size=18)
        row.addWidget(self._icon, 0, Qt.AlignmentFlag.AlignTop)

        self._text = label(text, role="body", wrap=True)
        row.addWidget(self._text, 1)

        self._action = QPushButton(action_text)
        self._action.setProperty("variant", "primary")
        self._action.setVisible(bool(action_text))
        self._action.clicked.connect(self.actioned)
        row.addWidget(self._action, 0, Qt.AlignmentFlag.AlignTop)

        self._close = IconButton("x", "Dismiss", tone="muted", size=14)
        self._close.setVisible(dismissible)
        self._close.clicked.connect(self._on_dismiss)
        row.addWidget(self._close, 0, Qt.AlignmentFlag.AlignTop)

        self._apply_tone(tone)

    def set_message(self, text: str, tone: str | None = None,
                    action_text: str | None = None) -> None:
        self._text.setText(text)
        if action_text is not None:
            self._action.setText(action_text)
            self._action.setVisible(bool(action_text))
        if tone and tone != self._tone:
            self._apply_tone(tone)

    def _apply_tone(self, tone: str) -> None:
        self._tone = tone
        self.setProperty("card", f"tint-{tone}")
        self._icon.set_icon(self.ICONS.get(tone, "info"), tone=tone)
        restyle(self)

    def _on_dismiss(self) -> None:
        self.hide()
        self.dismissed.emit()


def fit_table(table, *, row_height: int = 44, maximum: int = 420,
              minimum: int = 110) -> None:
    """Size a table to its own rows, within limits.

    Two things Qt will not do for you: a row containing a *cell widget* (a
    button, a badge) is not measured, so the row height has to be set; and a
    table with three rows still reserves space for ten, which reads as though
    something failed to load. This does both.
    """
    table.verticalHeader().setDefaultSectionSize(row_height)
    height = table.horizontalHeader().height() + 2 * table.frameWidth() + 8
    for row in range(table.rowCount()):
        height += table.rowHeight(row)
    table.setFixedHeight(max(minimum, min(maximum, height)))


class EmptyState(QWidget):
    """What a page shows when it has nothing to show.

    An empty list with no explanation reads like a bug. This says what would go
    here and, where it makes sense, offers the button that would fill it.
    """

    #: The call-to-action button was clicked.
    actioned = Signal()

    #: Width the description wraps at.
    TEXT_WIDTH = 430

    def __init__(self, icon: str, title: str, description: str = "",
                 action_text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_LG, SPACE_LG * 2, SPACE_LG, SPACE_LG * 2)
        column.setSpacing(SPACE_SM)
        column.setAlignment(Qt.AlignmentFlag.AlignCenter)

        column.addWidget(IconLabel(icon, tone="faint", size=44), 0,
                         Qt.AlignmentFlag.AlignHCenter)
        column.addSpacing(SPACE_XS)

        title_label = label(title, role="heading")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.addWidget(title_label)

        if description:
            text = label(description, role="muted", wrap=True)
            text.setAlignment(Qt.AlignmentFlag.AlignCenter)
            # A centred widget is sized to its sizeHint and never asked for
            # height-for-width, so the width is pinned and the hint becomes the
            # real wrapped height. Without this the text is clipped mid-sentence.
            text.setFixedWidth(self.TEXT_WIDTH)
            text.setMinimumHeight(text.heightForWidth(self.TEXT_WIDTH))
            column.addWidget(text, 0, Qt.AlignmentFlag.AlignCenter)

        if action_text:
            column.addSpacing(SPACE_SM)
            button = QPushButton(action_text)
            button.setProperty("variant", "primary")
            button.clicked.connect(self.actioned)
            column.addWidget(button, 0, Qt.AlignmentFlag.AlignCenter)
