"""The navigation rail.

A vertical list of pages with an optional badge on each, plus the app's
identity at the top and a live protection indicator at the bottom. The bottom
indicator is deliberately always visible: whatever page you are on, you can see
whether the machine is covered without navigating anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from . import icons
from .theme import SPACE_MD, SPACE_SM, SPACE_XS
from .widgets import IconLabel, Separator, label, restyle


@dataclass(frozen=True)
class NavItem:
    """One entry in the rail."""

    page_id: str
    title: str
    icon: str
    #: Items after a separator are grouped at the bottom (configuration etc.).
    section: str = "main"


class NavButton(QPushButton):
    """A sidebar entry: icon, label, optional count badge."""

    def __init__(self, item: NavItem, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.item = item
        self.setObjectName("navButton")
        self.setCheckable(True)
        self.setAutoExclusive(False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setIconSize(QSize(18, 18))

        row = QHBoxLayout(self)
        row.setContentsMargins(34, 0, 10, 0)
        row.setSpacing(SPACE_SM)
        row.addStretch(1)

        self._badge = QLabel()
        self._badge.setTextFormat(Qt.TextFormat.PlainText)
        self._badge.setObjectName("navBadge")
        self._badge.setVisible(False)
        row.addWidget(self._badge)

        self.setText(item.title)
        self.refresh_icon()

    def refresh_icon(self) -> None:
        """Re-render the icon in the right tone for the current state."""
        tone = "accent" if self.isChecked() else "muted"
        self.setIcon(icons.icon(self.item.icon, tone=tone, size=18))

    def set_badge(self, text: str) -> None:
        self._badge.setText(text)
        self._badge.setVisible(bool(text))

    def setChecked(self, checked: bool) -> None:  # noqa: N802 - Qt naming
        super().setChecked(checked)
        self.refresh_icon()


class Sidebar(QWidget):
    """The rail itself."""

    #: A page was selected. Carries its PAGE_ID.
    selected = Signal(str)

    WIDTH = 216

    def __init__(self, items: list[NavItem], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setFixedWidth(self.WIDTH)

        self._buttons: dict[str, NavButton] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_MD, SPACE_MD, SPACE_MD, SPACE_MD)
        column.setSpacing(SPACE_XS)

        column.addWidget(self._build_brand())
        column.addSpacing(SPACE_MD)

        current_section = items[0].section if items else "main"
        for item in items:
            if item.section != current_section:
                column.addSpacing(SPACE_SM)
                column.addWidget(Separator())
                column.addSpacing(SPACE_SM)
                current_section = item.section
            button = NavButton(item)
            button.clicked.connect(lambda _checked=False, i=item: self.selected.emit(i.page_id))
            self._group.addButton(button)
            self._buttons[item.page_id] = button
            column.addWidget(button)

        column.addStretch(1)
        column.addWidget(self._build_status())

    # -- brand ------------------------------------------------------------

    def _build_brand(self) -> QWidget:
        brand = QWidget()
        brand.setObjectName("sidebarBrand")
        row = QHBoxLayout(brand)
        row.setContentsMargins(6, 4, 0, 0)
        row.setSpacing(SPACE_SM)

        self._logo = QLabel()
        self._logo.setFixedSize(QSize(26, 26))
        self._logo.setScaledContents(True)
        row.addWidget(self._logo)

        names = QVBoxLayout()
        names.setSpacing(0)
        names.addWidget(label("ClamGuard", role="heading"))
        self._engine_label = label("", role="caption")
        names.addWidget(self._engine_label)
        row.addLayout(names)
        row.addStretch(1)
        return brand

    def set_engine_text(self, text: str) -> None:
        """The small line under the app name — the ClamAV version."""
        self._engine_label.setText(text)

    def set_accent(self, accent_name: str) -> None:
        self._logo.setPixmap(icons.logo(26, accent_name).pixmap(QSize(26, 26)))

    # -- status footer ----------------------------------------------------

    def _build_status(self) -> QWidget:
        frame = QFrame()
        frame.setProperty("card", "flat")
        row = QHBoxLayout(frame)
        row.setContentsMargins(10, 8, 10, 8)
        row.setSpacing(SPACE_SM)

        self._status_icon = IconLabel("shield", tone="muted", size=18)
        row.addWidget(self._status_icon, 0, Qt.AlignmentFlag.AlignVCenter)

        texts = QVBoxLayout()
        texts.setSpacing(0)
        self._status_title = label("Checking…", role="body")
        self._status_detail = label("", role="caption")
        texts.addWidget(self._status_title)
        texts.addWidget(self._status_detail)
        row.addLayout(texts)
        row.addStretch(1)
        return frame

    def set_status(self, title: str, detail: str, tone: str, icon_name: str) -> None:
        self._status_icon.set_icon(icon_name, tone=tone)
        self._status_title.setText(title)
        self._status_title.setProperty("tone", tone)
        restyle(self._status_title)
        self._status_detail.setText(detail)

    # -- selection --------------------------------------------------------

    def select(self, page_id: str) -> None:
        button = self._buttons.get(page_id)
        if button is not None and not button.isChecked():
            button.setChecked(True)
        for identifier, item in self._buttons.items():
            item.setChecked(identifier == page_id)

    def set_badge(self, page_id: str, text: str) -> None:
        button = self._buttons.get(page_id)
        if button is not None:
            button.set_badge(text)

    def refresh_icons(self) -> None:
        """After a theme change, re-render every icon."""
        for button in self._buttons.values():
            button.refresh_icon()
