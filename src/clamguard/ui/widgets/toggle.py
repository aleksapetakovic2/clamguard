"""A real on/off switch.

Qt stylesheets cannot draw a switch — there is no knob to style — so this is
painted by hand. It behaves exactly like a QCheckBox (it is one), which means
it works with keyboard focus, space to toggle, and the usual toggled signal.
"""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, QRectF, QSize, Property, Qt
from PySide6.QtGui import QColor, QPainter, QPainterPath
from PySide6.QtWidgets import QCheckBox, QWidget

from ..theme import ACCENTS, DEFAULT_ACCENT, Palette, DARK


class ToggleSwitch(QCheckBox):
    """An animated switch. Same API as QCheckBox."""

    WIDTH = 42
    HEIGHT = 23
    MARGIN = 2

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self._position = 0.0
        self._palette = DARK
        self._accent = ACCENTS[DEFAULT_ACCENT][0]
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._animation = QPropertyAnimation(self, b"knob_position", self)
        self._animation.setDuration(150)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.toggled.connect(self._animate_to)

    # -- theming ----------------------------------------------------------

    def apply_palette(self, palette: Palette, accent_name: str) -> None:
        """Called when the theme changes."""
        self._palette = palette
        self._accent = ACCENTS.get(accent_name, ACCENTS[DEFAULT_ACCENT])[0]
        self.update()

    # -- the animated property -------------------------------------------

    def _get_knob_position(self) -> float:
        return self._position

    def _set_knob_position(self, value: float) -> None:
        self._position = value
        self.update()

    #: 0.0 is off, 1.0 is on. Animated by _animate_to.
    knob_position = Property(float, _get_knob_position, _set_knob_position)

    def _animate_to(self, checked: bool) -> None:
        self._animation.stop()
        self._animation.setStartValue(self._position)
        self._animation.setEndValue(1.0 if checked else 0.0)
        self._animation.start()

    def setChecked(self, checked: bool) -> None:  # noqa: N802 - Qt naming
        super().setChecked(checked)
        # Jump straight there when set programmatically before the widget is
        # visible, so the first paint is not mid-animation.
        if not self.isVisible():
            self._animation.stop()
            self._set_knob_position(1.0 if checked else 0.0)

    # -- geometry and painting -------------------------------------------

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt naming
        base = super().sizeHint()
        text_width = base.width() if self.text() else 0
        return QSize(self.WIDTH + (text_width + 8 if self.text() else 0),
                     max(self.HEIGHT, base.height()))

    def hitButton(self, position) -> bool:  # noqa: N802 - Qt naming
        return self.contentsRect().contains(position)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        track = QRectF(0, (self.height() - self.HEIGHT) / 2, self.WIDTH, self.HEIGHT)
        radius = track.height() / 2

        enabled = self.isEnabled()
        off_colour = QColor(self._palette.surface_3)
        on_colour = QColor(self._accent)
        track_colour = _blend(off_colour, on_colour, self._position)
        if not enabled:
            track_colour.setAlpha(110)

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(track_colour)
        path = QPainterPath()
        path.addRoundedRect(track, radius, radius)
        painter.drawPath(path)

        travel = self.WIDTH - self.HEIGHT
        knob_x = track.left() + self.MARGIN + travel * self._position
        knob = QRectF(knob_x, track.top() + self.MARGIN,
                      self.HEIGHT - self.MARGIN * 2, self.HEIGHT - self.MARGIN * 2)
        knob_colour = QColor("#ffffff")
        if not enabled:
            knob_colour.setAlpha(150)
        painter.setBrush(knob_colour)
        painter.drawEllipse(knob)

        if self.text():
            painter.setPen(QColor(self._palette.text if enabled else self._palette.text_faint))
            text_rect = self.rect().adjusted(self.WIDTH + 8, 0, 0, 0)
            painter.drawText(text_rect,
                             int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter),
                             self.text())
        painter.end()


def _blend(first: QColor, second: QColor, ratio: float) -> QColor:
    ratio = max(0.0, min(1.0, ratio))
    return QColor(
        round(first.red() + (second.red() - first.red()) * ratio),
        round(first.green() + (second.green() - first.green()) * ratio),
        round(first.blue() + (second.blue() - first.blue()) * ratio),
    )
