"""A circular progress indicator for the scan page.

A ring rather than a bar because a scan has three things to show at once —
how far along it is, how it is going, and a headline number — and a ring gives
the middle back for the number.

When the total is unknown (a scan that has not counted its files yet) it spins
as an indeterminate sweep instead of pretending to know.
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from ..theme import ACCENTS, DARK, DEFAULT_ACCENT, Palette


class ProgressRing(QWidget):
    """A ring with a value in the middle.

    ::

        ring.set_progress(0.42)          # 42%
        ring.set_indeterminate(True)     # still counting
        ring.set_text("42%", "scanned")
    """

    SPIN_INTERVAL_MS = 16
    SPIN_DEGREES_PER_TICK = 3

    def __init__(self, diameter: int = 160, thickness: int = 10,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._diameter = diameter
        self._thickness = thickness
        self._progress = 0.0
        self._indeterminate = False
        self._sweep_start = 0
        self._primary = ""
        self._secondary = ""
        self._tone = "accent"
        self._palette: Palette = DARK
        self._accent = ACCENTS[DEFAULT_ACCENT][0]

        self.setFixedSize(QSize(diameter, diameter))

        self._spinner = QTimer(self)
        self._spinner.setInterval(self.SPIN_INTERVAL_MS)
        self._spinner.timeout.connect(self._advance_sweep)

    # -- theming ----------------------------------------------------------

    def apply_palette(self, palette: Palette, accent_name: str) -> None:
        self._palette = palette
        self._accent = ACCENTS.get(accent_name, ACCENTS[DEFAULT_ACCENT])[0]
        self.update()

    # -- state ------------------------------------------------------------

    def set_progress(self, fraction: float) -> None:
        """0.0 to 1.0. Turns off indeterminate mode."""
        self._progress = max(0.0, min(1.0, fraction))
        if self._indeterminate:
            self.set_indeterminate(False)
        self.update()

    def set_indeterminate(self, spinning: bool) -> None:
        self._indeterminate = spinning
        if spinning:
            self._spinner.start()
        else:
            self._spinner.stop()
        self.update()

    def set_text(self, primary: str, secondary: str = "") -> None:
        self._primary = primary
        self._secondary = secondary
        self.update()

    def set_tone(self, tone: str) -> None:
        """"accent", "ok", "warn" or "danger" — colours the filled arc."""
        self._tone = tone
        self.update()

    def _advance_sweep(self) -> None:
        self._sweep_start = (self._sweep_start + self.SPIN_DEGREES_PER_TICK) % 360
        self.update()

    def _arc_colour(self) -> QColor:
        return QColor({
            "ok": self._palette.ok,
            "warn": self._palette.warn,
            "danger": self._palette.danger,
            "info": self._palette.info,
        }.get(self._tone, self._accent))

    # -- painting ---------------------------------------------------------

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        inset = self._thickness / 2 + 1
        box = QRectF(inset, inset, self.width() - inset * 2, self.height() - inset * 2)

        track = QPen(QColor(self._palette.surface_3), self._thickness)
        track.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track)
        painter.drawArc(box, 0, 360 * 16)

        arc = QPen(self._arc_colour(), self._thickness)
        arc.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(arc)
        if self._indeterminate:
            # A 90-degree comet chasing its tail.
            painter.drawArc(box, -self._sweep_start * 16, -90 * 16)
        elif self._progress > 0:
            painter.drawArc(box, 90 * 16, int(-self._progress * 360 * 16))

        self._draw_centre_text(painter)
        painter.end()

    def _draw_centre_text(self, painter: QPainter) -> None:
        if not self._primary and not self._secondary:
            return

        primary_font = QFont(self.font())
        primary_font.setPointSizeF(self._diameter * 0.17)
        primary_font.setWeight(QFont.Weight.DemiBold)

        secondary_font = QFont(self.font())
        secondary_font.setPointSizeF(self._diameter * 0.065)

        centre = self.rect()
        painter.setFont(primary_font)
        painter.setPen(QColor(self._palette.text))
        primary_box = centre.adjusted(0, -int(self._diameter * 0.06), 0,
                                      -int(self._diameter * 0.06))
        painter.drawText(primary_box, int(Qt.AlignmentFlag.AlignCenter), self._primary)

        if self._secondary:
            painter.setFont(secondary_font)
            painter.setPen(QColor(self._palette.text_dim))
            secondary_box = centre.adjusted(0, int(self._diameter * 0.17), 0,
                                            int(self._diameter * 0.17))
            painter.drawText(secondary_box, int(Qt.AlignmentFlag.AlignCenter), self._secondary)
