"""Bundled SVG icons, recoloured to match the current theme.

ClamGuard ships its own icons instead of using the desktop icon theme, so it
looks the same on KDE, GNOME, XFCE or a bare window manager, and so a missing
icon can never leave a blank button.

Every SVG in resources/icons uses ``stroke="currentColor"``. At load time we
substitute a real colour and rasterise with QSvgRenderer. Results are cached,
because pages ask for the same icon many times.

Usage::

    from ..icons import icon
    button.setIcon(icon("scan"))              # default text colour
    button.setIcon(icon("trash", tone="danger"))
    button.setIcon(icon("check", "#00ff00", size=32))
"""

from __future__ import annotations

from functools import lru_cache

from PySide6.QtCore import QByteArray, QRectF, QSize, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from ..core import paths
from ..core.logging_setup import get_logger
from . import theme

log = get_logger(__name__)

ICON_DIR = paths.package_resource("icons")
DEFAULT_SIZE = 20

#: Filled in by apply_theme(); every icon(name) with no explicit colour uses it.
_tone_colours: dict[str, str] = {
    "default": theme.DARK.text,
    "muted": theme.DARK.text_dim,
    "faint": theme.DARK.text_faint,
    "ok": theme.DARK.ok,
    "warn": theme.DARK.warn,
    "danger": theme.DARK.danger,
    "info": theme.DARK.info,
    "accent": theme.ACCENTS[theme.DEFAULT_ACCENT][0],
    "on_accent": "#ffffff",
}


def configure(palette: theme.Palette, accent_name: str) -> None:
    """Point the icon tones at a palette. Called whenever the theme changes."""
    accent = theme.ACCENTS.get(accent_name, theme.ACCENTS[theme.DEFAULT_ACCENT])[0]
    _tone_colours.update(
        default=palette.text,
        muted=palette.text_dim,
        faint=palette.text_faint,
        ok=palette.ok,
        warn=palette.warn,
        danger=palette.danger,
        info=palette.info,
        accent=accent,
    )
    _render_pixmap.cache_clear()


def available() -> list[str]:
    """Names of every bundled icon, without the .svg suffix."""
    if not ICON_DIR.is_dir():
        return []
    return sorted(path.stem for path in ICON_DIR.glob("*.svg"))


@lru_cache(maxsize=256)
def _svg_source(name: str) -> str:
    """Raw SVG text for an icon name, or a blank document if it is missing."""
    path = ICON_DIR / f"{name}.svg"
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        log.warning("missing icon %r", name)
        return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"></svg>'


@lru_cache(maxsize=1024)
def _render_pixmap(name: str, colour: str, size: int, ratio_x100: int) -> QPixmap:
    """Rasterise one icon. Cached; the ratio is part of the key for HiDPI."""
    ratio = ratio_x100 / 100.0
    source = _svg_source(name).replace('stroke="currentColor"', f'stroke="{colour}"')
    source = source.replace('fill="currentColor"', f'fill="{colour}"')

    renderer = QSvgRenderer(QByteArray(source.encode("utf-8")))
    pixels = max(1, int(round(size * ratio)))
    pixmap = QPixmap(pixels, pixels)
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    renderer.render(painter, QRectF(0, 0, pixels, pixels))
    painter.end()
    return pixmap


def pixmap(name: str, colour: str | None = None, *, tone: str = "default",
           size: int = DEFAULT_SIZE, ratio: float = 2.0) -> QPixmap:
    """A single rasterised icon image."""
    resolved = colour or _tone_colours.get(tone, _tone_colours["default"])
    return _render_pixmap(name, resolved, size, int(round(ratio * 100)))


def icon(name: str, colour: str | None = None, *, tone: str = "default",
         size: int = DEFAULT_SIZE) -> QIcon:
    """A QIcon for `name`, coloured by `colour` or by a theme `tone`.

    We add both 1x and 2x pixmaps so the icon stays crisp when the window moves
    to a HiDPI screen.
    """
    result = QIcon()
    for ratio in (1.0, 2.0):
        result.addPixmap(pixmap(name, colour, tone=tone, size=size, ratio=ratio))
    return result


def render(painter: QPainter, rect, name: str, colour: str | None = None,
           *, tone: str = "default") -> None:
    """Draw an icon straight into a painter, at whatever size `rect` is.

    Preferred over building a QPixmap for a QLabel: QLabel mis-positions a
    pixmap whose devicePixelRatio is not 1, and painting the SVG directly is
    crisp at every scale with no cache to invalidate.
    """
    resolved = colour or _tone_colours.get(tone, _tone_colours["default"])
    source = _svg_source(name).replace('stroke="currentColor"', f'stroke="{resolved}"')
    source = source.replace('fill="currentColor"', f'fill="{resolved}"')
    renderer = QSvgRenderer(QByteArray(source.encode("utf-8")))
    renderer.render(painter, QRectF(rect))


def icon_size(size: int = DEFAULT_SIZE) -> QSize:
    """Convenience for ``setIconSize``."""
    return QSize(size, size)


#: The application logo, drawn rather than loaded, so it needs no extra file
#: and picks up the user's accent colour.
_LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="$light"/>
      <stop offset="1" stop-color="$base"/>
    </linearGradient>
  </defs>
  <path d="M32 4 L55 14 v17c0 13.6-9.4 23.6-23 28C18.4 54.6 9 44.6 9 31V14Z" fill="url(#g)"/>
  <path d="M32 10.5 L49 18 v13c0 10.4-7 18.2-17 21.8C22 49.2 15 41.4 15 31V18Z"
        fill="none" stroke="#ffffff" stroke-opacity=".35" stroke-width="1.6"/>
  <path d="M22.5 32.5 L29 39 L42 24.5" fill="none" stroke="#ffffff" stroke-width="5.2"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""


def logo(size: int = 64, accent_name: str | None = None) -> QIcon:
    """The ClamGuard shield, tinted with the current accent colour."""
    name = accent_name or "blue"
    base, light, _ = theme.ACCENTS.get(name, theme.ACCENTS[theme.DEFAULT_ACCENT])
    source = _LOGO_SVG.replace("$base", base).replace("$light", light)

    result = QIcon()
    for ratio in (1.0, 2.0):
        renderer = QSvgRenderer(QByteArray(source.encode("utf-8")))
        pixels = int(round(size * ratio))
        image = QPixmap(pixels, pixels)
        image.setDevicePixelRatio(ratio)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        renderer.render(painter, QRectF(0, 0, pixels, pixels))
        painter.end()
        result.addPixmap(image)
    return result


def logo_svg(accent_name: str = "blue") -> str:
    """The logo as SVG text — used when writing the .desktop icon file."""
    base, light, _ = theme.ACCENTS.get(accent_name, theme.ACCENTS[theme.DEFAULT_ACCENT])
    return _LOGO_SVG.replace("$base", base).replace("$light", light)
