"""The look of ClamGuard: design tokens in, Qt stylesheet out.

Every colour, radius and spacing value in the app comes from here. If you want
to restyle ClamGuard you should only ever need to touch this file and the SVGs
in resources/icons.

How it works:

    Palette   a frozen set of named colours (one for light, one for dark)
    ACCENTS   the user-selectable highlight colour
    QSS       a string.Template using $tokens, filled from the palette

Using string.Template rather than str.format keeps the stylesheet readable —
QSS is full of ``{`` and ``}`` and doubling them all would be miserable.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from string import Template

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFontDatabase, QGuiApplication, QPalette

from ..core import paths


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Palette:
    """Named colours for one appearance mode. All values are #rrggbb."""

    name: str
    is_dark: bool

    bg: str           # the window behind everything
    sidebar: str      # navigation rail
    surface: str      # cards, panels
    surface_2: str    # inputs, subtle fills, hover
    surface_3: str    # pressed, selected rows
    border: str       # visible dividers and input outlines
    border_soft: str  # barely-there separators

    text: str         # primary copy
    text_dim: str     # secondary copy, labels
    text_faint: str   # placeholders, disabled

    ok: str
    warn: str
    danger: str
    info: str

    shadow: str       # rgba() string, used sparingly


DARK = Palette(
    name="dark",
    is_dark=True,
    bg="#10131a",
    sidebar="#0b0e14",
    surface="#171b24",
    surface_2="#1e2430",
    surface_3="#262d3b",
    border="#272f3d",
    border_soft="#1c2029",
    text="#e8ecf4",
    text_dim="#97a1b2",
    text_faint="#6b7688",
    ok="#2ed47a",
    warn="#ffb020",
    danger="#ff5c5c",
    info="#4c9aff",
    shadow="rgba(0, 0, 0, 110)",
)

LIGHT = Palette(
    name="light",
    is_dark=False,
    bg="#f2f4f8",
    sidebar="#ffffff",
    surface="#ffffff",
    surface_2="#f0f3f8",
    surface_3="#e3e9f2",
    border="#dde3ec",
    border_soft="#e9edf4",
    text="#101623",
    text_dim="#5a6579",
    text_faint="#8a94a6",
    ok="#15a34a",
    warn="#d97706",
    danger="#dc2626",
    info="#2563eb",
    shadow="rgba(16, 22, 35, 28)",
)


#: Selectable highlight colours: name -> (base, hover, pressed).
ACCENTS: dict[str, tuple[str, str, str]] = {
    "blue": ("#3b82f6", "#5a97f8", "#2f6fe0"),
    "teal": ("#14b8a6", "#2ecfbd", "#0f9a8b"),
    "green": ("#22a55a", "#31be6d", "#1a8a4a"),
    "purple": ("#8b5cf6", "#a079f8", "#7443e0"),
    "orange": ("#f97316", "#fb8b3c", "#dd5f0a"),
    "crimson": ("#e11d48", "#ec3f65", "#be123c"),
}
DEFAULT_ACCENT = "blue"

#: Spacing scale, in device-independent pixels. Use these, not magic numbers.
SPACE_XS, SPACE_SM, SPACE_MD, SPACE_LG, SPACE_XL = 4, 8, 14, 20, 28

#: Corner radii.
RADIUS_SM, RADIUS_MD, RADIUS_LG = 6, 10, 16

#: Preferred font families, first match wins.
UI_FONT_STACK = ("Inter", "Noto Sans", "Cantarell", "DejaVu Sans", "Sans Serif")
MONO_FONT_STACK = ("JetBrains Mono", "Fira Code", "Source Code Pro", "Noto Sans Mono", "monospace")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def with_alpha(hex_colour: str, alpha: float) -> str:
    """``#rrggbb`` plus an alpha 0.0-1.0 as a QSS ``rgba(...)`` string."""
    colour = QColor(hex_colour)
    return f"rgba({colour.red()}, {colour.green()}, {colour.blue()}, {alpha:.3f})"


def mix(first: str, second: str, ratio: float) -> str:
    """Blend two hex colours. ratio=0 returns `first`, ratio=1 returns `second`."""
    a, b = QColor(first), QColor(second)
    blended = QColor(
        round(a.red() + (b.red() - a.red()) * ratio),
        round(a.green() + (b.green() - a.green()) * ratio),
        round(a.blue() + (b.blue() - a.blue()) * ratio),
    )
    return blended.name()


def pick_font(stack: tuple[str, ...], fallback: str) -> str:
    """First installed family from `stack`."""
    available = set(QFontDatabase.families())
    for family in stack:
        if family in available:
            return family
    return fallback


def system_prefers_dark() -> bool:
    """Ask the desktop whether it is in dark mode.

    Qt 6.5+ exposes this through QStyleHints. On a desktop that does not report
    it we fall back to inspecting the default palette's window colour.
    """
    hints = QGuiApplication.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if callable(scheme):
        try:
            return scheme() == Qt.ColorScheme.Dark
        except (AttributeError, TypeError):
            pass
    window = QGuiApplication.palette().color(QPalette.ColorRole.Window)
    return window.lightness() < 128


def resolve_palette(theme_setting: str) -> Palette:
    """Map the user's "auto"/"light"/"dark" preference to a Palette."""
    if theme_setting == "light":
        return LIGHT
    if theme_setting == "dark":
        return DARK
    return DARK if system_prefers_dark() else LIGHT


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------


#: QSS can colour a widget but it cannot draw a shape, so the few glyphs the
#: stylesheet needs — a tick in a checkbox, an arrow on a combo box — are
#: generated as tiny SVGs into the cache directory, one per colour. That keeps
#: them in step with the palette instead of shipping a fixed set of images.
_GLYPHS = {
    "check": ('<path d="M4 12.5 L9.5 18 L20 6.5"/>', 3.4),
    "chevron-down": ('<path d="M5 9 L12 16 L19 9"/>', 2.6),
    "chevron-up": ('<path d="M5 15 L12 8 L19 15"/>', 2.6),
}

_GLYPH_TEMPLATE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
    'stroke="COLOUR" stroke-width="WIDTH" stroke-linecap="round" '
    'stroke-linejoin="round">BODY</svg>'
)


def _glyph_image(name: str, colour: str) -> str:
    """Write one stylesheet glyph to the cache; return a QSS-safe path."""
    body, stroke = _GLYPHS[name]
    cache = paths.CACHE_DIR / "generated"
    target = cache / f"{name}-{colour.lstrip('#')}.svg"
    if not target.is_file():
        try:
            cache.mkdir(parents=True, exist_ok=True)
            target.write_text(
                _GLYPH_TEMPLATE.replace("COLOUR", colour)
                .replace("WIDTH", str(stroke))
                .replace("BODY", body),
                encoding="utf-8",
            )
        except OSError:
            return ""
    return target.as_posix()


def build_stylesheet(palette: Palette, accent_name: str = DEFAULT_ACCENT) -> str:
    """Render the full application stylesheet for a palette and accent."""
    accent, accent_hover, accent_pressed = ACCENTS.get(accent_name, ACCENTS[DEFAULT_ACCENT])

    tokens = asdict(palette)
    tokens.pop("is_dark")
    tokens.pop("name")
    tokens.update(
        accent=accent,
        accent_hover=accent_hover,
        accent_pressed=accent_pressed,
        accent_tint=with_alpha(accent, 0.16),
        accent_tint_soft=with_alpha(accent, 0.09),
        ok_tint=with_alpha(palette.ok, 0.15),
        warn_tint=with_alpha(palette.warn, 0.15),
        danger_tint=with_alpha(palette.danger, 0.15),
        info_tint=with_alpha(palette.info, 0.15),
        overlay=with_alpha("#ffffff" if palette.is_dark else "#101623", 0.06),
        on_accent="#ffffff",
        ui_font=pick_font(UI_FONT_STACK, "Sans Serif"),
        mono_font=pick_font(MONO_FONT_STACK, "monospace"),
        r_sm=RADIUS_SM,
        r_md=RADIUS_MD,
        r_lg=RADIUS_LG,
        disabled_text=palette.text_faint,
        check_icon=_glyph_image("check", "#ffffff"),
        chevron_down=_glyph_image("chevron-down", palette.text_dim),
        chevron_up=_glyph_image("chevron-up", palette.text_dim),
    )
    return Template(_QSS).substitute(tokens)


_QSS = """
/* ======================================================================
   Base
   ====================================================================== */
QWidget {
    background: transparent;
    color: $text;
    font-family: "$ui_font";
    font-size: 10pt;
}
QMainWindow, QDialog, #rootSurface {
    background: $bg;
}
QWidget:disabled { color: $disabled_text; }

QToolTip {
    background: $surface_3;
    color: $text;
    border: 1px solid $border;
    border-radius: ${r_sm}px;
    padding: 5px 8px;
}

/* ======================================================================
   Typography helpers — set via  label.setProperty("role", "...")
   ====================================================================== */
QLabel[role="display"] { font-size: 26pt; font-weight: 600; color: $text; }
QLabel[role="title"]   { font-size: 17pt; font-weight: 600; color: $text; }
QLabel[role="heading"] { font-size: 12pt; font-weight: 600; color: $text; }
QLabel[role="body"]    { font-size: 10pt; color: $text; }
QLabel[role="muted"]   { font-size:  9pt; color: $text_dim; }
QLabel[role="caption"] { font-size: 8.5pt; color: $text_faint; }
QLabel[role="metric"]  { font-size: 20pt; font-weight: 600; color: $text; }
QLabel[role="mono"]    { font-family: "$mono_font"; font-size: 9pt; color: $text_dim; }
QLabel[role="sectionLabel"] {
    font-size: 8.5pt; font-weight: 700; color: $text_faint;
    letter-spacing: 1px; text-transform: uppercase;
}
QLabel[tone="ok"]     { color: $ok; }
QLabel[tone="warn"]   { color: $warn; }
QLabel[tone="danger"] { color: $danger; }
QLabel[tone="info"]   { color: $info; }
QLabel[tone="accent"] { color: $accent; }

/* ======================================================================
   Sidebar
   ====================================================================== */
#sidebar {
    background: $sidebar;
    border-right: 1px solid $border_soft;
}
#sidebarBrand { padding: 2px 0; }
#navButton {
    background: transparent;
    border: none;
    border-radius: ${r_md}px;
    padding: 9px 12px;
    text-align: left;
    font-size: 10pt;
    font-weight: 500;
    color: $text_dim;
}
#navButton:hover { background: $overlay; color: $text; }
#navButton:checked {
    background: $accent_tint;
    color: $accent;
    font-weight: 600;
}
#navBadge {
    background: $danger;
    color: #ffffff;
    border-radius: 8px;
    padding: 1px 6px;
    font-size: 8pt;
    font-weight: 700;
}

/* ======================================================================
   Cards and panels
   ====================================================================== */
#card, QFrame[card="true"] {
    background: $surface;
    border: 1px solid $border;
    border-radius: ${r_lg}px;
}
QFrame[card="flat"] {
    background: $surface_2;
    border: 1px solid $border_soft;
    border-radius: ${r_md}px;
}
QFrame[card="tint-ok"]     { background: $ok_tint;     border: 1px solid $ok;     border-radius: ${r_lg}px; }
QFrame[card="tint-warn"]   { background: $warn_tint;   border: 1px solid $warn;   border-radius: ${r_lg}px; }
QFrame[card="tint-danger"] { background: $danger_tint; border: 1px solid $danger; border-radius: ${r_lg}px; }
QFrame[card="tint-info"]   { background: $info_tint;   border: 1px solid $info;   border-radius: ${r_lg}px; }

#hLine { background: $border_soft; max-height: 1px; border: none; }
#vLine { background: $border_soft; max-width: 1px; border: none; }

#pageHeader { background: $bg; border-bottom: 1px solid $border_soft; }

/* ======================================================================
   Buttons
   ====================================================================== */
QPushButton {
    background: $surface_2;
    color: $text;
    border: 1px solid $border;
    border-radius: ${r_md}px;
    padding: 8px 16px;
    font-size: 10pt;
    font-weight: 500;
    min-height: 18px;
}
QPushButton:hover   { background: $surface_3; }
QPushButton:pressed { background: $surface_3; border-color: $accent; }
QPushButton:disabled { color: $disabled_text; background: $surface_2; border-color: $border_soft; }

QPushButton[variant="primary"] {
    background: $accent; color: $on_accent; border: 1px solid $accent; font-weight: 600;
}
QPushButton[variant="primary"]:hover   { background: $accent_hover; border-color: $accent_hover; }
QPushButton[variant="primary"]:pressed { background: $accent_pressed; border-color: $accent_pressed; }
QPushButton[variant="primary"]:disabled { background: $surface_3; color: $disabled_text; border-color: $border; }

QPushButton[variant="danger"] {
    background: $danger; color: #ffffff; border: 1px solid $danger; font-weight: 600;
}
QPushButton[variant="danger"]:hover   { background: $danger; border-color: $danger; }
QPushButton[variant="danger"]:disabled { background: $surface_3; color: $disabled_text; border-color: $border; }

QPushButton[variant="ghost"] {
    background: transparent; border: 1px solid transparent; color: $text_dim; padding: 6px 10px;
}
QPushButton[variant="ghost"]:hover { background: $overlay; color: $text; }

QPushButton[variant="link"] {
    background: transparent; border: none; color: $accent; padding: 2px 4px;
    text-align: left; font-weight: 500;
}
QPushButton[variant="link"]:hover { color: $accent_hover; }

QPushButton[size="lg"] { padding: 12px 24px; font-size: 11pt; }

QToolButton {
    background: transparent; border: 1px solid transparent;
    border-radius: ${r_sm}px; padding: 5px;
}
QToolButton:hover { background: $overlay; }
QToolButton:pressed { background: $surface_3; }
QToolButton:checked { background: $accent_tint; }

/* ======================================================================
   Inputs
   ====================================================================== */
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox, QTimeEdit, QDateEdit {
    background: $surface_2;
    border: 1px solid $border;
    border-radius: ${r_md}px;
    padding: 7px 10px;
    color: $text;
    selection-background-color: $accent;
    selection-color: $on_accent;
}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus,
QDoubleSpinBox:focus, QComboBox:focus, QTimeEdit:focus, QDateEdit:focus {
    border-color: $accent;
    background: $surface;
}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {
    color: $disabled_text; background: $surface_2; border-color: $border_soft;
}
QLineEdit[state="error"], QSpinBox[state="error"] { border-color: $danger; }

QComboBox::drop-down {
    border: none; width: 26px; subcontrol-origin: padding; subcontrol-position: center right;
}
QComboBox::down-arrow { image: url("$chevron_down"); width: 12px; height: 12px; }
QComboBox::down-arrow:disabled { image: none; }
QComboBox QAbstractItemView {
    background: $surface;
    border: 1px solid $border;
    border-radius: ${r_md}px;
    padding: 4px;
    outline: none;
    selection-background-color: $accent_tint;
    selection-color: $text;
}
QSpinBox::up-button, QDoubleSpinBox::up-button, QTimeEdit::up-button,
QSpinBox::down-button, QDoubleSpinBox::down-button, QTimeEdit::down-button {
    width: 20px; border: none; background: transparent;
}
QSpinBox::up-arrow, QDoubleSpinBox::up-arrow, QTimeEdit::up-arrow {
    image: url("$chevron_up"); width: 10px; height: 10px;
}
QSpinBox::down-arrow, QDoubleSpinBox::down-arrow, QTimeEdit::down-arrow {
    image: url("$chevron_down"); width: 10px; height: 10px;
}

QCheckBox, QRadioButton { spacing: 8px; color: $text; padding: 2px; }
QCheckBox::indicator, QRadioButton::indicator { width: 17px; height: 17px; }
QCheckBox::indicator {
    border: 1.5px solid $text_faint; border-radius: 5px; background: $surface_2;
}
QCheckBox::indicator:hover { border-color: $accent; }
QCheckBox::indicator:checked {
    background: $accent; border-color: $accent;
    image: url("$check_icon");
}
QCheckBox::indicator:disabled { border-color: $border; background: $surface_2; }
QRadioButton::indicator {
    border: 1.5px solid $text_faint; border-radius: 9px; background: $surface_2;
}
QRadioButton::indicator:checked { border: 5px solid $accent; background: $surface; }
QRadioButton::indicator:hover { border-color: $accent; }

QGroupBox {
    border: 1px solid $border; border-radius: ${r_md}px;
    margin-top: 18px; padding: 14px 12px 10px 12px; font-weight: 600;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: $text_dim; }

/* ======================================================================
   Tables and lists
   ====================================================================== */
QAbstractItemView {
    background: $surface;
    alternate-background-color: $surface_2;
    border: 1px solid $border;
    border-radius: ${r_md}px;
    outline: none;
    selection-background-color: $accent_tint;
    selection-color: $text;
    gridline-color: $border_soft;
}
QTableView::item, QTreeView::item, QListView::item {
    padding: 7px 8px; border: none; border-bottom: 1px solid $border_soft;
}
QTableView::item:selected, QTreeView::item:selected, QListView::item:selected {
    background: $accent_tint; color: $text;
}
QHeaderView::section {
    background: $surface_2;
    color: $text_dim;
    border: none;
    border-bottom: 1px solid $border;
    border-right: 1px solid $border_soft;
    padding: 8px;
    font-size: 9pt;
    font-weight: 600;
}
QHeaderView::section:last { border-right: none; }
QTableCornerButton::section { background: $surface_2; border: none; }

/* ======================================================================
   Scrollbars
   ====================================================================== */
QScrollBar:vertical   { background: transparent; width: 11px; margin: 2px; }
QScrollBar:horizontal { background: transparent; height: 11px; margin: 2px; }
QScrollBar::handle:vertical, QScrollBar::handle:horizontal {
    background: $surface_3; border-radius: 4px; min-height: 28px; min-width: 28px;
}
QScrollBar::handle:hover { background: $text_faint; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; border: none; background: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
QScrollArea { border: none; background: transparent; }
QScrollArea > QWidget > QWidget { background: transparent; }

/* ======================================================================
   Progress
   ====================================================================== */
QProgressBar {
    background: $surface_3;
    border: none;
    border-radius: 5px;
    height: 8px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk { background: $accent; border-radius: 5px; }
QProgressBar[tone="ok"]::chunk     { background: $ok; }
QProgressBar[tone="warn"]::chunk   { background: $warn; }
QProgressBar[tone="danger"]::chunk { background: $danger; }

/* ======================================================================
   Tabs
   ====================================================================== */
QTabWidget::pane { border: none; background: transparent; }
QTabBar::tab {
    background: transparent;
    color: $text_dim;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 9px 16px;
    font-weight: 500;
}
QTabBar::tab:hover { color: $text; }
QTabBar::tab:selected { color: $accent; border-bottom-color: $accent; font-weight: 600; }

/* ======================================================================
   Menus
   ====================================================================== */
QMenu {
    background: $surface;
    border: 1px solid $border;
    border-radius: ${r_md}px;
    padding: 6px;
}
QMenu::item { padding: 7px 26px 7px 12px; border-radius: ${r_sm}px; color: $text; }
QMenu::item:selected { background: $accent_tint; color: $text; }
QMenu::item:disabled { color: $disabled_text; }
QMenu::separator { height: 1px; background: $border_soft; margin: 5px 8px; }
QMenu::icon { padding-left: 8px; }

/* ======================================================================
   Badges — label.setProperty("badge", "ok"|"warn"|"danger"|"info"|"neutral")
   ====================================================================== */
QLabel[badge] {
    border-radius: ${r_sm}px; padding: 3px 9px; font-size: 8.5pt; font-weight: 600;
}
QLabel[badge="ok"]      { background: $ok_tint;     color: $ok; }
QLabel[badge="warn"]    { background: $warn_tint;   color: $warn; }
QLabel[badge="danger"]  { background: $danger_tint; color: $danger; }
QLabel[badge="info"]    { background: $info_tint;   color: $info; }
QLabel[badge="accent"]  { background: $accent_tint; color: $accent; }
QLabel[badge="neutral"] { background: $surface_3;   color: $text_dim; }

/* ======================================================================
   Log / code views
   ====================================================================== */
QPlainTextEdit[role="log"] {
    font-family: "$mono_font";
    font-size: 9pt;
    background: $surface_2;
    border: 1px solid $border;
    border-radius: ${r_md}px;
    padding: 10px;
    color: $text_dim;
}

/* ======================================================================
   Hunt — the query page
   ====================================================================== */
#huntToolbar {
    background: $surface;
    border-bottom: 1px solid $border_soft;
}
#huntStatus {
    background: $sidebar;
    border-top: 1px solid $border_soft;
}
#huntRail {
    background: $sidebar;
    border-right: 1px solid $border_soft;
}
#insightsBar { background: $surface; }

#railTabs::tab {
    background: transparent;
    color: $text_dim;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 6px 11px;
    font-size: 9pt;
    font-weight: 500;
}
#railTabs::tab:hover { color: $text; }
#railTabs::tab:selected {
    color: $accent; border-bottom-color: $accent; font-weight: 600;
}

#railTree {
    background: transparent;
    border: none;
    outline: none;
    font-size: 9pt;
}
#railTree::item {
    padding: 4px 4px;
    border: none;
    border-radius: ${r_sm}px;
    color: $text_dim;
}
#railTree::item:hover { background: $overlay; color: $text; }
#railTree::item:selected { background: $accent_tint; color: $text; }
#railTree::branch { background: transparent; }

/* The editor. Monospace and sizing are set in code, because the gutter has
   to measure the same font the document uses. */
#kqlEditor {
    background: $surface;
    border: none;
    border-bottom: 1px solid $border_soft;
    padding: 6px 8px 6px 4px;
    selection-background-color: $accent;
    selection-color: $on_accent;
}
#kqlEditor:focus { border-bottom-color: $accent; }

#completerPopup {
    background: $surface;
    border: 1px solid $border;
    border-radius: ${r_md}px;
    padding: 4px;
    outline: none;
    font-family: "$mono_font";
    font-size: 9pt;
    selection-background-color: $accent_tint;
    selection-color: $text;
}
#completerPopup::item { padding: 5px 8px; border-radius: ${r_sm}px; }

#resultsGrid {
    background: $surface;
    alternate-background-color: $surface_2;
    border: none;
    outline: none;
    font-size: 9pt;
    gridline-color: $border_soft;
}
#resultsGrid::item {
    padding: 4px 8px;
    border: none;
    border-bottom: 1px solid $border_soft;
}
#resultsGrid::item:selected { background: $accent_tint; color: $text; }
#resultsGrid QHeaderView::section {
    padding: 6px 8px;
    font-size: 8.5pt;
}

#huntChart { background: $surface; }

/* ======================================================================
   Splitter, status bar, tray menu
   ====================================================================== */
QSplitter::handle { background: $border_soft; }
QSplitter::handle:horizontal { width: 1px; }
QSplitter::handle:vertical { height: 1px; }
QStatusBar { background: $sidebar; color: $text_dim; border-top: 1px solid $border_soft; }
QStatusBar::item { border: none; }
"""
