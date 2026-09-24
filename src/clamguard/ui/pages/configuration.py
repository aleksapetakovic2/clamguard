"""Editing ClamAV's own configuration files, safely.

Every option in clamd.conf and freshclam.conf is here — all 182 of them —
typed, grouped and searchable. The widget you get for an option comes from
core/conf_schema.py; the help text under it comes from the comments ClamAV
itself ships in the file, so it always matches the installed version.

Nothing is written until you press Save, and Save shows a unified diff of
exactly what will change before it asks for a password. The file on disk is
validated with clamconf and backed up with a timestamp before it is replaced,
both of which happen inside the privileged helper.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from ...core import paths
from ...core.conf_file import ConfFile, OptionDocs
from ...core.conf_schema import (
    BOOL,
    CLAMD,
    DIR,
    ENUM,
    FRESHCLAM,
    INT,
    MULTI,
    PATH,
    REGEX,
    SECONDS,
    SIZE,
    ConfOption,
    Schema,
    schema_for,
    validate,
)
from ...core.services import Role
from .. import icons
from ..config_apply import ConfigApplier
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    MessageBar,
    ToggleSwitch,
    label,
    restyle,
)
from .base import Page

#: Which units to restart after each file is saved.
RESTART_FOR = {
    CLAMD: (Role.DAEMON, Role.ONACCESS),
    FRESHCLAM: (Role.UPDATER,),
}

#: Files offered in the picker, in order.
FILES = (
    (CLAMD, "clamd.conf", "The scanning engine and real-time protection"),
    (FRESHCLAM, "freshclam.conf", "Signature downloads"),
)


class OptionEditor(QFrame):
    """One configuration option: label, control, help, default."""

    #: (key, value) where value is a str, bool, or list[str].
    changed = Signal(str, object)

    def __init__(self, option: ConfOption, value, docs: OptionDocs | None,
                 recognised: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.option = option
        self._emitting = True
        self.setProperty("card", "flat")

        column = QVBoxLayout(self)
        column.setContentsMargins(SPACE_MD, SPACE_MD, SPACE_MD, SPACE_MD)
        column.setSpacing(SPACE_SM)

        head = QHBoxLayout()
        head.setSpacing(SPACE_SM)
        titles = QVBoxLayout()
        titles.setSpacing(1)
        titles.addWidget(label(option.label, role="body"))
        titles.addWidget(label(option.key, role="mono"))
        head.addLayout(titles, 1)

        if option.sensitive:
            head.addWidget(Badge("Careful", "warn"))
        if option.advanced:
            head.addWidget(Badge("Advanced", "neutral"))
        if not recognised:
            badge = Badge("Unknown to this ClamAV", "neutral")
            badge.setToolTip(
                "This option is not in the configuration file shipped with the "
                "installed ClamAV. Setting it may be ignored, or may stop the "
                "service from starting.")
            head.addWidget(badge)

        self.control = self._build_control(value)
        if option.kind is BOOL:
            head.addWidget(self.control, 0, Qt.AlignmentFlag.AlignVCenter)
        column.addLayout(head)
        if option.kind is not BOOL:
            column.addWidget(self.control)

        self.error_label = label("", role="caption", tone="danger")
        self.error_label.setVisible(False)
        column.addWidget(self.error_label)

        help_text = self._help_text(docs)
        if help_text:
            column.addWidget(label(help_text, role="caption", wrap=True))

        if option.hint:
            hint_row = QHBoxLayout()
            hint_row.setSpacing(SPACE_SM)
            glyph = QLabel()
            glyph.setPixmap(icons.pixmap("info", tone="accent", size=13))
            glyph.setFixedSize(13, 13)
            hint_row.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
            hint_row.addWidget(label(option.hint, role="caption", tone="accent",
                                     wrap=True), 1)
            column.addLayout(hint_row)

        self._emitting = True

    # -- control construction ---------------------------------------------

    def _build_control(self, value) -> QWidget:
        kind = self.option.kind

        if kind == BOOL:
            toggle = ToggleSwitch()
            toggle.setChecked(bool(value))
            toggle.toggled.connect(
                lambda checked: self._emit(checked))
            return toggle

        if kind in (INT, SECONDS):
            box = QSpinBox()
            box.setRange(self.option.minimum if self.option.minimum is not None else 0,
                         self.option.maximum if self.option.maximum is not None
                         else 2_000_000_000)
            box.setSpecialValueText("")
            suffix = {SECONDS: " seconds"}.get(kind, f" {self.option.unit}"
                                               if self.option.unit else "")
            if suffix:
                box.setSuffix(suffix)
            try:
                box.setValue(int(value) if str(value).strip() else box.minimum())
            except (TypeError, ValueError):
                box.setValue(box.minimum())
            box.valueChanged.connect(lambda number: self._emit(str(number)))
            return box

        if kind == ENUM:
            combo = QComboBox()
            combo.addItems(list(self.option.choices))
            if value and str(value) in self.option.choices:
                combo.setCurrentText(str(value))
            combo.currentTextChanged.connect(self._emit)
            return combo

        if kind in (MULTI, REGEX):
            editor = QPlainTextEdit()
            editor.setPlaceholderText("One value per line")
            editor.setPlainText("\n".join(value if isinstance(value, list) else []))
            editor.setMaximumHeight(96)
            editor.textChanged.connect(
                lambda: self._emit([line.strip() for line
                                    in editor.toPlainText().splitlines()
                                    if line.strip()]))
            return editor

        # Everything else is a line of text, with a browse button for paths.
        if kind in (PATH, DIR):
            holder = QWidget()
            row = QHBoxLayout(holder)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(SPACE_SM)
            line = QLineEdit(str(value or ""))
            line.textChanged.connect(self._emit)
            browse = QPushButton("Browse…")
            browse.clicked.connect(lambda: self._browse(line))
            row.addWidget(line, 1)
            row.addWidget(browse, 0)
            self._line = line
            return holder

        line = QLineEdit(str(value or ""))
        if self.option.kind == SIZE:
            line.setPlaceholderText("e.g. 100M")
        line.textChanged.connect(self._emit)
        self._line = line
        return line

    def _browse(self, line: QLineEdit) -> None:
        if self.option.kind == DIR:
            chosen = QFileDialog.getExistingDirectory(
                self, f"Choose a directory for {self.option.key}",
                line.text() or "/")
        else:
            chosen, _ = QFileDialog.getSaveFileName(
                self, f"Choose a file for {self.option.key}", line.text() or "/")
        if chosen:
            line.setText(chosen)

    # -- validation and emission -------------------------------------------

    def _emit(self, value) -> None:
        if not self._emitting:
            return
        if isinstance(value, str):
            problem = validate(self.option, value)
            self._show_problem(problem)
            if problem:
                return
        elif isinstance(value, list):
            for item in value:
                problem = validate(self.option, item)
                if problem:
                    self._show_problem(f"{item}: {problem}")
                    return
            self._show_problem(None)
        self.changed.emit(self.option.key, value)

    def _show_problem(self, problem: str | None) -> None:
        self.error_label.setText(problem or "")
        self.error_label.setVisible(bool(problem))
        target = getattr(self, "_line", None)
        if target is not None:
            target.setProperty("state", "error" if problem else "")
            restyle(target)

    def _help_text(self, docs: OptionDocs | None) -> str:
        """ClamAV's own description, plus the shipped default."""
        parts: list[str] = []
        if docs and docs.description:
            parts.append(docs.description)
        if docs and docs.default:
            parts.append(f"ClamAV's default: {docs.default}.")
        elif self.option.default is not None:
            parts.append(f"Default: {self.option.default}.")
        for warning in (docs.warnings if docs else []):
            parts.append(f"Warning: {warning}")
        return "  ".join(parts)


class ConfigurationPage(Page):
    PAGE_ID = "configuration"
    TITLE = "Configuration"
    SUBTITLE = "ClamAV's own settings, from /etc/clamav"
    ICON = "wrench"
    SCROLLABLE = False

    def build(self) -> None:
        self.applier = ConfigApplier(self.context, self)
        self.applier.finished.connect(self._on_applied)
        self.applier.progress.connect(lambda text: self.notify.emit(text, "info"))

        self._file = CLAMD
        self._conf: ConfFile | None = None
        self._docs: dict[str, OptionDocs] = {}
        self._editors: dict[str, OptionEditor] = {}
        self._group = ""
        self._search = ""

        self.body.setContentsMargins(SPACE_LG + 6, SPACE_MD, SPACE_LG + 6, SPACE_MD)

        self.notice = MessageBar("", "info")
        self.body.addWidget(self.notice)

        self.body.addLayout(self._build_toolbar())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        self.group_list = QListWidget()
        self.group_list.setFixedWidth(206)
        self.group_list.currentItemChanged.connect(self._on_group_changed)
        splitter.addWidget(self.group_list)

        self.options_area = QScrollArea()
        self.options_area.setWidgetResizable(True)
        self.options_area.setFrameShape(QScrollArea.Shape.NoFrame)
        self.options_host = QWidget()
        self.options_layout = QVBoxLayout(self.options_host)
        self.options_layout.setContentsMargins(SPACE_MD, 0, SPACE_MD, SPACE_MD)
        self.options_layout.setSpacing(SPACE_SM)
        self.options_area.setWidget(self.options_host)
        splitter.addWidget(self.options_area)
        splitter.setStretchFactor(1, 1)
        self.body.addWidget(splitter, 1)

        self.body.addLayout(self._build_footer())
        self._load_file(CLAMD)

    def _build_toolbar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(SPACE_SM)

        self.file_box = QComboBox()
        for key, name, description in FILES:
            self.file_box.addItem(f"{name} — {description}", key)
        self.file_box.currentIndexChanged.connect(
            lambda: self._load_file(self.file_box.currentData()))
        row.addWidget(self.file_box, 2)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search all options…")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.textChanged.connect(self._on_search)
        row.addWidget(self.search_box, 2)

        self.advanced_toggle = ToggleSwitch("Show advanced")
        self.advanced_toggle.toggled.connect(lambda: self._render_options())
        row.addWidget(self.advanced_toggle, 0)
        return row

    def _build_footer(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(SPACE_SM)

        self.status_label = label("", role="muted")
        row.addWidget(self.status_label, 1)

        self.revert_button = QPushButton("Discard changes")
        self.revert_button.clicked.connect(lambda: self._load_file(self._file))
        self.revert_button.setEnabled(False)
        row.addWidget(self.revert_button)

        self.preview_button = QPushButton("Preview changes")
        self.preview_button.setIcon(icons.icon("eye", tone="muted", size=16))
        self.preview_button.clicked.connect(self._preview)
        self.preview_button.setEnabled(False)
        row.addWidget(self.preview_button)

        self.save_button = QPushButton("Review and save")
        self.save_button.setProperty("variant", "primary")
        self.save_button.setIcon(icons.icon("save", "#ffffff", size=16))
        self.save_button.clicked.connect(self._save)
        self.save_button.setEnabled(False)
        row.addWidget(self.save_button)
        return row

    # -- loading ----------------------------------------------------------

    def _load_file(self, file_key: str) -> None:
        self._file = file_key or CLAMD
        path = paths.CLAMD_CONF if self._file == CLAMD else paths.FRESHCLAM_CONF

        try:
            self._conf = ConfFile.load(path)
        except OSError as error:
            self._conf = ConfFile.parse("", path)
            self.notice.set_message(
                f"Could not read {path}: {error}. Nothing can be edited until it is "
                "readable.", "danger")
            self.notice.show()
        else:
            self._refresh_notice(path)

        self._docs = self._conf.documentation()
        self._rebuild_groups()
        self._render_options()
        self._refresh_dirty()

    def _refresh_notice(self, path: Path) -> None:
        if not self.context.privileged.available:
            self.notice.set_message(
                f"You can browse and change everything here, but saving writes to "
                f"{path}, which needs administrator rights. Preview changes still "
                "works — you can copy the diff and apply it by hand.", "warn")
        else:
            self.notice.set_message(
                f"Editing {path}. The current file is backed up before any change, "
                "and the new one is checked with clamconf before it is installed.",
                "info")
        self.notice.show()

    def _schema(self) -> Schema:
        return schema_for(self._file)

    def _rebuild_groups(self) -> None:
        schema = self._schema()
        self.group_list.blockSignals(True)
        self.group_list.clear()
        for group in schema.groups:
            count = len(self._visible_options(group))
            item = QListWidgetItem(f"{group}" if not count else f"{group}   ({count})")
            item.setData(Qt.ItemDataRole.UserRole, group)
            self.group_list.addItem(item)
        self.group_list.blockSignals(False)
        if self.group_list.count():
            self.group_list.setCurrentRow(0)
            self._group = schema.groups[0]

    def _visible_options(self, group: str) -> list[ConfOption]:
        schema = self._schema()
        options = schema.in_group(
            group, include_advanced=self.advanced_toggle.isChecked())
        # An advanced option that is actually set stays visible, because hiding
        # a value that is in effect is worse than showing a busy list.
        if not self.advanced_toggle.isChecked() and self._conf is not None:
            options += [
                option for option in schema.in_group(group)
                if option.advanced and self._conf.has(option.key)
            ]
        seen: dict[str, ConfOption] = {}
        for option in options:
            seen.setdefault(option.key, option)
        return list(seen.values())

    # -- rendering --------------------------------------------------------

    def _render_options(self) -> None:
        _clear(self.options_layout)
        self._editors = {}
        if self._conf is None:
            return

        schema = self._schema()
        if self._search:
            options = [option for option in schema.search(self._search)
                       if self.advanced_toggle.isChecked() or not option.advanced
                       or self._conf.has(option.key)]
            heading = (f"{len(options)} option{'' if len(options) == 1 else 's'} "
                       f"matching “{self._search}”")
        else:
            options = self._visible_options(self._group)
            heading = self._group

        self.options_layout.addWidget(label(heading, role="heading"))
        if not options:
            self.options_layout.addWidget(label(
                "Nothing here. Turn on “Show advanced” to see the rest.",
                role="muted", wrap=True))
            self.options_layout.addStretch(1)
            return

        recognised_keys = set(self._docs)
        for option in options:
            editor = OptionEditor(
                option,
                self._current_value(option),
                self._docs.get(option.key.lower()),
                option.key.lower() in recognised_keys,
            )
            editor.changed.connect(self._on_option_changed)
            self._editors[option.key] = editor
            self.options_layout.addWidget(editor)

        self.options_layout.addStretch(1)
        self.theme_refresh_requested.emit()

    def _current_value(self, option: ConfOption):
        assert self._conf is not None
        if option.kind == BOOL:
            return self._conf.get_bool(option.key, bool(option.default))
        if option.kind in (MULTI, REGEX):
            return self._conf.get_all(option.key)
        value = self._conf.get(option.key)
        if value is None:
            return "" if option.kind not in (INT, SECONDS) else ""
        return value

    # -- editing ----------------------------------------------------------

    def _on_option_changed(self, key: str, value) -> None:
        if self._conf is None:
            return
        schema_option = self._schema().get(key)
        if isinstance(value, list):
            self._conf.set_all(key, value)
        elif isinstance(value, bool):
            self._conf.set(key, value)
        elif str(value).strip() == "":
            self._conf.remove(key)
        else:
            self._conf.set(key, str(value).strip())
        if schema_option is not None and schema_option.sensitive:
            self.notify.emit(
                f"{schema_option.key} can affect whether ClamAV starts. "
                "Check the preview before saving.", "warn")
        self._refresh_dirty()

    def _on_search(self, text: str) -> None:
        self._search = text.strip()
        self.group_list.setEnabled(not self._search)
        self._render_options()

    def _on_group_changed(self, current: QListWidgetItem, _previous) -> None:
        if current is None:
            return
        self._group = current.data(Qt.ItemDataRole.UserRole)
        self._render_options()

    def _refresh_dirty(self) -> None:
        if self._conf is None:
            return
        changed = self._conf.changed_keys()
        dirty = bool(changed)
        self.save_button.setEnabled(dirty and self.context.privileged.available)
        self.preview_button.setEnabled(dirty)
        self.revert_button.setEnabled(dirty)
        if dirty:
            self.status_label.setText(
                f"{len(changed)} option{'' if len(changed) == 1 else 's'} changed: "
                + ", ".join(changed[:5]) + ("…" if len(changed) > 5 else ""))
            self.status_label.setProperty("tone", "warn")
        else:
            self.status_label.setText("No unsaved changes.")
            self.status_label.setProperty("tone", "")
        restyle(self.status_label)

    # -- saving -----------------------------------------------------------

    def _preview(self) -> None:
        if self._conf is None:
            return
        from ..dialogs import confirm
        from ..theme import resolve_palette

        confirm(
            self, "Pending changes",
            "This is exactly what would be written. Nothing has changed on disk yet.",
            detail=self._conf.diff(self._conf.path.name if self._conf.path
                                   else self._file),
            detail_kind="diff", detail_label="DIFF",
            confirm_text="Close", cancel_text="Cancel", tone="info",
            palette=resolve_palette(self.context.settings.str("theme")),
        )

    def _save(self) -> None:
        if self._conf is None or self._conf.path is None:
            return
        sensitive = [key for key in self._conf.changed_keys()
                     if (option := self._schema().get(key)) and option.sensitive]
        warning = ""
        if sensitive:
            warning = ("These options can stop ClamAV from starting if they are "
                       f"wrong: {', '.join(sensitive)}. The file is checked with "
                       "clamconf first, and the old one is kept as a backup.")

        self.applier.apply(
            self._conf.path,
            self._conf.to_text(),
            self._conf.diff(self._conf.path.name),
            f"Save changes to {self._conf.path.name}",
            restart=RESTART_FOR.get(self._file, ()),
            extra_warning=warning,
        )

    def _on_applied(self, ok: bool, message: str) -> None:
        self.notify.emit(message, "ok" if ok else "warn")
        if ok:
            self._load_file(self._file)

    # -- lifecycle --------------------------------------------------------

    def on_shown(self) -> None:
        self.context.privileged.refresh()
        if self._conf is None or not self._conf.is_modified():
            self._load_file(self._file)
        else:
            self._refresh_dirty()


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
