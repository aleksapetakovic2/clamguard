"""The scan page: choose what to check, watch it happen, deal with what it found.

Three views in a stack, because they are three different jobs and sharing a
layout between them would compromise all of them:

* **Setup** — pick a scope, a depth and an engine, then start.
* **Running** — a progress ring, the file being read right now, and the numbers
  that tell you whether to wait or go and make tea.
* **Results** — what was found, and a button for each thing you can do about it.

The page owns no scanning logic. It drives core.scanner and renders its
signals.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.database import format_bytes
from ...core.scan_profile import PRESETS, profile as profile_by_id
from ...core.scan_targets import ScanKind, paths_for
from ...core.scanner import Engine, ScanState, format_duration, format_rate
from .. import icons
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    Card,
    ElidedLabel,
    IconLabel,
    KeyValueRow,
    MessageBar,
    ProgressRing,
    Separator,
    fit_table,
    label,
    restyle,
)
from .base import Page

#: Tall enough for a row of buttons, with breathing room.
ROW_HEIGHT = 48

#: The scopes offered as big clickable tiles, in order.
SCOPES: tuple[ScanKind, ...] = (
    ScanKind.QUICK, ScanKind.FULL, ScanKind.HOME, ScanKind.REMOVABLE, ScanKind.CUSTOM,
)


class ScopeTile(QFrame):
    """One selectable scan scope."""

    clicked = Signal(object)

    def __init__(self, kind: ScanKind, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.kind = kind
        self._selected = False
        self.setProperty("card", "flat")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        row = QHBoxLayout(self)
        row.setContentsMargins(SPACE_MD, SPACE_MD, SPACE_MD, SPACE_MD)
        row.setSpacing(SPACE_MD)

        self._icon = IconLabel(kind.icon, tone="muted", size=22)
        row.addWidget(self._icon, 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(2)
        self._title = label(kind.title, role="body")
        texts.addWidget(self._title)
        texts.addWidget(label(kind.description, role="caption", wrap=True))
        self._detail = label("", role="caption", tone="accent")
        self._detail.setWordWrap(True)
        texts.addWidget(self._detail)
        row.addLayout(texts, 1)

        self._check = IconLabel("check-circle", tone="accent", size=18)
        self._check.setVisible(False)
        row.addWidget(self._check, 0, Qt.AlignmentFlag.AlignTop)

    def set_detail(self, text: str) -> None:
        self._detail.setText(text)
        self._detail.setVisible(bool(text))

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        self.setProperty("card", "tint-info" if selected else "flat")
        self._icon.set_icon(self.kind.icon, tone="accent" if selected else "muted")
        self._title.setProperty("tone", "accent" if selected else "")
        restyle(self._title)
        self._check.setVisible(selected)
        restyle(self)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt naming
        super().mousePressEvent(event)
        self.clicked.emit(self.kind)


class ScanPage(Page):
    PAGE_ID = "scan"
    TITLE = "Scan"
    SUBTITLE = "Check files and folders for threats"
    ICON = "scan"

    def build(self) -> None:
        self.stack = QStackedWidget()
        self.body.addWidget(self.stack)

        self._selected_kind = ScanKind.QUICK
        self._custom_paths: list[Path] = []
        self._live_threats: list = []
        self._last_result = None

        self.setup_view = self._build_setup_view()
        self.running_view = self._build_running_view()
        self.results_view = self._build_results_view()
        for view in (self.setup_view, self.running_view, self.results_view):
            self.stack.addWidget(view)

        self._connect_scanner()
        self._select_scope(ScanKind.QUICK)

    # ==================================================================
    # Setup view
    # ==================================================================

    def _build_setup_view(self) -> QWidget:
        view = QWidget()
        column = QVBoxLayout(view)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(SPACE_MD)

        self.engine_notice = MessageBar("", "info")
        column.addWidget(self.engine_notice)

        scope_card = Card("What to scan", icon="scan")
        self._tiles: dict[ScanKind, ScopeTile] = {}
        for kind in SCOPES:
            tile = ScopeTile(kind)
            tile.clicked.connect(self._select_scope)
            self._tiles[kind] = tile
            scope_card.body.addWidget(tile)

        choose_row = QHBoxLayout()
        choose_row.setSpacing(SPACE_SM)
        pick_folder = QPushButton("Choose folder…")
        pick_folder.setIcon(icons.icon("folder", tone="muted", size=16))
        pick_folder.clicked.connect(self._choose_folder)
        pick_files = QPushButton("Choose files…")
        pick_files.setIcon(icons.icon("file", tone="muted", size=16))
        pick_files.clicked.connect(self._choose_files)
        choose_row.addWidget(pick_folder)
        choose_row.addWidget(pick_files)
        choose_row.addStretch(1)
        scope_card.body.addLayout(choose_row)
        column.addWidget(scope_card)

        column.addWidget(self._build_options_card())

        start_row = QHBoxLayout()
        start_row.setSpacing(SPACE_SM)
        start_row.addStretch(1)
        self.start_button = QPushButton("Start scan")
        self.start_button.setProperty("variant", "primary")
        self.start_button.setProperty("size", "lg")
        self.start_button.setIcon(icons.icon("play", "#ffffff", size=18))
        self.start_button.clicked.connect(self._start_clicked)
        start_row.addWidget(self.start_button)
        column.addLayout(start_row)

        column.addStretch(1)
        return view

    def _build_options_card(self) -> Card:
        card = Card("How to scan", "Depth, engine and exclusions", icon="settings")

        profile_row = QHBoxLayout()
        profile_row.setSpacing(SPACE_MD)
        profile_row.addWidget(label("Depth", role="muted"), 0)
        self.profile_box = QComboBox()
        for preset in PRESETS:
            self.profile_box.addItem(preset.name, preset.id)
        self.profile_box.setCurrentIndex(
            max(0, self.profile_box.findData(
                self.context.settings.str("default_profile")))
        )
        self.profile_box.currentIndexChanged.connect(self._refresh_profile_notes)
        profile_row.addWidget(self.profile_box, 1)
        card.body.addLayout(profile_row)

        self.profile_notes = label("", role="caption", wrap=True)
        card.body.addWidget(self.profile_notes)
        card.body.addWidget(Separator())

        engine_row = QHBoxLayout()
        engine_row.setSpacing(SPACE_MD)
        engine_row.addWidget(label("Engine", role="muted"), 0)
        self.engine_box = QComboBox()
        for engine in Engine:
            self.engine_box.addItem(engine.title, engine.value)
        self.engine_box.currentIndexChanged.connect(self._refresh_engine_notice)
        engine_row.addWidget(self.engine_box, 1)
        card.body.addLayout(engine_row)
        card.body.addWidget(Separator())

        self.skip_hidden = QCheckBox("Skip hidden files and folders")
        self.skip_hidden.setChecked(not self.context.settings.bool("scan_hidden_files"))
        card.body.addWidget(self.skip_hidden)

        self.auto_quarantine = QCheckBox(
            "Move anything found straight into quarantine")
        self.auto_quarantine.setChecked(
            self.context.settings.str("on_threat_action") == "quarantine")
        self.auto_quarantine.setToolTip(
            "When off, detections are listed and you decide what to do with each one.")
        card.body.addWidget(self.auto_quarantine)
        return card

    # ==================================================================
    # Running view
    # ==================================================================

    def _build_running_view(self) -> QWidget:
        view = QWidget()
        column = QVBoxLayout(view)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(SPACE_MD)

        top = Card()
        inner = QHBoxLayout()
        inner.setSpacing(SPACE_LG * 2)

        self.ring = ProgressRing(170, 11)
        self.ring.set_indeterminate(True)
        self.ring.set_text("", "starting")
        inner.addWidget(self.ring, 0, Qt.AlignmentFlag.AlignVCenter)

        details = QVBoxLayout()
        details.setSpacing(SPACE_SM)

        self.phase_label = label("Preparing…", role="title")
        details.addWidget(self.phase_label)

        self.current_file = ElidedLabel("")
        self.current_file.setProperty("role", "mono")
        details.addWidget(self.current_file)
        details.addSpacing(SPACE_SM)

        numbers = QHBoxLayout()
        numbers.setSpacing(SPACE_LG * 2)
        self.stat_files = self._stat("0", "files scanned")
        self.stat_threats = self._stat("0", "threats")
        self.stat_elapsed = self._stat("0s", "elapsed")
        self.stat_remaining = self._stat("—", "remaining")
        for stat in (self.stat_files, self.stat_threats, self.stat_elapsed,
                     self.stat_remaining):
            numbers.addWidget(stat["widget"])
        numbers.addStretch(1)
        details.addLayout(numbers)
        details.addSpacing(SPACE_SM)

        self.rate_label = label("", role="caption")
        details.addWidget(self.rate_label)
        details.addStretch(1)

        controls = QHBoxLayout()
        controls.setSpacing(SPACE_SM)
        self.pause_button = QPushButton("Pause")
        self.pause_button.setIcon(icons.icon("pause", tone="muted", size=16))
        self.pause_button.clicked.connect(self._toggle_pause)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setProperty("variant", "danger")
        self.stop_button.setIcon(icons.icon("stop", "#ffffff", size=16))
        self.stop_button.clicked.connect(self._stop_clicked)
        controls.addWidget(self.pause_button)
        controls.addWidget(self.stop_button)
        controls.addStretch(1)
        details.addLayout(controls)

        inner.addLayout(details, 1)
        top.body.addLayout(inner)
        column.addWidget(top)

        self.live_threats_card = Card("Found so far", icon="alert-triangle", tone="danger")
        self.live_threats_box = QVBoxLayout()
        self.live_threats_box.setSpacing(2)
        self.live_threats_card.body.addLayout(self.live_threats_box)
        self.live_threats_card.setVisible(False)
        column.addWidget(self.live_threats_card)

        self.details_card = Card("Scanner output", icon="logs")
        self.details_toggle = QPushButton("Show")
        self.details_toggle.setProperty("variant", "ghost")
        self.details_toggle.setCheckable(True)
        self.details_toggle.toggled.connect(self._toggle_details)
        self.details_card.add_action(self.details_toggle)

        self.details_text = QPlainTextEdit()
        self.details_text.setProperty("role", "log")
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumBlockCount(2000)
        self.details_text.setMinimumHeight(180)
        self.details_text.setVisible(False)
        self.details_card.body.addWidget(self.details_text)
        column.addWidget(self.details_card)

        column.addStretch(1)
        return view

    def _stat(self, value: str, caption: str) -> dict:
        holder = QWidget()
        box = QVBoxLayout(holder)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(0)
        value_label = label(value, role="metric")
        caption_label = label(caption, role="caption")
        box.addWidget(value_label)
        box.addWidget(caption_label)
        return {"widget": holder, "value": value_label, "caption": caption_label}

    # ==================================================================
    # Results view
    # ==================================================================

    def _build_results_view(self) -> QWidget:
        view = QWidget()
        column = QVBoxLayout(view)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(SPACE_MD)

        self.result_hero = QFrame()
        self.result_hero.setProperty("card", "tint-ok")
        hero_row = QHBoxLayout(self.result_hero)
        hero_row.setContentsMargins(SPACE_LG, SPACE_LG, SPACE_LG, SPACE_LG)
        hero_row.setSpacing(SPACE_LG)

        self.result_icon = IconLabel("check-circle", tone="ok", size=44)
        hero_row.addWidget(self.result_icon, 0, Qt.AlignmentFlag.AlignVCenter)

        hero_texts = QVBoxLayout()
        hero_texts.setSpacing(2)
        self.result_title = label("", role="title")
        self.result_detail = label("", role="muted", wrap=True)
        hero_texts.addWidget(self.result_title)
        hero_texts.addWidget(self.result_detail)
        hero_row.addLayout(hero_texts, 1)

        again = QPushButton("Scan again")
        again.setIcon(icons.icon("refresh", tone="muted", size=16))
        again.clicked.connect(self._scan_again)
        hero_row.addWidget(again, 0, Qt.AlignmentFlag.AlignVCenter)

        new_scan = QPushButton("New scan")
        new_scan.setProperty("variant", "primary")
        new_scan.clicked.connect(lambda: self.stack.setCurrentWidget(self.setup_view))
        hero_row.addWidget(new_scan, 0, Qt.AlignmentFlag.AlignVCenter)
        column.addWidget(self.result_hero)

        self.threats_card = Card("Detections", icon="bug")
        bulk = QHBoxLayout()
        bulk.setSpacing(SPACE_SM)
        self.quarantine_all = QPushButton("Quarantine all")
        self.quarantine_all.setProperty("variant", "primary")
        self.quarantine_all.setIcon(icons.icon("quarantine", "#ffffff", size=16))
        self.quarantine_all.clicked.connect(self._quarantine_all)
        bulk.addWidget(self.quarantine_all)
        bulk.addStretch(1)
        self.threats_card.body.addLayout(bulk)

        self.threat_table = QTableWidget(0, 4)
        self.threat_table.setHorizontalHeaderLabels(["File", "Threat", "Size", ""])
        self.threat_table.verticalHeader().setVisible(False)
        self.threat_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.threat_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.threat_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.threat_table.customContextMenuRequested.connect(self._threat_context_menu)
        header = self.threat_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.threat_table.setColumnWidth(3, 208)
        self.threat_table.setWordWrap(False)
        self.threats_card.body.addWidget(self.threat_table)
        column.addWidget(self.threats_card)

        self.summary_card = Card("Scan summary", icon="info")
        self.summary_box = QVBoxLayout()
        self.summary_box.setSpacing(0)
        self.summary_card.body.addLayout(self.summary_box)
        column.addWidget(self.summary_card)

        self.problems_card = Card("Files that could not be scanned", icon="alert-triangle")
        self.problems_text = QPlainTextEdit()
        self.problems_text.setProperty("role", "log")
        self.problems_text.setReadOnly(True)
        self.problems_text.setMaximumHeight(160)
        self.problems_card.body.addWidget(self.problems_text)
        column.addWidget(self.problems_card)

        column.addStretch(1)
        return view

    # ==================================================================
    # Wiring
    # ==================================================================

    def _connect_scanner(self) -> None:
        scanner = self.context.scanner
        scanner.state_changed.connect(self._on_state)
        scanner.preparing_progress.connect(self._on_preparing)
        scanner.progress.connect(self._on_progress)
        scanner.threat_found.connect(self._on_threat)
        scanner.output_line.connect(self._on_output)
        scanner.warning.connect(self._on_output)
        scanner.finished.connect(self._on_finished)

    # -- public entry points ---------------------------------------------

    def start_preset_scan(self, kind: ScanKind) -> None:
        """Called by the dashboard, the tray and keyboard shortcuts."""
        self._select_scope(kind)
        self._start_clicked()

    def start_custom_scan(self, targets: list[Path]) -> None:
        """Called when files are dropped on the window or passed on the CLI."""
        self._custom_paths = [Path(target) for target in targets]
        self._select_scope(ScanKind.CUSTOM)
        self._start_clicked()

    def start_scheduled_scan(self, schedule) -> None:
        """Called by the scheduler."""
        kind = schedule.scan_kind
        if kind is ScanKind.CUSTOM:
            self._custom_paths = [Path(item) for item in schedule.custom_paths]
        self._select_scope(kind)
        index = self.profile_box.findData(schedule.profile_id)
        if index >= 0:
            self.profile_box.setCurrentIndex(index)
        self._start_clicked()

    # -- setup interactions ----------------------------------------------

    def _select_scope(self, kind: ScanKind) -> None:
        self._selected_kind = kind
        for candidate, tile in self._tiles.items():
            tile.set_selected(candidate is kind)
        self._refresh_scope_details()

    def _refresh_scope_details(self) -> None:
        for kind, tile in self._tiles.items():
            if kind is ScanKind.CUSTOM:
                if self._custom_paths:
                    names = ", ".join(path.name or str(path)
                                      for path in self._custom_paths[:3])
                    extra = (f" and {len(self._custom_paths) - 3} more"
                             if len(self._custom_paths) > 3 else "")
                    tile.set_detail(f"{names}{extra}")
                else:
                    tile.set_detail("")
                continue
            targets = paths_for(kind, quick_override=self.context.settings.list(
                "quick_scan_paths") if kind is ScanKind.QUICK else None)
            if not targets:
                tile.set_detail("Nothing to scan — no matching location found")
            elif kind is ScanKind.QUICK:
                tile.set_detail(f"{len(targets)} locations")
            elif kind is ScanKind.REMOVABLE:
                tile.set_detail(", ".join(path.name for path in targets))
            else:
                tile.set_detail(str(targets[0]))

    def _choose_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, "Choose a folder to scan", str(Path.home()))
        if chosen:
            self._custom_paths = [Path(chosen)]
            self._select_scope(ScanKind.CUSTOM)

    def _choose_files(self) -> None:
        chosen, _ = QFileDialog.getOpenFileNames(
            self, "Choose files to scan", str(Path.home()))
        if chosen:
            self._custom_paths = [Path(item) for item in chosen]
            self._select_scope(ScanKind.CUSTOM)

    def _refresh_profile_notes(self) -> None:
        preset = profile_by_id(self.profile_box.currentData())
        self.profile_notes.setText(
            f"{preset.description}  ·  " + "; ".join(preset.summary_lines()))

    def _refresh_engine_notice(self) -> None:
        """Explain, honestly, what the chosen engine does with the profile."""
        engine = Engine(self.engine_box.currentData())
        daemon = self.context.clamav.daemon

        if engine is Engine.DIRECT:
            self.engine_notice.set_message(
                "Scanning directly with clamscan. Your depth settings apply in full, "
                "but ClamAV has to load its whole signature database first, which "
                "takes several seconds and a lot of memory.", "info")
            self.engine_notice.show()
            return

        if not daemon.reachable:
            self.engine_notice.set_message(
                f"The ClamAV daemon is not responding ({daemon.detail}), so scans "
                "will use clamscan directly. That works, but it is several times "
                "slower.", "warn")
            self.engine_notice.show()
            return

        self.engine_notice.set_message(
            "Scanning through the ClamAV daemon, which is much faster. Note that the "
            "daemon uses the settings in clamd.conf — the depth option below applies "
            "only when scanning directly.", "info")
        self.engine_notice.show()

    # -- starting ---------------------------------------------------------

    def _start_clicked(self) -> None:
        if self.context.scanner.busy:
            self.notify.emit("A scan is already running.", "warn")
            return

        targets = self._resolve_targets()
        if not targets:
            self.notify.emit(
                "Nothing to scan. Choose a folder or some files first."
                if self._selected_kind is ScanKind.CUSTOM
                else f"{self._selected_kind.title} found nothing to scan on this machine.",
                "warn")
            return

        if self._selected_kind is ScanKind.FULL and not self._confirm_full_scan():
            return

        preset = profile_by_id(self.profile_box.currentData())
        engine = Engine(self.engine_box.currentData())

        self._live_threats = []
        self._clear_layout(self.live_threats_box)
        self.live_threats_card.setVisible(False)
        self.details_text.clear()
        self.ring.set_indeterminate(True)
        self.ring.set_tone("accent")
        self.ring.set_text("", "starting")
        self.stack.setCurrentWidget(self.running_view)

        self.context.scanner.start(
            self._selected_kind, targets, preset, engine,
            skip_hidden=self.skip_hidden.isChecked(),
        )

    def _resolve_targets(self) -> list[Path]:
        if self._selected_kind is ScanKind.CUSTOM:
            return [path for path in self._custom_paths if path.exists()]
        override = (self.context.settings.list("quick_scan_paths")
                    if self._selected_kind is ScanKind.QUICK else None)
        return paths_for(self._selected_kind, quick_override=override)

    def _confirm_full_scan(self) -> bool:
        answer = QMessageBox.question(
            self, "Full system scan",
            "A full system scan reads every file on every local filesystem. "
            "It can take several hours and will keep a CPU core busy the whole time.\n\n"
            "You can stop it at any point and keep whatever it found.\n\nStart it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _scan_again(self) -> None:
        self._start_clicked()

    # -- running ----------------------------------------------------------

    def _on_state(self, state: ScanState) -> None:
        if state is ScanState.PREPARING:
            self.phase_label.setText("Looking for files to scan…")
            self.ring.set_indeterminate(True)
            self.pause_button.setEnabled(False)
        elif state is ScanState.SCANNING:
            self.phase_label.setText("Scanning")
            self.pause_button.setEnabled(True)
            self.pause_button.setText("Pause")
            self.pause_button.setIcon(icons.icon("pause", tone="muted", size=16))
        elif state is ScanState.PAUSED:
            self.phase_label.setText("Paused")
            self.pause_button.setText("Resume")
            self.pause_button.setIcon(icons.icon("play", tone="muted", size=16))
        elif state is ScanState.STOPPING:
            self.phase_label.setText("Stopping…")
            self.pause_button.setEnabled(False)
            self.stop_button.setEnabled(False)

    def _on_preparing(self, files: int, total_bytes: int) -> None:
        self.ring.set_text(f"{files:,}", "files found")
        self.current_file.setText(
            f"{files:,} files so far ({format_bytes(total_bytes)})")

    def _on_progress(self, progress) -> None:
        self.ring.set_indeterminate(False)
        self.ring.set_progress(progress.fraction)
        self.ring.set_text(f"{progress.percent}%", f"of {progress.files_total:,} files")
        self.ring.set_tone("danger" if progress.threats else "accent")

        self.current_file.setText(progress.current_path)
        self.stat_files["value"].setText(f"{progress.files_done:,}")
        self.stat_threats["value"].setText(f"{progress.threats:,}")
        self.stat_threats["value"].setProperty("tone", "danger" if progress.threats else "")
        restyle(self.stat_threats["value"])
        self.stat_elapsed["value"].setText(format_duration(progress.elapsed))

        remaining = progress.eta_seconds()
        self.stat_remaining["value"].setText(
            format_duration(remaining) if remaining is not None else "—")

        rate = format_rate(progress.bytes_per_second)
        self.rate_label.setText(
            f"{rate}  ·  {progress.files_per_second:.0f} files/second  ·  "
            f"{format_bytes(progress.bytes_done)} of {format_bytes(progress.bytes_total)}"
        )

    def _on_threat(self, threat) -> None:
        self._live_threats.append(threat)
        self.live_threats_card.setVisible(True)
        if self.live_threats_box.count() < 12:
            row = QHBoxLayout()
            row.setSpacing(SPACE_SM)
            row.addWidget(IconLabel("bug", tone="danger", size=14), 0)
            name = label(threat.name, role="body", tone="danger")
            row.addWidget(name, 0)
            path = ElidedLabel(threat.path)
            path.setProperty("role", "mono")
            row.addWidget(path, 1)
            holder = QWidget()
            holder.setLayout(row)
            self.live_threats_box.addWidget(holder)
        self.live_threats_card.set_title(f"Found so far — {len(self._live_threats)}")

    def _on_output(self, line: str) -> None:
        if self.details_text.isVisible():
            self.details_text.appendPlainText(line)

    def _toggle_details(self, shown: bool) -> None:
        self.details_text.setVisible(shown)
        self.details_toggle.setText("Hide" if shown else "Show")

    def _toggle_pause(self) -> None:
        scanner = self.context.scanner
        if scanner.state is ScanState.PAUSED:
            scanner.resume()
        elif not scanner.pause():
            self.notify.emit("This scan could not be paused.", "warn")

    def _stop_clicked(self) -> None:
        self.context.scanner.stop()
        self.notify.emit("Stopping the scan…", "info")

    # -- results ----------------------------------------------------------

    def _on_finished(self, result) -> None:
        self._last_result = result
        self.stop_button.setEnabled(True)

        tone = "danger" if result.threats else ("warn" if result.status != "completed"
                                                else "ok")
        icon = ("alert-circle" if result.threats
                else "alert-triangle" if result.status != "completed"
                else "check-circle")
        self.result_hero.setProperty("card", f"tint-{tone}")
        restyle(self.result_hero)
        self.result_icon.set_icon(icon, tone=tone)
        self.result_title.setText(result.headline())
        self.result_title.setProperty("tone", tone)
        restyle(self.result_title)
        self.result_detail.setText(result.summary_line())

        self._fill_threat_table(result)
        self._fill_summary(result)
        self._fill_problems(result)
        self.stack.setCurrentWidget(self.results_view)

        if result.threats and self.auto_quarantine.isChecked():
            QTimer.singleShot(200, self._quarantine_all)

    def _fill_threat_table(self, result) -> None:
        self.threats_card.setVisible(bool(result.threats))
        self.threat_table.setRowCount(0)
        if not result.threats:
            return
        self.threats_card.set_title(
            f"Detections — {len(result.threats)}")
        for threat in result.threats:
            row = self.threat_table.rowCount()
            self.threat_table.insertRow(row)

            file_item = QTableWidgetItem(threat.path)
            file_item.setToolTip(threat.path)
            file_item.setData(Qt.ItemDataRole.UserRole, threat)
            self.threat_table.setItem(row, 0, file_item)
            self.threat_table.setItem(row, 1, QTableWidgetItem(threat.name))
            self.threat_table.setItem(row, 2, QTableWidgetItem(format_bytes(threat.size)))

            actions = QWidget()
            action_row = QHBoxLayout(actions)
            action_row.setContentsMargins(4, 2, 4, 2)
            action_row.setSpacing(SPACE_SM)
            quarantine = QPushButton("Quarantine")
            quarantine.setProperty("variant", "primary")
            quarantine.clicked.connect(lambda _=False, t=threat, r=row:
                                       self._quarantine_one(t, r))
            delete = QPushButton("Delete")
            delete.setProperty("variant", "danger")
            delete.clicked.connect(lambda _=False, t=threat, r=row:
                                   self._delete_one(t, r))
            action_row.addWidget(quarantine)
            action_row.addWidget(delete)
            self.threat_table.setCellWidget(row, 3, actions)
        fit_table(self.threat_table, row_height=ROW_HEIGHT)

    def _fill_summary(self, result) -> None:
        self._clear_layout(self.summary_box)
        rows = [
            ("Scope", ", ".join(result.targets) or "—"),
            ("Type", result.kind.title),
            ("Engine", "ClamAV daemon (clamdscan)" if result.engine == "clamdscan"
             else "clamscan, directly"),
            ("Depth", profile_by_id(result.profile_id).name),
            ("Files scanned", f"{result.files_scanned:,} of {result.files_total:,} found"),
            ("Data read", format_bytes(result.bytes_scanned)),
            ("Duration", format_duration(result.duration)),
            ("Finished", result.finished_at.strftime("%H:%M:%S on %d %B %Y")
             if result.finished_at else "—"),
        ]
        if result.skipped_unreadable:
            rows.append(("Skipped", f"{result.skipped_unreadable:,} unreadable, "
                                    f"{result.skipped_too_large:,} too large"))
        for key, value in rows:
            self.summary_box.addWidget(KeyValueRow(key, value))

    def _fill_problems(self, result) -> None:
        self.problems_card.setVisible(bool(result.errors))
        if result.errors:
            self.problems_card.set_title(
                f"Files that could not be scanned — {len(result.errors)}")
            self.problems_text.setPlainText("\n".join(result.errors[:200]))

    # -- threat actions ---------------------------------------------------

    def _quarantine_one(self, threat, row: int) -> None:
        def done(entry) -> None:
            self._mark_row(row, "Quarantined", "ok")
            self.context.history.set_action_for_quarantine(entry.id, "quarantined")
            self.notify.emit(f"{threat.filename} moved to quarantine.", "ok")

        def failed(message: str) -> None:
            self._mark_row(row, "Failed", "danger")
            self.notify.emit(message, "danger")

        self.context.quarantine.quarantine(
            Path(threat.path), threat.name,
            scan_id=self.context.current_scan_id,
            engine=self._last_result.engine if self._last_result else "",
            on_success=done, on_error=failed,
        )

    def _quarantine_all(self) -> None:
        if not self._last_result or not self._last_result.threats:
            return
        count = len(self._last_result.threats)
        for row in range(self.threat_table.rowCount()):
            item = self.threat_table.item(row, 0)
            if item is None:
                continue
            threat = item.data(Qt.ItemDataRole.UserRole)
            if threat is not None and Path(threat.path).exists():
                self._quarantine_one(threat, row)
        self.notify.emit(f"Quarantining {count} file{'' if count == 1 else 's'}…", "info")

    def _delete_one(self, threat, row: int) -> None:
        if self.context.settings.bool("confirm_before_delete"):
            answer = QMessageBox.warning(
                self, "Delete permanently",
                f"Delete this file for good?\n\n{threat.path}\n\n"
                "It will not go to quarantine and cannot be recovered from here. "
                "If this is a false positive you will not get the file back.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            Path(threat.path).unlink()
        except OSError as error:
            self._mark_row(row, "Failed", "danger")
            self.notify.emit(f"Could not delete {threat.filename}: {error}", "danger")
            return
        self._mark_row(row, "Deleted", "ok")
        self.notify.emit(f"{threat.filename} deleted.", "ok")

    def _mark_row(self, row: int, text: str, tone: str) -> None:
        """Replace a row's buttons with the outcome."""
        if row >= self.threat_table.rowCount():
            return
        badge = Badge(text, tone)
        holder = QWidget()
        box = QHBoxLayout(holder)
        box.setContentsMargins(6, 2, 6, 2)
        box.addWidget(badge)
        box.addStretch(1)
        self.threat_table.setCellWidget(row, 3, holder)

    def _threat_context_menu(self, position) -> None:
        item = self.threat_table.itemAt(position)
        if item is None:
            return
        row = item.row()
        threat = self.threat_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if threat is None:
            return

        menu = QMenu(self)
        menu.addAction("Copy file path",
                       lambda: self._copy(threat.path))
        menu.addAction("Copy threat name",
                       lambda: self._copy(threat.name))
        menu.addSeparator()
        menu.addAction("Show containing folder",
                       lambda: self._open_folder(Path(threat.path).parent))
        menu.addSeparator()
        menu.addAction("Quarantine", lambda: self._quarantine_one(threat, row))
        menu.addAction("Delete permanently", lambda: self._delete_one(threat, row))
        menu.exec(self.threat_table.viewport().mapToGlobal(position))

    def _copy(self, text: str) -> None:
        from PySide6.QtWidgets import QApplication

        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)
            self.notify.emit("Copied.", "info")

    def _open_folder(self, directory: Path) -> None:
        """Open a file manager. Never opens the infected file itself."""
        if not directory.is_dir():
            self.notify.emit("That folder no longer exists.", "warn")
            return
        opener = None
        for candidate in ("xdg-open", "gio", "kde-open"):
            found = subprocess.run(["which", candidate], capture_output=True,
                                   text=True, check=False)
            if found.returncode == 0:
                opener = found.stdout.strip()
                break
        if opener is None:
            self.notify.emit("No file manager could be found.", "warn")
            return
        args = [opener, "open", str(directory)] if opener.endswith("gio") \
            else [opener, str(directory)]
        try:
            subprocess.Popen(args, start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as error:
            self.notify.emit(f"Could not open the folder: {error}", "danger")

    # -- page lifecycle ---------------------------------------------------

    def on_shown(self) -> None:
        self._refresh_scope_details()
        self._refresh_profile_notes()
        self._refresh_engine_notice()
        if not self.context.scanner.busy and self.stack.currentWidget() is self.running_view:
            self.stack.setCurrentWidget(self.setup_view)

    @staticmethod
    def _clear_layout(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
