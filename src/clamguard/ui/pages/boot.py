"""The Boot Analyzer page.

What happens between the power button and the desktop, and whether any of it
is wrong. Five tabs: the findings themselves, where the boot time went, how
exposed each service is, everything that starts automatically, and the
catalogue of checks with the knobs behind it.

The rule this page is built around, and the reason it looks the way it does:
**it changes nothing.** Every other page in ClamGuard has an Apply button
somewhere; this one has a Copy button instead. The settings it inspects —
bootloaders, kernel command lines, ESP permissions, sysctls — are the ones
where a well-meant automatic fix turns into an unbootable machine, so the
suggestion is shown with its risk attached and the typing is left to the
person who has to live with the result.

The page owns the profile and the analyzer; the tabs are passive and are
handed a Report.
"""

from __future__ import annotations

import os
import subprocess

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...core import paths
from ...core.boot import custom, report as report_export
from ...core.boot.analyzer import BootAnalyzer
from ...core.boot.baseline import Baseline, WATCHED_ROOTS, record
from ...core.boot.model import (
    CATEGORY_ORDER,
    Category,
    Report,
    Severity,
    format_age,
    sort_findings,
)
from ...core.boot.profile import PRESETS, Profile
from ...core.process import run_in_background
from ...core.scan_targets import ScanKind
from ..dialogs import confirm
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    Card,
    EmptyState,
    FindingRow,
    IconButton,
    IconLabel,
    MessageBar,
    ProgressRing,
    StatTile,
    ToggleSwitch,
    flow_row,
    label,
    restyle,
)
from .base import Page
from .boot_tabs import ChecksTab, ExposureTab, StartupTab, TimelineTab

#: Severity chips in the hero, worst first. Clicking one filters the list.
CHIP_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO, Severity.PASS)


class BootPage(Page):
    """Everything about how this machine starts."""

    PAGE_ID = "boot"
    TITLE = "Boot Analyzer"
    SUBTITLE = "What happens before the desktop appears — and whether any of it is wrong"
    ICON = "boot"

    def __init__(self, context, parent=None) -> None:
        super().__init__(context, parent)
        self.profile = Profile()
        self.analyzer = BootAnalyzer(self.profile, self)
        self.report: Report | None = None
        self._rows: list[FindingRow] = []
        #: Widgets rebuilt on every filter pass — headers and the empty notice.
        #: Held so they can be destroyed rather than merely orphaned.
        self._transient: list[QWidget] = []
        self._severity_filter: Severity | None = None
        self._category_filter: Category | None = None

    # -- construction -----------------------------------------------------

    def build(self) -> None:
        self._build_header_actions()

        self.notice = MessageBar("", "info", dismissible=True)
        self.notice.setVisible(False)
        self.body.addWidget(self.notice)

        self.body.addWidget(self._build_hero())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_findings_tab(), "Findings")
        self.timeline_tab = TimelineTab()
        self.tabs.addTab(self.timeline_tab, "Boot time")
        self.exposure_tab = ExposureTab()
        self.tabs.addTab(self.exposure_tab, "Service exposure")
        self.startup_tab = StartupTab()
        self.tabs.addTab(self.startup_tab, "Startup surface")
        self.checks_tab = ChecksTab(self.profile)
        self.checks_tab.profile_changed.connect(self._on_profile_changed)
        self.checks_tab.open_custom_folder.connect(self._open_custom_folder)
        self.tabs.addTab(self.checks_tab, "Checks")
        self.body.addWidget(self.tabs, 1)

        self.analyzer.started.connect(self._on_started)
        self.analyzer.progressed.connect(self._on_progress)
        self.analyzer.finished.connect(self.show_report)
        self.analyzer.failed.connect(self._on_failed)
        self.analyzer.busy_changed.connect(self._on_busy)

        self._load_catalogue()
        self._show_idle()

    def _build_header_actions(self) -> None:
        self.preset_picker = QComboBox()
        for name, preset in PRESETS.items():
            self.preset_picker.addItem(preset.title, name)
            self.preset_picker.setItemData(
                self.preset_picker.count() - 1, preset.blurb,
                Qt.ItemDataRole.ToolTipRole)
        index = self.preset_picker.findData(self.profile.preset)
        self.preset_picker.setCurrentIndex(max(0, index))
        self.preset_picker.currentIndexChanged.connect(self._on_preset_changed)
        self.preset_picker.setFixedWidth(150)
        self.add_header_action(self.preset_picker)

        savvy_holder = QWidget()
        savvy_row = QHBoxLayout(savvy_holder)
        savvy_row.setContentsMargins(0, 0, 0, 0)
        savvy_row.setSpacing(SPACE_SM)
        savvy_row.addWidget(label("Savvy mode", role="muted"))
        self.savvy = ToggleSwitch()
        self.savvy.setChecked(self.profile.savvy_mode)
        self.savvy.setToolTip(
            "Expands the raw evidence under every finding, and shows the list "
            "of everything the analyzer read.")
        self.savvy.toggled.connect(self._on_savvy_toggled)
        savvy_row.addWidget(self.savvy)
        self.add_header_action(savvy_holder)

        self.more_button = IconButton(
            "more-vertical", "Reports, baselines and the checks folder",
            tone="muted", size=18)
        self.more_button.clicked.connect(self._show_menu)
        self.add_header_action(self.more_button)

        self.analyse_button = QPushButton("Analyse")
        self.analyse_button.setProperty("variant", "primary")
        self.analyse_button.clicked.connect(self.analyse)
        self.add_header_action(self.analyse_button)

    def _build_hero(self) -> QWidget:
        card = Card()
        card.setProperty("card", "true")

        row = QHBoxLayout()
        row.setSpacing(SPACE_LG)

        self.ring = ProgressRing(diameter=124, thickness=10)
        self.ring.set_text("—", "not run")
        row.addWidget(self.ring, 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(SPACE_SM)

        headline_row = QHBoxLayout()
        headline_row.setSpacing(SPACE_SM)
        self.grade_badge = Badge("Not run", "neutral")
        headline_row.addWidget(self.grade_badge, 0, Qt.AlignmentFlag.AlignTop)
        self.headline = label("", role="body", wrap=True)
        headline_row.addWidget(self.headline, 1)
        texts.addLayout(headline_row)

        self.working = label("", role="mono", wrap=True)
        self.working.setToolTip(
            "Every finding costs the score its severity's weight: a critical "
            "25, a high 12, a medium 5, a low 2. Muted findings cost nothing.")
        texts.addWidget(self.working)

        self.chips_holder = QWidget()
        self.chips = QHBoxLayout(self.chips_holder)
        self.chips.setContentsMargins(0, 0, 0, 0)
        self.chips.setSpacing(SPACE_SM)
        texts.addWidget(self.chips_holder)

        # A flow rather than a row: seven facts side by side were a 650px
        # minimum on their own, which clipped the hero card's right edge at the
        # window's smallest size. They wrap onto a second line instead.
        self.facts_holder = flow_row(spacing=SPACE_LG)
        self.facts = self.facts_holder.layout()
        texts.addWidget(self.facts_holder)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        texts.addWidget(self.progress)
        self.progress_label = label("", role="caption")
        self.progress_label.setVisible(False)
        texts.addWidget(self.progress_label)

        row.addLayout(texts, 1)
        card.body.addLayout(row)
        return card

    def _build_findings_tab(self) -> QWidget:
        holder = QWidget()
        column = QVBoxLayout(holder)
        column.setContentsMargins(0, SPACE_MD, 0, 0)
        column.setSpacing(SPACE_MD)

        filters = QFrame()
        filters.setProperty("card", "flat")
        filter_row = QHBoxLayout(filters)
        filter_row.setContentsMargins(SPACE_MD, SPACE_SM, SPACE_MD, SPACE_SM)
        filter_row.setSpacing(SPACE_SM)

        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search findings — a word, a path, a check id…")
        self.search.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self.search, 1)

        # The pickers and toggles share one holder, so that when the whole bar
        # is too wide for the page they drop below the search box together
        # rather than each on a line of its own.
        controls = QWidget()
        control_row = QHBoxLayout(controls)
        control_row.setContentsMargins(0, 0, 0, 0)
        control_row.setSpacing(SPACE_SM)
        filter_row.addWidget(controls, 0)

        self.category_picker = QComboBox()
        self.category_picker.addItem("Every area", None)
        for category in CATEGORY_ORDER:
            self.category_picker.addItem(category.title, category)
        self.category_picker.currentIndexChanged.connect(self._on_category_changed)
        _let_shrink(self.category_picker)
        control_row.addWidget(self.category_picker, 0)

        self.sort_picker = QComboBox()
        self.sort_picker.addItem("Worst first", "severity")
        self.sort_picker.addItem("By area", "category")
        self.sort_picker.addItem("By check", "check")
        self.sort_picker.currentIndexChanged.connect(self._apply_filters)
        _let_shrink(self.sort_picker)
        control_row.addWidget(self.sort_picker, 0)

        self.show_passes = QPushButton("Show passed")
        self.show_passes.setCheckable(True)
        self.show_passes.setChecked(self.profile.show_passes)
        self.show_passes.setToolTip(
            "Checks that ran and found nothing wrong. Worth seeing once: "
            "“we looked and it is fine” is not the same as “we did not look”.")
        self.show_passes.clicked.connect(self._on_show_passes)
        control_row.addWidget(self.show_passes, 0)

        self.show_muted = QPushButton("Show muted")
        self.show_muted.setCheckable(True)
        self.show_muted.clicked.connect(self._apply_filters)
        control_row.addWidget(self.show_muted, 0)
        column.addWidget(filters)
        # Inset: the bar's own padding, and the tab widget's frame around it.
        self.make_responsive(filter_row, inset=2 * SPACE_MD + 6)

        self.result_count = label("", role="muted", wrap=True)
        column.addWidget(self.result_count)

        self.findings_holder = QWidget()
        self.findings_column = QVBoxLayout(self.findings_holder)
        self.findings_column.setContentsMargins(0, 0, 0, 0)
        self.findings_column.setSpacing(SPACE_SM)
        column.addWidget(self.findings_holder)

        self.findings_empty = EmptyState(
            "boot", "Nothing analysed yet",
            "ClamGuard has not looked at how this machine boots. The analysis "
            "reads about two hundred files and runs a dozen inspection "
            "commands; it changes nothing and takes a few seconds.",
            action_text="Analyse now")
        self.findings_empty.actioned.connect(self.analyse)
        column.addWidget(self.findings_empty)

        self.skipped_card = Card(
            "Checks that did not run", "Not the same as passing.", icon="info")
        self.skipped_text = label("", role="muted", wrap=True)
        self.skipped_card.body.addWidget(self.skipped_text)
        self.skipped_card.setVisible(False)
        column.addWidget(self.skipped_card)

        self.probe_card = Card(
            "What the analyzer looked at",
            "Every file read and every command run during the last analysis, "
            "in order. Nothing else was touched.", icon="terminal")
        self.probe_log = QPlainTextEdit()
        self.probe_log.setProperty("role", "log")
        self.probe_log.setReadOnly(True)
        self.probe_log.setMinimumHeight(240)
        self.probe_log.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.probe_card.body.addWidget(self.probe_log)
        self.probe_card.setVisible(False)
        column.addWidget(self.probe_card)

        column.addStretch(1)
        return holder

    # -- lifecycle --------------------------------------------------------

    def on_shown(self) -> None:
        if self.report is None and not self.analyzer.busy:
            self.analyse()

    def badge(self) -> str:
        if self.report is None:
            return ""
        serious = (self.report.count(Severity.CRITICAL)
                   + self.report.count(Severity.HIGH))
        return str(serious) if serious else ""

    # -- running ----------------------------------------------------------

    def analyse(self) -> None:
        if not self.analyzer.start():
            return

    def _load_catalogue(self) -> None:
        checks = self.analyzer.available_checks()
        self.checks_tab.set_checks(checks, self.analyzer.custom_problems)
        if self.analyzer.custom_problems:
            self.notice.set_message(
                f"{len(self.analyzer.custom_problems)} of your own check files "
                "could not be used. The Checks tab says why.", "warn")
            self.notice.setVisible(True)

    def _on_started(self, total: int) -> None:
        self.progress.setRange(0, total)
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.progress_label.setVisible(True)
        self.ring.set_indeterminate(True)
        self.ring.set_text("", "analysing")
        self.grade_badge.set_state("Analysing", "info")
        self.headline.setText(
            "Reading firmware variables, the kernel's own state, the boot "
            "files and everything set to start automatically.")

    def _on_progress(self, done: int, total: int, title: str) -> None:
        self.progress.setValue(done)
        self.progress_label.setText(f"{done} of {total} — {title}")

    def _on_busy(self, busy: bool) -> None:
        self.analyse_button.setEnabled(not busy)
        self.analyse_button.setText("Analysing…" if busy else "Analyse")
        self.preset_picker.setEnabled(not busy)

    def _on_failed(self, message: str) -> None:
        self.progress.setVisible(False)
        self.progress_label.setVisible(False)
        self.ring.set_indeterminate(False)
        self.notice.set_message(message, "danger")
        self.notice.setVisible(True)
        self._show_idle()

    # -- showing a report -------------------------------------------------

    def show_report(self, report: Report) -> None:
        self.report = report
        self.progress.setVisible(False)
        self.progress_label.setVisible(False)
        self.findings_empty.setVisible(False)

        self.ring.set_indeterminate(False)
        self.ring.set_progress(report.score / 100)
        self.ring.set_tone(report.grade_tone)
        self.ring.set_text(str(report.score), "out of 100")
        self.grade_badge.set_state(report.grade, report.grade_tone)
        self.headline.setText(report.headline())

        self.working.setText(report.score_explanation())

        self._build_chips(report)
        self._build_facts(report)
        self._build_rows(report)

        self.skipped_card.setVisible(bool(report.skipped))
        if report.skipped:
            self.skipped_text.setText("\n".join(
                f"• {item.title} — {item.reason}" for item in report.skipped))

        self.probe_card.setVisible(self.savvy.isChecked())
        self.probe_log.setPlainText("\n".join(report.probe_log))

        self.timeline_tab.update_report(report)
        self.exposure_tab.update_report(report)
        self.startup_tab.update_report(report)

        self.set_subtitle(
            f"{report.hostname} · {report.distribution or 'unknown'} · "
            f"analysed {format_age(report.started_at.timestamp())} in "
            f"{report.duration:.1f}s · {self.profile.summary()}")
        self.badge_changed.emit(self.badge())
        self.context.status_changed.emit()

    def _build_chips(self, report: Report) -> None:
        _discard(self.chips)
        chip = QPushButton("All")
        chip.setCheckable(True)
        chip.setChecked(self._severity_filter is None)
        chip.setProperty("variant", "ghost")
        chip.clicked.connect(lambda: self._filter_by_severity(None))
        self.chips.addWidget(chip)

        for level in CHIP_ORDER:
            count = report.count(level)
            if not count:
                continue
            button = QPushButton(f"{count} {level.label.lower()}")
            button.setCheckable(True)
            button.setChecked(self._severity_filter is level)
            button.setProperty("variant", "ghost")
            button.setProperty("tone", level.tone)
            button.clicked.connect(
                lambda _checked=False, value=level: self._filter_by_severity(value))
            restyle(button)
            self.chips.addWidget(button)

        muted = len(report.muted())
        if muted:
            note = label(f"· {muted} muted", role="caption")
            self.chips.addWidget(note)
        self.chips.addStretch(1)

    def _build_facts(self, report: Report) -> None:
        _discard(self.facts)
        for key, value in report.facts.items():
            tile = StatTile(value, key)
            tile.value_label.setProperty("role", "body")
            restyle(tile.value_label)
            self.facts.addWidget(tile)

    def _build_rows(self, report: Report) -> None:
        # Drop the page's own references first, then destroy: the rows from the
        # previous report are finished with, and leaving them merely orphaned
        # is what made repeated analyses grow the widget count.
        self._rows = []
        _discard(self.findings_column)
        savvy = self.savvy.isChecked()

        for finding in report.findings:
            row = FindingRow(finding, savvy=savvy)
            row.mute_requested.connect(self._mute)
            row.unmute_requested.connect(self._unmute)
            row.severity_changed.connect(self._override_severity)
            row.copied.connect(lambda message: self.notify.emit(message, "ok"))
            self._rows.append(row)

        self._apply_filters()

    # -- filtering --------------------------------------------------------

    def _visible_findings(self) -> list:
        if self.report is None:
            return []
        wanted = []
        text = self.search.text()
        for finding in self.report.findings:
            if finding.muted and not self.show_muted.isChecked():
                continue
            if finding.severity is Severity.PASS and not self.show_passes.isChecked():
                continue
            if self._severity_filter is not None \
                    and finding.severity is not self._severity_filter:
                continue
            if self._category_filter is not None \
                    and finding.category is not self._category_filter:
                continue
            if not finding.matches(text):
                continue
            wanted.append(finding)
        return sort_findings(wanted, self.sort_picker.currentData() or "severity")

    def _apply_filters(self, *_args) -> None:
        # _detach, not _discard: the rows are reused, and the category headers
        # and the "nothing matches" label are recreated below either way.
        _detach(self.findings_column)
        if self.report is None:
            return

        for widget in self._transient:
            widget.deleteLater()
        self._transient = []

        wanted = self._visible_findings()
        by_id = {row.finding.id: row for row in self._rows}
        grouping = (self.sort_picker.currentData() or "severity") == "category"
        current_category = None

        for finding in wanted:
            if grouping and finding.category is not current_category:
                current_category = finding.category
                self.findings_column.addWidget(
                    _category_header(current_category))
                self._transient.append(self.findings_column.itemAt(
                    self.findings_column.count() - 1).widget())
            row = by_id.get(finding.id)
            if row is not None:
                row.setParent(self.findings_holder)
                self.findings_column.addWidget(row)
                row.setVisible(True)

        total = len(self.report.findings)
        self.result_count.setText(
            f"Showing {len(wanted)} of {total} findings."
            + ("" if self.show_passes.isChecked()
               else f"  {len(self.report.passes())} checks passed — "
                    "“Show passed” lists them.")
        )
        self.findings_empty.setVisible(not wanted and not self.report.findings)

        if not wanted and self.report.findings:
            nothing = label("Nothing matches those filters.", role="muted")
            nothing.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.findings_column.addWidget(nothing)
            self._transient.append(nothing)

    def _filter_by_severity(self, severity) -> None:
        self._severity_filter = None if self._severity_filter is severity else severity
        # Clicking the "21 pass" chip has to turn passes on, or it filters to
        # a category the list is currently hiding and shows nothing.
        if self._severity_filter is Severity.PASS and not self.show_passes.isChecked():
            self.show_passes.setChecked(True)
            self.profile.show_passes = True
            self.profile.save()
        if self.report is not None:
            self._build_chips(self.report)
        self._apply_filters()

    def _on_category_changed(self) -> None:
        self._category_filter = self.category_picker.currentData()
        self._apply_filters()

    def _on_show_passes(self) -> None:
        self.profile.show_passes = self.show_passes.isChecked()
        self.profile.save()
        self._apply_filters()

    # -- profile edits ----------------------------------------------------

    def _on_preset_changed(self) -> None:
        name = self.preset_picker.currentData()
        if not name or name == self.profile.preset:
            return
        self.profile.set_preset(name)
        self.checks_tab.refresh_from_profile()
        self.notify.emit(f"Switched to the {PRESETS[name].title} profile. "
                         "Re-analysing.", "info")
        self.analyse()

    def _on_profile_changed(self) -> None:
        self.notice.set_message(
            "The profile changed. Analyse again to see the difference.",
            "info", action_text="Analyse")
        self.notice.actioned.connect(self.analyse, Qt.ConnectionType.UniqueConnection)
        self.notice.setVisible(True)

    def _on_savvy_toggled(self, on: bool) -> None:
        self.profile.savvy_mode = on
        self.profile.save()
        for row in self._rows:
            row.set_savvy(on)
        self.probe_card.setVisible(on and self.report is not None)

    def _mute(self, finding_id: str) -> None:
        if not confirm(
            self, "Stop counting this finding?",
            f"“{finding_id}” will stay in the list but will no longer count "
            "towards the score, and will not raise the sidebar badge.\n\n"
            "Use this for something you have decided about — Secure Boot off "
            "on a machine that cannot support it, say. It is not the same as "
            "turning the check off: the check still runs, so if the situation "
            "changes you will still see it.",
            confirm_text="Mute it", tone="info",
        ):
            return
        self.profile.mute(finding_id, "Muted from the Boot Analyzer.")
        self._refresh_after_profile_edit()
        self.notify.emit("Muted. It still appears under “Show muted”.", "info")

    def _unmute(self, finding_id: str) -> None:
        self.profile.unmute(finding_id)
        self._refresh_after_profile_edit()
        self.notify.emit("Counting it again.", "info")

    def _override_severity(self, finding_id: str, severity) -> None:
        self.profile.override_severity(finding_id, severity)
        self._refresh_after_profile_edit()

    def _refresh_after_profile_edit(self) -> None:
        """Re-apply the profile to the findings we already have.

        No need to re-probe: muting and severity overrides are applied to a
        Finding after the check produced it, so the same report can simply be
        re-decorated. Re-running would take three seconds and change nothing.
        """
        if self.report is None:
            return
        from dataclasses import replace

        refreshed = []
        for finding in self.report.findings:
            base = finding
            if finding.original_severity is not None:
                base = replace(finding, severity=finding.original_severity,
                               original_severity=None)
            if finding.muted:
                base = replace(base, muted=False, mute_reason="")
            refreshed.append(self.profile.apply_to(base))
        self.report = replace(self.report, findings=tuple(refreshed))
        self.show_report(self.report)

    # -- the ⋯ menu -------------------------------------------------------

    def _show_menu(self) -> None:
        menu = QMenu(self)
        has_report = self.report is not None

        export = menu.addMenu("Export this report")
        export.setEnabled(has_report)
        for name, extension, description in report_export.describe_formats():
            action = export.addAction(f"{description}  (.{extension})")
            action.triggered.connect(
                lambda _checked=False, fmt=name: self._export(fmt))

        menu.addSeparator()
        baseline = Baseline.load()
        record_action = menu.addAction(
            "Re-record the baseline…" if baseline.exists else "Record a baseline…")
        record_action.triggered.connect(self._record_baseline)
        if baseline.exists:
            info = menu.addAction(
                f"Baseline: {len(baseline.entries)} files, "
                f"recorded {format_age(_iso_timestamp(baseline.taken_at))}")
            info.setEnabled(False)

        menu.addSeparator()
        scan = menu.addAction("Scan the boot files with ClamAV")
        scan.triggered.connect(self._scan_boot_surfaces)

        folder = menu.addAction("Open the checks folder")
        folder.triggered.connect(self._open_custom_folder)

        menu.addSeparator()
        reset = menu.addAction("Reset this profile to defaults")
        reset.setEnabled(self.profile.customised)
        reset.triggered.connect(self._reset_profile)

        menu.exec(self.more_button.mapToGlobal(
            self.more_button.rect().bottomLeft()))

    def _export(self, format_name: str) -> None:
        if self.report is None:
            return
        directory = QFileDialog.getExistingDirectory(
            self, "Where should the report go?", str(paths.REPORTS_DIR))
        if not directory:
            return
        from pathlib import Path

        try:
            written = report_export.write(self.report, Path(directory), format_name)
        except (OSError, ValueError) as exc:
            self.notice.set_message(f"The report could not be written: {exc}",
                                    "danger")
            self.notice.setVisible(True)
            return
        extra = (" Every command in it is commented out — it is a worksheet, "
                 "not a script to run." if format_name == "script" else "")
        self.notify.emit(f"Written to {written.name}.{extra}", "ok")

    def _record_baseline(self) -> None:
        existing = Baseline.load()
        roots = "\n".join(f"    {root}" for root in WATCHED_ROOTS)
        if not confirm(
            self, "Record a baseline of the boot chain?",
            "ClamGuard will hash everything in these places and remember it, "
            "so that a later analysis can tell you exactly what changed:\n\n"
            f"{roots}\n\n"
            "Record it when you believe the machine is in a good state. "
            "Nothing is modified — the baseline is written to your own data "
            "directory."
            + ("\n\nThis replaces the baseline you recorded "
               f"{format_age(_iso_timestamp(existing.taken_at))}."
               if existing.exists else ""),
            confirm_text="Record it", tone="info",
            detail=f"Written to:\n{paths.DATA_DIR / 'boot-baseline.json'}",
        ):
            return

        self.notify.emit("Recording the baseline…", "info")
        run_in_background(
            lambda: _record_and_save(),
            on_done=self._baseline_recorded,
            on_error=lambda message: self.notice.set_message(
                f"The baseline could not be saved: {message}", "danger"),
        )

    def _baseline_recorded(self, result) -> None:
        count, hashed = result
        self.notify.emit(
            f"Baseline recorded: {count} files, {hashed} of them hashed. "
            "The rest are root-only and are tracked by size and date.", "ok")
        self.analyse()

    def _scan_boot_surfaces(self) -> None:
        """Hand the boot-critical directories to the scanner."""
        from pathlib import Path

        targets = [Path(os.path.expanduser(root)) for root in WATCHED_ROOTS]
        targets = [path for path in targets if path.exists()]
        if not targets:
            self.notify.emit("None of the boot directories could be read.", "warn")
            return
        self.notify.emit(
            f"Scanning {len(targets)} boot locations with ClamAV.", "info")
        self.request_scan.emit(ScanKind.CUSTOM, targets)

    def _open_custom_folder(self) -> None:
        try:
            sample = custom.write_example()
        except OSError as exc:
            self.notice.set_message(
                f"The checks folder could not be created: {exc}", "danger")
            self.notice.setVisible(True)
            return
        _open_in_file_manager(sample.parent)
        self.notify.emit(
            f"Your checks live in {sample.parent}. There is a worked example "
            "in there to copy.", "info")

    def _reset_profile(self) -> None:
        if not confirm(
            self, "Reset the Boot Analyzer profile?",
            "This puts the preset back to Balanced and clears every check you "
            "turned off, every severity you changed and every finding you "
            "muted. Your own check files in the checks folder are not touched.",
            confirm_text="Reset it", tone="warn", destructive=True,
        ):
            return
        self.profile.reset()
        self.preset_picker.setCurrentIndex(
            max(0, self.preset_picker.findData(self.profile.preset)))
        self.checks_tab.refresh_from_profile()
        self.notify.emit("Profile reset. Re-analysing.", "info")
        self.analyse()

    # -- idle state -------------------------------------------------------

    def _show_idle(self) -> None:
        self.ring.set_progress(0.0)
        self.ring.set_text("—", "not run")
        self.grade_badge.set_state("Not run", "neutral")
        self.headline.setText(
            "ClamGuard has not looked at how this machine boots yet. The "
            "analysis is read-only: it reads files and runs inspection "
            "commands, and changes nothing.")
        self.working.setText("")
        self.result_count.setText("")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detach(layout) -> None:
    """Empty a layout, leaving its widgets alive.

    Used when re-filtering the findings list: the page holds every FindingRow
    in ``self._rows`` and puts the matching ones straight back, so destroying
    them would mean rebuilding forty-five widgets on every keystroke in the
    search box.
    """
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)


def _let_shrink(picker: QComboBox, characters: int = 9) -> None:
    """Let a combo box be narrower than its longest entry.

    By default a QComboBox's minimum is its widest item, and five of them in
    the filter bar added up past the viewport at the window's smallest size.
    The popup still shows every entry in full.
    """
    picker.setSizeAdjustPolicy(
        QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
    picker.setMinimumContentsLength(characters)


def _discard(layout) -> None:
    """Empty a layout and destroy what was in it.

    setParent(None) alone is not enough: it orphans the widget but leaves the
    C++ object alive until the Python wrapper happens to be collected, which
    over a long-running session with repeated analyses is a slow leak.
    deleteLater() is the Qt-correct way to say "and this is finished with".
    """
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()


def _category_header(category: Category) -> QWidget:
    holder = QWidget()
    row = QHBoxLayout(holder)
    row.setContentsMargins(0, SPACE_MD, 0, 2)
    row.setSpacing(SPACE_SM)
    row.addWidget(IconLabel(category.icon, tone="faint", size=15), 0)
    row.addWidget(label(category.title, role="sectionLabel"), 0)
    row.addWidget(label(category.blurb, role="caption"), 1)
    return holder


def _record_and_save() -> tuple[int, int]:
    """Take a baseline and write it. Runs on a worker thread."""
    baseline = record()
    baseline.save()
    return len(baseline.entries), baseline.hashed_count


def _iso_timestamp(iso: str) -> float:
    from datetime import datetime

    try:
        return datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _open_in_file_manager(directory) -> None:
    """Best-effort xdg-open. A desktop without it is not an error worth raising."""
    try:
        subprocess.Popen(["xdg-open", str(directory)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass
