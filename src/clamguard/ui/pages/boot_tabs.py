"""The Boot Analyzer's four secondary tabs.

The Findings tab is the page itself; these are the places where a table says
more than a list of findings would:

``TimelineTab``    where the boot time went, as a bar rather than a sentence
``ExposureTab``    every unit's sandboxing score, sortable, with the detail
``StartupTab``     everything that starts automatically, in one list
``ChecksTab``      what runs, how harshly, and the knobs behind the presets

Each is an ordinary QWidget with an ``update_report()`` method. They hold no
state of their own beyond what they are showing, so the page can rebuild them
from a fresh report without any teardown.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDoubleSpinBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.boot.checks.services import Exposure, unit_detail
from ...core.boot.model import Report, Severity, format_duration
from ...core.boot.probe import Probe
from ...core.boot.profile import BASE_SEVERITIES, BASE_THRESHOLDS, Profile
from ...core.process import run_in_background
from ..theme import SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    Bar,
    BarList,
    Card,
    EmptyState,
    Segment,
    StackedBar,
    fit_table,
    label,
)

#: The boot phase colours, matching the HTML export so a printed report and
#: the window agree with each other.
PHASE_COLOURS = {
    "firmware": "#8b5cf6",
    "loader": "#3b82f6",
    "kernel": "#14b8a6",
    "initrd": "#f59e0b",
    "userspace": "#22a55a",
}


def _table(headers: list[str], stretch: int = 0) -> QTableWidget:
    """A read-only table set up the way every table on this page wants."""
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    header = table.horizontalHeader()
    for column in range(len(headers)):
        header.setSectionResizeMode(
            column,
            QHeaderView.ResizeMode.Stretch if column == stretch
            else QHeaderView.ResizeMode.ResizeToContents)
    return table


def _cell(text: str, *, tone: str = "", mono: bool = False,
          sort_value=None) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    if sort_value is not None:
        # Qt sorts by the display string unless given something better, which
        # would put "9.6" before "10.0".
        item.setData(Qt.ItemDataRole.UserRole, sort_value)
        item.setData(Qt.ItemDataRole.EditRole, sort_value)
    if tone:
        item.setData(Qt.ItemDataRole.ToolTipRole, text)
    if mono:
        font = item.font()
        font.setFamily("monospace")
        item.setFont(font)
    return item


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


class TimelineTab(QWidget):
    """Where the time between power-on and the login screen went."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, SPACE_MD, 0, 0)
        column.setSpacing(SPACE_MD)

        self.phases_card = Card("Boot phases", "", icon="gauge")
        self.total_badge = Badge("—", "neutral")
        self.phases_card.add_action(self.total_badge)
        self.bar = StackedBar()
        self.phases_card.body.addWidget(self.bar)
        self.phase_note = label("", role="muted", wrap=True)
        self.phases_card.body.addWidget(self.phase_note)
        column.addWidget(self.phases_card)

        self.units_card = Card(
            "Slowest units", "How long each unit took to start. Units that "
            "start in parallel do not add up — only the critical chain below "
            "actually delays the login screen.", icon="clock")
        self.units = BarList()
        self.units_card.body.addWidget(self.units)
        column.addWidget(self.units_card)

        self.chain_card = Card(
            "Critical chain", "The units that genuinely held the boot up, each "
            "waiting for the one below it.", icon="layers")
        self.chain = QPlainTextEdit()
        self.chain.setProperty("role", "log")
        self.chain.setReadOnly(True)
        self.chain.setMinimumHeight(180)
        self.chain_card.body.addWidget(self.chain)
        column.addWidget(self.chain_card)

        self.empty = EmptyState(
            "gauge", "No boot timing available",
            "systemd-analyze could not measure this boot. That happens on a "
            "machine that does not use systemd, or in a container.")
        column.addWidget(self.empty)
        self.empty.setVisible(False)
        column.addStretch(1)

    def update_report(self, report: Report) -> None:
        timings = report.timings
        has_timing = bool(timings and timings.measured)
        for widget in (self.phases_card, self.units_card, self.chain_card):
            widget.setVisible(has_timing)
        self.empty.setVisible(not has_timing)
        if not has_timing:
            return

        self.total_badge.set_state(timings.total_text, "neutral")
        self.bar.set_segments([
            Segment(phase.name, phase.seconds,
                    PHASE_COLOURS.get(phase.name, ""), phase.text)
            for phase in timings.phases
        ])
        slowest = max(timings.phases, key=lambda phase: phase.seconds,
                      default=None)
        self.phase_note.setText(
            f"The {slowest.name} phase took the longest, at {slowest.text} of "
            f"{timings.total_text}." if slowest else "")

        limit = max((seconds for _unit, seconds in timings.slowest_units[:1]),
                    default=1.0)
        self.units.set_bars([
            Bar(timings.unit_label(unit), seconds, format_duration(seconds),
                "danger" if seconds > limit * 0.66 else
                "warn" if seconds > limit * 0.33 else "info")
            for unit, seconds in timings.slowest_units[:15]
        ])
        self.chain.setPlainText("\n".join(timings.critical_chain)
                                or "systemd-analyze reported no critical chain.")


# ---------------------------------------------------------------------------
# Service exposure
# ---------------------------------------------------------------------------


class ExposureTab(QWidget):
    """Every service, scored by how much it could reach if compromised."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, SPACE_MD, 0, 0)
        column.setSpacing(SPACE_MD)

        self.card = Card(
            "Service exposure",
            "systemd's own score, 0 to 10, for how much of the system each "
            "unit could reach if something got into it. A high score is not a "
            "vulnerability — it is the blast radius if there ever is one. "
            "Select a unit to see exactly which protections it is missing.",
            icon="power")

        controls = QHBoxLayout()
        controls.setSpacing(SPACE_SM)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter units…")
        self.search.textChanged.connect(self._apply_filter)
        controls.addWidget(self.search, 1)
        self.summary = label("", role="muted")
        controls.addWidget(self.summary, 0)
        self.card.body.addLayout(controls)

        self.table = _table(["Unit", "Exposure", "Verdict"], stretch=0)
        self.table.setSortingEnabled(True)
        self.table.setMinimumHeight(260)
        self.table.itemSelectionChanged.connect(self._show_detail)
        self.card.body.addWidget(self.table)
        column.addWidget(self.card)

        self.detail_card = Card("", "Select a unit above.", icon="shield")
        self.detail = QPlainTextEdit()
        self.detail.setProperty("role", "log")
        self.detail.setReadOnly(True)
        self.detail.setMinimumHeight(220)
        self.detail.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.detail_card.body.addWidget(self.detail)
        column.addWidget(self.detail_card)

        self.empty = EmptyState(
            "power", "No exposure scores",
            "systemd-analyze security produced nothing. It needs systemd 246 "
            "or newer.")
        self.empty.setVisible(False)
        column.addWidget(self.empty)
        column.addStretch(1)

        self._rows: list[Exposure] = []
        self._loading = ""

    def update_report(self, report: Report) -> None:
        self._rows = list(report.details.get("exposure", ()))
        self.empty.setVisible(not self._rows)
        self.card.setVisible(bool(self._rows))
        self.detail_card.setVisible(bool(self._rows))
        if not self._rows:
            return

        unsafe = sum(1 for row in self._rows if row.score >= 9.0)
        self.summary.setText(
            f"{len(self._rows)} units · {unsafe} scoring 9.0 or worse")
        self._fill(self._rows)

    def _fill(self, rows) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            self.table.setItem(index, 0, _cell(row.unit))
            self.table.setItem(index, 1, _cell(f"{row.score:.1f}",
                                               sort_value=row.score))
            verdict = _cell(row.predicate)
            self.table.setItem(index, 2, verdict)
        self.table.setSortingEnabled(True)
        fit_table(self.table, row_height=30, maximum=420, minimum=160)

    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        self._fill([row for row in self._rows if needle in row.unit.lower()]
                   if needle else self._rows)

    def _show_detail(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        unit = self.table.item(items[0].row(), 0).text()
        if unit == self._loading:
            return
        self._loading = unit
        self.detail_card.set_title(unit)
        self.detail_card.set_subtitle("Asking systemd…")
        self.detail.setPlainText("")

        # systemd-analyze takes a moment per unit, so it goes to a worker
        # rather than freezing the table while you arrow through it.
        run_in_background(
            lambda name=unit: unit_detail(Probe(), name),
            on_done=lambda text, name=unit: self._detail_ready(name, text),
            on_error=lambda message, name=unit: self._detail_ready(name, message),
        )

    def _detail_ready(self, unit: str, text: str) -> None:
        if unit != self._loading:
            return      # the user moved on while it was running
        self.detail_card.set_subtitle(
            "Every sandboxing option systemd checks, and whether this unit "
            "sets it.")
        self.detail.setPlainText(text or "systemd-analyze returned nothing.")


# ---------------------------------------------------------------------------
# Startup surface
# ---------------------------------------------------------------------------


class StartupTab(QWidget):
    """Everything on this machine that runs without being asked."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, SPACE_MD, 0, 0)
        column.setSpacing(SPACE_MD)

        self.card = Card(
            "Startup surface",
            "Every systemd unit, desktop autostart entry, cron job, shell "
            "profile, udev rule and modprobe hook that runs on its own. This is "
            "the list malware wants to be on, so it is worth knowing what is "
            "already there.",
            icon="layers")

        controls = QHBoxLayout()
        controls.setSpacing(SPACE_SM)
        self.origin = QComboBox()
        self.origin.addItem("Everything", "")
        self.origin.currentIndexChanged.connect(self._apply_filter)
        controls.addWidget(self.origin, 0)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name, command or path…")
        self.search.textChanged.connect(self._apply_filter)
        controls.addWidget(self.search, 1)

        self.only_flagged = QPushButton("Only flagged")
        self.only_flagged.setCheckable(True)
        self.only_flagged.clicked.connect(self._apply_filter)
        controls.addWidget(self.only_flagged, 0)
        self.card.body.addLayout(controls)

        self.summary = label("", role="muted", wrap=True)
        self.card.body.addWidget(self.summary)

        self.table = _table(["", "Where from", "Name", "Runs", "Notes"], stretch=3)
        self.table.setMinimumHeight(320)
        self.table.itemSelectionChanged.connect(self._show_path)
        self.card.body.addWidget(self.table)

        self.path_label = label("", role="mono", wrap=True)
        self.card.body.addWidget(self.path_label)
        column.addWidget(self.card)

        self.empty = EmptyState(
            "layers", "Nothing enumerated yet",
            "Run an analysis and this fills with everything that starts "
            "automatically.")
        self.empty.setVisible(False)
        column.addWidget(self.empty)
        column.addStretch(1)

        self._entries: list = []

    def update_report(self, report: Report) -> None:
        self._entries = list(report.details.get("startup", ()))
        self.empty.setVisible(not self._entries)
        self.card.setVisible(bool(self._entries))
        if not self._entries:
            return

        origins = []
        for entry in self._entries:
            if entry.origin not in origins:
                origins.append(entry.origin)
        current = self.origin.currentData()
        self.origin.blockSignals(True)
        self.origin.clear()
        self.origin.addItem(f"Everything ({len(self._entries)})", "")
        for origin in origins:
            count = sum(1 for entry in self._entries if entry.origin == origin)
            self.origin.addItem(f"{origin} ({count})", origin)
        index = self.origin.findData(current)
        self.origin.setCurrentIndex(max(0, index))
        self.origin.blockSignals(False)

        flagged = sum(1 for entry in self._entries if entry.notable)
        unreadable = report.details.get("startup_unreadable", ())
        self.summary.setText(
            f"{len(self._entries)} automatic start-ups across "
            f"{len(origins)} mechanisms. {flagged} flagged for a closer look."
            + (f" {len(unreadable)} places could not be read without root: "
               + ", ".join(unreadable[:4]) + "." if unreadable else ""))
        self._apply_filter()

    def _apply_filter(self, *_args) -> None:
        needle = self.search.text().strip().lower()
        origin = self.origin.currentData() or ""
        rows = [
            entry for entry in self._entries
            if (not origin or entry.origin == origin)
            and (not self.only_flagged.isChecked() or entry.notable)
            and (not needle or needle in
                 f"{entry.name} {entry.command} {entry.path}".lower())
        ]
        rows.sort(key=lambda entry: (not entry.serious, not entry.notable,
                                     entry.origin, entry.name))
        self._fill(rows)

    def _fill(self, rows) -> None:
        self.table.setRowCount(len(rows))
        for index, entry in enumerate(rows):
            mark = "!" if entry.serious else ("•" if entry.notable else "")
            marker = _cell(mark)
            marker.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(index, 0, marker)
            self.table.setItem(index, 1, _cell(entry.origin))
            name = entry.name + ("" if entry.enabled else "  (disabled)")
            self.table.setItem(index, 2, _cell(name))
            self.table.setItem(index, 3, _cell(entry.command or "—", mono=True))
            self.table.setItem(index, 4, _cell(entry.reasons or ""))
        fit_table(self.table, row_height=28, maximum=520, minimum=200)
        self.path_label.setText("")

    def _show_path(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        row = items[0].row()
        name = self.table.item(row, 2).text().replace("  (disabled)", "")
        for entry in self._entries:
            if entry.name == name:
                self.path_label.setText(f"{entry.path}    →    {entry.command}")
                return


# ---------------------------------------------------------------------------
# Checks and policy
# ---------------------------------------------------------------------------


class ChecksTab(QWidget):
    """What runs, how harshly, and the knobs the presets are made of."""

    #: The profile changed in a way that needs a re-run to take effect.
    profile_changed = Signal()
    #: Open the folder where user-written checks live.
    open_custom_folder = Signal()

    def __init__(self, profile: Profile, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.profile = profile
        self._checks: list = []
        self._building = False

        column = QVBoxLayout(self)
        column.setContentsMargins(0, SPACE_MD, 0, 0)
        column.setSpacing(SPACE_MD)

        self.catalogue_card = Card(
            "Checks", "Everything the analyzer can look at, and what each one "
            "reads. Untick one to stop it running — the report then says so, "
            "rather than quietly showing fewer findings.", icon="check-circle")
        self.counts = Badge("", "neutral")
        self.catalogue_card.add_action(self.counts)

        self.table = _table(["Run", "Check", "Area", "What it reads"], stretch=3)
        self.table.setMinimumHeight(340)
        self.table.itemChanged.connect(self._on_check_toggled)
        self.catalogue_card.body.addWidget(self.table)
        column.addWidget(self.catalogue_card)

        self.custom_card = Card(
            "Your own checks",
            "Drop a JSON file into the checks folder and it appears in the "
            "list above. Six kinds are available — a sysctl value, a file's "
            "existence, its permissions, its contents, a kernel parameter, or a "
            "unit's state. There is deliberately no way to make one run a "
            "command.", icon="sliders")
        custom_row = QHBoxLayout()
        custom_row.setSpacing(SPACE_SM)
        self.custom_status = label("", role="muted", wrap=True)
        custom_row.addWidget(self.custom_status, 1)
        folder = QPushButton("Open the checks folder")
        folder.clicked.connect(self.open_custom_folder)
        custom_row.addWidget(folder, 0)
        self.custom_card.body.addLayout(custom_row)
        column.addWidget(self.custom_card)

        self.policy_card = Card(
            "How harshly", "The presets are nothing more than a set of these. "
            "Change one and the preset becomes “custom” — the arithmetic stays "
            "visible either way.", icon="shield")
        self.policy_table = _table(["Condition", "Severity"], stretch=0)
        self.policy_table.setMinimumHeight(300)
        self.policy_card.body.addWidget(self.policy_table)
        column.addWidget(self.policy_card)

        self.threshold_card = Card(
            "Thresholds", "The numbers the checks compare against.",
            icon="gauge")
        self.threshold_table = _table(["Threshold", "Value"], stretch=0)
        self.threshold_card.body.addWidget(self.threshold_table)
        column.addWidget(self.threshold_card)
        column.addStretch(1)

    # -- population -------------------------------------------------------

    def set_checks(self, checks, custom_problems=()) -> None:
        """Fill the catalogue. Called once the analyzer knows what exists."""
        self._checks = list(checks)
        self._building = True
        self.table.setRowCount(len(self._checks))
        for index, item in enumerate(self._checks):
            toggle = QTableWidgetItem(item.title)
            toggle.setFlags(Qt.ItemFlag.ItemIsUserCheckable
                            | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            toggle.setCheckState(Qt.CheckState.Checked
                                 if self.profile.is_enabled(item.id)
                                 else Qt.CheckState.Unchecked)
            toggle.setData(Qt.ItemDataRole.UserRole, item.id)
            toggle.setText("")
            self.table.setItem(index, 0, toggle)

            name = item.title + ("   (yours)" if "custom" in item.tags else "")
            title = _cell(name)
            title.setToolTip(item.id)
            self.table.setItem(index, 1, title)
            self.table.setItem(index, 2, _cell(item.category.title))
            self.table.setItem(index, 3, _cell(item.inspects))
        self._building = False
        fit_table(self.table, row_height=28, maximum=560, minimum=240)
        self._refresh_counts()

        mine = [item for item in self._checks if "custom" in item.tags]
        if custom_problems:
            self.custom_status.setText(
                f"{len(mine)} of your checks loaded. "
                + " ".join(f"⚠ {problem}" for problem in custom_problems))
        elif mine:
            self.custom_status.setText(
                f"{len(mine)} of your own checks are loaded: "
                + ", ".join(item.id for item in mine) + ".")
        else:
            self.custom_status.setText(
                "You have not written any yet. Opening the folder creates a "
                "worked example you can edit.")

        self._build_policy()
        self._build_thresholds()

    def _refresh_counts(self) -> None:
        off = len(self.profile.disabled_checks)
        self.counts.set_state(
            f"{len(self._checks) - off} of {len(self._checks)} running",
            "warn" if off else "neutral")

    def _on_check_toggled(self, item: QTableWidgetItem) -> None:
        if self._building or item.column() != 0:
            return
        check_id = item.data(Qt.ItemDataRole.UserRole)
        if not check_id:
            return
        self.profile.enable_check(
            check_id, item.checkState() == Qt.CheckState.Checked)
        self._refresh_counts()
        self.profile_changed.emit()

    # -- policy -----------------------------------------------------------

    def _build_policy(self) -> None:
        if self.policy_table.rowCount():
            return          # built once; the values are re-read on change
        keys = sorted(BASE_SEVERITIES)
        self.policy_table.setRowCount(len(keys))
        resolved = self.profile.policy()
        for index, key in enumerate(keys):
            self.policy_table.setItem(index, 0, _cell(key.replace("_", " ")))
            picker = QComboBox()
            picker.addItem("Preset default", None)
            for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                          Severity.LOW, Severity.INFO, Severity.PASS):
                picker.addItem(level.label, level)
            override = self.profile.policy_overrides.get(key)
            if override is not None:
                picker.setCurrentIndex(picker.findData(override))
            else:
                picker.setItemText(
                    0, f"Preset default ({resolved.severity(key).label})")
            picker.currentIndexChanged.connect(
                lambda position, name=key, box=picker:
                self._set_policy(name, box.itemData(position)))
            self.policy_table.setCellWidget(index, 1, picker)
        fit_table(self.policy_table, row_height=36, maximum=420, minimum=240)

    def _set_policy(self, key: str, severity) -> None:
        self.profile.override_policy(key, severity)
        self.profile_changed.emit()

    def _build_thresholds(self) -> None:
        if self.threshold_table.rowCount():
            return
        keys = sorted(BASE_THRESHOLDS)
        self.threshold_table.setRowCount(len(keys))
        resolved = self.profile.policy()
        for index, key in enumerate(keys):
            self.threshold_table.setItem(index, 0, _cell(key.replace("_", " ")))
            spin = QDoubleSpinBox()
            spin.setRange(0.0, 100000.0)
            spin.setDecimals(1)
            spin.setSingleStep(1.0)
            spin.setValue(resolved.threshold(key))
            spin.setFixedWidth(140)
            spin.valueChanged.connect(
                lambda value, name=key: self._set_threshold(name, value))
            self.threshold_table.setCellWidget(index, 1, spin)
        fit_table(self.threshold_table, row_height=36, maximum=420, minimum=200)

    def _set_threshold(self, key: str, value: float) -> None:
        self.profile.override_threshold(key, value)
        self.profile_changed.emit()

    def refresh_from_profile(self) -> None:
        """Re-read the profile after a preset change reset the overrides."""
        self._building = True
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            check_id = item.data(Qt.ItemDataRole.UserRole)
            item.setCheckState(Qt.CheckState.Checked
                               if self.profile.is_enabled(check_id)
                               else Qt.CheckState.Unchecked)
        self._building = False
        self._refresh_counts()

        resolved = self.profile.policy()
        for row in range(self.policy_table.rowCount()):
            key = self.policy_table.item(row, 0).text().replace(" ", "_")
            picker = self.policy_table.cellWidget(row, 1)
            if picker is None:
                continue
            picker.blockSignals(True)
            override = self.profile.policy_overrides.get(key)
            picker.setItemText(0, f"Preset default ({resolved.severity(key).label})"
                               if key in BASE_SEVERITIES else "Preset default")
            picker.setCurrentIndex(picker.findData(override) if override else 0)
            picker.blockSignals(False)

        for row in range(self.threshold_table.rowCount()):
            key = self.threshold_table.item(row, 0).text().replace(" ", "_")
            spin = self.threshold_table.cellWidget(row, 1)
            if spin is None or key not in BASE_THRESHOLDS:
                continue
            spin.blockSignals(True)
            spin.setValue(resolved.threshold(key))
            spin.blockSignals(False)
