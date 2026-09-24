"""Real-time protection and the ClamAV services behind it.

This is the page that turns "clamav-clamonacc.service: failed" into a sentence
and a button. Each service gets a card showing what it is for, what state it is
in, and — when something is wrong — exactly what is wrong and what change would
fix it, with the diff shown before anything is written.

Nothing on this page acts without confirmation. Starting a service, stopping
one, or editing clamd.conf all go through ServiceController or ConfigApplier,
which always ask first.
"""

from __future__ import annotations


from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from pathlib import Path

from ...core import paths
from ...core.conf_file import ConfFile
from ...core.diagnostics import Diagnosis, Remedy, diagnose_on_access, diagnose_service
from ...core.privileged import install_command
from ...core.services import Role
from .. import icons
from ..config_apply import ConfigApplier, ServiceController
from ..dialogs import confirm
from ..theme import SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    Card,
    ElidedLabel,
    IconLabel,
    KeyValueRow,
    MessageBar,
    Separator,
    ToggleSwitch,
    label,
)
from .base import Page


class _DetectionRow(QWidget):
    """One thing real-time protection caught, with what you can do about it."""

    def __init__(self, detection, on_quarantine, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, SPACE_SM, 0, SPACE_SM)
        row.setSpacing(SPACE_MD)

        row.addWidget(IconLabel("bug", tone="danger", size=18), 0,
                      Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(1)
        head = QHBoxLayout()
        head.setSpacing(SPACE_SM)
        head.addWidget(label(detection.threat, role="body", tone="danger"), 0)
        head.addWidget(label(f"{detection.found_at:%H:%M:%S}", role="caption"), 0)
        head.addStretch(1)
        texts.addLayout(head)
        path_label = ElidedLabel(detection.path)
        path_label.setProperty("role", "mono")
        texts.addWidget(path_label)
        row.addLayout(texts, 1)

        if detection.still_exists:
            button = QPushButton("Quarantine")
            button.setProperty("variant", "primary")
            button.clicked.connect(lambda: on_quarantine(detection))
            row.addWidget(button, 0, Qt.AlignmentFlag.AlignTop)
        else:
            row.addWidget(Badge("Already gone", "neutral"), 0,
                          Qt.AlignmentFlag.AlignTop)


class DiagnosisBlock(QWidget):
    """One finding, its evidence, and the buttons that fix it."""

    def __init__(self, diagnosis: Diagnosis, on_fix, parent: QWidget | None = None):
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, SPACE_SM, 0, SPACE_SM)
        column.setSpacing(SPACE_SM)

        head = QHBoxLayout()
        head.setSpacing(SPACE_SM)
        icon = {"danger": "alert-circle", "warn": "alert-triangle"}.get(
            diagnosis.severity, "info")
        head.addWidget(IconLabel(icon, tone=diagnosis.severity, size=18), 0,
                       Qt.AlignmentFlag.AlignTop)
        head.addWidget(label(diagnosis.title, role="body", tone=diagnosis.severity,
                             wrap=True), 1)
        column.addLayout(head)

        column.addWidget(label(diagnosis.detail, role="muted", wrap=True))

        if diagnosis.evidence:
            evidence = QPlainTextEdit()
            evidence.setProperty("role", "log")
            evidence.setReadOnly(True)
            evidence.setPlainText("\n".join(diagnosis.evidence))
            evidence.setMaximumHeight(22 * min(6, len(diagnosis.evidence)) + 24)
            column.addWidget(evidence)

        if diagnosis.remedies:
            for remedy in diagnosis.remedies:
                column.addWidget(_RemedyRow(remedy, on_fix))


class _RemedyRow(QWidget):
    """A single proposed fix with its explanation and an Apply button."""

    def __init__(self, remedy: Remedy, on_fix, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(26, 2, 0, 2)
        row.setSpacing(SPACE_MD)

        texts = QVBoxLayout()
        texts.setSpacing(1)
        title_row = QHBoxLayout()
        title_row.setSpacing(SPACE_SM)
        title_row.addWidget(label(remedy.title, role="body"), 0)
        if remedy.recommended:
            title_row.addWidget(Badge("Recommended", "accent"), 0)
        title_row.addStretch(1)
        texts.addLayout(title_row)
        texts.addWidget(label(remedy.explanation, role="caption", wrap=True))
        row.addLayout(texts, 1)

        button = QPushButton("Review and apply")
        if remedy.recommended:
            button.setProperty("variant", "primary")
        button.clicked.connect(lambda: on_fix(remedy))
        row.addWidget(button, 0, Qt.AlignmentFlag.AlignTop)


class ServiceCard(Card):
    """One systemd unit with its state, its controls and its diagnoses."""

    def __init__(self, role: Role, controller: ServiceController,
                 parent: QWidget | None = None) -> None:
        super().__init__(role.title, role.explanation,
                         icon={"daemon": "cpu", "updater": "updates",
                               "onaccess": "shield-check"}[role.value],
                         parent=parent)
        self.role = role
        self.controller = controller

        self.state_badge = Badge("", "neutral")
        self.add_action(self.state_badge)

        self.facts = QVBoxLayout()
        self.facts.setSpacing(0)
        self.body.addLayout(self.facts)

        self.body.addWidget(Separator())

        controls = QHBoxLayout()
        controls.setSpacing(SPACE_SM)
        self.start_button = QPushButton("Start")
        self.start_button.setIcon(icons.icon("play", tone="muted", size=16))
        self.start_button.clicked.connect(lambda: controller.act("start", role))
        self.stop_button = QPushButton("Stop")
        self.stop_button.setIcon(icons.icon("stop", tone="muted", size=16))
        self.stop_button.clicked.connect(lambda: controller.act("stop", role))
        self.restart_button = QPushButton("Restart")
        self.restart_button.setIcon(icons.icon("refresh", tone="muted", size=16))
        self.restart_button.clicked.connect(lambda: controller.act("restart", role))
        controls.addWidget(self.start_button)
        controls.addWidget(self.stop_button)
        controls.addWidget(self.restart_button)
        controls.addStretch(1)

        controls.addWidget(label("Start at boot", role="muted"))
        self.boot_toggle = ToggleSwitch()
        self.boot_toggle.clicked.connect(self._toggle_boot)
        controls.addWidget(self.boot_toggle)
        self.body.addLayout(controls)

        self.diagnoses_box = QVBoxLayout()
        self.diagnoses_box.setSpacing(0)
        self.body.addLayout(self.diagnoses_box)

        self.journal_toggle = QPushButton("Show recent log")
        self.journal_toggle.setProperty("variant", "link")
        self.journal_toggle.setCheckable(True)
        self.journal_toggle.toggled.connect(self._toggle_journal)
        self.body.addWidget(self.journal_toggle, 0, Qt.AlignmentFlag.AlignLeft)

        self.journal = QPlainTextEdit()
        self.journal.setProperty("role", "log")
        self.journal.setReadOnly(True)
        self.journal.setMaximumHeight(200)
        self.journal.setVisible(False)
        self.body.addWidget(self.journal)

    def _toggle_boot(self) -> None:
        self.controller.act(
            "enable" if self.boot_toggle.isChecked() else "disable", self.role)

    def _toggle_journal(self, shown: bool) -> None:
        self.journal.setVisible(shown)
        self.journal_toggle.setText("Hide recent log" if shown else "Show recent log")

    def show_status(self, status, privileged: bool) -> None:
        self.state_badge.set_state(status.summary(), status.tone())

        _clear(self.facts)
        if not status.exists:
            self.facts.addWidget(label(
                "No systemd unit for this was found on this machine.",
                role="muted", wrap=True))
        else:
            self.facts.addWidget(KeyValueRow("Unit", status.unit, mono=True))
            if status.since and status.running:
                self.facts.addWidget(KeyValueRow(
                    "Running since", status.since.strftime("%d %B %Y, %H:%M")))
            if status.failed and status.exit_status:
                self.facts.addWidget(KeyValueRow(
                    "Exit status", str(status.exit_status), tone="danger"))

        usable = status.exists and privileged and not status.masked
        self.start_button.setEnabled(usable and not status.running)
        self.stop_button.setEnabled(usable and status.running)
        self.restart_button.setEnabled(usable)
        self.boot_toggle.setEnabled(usable)
        self.boot_toggle.setChecked(status.enabled)

        if not privileged:
            note = "Controlling services needs the ClamGuard helper."
            for button in (self.start_button, self.stop_button, self.restart_button):
                button.setToolTip(note)
            self.boot_toggle.setToolTip(note)

    def show_diagnoses(self, diagnoses: list[Diagnosis], on_fix) -> None:
        _clear(self.diagnoses_box)
        if not diagnoses:
            return
        self.diagnoses_box.addWidget(Separator())
        for diagnosis in diagnoses:
            self.diagnoses_box.addWidget(DiagnosisBlock(diagnosis, on_fix))

    def show_journal(self, text: str) -> None:
        self.journal.setPlainText(text or "Nothing in the journal for this unit.")


class ProtectionPage(Page):
    PAGE_ID = "protection"
    TITLE = "Protection"
    SUBTITLE = "Real-time scanning and the ClamAV services behind it"
    ICON = "protection"

    def build(self) -> None:
        self.applier = ConfigApplier(self.context, self)
        self.applier.finished.connect(self._on_applied)
        self.applier.progress.connect(lambda text: self.notify.emit(text, "info"))

        self.controller = ServiceController(self.context, self)
        self.controller.finished.connect(self._on_service_action)

        self.helper_notice = MessageBar("", "warn", action_text="How?")
        self.helper_notice.actioned.connect(self._explain_helper)
        self.body.addWidget(self.helper_notice)

        self.body.addWidget(self._build_realtime_feed())

        self.cards: dict[Role, ServiceCard] = {}
        for role in (Role.ONACCESS, Role.DAEMON, Role.UPDATER):
            card = ServiceCard(role, self.controller)
            self.cards[role] = card
            self.body.addWidget(card)

        self.body.addWidget(self._build_onaccess_settings())
        self.add_stretch()

    def _build_realtime_feed(self) -> Card:
        """What on-access scanning has caught while ClamGuard has been open.

        Without this, real-time protection could be working perfectly and the
        application would show nothing but a green badge — which is exactly the
        situation that makes people think it is broken.
        """
        card = Card("Caught by real-time protection", icon="bug")

        self.feed_badge = Badge("", "neutral")
        card.add_action(self.feed_badge)

        self.feed_status = label("", role="muted", wrap=True)
        card.body.addWidget(self.feed_status)

        self.feed_box = QVBoxLayout()
        self.feed_box.setSpacing(0)
        card.body.addLayout(self.feed_box)

        self.realtime_card = card
        return card

    def _refresh_realtime_feed(self) -> None:
        monitor = self.context.realtime
        caught = monitor.history

        reason = monitor.unavailable_reason()
        if reason:
            self.feed_badge.set_state("Unavailable", "neutral")
            self.feed_status.setText(reason)
        elif not monitor.watching:
            self.feed_badge.set_state("Not watching", "neutral")
            self.feed_status.setText(
                "ClamGuard watches the daemon's log for detections while real-time "
                "protection is running. It is not running at the moment.")
        else:
            self.feed_badge.set_state("Watching", "ok")
            self.feed_status.setText(
                f"{len(caught)} detection{'' if len(caught) == 1 else 's'} since "
                "ClamGuard started." if caught else
                "Watching the daemon's log. Anything the on-access scanner finds "
                "appears here as it happens.")

        _clear(self.feed_box)
        for detection in caught[:12]:
            self.feed_box.addWidget(Separator())
            self.feed_box.addWidget(_DetectionRow(detection, self._quarantine_caught))

    def _quarantine_caught(self, detection) -> None:
        """Move something the on-access scanner found into the vault."""
        path = Path(detection.path)
        if not path.exists():
            self.notify.emit(f"{detection.filename} is already gone.", "info")
            self.context.realtime.forget(detection.path)
            self._refresh_realtime_feed()
            return

        def done(entry) -> None:
            self.context.realtime.forget(detection.path)
            self.context.history.set_action_for_quarantine(entry.id, "quarantined")
            self.notify.emit(f"{detection.filename} moved to quarantine.", "ok")
            self._refresh_realtime_feed()

        self.context.quarantine.quarantine(
            path, detection.threat, engine="clamonacc",
            on_success=done,
            on_error=lambda message: self.notify.emit(message, "danger"))

    def _build_onaccess_settings(self) -> Card:
        card = Card("What real-time scanning watches",
                    "These come from clamd.conf and apply to clamonacc",
                    icon="eye")
        self.settings_box = QVBoxLayout()
        self.settings_box.setSpacing(0)
        card.body.addLayout(self.settings_box)

        open_config = QPushButton("Edit all of clamd.conf")
        open_config.setProperty("variant", "link")
        open_config.clicked.connect(lambda: self.navigate.emit("configuration"))
        card.body.addWidget(open_config, 0, Qt.AlignmentFlag.AlignLeft)
        self.onaccess_card = card
        return card

    # -- refresh ----------------------------------------------------------

    def on_shown(self) -> None:
        self.context.services.refresh()
        self.context.privileged.refresh()
        self.refresh()

    def refresh(self) -> None:
        privileged = self.context.privileged.available
        self.helper_notice.setVisible(not privileged)
        if not privileged:
            self.helper_notice.set_message(
                "ClamGuard can see what these services are doing but cannot start, "
                "stop or reconfigure them: that needs administrator rights, which "
                "come from a helper you install yourself.", "warn")

        self._refresh_realtime_feed()

        conf = ConfFile.load_or_empty(paths.CLAMD_CONF)
        statuses = self.context.services.statuses()

        for role, card in self.cards.items():
            status = statuses[role]
            card.show_status(status, privileged)
            journal_lines = self.context.services.last_error_lines(role, limit=12)

            if role is Role.ONACCESS:
                diagnoses = diagnose_on_access(
                    conf, status, statuses[Role.DAEMON], journal_lines,
                    paths.CLAMD_CONF)
            else:
                diagnoses = diagnose_service(role, status, journal_lines)
            card.show_diagnoses(diagnoses, self._apply_remedy)

            if card.journal.isVisible():
                self._load_journal(role, card)

        self._refresh_onaccess_settings(conf)

    def _load_journal(self, role: Role, card: ServiceCard) -> None:
        result = self.context.services.journal(role, lines=200)
        card.show_journal(result.stdout if result.ok else result.error)

    def _refresh_onaccess_settings(self, conf: ConfFile) -> None:
        _clear(self.settings_box)

        include = conf.get_all("OnAccessIncludePath")
        mount = conf.get_all("OnAccessMountPath")
        exclude_paths = conf.get_all("OnAccessExcludePath")
        exclude_users = conf.get_all("OnAccessExcludeUname")
        exclude_uids = conf.get_all("OnAccessExcludeUID")

        self.settings_box.addWidget(KeyValueRow(
            "Watched directories", "\n".join(include) or "none", mono=bool(include)))
        self.settings_box.addWidget(KeyValueRow(
            "Watched mount points", "\n".join(mount) or "none", mono=bool(mount)))
        if exclude_paths:
            self.settings_box.addWidget(KeyValueRow(
                "Never watched", "\n".join(exclude_paths), mono=True))

        excluded = exclude_users + exclude_uids
        if conf.get_bool("OnAccessExcludeRootUID", False):
            excluded.append("everything running as root")
        self.settings_box.addWidget(KeyValueRow(
            "Ignored accounts", ", ".join(excluded) or "none — this stops clamonacc "
            "from starting", tone="" if excluded else "danger"))

        blocking = conf.get_bool("OnAccessPrevention", False)
        self.settings_box.addWidget(KeyValueRow(
            "On detection", "Access is blocked" if blocking
            else "Reported only, access still allowed",
            tone="ok" if blocking else "warn"))
        self.settings_box.addWidget(KeyValueRow(
            "Also scan on create and move",
            "Yes" if conf.get_bool("OnAccessExtraScanning", False) else "No"))
        self.settings_box.addWidget(KeyValueRow(
            "Maximum file size", conf.get("OnAccessMaxFileSize") or "5M (default)"))

    # -- actions ----------------------------------------------------------

    def _apply_remedy(self, remedy: Remedy) -> None:
        """Turn a diagnosis remedy into a reviewed configuration change."""
        try:
            conf = ConfFile.load(remedy.file)
        except OSError as error:
            self.notify.emit(f"Cannot read {remedy.file}: {error}", "danger")
            return

        remedy.apply_to(conf)
        if not conf.is_modified():
            self.notify.emit("That change is already in place.", "info")
            return

        self.applier.apply(
            remedy.file, conf.to_text(), conf.diff(remedy.file.name),
            f"{remedy.title}\n\n{remedy.explanation}",
            restart=remedy.restart,
        )

    def _on_applied(self, ok: bool, message: str) -> None:
        self.notify.emit(message, "ok" if ok else "warn")
        if ok:
            self.context.services.refresh()
            self.refresh()

    def _on_service_action(self, ok: bool, message: str) -> None:
        self.notify.emit(message, "ok" if ok else "danger")
        self.refresh()

    def _explain_helper(self) -> None:
        confirm(
            self, "Enabling privileged actions",
            "ClamGuard never runs as root. A short helper script does the few "
            "privileged things — writing /etc/clamav, controlling services, running "
            "updates — and you install it yourself so you can read it first.\n\n"
            "Run this in a terminal:",
            detail=install_command(), detail_label="COMMAND TO RUN",
            confirm_text="Got it", cancel_text="Close", tone="info",
        )


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
            continue
        child = item.layout()
        if child is not None:
            _clear(child)
