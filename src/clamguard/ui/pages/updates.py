"""Signature updates: how current the databases are, and refreshing them.

The number that matters on this page is the age of the *daily* database.
ClamAV publishes it several times a day and it is what carries new threats;
main.cvd changes a few times a year and bytecode.cvd less often than that. So
the page leads with age, not with version numbers.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core.conf_file import ConfFile
from ...core.database import Freshness, format_bytes
from ...core.freshclam import UpdateState
from ...core.process import run_in_background
from ...core.services import Role
from ...core import paths
from .. import icons
from ..theme import SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    Card,
    IconLabel,
    KeyValueRow,
    MessageBar,
    Separator,
    label,
    restyle,
)
from .base import Page


class DatabaseCard(Card):
    """One signature database, with everything known about it."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("Database", icon="database", parent=parent)
        self.entry = None

        self.badge = Badge("", "neutral")
        self.add_action(self.badge)

        self.description = label("", role="caption", wrap=True)
        self.body.addWidget(self.description)
        self.body.addWidget(Separator())

        self.rows = QVBoxLayout()
        self.rows.setSpacing(0)
        self.body.addLayout(self.rows)

        self.verify_result = label("", role="caption")
        self.verify_result.setVisible(False)
        self.body.addWidget(self.verify_result)

        self.verify_button = QPushButton("Verify signature")
        self.verify_button.setProperty("variant", "link")
        self.body.addWidget(self.verify_button, 0, Qt.AlignmentFlag.AlignLeft)

    def show_entry(self, entry, warn_days: int) -> None:
        self.entry = entry
        self.set_title(entry.display_name)
        self.description.setText(entry.description)

        age = entry.age
        days = age.total_seconds() / 86400 if age else 0
        if entry.name == "daily":
            tone = "ok" if days <= warn_days else ("warn" if days <= warn_days * 3
                                                   else "danger")
        else:
            tone = "ok"
        self.badge.set_state(entry.age_text(), tone)

        _clear(self.rows)
        self.rows.addWidget(KeyValueRow("Version", str(entry.version) or "—"))
        self.rows.addWidget(KeyValueRow("Signatures", f"{entry.signature_count:,}"))
        self.rows.addWidget(KeyValueRow(
            "Built", entry.built.strftime("%d %B %Y, %H:%M %Z") if entry.built
            else entry.modified.strftime("%d %B %Y, %H:%M")))
        self.rows.addWidget(KeyValueRow("Size", format_bytes(entry.size)))
        self.rows.addWidget(KeyValueRow("File", entry.path.name, mono=True))

    def show_verify(self, ok: bool, message: str) -> None:
        self.verify_result.setText(message)
        self.verify_result.setProperty("tone", "ok" if ok else "danger")
        restyle(self.verify_result)
        self.verify_result.setVisible(True)
        self.verify_button.setEnabled(True)
        self.verify_button.setText("Verify signature")


class UpdatesPage(Page):
    PAGE_ID = "updates"
    TITLE = "Updates"
    SUBTITLE = "Virus signature downloads"
    ICON = "updates"

    def build(self) -> None:
        self.helper_notice = MessageBar("", "warn", action_text="How do I do that?")
        self.helper_notice.actioned.connect(self._explain_helper)
        self.body.addWidget(self.helper_notice)

        self.body.addWidget(self._build_status_card())

        self.database_row = QHBoxLayout()
        self.database_row.setSpacing(SPACE_MD)
        self.database_cards: dict[str, DatabaseCard] = {}
        for name in ("daily", "main", "bytecode"):
            card = DatabaseCard()
            card.verify_button.clicked.connect(
                lambda _=False, key=name: self._verify(key))
            self.database_cards[name] = card
            self.database_row.addWidget(card, 1)
        self.body.addLayout(self.database_row)
        # Three cards side by side need ~920px; below that they stack rather
        # than cutting the third one off.
        self.make_responsive(self.database_row)

        self.custom_card = Card("Third-party signatures", icon="file")
        self.custom_box = QVBoxLayout()
        self.custom_box.setSpacing(0)
        self.custom_card.body.addLayout(self.custom_box)
        self.body.addWidget(self.custom_card)

        self.body.addWidget(self._build_automatic_card())
        self.add_stretch()

        freshclam = self.context.freshclam
        freshclam.state_changed.connect(self._on_state)
        freshclam.progress.connect(self._on_progress)
        freshclam.output_line.connect(self._on_output)
        freshclam.finished.connect(self._on_finished)

    # -- cards ------------------------------------------------------------

    def _build_status_card(self) -> Card:
        card = Card()
        top = QHBoxLayout()
        top.setSpacing(SPACE_MD)

        self.status_icon = IconLabel("database", tone="ok", size=34)
        top.addWidget(self.status_icon, 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.status_title = label("", role="heading")
        self.status_detail = label("", role="muted", wrap=True)
        texts.addWidget(self.status_title)
        texts.addWidget(self.status_detail)
        top.addLayout(texts, 1)

        self.update_button = QPushButton("Update now")
        self.update_button.setProperty("variant", "primary")
        self.update_button.setProperty("size", "lg")
        self.update_button.setIcon(icons.icon("download", "#ffffff", size=18))
        self.update_button.clicked.connect(self._update_now)
        top.addWidget(self.update_button, 0, Qt.AlignmentFlag.AlignTop)
        card.body.addLayout(top)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setVisible(False)
        card.body.addWidget(self.progress)

        self.progress_label = label("", role="caption")
        self.progress_label.setVisible(False)
        card.body.addWidget(self.progress_label)

        self.output_toggle = QPushButton("Show what freshclam is doing")
        self.output_toggle.setProperty("variant", "link")
        self.output_toggle.setCheckable(True)
        self.output_toggle.toggled.connect(self._toggle_output)
        self.output_toggle.setVisible(False)
        card.body.addWidget(self.output_toggle, 0, Qt.AlignmentFlag.AlignLeft)

        self.output = QPlainTextEdit()
        self.output.setProperty("role", "log")
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(500)
        self.output.setMinimumHeight(150)
        self.output.setVisible(False)
        card.body.addWidget(self.output)

        self.status_card = card
        return card

    def _build_automatic_card(self) -> Card:
        card = Card("Automatic updates", "freshclam running in the background",
                    icon="clock")
        open_protection = QPushButton("Manage the service")
        open_protection.setProperty("variant", "ghost")
        open_protection.clicked.connect(lambda: self.navigate.emit("protection"))
        card.add_action(open_protection)

        self.automatic_box = QVBoxLayout()
        self.automatic_box.setSpacing(0)
        card.body.addLayout(self.automatic_box)
        self.automatic_card = card
        return card

    # -- refresh ----------------------------------------------------------

    def on_shown(self) -> None:
        self.context.database.refresh()
        self.context.services.refresh()
        self.refresh()

    def refresh(self) -> None:
        self._refresh_helper_notice()
        self._refresh_status()
        self._refresh_databases()
        self._refresh_custom()
        self._refresh_automatic()

    def _refresh_helper_notice(self) -> None:
        available = self.context.privileged.available
        self.helper_notice.setVisible(not available)
        if not available:
            self.helper_notice.set_message(
                "ClamGuard cannot download signatures itself: updates write to the "
                "system database directory, which needs administrator rights. The "
                "automatic updater service can still be doing this in the background.",
                "warn")
        self.update_button.setEnabled(available and not self.context.freshclam.running)

    def _refresh_status(self) -> None:
        summary = self.context.database.summary
        tone = summary.freshness.tone
        self.status_icon.set_icon(
            "check-circle" if summary.freshness is Freshness.CURRENT else "alert-triangle",
            tone=tone)
        self.status_title.setText({
            Freshness.CURRENT: "Signatures are up to date",
            Freshness.AGEING: "Signatures are getting old",
            Freshness.STALE: "Signatures are out of date",
            Freshness.MISSING: "No signatures installed",
            Freshness.UNKNOWN: "Signature status unknown",
        }[summary.freshness])
        self.status_title.setProperty("tone", tone)
        restyle(self.status_title)
        self.status_detail.setText(summary.headline())

    def _refresh_databases(self) -> None:
        summary = self.context.database.summary
        by_name = {entry.name: entry for entry in summary.official()}
        for name, card in self.database_cards.items():
            entry = by_name.get(name)
            card.setVisible(entry is not None)
            if entry is not None:
                card.show_entry(entry, self.context.database.warn_after_days)

    def _refresh_custom(self) -> None:
        _clear(self.custom_box)
        custom = self.context.database.summary.custom()
        self.custom_card.setVisible(bool(custom))
        if not custom:
            return
        self.custom_card.set_title(f"Third-party signatures — {len(custom)}")
        self.custom_box.addWidget(label(
            "Signature files in the database directory that did not come from "
            "ClamAV's official feed.", role="caption", wrap=True))
        for entry in custom:
            self.custom_box.addWidget(KeyValueRow(
                entry.path.name, f"{format_bytes(entry.size)} · {entry.age_text()}"))

    def _refresh_automatic(self) -> None:
        _clear(self.automatic_box)
        status = self.context.services.status(Role.UPDATER)

        row = QHBoxLayout()
        row.setSpacing(SPACE_SM)
        row.addWidget(label("Updater service", role="body"), 1)
        row.addWidget(Badge(status.summary(), status.tone()))
        holder = QWidget()
        holder.setLayout(row)
        self.automatic_box.addWidget(holder)

        if status.exists:
            self.automatic_box.addWidget(KeyValueRow("Unit", status.unit, mono=True))
            self.automatic_box.addWidget(KeyValueRow(
                "Starts at boot", "Yes" if status.enabled else "No"))
            if status.since:
                self.automatic_box.addWidget(KeyValueRow(
                    "Running since", status.since.strftime("%d %B %Y, %H:%M")))
        else:
            self.automatic_box.addWidget(label(
                "No freshclam service was found. Signatures will only update when "
                "you press Update now.", role="muted", wrap=True))

        checks = self._configured_checks_per_day()
        if checks:
            hours = 24 / checks
            self.automatic_box.addWidget(KeyValueRow(
                "Checks per day",
                f"{checks} (about every {hours:.0f} hour{'' if hours == 1 else 's'})"))

        self.automatic_box.addWidget(Separator())
        self.automatic_box.addWidget(KeyValueRow(
            "Database directory", str(paths.CLAMAV_DB_DIR), mono=True))

    def _configured_checks_per_day(self) -> int:
        """Read Checks out of freshclam.conf. Readable by anyone; no root needed."""
        conf = ConfFile.load_or_empty(paths.FRESHCLAM_CONF)
        return conf.get_int("Checks", 0)

    # -- updating ---------------------------------------------------------

    def _update_now(self) -> None:
        freshclam = self.context.freshclam
        reason = freshclam.blocking_reason()
        if reason:
            self.notify.emit(reason, "warn")
            return

        if freshclam.updater_service_running():
            from ..dialogs import confirm

            if not confirm(
                self, "The updater is already running",
                "The clamav-freshclam service is running in the background and "
                "holds freshclam's lock file. A manual update will probably refuse "
                "to start.\n\nYou can try anyway — nothing will be damaged — or stop "
                "the service first on the Protection page.",
                confirm_text="Try anyway", tone="info",
            ):
                return

        self.output.clear()
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.progress_label.setVisible(True)
        self.output_toggle.setVisible(True)
        freshclam.start()

    def _on_state(self, state: UpdateState) -> None:
        running = state is UpdateState.RUNNING
        self.update_button.setEnabled(not running and self.context.privileged.available)
        self.update_button.setText("Updating…" if running else "Update now")

    def _on_progress(self, text: str, percent: int) -> None:
        self.progress_label.setText(text)
        if percent < 0:
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, 100)
            self.progress.setValue(percent)

    def _on_output(self, line: str) -> None:
        self.output.appendPlainText(line)

    def _on_finished(self, result) -> None:
        self.progress.setVisible(False)
        self.progress_label.setText(result.headline())

        tone = {
            UpdateState.SUCCEEDED: "ok",
            UpdateState.UP_TO_DATE: "ok",
            UpdateState.CANCELLED: "warn",
            UpdateState.FAILED: "danger",
        }.get(result.state, "info")
        self.notify.emit(result.headline(), tone)

        if result.state is UpdateState.FAILED:
            self.output_toggle.setChecked(True)

        if result.updated_databases:
            reloaded = self.context.clamav.reload_daemon_database()
            if reloaded:
                self.notify.emit("Told the ClamAV daemon to load the new signatures.",
                                 "info")
        self.refresh()

    def _toggle_output(self, shown: bool) -> None:
        self.output.setVisible(shown)
        self.output_toggle.setText(
            "Hide what freshclam is doing" if shown else "Show what freshclam is doing")

    # -- verification -----------------------------------------------------

    def _verify(self, name: str) -> None:
        card = self.database_cards.get(name)
        if card is None or card.entry is None:
            return
        card.verify_button.setEnabled(False)
        card.verify_button.setText("Checking…")
        path = card.entry.path

        run_in_background(
            lambda: self.context.database.verify(path),
            on_done=lambda outcome: card.show_verify(*outcome),
            on_error=lambda message: card.show_verify(False, message),
        )

    def _explain_helper(self) -> None:
        from ..dialogs import confirm
        from ...core.privileged import install_command

        confirm(
            self, "Enabling privileged actions",
            "ClamGuard runs as you, not as root. To write to system directories it "
            "uses a small helper script that you install yourself — ClamGuard will "
            "never install it for you.\n\nRun this in a terminal, then come back and "
            "press Update now:",
            detail=install_command(),
            detail_label="COMMAND TO RUN",
            confirm_text="Got it", cancel_text="Close", tone="info",
        )


def _clear(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
