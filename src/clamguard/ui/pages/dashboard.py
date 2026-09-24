"""The dashboard: one honest answer to "am I protected?", and the reasons.

This is the page most users will look at most, and often the only one. It has
to do three things in the first second of looking at it:

1. say whether the machine is covered, in one word and one colour;
2. list what is wrong, if anything, with a button that fixes each thing;
3. offer the two actions people actually want — scan, and update.

Everything else on the page is supporting detail.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core.database import format_bytes, humanise_age
from ...core.scan_targets import ScanKind
from ...core.scanner import format_duration
from ...core.services import Role
from .. import icons
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM
from ..widgets import (Badge, Card, IconLabel, KeyValueRow, MessageBar,
                       Separator, label, restyle)
from .base import Page


class HeroCard(QFrame):
    """The big protection banner at the top of the dashboard."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("card", "tint-ok")

        row = QHBoxLayout(self)
        row.setContentsMargins(SPACE_LG + 6, SPACE_LG, SPACE_LG + 6, SPACE_LG)
        row.setSpacing(SPACE_LG)

        self._shield = IconLabel("shield", tone="ok", size=56)
        row.addWidget(self._shield, 0, Qt.AlignmentFlag.AlignVCenter)

        column = QVBoxLayout()
        column.setSpacing(3)
        self._title = label("Checking…", role="display")
        self._detail = label("", role="body", wrap=True)
        column.addWidget(self._title)
        column.addWidget(self._detail)
        row.addLayout(column, 1)

        actions = QVBoxLayout()
        actions.setSpacing(SPACE_SM)
        self.scan_button = QPushButton("Quick scan")
        self.scan_button.setProperty("variant", "primary")
        self.scan_button.setProperty("size", "lg")
        self.scan_button.setIcon(icons.icon("scan", "#ffffff", size=18))
        self.scan_button.setMinimumWidth(168)

        self.update_button = QPushButton("Update signatures")
        self.update_button.setIcon(icons.icon("updates", tone="muted", size=18))
        self.update_button.setMinimumWidth(168)

        actions.addWidget(self.scan_button)
        actions.addWidget(self.update_button)
        row.addLayout(actions, 0)

    def set_status(self, title: str, detail: str, tone: str, icon_name: str) -> None:
        self.setProperty("card", f"tint-{tone}")
        restyle(self)
        self._shield.set_icon(icon_name, tone=tone)
        self._title.setText(title)
        self._title.setProperty("tone", tone)
        restyle(self._title)
        self._detail.setText(detail)


class IssueRow(QFrame):
    """One thing to fix, with the button that fixes it."""

    def __init__(self, issue, on_action, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, SPACE_SM, 0, SPACE_SM)
        row.setSpacing(SPACE_MD)

        tone = "danger" if issue.blocking else "warn"
        row.addWidget(
            IconLabel("alert-circle" if issue.blocking else "alert-triangle",
                      tone=tone, size=18), 0, Qt.AlignmentFlag.AlignTop)

        texts = QVBoxLayout()
        texts.setSpacing(1)
        texts.addWidget(label(issue.title, role="body", tone=tone))
        texts.addWidget(label(issue.detail, role="muted", wrap=True))
        row.addLayout(texts, 1)

        if issue.page and issue.action_text:
            button = QPushButton(issue.action_text)
            button.clicked.connect(lambda: on_action(issue.page))
            row.addWidget(button, 0, Qt.AlignmentFlag.AlignTop)
        elif issue.page:
            button = QPushButton("Open")
            button.setProperty("variant", "ghost")
            button.clicked.connect(lambda: on_action(issue.page))
            row.addWidget(button, 0, Qt.AlignmentFlag.AlignTop)


class ServiceRow(QFrame):
    """One systemd unit, with its state."""

    def __init__(self, role: Role, status, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, SPACE_SM - 2, 0, SPACE_SM - 2)
        row.setSpacing(SPACE_MD)

        texts = QVBoxLayout()
        texts.setSpacing(1)
        texts.addWidget(label(role.title, role="body"))
        texts.addWidget(label(role.explanation, role="caption"))
        row.addLayout(texts, 1)
        row.addWidget(Badge(status.summary(), status.tone()), 0,
                      Qt.AlignmentFlag.AlignVCenter)


class DashboardPage(Page):
    PAGE_ID = "dashboard"
    TITLE = "Dashboard"
    SUBTITLE = "Protection status at a glance"
    ICON = "dashboard"

    def build(self) -> None:
        self.welcome = MessageBar(
            "ClamGuard is ready to scan. To let it also update signatures, control "
            "ClamAV's services and edit /etc/clamav, install the small helper that "
            "does those as root — you run that yourself, after reading it.",
            "info", action_text="Show me how", dismissible=True)
        self.welcome.actioned.connect(self._explain_helper)
        self.welcome.dismissed.connect(
            lambda: self.context.settings.set("helper_prompt_dismissed", True))
        self.body.addWidget(self.welcome)

        self.hero = HeroCard()
        self.hero.scan_button.clicked.connect(self._quick_scan)
        self.hero.update_button.clicked.connect(lambda: self.navigate.emit("updates"))
        self.body.addWidget(self.hero)

        self.issues_card = Card("What needs attention", icon="alert-triangle", tone="")
        self.body.addWidget(self.issues_card)

        grid = QHBoxLayout()
        grid.setSpacing(SPACE_MD)
        grid.addWidget(self._build_signatures_card(), 1)
        grid.addWidget(self._build_last_scan_card(), 1)
        self.body.addLayout(grid)
        self.make_responsive(grid)

        self.services_card = Card("ClamAV services", "What is running right now",
                                  icon="cpu")
        open_protection = QPushButton("Manage")
        open_protection.setProperty("variant", "ghost")
        open_protection.clicked.connect(lambda: self.navigate.emit("protection"))
        self.services_card.add_action(open_protection)
        self.body.addWidget(self.services_card)
        inspection = QHBoxLayout()
        inspection.setSpacing(SPACE_MD)
        inspection.addWidget(self._build_boot_card(), 1)
        inspection.addWidget(self._build_hunt_card(), 1)
        self.body.addLayout(inspection)
        self.make_responsive(inspection)

        self.body.addWidget(self._build_stats_card())
        self.add_stretch()

    # -- cards ------------------------------------------------------------

    def _build_boot_card(self) -> Card:
        """A pointer to the Boot Analyzer, not a summary of it.

        Deliberately does not run the analysis. It takes three seconds and
        reads a couple of hundred files, which is fine when somebody asks for
        it and wrong on every launch. The dashboard's job here is to say the
        page exists.
        """
        card = Card(
            "How this machine boots",
            "Scanning covers files. The Boot Analyzer covers the firmware, the "
            "bootloader, the kernel, and everything set to start on its own — "
            "the part a file scanner can never see.",
            icon="boot")
        open_boot = QPushButton("Analyse")
        open_boot.setProperty("variant", "ghost")
        open_boot.clicked.connect(lambda: self.navigate.emit("boot"))
        card.add_action(open_boot)
        return card

    def _build_hunt_card(self) -> Card:
        """A pointer to Hunt. Like the Boot card, it runs nothing itself.

        Indexing reads a couple of hundred megabytes; doing that because
        somebody opened the dashboard would be rude. This says the page is
        there and what it is for.
        """
        card = Card(
            "What the logs remember",
            "Every application on this machine writes a log somewhere nobody "
            "reads. Hunt finds them, converts them into one table, and lets "
            "you query the lot in KQL — then runs a set of rules over them "
            "for the things people usually miss.",
            icon="hunt")
        open_hunt = QPushButton("Open Hunt")
        open_hunt.setProperty("variant", "ghost")
        open_hunt.clicked.connect(lambda: self.navigate.emit("hunt"))
        card.add_action(open_hunt)
        return card

    def _build_signatures_card(self) -> Card:
        card = Card("Virus signatures", icon="database")
        self.signature_headline = label("", role="body", wrap=True)
        card.body.addWidget(self.signature_headline)
        card.body.addWidget(Separator())

        self.signature_rows = QVBoxLayout()
        self.signature_rows.setSpacing(0)
        card.body.addLayout(self.signature_rows)

        card.body.addStretch(1)
        update_now = QPushButton("Check for updates")
        update_now.setProperty("variant", "link")
        update_now.clicked.connect(lambda: self.navigate.emit("updates"))
        card.body.addWidget(update_now, 0, Qt.AlignmentFlag.AlignLeft)
        self.signatures_card = card
        return card

    def _build_last_scan_card(self) -> Card:
        card = Card("Last scan", icon="scan")
        self.last_scan_headline = label("", role="body", wrap=True)
        card.body.addWidget(self.last_scan_headline)
        card.body.addWidget(Separator())

        self.last_scan_rows = QVBoxLayout()
        self.last_scan_rows.setSpacing(0)
        card.body.addLayout(self.last_scan_rows)

        card.body.addStretch(1)
        open_history = QPushButton("See all scans")
        open_history.setProperty("variant", "link")
        open_history.clicked.connect(lambda: self.navigate.emit("history"))
        card.body.addWidget(open_history, 0, Qt.AlignmentFlag.AlignLeft)
        self.last_scan_card = card
        return card

    def _build_stats_card(self) -> Card:
        card = Card("Since you installed ClamGuard", icon="activity")
        self.stats_grid = QGridLayout()
        self.stats_grid.setHorizontalSpacing(SPACE_LG * 2)
        card.body.addLayout(self.stats_grid)
        return card

    # -- refresh ----------------------------------------------------------

    def on_shown(self) -> None:
        self.context.refresh()
        self.refresh()

    def refresh(self) -> None:
        # The one-off nudge about the helper: shown until it is installed or
        # the user dismisses it, and never again after either.
        self.welcome.setVisible(
            not self.context.privileged.available
            and not self.context.settings.bool("helper_prompt_dismissed"))

        status = self.context.protection_status()
        self.hero.set_status(status.level.title, status.headline, status.level.tone,
                             status.level.icon)
        self._refresh_issues(status)
        self._refresh_signatures()
        self._refresh_last_scan()
        self._refresh_services()
        self._refresh_stats()

    def _refresh_issues(self, status) -> None:
        _empty(self.issues_card.body)
        if not status.issues:
            row = QHBoxLayout()
            row.setSpacing(SPACE_SM)
            row.addWidget(IconLabel("check-circle", tone="ok", size=18), 0)
            row.addWidget(label("Nothing needs your attention.", role="body", tone="ok"), 1)
            self.issues_card.body.addLayout(row)
            self.issues_card.set_title("All clear")
            return

        count = len(status.issues)
        self.issues_card.set_title(
            "1 thing needs your attention" if count == 1
            else f"{count} things need your attention")
        for index, issue in enumerate(status.issues):
            if index:
                self.issues_card.body.addWidget(Separator())
            self.issues_card.body.addWidget(
                IssueRow(issue, lambda page: self.navigate.emit(page)))

    def _refresh_signatures(self) -> None:
        summary = self.context.database.summary
        self.signature_headline.setText(summary.headline())
        self.signature_headline.setProperty("tone", summary.freshness.tone)
        restyle(self.signature_headline)

        _empty(self.signature_rows)
        for entry in summary.official():
            self.signature_rows.addWidget(KeyValueRow(
                entry.display_name,
                f"version {entry.version} · {entry.signature_count:,} signatures · "
                f"{entry.age_text()}",
            ))
        if not summary.official():
            self.signature_rows.addWidget(
                label("No official databases found.", role="muted"))
        else:
            self.signature_rows.addWidget(KeyValueRow(
                "On disk", format_bytes(summary.total_bytes)))

    def _refresh_last_scan(self) -> None:
        last = self.context.history.last_scan()
        _empty(self.last_scan_rows)

        if last is None:
            self.last_scan_headline.setText("This machine has not been scanned yet.")
            self.last_scan_headline.setProperty("tone", "warn")
            restyle(self.last_scan_headline)
            self.last_scan_rows.addWidget(
                label("Run a quick scan to get a baseline.", role="muted", wrap=True))
            return

        self.last_scan_headline.setText(last.outcome())
        self.last_scan_headline.setProperty("tone", last.tone)
        restyle(self.last_scan_headline)

        when = last.started_at or datetime.now()
        self.last_scan_rows.addWidget(KeyValueRow(
            "When", f"{when:%A %d %B, %H:%M} ({humanise_age(datetime.now() - when)})"))
        self.last_scan_rows.addWidget(KeyValueRow("Type", last.kind.capitalize()))
        self.last_scan_rows.addWidget(KeyValueRow("Scope", last.target_text()))
        self.last_scan_rows.addWidget(KeyValueRow(
            "Result", f"{last.files_scanned:,} files in {format_duration(last.duration)}"))

    def _refresh_services(self) -> None:
        _empty(self.services_card.body)
        if not self.context.services.available:
            self.services_card.body.addWidget(label(
                "This machine does not use systemd, so ClamGuard cannot report on "
                "ClamAV's services.", role="muted", wrap=True))
            return

        shown = 0
        for role in Role:
            status = self.context.services.status(role)
            if not status.exists:
                continue
            if shown:
                self.services_card.body.addWidget(Separator())
            self.services_card.body.addWidget(ServiceRow(role, status))
            shown += 1
        if not shown:
            self.services_card.body.addWidget(label(
                "No ClamAV systemd units were found on this machine.",
                role="muted", wrap=True))

    def _refresh_stats(self) -> None:
        while self.stats_grid.count():
            item = self.stats_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        totals = self.context.history.totals()
        quarantined = self.context.quarantine.count()
        entries = (
            (f"{totals['scans']:,}", "scans run", ""),
            (f"{totals['files']:,}", "files checked", ""),
            (f"{totals['threats']:,}", "threats found",
             "danger" if totals["threats"] else ""),
            (f"{quarantined:,}", "in quarantine", "warn" if quarantined else ""),
        )
        for column, (value, caption, tone) in enumerate(entries):
            box = QVBoxLayout()
            box.setSpacing(0)
            box.addWidget(label(value, role="metric", tone=tone))
            box.addWidget(label(caption, role="caption"))
            holder = QWidget()
            holder.setLayout(box)
            self.stats_grid.addWidget(holder, 0, column)
        self.stats_grid.setColumnStretch(len(entries), 1)

    # -- actions ----------------------------------------------------------

    def _quick_scan(self) -> None:
        self.request_scan.emit(ScanKind.QUICK, None)

    def _explain_helper(self) -> None:
        from ...core.privileged import install_command
        from ..dialogs import confirm

        confirm(
            self, "Enabling privileged actions",
            "ClamGuard runs as you, never as root. The few things that need "
            "administrator rights — updating signatures, starting and stopping "
            "ClamAV's services, editing /etc/clamav — go through one short helper "
            "script.\n\nYou install it yourself, so you can read it first. It is "
            "about 400 lines and has no dependencies.\n\nRead it, then run:",
            detail=install_command(), detail_label="COMMAND TO RUN",
            confirm_text="Got it", cancel_text="Close", tone="info",
        )
        self.context.privileged.refresh()
        self.refresh()


def _empty(layout) -> None:
    """Remove and delete every widget in a layout, including nested layouts."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)
            widget.deleteLater()
            continue
        child = item.layout()
        if child is not None:
            _empty(child)
            child.deleteLater()
