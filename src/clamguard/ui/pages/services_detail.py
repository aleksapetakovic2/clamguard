"""The right-hand panel: everything known about one unit.

Ordered by the question a person actually arrived with. "What is this?" first,
then "is something wrong with it?", then "why is it here?", and only then the
raw facts. Putting the property table first would be honest and useless — it is
what `systemctl show` already does.

Nothing here can change anything. The privileged helper controls only the
ClamAV units and refuses every other name, so for anything else the panel offers the
command and a Copy button, exactly as the Boot Analyzer does for its remedies.
"""

from __future__ import annotations

import getpass
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...core.units.model import (
    Provenance,
    Unit,
    human_bytes,
    human_duration,
    man_command,
)
from ..theme import SPACE_LG, SPACE_MD, SPACE_SM
from ..widgets import (
    Badge,
    Card,
    CommandBlock,
    EmptyState,
    IconButton,
    KeyValueRow,
    Separator,
    break_anywhere_label,
    flow_row,
    label,
)

#: Narrower than KeyValueRow's default. The pane is ~300px at the window's
#: minimum size, and the default 150px key column alone left too little for
#: a path to wrap into.
KEY_WIDTH = 112


def _row(key: str, value: str = "", tone: str = "", mono: bool = False) -> KeyValueRow:
    """A key/value row sized for this pane.

    Prose and unit-name lists break anywhere when they must; paths stay
    selectable, because they already wrap at every slash and they are the
    values a person most often wants to copy.
    """
    return KeyValueRow(key, value, tone=tone, mono=mono, key_width=KEY_WIDTH,
                       break_anywhere=not mono)


#: What each systemctl verb does, in a person's words. `_relevant_commands`
#: picks the ones that make sense for a unit's current state.
COMMANDS = {
    "status": "systemd's own summary, and the last few journal lines",
    "restart": "stop it and start it again",
    "stop": "stop it now, until the next boot",
    "start": "start it now",
    "enable": "start it automatically at boot, from now on",
    "disable": "stop starting it at boot",
    "cat": "print the unit file and every drop-in that modifies it",
}


class UnitDetail(QScrollArea):
    """Everything about one unit, rebuilt on each selection."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        # As-needed rather than off. Everything below is built to wrap, but if
        # something ever cannot, a scrollbar is honest where "off" silently cut
        # the right edge of every card — which is what it did below ~1100px.
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        self._holder = QWidget()
        self.column = QVBoxLayout(self._holder)
        self.column.setContentsMargins(SPACE_MD, 0, SPACE_MD, SPACE_LG)
        self.column.setSpacing(SPACE_MD)
        self.setWidget(self._holder)

        self.show_nothing()

    # -- building ----------------------------------------------------------

    def show_nothing(self) -> None:
        self._clear()
        self.column.addWidget(EmptyState(
            "layers", "Pick a unit",
            "Everything this machine knows about it — what it is, which package "
            "put it there, what starts it, what depends on it, and what it cost "
            "at boot."))
        self.column.addStretch(1)

    def show_unit(self, unit: Unit) -> None:
        self._clear()
        self.column.addWidget(self._identity(unit))

        if unit.purpose.flags:
            self.column.addWidget(self._flags(unit))

        self.column.addWidget(self._what_it_is(unit))

        if unit.purpose.reasons or unit.purpose.dependents:
            self.column.addWidget(self._why(unit))

        self.column.addWidget(self._facts(unit))

        if unit.exec_start or unit.exec_start_pre or unit.exec_stop:
            self.column.addWidget(self._what_it_runs(unit))

        if unit.fragment_path or unit.drop_in_paths:
            self.column.addWidget(self._files(unit))

        if unit.purpose.reading:
            self.column.addWidget(self._reading(unit))

        self.column.addWidget(self._commands(unit))
        self.column.addStretch(1)

    def _clear(self) -> None:
        while self.column.count():
            item = self.column.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    # -- sections ----------------------------------------------------------

    def _identity(self, unit: Unit) -> QWidget:
        card = Card()
        # A title that can break anywhere, beside a button that copies the
        # exact name. A device unit's escaped name has fifty characters with no
        # break opportunity; as an ordinary label it forced the pane 600px wide.
        title_row = QHBoxLayout()
        title_row.setSpacing(SPACE_SM)
        title_row.addWidget(break_anywhere_label(unit.id, role="title"), 1)
        copy = IconButton("copy", f"Copy “{unit.id}”", tone="muted", size=16)
        copy.clicked.connect(lambda _=False, name=unit.id: _copy_text(name))
        title_row.addWidget(copy, 0, Qt.AlignmentFlag.AlignTop)
        title_holder = QWidget()
        title_holder.setLayout(title_row)
        card.body.addWidget(title_holder)

        badges = [Badge(unit.state_summary(), unit.tone()),
                  Badge(unit.kind.title, "info"),
                  Badge(unit.provenance.title, unit.provenance.tone)]
        if unit.enablement.value:
            badges.append(Badge(unit.enablement.value, "neutral"))
        # A flow, not a row: four badges side by side were 350px of minimum
        # width on their own, wider than the pane at the window's minimum size.
        card.body.addWidget(flow_row(*badges, spacing=SPACE_SM))

        if unit.purpose.headline:
            card.body.addWidget(break_anywhere_label(unit.purpose.headline, role="body"))
            if unit.purpose.headline_source:
                card.body.addWidget(label(f"— from {unit.purpose.headline_source}",
                                          role="caption", tone="muted"))
        return card

    def _flags(self, unit: Unit) -> QWidget:
        card = Card("Worth knowing", icon="alert-triangle", tone="warn")
        for text, tone in unit.purpose.flags:
            row = QHBoxLayout()
            row.setSpacing(SPACE_SM)
            dot = Badge("", tone if tone != "neutral" else "info")
            dot.setFixedWidth(6)
            row.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
            row.addWidget(label(text, role="body", tone=tone, wrap=True,
                                selectable=True), 1)
            holder = QWidget()
            holder.setLayout(row)
            card.body.addWidget(holder)
        return card

    def _what_it_is(self, unit: Unit) -> QWidget:
        card = Card("What it is", icon="info")

        # Every source, labelled, rather than one blended sentence. They
        # genuinely say different things: the unit file names this unit, the
        # man page describes the program, the package describes the project.
        if unit.description:
            card.body.addWidget(_row("Unit file says", unit.description))
        if unit.man_summary:
            card.body.addWidget(_row("Man page says", unit.man_summary))
        if unit.package:
            version = f" {unit.package_version}" if unit.package_version else ""
            card.body.addWidget(_row("Package", f"{unit.package}{version}"))
            if unit.package_summary:
                card.body.addWidget(_row("Package does", unit.package_summary))
        elif unit.fragment_path:
            # Why there is no package matters more than that there is none: a
            # generated mount and a hand-written service are different findings,
            # and "we could not ask" is not the same as "nobody owns it".
            text, tone = _NO_PACKAGE.get(unit.provenance, _NO_PACKAGE[None])
            card.body.addWidget(_row("Package", text, tone=tone))

        if unit.purpose.notes:
            card.body.addWidget(Separator())
            for note in unit.purpose.notes:
                # Notes quote unit names ("Its state follows sys-devices-…"),
                # so they need the same break-anywhere treatment as the title.
                card.body.addWidget(break_anywhere_label("• " + note, role="body"))
        return card

    def _why(self, unit: Unit) -> QWidget:
        card = Card("Why it is here", icon="layers")
        # Break-anywhere for the same reason as the notes: these sentences quote
        # unit names, and a device's escaped name has no break opportunity.
        for line in unit.purpose.reasons:
            card.body.addWidget(break_anywhere_label("• " + line, role="body"))
        if unit.purpose.dependents:
            card.body.addWidget(Separator())
            card.body.addWidget(label("If it stopped", role="sectionLabel"))
            for line in unit.purpose.dependents:
                card.body.addWidget(break_anywhere_label("• " + line, role="body"))
        return card

    def _facts(self, unit: Unit) -> QWidget:
        card = Card("The details", icon="table")

        def add(key: str, value: str, tone: str = "", mono: bool = False) -> None:
            if value:
                card.body.addWidget(_row(key, value, tone=tone, mono=mono))

        add("State", f"{unit.active_state} ({unit.sub_state})" if unit.sub_state
            else unit.active_state, tone=unit.tone())
        add("Since", _since(unit.active_since))
        add("Starts at boot", unit.enablement.value)
        if unit.unit_file_preset and unit.deviates_from_preset:
            add("Distribution ships it", unit.unit_file_preset, tone="warn")
        add("Type", unit.service_type)
        add("Restart policy", unit.restart)
        add("Runs as", _runs_as(unit))
        add("Main PID", str(unit.main_pid) if unit.main_pid else "")
        add("Memory", human_bytes(unit.memory_bytes))
        add("CPU used", human_duration(unit.cpu_nsec / 1e9) if unit.cpu_nsec else "")
        add("Tasks", str(unit.tasks) if unit.tasks else "")
        add("Restarts", str(unit.restarts) if unit.restarts else "")
        add("Time at boot", human_duration(unit.boot_seconds) if unit.boot_seconds else "")
        add("Slice", unit.slice_name)

        if unit.exposure is not None:
            add("Sandboxing", f"{unit.exposure.score:.1f}/10 {unit.exposure.rating.lower()}",
                tone=unit.exposure.tone)
        if unit.ports:
            add("Listening on", ", ".join(port.display for port in unit.ports),
                tone="warn" if any(p.world_reachable for p in unit.ports) else "")
        if unit.condition_result:
            add("Conditions met", unit.condition_result,
                tone="warn" if unit.condition_result == "no" else "")
        if unit.load_error:
            add("Load error", unit.load_error, tone="danger")

        for name, value in (("Requires", unit.requires), ("Wants", unit.wants),
                            ("After", unit.after), ("Before", unit.before),
                            ("Conflicts", unit.conflicts)):
            if value:
                add(name, ", ".join(value))
        return card

    def _what_it_runs(self, unit: Unit) -> QWidget:
        card = Card("What it runs", icon="terminal")
        for title, commands in (("Before starting", unit.exec_start_pre),
                                ("Start", unit.exec_start),
                                ("Stop", unit.exec_stop)):
            for command in commands:
                card.body.addWidget(_row(title, command.display, mono=True))
        return card

    def _files(self, unit: Unit) -> QWidget:
        card = Card("Files", icon="file")
        if unit.fragment_path:
            card.body.addWidget(_row("Unit file", unit.fragment_path, mono=True))
        if unit.source_path:
            card.body.addWidget(_row("Generated from", unit.source_path, mono=True))
        for path in unit.drop_in_paths:
            local = path in unit.local_drop_ins
            card.body.addWidget(_row(
                "Override" if local else "Drop-in", path, mono=True,
                tone="warn" if local else ""))
        return card

    def _reading(self, unit: Unit) -> QWidget:
        card = Card("Read more", icon="help")
        for text, target in unit.purpose.reading:
            if target.startswith("man:"):
                card.body.addWidget(CommandBlock(man_command(target)))
            else:
                # The address itself, selectable, rather than its label: the
                # package homepage rendered as "dbus-broker homepage", which
                # can be neither read nor copied as a link.
                key = "Homepage" if text.endswith(" homepage") else "Link"
                card.body.addWidget(_row(key, target.removeprefix("file:"), mono=True))
        return card

    def _commands(self, unit: Unit) -> QWidget:
        card = Card("Commands", icon="terminal",
                    subtitle="ClamGuard does not run these for you")
        card.body.addWidget(label(
            "The privileged helper controls the ClamAV units and refuses "
            "every other name, on purpose. Copy what you need and run it "
            "yourself.", role="caption", tone="muted", wrap=True))
        for verb in _relevant_commands(unit):
            caption = COMMANDS[verb]
            if unit.user_manager:
                # The session manager starts things at login, not at boot.
                caption = caption.replace("boot", "login")
            card.body.addWidget(label(caption, role="caption", tone="muted", wrap=True))
            card.body.addWidget(CommandBlock(unit.systemctl_command(verb)))
        card.body.addWidget(label("its recent log lines", role="caption", tone="muted",
                                  wrap=True))
        card.body.addWidget(CommandBlock(unit.journal_command()))
        return card


def _relevant_commands(unit: Unit) -> list[str]:
    """Only the verbs that make sense for this unit right now.

    Offering `start` for something already running, or `enable` for a static
    unit that cannot be enabled, is noise that makes the real option harder to
    find.
    """
    chosen = ["status"]
    if not unit.exists:
        return chosen

    if unit.running:
        chosen += ["restart", "stop"]
    elif unit.can_start and not unit.masked:
        chosen.append("start")

    enablement = unit.enablement.value
    if enablement in ("disabled", "indirect"):
        chosen.append("enable")
    elif enablement in ("enabled", "enabled-runtime"):
        chosen.append("disable")

    chosen.append("cat")
    return chosen


#: What to say in the Package row when there is no package, by provenance.
_NO_PACKAGE = {
    Provenance.LOCAL: ("none — this unit file was written by hand", "warn"),
    Provenance.UNPACKAGED: ("none — no installed package claims this file", "warn"),
    Provenance.GENERATED: ("none — generated, not installed", ""),
    Provenance.TRANSIENT: ("none — created at runtime", ""),
    Provenance.UNKNOWN: ("unknown — no package manager ClamGuard can ask", ""),
    None: ("unknown", ""),
}


def _copy_text(text: str) -> None:
    clipboard = QApplication.clipboard()
    if clipboard is not None:
        clipboard.setText(text)


def _runs_as(unit: Unit) -> str:
    """Whose account the unit's process runs under, if it has a process.

    An empty ``User=`` means root on the system manager and *you* on your
    session's — the earlier version said "root" for both.
    """
    if unit.user:
        return unit.user
    if unit.kind.value != "service" or not unit.exec_start:
        return ""
    if unit.user_manager:
        return f"{getpass.getuser()} (your session)"
    return "root"


def _since(moment: datetime | None) -> str:
    if moment is None:
        return ""
    delta = datetime.now() - moment
    seconds = delta.total_seconds()
    if seconds < 0:
        return moment.strftime("%Y-%m-%d %H:%M")
    return f"{moment.strftime('%Y-%m-%d %H:%M')} ({human_duration(seconds)} ago)"
