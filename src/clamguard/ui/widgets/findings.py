"""The expandable row that shows one Boot Analyzer finding.

Collapsed, a finding is one line: how bad it is, what it is, and what was
observed. Expanded, it is the whole argument — what it means, why it matters,
what would change it, and the raw evidence it was derived from.

That last part is the point. A security tool that says "Secure Boot is off"
and nothing else is asking to be believed; one that shows you the five bytes it
read out of the EFI variable and the command that would show you the same thing
is asking to be checked. Everything here is built around making the second one
easy.

Nothing in this file applies a fix. A fix is shown with a Copy button, and the
user runs it themselves.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core.boot.model import Finding, Fix, Severity
from ..theme import SPACE_MD, SPACE_SM, SPACE_XS
from .common import Badge, IconButton, IconLabel, Separator, label


class CommandBlock(QWidget):
    """A shell command with a Copy button. Never a Run button.

    The Boot Analyzer suggests changes to bootloaders, kernel command lines and
    system permissions. Those are exactly the changes that should pass through
    a human reading them, so the only affordance here is copying.
    """

    copied = Signal(str)

    def __init__(self, command: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.command = command

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 2, 0, 2)
        row.setSpacing(SPACE_SM)

        view = QPlainTextEdit()
        view.setProperty("role", "log")
        view.setReadOnly(True)
        view.setPlainText(command)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        lines = command.count("\n") + 1
        self._text_height = min(150, 17 * lines + 22)
        view.setFixedHeight(self._text_height)
        view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # A command wider than the box gets a horizontal scrollbar, and in a
        # box sized for exactly one line that scrollbar covered the line: a
        # long `journalctl --user-unit …` in a narrow pane rendered as an empty
        # box. Grow by the scrollbar's height whenever it is needed.
        self._view = view
        view.horizontalScrollBar().rangeChanged.connect(self._fit_height)
        row.addWidget(view, 1)

        copy = IconButton("copy", "Copy this command", tone="muted", size=16)
        copy.clicked.connect(self._copy)
        row.addWidget(copy, 0, Qt.AlignmentFlag.AlignTop)

    def _fit_height(self, _minimum: int = 0, maximum: int = 0) -> None:
        bar = self._view.horizontalScrollBar()
        extra = bar.sizeHint().height() if maximum > 0 else 0
        if self._view.height() != self._text_height + extra:
            self._view.setFixedHeight(self._text_height + extra)

    def _copy(self) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(self.command)
        self.copied.emit(self.command)


class FixBlock(QWidget):
    """One suggested fix: what it does, the command, and what it costs."""

    copied = Signal(str)

    def __init__(self, fix: Fix, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, SPACE_XS, 0, SPACE_SM)
        column.setSpacing(2)

        head = QHBoxLayout()
        head.setSpacing(SPACE_SM)
        head.addWidget(IconLabel("wrench", tone="accent", size=14), 0,
                       Qt.AlignmentFlag.AlignTop)
        head.addWidget(label(fix.title, role="body"), 0)
        if fix.recommended:
            head.addWidget(Badge("Suggested", "accent"), 0)
        if fix.reboot_required:
            head.addWidget(Badge("Needs a reboot", "info"), 0)
        head.addStretch(1)
        column.addLayout(head)

        if fix.explanation:
            explanation = label(fix.explanation, role="muted", wrap=True)
            explanation.setContentsMargins(22, 0, 0, 0)
            column.addWidget(explanation)

        if fix.command:
            block = CommandBlock(fix.command)
            block.setContentsMargins(22, 0, 0, 0)
            block.copied.connect(self.copied)
            column.addWidget(block)

        if fix.manual:
            manual = label(f"By hand: {fix.manual}", role="muted", wrap=True)
            manual.setContentsMargins(22, 0, 0, 0)
            column.addWidget(manual)

        if fix.risk:
            risk = QWidget()
            risk_row = QHBoxLayout(risk)
            risk_row.setContentsMargins(22, 2, 0, 0)
            risk_row.setSpacing(SPACE_SM)
            risk_row.addWidget(IconLabel("alert-triangle", tone="warn", size=14), 0,
                               Qt.AlignmentFlag.AlignTop)
            risk_row.addWidget(label(fix.risk, role="caption", tone="warn", wrap=True), 1)
            column.addWidget(risk)


class EvidenceBlock(QWidget):
    """One piece of raw evidence, with the source it came from."""

    def __init__(self, evidence, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, 2, 0, SPACE_XS)
        column.setSpacing(2)

        head = QHBoxLayout()
        head.setSpacing(SPACE_SM)
        head.addWidget(IconLabel("terminal" if evidence.is_command else "file",
                                 tone="faint", size=13), 0)
        head.addWidget(label(evidence.source, role="caption"), 1)
        column.addLayout(head)

        view = QPlainTextEdit()
        view.setProperty("role", "log")
        view.setReadOnly(True)
        view.setPlainText(evidence.preview())
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        lines = evidence.preview().count("\n") + 1
        view.setFixedHeight(min(190, 16 * lines + 20))
        column.addWidget(view)


class FindingRow(QFrame):
    """One finding, collapsed to a line until you ask for more."""

    #: (finding id) — the user asked to stop counting this one.
    mute_requested = Signal(str)
    #: (finding id) — put it back.
    unmute_requested = Signal(str)
    #: (finding id, Severity or None) — pin or unpin its severity.
    severity_changed = Signal(str, object)
    #: Something was copied; the page raises a toast.
    copied = Signal(str)
    #: The row was expanded or collapsed, so the list can re-lay out.
    toggled = Signal(bool)

    def __init__(self, finding: Finding, *, savvy: bool = False,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.finding = finding
        self._savvy = savvy
        self._expanded = False
        self._detail: QWidget | None = None
        self.setProperty("card", "flat")

        self._column = QVBoxLayout(self)
        self._column.setContentsMargins(SPACE_MD, SPACE_SM, SPACE_MD, SPACE_SM)
        self._column.setSpacing(SPACE_SM)
        self._column.addWidget(self._build_header())

    # -- header -----------------------------------------------------------

    def _build_header(self) -> QWidget:
        finding = self.finding
        header = QWidget()
        header.setCursor(Qt.CursorShape.PointingHandCursor)
        row = QHBoxLayout(header)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(SPACE_SM)

        tone = "faint" if finding.muted else finding.severity.tone
        row.addWidget(IconLabel(finding.severity.icon, tone=tone, size=17), 0,
                      Qt.AlignmentFlag.AlignVCenter)

        title = label(finding.title, role="muted" if finding.muted else "body",
                      wrap=True)
        row.addWidget(title, 1)

        if finding.value and finding.severity is not Severity.PASS:
            row.addWidget(Badge(_shorten(finding.value), "neutral"), 0)

        self._severity_badge = Badge(finding.severity.label,
                                     "neutral" if finding.muted else finding.severity.tone)
        row.addWidget(self._severity_badge, 0)

        if finding.muted:
            row.addWidget(Badge("Muted", "neutral"), 0)
        if finding.original_severity is not None and not finding.muted:
            badge = Badge("Adjusted", "info")
            badge.setToolTip(
                f"You changed this from {finding.original_severity.label}.")
            row.addWidget(badge, 0)

        self._chevron = IconButton("chevron-down", "Show the detail",
                                   tone="faint", size=15)
        self._chevron.clicked.connect(self.toggle)
        row.addWidget(self._chevron, 0)

        # The whole header is the click target, not just the chevron. A
        # QWidget subclass for one event handler would be more code saying
        # less, so the handler is attached directly.
        header.mouseReleaseEvent = lambda _event: self.toggle()  # noqa: E731
        return header

    # -- expansion --------------------------------------------------------

    def toggle(self) -> None:
        self.set_expanded(not self._expanded)

    def set_expanded(self, expanded: bool) -> None:
        if expanded == self._expanded:
            return
        self._expanded = expanded
        self._chevron.set_icon_name("chevron-up" if expanded else "chevron-down")
        if expanded:
            if self._detail is None:
                self._detail = self._build_detail()
                self._column.addWidget(self._detail)
            self._detail.setVisible(True)
        elif self._detail is not None:
            self._detail.setVisible(False)
        self.toggled.emit(expanded)

    @property
    def expanded(self) -> bool:
        return self._expanded

    def set_savvy(self, savvy: bool) -> None:
        """Savvy mode expands the evidence blocks by default."""
        if savvy == self._savvy:
            return
        self._savvy = savvy
        if self._detail is not None and hasattr(self, "_evidence_holder"):
            self._evidence_holder.setVisible(savvy)
            self._evidence_toggle.setText(
                "Hide evidence" if savvy else
                f"Show evidence ({len(self.finding.evidence)})")

    # -- detail -----------------------------------------------------------

    def _build_detail(self) -> QWidget:
        finding = self.finding
        holder = QWidget()
        column = QVBoxLayout(holder)
        column.setContentsMargins(26, 0, 0, SPACE_XS)
        column.setSpacing(SPACE_SM)

        if finding.summary:
            column.addWidget(label(finding.summary, role="body", wrap=True))

        if finding.impact:
            impact = QFrame()
            impact.setProperty("card", "flat")
            impact_row = QHBoxLayout(impact)
            impact_row.setContentsMargins(SPACE_MD, SPACE_SM, SPACE_MD, SPACE_SM)
            impact_row.setSpacing(SPACE_SM)
            impact_row.addWidget(IconLabel("info", tone="info", size=15), 0,
                                 Qt.AlignmentFlag.AlignTop)
            texts = QVBoxLayout()
            texts.setSpacing(1)
            texts.addWidget(label("Why it matters", role="sectionLabel"))
            texts.addWidget(label(finding.impact, role="muted", wrap=True))
            impact_row.addLayout(texts, 1)
            column.addWidget(impact)

        if finding.expected and finding.value:
            column.addWidget(label(
                f"Observed “{finding.value}”, expected “{finding.expected}”.",
                role="caption"))

        if finding.mute_reason:
            column.addWidget(label(f"Muted: {finding.mute_reason}", role="caption"))

        if finding.fixes:
            column.addWidget(label("What would change it", role="sectionLabel"))
            for fix in finding.fixes:
                block = FixBlock(fix)
                block.copied.connect(lambda _c: self.copied.emit("Command copied."))
                column.addWidget(block)

        if finding.evidence:
            column.addWidget(self._build_evidence())

        if finding.references:
            references = QVBoxLayout()
            references.setSpacing(1)
            references.addWidget(label("Further reading", role="sectionLabel"))
            for reference in finding.references:
                references.addWidget(label(f"{reference.title} — {reference.locator}",
                                           role="caption", wrap=True))
            column.addLayout(references)

        column.addWidget(Separator())
        column.addWidget(self._build_actions())
        return holder

    def _build_evidence(self) -> QWidget:
        holder = QWidget()
        column = QVBoxLayout(holder)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(SPACE_XS)

        self._evidence_toggle = QPushButton(
            "Hide evidence" if self._savvy
            else f"Show evidence ({len(self.finding.evidence)})")
        self._evidence_toggle.setProperty("variant", "link")
        self._evidence_toggle.clicked.connect(self._toggle_evidence)
        column.addWidget(self._evidence_toggle, 0, Qt.AlignmentFlag.AlignLeft)

        self._evidence_holder = QWidget()
        inner = QVBoxLayout(self._evidence_holder)
        inner.setContentsMargins(0, 0, 0, 0)
        inner.setSpacing(SPACE_XS)
        for evidence in self.finding.evidence:
            inner.addWidget(EvidenceBlock(evidence))
        self._evidence_holder.setVisible(self._savvy)
        column.addWidget(self._evidence_holder)
        return holder

    def _toggle_evidence(self) -> None:
        shown = not self._evidence_holder.isVisible()
        self._evidence_holder.setVisible(shown)
        self._evidence_toggle.setText(
            "Hide evidence" if shown
            else f"Show evidence ({len(self.finding.evidence)})")

    def _build_actions(self) -> QWidget:
        finding = self.finding
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(SPACE_SM)

        identifier = label(finding.id, role="mono")
        identifier.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(identifier, 1)

        if finding.severity is not Severity.PASS:
            row.addWidget(label("Treat as", role="caption"), 0)
            picker = QComboBox()
            picker.addItem("Whatever ClamGuard says", None)
            for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                          Severity.LOW, Severity.INFO):
                picker.addItem(level.label, level)
            if finding.original_severity is not None:
                index = picker.findText(finding.severity.label)
                picker.setCurrentIndex(max(0, index))
            picker.setFixedWidth(180)
            picker.currentIndexChanged.connect(
                lambda index, box=picker: self.severity_changed.emit(
                    finding.id, box.itemData(index)))
            row.addWidget(picker, 0)

            mute = QPushButton("Unmute" if finding.muted else "Mute")
            mute.setProperty("variant", "ghost")
            mute.setToolTip(
                "Stop this counting towards the score. It stays in the list."
                if not finding.muted else "Count this again.")
            mute.clicked.connect(
                lambda: (self.unmute_requested if finding.muted
                         else self.mute_requested).emit(finding.id))
            row.addWidget(mute, 0)
        return holder


def _shorten(text: str, limit: int = 34) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
