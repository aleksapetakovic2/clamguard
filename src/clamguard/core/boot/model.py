"""The vocabulary the Boot Analyzer speaks: findings, evidence, fixes, scores.

Read this file first. Everything else in the package produces or consumes the
types defined here, and they are deliberately dull: frozen dataclasses with no
behaviour beyond formatting and comparison.

The shape of one result:

    Finding                 "Secure Boot is disabled"
      ├─ severity           HIGH
      ├─ category           FIRMWARE
      ├─ summary            what is true, in one or two sentences
      ├─ impact             what an attacker gains from it
      ├─ evidence[]         where that came from — a file, a command, its output
      ├─ fixes[]            what would change it, as a command to copy
      └─ references[]       further reading

Two design rules worth keeping:

* **A finding always carries its evidence.** A security tool that says "trust
  me" is not much use to the person who has to act on it, and ClamGuard's whole
  posture is that the user can check its work.
* **A fix is never applied.** The Boot Analyzer touches system-critical
  settings, so it shows the command and leaves the decision — and the typing —
  to the person at the keyboard.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum, IntEnum


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(IntEnum):
    """How much a finding matters. Ordered, so findings sort by it.

    The numbers are spaced so a future level can be slotted between two
    existing ones without renumbering anything that is stored on disk.
    """

    PASS = 0
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return {
            Severity.PASS: "Pass",
            Severity.INFO: "Info",
            Severity.LOW: "Low",
            Severity.MEDIUM: "Medium",
            Severity.HIGH: "High",
            Severity.CRITICAL: "Critical",
        }[self]

    @property
    def tone(self) -> str:
        """The palette tone the UI colours this with. See ui/theme.py."""
        return {
            Severity.PASS: "ok",
            Severity.INFO: "info",
            Severity.LOW: "info",
            Severity.MEDIUM: "warn",
            Severity.HIGH: "danger",
            Severity.CRITICAL: "danger",
        }[self]

    @property
    def icon(self) -> str:
        return {
            Severity.PASS: "check-circle",
            Severity.INFO: "info",
            Severity.LOW: "info",
            Severity.MEDIUM: "alert-triangle",
            Severity.HIGH: "alert-circle",
            Severity.CRITICAL: "shield-off",
        }[self]

    @property
    def is_problem(self) -> bool:
        """True for anything the user might want to act on."""
        return self >= Severity.LOW

    @classmethod
    def parse(cls, text: str, fallback: "Severity" = None) -> "Severity":
        """Read a severity from a settings file. Never raises."""
        try:
            return cls[str(text).strip().upper()]
        except KeyError:
            return fallback if fallback is not None else cls.INFO


#: How many points each severity costs the overall score. The UI shows this
#: arithmetic rather than presenting the score as an oracle.
SCORE_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
    Severity.PASS: 0,
}


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------


class Category(str, Enum):
    """The seven areas the analyzer looks at. Also the UI's grouping."""

    FIRMWARE = "firmware"
    KERNEL = "kernel"
    HARDENING = "hardening"
    BOOTCHAIN = "bootchain"
    SERVICES = "services"
    PERSISTENCE = "persistence"
    PERFORMANCE = "performance"
    INTEGRITY = "integrity"

    @property
    def title(self) -> str:
        return {
            Category.FIRMWARE: "Firmware & Secure Boot",
            Category.KERNEL: "Kernel & mitigations",
            Category.HARDENING: "Kernel hardening",
            Category.BOOTCHAIN: "Boot chain & disks",
            Category.SERVICES: "Services & units",
            Category.PERSISTENCE: "Startup surface",
            Category.PERFORMANCE: "Boot performance",
            Category.INTEGRITY: "Integrity & drift",
        }[self]

    @property
    def blurb(self) -> str:
        """One line explaining what this category is about."""
        return {
            Category.FIRMWARE:
                "What the firmware verifies before the kernel exists.",
            Category.KERNEL:
                "What the running kernel allows, and what it is protected against.",
            Category.HARDENING:
                "Switches that make a local exploit harder to land.",
            Category.BOOTCHAIN:
                "The files and disks the machine boots from.",
            Category.SERVICES:
                "Units that failed, or that run with more power than they need.",
            Category.PERSISTENCE:
                "Everything wired to run automatically — where malware hides.",
            Category.PERFORMANCE:
                "Where the time between power-on and login actually goes.",
            Category.INTEGRITY:
                "What changed since last time, and what the journal complained about.",
        }[self]

    @property
    def icon(self) -> str:
        return {
            Category.FIRMWARE: "key",
            Category.KERNEL: "cpu",
            Category.HARDENING: "shield",
            Category.BOOTCHAIN: "hard-drive",
            Category.SERVICES: "power",
            Category.PERSISTENCE: "layers",
            Category.PERFORMANCE: "gauge",
            Category.INTEGRITY: "compare",
        }[self]

    @classmethod
    def parse(cls, text: str) -> "Category | None":
        try:
            return cls(str(text).strip().lower())
        except ValueError:
            return None


#: Display order. Security first, performance last — that is the order a
#: person cares about them in.
CATEGORY_ORDER: tuple[Category, ...] = (
    Category.FIRMWARE,
    Category.BOOTCHAIN,
    Category.KERNEL,
    Category.HARDENING,
    Category.PERSISTENCE,
    Category.SERVICES,
    Category.INTEGRITY,
    Category.PERFORMANCE,
)


# ---------------------------------------------------------------------------
# The parts of a finding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    """Where a finding came from, verbatim.

    ``source`` is a path or a command line, never prose — the point is that the
    user can go and run it themselves. ``content`` is what it said.
    """

    source: str
    content: str
    #: "file" | "command" | "sysfs" | "computed"
    kind: str = "file"

    #: Longer evidence is truncated for display; the full text stays available.
    PREVIEW_LINES = 12

    def preview(self) -> str:
        lines = self.content.splitlines()
        if len(lines) <= self.PREVIEW_LINES:
            return self.content.strip()
        hidden = len(lines) - self.PREVIEW_LINES
        shown = "\n".join(lines[: self.PREVIEW_LINES])
        return f"{shown}\n… {hidden} more line{'' if hidden == 1 else 's'}"

    @property
    def is_command(self) -> bool:
        return self.kind == "command"


@dataclass(frozen=True)
class Fix:
    """Something the user could do. ClamGuard will not do it for them.

    ``command`` is a shell command, exactly as it should be typed. ``manual``
    is for the things no command can reach — a firmware setting, a BIOS menu.
    A fix may have both: "reboot into setup and enable it, or if your
    distribution supports it, run …".
    """

    title: str
    explanation: str = ""
    command: str = ""
    manual: str = ""
    #: What could go wrong. Shown in the same breath as the command, because a
    #: fix that locks someone out of their machine is not a fix.
    risk: str = ""
    reboot_required: bool = False
    #: True for the fix ClamGuard would pick, when there are several.
    recommended: bool = False

    @property
    def has_command(self) -> bool:
        return bool(self.command.strip())


@dataclass(frozen=True)
class Reference:
    """Further reading. A name and where to find it — never fetched."""

    title: str
    #: A URL, a man page ("man 5 crypttab"), or a kernel doc path.
    locator: str


@dataclass(frozen=True)
class Finding:
    """One observation about how this machine boots.

    ``id`` must be stable across runs and releases: the user's mute list and
    the severity overrides are keyed on it. Use dotted names that read as a
    path — ``firmware.secure-boot.disabled``.
    """

    id: str
    check_id: str
    category: Category
    severity: Severity
    title: str
    summary: str = ""
    #: Why it matters — what an attacker gains, or what breaks.
    impact: str = ""
    #: The short observed value, for the collapsed row: "disabled", "2m 4s".
    value: str = ""
    #: What it would say if all were well.
    expected: str = ""
    evidence: tuple[Evidence, ...] = ()
    fixes: tuple[Fix, ...] = ()
    references: tuple[Reference, ...] = ()
    tags: frozenset[str] = frozenset()
    #: Set when the user's profile silenced this finding. Muted findings are
    #: still produced and still displayed on request — they just stop counting.
    muted: bool = False
    mute_reason: str = ""
    #: Set when the profile changed the severity the check asked for.
    original_severity: Severity | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("a finding needs a stable id")

    # -- derived ----------------------------------------------------------

    @property
    def is_problem(self) -> bool:
        return self.severity.is_problem and not self.muted

    @property
    def counts_towards_score(self) -> bool:
        return not self.muted and self.severity in SCORE_WEIGHTS

    @property
    def has_fix(self) -> bool:
        return bool(self.fixes)

    @property
    def runnable_fixes(self) -> tuple[Fix, ...]:
        return tuple(fix for fix in self.fixes if fix.has_command)

    def recommended_fix(self) -> Fix | None:
        for fix in self.fixes:
            if fix.recommended:
                return fix
        return self.fixes[0] if self.fixes else None

    def matches(self, text: str) -> bool:
        """Free-text search over everything a user might type."""
        needle = text.strip().lower()
        if not needle:
            return True
        haystack = " ".join((
            self.id, self.title, self.summary, self.impact, self.value,
            self.category.value, self.severity.label, " ".join(sorted(self.tags)),
            " ".join(item.source for item in self.evidence),
        )).lower()
        return needle in haystack

    # -- profile application ---------------------------------------------

    def with_severity(self, severity: Severity) -> "Finding":
        """A copy at a different severity, remembering what it was."""
        if severity == self.severity:
            return self
        return replace(self, severity=severity,
                       original_severity=self.original_severity or self.severity)

    def muted_as(self, reason: str) -> "Finding":
        return replace(self, muted=True, mute_reason=reason)

    # -- serialisation ----------------------------------------------------

    def to_dict(self) -> dict:
        """A plain dictionary, for the JSON export and for tests."""
        return {
            "id": self.id,
            "check": self.check_id,
            "category": self.category.value,
            "severity": self.severity.label,
            "title": self.title,
            "summary": self.summary,
            "impact": self.impact,
            "value": self.value,
            "expected": self.expected,
            "muted": self.muted,
            "mute_reason": self.mute_reason,
            "tags": sorted(self.tags),
            "evidence": [
                {"source": item.source, "kind": item.kind, "content": item.content}
                for item in self.evidence
            ],
            "fixes": [
                {"title": fix.title, "explanation": fix.explanation,
                 "command": fix.command, "manual": fix.manual, "risk": fix.risk,
                 "reboot_required": fix.reboot_required}
                for fix in self.fixes
            ],
            "references": [
                {"title": ref.title, "locator": ref.locator} for ref in self.references
            ],
        }


# ---------------------------------------------------------------------------
# Boot timing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BootPhase:
    """One slice of `systemd-analyze time`."""

    name: str
    seconds: float

    @property
    def text(self) -> str:
        return format_duration(self.seconds)


@dataclass(frozen=True)
class BootTimings:
    """How long each stage of the boot took, and which units were slowest."""

    phases: tuple[BootPhase, ...] = ()
    total_seconds: float = 0.0
    #: unit name -> seconds, sorted slowest first.
    slowest_units: tuple[tuple[str, float], ...] = ()
    #: How many extra names udev gave a device unit, for the ones that were
    #: folded together. Kept out of the unit name itself so that checks can
    #: still match on the ".device" suffix — a label like
    #: "dev-sda.device (+18 more names)" would not.
    unit_aliases: dict[str, int] = field(default_factory=dict)
    #: `systemd-analyze critical-chain`, verbatim, as lines.
    critical_chain: tuple[str, ...] = ()

    @property
    def measured(self) -> bool:
        return self.total_seconds > 0

    def phase(self, name: str) -> float:
        for item in self.phases:
            if item.name == name:
                return item.seconds
        return 0.0

    def unit_label(self, unit: str) -> str:
        """The unit name as a person should see it, aliases noted."""
        extra = self.unit_aliases.get(unit, 0)
        return f"{unit}  (+{extra} more names)" if extra else unit

    @property
    def total_text(self) -> str:
        return format_duration(self.total_seconds)


# ---------------------------------------------------------------------------
# A whole run
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SkippedCheck:
    """A check that could not run, and why. Never silently dropped."""

    check_id: str
    title: str
    reason: str


@dataclass(frozen=True)
class Report:
    """Everything one analysis run produced."""

    findings: tuple[Finding, ...] = ()
    skipped: tuple[SkippedCheck, ...] = ()
    #: Headline system facts for the summary strip: "Firmware" -> "UEFI".
    facts: dict[str, str] = field(default_factory=dict)
    timings: BootTimings | None = None
    started_at: datetime = field(default_factory=datetime.now)
    duration: float = 0.0
    #: Machine identity, so an exported report says which machine it is about.
    hostname: str = ""
    kernel: str = ""
    distribution: str = ""
    #: The profile preset that was in force.
    preset: str = ""
    #: Every file read and command run, for the "what did you touch" panel.
    probe_log: tuple[str, ...] = ()
    #: Structured extras the UI tabs render as tables: "startup" (the startup
    #: inventory), "exposure" (per-unit sandboxing scores), and
    #: "startup_unreadable". The findings are the contract — this is the same
    #: material in the shape a table wants, and it is deliberately left out of
    #: to_dict() because the exports already carry it as evidence.
    details: dict = field(default_factory=dict)

    # -- selection --------------------------------------------------------

    def problems(self) -> tuple[Finding, ...]:
        """Findings that need attention, worst first."""
        return tuple(sorted(
            (item for item in self.findings if item.is_problem),
            key=_finding_sort_key,
        ))

    def passes(self) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if item.severity is Severity.PASS)

    def muted(self) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if item.muted)

    def by_category(self, category: Category) -> tuple[Finding, ...]:
        return tuple(sorted(
            (item for item in self.findings if item.category is category),
            key=_finding_sort_key,
        ))

    def count(self, severity: Severity) -> int:
        return sum(1 for item in self.findings
                   if item.severity is severity and not item.muted)

    @property
    def counts(self) -> dict[Severity, int]:
        return {level: self.count(level) for level in Severity}

    @property
    def worst(self) -> Severity:
        live = [item.severity for item in self.findings if not item.muted]
        return max(live) if live else Severity.PASS

    # -- the score --------------------------------------------------------

    @property
    def score(self) -> int:
        """0-100. Starts at 100; every live finding costs its severity's weight.

        Deliberately simple and deliberately public: :meth:`score_working` hands
        the UI the arithmetic so the number can be checked rather than believed.
        """
        penalty = sum(SCORE_WEIGHTS[item.severity]
                      for item in self.findings if item.counts_towards_score)
        return max(0, 100 - penalty)

    def score_working(self) -> list[tuple[str, int]]:
        """The score's arithmetic: [("2 high", -24), ...]."""
        steps: list[tuple[str, int]] = []
        for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            number = self.count(level)
            if number:
                steps.append((f"{number} {level.label.lower()}",
                              -number * SCORE_WEIGHTS[level]))
        return steps

    def score_explanation(self) -> str:
        """``100 − 15 (3 medium) − 28 (14 low) = 57``.

        One string, used by the page, the Markdown export and the HTML export,
        so the three can never present different arithmetic for the same score.
        """
        steps = self.score_working()
        if not steps:
            return f"100 − nothing = {self.score}"
        parts = " ".join(f"− {abs(change)} ({label})" for label, change in steps)
        return f"100 {parts} = {self.score}"

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            return "Solid"
        if score >= 75:
            return "Good"
        if score >= 55:
            return "Fair"
        if score >= 35:
            return "Weak"
        return "Poor"

    @property
    def grade_tone(self) -> str:
        score = self.score
        if score >= 75:
            return "ok"
        if score >= 45:
            return "warn"
        return "danger"

    def headline(self) -> str:
        """One sentence for the top of the page."""
        problems = len(self.problems())
        if not self.findings:
            return "Nothing has been analysed yet."
        if not problems:
            return "Nothing to act on. Every check this profile runs came back clean."
        critical = self.count(Severity.CRITICAL)
        high = self.count(Severity.HIGH)
        if critical:
            return (f"{critical} critical problem{'' if critical == 1 else 's'} "
                    f"with how this machine boots, out of {problems} finding"
                    f"{'' if problems == 1 else 's'}.")
        if high:
            return (f"{high} serious problem{'' if high == 1 else 's'} "
                    f"out of {problems} finding{'' if problems == 1 else 's'}.")
        return (f"{problems} thing{'' if problems == 1 else 's'} worth a look. "
                "Nothing urgent.")

    def to_dict(self) -> dict:
        return {
            "generated": self.started_at.isoformat(timespec="seconds"),
            "duration_seconds": round(self.duration, 3),
            "hostname": self.hostname,
            "kernel": self.kernel,
            "distribution": self.distribution,
            "preset": self.preset,
            "score": self.score,
            "grade": self.grade,
            "counts": {level.label: self.count(level) for level in Severity
                       if self.count(level)},
            "facts": dict(self.facts),
            "boot_time": {
                "total_seconds": round(self.timings.total_seconds, 3),
                "phases": [{"name": phase.name, "seconds": round(phase.seconds, 3)}
                           for phase in self.timings.phases],
                "slowest_units": [{"unit": unit, "seconds": round(seconds, 3)}
                                  for unit, seconds in self.timings.slowest_units],
            } if self.timings and self.timings.measured else None,
            "findings": [item.to_dict() for item in self.findings],
            "skipped": [{"check": item.check_id, "reason": item.reason}
                        for item in self.skipped],
        }


def _finding_sort_key(finding: Finding) -> tuple:
    """Worst first, then by category order, then alphabetically by title."""
    try:
        category_rank = CATEGORY_ORDER.index(finding.category)
    except ValueError:
        category_rank = len(CATEGORY_ORDER)
    return (-int(finding.severity), category_rank, finding.title.lower())


def sort_findings(findings, key: str = "severity") -> list[Finding]:
    """Order findings for display. `key` is "severity", "category" or "check"."""
    items = list(findings)
    if key == "category":
        return sorted(items, key=lambda f: (
            CATEGORY_ORDER.index(f.category) if f.category in CATEGORY_ORDER else 99,
            -int(f.severity), f.title.lower()))
    if key == "check":
        return sorted(items, key=lambda f: (f.check_id, -int(f.severity)))
    return sorted(items, key=_finding_sort_key)


# ---------------------------------------------------------------------------
# Formatting helpers used all over the package
# ---------------------------------------------------------------------------


def format_duration(seconds: float) -> str:
    """``2.4s``, ``1m 32s``, ``2h 05m`` — never a bare float."""
    if seconds < 0:
        return "—"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {remainder:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def format_age(timestamp: float) -> str:
    """``3 days ago`` from a POSIX timestamp."""
    delta = max(0.0, time.time() - timestamp)
    if delta < 90:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)} minutes ago"
    if delta < 86400:
        hours = int(delta // 3600)
        return f"{hours} hour{'' if hours == 1 else 's'} ago"
    days = int(delta // 86400)
    if days < 60:
        return f"{days} day{'' if days == 1 else 's'} ago"
    months = days // 30
    return f"{months} month{'' if months == 1 else 's'} ago"
