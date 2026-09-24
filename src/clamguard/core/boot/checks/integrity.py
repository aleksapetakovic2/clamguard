"""What changed since last time, and what the journal complained about.

Two checks with one thing in common: they compare this boot against something
else. The first compares the files in the boot chain against a snapshot the
user recorded earlier; the second compares the volume of errors in the journal
against what the profile considers normal.

Neither runs a scan or reads a signature database. The baseline comparison is
deliberately cheap — it re-hashes the same files the snapshot covered, nothing
more — so that running the Boot Analyzer stays a few seconds' work.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterator

from ..baseline import Baseline, compare, record
from ..model import Category, Evidence, Finding, Fix, Severity, format_age
from ..probe import Probe
from ..profile import Policy
from ..registry import SkipCheck, check, finding, get, passed
from .common import listing, plural


@check(
    "integrity.baseline",
    title="Changes since the recorded baseline",
    category=Category.INTEGRITY,
    inspects="Re-hashes the files covered by the saved baseline and compares them.",
    worst=Severity.HIGH,
    tags=("integrity",),
    slow=True,
)
def baseline_drift(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Has anything in the boot chain changed since you last looked?"""
    item = get("integrity.baseline")
    saved = Baseline.load()
    if not saved.exists:
        yield finding(
            item, "none", Severity.INFO,
            "No baseline has been recorded yet",
            "A baseline is a list of hashes for everything in the boot chain. "
            "With one recorded, ClamGuard can tell you exactly which files "
            "changed since — which is the practical substitute for measured "
            "boot on a machine that does not have it.",
            impact="Without a baseline there is no way to answer 'did "
                   "something change my bootloader?' after the fact.",
            value="not recorded",
            evidence=(Evidence("boot-baseline.json", "not present",
                               kind="computed"),),
            fixes=(Fix(
                title="Record one now",
                explanation="Takes a second or two. Do it when you have "
                            "reason to believe the machine is in a good state "
                            "— straight after an install, say.",
                manual="Boot Analyzer → ⋯ → Record baseline.",
                recommended=True,
            ),),
            tags=frozenset({"integrity"}),
        )
        return

    current = record(saved.roots or None)
    drift = compare(saved, current)
    evidence = (
        Evidence("boot baseline",
                 f"recorded {saved.taken_at} on kernel {saved.kernel or 'unknown'}\n"
                 f"{len(saved.entries)} files, {saved.hashed_count} of them hashed\n"
                 f"roots: {', '.join(saved.roots)}", kind="computed"),
    )

    if drift.empty:
        yield passed(
            item, "unchanged", "Nothing in the boot chain has changed",
            f"{plural(len(saved.entries), 'file')} compared against the "
            f"baseline recorded {format_age(_timestamp(saved.taken_at))}.",
            value="unchanged", evidence=evidence,
        )
        return

    routine = drift.looks_like_a_kernel_update()
    detail = "\n".join(f"{change.kind:<12} {change.path}\n             {change.detail}"
                       for change in drift.changes[:30])
    evidence = evidence + (Evidence("baseline comparison", detail, kind="computed"),)

    severity = (policy.severity("baseline_drift_expected") if routine
                else policy.severity("baseline_drift"))
    if not drift.serious:
        severity = min(severity, Severity.LOW)

    yield finding(
        item, "changed", severity,
        f"{drift.summary()} in the boot chain since the baseline",
        (
            "The changed files look like a routine kernel update: a kernel "
            "image, an initramfs and the bootloader configuration, all written "
            "within a few minutes of each other. That is a heuristic, not "
            "proof — check the list below against what you remember installing."
            if routine else
            "These files decide what the machine runs at boot. Work through "
            "the list and account for each one."
        ),
        impact=(
            "A change you can explain is fine. A change you cannot is the "
            "single most serious thing this page can tell you, because it "
            "happens before anything that could detect it."
        ),
        value=drift.summary(),
        expected="unchanged",
        evidence=evidence,
        fixes=(
            Fix(
                title="Check your package manager's log for that time",
                explanation="A change that lines up with a package transaction "
                            "is an update; one that does not is worth chasing.",
                command="# Debian/Ubuntu: less /var/log/dpkg.log\n"
                        "# Fedora/RHEL:   sudo dnf history\n"
                        "# Arch:          less /var/log/pacman.log",
                recommended=True,
            ),
            Fix(
                title="Scan the changed files with ClamAV",
                explanation="Hands the changed paths straight to the scanner.",
                manual="Boot Analyzer → Integrity → Scan changed files.",
            ),
            Fix(
                title="Accept the changes as the new baseline",
                explanation="Only once you are satisfied every change is "
                            "accounted for.",
                manual="Boot Analyzer → ⋯ → Record baseline.",
            ),
        ),
        tags=frozenset({"integrity"}),
    )

    if drift.unhashed:
        yield finding(
            item, "unhashed", Severity.INFO,
            f"{plural(len(drift.unhashed), 'file')} could only be compared by size and date",
            "ClamGuard does not run as root, so it cannot read these: "
            + listing(sorted(set(drift.unhashed)), limit=5) + ". They are "
            "checked by size, mode and timestamp, which catches a replacement "
            "but not a same-size edit.",
            impact="An initramfs is usually in this group, and an initramfs is "
                   "exactly what someone would modify.",
            value=plural(len(drift.unhashed), "file"),
            evidence=(Evidence("unreadable files",
                               "\n".join(sorted(set(drift.unhashed))),
                               kind="computed"),),
            fixes=(Fix(
                title="Hash them yourself and keep the list",
                explanation="Run this as root now and again after any change "
                            "you did not expect.",
                command="sudo sha256sum /boot/initramfs-* /boot/initrd* 2>/dev/null",
            ),),
            tags=frozenset({"integrity"}),
        )


def _timestamp(iso: str) -> float:
    from datetime import datetime

    try:
        return datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return 0.0


# ---------------------------------------------------------------------------
# The journal
# ---------------------------------------------------------------------------

#: Messages that are noisy on every desktop and say nothing about health.
#: Filtered out of the *count*, but still visible in the evidence.
_BORING = (
    "rate limit exceeded",
    "failed to get quota",
    "gnome-shell",
    "pipewire",
)

_TIMESTAMP_PREFIX = re.compile(r"^\S+\s+\S+\s+")


@check(
    "integrity.journal",
    title="Errors in this boot's journal",
    category=Category.INTEGRITY,
    inspects="journalctl -b -p err, grouped by the message that repeats.",
    worst=Severity.MEDIUM,
    tags=("integrity",),
)
def journal_errors(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A pile of repeated errors is how a broken machine looks from the inside."""
    item = get("integrity.journal")
    result = probe.run("journalctl", "-b", "-p", "3", "--no-pager",
                       "-o", "short-iso", "-n", "1000")
    if not result.ok and not result.stdout:
        raise SkipCheck(f"the journal could not be read: {result.output[:120]}")

    lines = result.lines()
    interesting = [line for line in lines
                   if not any(word in line.lower() for word in _BORING)]
    grouped = Counter(_normalise(line) for line in interesting)
    top = grouped.most_common(8)
    budget = policy.threshold("journal_error_budget")

    evidence = (
        Evidence("journalctl -b -p err",
                 f"{len(lines)} error-priority messages this boot, "
                 f"{len(interesting)} after filtering known-noisy sources\n\n"
                 + "\n".join(f"{count:>5} ×  {message[:110]}"
                             for message, count in top),
                 kind="command"),
    )

    if len(interesting) <= budget:
        yield passed(
            item, "quiet", "The journal is reasonably quiet",
            f"{len(interesting)} error-priority messages this boot, within the "
            f"{int(budget)} this profile allows for.",
            value=str(len(interesting)), evidence=evidence,
        )
        return

    worst_message, worst_count = top[0] if top else ("", 0)
    yield finding(
        item, "noisy", policy.severity("journal_errors"),
        f"{len(interesting)} errors were logged during this boot",
        (f"The most frequent is “{worst_message[:120]}”, {worst_count} times. "
         if worst_count > 1 else "")
        + f"This profile treats more than {int(budget)} as worth looking at.",
        impact=(
            "Most of these will be a driver complaining about hardware it does "
            "not fully support, and are harmless. They matter because they bury "
            "the one message that is not — a failing disk, a service that "
            "cannot reach its socket, a permission error in something "
            "security-relevant."
        ),
        value=str(len(interesting)),
        expected=f"under {int(budget)}",
        evidence=evidence,
        fixes=(
            Fix(
                title="Read them grouped by what repeats",
                explanation="Turns a thousand lines into a handful of distinct "
                            "problems.",
                command="journalctl -b -p err --no-pager -o cat | sort | "
                        "uniq -c | sort -rn | head -20",
                recommended=True,
            ),
            Fix(
                title="Look at just the kernel's errors",
                explanation="Hardware problems show up here first.",
                command="journalctl -b -k -p err --no-pager",
            ),
        ),
        tags=frozenset({"integrity"}),
    )


def _normalise(line: str) -> str:
    """Strip the timestamp, host and PID so repeats of one message group."""
    text = _TIMESTAMP_PREFIX.sub("", line, count=1)
    text = re.sub(r"^\S+\s+", "", text, count=1)          # hostname
    text = re.sub(r"\[\d+\]", "[]", text)                  # pid
    text = re.sub(r"0x[0-9a-fA-F]+", "0x…", text)          # addresses
    text = re.sub(r"\b\d{3,}\b", "N", text)                # long numbers
    return text.strip()
