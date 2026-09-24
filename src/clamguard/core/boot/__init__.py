"""Boot Analyzer — what happens between the power button and the login screen.

An antivirus checks files. This package checks the thing that decides which
files get to run in the first place: firmware settings, the bootloader, the
kernel and its mitigations, and everything wired to start automatically.

The public names::

    from clamguard.core.boot import BootAnalyzer, Report, Severity

Read :mod:`clamguard.core.boot.model` first — it defines the vocabulary the
rest of the package speaks. Then :mod:`clamguard.core.boot.probe`, which is the
only way a check is allowed to look at the system.

**Nothing in this package writes anything.** Every check is read-only, runs
unprivileged, and reports a fix as a command for the user to run themselves.
"""

from .model import (
    Category,
    Evidence,
    Finding,
    Fix,
    Reference,
    Report,
    Severity,
)
from .probe import Probe
from .registry import Check, catalogue, check

__all__ = [
    "Category", "Check", "Evidence", "Finding", "Fix", "Probe", "Reference",
    "Report", "Severity", "catalogue", "check",
]
