"""The catalogue of checks, and the decorator that fills it.

A check is a plain function::

    @check("firmware.secure-boot",
           title="Secure Boot",
           category=Category.FIRMWARE,
           inspects="The SecureBoot EFI variable, and bootctl's summary.",
           worst=Severity.HIGH)
    def secure_boot(probe: Probe, policy: Policy) -> Iterator[Finding]:
        ...

It takes a :class:`~clamguard.core.boot.probe.Probe` — the only way it may look
at the machine — and a :class:`~clamguard.core.boot.profile.Policy`, which
tells it how severe this user considers each kind of problem. It yields
findings. It does not decide whether it should run, or how it is displayed; the
profile and the UI handle that. Two arguments in, findings out, no state:
that is what makes every check reproducible in a test.

``inspects`` is not decoration: the Checks tab shows it, so a user can see what
a check looks at before enabling it. Write it as a sentence about files and
commands, not about intentions.

Registration happens at import time. :mod:`clamguard.core.boot.checks` imports
every check module, so importing that package is what populates the catalogue.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

from ..logging_setup import get_logger
from .model import Category, Evidence, Finding, Severity, SkippedCheck
from .probe import Probe
from .profile import Policy

log = get_logger(__name__)

#: A check's body. Yields findings; may yield none.
CheckFunction = Callable[[Probe, Policy], Iterable[Finding]]


@dataclass(frozen=True)
class Check:
    """One registered check and everything the UI needs to describe it."""

    id: str
    title: str
    category: Category
    #: What files and commands this looks at. Shown in the Checks tab.
    inspects: str
    function: CheckFunction
    #: The worst severity this check can produce, so the catalogue can be
    #: sorted and filtered before anything has run.
    worst: Severity = Severity.MEDIUM
    tags: frozenset[str] = frozenset()
    #: True for checks that take noticeable time; the profile can turn the
    #: slow ones off without losing the fast ones.
    slow: bool = False
    #: Checks the user is unlikely to want by default — very chatty ones, or
    #: ones that only make sense on servers.
    enabled_by_default: bool = True

    def __str__(self) -> str:
        return f"{self.id} ({self.category.value})"


@dataclass
class CheckRun:
    """What happened when one check ran."""

    check: Check
    findings: tuple[Finding, ...] = ()
    seconds: float = 0.0
    error: str = ""
    skipped: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and not self.skipped


_REGISTRY: dict[str, Check] = {}


def check(
    check_id: str,
    *,
    title: str,
    category: Category,
    inspects: str,
    worst: Severity = Severity.MEDIUM,
    tags: Iterable[str] = (),
    slow: bool = False,
    enabled_by_default: bool = True,
) -> Callable[[CheckFunction], CheckFunction]:
    """Register a check. Returns the function unchanged, so it stays testable."""

    def register(function: CheckFunction) -> CheckFunction:
        if check_id in _REGISTRY:
            raise ValueError(f"two checks claim the id {check_id!r}")
        _REGISTRY[check_id] = Check(
            id=check_id,
            title=title,
            category=category,
            inspects=inspects,
            function=function,
            worst=worst,
            tags=frozenset(tags),
            slow=slow,
            enabled_by_default=enabled_by_default,
        )
        return function

    return register


def catalogue() -> tuple[Check, ...]:
    """Every registered check, in display order.

    Importing :mod:`clamguard.core.boot.checks` is what fills this; doing it
    here rather than at module scope avoids an import cycle between the
    registry and the checks that decorate themselves with it.
    """
    from . import checks  # noqa: F401  - imported for its side effect

    from .model import CATEGORY_ORDER

    def position(item: Check) -> tuple:
        rank = (CATEGORY_ORDER.index(item.category)
                if item.category in CATEGORY_ORDER else len(CATEGORY_ORDER))
        return (rank, item.id)

    return tuple(sorted(_REGISTRY.values(), key=position))


def get(check_id: str) -> Check | None:
    catalogue()
    return _REGISTRY.get(check_id)


def categories_present() -> tuple[Category, ...]:
    """Categories that actually have checks registered in them."""
    from .model import CATEGORY_ORDER

    present = {item.category for item in catalogue()}
    return tuple(name for name in CATEGORY_ORDER if name in present)


# ---------------------------------------------------------------------------
# Running one
# ---------------------------------------------------------------------------


def run_check(item: Check, probe: Probe, policy: Policy | None = None) -> CheckRun:
    """Run one check, catching anything it throws.

    A check that crashes must not take the analysis down with it, and must not
    disappear quietly either: the failure comes back as an INFO finding naming
    the check, so a bug in one corner of the catalogue is visible rather than
    silently reducing coverage.
    """
    started = time.monotonic()
    policy = policy or Policy.for_preset("balanced")
    try:
        findings = tuple(item.function(probe, policy) or ())
    except SkipCheck as reason:
        return CheckRun(item, seconds=time.monotonic() - started, skipped=str(reason))
    except Exception as exc:  # noqa: BLE001 - one bad check must not stop the rest
        log.exception("boot check %s failed", item.id)
        elapsed = time.monotonic() - started
        return CheckRun(
            item,
            findings=(_crash_finding(item, exc),),
            seconds=elapsed,
            error=str(exc),
        )
    return CheckRun(item, findings=findings, seconds=time.monotonic() - started)


class SkipCheck(Exception):
    """Raised by a check that cannot run here. The reason is shown to the user.

    Use it for "this machine has no UEFI", not for "everything is fine" —
    a check with nothing to report should simply yield nothing.
    """


def _crash_finding(item: Check, exc: Exception) -> Finding:
    return Finding(
        id=f"{item.id}.check-failed",
        check_id=item.id,
        category=item.category,
        severity=Severity.INFO,
        title=f"The “{item.title}” check could not complete",
        summary=(
            "This is a bug in ClamGuard, not a problem with your machine. "
            "The rest of the analysis is unaffected, but this area was not "
            "covered — so treat it as unknown rather than clean."
        ),
        impact="One area of the boot analysis has no result.",
        value=type(exc).__name__,
        evidence=(Evidence(f"check {item.id}", f"{type(exc).__name__}: {exc}",
                           kind="computed"),),
        tags=frozenset({"internal"}),
    )


def skipped_record(run: CheckRun) -> SkippedCheck | None:
    if not run.skipped:
        return None
    return SkippedCheck(run.check.id, run.check.title, run.skipped)


# ---------------------------------------------------------------------------
# Small helpers checks use constantly
# ---------------------------------------------------------------------------


def finding(
    item: Check,
    suffix: str,
    severity: Severity,
    title: str,
    summary: str,
    **extra,
) -> Finding:
    """Build a Finding that inherits its check's id and category.

    Saves every check from repeating ``check_id=`` and ``category=``, and makes
    finding ids consistently ``<check id>.<suffix>``.
    """
    return Finding(
        id=f"{item.id}.{suffix}" if suffix else item.id,
        check_id=item.id,
        category=item.category,
        severity=severity,
        title=title,
        summary=summary,
        **extra,
    )


def passed(item: Check, suffix: str, title: str, summary: str = "", **extra) -> Finding:
    """A PASS finding — proof a check ran and found nothing wrong.

    Worth emitting: "we looked and it is fine" is different from "we did not
    look", and the difference is exactly what a person wants from a security
    report. The UI hides passes until asked.
    """
    return finding(item, suffix, Severity.PASS, title, summary, **extra)


def iter_findings(*groups: Iterable[Finding]) -> Iterator[Finding]:
    """Flatten several optional finding sources into one stream."""
    for group in groups:
        for item in group:
            if item is not None:
                yield item


#: Exposed for tests that need to register and then remove a temporary check.
def _unregister(check_id: str) -> None:
    _REGISTRY.pop(check_id, None)
