"""Units that failed, or that run with more power than they need.

Two different questions live here. The first is operational: did everything
that was supposed to start actually start? A machine in the `degraded` state
has something broken and usually nobody has noticed, because nothing tells you
unless you ask.

The second is about blast radius. ``systemd-analyze security`` scores each
service by how much of the system it could reach if it were compromised, and
it is remarkably good at it. The scores are advisory — a low score is not a
vulnerability — so they are reported quietly by default and the detail lives
in its own tab.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterator

from ..model import Category, Evidence, Finding, Fix, Reference, Severity
from ..probe import Probe
from ..profile import Policy
from ..registry import SkipCheck, check, finding, get, passed
from .common import listing, plural

#: Units whose whole job is security. Masking one is almost always a mistake
#: or somebody covering their tracks, so it is called out by name.
SECURITY_UNITS = (
    "auditd", "apparmor", "firewalld", "ufw", "nftables", "iptables",
    "systemd-journald", "clamav-daemon", "clamav-clamonacc", "clamav-freshclam",
    "clamd", "selinux-autorelabel", "aide", "fail2ban",
)

VENDOR_UNIT_DIRS = ("/usr/lib/systemd/system", "/lib/systemd/system")
LOCAL_UNIT_DIR = "/etc/systemd/system"


@dataclass(frozen=True)
class Exposure:
    """One row of ``systemd-analyze security``."""

    unit: str
    score: float
    predicate: str

    @property
    def tone(self) -> str:
        if self.score >= 9.0:
            return "danger"
        if self.score >= 7.0:
            return "warn"
        if self.score >= 4.0:
            return "info"
        return "ok"


def exposure_table(probe: Probe) -> list[Exposure]:
    """Every unit systemd will score, worst first.

    Exported because the Boot Analyzer's Services tab shows the whole table,
    not just the units that crossed a threshold.
    """
    result = probe.run("systemd-analyze", "security", "--no-pager")
    if not result.ok:
        return []
    rows: list[Exposure] = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 3 or not fields[0].endswith((".service", ".socket", ".mount")):
            continue
        try:
            score = float(fields[1])
        except ValueError:
            continue
        rows.append(Exposure(fields[0], score, fields[2]))
    return sorted(rows, key=lambda row: -row.score)


def unit_detail(probe: Probe, unit: str) -> str:
    """``systemd-analyze security <unit>``, for the detail panel."""
    result = probe.run("systemd-analyze", "security", unit, "--no-pager")
    return result.stdout if result.stdout else result.output


@check(
    "services.failed",
    title="Failed units",
    category=Category.SERVICES,
    inspects="systemctl list-units --failed, and each failure's journal lines.",
    worst=Severity.HIGH,
    tags=("services",),
)
def failed_units(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Something that did not start is the most actionable thing on this page."""
    item = get("services.failed")
    result = probe.run("systemctl", "list-units", "--failed", "--no-legend",
                       "--plain", "--no-pager")
    if not result.ok and result.stderr.strip():
        raise SkipCheck(f"systemctl would not answer: {result.output[:120]}")

    units = []
    for line in result.lines():
        fields = line.split()
        if fields and fields[0].endswith((".service", ".mount", ".timer",
                                          ".socket", ".target", ".path")):
            units.append(fields[0])

    if not units:
        yield passed(
            item, "none", "Everything that was supposed to start, started",
            "No unit is in the failed state.",
            value="0 failed",
            evidence=(Evidence("systemctl list-units --failed",
                               "0 loaded units listed.", kind="command"),),
        )
        return

    for unit in units:
        lines = _journal_for(probe, unit)
        security = any(name in unit for name in SECURITY_UNITS)
        yield finding(
            item, unit.replace(".", "-"),
            policy.at_least("failed_unit",
                            Severity.HIGH if security else Severity.MEDIUM),
            f"{unit} failed to start",
            (f"{unit} is a security service, and it is not running."
             if security else
             f"{unit} entered the failed state during this boot."),
            impact=(
                "Whatever this unit does is not happening, and nothing on the "
                "desktop will tell you. If it is a security service — a "
                "firewall, an audit daemon, a scanner — the machine is running "
                "without it."
            ),
            value="failed",
            expected="active",
            evidence=(
                Evidence(f"systemctl status {unit}",
                         _status_summary(probe, unit), kind="command"),
                Evidence(f"journalctl -b -u {unit}",
                         "\n".join(lines) or "no journal lines retained",
                         kind="command"),
            ),
            fixes=(
                Fix(
                    title="Read why it failed",
                    explanation="The journal for one unit, this boot only.",
                    command=f"journalctl -b -u {unit} --no-pager",
                    recommended=True,
                ),
                Fix(
                    title="Try starting it again",
                    explanation="Some failures are a race at boot and nothing more.",
                    command=f"sudo systemctl restart {unit}",
                ),
                Fix(
                    title="Stop it trying, if you do not need it",
                    explanation="Disabling is honest; leaving a unit failing "
                                "forever hides real failures in the noise.",
                    command=f"sudo systemctl disable --now {unit}",
                    risk="Make sure you know what it does first.",
                ),
            ),
            tags=frozenset({"services"}),
        )


def _journal_for(probe: Probe, unit: str, lines: int = 12) -> list[str]:
    result = probe.run("journalctl", "-b", "-u", unit, "--no-pager",
                       "-o", "short-iso", "-n", str(lines))
    return result.lines() if result.ok else []


def _status_summary(probe: Probe, unit: str) -> str:
    result = probe.run("systemctl", "show", unit, "--no-pager",
                       "--property=Description,LoadState,ActiveState,SubState,"
                       "Result,ExecMainStatus,FragmentPath")
    return result.stdout.strip() if result.ok else result.output


@check(
    "services.state",
    title="Overall systemd state",
    category=Category.SERVICES,
    inspects="systemctl is-system-running.",
    worst=Severity.MEDIUM,
    tags=("services",),
)
def system_state(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """One word that summarises whether the boot went to plan."""
    item = get("services.state")
    result = probe.run("systemctl", "is-system-running")
    state = (result.stdout or result.stderr).strip()
    if not state:
        raise SkipCheck("systemctl would not report the system state")

    evidence = (Evidence("systemctl is-system-running", state, kind="command"),)

    if state == "running":
        yield passed(
            item, "running", "systemd reports the system as running",
            "Every unit reached its intended state.",
            value=state, evidence=evidence,
        )
        return

    explanations = {
        "degraded": "at least one unit failed; see the findings above",
        "starting": "the boot has not finished yet",
        "maintenance": "the system is in emergency or rescue mode",
        "stopping": "the system is shutting down",
        "initializing": "the boot has barely begun",
        "offline": "systemd is not the init system here",
        "unknown": "systemd could not tell",
    }
    yield finding(
        item, state, policy.severity("system_degraded"),
        f"systemd reports the system as {state}",
        f"That means {explanations.get(state, 'something other than a clean boot')}.",
        impact="A degraded system keeps working, which is exactly why nobody "
               "notices. The failure is usually months old by the time anyone "
               "looks.",
        value=state,
        expected="running",
        evidence=evidence,
        fixes=(Fix(
            title="List what is failing",
            explanation="Then deal with each, or disable it honestly.",
            command="systemctl --failed",
            recommended=True,
        ),),
        tags=frozenset({"services"}),
    )


@check(
    "services.exposure",
    title="Service exposure scores",
    category=Category.SERVICES,
    inspects="systemd-analyze security, which scores each unit's sandboxing.",
    worst=Severity.MEDIUM,
    tags=("services", "hardening"),
    slow=True,
)
def service_exposure(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """How much of the system each service could reach if it were compromised."""
    item = get("services.exposure")
    rows = exposure_table(probe)
    if not rows:
        raise SkipCheck("systemd-analyze security produced no output")

    limit = policy.threshold("exposure_unsafe")
    worst = [row for row in rows if row.score >= limit]
    table = "\n".join(f"{row.unit:<44} {row.score:>5.1f}  {row.predicate}"
                      for row in rows[:25])
    evidence = (Evidence("systemd-analyze security", table, kind="command"),)

    if not worst:
        yield passed(
            item, "contained", "No service scores above the exposure threshold",
            f"{plural(len(rows), 'unit')} scored; the worst is "
            f"{rows[0].unit} at {rows[0].score:.1f}, below the {limit:.1f} "
            "this profile flags at.",
            value=f"worst {rows[0].score:.1f}", evidence=evidence,
        )
        return

    network_facing = [row for row in worst
                      if any(word in row.unit for word in
                             ("ssh", "http", "nginx", "apache", "smb", "nfs",
                              "cups", "avahi", "bluetooth", "network"))]
    yield finding(
        item, "unsafe", policy.severity("unit_exposure"),
        f"{plural(len(worst), 'service')} runs with almost no sandboxing",
        f"systemd scores each unit from 0 to 10 by how much of the system it "
        f"could reach if it were taken over. {plural(len(worst), 'unit')} "
        f"score{'s' if len(worst) == 1 else ''} {limit:.1f} or worse: "
        + listing([row.unit for row in worst], limit=6) + ".",
        impact=(
            "These are scores, not vulnerabilities — a service with a high "
            "score is only a problem if something gets into it. It matters "
            "most for anything listening on the network"
            + (f", which here includes {listing([row.unit for row in network_facing], limit=4)}."
               if network_facing else ", of which there are none in this list.")
        ),
        value=f"{len(worst)} at {limit:.1f}+",
        expected=f"below {limit:.1f}",
        evidence=evidence,
        fixes=(
            Fix(
                title="See exactly what a unit is missing",
                explanation="Lists every sandboxing option and whether it is set.",
                command=f"systemd-analyze security {worst[0].unit}",
                recommended=True,
            ),
            Fix(
                title="Add sandboxing without editing the vendor unit",
                explanation=(
                    "A drop-in file overrides individual settings and survives "
                    "package updates. ProtectSystem=strict, PrivateTmp=yes and "
                    "NoNewPrivileges=yes are the usual first three."
                ),
                command=f"sudo systemctl edit {worst[0].unit}",
                risk="Sandboxing a service too hard makes it fail in ways that "
                     "are hard to read. Change one setting at a time and check "
                     "the journal.",
            ),
        ),
        references=(Reference("systemd.exec(5) sandboxing options",
                              "man 5 systemd.exec"),),
        tags=frozenset({"services", "hardening"}),
    )


@check(
    "services.overrides",
    title="Locally overridden units",
    category=Category.SERVICES,
    inspects="/etc/systemd/system for files that shadow a packaged unit.",
    worst=Severity.MEDIUM,
    tags=("services", "persistence"),
)
def local_overrides(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A local copy of a vendor unit silently replaces it — and never updates."""
    item = get("services.overrides")
    if not probe.is_dir(LOCAL_UNIT_DIR):
        raise SkipCheck("/etc/systemd/system does not exist")

    shadowing: list[str] = []
    drop_ins: list[str] = []

    for name in probe.listdir(LOCAL_UNIT_DIR):
        path = os.path.join(LOCAL_UNIT_DIR, name)
        if name.endswith(".d") and probe.is_dir(path):
            for piece in probe.listdir(path):
                if piece.endswith(".conf"):
                    drop_ins.append(os.path.join(path, piece))
            continue
        if os.path.islink(path):
            continue  # an enable symlink, not an override
        if not name.endswith((".service", ".socket", ".timer", ".mount", ".path")):
            continue
        for vendor in VENDOR_UNIT_DIRS:
            if probe.exists(os.path.join(vendor, name)):
                shadowing.append(f"{path}  shadows  {os.path.join(vendor, name)}")
                break

    evidence = (Evidence(f"ls {LOCAL_UNIT_DIR}",
                         "\n".join(shadowing + drop_ins) or "no overrides",
                         kind="computed"),)

    if not shadowing:
        yield passed(
            item, "none", "No packaged unit is shadowed by a local copy",
            (f"{plural(len(drop_ins), 'drop-in file')} adjust settings, which "
             "is the supported way to do it." if drop_ins else
             "Nothing in /etc/systemd/system replaces a packaged unit."),
            value=f"{len(drop_ins)} drop-ins", evidence=evidence,
        )
        return

    yield finding(
        item, "shadowed", policy.severity("vendor_unit_overridden"),
        f"{plural(len(shadowing), 'packaged unit')} is replaced by a local copy",
        "A file in /etc/systemd/system with the same name as a packaged unit "
        "replaces it completely. systemd will not tell you, and package "
        "updates to the original will have no effect.",
        impact=(
            "Two problems. Practically, the unit stops receiving the fixes its "
            "package ships. From a security point of view, this is a tidy "
            "place to hide: the service keeps its familiar name while running "
            "something else entirely. Check what these actually start."
        ),
        value=plural(len(shadowing), "unit"),
        expected="drop-in files, not full replacements",
        evidence=evidence,
        fixes=(
            Fix(
                title="Compare each override against the packaged version",
                explanation="If the difference is small, a drop-in would do the "
                            "same job and keep the updates.",
                command="for f in /etc/systemd/system/*.service; do "
                        "[ -L \"$f\" ] || diff -u \"/usr/lib/systemd/system/${f##*/}\" "
                        "\"$f\" 2>/dev/null; done",
                recommended=True,
            ),
            Fix(
                title="Convert one to a drop-in",
                explanation="`systemctl edit` writes a .d/override.conf that "
                            "changes only the lines you put in it.",
                command="sudo systemctl edit <unit>.service",
            ),
        ),
        tags=frozenset({"services", "persistence"}),
    )


@check(
    "services.masked",
    title="Masked units",
    category=Category.SERVICES,
    inspects="systemctl list-unit-files --state=masked.",
    worst=Severity.HIGH,
    tags=("services",),
)
def masked_units(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A masked unit cannot be started at all, even on purpose."""
    item = get("services.masked")
    result = probe.run("systemctl", "list-unit-files", "--state=masked",
                       "--no-legend", "--plain", "--no-pager")
    # systemctl exits non-zero when a --state filter matches nothing, so an
    # empty result with an error code means "none", not "could not check".
    # Only a message on stderr is a real failure.
    if not result.ok and result.stderr.strip():
        raise SkipCheck(f"systemctl would not list masked units: {result.output[:120]}")

    masked = [line.split()[0] for line in result.lines() if line.split()]
    security = [unit for unit in masked
                if any(name in unit for name in SECURITY_UNITS)]
    evidence = (Evidence("systemctl list-unit-files --state=masked",
                         "\n".join(masked) or "none", kind="command"),)

    if security:
        yield finding(
            item, "security", policy.severity("masked_security_unit"),
            f"{plural(len(security), 'security service')} is masked",
            listing(security) + " cannot be started at all — masking is "
            "stronger than disabling. `systemctl start` on a masked unit fails.",
            impact="These are the services that watch the machine. Masking one "
                   "is an explicit decision by somebody; make sure it was you.",
            value=listing(security, limit=3),
            expected="not masked",
            evidence=evidence,
            fixes=(Fix(
                title="Unmask it",
                explanation="Then decide separately whether to enable it.",
                command=f"sudo systemctl unmask {security[0]}",
                recommended=True,
            ),),
            tags=frozenset({"services"}),
        )
        return

    if masked:
        yield finding(
            item, "some", Severity.INFO,
            f"{plural(len(masked), 'unit')} is masked",
            "Masked units cannot be started even explicitly. Distributions mask "
            "a few by default — ones replaced by a newer service, usually.",
            value=str(len(masked)), evidence=evidence,
            tags=frozenset({"services"}),
        )
        return

    yield passed(
        item, "none", "No units are masked",
        "Nothing has been forcibly prevented from starting.",
        value="0", evidence=evidence,
    )
