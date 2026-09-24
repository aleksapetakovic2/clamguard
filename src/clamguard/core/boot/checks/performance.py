"""Where the time between power-on and login actually goes.

A slow boot is not a security problem, but "something is wrong with this
machine" is exactly the question the Boot Analyzer exists to answer, and the
most common concrete answer is a unit waiting on something that is never going
to arrive. systemd measures all of it; this reads the measurements and names
the culprit.

The parsing here is the only fiddly part: ``systemd-analyze`` prints durations
as human text — ``1min 31.963s``, ``845ms`` — so there is a small parser for
that, tested directly.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..model import (
    BootPhase,
    BootTimings,
    Category,
    Evidence,
    Finding,
    Fix,
    Severity,
    format_duration,
)
from ..probe import Probe
from ..profile import Policy
from ..registry import SkipCheck, check, finding, get, passed
from .common import listing, plural

#: "2min 41.027s" -> the pieces. systemd uses y, month, w, d, h, min, s, ms, us.
_DURATION_PART = re.compile(
    r"(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>y|month|w|d|h|min|ms|us|s)\b")

_UNIT_SECONDS = {
    "y": 365 * 86400.0, "month": 30 * 86400.0, "w": 7 * 86400.0,
    "d": 86400.0, "h": 3600.0, "min": 60.0, "s": 1.0,
    "ms": 0.001, "us": 0.000001,
}

#: "Startup finished in 24.311s (firmware) + 7.021s (loader) + …"
_PHASE = re.compile(r"(?P<duration>[\d.]+(?:\s*\w+\s*[\d.]+)*\s*\w+)\s*\((?P<name>\w+)\)")


def parse_duration(text: str) -> float:
    """``"1min 31.963s"`` → ``91.963``. Unparseable text gives 0.0."""
    total = 0.0
    for match in _DURATION_PART.finditer(text):
        total += float(match.group("value")) * _UNIT_SECONDS[match.group("unit")]
    return total


def unescape_unit(name: str) -> str:
    r"""``dev-disk-by\x2duuid-….device`` → ``dev-disk-by-uuid-….device``.

    systemd escapes anything not allowed in a unit name as ``\xNN``. Leaving
    that in makes a list of device units almost unreadable.
    """
    def replace(match):
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return re.sub(r"\\x([0-9a-fA-F]{2})", replace, name)


def collapse_device_aliases(
    units: list[tuple[str, float]],
) -> tuple[list[tuple[str, float]], dict[str, int]]:
    """One row per device, not one per name udev gave it.

    A single partition appears in `systemd-analyze blame` under every alias in
    /dev/disk/by-* — a dozen rows, identical times, all describing one wait.
    Left alone they fill the chart and hide everything else, so device units
    with the same duration are folded into the shortest of their names.

    Returns the collapsed list and, separately, how many names each survivor
    stands for. The count is deliberately *not* folded into the name: several
    checks select device units by their ".device" suffix, and a name with a
    suffix appended would silently stop matching.
    """
    groups: dict[float, list[str]] = {}
    collapsed: list[tuple[str, float]] = []
    aliases: dict[str, int] = {}

    for name, seconds in units:
        if not name.endswith(".device"):
            collapsed.append((unescape_unit(name), seconds))
            continue
        groups.setdefault(round(seconds, 1), []).append(name)

    for seconds, names in groups.items():
        # The shortest name is the one a person recognises: dev-sda1.device
        # rather than dev-disk-by\x2dpath-pci\x2d0000:0f:00.0….device.
        shortest = unescape_unit(min(names, key=len))
        collapsed.append((shortest, seconds))
        if len(names) > 1:
            aliases[shortest] = len(names) - 1

    collapsed.sort(key=lambda row: -row[1])
    return collapsed, aliases


def timings(probe: Probe) -> BootTimings:
    """Boot phases, the slowest units, and the critical chain.

    Exported: the Boot Analyzer's timeline tab draws from the same call, and
    the report embeds it.
    """
    cached = getattr(probe, "_boot_timings", None)
    if cached is not None:
        return cached

    phases: list[BootPhase] = []
    total = 0.0
    summary = probe.run("systemd-analyze", "time")
    for line in summary.stdout.splitlines():
        if not line.startswith("Startup finished"):
            continue
        for match in _PHASE.finditer(line):
            phases.append(BootPhase(match.group("name"),
                                    parse_duration(match.group("duration"))))
        _, _, tail = line.rpartition("=")
        total = parse_duration(tail)
        break
    if phases and not total:
        total = sum(phase.seconds for phase in phases)

    slowest: list[tuple[str, float]] = []
    blame = probe.run("systemd-analyze", "blame", "--no-pager")
    for line in blame.lines():
        parts = line.strip().rsplit(" ", 1)
        if len(parts) != 2:
            continue
        seconds = parse_duration(parts[0])
        if seconds:
            slowest.append((parts[1], seconds))
    slowest, aliases = collapse_device_aliases(slowest)

    chain = probe.run("systemd-analyze", "critical-chain", "--no-pager")
    result = BootTimings(
        phases=tuple(phases),
        total_seconds=total,
        slowest_units=tuple(slowest[:40]),
        unit_aliases=aliases,
        critical_chain=tuple(line for line in chain.stdout.splitlines()
                             if line.strip() and not line.startswith("The time")),
    )
    setattr(probe, "_boot_timings", result)
    return result


@check(
    "performance.total",
    title="Total boot time",
    category=Category.PERFORMANCE,
    inspects="systemd-analyze time.",
    worst=Severity.MEDIUM,
    tags=("performance",),
)
def total_time(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """How long it took, broken down by phase."""
    item = get("performance.total")
    measured = timings(probe)
    if not measured.measured:
        raise SkipCheck("systemd-analyze could not measure this boot")

    breakdown = "  +  ".join(f"{phase.text} ({phase.name})"
                             for phase in measured.phases)
    evidence = (Evidence("systemd-analyze time",
                         f"{breakdown}\n= {measured.total_text}", kind="command"),)
    budget = policy.threshold("boot_total_seconds")

    if measured.total_seconds <= budget:
        yield passed(
            item, "quick", f"The machine booted in {measured.total_text}",
            breakdown,
            value=measured.total_text, evidence=evidence,
        )
        return

    worst = max(measured.phases, key=lambda phase: phase.seconds,
                default=BootPhase("", 0.0))
    advice = {
        "firmware": "That is the firmware's own self-test, before any of your "
                    "software runs. Look for a 'fast boot' option, and for "
                    "controllers you do not use that can be disabled.",
        "loader": "That is the bootloader's menu timeout, mostly. Shortening "
                  "it is one line in the bootloader configuration.",
        "kernel": "The kernel itself, decompressing and probing hardware. "
                  "Rarely the thing worth attacking.",
        "initrd": "The initramfs — usually waiting for a disk that is slow or "
                  "is not there at all. See the device-timeout finding.",
        "userspace": "systemd starting services. The slow-unit finding names "
                     "which ones.",
    }.get(worst.name, "")

    yield finding(
        item, "slow", policy.severity("boot_slow"),
        f"Booting takes {measured.total_text}",
        f"{breakdown}. This profile expects under {format_duration(budget)}. "
        f"Most of it is the {worst.name} phase, at {worst.text}. {advice}",
        impact="Slow boots are usually one thing waiting for a timeout rather "
               "than everything being a little slow — which means there is "
               "normally one specific cause to find.",
        value=measured.total_text,
        expected=f"under {format_duration(budget)}",
        evidence=evidence,
        fixes=(Fix(
            title="See the breakdown per unit",
            explanation="Lists every unit by how long it took to start.",
            command="systemd-analyze blame | head -20",
            recommended=True,
        ),),
        tags=frozenset({"performance"}),
    )


@check(
    "performance.devices",
    title="Waiting for devices",
    category=Category.PERFORMANCE,
    inspects="systemd-analyze blame for .device and .mount units, and /etc/fstab.",
    worst=Severity.MEDIUM,
    tags=("performance",),
)
def device_waits(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """The single most common cause of a two-minute boot: a disk that is not there."""
    item = get("performance.devices")
    measured = timings(probe)
    if not measured.slowest_units:
        raise SkipCheck("systemd-analyze blame produced no output")

    limit = policy.threshold("unit_slow_seconds")
    devices = [(unit, seconds) for unit, seconds in measured.slowest_units
               if unit.endswith((".device", ".mount", ".swap")) and seconds >= limit]
    if not devices:
        yield passed(
            item, "prompt", "No device kept the boot waiting",
            "No .device or .mount unit took longer than "
            f"{format_duration(limit)} to appear.",
            value="none",
            evidence=(Evidence("systemd-analyze blame",
                               "\n".join(f"{format_duration(seconds):>10}  {unit}"
                                         for unit, seconds in measured.slowest_units[:10]),
                               kind="command"),),
        )
        return

    worst_unit, worst_seconds = devices[0]
    # A dozen aliases for the same partition all appear separately; collapsing
    # them to the distinct wait times says what actually happened.
    distinct = sorted({round(seconds) for _unit, seconds in devices}, reverse=True)

    fstab = probe.file("/etc/fstab")
    fstab_lines = [line for line in fstab.lines()
                   if line.strip() and not line.startswith("#")] if fstab.ok else []
    without_nofail = [line for line in fstab_lines
                      if "nofail" not in line and not line.split()[1:2] == ["/"]]

    yield finding(
        item, "timeout", policy.severity("device_timeout"),
        f"The boot waited {format_duration(worst_seconds)} for a device",
        f"{measured.unit_label(worst_unit)} took "
        f"{format_duration(worst_seconds)} to appear"
        + (f", and {plural(len(devices) - 1, 'other device unit')} waited too"
           if len(devices) > 1 else "")
        + ". systemd waits up to 90 seconds by default for a device named in "
        "/etc/fstab or /etc/crypttab before giving up.",
        impact=(
            "This is almost always a disk in /etc/fstab that is not connected: "
            "an external drive, a card reader, or a partition that was removed "
            "without updating fstab. Adding `nofail` to that entry makes the "
            "machine carry on instead of waiting."
        ),
        value=", ".join(format_duration(seconds) for seconds in distinct[:3]),
        expected=f"under {format_duration(limit)}",
        evidence=(
            Evidence("systemd-analyze blame",
                     "\n".join(f"{format_duration(seconds):>10}  "
                               f"{measured.unit_label(unit)}"
                               for unit, seconds in devices[:12]), kind="command"),
            Evidence("/etc/fstab",
                     "\n".join(fstab_lines) if fstab_lines
                     else fstab.error or "not readable"),
        ),
        fixes=(
            Fix(
                title="Find which entry is waiting",
                explanation="Matches the slow device unit against fstab.",
                command="systemd-analyze blame | grep -E '\\.(device|mount)$' | head\n"
                        "cat /etc/fstab",
                recommended=True,
            ),
            Fix(
                title="Let the boot continue without it",
                explanation=(
                    "Add `nofail` and a short device timeout to the fstab line "
                    "for the disk that is not always present:\n"
                    "  UUID=…  /mnt/thing  ext4  defaults,nofail,"
                    "x-systemd.device-timeout=5s  0 2"
                ),
                command="sudo nano /etc/fstab && sudo systemctl daemon-reload",
                risk="A mistake in fstab can stop the machine booting. "
                     "`sudo findmnt --verify` checks the file first."
                     + (f" {plural(len(without_nofail), 'entry', 'entries')} "
                        "currently lack nofail." if without_nofail else ""),
            ),
        ),
        tags=frozenset({"performance"}),
    )


@check(
    "performance.units",
    title="Slow units",
    category=Category.PERFORMANCE,
    inspects="systemd-analyze blame and systemd-analyze critical-chain.",
    worst=Severity.LOW,
    tags=("performance",),
)
def slow_units(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Services that took a long time, excluding the device waits above."""
    item = get("performance.units")
    measured = timings(probe)
    if not measured.slowest_units:
        raise SkipCheck("systemd-analyze blame produced no output")

    limit = policy.threshold("unit_slow_seconds")
    slow = [(unit, seconds) for unit, seconds in measured.slowest_units
            if seconds >= limit and not unit.endswith((".device", ".mount", ".swap"))]
    table = "\n".join(f"{format_duration(seconds):>10}  {unit}"
                      for unit, seconds in measured.slowest_units[:15])
    evidence = (
        Evidence("systemd-analyze blame", table, kind="command"),
        Evidence("systemd-analyze critical-chain",
                 "\n".join(measured.critical_chain[:15]), kind="command"),
    )

    if not slow:
        yield passed(
            item, "quick", "No service held the boot up",
            f"Nothing took longer than {format_duration(limit)}.",
            value="none", evidence=evidence,
        )
        return

    yield finding(
        item, "slow", policy.severity("unit_slow"),
        f"{plural(len(slow), 'service')} took longer than {format_duration(limit)} to start",
        listing([f"{unit} ({format_duration(seconds)})" for unit, seconds in slow],
                limit=5) + ".",
        impact="Only the units on the critical chain actually delay the login "
               "screen; the rest start in parallel and their time is not "
               "additive. The critical chain is in the evidence below.",
        value=f"{format_duration(slow[0][1])} worst",
        expected=f"under {format_duration(limit)}",
        evidence=evidence,
        fixes=(Fix(
            title="See what is really on the critical path",
            explanation="Only these units delay the boot; blame lists "
                        "everything, in parallel or not.",
            command="systemd-analyze critical-chain",
            recommended=True,
        ),),
        tags=frozenset({"performance"}),
    )


@check(
    "performance.firmware",
    title="Firmware time",
    category=Category.PERFORMANCE,
    inspects="The firmware and loader phases of systemd-analyze time.",
    worst=Severity.LOW,
    tags=("performance",),
)
def firmware_time(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Time spent before any of your software runs."""
    item = get("performance.firmware")
    measured = timings(probe)
    if not measured.measured:
        raise SkipCheck("systemd-analyze could not measure this boot")

    firmware = measured.phase("firmware")
    loader = measured.phase("loader")
    if not firmware and not loader:
        raise SkipCheck("this boot reported no firmware or loader phase")

    budget = policy.threshold("firmware_seconds")
    evidence = (Evidence("systemd-analyze time",
                         f"firmware {format_duration(firmware)}, "
                         f"loader {format_duration(loader)}", kind="command"),)

    if firmware + loader <= budget:
        yield passed(
            item, "quick", "The firmware hands over promptly",
            f"{format_duration(firmware)} in firmware, "
            f"{format_duration(loader)} in the bootloader.",
            value=format_duration(firmware + loader), evidence=evidence,
        )
        return

    yield finding(
        item, "slow", policy.severity("firmware_slow"),
        f"{format_duration(firmware + loader)} passes before the kernel starts",
        f"The firmware takes {format_duration(firmware)} and the bootloader "
        f"{format_duration(loader)}. None of that is your operating system.",
        impact="Usually one of: the firmware probing a storage controller with "
               "nothing attached, memory training on a machine with XMP "
               "enabled, network boot being tried first, or simply the "
               "bootloader's menu timeout.",
        value=format_duration(firmware + loader),
        expected=f"under {format_duration(budget)}",
        evidence=evidence,
        fixes=(
            Fix(
                title="Shorten the bootloader menu timeout",
                explanation="GRUB: GRUB_TIMEOUT in /etc/default/grub. "
                            "systemd-boot: timeout in loader.conf.",
                command="grep -n TIMEOUT /etc/default/grub 2>/dev/null",
            ),
            Fix(
                title="Turn off what the firmware is waiting for",
                explanation="Network boot, unused SATA ports and 'thorough' "
                            "memory testing are the usual candidates.",
                manual="Firmware setup → Boot → disable network/PXE boot; "
                       "Advanced → disable unused controllers.",
                reboot_required=True,
            ),
        ),
        tags=frozenset({"performance"}),
    )
