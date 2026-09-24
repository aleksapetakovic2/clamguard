"""Turning facts about a unit into the sentences that explain it.

This is the point of the Services page: not "is it running" but "what is
this, why is it here, and do I need it". Everything below is derived from
evidence already collected — the unit's own fields, its package, its man page,
its dependency edges. There is deliberately **no hand-written per-unit
glossary**. A table mapping `cups.service` to a paragraph about printing would
be wrong the first time a distribution renamed something, and there are four
hundred of them.

What there *is* instead is a **families** layer: structural patterns that are
true because of how systemd works, not because of what a particular project
called itself. ``getty@tty1.service`` is a login prompt on a terminal for the
same reason on every machine that has ever run systemd, and that will not rot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .model import (
    Enablement,
    Inventory,
    Purpose,
    Unit,
    UnitKind,
    human_duration,
    man_command,
)

#: A unit whose boot cost is above this is worth pointing at. Measured rather
#: than guessed: on this machine 100 units report a second or more and 97 of
#: them report the same 2.717 s — `systemd-analyze blame` gives units that
#: finished together identical figures — so a low threshold flags a crowd.
#: Above five seconds there is exactly one unit, which is the one worth seeing.
SLOW_BOOT_SECONDS = 5.0

#: Flag a unit's sandboxing only when it is *this* bad. systemd's own scale
#: calls 6+ "exposed", but the median scored unit on an ordinary desktop is
#: 9.4: almost nothing outside systemd's own units is sandboxed at all. A flag
#: that fires on two thirds of the list is decoration, so this is set where it
#: means "essentially unconfined" and is further narrowed to units that are
#: actually running as root. The score itself is always shown in the details.
UNSANDBOXED_SCORE = 9.0


@dataclass(frozen=True, slots=True)
class Family:
    """A structural pattern and what it means."""

    pattern: re.Pattern
    note: str


#: Matched in order; the first hit wins. Every entry here is true because of
#: how systemd is built, not because of what any particular project is called.
FAMILIES: tuple[Family, ...] = (
    Family(re.compile(r"^user@\d+\.service$"),
           "The systemd instance that runs one logged-in user's own services. "
           "Everything in that user's session hangs off this."),
    Family(re.compile(r"^user-runtime-dir@\d+\.service$"),
           "Sets up and tears down /run/user/<uid> for one logged-in user."),
    Family(re.compile(r"^getty@"),
           "A login prompt on a text terminal. One instance per terminal."),
    Family(re.compile(r"^serial-getty@"),
           "A login prompt on a serial port."),
    Family(re.compile(r"^session-\d+\.scope$"),
           "One login session's processes, adopted by systemd rather than "
           "started by it. It appears when you log in and goes when you log out."),
    Family(re.compile(r"^app-.*@autostart\.service$"),
           "A desktop autostart entry: systemd-xdg-autostart-generator turns "
           "each .desktop file in an autostart folder into a unit like this "
           "one when you log in."),
    Family(re.compile(r"^app-.*\.(service|scope)$"),
           "An application your desktop started, wrapped in a unit so systemd "
           "can account for it and clean up after it."),
    Family(re.compile(r"^dbus-org\.freedesktop\."),
           "An activation alias: D-Bus starts the real unit under this name "
           "when a program asks for that bus service."),
    Family(re.compile(r"^systemd-"),
           "Part of systemd itself, shipped with the init system rather than "
           "by an application."),
    Family(re.compile(r"^dev-.*\.(device|swap)$"),
           "A kernel device exposed as a unit so other units can wait for it."),
    Family(re.compile(r"^(?:.*\\x2d)?.*\.mount$"),
           "A filesystem mount point. Usually generated from /etc/fstab."),
    Family(re.compile(r"@\d*\.service$"),
           "One instance of a template unit — the same unit file, started "
           "once per name after the @."),
)


def describe(unit: Unit, inventory: Inventory | None = None) -> Purpose:
    """Everything worth saying about why this unit exists."""
    headline, source = _headline(unit)
    return Purpose(
        headline=headline,
        headline_source=source,
        notes=_notes(unit),
        reasons=_reasons(unit, inventory),
        dependents=_dependents(unit),
        flags=_flags(unit),
        reading=_reading(unit),
    )


def describe_all(inventory: Inventory) -> None:
    """Fill in :attr:`Unit.purpose` for every unit, in place."""
    for unit in inventory:
        unit.purpose = describe(unit, inventory)


# ---------------------------------------------------------------------------
# The one-line answer
# ---------------------------------------------------------------------------


def _headline(unit: Unit) -> tuple[str, str]:
    """The best single sentence available, and where it came from.

    ``Description=`` wins when it exists because it describes *this unit*,
    where a package description describes a whole package that may ship six of
    them. The man page is the fallback because it is usually the most
    informative, and the package description the last resort because it is the
    least specific.
    """
    if unit.description and unit.description != unit.id:
        return unit.description, "the unit file"
    if unit.man_summary:
        return unit.man_summary, "its man page"
    if unit.package_summary:
        return unit.package_summary, f"the {unit.package} package"
    if not unit.exists:
        return (unit.load_error or "systemd has no unit by this name."), "systemd"
    return "", ""


# ---------------------------------------------------------------------------
# Structural facts
# ---------------------------------------------------------------------------


def _notes(unit: Unit) -> tuple[str, ...]:
    notes: list[str] = []

    kind_blurb = unit.kind.blurb
    if kind_blurb:
        notes.append(kind_blurb)

    for family in FAMILIES:
        if family.pattern.search(unit.id):
            notes.append(family.note)
            break

    if unit.instance:
        notes.append(f"An instance of {unit.template}, started with "
                     f"“{unit.instance}” as its parameter.")

    if unit.aliases:
        notes.append("Also known as " + ", ".join(unit.aliases) + ".")

    if unit.following:
        notes.append(f"Its state follows {unit.following}.")

    if unit.triggered_by:
        notes.append("Does not run continuously — it is started on demand by "
                     + ", ".join(unit.triggered_by) + ".")

    if unit.triggers:
        notes.append("Starts " + ", ".join(unit.triggers) + " when it fires.")

    if unit.skipped:
        notes.append("Skipped on purpose: its ExecCondition= check decided not "
                     "to run it. For a desktop autostart entry that usually "
                     "means it belongs to a different desktop.")

    if unit.source_path:
        notes.append(f"Generated from {unit.source_path}.")

    if unit.service_type == "oneshot":
        notes.append("A one-shot: it runs, finishes, and being “inactive” "
                     "afterwards is success rather than failure.")

    explanation = unit.enablement.explanation
    if explanation:
        notes.append(explanation)

    return tuple(notes)


# ---------------------------------------------------------------------------
# Why is this here
# ---------------------------------------------------------------------------


def _reasons(unit: Unit, inventory: Inventory | None) -> tuple[str, ...]:
    """What pulled this unit in — the answer to "why is this running"."""
    reasons: list[str] = []

    if unit.wanted_by:
        reasons.append("Wanted by " + _join(unit.wanted_by)
                       + " — pulled in when that is reached, but its failure "
                         "would not stop it.")
    if unit.required_by:
        reasons.append("Required by " + _join(unit.required_by)
                       + " — that cannot start without this one.")
    if unit.triggered_by:
        reasons.append("Activated on demand by " + _join(unit.triggered_by) + ".")

    if not reasons and unit.enablement is Enablement.ENABLED:
        reasons.append("Enabled directly, and nothing else asks for it.")
    if not reasons and unit.running:
        reasons.append("Running, but nothing on this machine lists it as a "
                       "dependency — it was most likely started by hand.")

    if unit.after and inventory is not None:
        waited = [name for name in unit.after
                  if (other := inventory.get(name)) is not None and other.running]
        if waited:
            reasons.append("Waits for " + _join(tuple(waited)) + " before starting.")

    return tuple(reasons)


def _dependents(unit: Unit) -> tuple[str, ...]:
    """What would notice if this stopped."""
    hard = tuple(unit.required_by)
    soft = tuple(name for name in unit.wanted_by if name not in hard)
    lines: list[str] = []
    if hard:
        lines.append(f"{len(hard)} unit{'' if len(hard) == 1 else 's'} would fail "
                     f"to start without it: {_join(hard)}.")
    if soft:
        # "1 unit asks" but "2 units ask" — the plural moves between the two
        # words, so neither suffix can be shared.
        lines.append(f"{len(soft)} unit{'' if len(soft) == 1 else 's'} "
                     f"ask{'s' if len(soft) == 1 else ''} for it but would carry "
                     f"on without it: {_join(soft)}.")
    if not lines:
        lines.append("Nothing on this machine depends on it.")
    return tuple(lines)


# ---------------------------------------------------------------------------
# Worth a second look
# ---------------------------------------------------------------------------


def _flags(unit: Unit) -> tuple[tuple[str, str], ...]:
    """Each (sentence, tone). Only things a person would actually act on."""
    flags: list[tuple[str, str]] = []

    if not unit.exists:
        flags.append((unit.load_error or "systemd cannot find this unit.", "danger"))
        return tuple(flags)

    if unit.active_state == "failed":
        detail = f" It last exited {unit.exit_status}." if unit.exit_status else ""
        flags.append((f"This unit failed.{detail}", "danger"))

    if unit.result and unit.result != "success" and not unit.skipped:
        flags.append((f"Its last run ended in “{unit.result}” rather "
                      "than success.", "danger"))

    if unit.restarts:
        flags.append((f"It has restarted {unit.restarts} time"
                      f"{'s' if unit.restarts != 1 else ''} since it was started.",
                      "warn"))

    if unit.masked:
        flags.append(("Masked: it cannot be started by anything until it is "
                      "unmasked.", "warn"))

    # Only when it is actually puzzling. 446 of this machine's 645 units have
    # an unmet condition — hardware that is not present, a file that does not
    # exist — and for a unit nobody expected to run that is simply how systemd
    # works. It is worth saying only when the unit is set to start and did not.
    # Only for units somebody actually switched on. `static` counts as
    # "starts itself" elsewhere — it does, when pulled in — but a static unit
    # that never got pulled in is not a puzzle, and 182 of this machine's
    # blockdev@ and alsa-state targets are exactly that.
    if (unit.condition_result == "no" and not unit.running
            and unit.enablement in (Enablement.ENABLED, Enablement.ENABLED_RUNTIME)):
        flags.append(("This is set to start, but a Condition= in the unit file "
                      "was not met, so systemd skipped it. That is a deliberate "
                      "no-op rather than a failure — run `systemctl status` to "
                      "see which condition.", "neutral"))

    if unit.deviates_from_preset:
        shipped = "enabled" if unit.preset.starts_itself else "disabled"
        now = "enabled" if unit.enablement.starts_itself else "disabled"
        flags.append((f"Someone changed this: your distribution ships it "
                      f"{shipped}, and it is {now} here.", "warn"))

    # Generated units are not flagged: they are normal — every fstab mount and
    # every desktop autostart entry is one — and the Enablement note already
    # says where they come from. Flagging them put 17 ordinary session entries
    # under "Worth knowing".
    if unit.is_unpackaged:
        flags.append((f"No package owns {unit.fragment_path}. This unit was "
                      "added to the machine by hand.", "warn"))

    local_drop_ins = unit.local_drop_ins
    if local_drop_ins:
        flags.append(("Locally modified by " + _join(tuple(local_drop_ins))
                      + ", which overrides the unit file as it was installed.",
                      "warn"))

    if (unit.exposure is not None and unit.exposure.score >= UNSANDBOXED_SCORE
            and unit.running and unit.runs_as_root):
        flags.append((unit.exposure.explanation, "warn"))

    if unit.runs_as_root and unit.running and unit.kind is UnitKind.SERVICE:
        world = [port for port in unit.ports if port.world_reachable]
        if world:
            flags.append(("Runs as root and is listening on "
                          + _join(tuple(port.display for port in world))
                          + ", reachable from outside this machine.", "danger"))

    if unit.boot_seconds >= SLOW_BOOT_SECONDS:
        flags.append((f"Cost {human_duration(unit.boot_seconds)} of your last "
                      "boot.", "warn"))

    return tuple(flags)


# ---------------------------------------------------------------------------
# Where to read more
# ---------------------------------------------------------------------------


def _reading(unit: Unit) -> tuple[tuple[str, str], ...]:
    """(label, target) for the Documentation= entries and the package page."""
    reading: list[tuple[str, str]] = []
    for entry in unit.documentation:
        if entry.startswith("man:"):
            reading.append((man_command(entry), entry))
        elif entry.startswith(("http://", "https://")):
            reading.append((entry, entry))
        elif entry.startswith("file:"):
            reading.append((entry[5:], entry))
        else:
            reading.append((entry, entry))

    if unit.package_url and not any(target == unit.package_url
                                    for _, target in reading):
        reading.append((f"{unit.package} homepage", unit.package_url))
    return tuple(reading)


def _join(names: tuple[str, ...], limit: int = 4) -> str:
    """``a, b and 3 more`` — a dependency list can be forty entries long."""
    listed = list(names[:limit])
    remainder = len(names) - len(listed)
    if remainder > 0:
        return ", ".join(listed) + f" and {remainder} more"
    if len(listed) == 1:
        return listed[0]
    return ", ".join(listed[:-1]) + " and " + listed[-1] if listed else ""
