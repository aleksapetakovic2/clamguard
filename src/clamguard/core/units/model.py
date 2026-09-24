"""What a unit is, in dataclasses. No I/O lives here.

Everything in this module can be constructed from a dictionary of systemd
properties and tested without a machine to run on, which is the point: the
parsing rules are fiddly enough (see :mod:`.inventory`) that they deserve tests
that do not depend on what happens to be installed.

The vocabulary follows systemd's own, because inventing a parallel one would
mean translating twice and being wrong once. The exceptions are
:class:`Provenance` and :class:`Purpose`, which are ours — systemd has no
opinion about where a unit file came from or whether you needed it.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

#: ``Result=`` values that mean "chose not to run" rather than "broke".
SKIPPED_RESULTS = frozenset({"exec-condition"})

#: systemctl verbs that only read, and so never need `sudo`.
READ_ONLY_VERBS = frozenset({"status", "cat", "show", "list-dependencies",
                             "is-active", "is-enabled", "is-failed"})

#: systemd reports "no value" in several dialects depending on the property.
EMPTY_VALUES = frozenset({"", "n/a", "[not set]", "(null)", "infinity",
                          "[no data]", "0"})


class UnitKind(str, Enum):
    """The suffix on a unit name, which is also what the unit does."""

    SERVICE = "service"
    SOCKET = "socket"
    TIMER = "timer"
    TARGET = "target"
    MOUNT = "mount"
    AUTOMOUNT = "automount"
    PATH = "path"
    SLICE = "slice"
    SCOPE = "scope"
    DEVICE = "device"
    SWAP = "swap"
    SNAPSHOT = "snapshot"
    OTHER = "other"

    @classmethod
    def of(cls, unit: str) -> "UnitKind":
        suffix = unit.rpartition(".")[2]
        try:
            return cls(suffix)
        except ValueError:
            return cls.OTHER

    @property
    def title(self) -> str:
        return {
            UnitKind.SERVICE: "Service",
            UnitKind.SOCKET: "Socket",
            UnitKind.TIMER: "Timer",
            UnitKind.TARGET: "Target",
            UnitKind.MOUNT: "Mount",
            UnitKind.AUTOMOUNT: "Automount",
            UnitKind.PATH: "Path watch",
            UnitKind.SLICE: "Slice",
            UnitKind.SCOPE: "Scope",
            UnitKind.DEVICE: "Device",
            UnitKind.SWAP: "Swap",
            UnitKind.SNAPSHOT: "Snapshot",
            UnitKind.OTHER: "Unit",
        }[self]

    @property
    def blurb(self) -> str:
        """One line on what this kind of unit is for."""
        return {
            UnitKind.SERVICE: "A program systemd starts and supervises.",
            UnitKind.SOCKET: "A port or socket that starts its service on the "
                             "first connection.",
            UnitKind.TIMER: "A schedule. It starts another unit and does not "
                            "run continuously itself.",
            UnitKind.TARGET: "A grouping with no program of its own — a "
                             "milestone other units attach themselves to.",
            UnitKind.MOUNT: "A filesystem mount point.",
            UnitKind.AUTOMOUNT: "A mount point that attaches on first access.",
            UnitKind.PATH: "A file or directory watch that starts a unit when "
                           "something changes.",
            UnitKind.SLICE: "A resource-limit group that other units live in.",
            UnitKind.SCOPE: "Processes systemd is supervising but did not "
                            "start — a login session, a container.",
            UnitKind.DEVICE: "A kernel device, exposed so units can depend on it.",
            UnitKind.SWAP: "A swap partition or file.",
            UnitKind.SNAPSHOT: "A saved copy of the manager state.",
            UnitKind.OTHER: "",
        }[self]


class Enablement(str, Enum):
    """Whether the unit starts on its own, from ``UnitFileState``."""

    ENABLED = "enabled"
    ENABLED_RUNTIME = "enabled-runtime"
    DISABLED = "disabled"
    STATIC = "static"
    MASKED = "masked"
    MASKED_RUNTIME = "masked-runtime"
    INDIRECT = "indirect"
    ALIAS = "alias"
    GENERATED = "generated"
    TRANSIENT = "transient"
    LINKED = "linked"
    LINKED_RUNTIME = "linked-runtime"
    BAD = "bad"
    UNKNOWN = ""

    @classmethod
    def of(cls, value: str) -> "Enablement":
        try:
            return cls(value or "")
        except ValueError:
            return cls.UNKNOWN

    @property
    def starts_itself(self) -> bool:
        """Will this come up without anyone asking?"""
        return self in (Enablement.ENABLED, Enablement.ENABLED_RUNTIME,
                        Enablement.STATIC, Enablement.GENERATED,
                        Enablement.INDIRECT)

    @property
    def explanation(self) -> str:
        return {
            Enablement.ENABLED: "Starts at boot, because a symlink says so.",
            Enablement.ENABLED_RUNTIME: "Enabled until the next reboot only.",
            Enablement.DISABLED: "Installed but not started at boot.",
            Enablement.STATIC: "Has no [Install] section, so it cannot be "
                               "enabled or disabled — it runs when something "
                               "else pulls it in.",
            Enablement.MASKED: "Linked to /dev/null. It cannot be started at "
                               "all, by anything, until it is unmasked.",
            Enablement.MASKED_RUNTIME: "Masked until the next reboot.",
            Enablement.INDIRECT: "Not enabled itself, but something it is "
                                 "listed under is.",
            Enablement.ALIAS: "Another name for a different unit.",
            Enablement.GENERATED: "Written by a generator rather than shipped "
                                  "as a file — from /etc/fstab, a desktop "
                                  "autostart entry, a kernel argument or "
                                  "similar.",
            Enablement.TRANSIENT: "Created at runtime by an API call. It will "
                                  "not survive a reboot.",
            Enablement.LINKED: "Symlinked into the unit path from somewhere "
                               "outside it.",
            Enablement.LINKED_RUNTIME: "Symlinked in until the next reboot.",
            Enablement.BAD: "systemd could not make sense of this unit file.",
            Enablement.UNKNOWN: "",
        }[self]


class Provenance(str, Enum):
    """Where the unit file came from. Ours, not systemd's."""

    PACKAGE = "package"        # a distribution package owns the file
    LOCAL = "local"            # written by hand, usually /etc/systemd/system
    GENERATED = "generated"    # /run/systemd/generator*, made at boot
    TRANSIENT = "transient"    # created over the API, no file at all
    UNPACKAGED = "unpackaged"  # a real file that no package claims
    UNKNOWN = "unknown"

    @property
    def title(self) -> str:
        return {
            Provenance.PACKAGE: "From a package",
            Provenance.LOCAL: "Added locally",
            Provenance.GENERATED: "Generated at boot",
            Provenance.TRANSIENT: "Created at runtime",
            Provenance.UNPACKAGED: "No package owns this",
            Provenance.UNKNOWN: "Origin unknown",
        }[self]

    @property
    def tone(self) -> str:
        """Badge colour. Local and unpackaged are worth a second look."""
        return {
            Provenance.PACKAGE: "ok",
            Provenance.LOCAL: "warn",
            Provenance.GENERATED: "neutral",
            Provenance.TRANSIENT: "neutral",
            Provenance.UNPACKAGED: "warn",
            Provenance.UNKNOWN: "neutral",
        }[self]


@dataclass(frozen=True, slots=True)
class ExecCommand:
    """One ``ExecStart=`` line, unpacked from systemd's struct syntax."""

    path: str = ""
    argv: tuple[str, ...] = ()
    ignore_errors: bool = False

    @property
    def display(self) -> str:
        return " ".join(self.argv) if self.argv else self.path

    @property
    def program(self) -> str:
        """The binary, for looking up a man page or a package."""
        return self.path or (self.argv[0] if self.argv else "")


@dataclass(frozen=True, slots=True)
class Exposure:
    """One row of ``systemd-analyze security``."""

    unit: str
    score: float = 0.0
    rating: str = ""        # OK / MEDIUM / EXPOSED / UNSAFE

    @property
    def tone(self) -> str:
        # systemd's own thresholds: <2 OK, <4 medium, <6 exposed, else unsafe.
        if self.score < 2.0:
            return "ok"
        if self.score < 6.0:
            return "warn"
        return "danger"

    @property
    def explanation(self) -> str:
        return (f"systemd scores this unit's sandboxing {self.score:.1f} out of "
                f"10 ({self.rating.lower() or 'unrated'}). Lower is better: the "
                "score counts the restrictions the unit does *not* apply, so a "
                "high number means a compromise of this service would have a "
                "large blast radius.")


@dataclass(frozen=True, slots=True)
class ListeningPort:
    """A socket held open by this unit's main process."""

    protocol: str = ""
    address: str = ""
    port: str = ""

    @property
    def display(self) -> str:
        return f"{self.protocol} {self.address}:{self.port}".strip()

    @property
    def world_reachable(self) -> bool:
        """Bound to every interface rather than just this machine."""
        return self.address in ("0.0.0.0", "*", "::", "[::]")


@dataclass(slots=True)
class Purpose:
    """The synthesised answer to "what is this and why is it here".

    Assembled by :mod:`.purpose` from every source available. Every field is
    optional because every source is optional — a machine without `pacman`,
    without man pages or without `systemd-analyze` still gets a page.
    """

    #: One sentence, the best available. Description, man page or package.
    headline: str = ""
    #: Where the headline came from, so the UI can say so.
    headline_source: str = ""
    #: Structural facts: "a template instance of getty@.service".
    notes: tuple[str, ...] = ()
    #: Why this unit is running at all, in dependency terms.
    reasons: tuple[str, ...] = ()
    #: What would be affected if it stopped.
    dependents: tuple[str, ...] = ()
    #: Things worth a second look, each (text, tone).
    flags: tuple[tuple[str, str], ...] = ()
    #: Where to read more: (label, target) for man pages and URLs.
    reading: tuple[tuple[str, str], ...] = ()


@dataclass(slots=True)
class Unit:
    """One systemd unit and everything gathered about it."""

    id: str
    description: str = ""
    names: tuple[str, ...] = ()

    load_state: str = ""
    load_error: str = ""
    active_state: str = ""
    sub_state: str = ""
    unit_file_state: str = ""
    unit_file_preset: str = ""
    following: str = ""

    fragment_path: str = ""
    source_path: str = ""
    drop_in_paths: tuple[str, ...] = ()
    documentation: tuple[str, ...] = ()

    service_type: str = ""
    restart: str = ""
    exec_start: tuple[ExecCommand, ...] = ()
    exec_start_pre: tuple[ExecCommand, ...] = ()
    exec_stop: tuple[ExecCommand, ...] = ()

    main_pid: int = 0
    user: str = ""
    group: str = ""
    slice_name: str = ""

    memory_bytes: int = 0
    cpu_nsec: int = 0
    tasks: int = 0

    active_since: datetime | None = None
    state_changed: datetime | None = None
    result: str = ""
    exit_status: int = 0
    restarts: int = 0

    condition_result: str = ""
    assert_result: str = ""
    can_start: bool = True
    refuse_manual_start: bool = False

    requires: tuple[str, ...] = ()
    wants: tuple[str, ...] = ()
    after: tuple[str, ...] = ()
    before: tuple[str, ...] = ()
    wanted_by: tuple[str, ...] = ()
    required_by: tuple[str, ...] = ()
    triggered_by: tuple[str, ...] = ()
    triggers: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()

    # -- filled in by enrich.py -------------------------------------------
    package: str = ""
    package_version: str = ""
    package_summary: str = ""
    package_url: str = ""
    man_summary: str = ""
    exposure: Exposure | None = None
    boot_seconds: float = 0.0
    ports: tuple[ListeningPort, ...] = ()

    #: True for a unit of the calling user's own manager (`systemctl --user`).
    #: Everything that turns a unit into a command or a privilege judgement has
    #: to know this: `User=` is empty on a session unit because it runs as you,
    #: not because it runs as root, and a command without `--user` names the
    #: *system* unit of the same name — 36 names exist in both trees.
    user_manager: bool = False
    #: True once a package manager was asked who owns this unit's file.
    #: Without it, an empty `package` means "unknown", not "nobody".
    package_checked: bool = False
    #: Whether a preset rule actually names this unit. None when the preset
    #: files could not be read. The session manager reports "enabled" for any
    #: unit no rule mentions — systemd's built-in default, not a decision
    #: anybody made — so without this, 37 untouched session units were
    #: reported as "someone changed this".
    preset_ruled: bool | None = None

    # -- filled in by purpose.py ------------------------------------------
    purpose: Purpose = field(default_factory=Purpose)

    # -- derived -----------------------------------------------------------

    @property
    def kind(self) -> UnitKind:
        return UnitKind.of(self.id)

    @property
    def name(self) -> str:
        """The unit name without its suffix, for display."""
        return self.id.rpartition(".")[0] or self.id

    @property
    def enablement(self) -> Enablement:
        return Enablement.of(self.unit_file_state)

    @property
    def preset(self) -> Enablement:
        return Enablement.of(self.unit_file_preset)

    @property
    def exists(self) -> bool:
        return self.load_state not in ("", "not-found")

    @property
    def running(self) -> bool:
        return self.active_state == "active"

    @property
    def failed(self) -> bool:
        return self.active_state == "failed" or (
            self.result not in ("", "success") and not self.skipped)

    @property
    def skipped(self) -> bool:
        """Its ExecCondition= decided not to run it — deliberate, not a failure.

        Six of one desktop's session units end this way: GNOME's keyring
        autostart entries on a KDE login, which check the desktop and bow out.
        Reported as a failed run, they were six false alarms in red.
        """
        return self.result in SKIPPED_RESULTS

    @property
    def masked(self) -> bool:
        return self.load_state == "masked" or self.enablement in (
            Enablement.MASKED, Enablement.MASKED_RUNTIME)

    @property
    def is_alias(self) -> bool:
        """True when this name is a second name for a different unit."""
        return bool(self.names) and self.id not in self.names[:1]

    @property
    def aliases(self) -> tuple[str, ...]:
        return tuple(name for name in self.names if name != self.id)

    @property
    def template(self) -> str:
        """``getty@.service`` for ``getty@tty1.service``, else ""."""
        head, at, rest = self.id.partition("@")
        if not at or not rest:
            return ""
        suffix = self.id.rpartition(".")[2]
        return f"{head}@.{suffix}"

    @property
    def instance(self) -> str:
        """``tty1`` for ``getty@tty1.service``, else ""."""
        _, at, rest = self.id.partition("@")
        return rest.rpartition(".")[0] if at else ""

    @property
    def is_template(self) -> bool:
        """A template itself (``getty@.service``), which cannot be started."""
        return "@." in self.id

    @property
    def provenance(self) -> Provenance:
        """Where this unit file came from.

        Told apart in this order because the categories overlap: a generated
        unit also has no package, and a hand-written one in /etc is not the
        same finding as a packaged file someone deleted the package of.
        """
        path = self.fragment_path
        # Transient first, and by path as well as by state: a login session's
        # scope has a FragmentPath under .../systemd/transient even though no
        # file was ever installed, and checking the path only when there is no
        # FragmentPath classified every logged-in session as "added by hand".
        # Matched anywhere in the path because the session manager's copies
        # live under /run/user/<uid>/systemd/, not /run/systemd/.
        if self.enablement is Enablement.TRANSIENT or "/systemd/transient/" in path:
            return Provenance.TRANSIENT
        if not path:
            return Provenance.UNKNOWN
        if "/systemd/generator" in path or self.enablement is Enablement.GENERATED:
            return Provenance.GENERATED
        if self.package:
            return Provenance.PACKAGE
        if is_local_path(path):
            return Provenance.LOCAL
        # Only now is "no package claims it" a finding — and only if a package
        # manager was actually asked. On a distribution whose package manager
        # ClamGuard cannot query, every unit would otherwise be reported as
        # added by hand.
        if not self.package_checked:
            return Provenance.UNKNOWN
        return Provenance.UNPACKAGED

    @property
    def local_drop_ins(self) -> tuple[str, ...]:
        """Drop-ins someone wrote on this machine, as opposed to shipped ones.

        /etc for the system manager, the home directory for the session's —
        checking only /etc missed every `systemctl --user edit`.
        """
        return tuple(path for path in self.drop_in_paths if is_local_path(path))

    @property
    def is_unpackaged(self) -> bool:
        """No distribution package claims this unit file."""
        return self.provenance in (Provenance.LOCAL, Provenance.UNPACKAGED)

    @property
    def deviates_from_preset(self) -> bool:
        """Enabled when the distribution ships it disabled, or the reverse.

        The single most interesting bit of a unit's state: it separates "this
        machine's defaults" from "somebody decided this".
        """
        if not self.unit_file_preset or self.preset is Enablement.UNKNOWN:
            return False
        if self.preset_ruled is False:
            return False
        if self.enablement in (Enablement.STATIC, Enablement.GENERATED,
                               Enablement.TRANSIENT, Enablement.ALIAS,
                               Enablement.INDIRECT):
            return False
        return self.enablement.starts_itself != self.preset.starts_itself

    @property
    def idle_timer_target(self) -> bool:
        """A service that exists only to be run by a timer or socket."""
        return bool(self.triggered_by)

    def state_summary(self) -> str:
        """One short line for a badge."""
        if not self.exists:
            return "Not found"
        if self.masked:
            return "Masked"
        if self.active_state == "failed":
            return f"Failed (exit {self.exit_status})" if self.exit_status else "Failed"
        if self.active_state == "active":
            return self.sub_state.capitalize() or "Active"
        if self.active_state in ("activating", "deactivating", "reloading"):
            return self.active_state.capitalize()
        if self.sub_state == "dead" and self.result == "success" and self.restarts == 0:
            return "Inactive"
        return self.active_state.capitalize() or "Inactive"

    def tone(self) -> str:
        """Badge colour: ok / warn / danger / neutral."""
        if not self.exists:
            return "neutral"
        if self.active_state == "failed":
            return "danger"
        if self.masked:
            return "warn"
        if self.running:
            return "ok"
        return "neutral"

    @property
    def runs_as_root(self) -> bool:
        """Does this unit's process run as root?

        An empty ``User=`` means root for the system manager and *the calling
        user* for a session unit, which is why this cannot just read the field.
        """
        if self.user_manager:
            return False
        return self.user in ("", "root")

    def systemctl_command(self, action: str) -> str:
        """The command a person would type to do this themselves.

        ClamGuard does not run these. The privileged helper controls only the
        ClamAV units and refuses everything else, and a browser is not a
        reason to widen that.

        Two things this gets right that a plain f-string did not. A session
        unit needs ``--user`` and must *not* get ``sudo`` — without the flag,
        copying "restart dbus-broker.service" off the session list would have
        restarted the system message bus. And reading needs no privilege, so
        `status` and `cat` are never prefixed with `sudo` either.
        """
        scope = "--user " if self.user_manager else ""
        needs_root = not self.user_manager and action not in READ_ONLY_VERBS
        return f"{'sudo ' if needs_root else ''}systemctl {scope}{action} {self.id}"

    def journal_command(self, lines: int = 100) -> str:
        """The journalctl line for this unit's own log."""
        selector = "--user-unit" if self.user_manager else "-u"
        return f"journalctl {selector} {self.id} -n {lines} --no-pager"


@dataclass(slots=True)
class Inventory:
    """Every unit on the machine, with the indexes the UI needs.

    Reverse dependencies are *not* computed here. systemd already maintains
    them: ``RequiredBy`` and ``WantedBy`` on a unit are real reverse edges, not
    merely what its ``[Install]`` section declared — ``dbus.socket`` reports a
    dozen services under ``RequiredBy``. Inverting the forward edges ourselves
    would be a second source of truth with nothing to add.
    """

    units: tuple[Unit, ...] = ()
    #: Every alias name pointing at the canonical id it resolves to.
    aliases: dict[str, str] = field(default_factory=dict)
    #: Anything that went wrong while collecting, shown rather than swallowed.
    problems: tuple[str, ...] = ()
    #: How long the collection took, in seconds.
    elapsed: float = 0.0
    #: id -> unit. A real field because the class uses __slots__.
    by_id: dict[str, Unit] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Rebuilt rather than required from the caller, so an Inventory is
        # always internally consistent however it was constructed.
        self.by_id = {unit.id: unit for unit in self.units}

    def get(self, name: str) -> Unit | None:
        """A unit by id or by any of its aliases."""
        unit = self.by_id.get(name)
        if unit is not None:
            return unit
        target = self.aliases.get(name)
        return self.by_id.get(target) if target else None

    def __len__(self) -> int:
        return len(self.units)

    def __iter__(self):
        return iter(self.units)

    def of_kind(self, kind: UnitKind) -> list[Unit]:
        return [unit for unit in self.units if unit.kind is kind]

    def failed(self) -> list[Unit]:
        return [unit for unit in self.units if unit.active_state == "failed"]

    def running(self) -> list[Unit]:
        return [unit for unit in self.units if unit.running]

    def counts(self) -> dict[str, int]:
        """The summary strip at the top of the page."""
        return {
            "total": len(self.units),
            "running": sum(1 for unit in self.units if unit.running),
            "failed": sum(1 for unit in self.units if unit.active_state == "failed"),
            "enabled": sum(1 for unit in self.units if unit.enablement.starts_itself),
            "masked": sum(1 for unit in self.units if unit.masked),
            "unpackaged": sum(1 for unit in self.units if unit.is_unpackaged),
        }


#: Where an administrator's own unit files live. Packages ship to /usr/lib (or
#: /lib); anything here was put there by a person.
LOCAL_UNIT_PREFIXES = ("/etc/systemd/", "/usr/local/")


def _in_home(path: str) -> bool:
    """A unit file somewhere in a home directory — ~/.config/systemd/user and
    friends — which only its owner can have written."""
    from pathlib import Path

    try:
        home = str(Path.home())
    except RuntimeError:
        home = ""
    return bool(home) and (path == home or path.startswith(home.rstrip("/") + "/"))


def is_local_path(path: str) -> bool:
    """A unit file or drop-in an administrator or user wrote, not a package."""
    return path.startswith(LOCAL_UNIT_PREFIXES) or _in_home(path)


def man_command(entry: str) -> str:
    """``man:clamd.conf(5)`` -> ``man 5 clamd.conf``.

    The section goes *first*. ``man clamd.conf 5`` — the obvious rewrite of the
    Documentation= form, and what an earlier version produced — asks for two
    pages, the second one called "5", and fails with "No manual entry for 5".
    """
    page = entry[4:] if entry.startswith("man:") else entry
    name, bracket, rest = page.partition("(")
    section = rest.rstrip(")") if bracket else ""
    return f"man {section} {name}" if section else f"man {name}"


def clean(value: str) -> str:
    """systemd's several spellings of "nothing", collapsed to ""."""
    stripped = (value or "").strip()
    return "" if stripped in EMPTY_VALUES else stripped


def as_int(value: str) -> int:
    """A systemd numeric property, which may be absent or "infinity"."""
    stripped = (value or "").strip()
    if not stripped or stripped in ("[not set]", "infinity", "n/a"):
        return 0
    try:
        return int(stripped)
    except ValueError:
        return 0


def as_bool(value: str) -> bool:
    return (value or "").strip() == "yes"


def as_list(value: str) -> tuple[str, ...]:
    """A space-separated systemd list property, with systemd's quoting undone.

    `systemctl show` shell-quotes any entry that needs it — every unit name
    with an escaped character, which is most mounts and devices:

        After=-.slice "blockdev@dev-disk-by\\x2duuid-1d5d….target"

    Splitting on whitespace kept the quotes and the doubled backslash, so on
    one desktop 87 dependency edges named units that do not exist and 98 units
    listed their own name as an alias of themselves. The quoting is POSIX
    double-quote quoting, which is exactly what shlex undoes.
    """
    text = (value or "").strip()
    if not text:
        return ()
    if '"' not in text and "'" not in text:
        return tuple(text.split())
    try:
        return tuple(part for part in shlex.split(text) if part)
    except ValueError:
        # Unbalanced quoting would be a systemd bug, but a malformed property
        # must degrade to the old behaviour rather than lose the whole unit.
        return tuple(text.split())


def human_bytes(count: int) -> str:
    if count <= 0:
        return "—"
    size = float(count)
    for suffix in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or suffix == "TB":
            return f"{size:.0f} {suffix}" if suffix == "B" else f"{size:.1f} {suffix}"
        size /= 1024
    return f"{size:.1f} TB"


def human_duration(seconds: float) -> str:
    if seconds <= 0:
        return "—"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, rest = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {rest}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"
