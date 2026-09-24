"""Reading every unit off the machine, in as few forks as possible.

The shape of this module is dictated by one measurement: ``systemctl show``
with 460 unit names and 35 properties takes **one second**. The same
information gathered one unit at a time takes 460 forks and a frozen window.
So there is exactly one batch call. Reverse dependencies come back in it
too: ``RequiredBy`` and ``WantedBy`` are real reverse edges, not merely what
an ``[Install]`` section declared.

Three traps live here, all found by probing a real system rather than by
reading documentation:

``--`` before the unit names
    ``-.mount`` is the root filesystem's unit. Without a ``--`` separator
    ``systemctl`` reads it as a malformed option and the whole batch fails.

Aliases resolve on the way in
    Asking about ``dbus.service`` returns a record whose ``Id`` is
    ``dbus-broker.service``. Units are therefore keyed on ``Id``, and
    ``Names`` builds the alias index.

Templates cannot be shown
    86 of this machine's 546 unit *files* are templates (``getty@.service``)
    and have no state at all. Their instances (``getty@tty1.service``) exist
    only in ``list-units``. Both listings are needed to see everything.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime

from ..logging_setup import get_logger
from ..process import run, which
from .model import (
    ExecCommand,
    Inventory,
    Unit,
    as_bool,
    as_int,
    as_list,
    clean,
)

log = get_logger(__name__)

#: Everything worth asking for in the one batch call. Adding a property here
#: costs nothing measurable; adding a second call costs a second.
PROPERTIES = (
    "Id", "Names", "Description", "Following",
    "LoadState", "LoadError", "ActiveState", "SubState",
    "UnitFileState", "UnitFilePreset",
    "FragmentPath", "SourcePath", "DropInPaths", "Documentation",
    "Type", "Restart", "ExecStart", "ExecStartPre", "ExecStop",
    "MainPID", "User", "Group", "Slice",
    "MemoryCurrent", "CPUUsageNSec", "TasksCurrent",
    "ActiveEnterTimestamp", "StateChangeTimestamp",
    "Result", "ExecMainStatus", "NRestarts",
    "ConditionResult", "AssertResult", "CanStart", "RefuseManualStart",
    "Requires", "Wants", "After", "Before",
    "WantedBy", "RequiredBy", "TriggeredBy", "Triggers", "Conflicts",
)

#: `systemctl show` accepts a lot of names, but ARG_MAX is a real ceiling on
#: some systems and the saving past a few hundred is nil. Chunk conservatively.
CHUNK = 350

TIMEOUT = 60.0

#: ``ExecStart`` is a struct, not a string:
#:     { path=/usr/sbin/clamonacc ; argv[]=/usr/sbin/clamonacc -F ; ignore_errors=no ; ... }
#: and argv[] routinely contains bare semicolons, as in
#:     argv[]=/bin/bash -c while [ ! -S /run/clamav/clamd.ctl ]; do sleep 1; done
#: so it cannot be split on ';'. It is bounded instead by the fixed
#: ``ignore_errors=`` field that always follows it.
_EXEC = re.compile(
    r"\{\s*path=(?P<path>.*?)\s*;\s*argv\[\]=(?P<argv>.*?)\s*;\s*"
    r"ignore_errors=(?P<ignore>yes|no)",
    re.DOTALL,
)

#: Documentation= is a space-separated list whose entries may be quoted.
_DOC = re.compile(r'"([^"]*)"|(\S+)')


def available() -> bool:
    return which("systemctl") is not None


def collect(*, user: bool = False) -> Inventory:
    """Every unit this machine knows about, with its state.

    `user` reads the calling user's own unit tree (``systemctl --user``)
    instead of the system one. On a desktop that is another two hundred units
    and most of the session.
    """
    started = time.monotonic()
    systemctl = which("systemctl")
    if systemctl is None:
        return Inventory(problems=("systemctl is not on this machine, so there "
                                   "are no units to show.",))

    problems: list[str] = []
    names, listing_problems = _roster(systemctl, user=user)
    problems.extend(listing_problems)
    if not names:
        return Inventory(problems=tuple(problems or ["systemctl listed no units."]),
                         elapsed=time.monotonic() - started)

    records: list[dict[str, str]] = []
    for chunk in _chunks(sorted(names), CHUNK):
        result = run(systemctl, _show_arguments(chunk, user=user), timeout=TIMEOUT)
        if not result.ok and not result.stdout:
            problems.append(f"systemctl show failed: {result.output[:160]}")
            continue
        records.extend(parse_show_output(result.stdout))

    units = [build_unit(record) for record in records]
    for unit in units:
        unit.user_manager = user
    # A template has no state of its own, and systemd returns a near-empty
    # record for one. Keeping it would put 86 permanently-inactive rows in the
    # list that no amount of clicking explains.
    units = [unit for unit in units if not unit.is_template]
    units = _deduplicate(units)
    units.sort(key=lambda unit: unit.id)

    inventory = Inventory(
        units=tuple(units),
        aliases=_alias_index(units),
        elapsed=time.monotonic() - started,
        problems=tuple(problems),
    )
    log.info("units: %d collected in %.2fs%s", len(units), inventory.elapsed,
             " (user)" if user else "")
    return inventory


# ---------------------------------------------------------------------------
# The two listings
# ---------------------------------------------------------------------------


def _roster(systemctl: str, *, user: bool) -> tuple[set[str], list[str]]:
    """Unit names from both listings.

    ``list-unit-files`` knows about units that have never been loaded;
    ``list-units`` knows about loaded ones, which is the only place template
    *instances* appear. Neither is a superset of the other.
    """
    problems: list[str] = []
    names: set[str] = set()

    scope = ["--user"] if user else []

    files = run(systemctl, [*scope, "list-unit-files", "--no-legend", "--no-pager"],
                timeout=TIMEOUT)
    if files.ok:
        for line in files.lines():
            parts = line.split()
            if parts and "." in parts[0]:
                names.add(parts[0])
    else:
        problems.append(f"systemctl list-unit-files failed: {files.output[:160]}")

    loaded = run(systemctl,
                 [*scope, "list-units", "--all", "--output=json", "--no-pager"],
                 timeout=TIMEOUT)
    if loaded.ok:
        names.update(_loaded_names(loaded.stdout, problems))
    else:
        problems.append(f"systemctl list-units failed: {loaded.output[:160]}")

    # A template cannot be shown and has no state; asking about one wastes a
    # slot in the batch and returns a record we would throw away anyway.
    return {name for name in names if "@." not in name}, problems


def _loaded_names(text: str, problems: list[str]) -> set[str]:
    """Unit names out of ``list-units --output=json``.

    Older systemd has no JSON output at all. Rather than parse the columnar
    form — which is localised and has a ``●`` in column one — treat the
    absence as "this listing contributed nothing" and carry on with the other.
    """
    try:
        rows = json.loads(text or "[]")
    except (ValueError, TypeError):
        problems.append("systemctl list-units did not return usable JSON; "
                        "template instances may be missing from this list.")
        return set()
    found = set()
    for row in rows if isinstance(rows, list) else ():
        name = (row or {}).get("unit", "") if isinstance(row, dict) else ""
        if name and "." in name:
            found.add(name)
    return found


def _show_arguments(names: list[str], *, user: bool) -> list[str]:
    """``show`` arguments, with the separator that ``-.mount`` requires."""
    scope = ["--user"] if user else []
    return [*scope, "show", "--no-pager",
            f"--property={','.join(PROPERTIES)}", "--", *names]


def _chunks(items: list[str], size: int):
    for start in range(0, len(items), size):
        yield items[start:start + size]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_show_output(text: str) -> list[dict[str, str]]:
    """Split ``systemctl show`` output into one dictionary per unit.

    Records are separated by a blank line. Values may themselves contain
    newlines (a ``Documentation=`` with an embedded one, say), so a line
    without an ``=`` is appended to the previous key rather than dropped.
    """
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key = ""

    for line in (text or "").splitlines():
        if not line.strip():
            if current:
                records.append(current)
                current, last_key = {}, ""
            continue
        key, separator, value = line.partition("=")
        if separator and key and not key[0].isspace():
            current[key] = value
            last_key = key
        elif last_key:
            current[last_key] += "\n" + line

    if current:
        records.append(current)
    return records


def parse_exec(value: str) -> tuple[ExecCommand, ...]:
    """Unpack one or more ``{ path=… ; argv[]=… ; … }`` structs."""
    commands = []
    for match in _EXEC.finditer(value or ""):
        argv = tuple(part for part in match.group("argv").split(" ") if part)
        commands.append(ExecCommand(
            path=match.group("path").strip(),
            argv=argv,
            ignore_errors=match.group("ignore") == "yes",
        ))
    return tuple(commands)


def parse_documentation(value: str) -> tuple[str, ...]:
    """``"man:clamonacc(8)" "man:clamd.conf(5)" https://docs.clamav.net/``."""
    found = []
    for quoted, bare in _DOC.findall(value or ""):
        entry = quoted or bare
        if entry:
            found.append(entry)
    return tuple(found)


def parse_timestamp(value: str) -> datetime | None:
    """systemd prints ``Mon 2026-09-21 12:42:56 CEST``.

    The zone name is dropped rather than resolved: it is the machine's own
    local zone in every case we display, and pulling in a zone database to
    re-derive what ``datetime.now()`` already uses would buy nothing.
    """
    text = clean(value)
    if not text:
        return None
    parts = text.split()
    if len(parts) < 3:
        return None
    try:
        return datetime.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def build_unit(fields: dict[str, str]) -> Unit:
    """One parsed record into a :class:`~.model.Unit`."""
    identifier = clean(fields.get("Id", ""))
    names = as_list(fields.get("Names", ""))
    if not identifier:
        identifier = names[0] if names else "?"

    return Unit(
        id=identifier,
        names=names,
        description=clean(fields.get("Description", "")),
        following=clean(fields.get("Following", "")),

        load_state=clean(fields.get("LoadState", "")),
        load_error=_load_error(fields.get("LoadError", "")),
        active_state=clean(fields.get("ActiveState", "")),
        sub_state=clean(fields.get("SubState", "")),
        unit_file_state=clean(fields.get("UnitFileState", "")),
        unit_file_preset=clean(fields.get("UnitFilePreset", "")),

        fragment_path=clean(fields.get("FragmentPath", "")),
        source_path=clean(fields.get("SourcePath", "")),
        drop_in_paths=as_list(fields.get("DropInPaths", "")),
        documentation=parse_documentation(fields.get("Documentation", "")),

        service_type=clean(fields.get("Type", "")),
        restart=clean(fields.get("Restart", "")),
        exec_start=parse_exec(fields.get("ExecStart", "")),
        exec_start_pre=parse_exec(fields.get("ExecStartPre", "")),
        exec_stop=parse_exec(fields.get("ExecStop", "")),

        main_pid=as_int(fields.get("MainPID", "")),
        user=clean(fields.get("User", "")),
        group=clean(fields.get("Group", "")),
        slice_name=clean(fields.get("Slice", "")),

        memory_bytes=as_int(fields.get("MemoryCurrent", "")),
        cpu_nsec=as_int(fields.get("CPUUsageNSec", "")),
        tasks=as_int(fields.get("TasksCurrent", "")),

        active_since=parse_timestamp(fields.get("ActiveEnterTimestamp", "")),
        state_changed=parse_timestamp(fields.get("StateChangeTimestamp", "")),
        result=clean(fields.get("Result", "")),
        exit_status=as_int(fields.get("ExecMainStatus", "")),
        restarts=as_int(fields.get("NRestarts", "")),

        condition_result=clean(fields.get("ConditionResult", "")),
        assert_result=clean(fields.get("AssertResult", "")),
        can_start=as_bool(fields.get("CanStart", "yes")),
        refuse_manual_start=as_bool(fields.get("RefuseManualStart", "")),

        requires=as_list(fields.get("Requires", "")),
        wants=as_list(fields.get("Wants", "")),
        after=as_list(fields.get("After", "")),
        before=as_list(fields.get("Before", "")),
        wanted_by=as_list(fields.get("WantedBy", "")),
        required_by=as_list(fields.get("RequiredBy", "")),
        triggered_by=as_list(fields.get("TriggeredBy", "")),
        triggers=as_list(fields.get("Triggers", "")),
        conflicts=as_list(fields.get("Conflicts", "")),
    )


def _load_error(value: str) -> str:
    """``org.freedesktop.systemd1.NoSuchUnit "Unit x.service not found."``

    Only the human half is worth showing.
    """
    text = clean(value)
    if not text:
        return ""
    _, quote, rest = text.partition('"')
    return rest.rstrip('"').strip() if quote else text


# ---------------------------------------------------------------------------
# Indexes built from what we already have
# ---------------------------------------------------------------------------


def _deduplicate(units: list[Unit]) -> list[Unit]:
    """One entry per unit, however many names reached it.

    A unit with an alias is in the roster under both names, and `systemctl
    show` answers both — with the *same* ``Id`` each time, because asking about
    an alias resolves it. Without this,
    ``dbus-org.freedesktop.nm-dispatcher.service`` and
    ``NetworkManager-dispatcher.service`` put two identical rows in the list.
    """
    seen: dict[str, Unit] = {}
    for unit in units:
        seen.setdefault(unit.id, unit)
    return list(seen.values())


def _alias_index(units: list[Unit]) -> dict[str, str]:
    """Every alternative name, pointing at the id it resolves to."""
    index: dict[str, str] = {}
    for unit in units:
        for name in unit.names:
            if name != unit.id:
                index[name] = unit.id
    return index


# Reverse dependencies deliberately have no code here. `RequiredBy` and
# `WantedBy` come back from `systemctl show` as real reverse edges — probed on
# a live system, `dbus.socket` reports a dozen services under `RequiredBy` —
# so inverting the forward edges ourselves would add a second source of truth
# and no information. `systemctl list-dependencies --reverse` would be a fork
# per unit for the same answer.
