"""Everything systemd does not know about its own units.

systemd can tell you a unit is running. It cannot tell you which package put
it there, what the man page says it does, how much of your boot it cost, or
what ports it is listening on. Those answers come from five other programs,
all of them optional and all of them cheap:

=========================  ======  =================================
``pacman -Qo`` / ``dpkg -S``  0.13 s  which package owns the unit file
``pacman -Qi`` / ``dpkg-query``  0.32 s  that package's own description
``whatis``                   ~0 s    the man page's one-line summary
``systemd-analyze security`` 0.16 s  how well sandboxed the unit is
``systemd-analyze blame``    0.36 s  what it cost at boot
``ss -lntupH``               0.03 s  the ports it holds open
=========================  ======  =================================

Every one of them may be missing. A missing tool removes a row from the detail
pane and nothing else — there is no path through this module that raises.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from ..logging_setup import get_logger
from ..process import run, which
from .model import Exposure, Inventory, ListeningPort, Unit

log = get_logger(__name__)

TIMEOUT = 30.0

#: `pacman -Qo` prints one of these per path it recognises.
_OWNED = re.compile(r"^(?P<path>.+?) is owned by (?P<package>\S+) (?P<version>\S+)$")

#: `dpkg -S` prints "package: /path" — and "pkg1, pkg2: /path" when shared.
_DPKG = re.compile(r"^(?P<packages>[^:]+):\s+(?P<path>/.+)$")

#: `systemd-analyze security` is a table: unit, score, rating, and an emoticon.
_SECURITY = re.compile(r"^(?P<unit>\S+\.\w+)\s+(?P<score>\d+\.\d+)\s+(?P<rating>[A-Z]+)")

#: `systemd-analyze blame` is "24.447s unit.service", and the time may carry
#: minutes ("1min 4.552s") or milliseconds ("812ms").
_BLAME = re.compile(r"^\s*(?P<time>\S+(?:\s+\S+)?)\s+(?P<unit>\S+\.\w+)\s*$")
_DURATION = re.compile(r"(?:(?P<min>\d+)min\s*)?(?:(?P<sec>[\d.]+)s)?(?:(?P<ms>\d+)ms)?")

#: `ss -lntupH`: proto, state, recvq, sendq, local, peer, then users:(("name",pid=N,...))
_SS_PID = re.compile(r"pid=(?P<pid>\d+)")

#: `man:clamonacc(8)` -> clamonacc
_MAN_DOC = re.compile(r"^man:(?P<page>[^(]+)(?:\((?P<section>[^)]*)\))?$")

#: `whatis` prints "clamonacc (8) - an anti-virus on-access scanning daemon".
_WHATIS = re.compile(r"^(?P<name>\S+)\s*\([^)]*\)\s*-\s*(?P<summary>.+)$")


@dataclass(slots=True)
class Package:
    """One installed package, as far as we care."""

    name: str = ""
    version: str = ""
    summary: str = ""
    url: str = ""


@dataclass(slots=True)
class Enrichment:
    """The lookup tables, kept so the UI can show what was and was not found."""

    #: unit file path -> package name
    owners: dict[str, str] = field(default_factory=dict)
    #: package name -> its description
    packages: dict[str, Package] = field(default_factory=dict)
    #: man page name -> its one-line summary
    manuals: dict[str, str] = field(default_factory=dict)
    #: unit id -> sandboxing score
    exposure: dict[str, Exposure] = field(default_factory=dict)
    #: unit id -> seconds spent during boot
    boot: dict[str, float] = field(default_factory=dict)
    #: pid -> the sockets it is listening on
    ports: dict[int, tuple[ListeningPort, ...]] = field(default_factory=dict)
    #: Tools that were not available, so the UI can say why a row is missing.
    missing: tuple[str, ...] = ()
    #: Which package manager answered: "pacman", "dpkg", "rpm", or "" for none.
    #: An empty `Unit.package` only means "no package owns this" when this is set.
    package_manager: str = ""


def enrich(inventory: Inventory, *, user: bool = False) -> Enrichment:
    """Gather everything else and write it onto the units, in place.

    Returns the tables as well, because the page shows "no package manager
    found" rather than silently omitting the provenance row.

    `user` must match the scope the inventory was read from. Sandboxing scores
    and boot times are per *manager*, and 36 unit names on an ordinary desktop
    exist in both trees — `dbus-broker.service`, `dbus.socket` — so asking the
    system manager about a user inventory hands the session's units the system
    units' numbers, matched by name and silently wrong.
    """
    missing: list[str] = []
    found = Enrichment()

    paths = sorted({unit.fragment_path for unit in inventory if unit.fragment_path})
    found.owners, found.package_manager = _owners(paths, missing)
    found.packages = _package_details(sorted(set(found.owners.values())), missing)
    found.exposure = _exposure(missing, user=user)
    found.boot = _boot_times(missing, user=user)
    found.ports = _listening_ports(missing)
    found.manuals = _manuals(inventory, missing)
    found.missing = tuple(missing)
    patterns = preset_patterns(user=user)

    for unit in inventory:
        _apply(unit, found)
        if patterns is not None:
            unit.preset_ruled = _preset_names(unit, patterns)
    return found


def _apply(unit: Unit, found: Enrichment) -> None:
    package_name = found.owners.get(unit.fragment_path, "")
    unit.package = package_name
    unit.package_checked = bool(found.package_manager and unit.fragment_path)
    package = found.packages.get(package_name)
    if package is not None:
        unit.package_version = package.version
        unit.package_summary = package.summary
        unit.package_url = package.url

    unit.exposure = found.exposure.get(unit.id)
    unit.boot_seconds = found.boot.get(unit.id, 0.0)
    if unit.main_pid:
        unit.ports = found.ports.get(unit.main_pid, ())

    for page in _man_pages(unit):
        summary = found.manuals.get(page)
        if summary:
            unit.man_summary = summary
            break


# ---------------------------------------------------------------------------
# Preset rules
# ---------------------------------------------------------------------------

#: Where preset files live, most important first. A file in an earlier
#: directory hides one of the same name in a later one, as systemd does it.
SYSTEM_PRESET_DIRS = ("/etc/systemd/system-preset", "/run/systemd/system-preset",
                      "/usr/local/lib/systemd/system-preset",
                      "/usr/lib/systemd/system-preset")
USER_PRESET_DIRS = ("/etc/systemd/user-preset", "/run/systemd/user-preset",
                    "/usr/local/lib/systemd/user-preset", "/usr/lib/systemd/user-preset")


def preset_patterns(*, user: bool = False,
                    directories: tuple[str, ...] | None = None) -> list[str] | None:
    """Every unit pattern a preset rule names, or None if none could be read.

    Only *whether* a rule names a unit matters here, not what it says:
    systemd's own answer is already in UnitFilePreset. What systemd does not
    say is that "enabled" for a session unit is usually no rule at all — its
    built-in default — while Arch's system presets end in an explicit
    `disable *`. The first is nobody's decision; the second is the
    distribution's, and deviating from it is worth pointing out.
    """
    from pathlib import Path

    if directories is None:
        directories = USER_PRESET_DIRS if user else SYSTEM_PRESET_DIRS
        if user:
            config = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
            directories = (str(Path(config) / "systemd" / "user-preset"), *directories)
    chosen: dict[str, Path] = {}
    readable = False
    for directory in directories:
        folder = Path(directory)
        try:
            entries = sorted(folder.glob("*.preset"))
        except OSError:
            continue
        readable = readable or folder.is_dir()
        for entry in entries:
            chosen.setdefault(entry.name, entry)
    if not readable:
        return None
    patterns: list[str] = []
    for name in sorted(chosen):
        try:
            text = chosen[name].read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue          # a file masked with /dev/null reads as empty anyway
        for line in text.splitlines():
            words = line.split()
            if len(words) >= 2 and words[0] in ("enable", "disable", "ignore"):
                patterns.append(words[1])
    return patterns


def _preset_names(unit: Unit, patterns: list[str]) -> bool:
    import fnmatch

    names = [unit.id, *unit.aliases]
    if unit.template:
        names.append(unit.template)
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns for name in names)


# ---------------------------------------------------------------------------
# Package ownership
# ---------------------------------------------------------------------------


def _owners(paths: list[str], missing: list[str]) -> tuple[dict[str, str], str]:
    """Map every unit file to the package that shipped it.

    A path *absent* from the result is as interesting as one present: it means
    no package claims the file, which is either a hand-written unit in
    /etc/systemd/system or something generated at boot.
    """
    if not paths:
        return {}, ""
    if which("pacman"):
        return _pacman_owners(paths), "pacman"
    if which("dpkg"):
        return _dpkg_owners(paths), "dpkg"
    if which("rpm"):
        return _rpm_owners(paths), "rpm"
    missing.append("No package manager ClamGuard can ask was found (pacman, "
                   "dpkg or rpm), so unit files are not traced back to a "
                   "package — and none is called hand-written for lack of one.")
    return {}, ""


def _pacman_owners(paths: list[str]) -> dict[str, str]:
    # Exits non-zero when *any* path is unowned, which is normal and not an
    # error — the owned ones are still on stdout.
    result = run("pacman", ["-Qo", *paths], timeout=TIMEOUT)
    owners: dict[str, str] = {}
    for line in result.lines():
        match = _OWNED.match(line.strip())
        if match:
            owners[match.group("path")] = match.group("package")
    return owners


def _dpkg_owners(paths: list[str]) -> dict[str, str]:
    """dpkg, asked under both spellings of a merged-/usr path.

    After Debian's /usr merge, systemd reports ``/usr/lib/systemd/system/x``
    while dpkg's database often still records ``/lib/systemd/system/x`` — and
    ``dpkg -S`` does not resolve the alias. Asking only for the reported path
    would make every unit on the machine look hand-written.
    """
    wanted = set(paths)
    alias_of: dict[str, str] = {}
    for path in paths:
        alias = _merged_usr_alias(path)
        if alias and alias not in wanted:
            alias_of[alias] = path
    result = run("dpkg", ["-S", *sorted(wanted | set(alias_of))], timeout=TIMEOUT)
    owners: dict[str, str] = {}
    for line in result.lines():
        text = line.strip()
        # "diversion by foo from: /path" and "diversion by foo to: /path" are
        # dpkg describing a diversion, not naming an owner.
        if text.startswith("diversion by "):
            continue
        match = _DPKG.match(text)
        if match:
            reported = match.group("path")
            target = reported if reported in wanted else alias_of.get(reported, reported)
            # "pkg1, pkg2: /path" when several packages ship it; the first is
            # the one a person means.
            owners.setdefault(target, match.group("packages").split(",")[0].strip())
    return owners


def _merged_usr_alias(path: str) -> str:
    """``/usr/lib/x`` <-> ``/lib/x``, the two names of one file after the merge."""
    if path.startswith("/usr/lib/"):
        return path[len("/usr"):]
    if path.startswith("/lib/"):
        return "/usr" + path
    return ""


def _rpm_owners(paths: list[str]) -> dict[str, str]:
    owners: dict[str, str] = {}
    # rpm -qf takes many paths but prints only the package per line, with no
    # path to match it against, so the association is positional.
    result = run("rpm", ["-qf", "--qf", "%{NAME}\n", *paths], timeout=TIMEOUT)
    lines = result.stdout.splitlines()
    for path, line in zip(paths, lines):
        name = line.strip()
        if name and "not owned by" not in name and not name.startswith("error"):
            owners[path] = name
    return owners


def _package_details(names: list[str], missing: list[str]) -> dict[str, Package]:
    """The description and homepage of each owning package.

    This is the single most human answer to "what is this for" — a
    distribution maintainer wrote it for exactly that purpose, and it is
    almost always better than the unit's own ``Description=``.
    """
    if not names:
        return {}
    if which("pacman"):
        return _pacman_details(names)
    if which("dpkg-query"):
        return _dpkg_details(names)
    if which("rpm"):
        return _rpm_details(names)
    return {}


def _pacman_details(names: list[str]) -> dict[str, Package]:
    result = run("pacman", ["-Qi", *names], timeout=TIMEOUT)
    packages: dict[str, Package] = {}
    for block in result.stdout.split("\n\n"):
        fields = _colon_fields(block)
        name = fields.get("Name", "")
        if name:
            packages[name] = Package(name=name,
                                     version=fields.get("Version", ""),
                                     summary=fields.get("Description", ""),
                                     url=fields.get("URL", ""))
    return packages


def _dpkg_details(names: list[str]) -> dict[str, Package]:
    result = run("dpkg-query",
                 ["-W", "-f=${Package}\t${Version}\t${Homepage}\t${binary:Summary}\n",
                  *names], timeout=TIMEOUT)
    packages: dict[str, Package] = {}
    for line in result.lines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0]:
            packages[parts[0]] = Package(name=parts[0], version=parts[1],
                                         url=parts[2], summary=parts[3])
    return packages


def _rpm_details(names: list[str]) -> dict[str, Package]:
    result = run("rpm", ["-q", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{URL}\t%{SUMMARY}\n",
                         *names], timeout=TIMEOUT)
    packages: dict[str, Package] = {}
    for line in result.lines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0]:
            packages[parts[0]] = Package(name=parts[0], version=parts[1],
                                         url=parts[2], summary=parts[3])
    return packages


def _colon_fields(block: str) -> dict[str, str]:
    """``Name            : clamav`` blocks, as printed by pacman -Qi."""
    fields: dict[str, str] = {}
    key = ""
    for line in block.splitlines():
        if line.startswith(" ") and key:
            fields[key] += " " + line.strip()
            continue
        name, separator, value = line.partition(":")
        if separator:
            key = name.strip()
            fields[key] = value.strip()
    return fields


# ---------------------------------------------------------------------------
# Man pages
# ---------------------------------------------------------------------------


def _man_pages(unit: Unit) -> list[str]:
    """Candidate man page names for a unit, best first.

    ``Documentation=man:clamonacc(8)`` is authoritative when it is there. When
    it is not, the binary's own name is the next best guess — `sshd.service`
    runs `/usr/bin/sshd`, and `man sshd` is what a person would try.
    """
    pages: list[str] = []
    for entry in unit.documentation:
        match = _MAN_DOC.match(entry)
        if match:
            page = match.group("page").strip()
            if page:
                pages.append(page)
    for command in unit.exec_start:
        program = command.program.rpartition("/")[2]
        if program and program not in pages:
            pages.append(program)
    name = unit.name.partition("@")[0]
    if name and name not in pages:
        pages.append(name)
    return pages


def _manuals(inventory: Inventory, missing: list[str]) -> dict[str, str]:
    """One `whatis` call for every candidate page on the machine."""
    if not which("whatis"):
        missing.append("`whatis` is not available, so man page summaries are "
                       "not shown. It comes with man-db.")
        return {}

    wanted = sorted({page for unit in inventory for page in _man_pages(unit)})
    if not wanted:
        return {}

    manuals: dict[str, str] = {}
    # whatis exits non-zero when *any* name is unknown, which is the common
    # case, so the return code is ignored and stdout is read regardless.
    for batch in (wanted[i:i + 200] for i in range(0, len(wanted), 200)):
        result = run("whatis", batch, timeout=TIMEOUT)
        for line in result.stdout.splitlines():
            match = _WHATIS.match(line.strip())
            if match:
                manuals.setdefault(match.group("name"), match.group("summary").strip())
    return manuals


# ---------------------------------------------------------------------------
# systemd-analyze
# ---------------------------------------------------------------------------


def _exposure(missing: list[str], *, user: bool = False) -> dict[str, Exposure]:
    if not which("systemd-analyze"):
        missing.append("`systemd-analyze` is not available, so sandboxing "
                       "scores and boot times are not shown.")
        return {}
    scope = ["--user"] if user else []
    result = run("systemd-analyze", [*scope, "security", "--no-pager"], timeout=TIMEOUT)
    scores: dict[str, Exposure] = {}
    for line in result.stdout.splitlines():
        match = _SECURITY.match(line.strip())
        if match:
            scores[match.group("unit")] = Exposure(
                unit=match.group("unit"),
                score=float(match.group("score")),
                rating=match.group("rating"),
            )
    return scores


def _boot_times(missing: list[str], *, user: bool = False) -> dict[str, float]:
    if not which("systemd-analyze"):
        return {}
    scope = ["--user"] if user else []
    result = run("systemd-analyze", [*scope, "blame", "--no-pager"], timeout=TIMEOUT)
    times: dict[str, float] = {}
    for line in result.stdout.splitlines():
        match = _BLAME.match(line.rstrip())
        if not match:
            continue
        seconds = _duration(match.group("time"))
        if seconds > 0:
            times[match.group("unit")] = seconds
    return times


def _duration(text: str) -> float:
    """``1min 4.552s``, ``24.447s`` and ``812ms`` into seconds."""
    match = _DURATION.search((text or "").replace(" ", ""))
    if not match:
        return 0.0
    total = 0.0
    if match.group("min"):
        total += int(match.group("min")) * 60
    if match.group("sec"):
        total += float(match.group("sec"))
    if match.group("ms"):
        total += int(match.group("ms")) / 1000
    return total


# ---------------------------------------------------------------------------
# Listening sockets
# ---------------------------------------------------------------------------


def _listening_ports(missing: list[str]) -> dict[int, tuple[ListeningPort, ...]]:
    """Which process is listening where, keyed by pid.

    Run as an ordinary user, `ss` still lists every listening socket but only
    attributes the ones owned by this user to a process. That is a real limit
    and the page says so rather than implying a service holds no ports.
    """
    if not which("ss"):
        missing.append("`ss` is not available, so listening ports are not "
                       "shown. It comes with iproute2.")
        return {}

    result = run("ss", ["-lntupH"], timeout=TIMEOUT)
    ports: dict[int, list[ListeningPort]] = {}
    sockets = 0
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        sockets += 1
        protocol = fields[0]
        local = fields[4]
        address, _, port = local.rpartition(":")
        for match in _SS_PID.finditer(line):
            pid = int(match.group("pid"))
            entry = ListeningPort(protocol=protocol, address=address, port=port)
            bucket = ports.setdefault(pid, [])
            if entry not in bucket:
                bucket.append(entry)

    if sockets and not ports:
        # `ss` lists every listening socket to anyone, but names the process
        # behind one only for the caller's own. Every system service runs as
        # somebody else, so unprivileged we see the sockets and can attach none
        # of them. Saying so beats an empty row implying nothing is listening.
        missing.append(
            f"{sockets} listening sockets exist, but matching them to services "
            "needs root — `ss` only names the process for your own sockets. "
            "Run `sudo ss -lntup` to see which service holds which port.")
    return {pid: tuple(entries) for pid, entries in ports.items()}
