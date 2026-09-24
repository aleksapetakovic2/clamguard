"""Everything wired to run automatically — where malware hides.

This is the part of the Boot Analyzer that earns its place inside an
antivirus. A scanner finds a malicious file; this finds the line that makes a
file run at every boot, which is the thing that turns a one-off compromise
into a permanent one.

The module has two halves. :func:`inventory` enumerates every automatic
start-up on the machine — systemd units, XDG autostart entries, cron jobs,
shell profiles, udev rules, modprobe hooks — into one list, which the Startup
surface tab displays in full. The checks then look through that same list for
the handful of shapes that have no innocent explanation.

The suspicion rules live in :mod:`.common` and are deliberately narrow. A
startup list with twenty false positives is a startup list nobody reads, and
then the one real entry goes unnoticed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterator

from ..model import Category, Evidence, Finding, Fix, Reference, Severity
from ..probe import Probe
from ..profile import Policy
from ..registry import SkipCheck, check, finding, get, passed
from .common import (
    Suspicion,
    desktop_entry_exec,
    desktop_entry_is_active,
    exec_lines,
    inspect_command,
    is_modprobe_reentry,
    listing,
    octal,
    plural,
)

#: Where a distribution's own unit files live. A unit here was written by a
#: package maintainer; one outside was written by somebody on this machine,
#: and the two deserve different amounts of suspicion.
VENDOR_PREFIXES = ("/usr/lib/systemd/", "/lib/systemd/")

SYSTEM_UNIT_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system",
                    "/lib/systemd/system", "/run/systemd/system")
USER_UNIT_DIRS = ("~/.config/systemd/user", "/usr/lib/systemd/user",
                  "/etc/systemd/user")

#: Files a login shell reads. Anything appended to one of these runs every time
#: the user opens a terminal, which is as good as a boot hook for most purposes.
SHELL_PROFILES = (
    "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/zshrc",
    "/etc/zsh/zprofile", "~/.profile", "~/.bash_profile", "~/.bashrc",
    "~/.bash_login", "~/.zshrc", "~/.zprofile", "~/.zshenv",
    "~/.config/fish/config.fish",
)

#: Directories on the default boot-time PATH.
DEFAULT_PATH_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin",
                     "/usr/bin", "/sbin", "/bin")

MITRE_PERSISTENCE = Reference("MITRE ATT&CK: boot or logon autostart execution",
                              "https://attack.mitre.org/techniques/T1547/")


@dataclass(frozen=True)
class StartupEntry:
    """One thing that runs without anybody asking it to."""

    origin: str
    name: str
    path: str
    command: str = ""
    enabled: bool = True
    suspicions: tuple[Suspicion, ...] = ()
    #: Who owns the file that defines it, when that is not root.
    owner: str = ""

    @property
    def suspicious(self) -> bool:
        """Anything at all was noticed, including the low-weight notes."""
        return bool(self.suspicions)

    @property
    def notable(self) -> bool:
        """Worth turning into a finding, rather than just listing."""
        return any(item.notable for item in self.suspicions)

    @property
    def serious(self) -> bool:
        return any(item.serious for item in self.suspicions)

    @property
    def reasons(self) -> str:
        return "; ".join(item.reason for item in self.suspicions)


@dataclass
class Inventory:
    """Everything found, grouped by where it came from."""

    entries: list[StartupEntry] = field(default_factory=list)
    #: Places that exist but could not be read, so the UI can say so.
    unreadable: list[str] = field(default_factory=list)

    def of(self, origin: str) -> list[StartupEntry]:
        return [entry for entry in self.entries if entry.origin == origin]

    def suspicious(self) -> list[StartupEntry]:
        return [entry for entry in self.entries if entry.suspicious]

    def notable(self) -> list[StartupEntry]:
        return [entry for entry in self.entries if entry.notable]

    @property
    def origins(self) -> list[str]:
        seen: list[str] = []
        for entry in self.entries:
            if entry.origin not in seen:
                seen.append(entry.origin)
        return seen


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def inventory(probe: Probe) -> Inventory:
    """Every automatic start-up on this machine, in one list.

    Cached on the probe for the duration of a run, because four checks and one
    UI tab all want it and it costs a hundred file reads.
    """
    cached = getattr(probe, "_startup_inventory", None)
    if cached is not None:
        return cached

    found = Inventory()
    home = os.path.expanduser("~")
    _collect_system_units(probe, found)
    _collect_user_units(probe, found, home)
    _collect_autostart(probe, found, home)
    _collect_cron(probe, found)
    _collect_shell_profiles(probe, found, home)
    _collect_udev(probe, found)
    _collect_modprobe(probe, found)

    setattr(probe, "_startup_inventory", found)
    return found


def _unit_path(probe: Probe, name: str, directories) -> str:
    for directory in directories:
        candidate = os.path.join(os.path.expanduser(directory), name)
        if probe.file(candidate).ok:
            return candidate
    return ""


def _collect_system_units(probe: Probe, found: Inventory) -> None:
    result = probe.run("systemctl", "list-unit-files", "--state=enabled",
                       "--no-legend", "--plain", "--no-pager")
    if not result.ok and not result.stdout:
        found.unreadable.append("systemctl list-unit-files (system)")
        return
    home = os.path.expanduser("~")
    for line in result.lines():
        fields = line.split()
        if not fields or not fields[0].endswith((".service", ".timer", ".path", ".socket")):
            continue
        name = fields[0]
        path = _unit_path(probe, name, SYSTEM_UNIT_DIRS)
        text = probe.text(path) if path else ""
        commands = exec_lines(text)
        command = commands[0][1] if commands else ""
        info = probe.stat(path) if path else None
        packaged = path.startswith(VENDOR_PREFIXES)
        found.entries.append(StartupEntry(
            origin="systemd (system)",
            name=name,
            path=path or "(unit file not found)",
            command=command,
            suspicions=tuple(inspect_command(
                command, home=home, system_scope=True,
                # A packaged unit with a bare ExecStart is upstream's choice,
                # not a finding — seatd.service ships exactly that. A unit
                # somebody added to /etc is a different matter.
                require_absolute=not packaged)) if command else (),
            owner="" if info is None or info.st_uid == 0 else str(info.st_uid),
        ))


def _collect_user_units(probe: Probe, found: Inventory, home: str) -> None:
    result = probe.run("systemctl", "--user", "list-unit-files", "--state=enabled",
                       "--no-legend", "--plain", "--no-pager")
    if not result.ok and not result.stdout:
        # No user session bus is normal when running headless; not a failure.
        return
    for line in result.lines():
        fields = line.split()
        if not fields or not fields[0].endswith((".service", ".timer", ".path", ".socket")):
            continue
        name = fields[0]
        path = _unit_path(probe, name, USER_UNIT_DIRS)
        commands = exec_lines(probe.text(path)) if path else []
        command = commands[0][1] if commands else ""
        found.entries.append(StartupEntry(
            origin="systemd (user)",
            name=name,
            path=path or "(unit file not found)",
            command=command,
            suspicions=tuple(inspect_command(command, home=home)) if command else (),
        ))


def _collect_autostart(probe: Probe, found: Inventory, home: str) -> None:
    for directory in (os.path.join(home, ".config/autostart"), "/etc/xdg/autostart"):
        if not probe.is_dir(directory):
            continue
        for path in probe.files_in(directory, ".desktop"):
            text = probe.text(path)
            command = desktop_entry_exec(text)
            found.entries.append(StartupEntry(
                origin="XDG autostart",
                name=os.path.basename(path),
                path=path,
                command=command,
                enabled=desktop_entry_is_active(text),
                suspicions=tuple(inspect_command(command, home=home)) if command else (),
            ))


def _collect_cron(probe: Probe, found: Inventory) -> None:
    files: list[str] = []
    for path in ("/etc/crontab", "/etc/anacrontab"):
        if probe.file(path).ok:
            files.append(path)
    for directory in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
                      "/etc/cron.weekly", "/etc/cron.monthly"):
        files.extend(probe.files_in(directory))

    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    for spool in (f"/var/spool/cron/crontabs/{user}", f"/var/spool/cron/{user}"):
        if user and probe.file(spool).exists:
            if probe.file(spool).ok:
                files.append(spool)
            else:
                found.unreadable.append(spool)

    for path in files:
        result = probe.file(path)
        if not result.ok:
            found.unreadable.append(path)
            continue
        if path.startswith(("/etc/cron.hourly", "/etc/cron.daily",
                            "/etc/cron.weekly", "/etc/cron.monthly")):
            # These are whole scripts, not crontab lines. Judge the script.
            found.entries.append(StartupEntry(
                origin="cron", name=os.path.basename(path), path=path,
                command=path,
                suspicions=tuple(_inspect_script(result.text)),
            ))
            continue
        system_table = not path.startswith("/var/spool/cron")
        for line in result.lines():
            command = crontab_command(line, system_table=system_table)
            if not command:
                continue
            found.entries.append(StartupEntry(
                origin="cron", name=os.path.basename(path), path=path,
                command=command,
                suspicions=tuple(inspect_command(command)),
            ))


def crontab_command(line: str, *, system_table: bool) -> str:
    """The command part of a crontab line, or "" for anything else.

    The two formats differ by one column: /etc/crontab and /etc/cron.d name
    the user to run as between the schedule and the command, while a personal
    crontab does not. Which file it came from is the only reliable way to tell
    them apart, so the caller says.
    """
    text = line.strip()
    if not text or text.startswith("#"):
        return ""
    # MAILTO=, PATH=, SHELL= and friends are settings, not jobs.
    first = text.split(None, 1)[0]
    if "=" in first and not first.startswith("@"):
        return ""

    columns = (2 if system_table else 1) if text.startswith("@") else \
        (6 if system_table else 5)
    fields = text.split(None, columns)
    if len(fields) <= columns:
        return ""
    return fields[columns].strip()


def _inspect_script(text: str) -> list[Suspicion]:
    """Look at a whole shell script rather than one command line."""
    found: list[Suspicion] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for item in inspect_command(line):
            if item.serious and item not in found:
                found.append(item)
    return found


def _collect_shell_profiles(probe: Probe, found: Inventory, home: str) -> None:
    paths = [os.path.expanduser(path) for path in SHELL_PROFILES]
    paths.extend(probe.files_in("/etc/profile.d"))
    for path in paths:
        result = probe.file(path)
        if not result.ok:
            continue
        suspicions = _inspect_script(result.text)
        if not suspicions:
            # A profile script with nothing alarming in it is not a start-up
            # entry worth listing; there are dozens and they are all boring.
            continue
        found.entries.append(StartupEntry(
            origin="shell profile",
            name=os.path.basename(path),
            path=path,
            command=_first_interesting_line(result.text),
            suspicions=tuple(suspicions),
        ))


def _first_interesting_line(text: str) -> str:
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and inspect_command(line):
            return line[:200]
    return ""


def _collect_udev(probe: Probe, found: Inventory) -> None:
    for path in probe.files_in("/etc/udev/rules.d", ".rules"):
        result = probe.file(path)
        if not result.ok:
            continue
        for line in result.lines():
            if "RUN+=" not in line and "RUN=" not in line:
                continue
            command = line.split("RUN", 1)[1].lstrip("+=").strip().strip('"')
            found.entries.append(StartupEntry(
                origin="udev rule",
                name=os.path.basename(path),
                path=path,
                command=command,
                suspicions=tuple(inspect_command(command)),
            ))


def _collect_modprobe(probe: Probe, found: Inventory) -> None:
    # Only /etc. /usr/lib/modprobe.d belongs to packages and is full of the
    # documented `install x /sbin/modprobe --ignore-install x && setup-script`
    # idiom, which is a dependency declaration rather than a boot hook.
    for directory in ("/etc/modprobe.d",):
        for path in probe.files_in(directory, ".conf"):
            result = probe.file(path)
            if not result.ok:
                continue
            for line in result.lines():
                if not line.startswith("install "):
                    continue
                fields = line.split(None, 2)
                if len(fields) < 3:
                    continue
                module, command = fields[1], fields[2]
                # `install <mod> /bin/true` is the standard way to blacklist a
                # module and is not interesting. Anything else runs a program.
                if command.strip() in ("/bin/true", "/bin/false", "true", "false",
                                       "/usr/bin/true", "/usr/bin/false"):
                    continue
                suspicions = tuple(inspect_command(command, system_scope=True))
                if not suspicions and not is_modprobe_reentry(command):
                    suspicions = (Suspicion(
                        "runs a command when a kernel module is loaded", "low"),)
                found.entries.append(StartupEntry(
                    origin="modprobe hook",
                    name=f"{module} ({os.path.basename(path)})",
                    path=path,
                    command=command,
                    suspicions=suspicions,
                ))


def weight_of(policy: Policy, key: str, entry: StartupEntry) -> Severity:
    """How severe one flagged start-up entry is.

    `Policy.at_least` would be wrong here. It raises the floor *up* to the
    policy value, which would report `ExecStartPre=/bin/sh -c 'wait for the
    socket'` — a completely ordinary thing for a packaged unit to do — at the
    same severity as a line that pipes a download into a shell. Only the
    genuinely unexplainable shapes get the policy's full weight; the merely
    unusual ones are capped low, so they are listed without shouting.
    """
    full = policy.severity(key)
    return full if entry.serious else min(full, Severity.LOW)


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@check(
    "persistence.ld-preload",
    title="Library preloading",
    category=Category.PERSISTENCE,
    inspects="/etc/ld.so.preload and LD_PRELOAD in /etc/environment.",
    worst=Severity.CRITICAL,
    tags=("persistence", "rootkit"),
)
def library_preloading(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """The classic userspace rootkit hook. Usually absent; never innocent."""
    item = get("persistence.ld-preload")
    preload = probe.file("/etc/ld.so.preload")
    environment = probe.file("/etc/environment")
    in_environment = [line for line in environment.lines()
                      if line.replace(" ", "").upper().startswith("LD_PRELOAD=")]

    if preload.missing and not in_environment:
        yield passed(
            item, "absent", "Nothing is preloaded into every program",
            "/etc/ld.so.preload does not exist and /etc/environment sets no "
            "LD_PRELOAD. This is the file a userspace rootkit uses to get its "
            "code into every process on the machine, so its absence is worth "
            "stating rather than assuming.",
            value="absent",
            evidence=(Evidence("/etc/ld.so.preload", "no such file"),),
        )
        return

    libraries = preload.lines() if preload.ok else []
    evidence = (
        Evidence("/etc/ld.so.preload",
                 preload.text.strip() if preload.ok else preload.error),
        Evidence("/etc/environment",
                 "\n".join(in_environment) or "no LD_PRELOAD"),
    )

    yield finding(
        item, "present", policy.at_least("ld_preload", Severity.HIGH),
        "A library is force-loaded into every program on this machine",
        (f"/etc/ld.so.preload lists {listing(libraries)}. "
         if libraries else "")
        + ("/etc/environment sets LD_PRELOAD. " if in_environment else "")
        + "Everything the dynamic linker starts will load that library first, "
        "and it can replace any function in any program — including the ones "
        "ClamGuard uses to read files.",
        impact=(
            "There are legitimate uses (libeatmydata, some profilers, a few "
            "accessibility tools) but they are rare, and this is the standard "
            "way a userspace rootkit hides files and processes. Identify the "
            "library before assuming either."
        ),
        value=listing(libraries, limit=2) or "LD_PRELOAD set",
        expected="no such file",
        evidence=evidence,
        fixes=(
            Fix(
                title="Find out what the library is",
                explanation="Which package owns it, when it appeared, and what "
                            "it exports.",
                command="ls -l $(cat /etc/ld.so.preload 2>/dev/null) ; "
                        "file $(cat /etc/ld.so.preload 2>/dev/null)",
                recommended=True,
            ),
            Fix(
                title="Scan it",
                explanation="ClamGuard can check the library itself against the "
                            "signature database.",
                manual="Copy the path and run a custom scan from the Scan page.",
            ),
        ),
        references=(MITRE_PERSISTENCE,),
        tags=frozenset({"persistence", "rootkit"}),
    )


@check(
    "persistence.units",
    title="What starts at boot",
    category=Category.PERSISTENCE,
    inspects="Every enabled systemd unit's ExecStart, system and user.",
    worst=Severity.HIGH,
    tags=("persistence", "services"),
)
def suspicious_units(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Enabled units whose command does something no package would do."""
    item = get("persistence.units")
    found = inventory(probe)
    units = found.of("systemd (system)") + found.of("systemd (user)")
    if not units:
        raise SkipCheck("no enabled units could be listed")

    flagged = [entry for entry in units if entry.notable]
    non_root = [entry for entry in found.of("systemd (system)") if entry.owner]

    summary = Evidence(
        "systemctl list-unit-files --state=enabled",
        f"{len(units)} enabled units examined\n"
        + "\n".join(f"{entry.name:<40} {entry.command[:90]}" for entry in units[:20]),
        kind="command")

    for entry in flagged:
        yield finding(
            item, entry.name.replace(".", "-"),
            weight_of(policy, "suspicious_exec", entry),
            f"{entry.name} starts something unusual",
            f"It {entry.reasons}.",
            impact=(
                "A systemd unit is the most durable way to make something run "
                "at every boot, and an enabled one needs no further action from "
                "anybody. Check what this actually starts."
            ),
            value=entry.command[:60] or "(no ExecStart)",
            expected="an absolute path to a packaged program",
            evidence=(
                Evidence(entry.path, probe.text(entry.path)[:2000]
                         or "(unit file not readable)"),
                summary,
            ),
            fixes=(
                Fix(
                    title="See what the unit does and who installed it",
                    explanation="If no package owns the file, somebody put it "
                                "there by hand.",
                    command=f"systemctl cat {entry.name}",
                    recommended=True,
                ),
                Fix(
                    title="Stop it starting, while you work out what it is",
                    explanation="Disabling is reversible; deleting is not.",
                    command=f"sudo systemctl disable --now {entry.name}",
                ),
            ),
            references=(MITRE_PERSISTENCE,),
            tags=frozenset({"persistence", "services"}),
        )

    if non_root:
        yield finding(
            item, "non-root-owned", policy.severity("unit_in_home"),
            f"{plural(len(non_root), 'system unit file')} is not owned by root",
            listing([entry.path for entry in non_root])
            + " — a system unit runs as whatever it says it does, usually root, "
            "but the file describing it can be changed by its owner.",
            impact="Whoever owns the file can change what the service runs, "
                   "without needing any privilege to do so.",
            value=plural(len(non_root), "file"),
            expected="root:root",
            evidence=(summary,),
            fixes=(Fix("Give the unit files back to root", "",
                       command="sudo chown root:root /etc/systemd/system/*.service"),),
            tags=frozenset({"persistence", "services"}),
        )

    if not flagged and not non_root:
        yield passed(
            item, "clean", f"{plural(len(units), 'enabled unit')} checked, nothing unusual",
            "Every enabled unit starts an absolute path, none run an inline "
            "shell command, fetch anything from the network at boot, or live "
            "in a directory anybody can write to.",
            value=f"{len(units)} units", evidence=(summary,),
        )


@check(
    "persistence.autostart",
    title="Desktop autostart entries",
    category=Category.PERSISTENCE,
    inspects="~/.config/autostart and /etc/xdg/autostart .desktop files.",
    worst=Severity.HIGH,
    tags=("persistence", "desktop"),
)
def autostart_entries(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """What the desktop session starts when you log in."""
    item = get("persistence.autostart")
    entries = inventory(probe).of("XDG autostart")
    if not entries:
        raise SkipCheck("no XDG autostart directories exist")

    active = [entry for entry in entries if entry.enabled]
    flagged = [entry for entry in active if entry.notable]
    summary = Evidence(
        "~/.config/autostart and /etc/xdg/autostart",
        "\n".join(f"{entry.name:<40} {entry.command[:80]}" for entry in entries),
        kind="computed")

    for entry in flagged:
        yield finding(
            item, entry.name.replace(".", "-"),
            weight_of(policy, "autostart_suspicious", entry),
            f"{entry.name} runs something unusual at login",
            f"It {entry.reasons}.",
            impact=(
                "An autostart entry needs no privilege at all to create — any "
                "program running as you can drop a .desktop file in "
                "~/.config/autostart, and it will run at every login from then "
                "on. It is the cheapest persistence on a Linux desktop."
            ),
            value=entry.command[:60],
            evidence=(Evidence(entry.path, probe.text(entry.path)[:1500]), summary),
            fixes=(
                Fix(
                    title="Read the entry",
                    explanation="A legitimate one names a program you installed.",
                    command=f"cat {entry.path}",
                    recommended=True,
                ),
                Fix(
                    title="Remove it",
                    explanation="Only after you know what it is.",
                    command=f"rm {entry.path}"
                    if entry.path.startswith(os.path.expanduser("~"))
                    else f"sudo rm {entry.path}",
                    risk="If it belongs to a package, the package will put it "
                         "back on the next update.",
                ),
            ),
            references=(MITRE_PERSISTENCE,),
            tags=frozenset({"persistence", "desktop"}),
        )

    if not flagged:
        yield passed(
            item, "clean",
            f"{plural(len(active), 'autostart entry', 'autostart entries')} at login, nothing unusual",
            f"{len(entries) - len(active)} more are present but disabled.",
            value=f"{len(active)} entries", evidence=(summary,),
        )


@check(
    "persistence.scheduled",
    title="Cron and scheduled jobs",
    category=Category.PERSISTENCE,
    inspects="/etc/crontab, /etc/cron.d, the cron.* directories and your own crontab.",
    worst=Severity.HIGH,
    tags=("persistence",),
)
def scheduled_jobs(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Cron is the oldest persistence mechanism and still the most common."""
    item = get("persistence.scheduled")
    found = inventory(probe)
    entries = found.of("cron")
    unreadable = [path for path in found.unreadable if "cron" in path]

    if not entries and not unreadable:
        raise SkipCheck("no cron configuration is present or readable")

    flagged = [entry for entry in entries if entry.notable]
    summary = Evidence(
        "/etc/crontab, /etc/cron.d, /etc/cron.*",
        "\n".join(f"{entry.name:<24} {entry.command[:90]}" for entry in entries)
        or "no jobs found",
        kind="computed")

    for entry in flagged:
        yield finding(
            item, entry.name.replace(".", "-") + "-" + str(abs(hash(entry.command)) % 10000),
            weight_of(policy, "cron_suspicious", entry),
            f"A scheduled job in {entry.name} runs something unusual",
            f"It {entry.reasons}.",
            impact="A cron entry runs on a schedule forever, with no session "
                   "and no terminal, which makes it convenient for anything "
                   "that wants to call home quietly.",
            value=entry.command[:60],
            evidence=(Evidence(entry.path, probe.text(entry.path)[:1500]), summary),
            fixes=(Fix("Read the whole file", "",
                       command=f"cat {entry.path}", recommended=True),),
            references=(MITRE_PERSISTENCE,),
            tags=frozenset({"persistence"}),
        )

    if unreadable:
        yield finding(
            item, "unreadable", Severity.INFO,
            f"{plural(len(unreadable), 'cron file')} could not be read",
            "Other users' crontabs are root-only, which is correct. ClamGuard "
            "does not run as root, so it can only check yours and the system "
            "ones: " + listing(unreadable) + ".",
            value=plural(len(unreadable), "file"),
            evidence=(summary,),
            fixes=(Fix(
                title="Check every user's crontab yourself",
                explanation="Lists the scheduled jobs of every account on the "
                            "machine.",
                command="sudo sh -c 'for u in $(cut -d: -f1 /etc/passwd); do "
                        "crontab -l -u \"$u\" 2>/dev/null | sed \"s/^/$u: /\"; done'",
            ),),
            tags=frozenset({"persistence"}),
        )

    if not flagged:
        yield passed(
            item, "clean", f"{plural(len(entries), 'scheduled job')} checked, nothing unusual",
            "No job downloads and runs anything, uses an inline shell, or "
            "points into a world-writable directory.",
            value=f"{len(entries)} jobs", evidence=(summary,),
        )


@check(
    "persistence.shell-profiles",
    title="Shell start-up files",
    category=Category.PERSISTENCE,
    inspects="/etc/profile, /etc/profile.d and the per-user shell rc files.",
    worst=Severity.HIGH,
    tags=("persistence",),
)
def shell_profiles(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A line appended to .bashrc runs every time you open a terminal."""
    item = get("persistence.shell-profiles")
    entries = inventory(probe).of("shell profile")
    checked = len([path for path in SHELL_PROFILES
                   if probe.file(os.path.expanduser(path)).ok]) \
        + len(probe.files_in("/etc/profile.d"))

    if not checked:
        raise SkipCheck("no shell start-up files were readable")

    if not entries:
        yield passed(
            item, "clean", f"{plural(checked, 'shell start-up file')} checked, nothing unusual",
            "None of them download anything, decode a blob, or run something "
            "out of a world-writable directory.",
            value=f"{checked} files",
            evidence=(Evidence("shell profiles checked",
                               "\n".join(os.path.expanduser(path)
                                         for path in SHELL_PROFILES),
                               kind="computed"),),
        )
        return

    for entry in entries:
        yield finding(
            item, os.path.basename(entry.path).replace(".", "-"),
            weight_of(policy, "profile_script_suspicious", entry),
            f"{entry.path} contains something unusual",
            f"A line in it {entry.reasons}.",
            impact=(
                "Shell start-up files run with your full privileges every time "
                "you open a terminal. Appending one line to ~/.bashrc needs no "
                "root and survives every update."
            ),
            value=entry.command[:60],
            evidence=(Evidence(entry.path, probe.text(entry.path)[:2000]),),
            fixes=(Fix(
                title="Read the file and check the date",
                explanation="A line you do not remember writing, at the bottom "
                            "of the file, with a recent modification time, is "
                            "the shape this normally takes.",
                command=f"ls -l {entry.path} && tail -30 {entry.path}",
                recommended=True,
            ),),
            references=(MITRE_PERSISTENCE,),
            tags=frozenset({"persistence"}),
        )


@check(
    "persistence.kernel-hooks",
    title="udev and modprobe hooks",
    category=Category.PERSISTENCE,
    inspects="/etc/udev/rules.d for RUN+= and /etc/modprobe.d for install lines.",
    worst=Severity.HIGH,
    tags=("persistence", "kernel"),
)
def kernel_hooks(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """Two places that run a command in response to kernel events."""
    item = get("persistence.kernel-hooks")
    found = inventory(probe)
    udev = found.of("udev rule")
    modprobe = found.of("modprobe hook")
    if not udev and not modprobe:
        yield passed(
            item, "none", "No local udev or modprobe hooks",
            "Nothing in /etc/udev/rules.d runs a command, and no modprobe "
            "install line does anything but blacklist a module.",
            value="none",
            evidence=(Evidence("/etc/udev/rules.d, /etc/modprobe.d",
                               "no RUN+= or install hooks", kind="computed"),),
        )
        return

    for entry in [item_ for item_ in modprobe if item_.notable]:
        yield finding(
            item, "modprobe-" + entry.name.split()[0],
            weight_of(policy, "modprobe_install_hook", entry),
            f"Loading the {entry.name.split()[0]} module runs a command",
            f"`install {entry.name.split()[0]} {entry.command}` in "
            f"{entry.path}. modprobe will run that instead of simply loading "
            "the module.",
            impact=(
                "This is a documented feature used for module dependencies, and "
                "a known persistence technique: the command runs as root, at "
                "whatever moment the module is first needed, which on a desktop "
                "is usually during boot."
            ),
            value=entry.command[:60],
            evidence=(Evidence(entry.path, probe.text(entry.path)[:1500]),),
            fixes=(Fix("Read the file and work out which package owns it", "",
                       command=f"cat {entry.path}", recommended=True),),
            references=(MITRE_PERSISTENCE,),
            tags=frozenset({"persistence", "kernel"}),
        )

    flagged = [entry for entry in udev if entry.notable]
    for entry in flagged:
        yield finding(
            item, "udev-" + entry.name.replace(".", "-"),
            weight_of(policy, "udev_run_rule", entry),
            f"A udev rule in {entry.name} runs something unusual",
            f"It {entry.reasons}.",
            impact="udev rules run as root whenever the matching device "
                   "appears — including at boot, and including for a device "
                   "someone plugs in.",
            value=entry.command[:60],
            evidence=(Evidence(entry.path, probe.text(entry.path)[:1500]),),
            fixes=(Fix("Read the rule", "", command=f"cat {entry.path}",
                       recommended=True),),
            tags=frozenset({"persistence", "kernel"}),
        )

    if udev and not flagged:
        yield finding(
            item, "udev-present", Severity.INFO,
            f"{plural(len(udev), 'local udev rule')} runs a command",
            "Nothing about them looks wrong — they run absolute paths to "
            "installed programs — but they are listed because a rule that runs "
            "a command is worth knowing about: "
            + listing([entry.name for entry in udev]) + ".",
            value=plural(len(udev), "rule"),
            evidence=(Evidence("/etc/udev/rules.d",
                               "\n".join(f"{entry.name}: {entry.command}"
                                         for entry in udev), kind="computed"),),
            tags=frozenset({"persistence", "kernel"}),
        )


@check(
    "persistence.path",
    title="Writable directories on the system PATH",
    category=Category.PERSISTENCE,
    inspects=f"The permissions of {', '.join(DEFAULT_PATH_DIRS)}.",
    worst=Severity.CRITICAL,
    tags=("persistence", "permissions"),
)
def writable_path(probe: Probe, policy: Policy) -> Iterator[Finding]:
    """A writable PATH directory lets anyone replace any command."""
    item = get("persistence.path")
    problems: list[str] = []
    rows: list[str] = []

    for directory in DEFAULT_PATH_DIRS:
        # follow=True on purpose: /bin, /sbin and /usr/sbin are symlinks to
        # /usr/bin on a merged-/usr system, and a symlink's own mode is always
        # 0777. Reading that as "world-writable" would be a false alarm of the
        # loudest possible kind.
        info = probe.stat(directory, follow=True)
        if info is None:
            continue
        mode = info.st_mode & 0o7777
        rows.append(f"{directory:<20} {octal(mode)}  uid {info.st_uid}")
        if mode & 0o002 and not mode & 0o1000:
            problems.append(f"{directory} is mode {octal(mode)}")
        elif info.st_uid != 0:
            problems.append(f"{directory} is owned by uid {info.st_uid}, not root")

    if not rows:
        raise SkipCheck("none of the standard PATH directories exist")

    evidence = (Evidence("stat on PATH directories", "\n".join(rows), kind="computed"),)

    if not problems:
        yield passed(
            item, "clean", "Every directory on the system PATH is root-owned",
            f"{plural(len(rows), 'directory', 'directories')} checked; none is "
            "writable by anyone but root.",
            value=f"{len(rows)} checked", evidence=evidence,
        )
        return

    yield finding(
        item, "writable", policy.at_least("world_writable_path", Severity.CRITICAL),
        "A directory on the system PATH can be written by someone other than root",
        "; ".join(problems) + ". Anything placed there shadows the real "
        "command if it comes earlier in the PATH.",
        impact=(
            "Put a file called `ls` in a writable PATH directory and the next "
            "person to type ls — including root, including a cron job — runs "
            "it instead. This is a complete compromise of the machine by the "
            "shortest route there is."
        ),
        value=plural(len(problems), "directory", "directories"),
        expected="root-owned, mode 0755",
        evidence=evidence,
        fixes=(Fix(
            title="Restore the correct ownership and mode",
            explanation="These directories should be root:root and 0755 on "
                        "every distribution.",
            command="sudo chown root:root " + " ".join(DEFAULT_PATH_DIRS)
                    + " && sudo chmod 0755 " + " ".join(DEFAULT_PATH_DIRS),
            recommended=True,
        ),),
        references=(MITRE_PERSISTENCE,),
        tags=frozenset({"persistence", "permissions"}),
    )
