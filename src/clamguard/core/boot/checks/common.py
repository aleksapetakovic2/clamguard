"""Helpers more than one check needs.

Mostly two things: describing file permissions in words, and deciding whether
a command line looks like something a package maintainer wrote or something an
attacker did. The second one is the interesting part and it lives here rather
than in one check because four different checks — units, autostart entries,
cron jobs and shell profiles — ask the same question about different files.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass

#: Directories anyone can write to. A boot-time command living in one of these
#: is a finding on its own: whoever wrote it there chose a location where any
#: local user can replace it.
WORLD_WRITABLE_ROOTS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")

#: Fetch-and-run. The single most common shape of a Linux persistence payload,
#: and something no distribution package does at boot.
_DOWNLOAD_TOOLS = ("curl", "wget", "fetch", "nc", "ncat", "socat")
_SHELLS = ("sh", "bash", "dash", "zsh", "ksh", "fish")

#: Interpreters that will happily run a string from the command line.
_INLINE_INTERPRETERS = ("python", "python3", "perl", "ruby", "php", "node", "lua")

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/=]{80,}")
_HEX_BLOB = re.compile(r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){12,}")


@dataclass(frozen=True)
class Suspicion:
    """One reason a command line looks wrong, and how much it matters.

    Three weights, and the difference between them is the difference between a
    useful startup report and an unreadable one:

    ``high``
        No legitimate explanation at boot. Downloading and executing, decoding
        a blob, running out of a world-writable directory.
    ``medium``
        Unusual enough to list, common enough to have an innocent reason. An
        inline shell command, a network request.
    ``low``
        A style observation. Recorded so the Startup surface tab can show it,
        but never enough on its own to make a finding — `seatd.service` ships
        with a relative ExecStart and there is nothing wrong with it.
    """

    reason: str
    weight: str = "medium"

    @property
    def serious(self) -> bool:
        return self.weight == "high"

    @property
    def notable(self) -> bool:
        """Worth a finding. A pile of low-weight notes is not."""
        return self.weight in ("high", "medium")


#: modprobe install lines routinely re-invoke modprobe to do the real load.
#: That is the documented idiom, not a hook doing something else.
_MODPROBE_REENTRY = re.compile(r"\bmodprobe\b.*--ignore-install|\bmodprobe\s+-i\b")


def inspect_command(
    command: str,
    *,
    home: str | None = None,
    system_scope: bool = False,
    require_absolute: bool = False,
) -> list[Suspicion]:
    """Why this command line is or is not the kind of thing that belongs at boot.

    Returns an empty list for ordinary commands. The rules are deliberately
    conservative — every one of them describes something a distribution package
    does not do — because a startup list full of false positives is a startup
    list nobody reads.

    ``system_scope``
        True for anything that runs as root or system-wide. It raises the
        weight of the rules where the distinction matters: a *system* service
        running a binary out of somebody's home directory is a different
        proposition from a user's own login item doing the same.
    ``require_absolute``
        True only where a relative path is genuinely unusual. systemd units
        mostly use absolute paths, but a ``.desktop`` file or a crontab line
        with a bare command name is completely normal, and flagging those buries
        everything else.
    """
    text = command.strip()
    if not text:
        return []

    found: list[Suspicion] = []
    lowered = text.lower()
    words = _safe_split(text)
    program = os.path.basename(words[0]) if words else ""

    for root in WORLD_WRITABLE_ROOTS:
        if root in text or text.startswith(root.rstrip("/")):
            found.append(Suspicion(
                f"runs something from {root.rstrip('/')}, which any local user can write to",
                "high"))
            break

    if any(f"{tool} " in lowered or lowered.startswith(tool) for tool in _DOWNLOAD_TOOLS):
        if "|" in text and any(shell in lowered for shell in _SHELLS):
            found.append(Suspicion(
                "downloads something and pipes it straight into a shell", "high"))
        else:
            found.append(Suspicion(
                "makes a network request at start-up", "medium"))

    if program in _SHELLS and ("-c" in words or "-lc" in words):
        found.append(Suspicion("runs an inline shell command rather than a program",
                               "medium"))

    if program in _INLINE_INTERPRETERS and ("-c" in words or "-e" in words):
        found.append(Suspicion(f"runs inline {program} code rather than a script file",
                               "medium"))

    if "base64" in lowered and ("-d" in words or "--decode" in lowered):
        found.append(Suspicion("decodes base64 and runs the result", "high"))
    elif _BASE64_BLOB.search(text):
        found.append(Suspicion("contains a long encoded blob", "medium"))

    if _HEX_BLOB.search(text):
        found.append(Suspicion("contains an escaped byte string", "medium"))

    if home and (text.startswith(home) or f" {home}" in text):
        found.append(Suspicion(
            "runs a program from a home directory, which its owner can change "
            "without any privilege",
            "high" if system_scope else "medium"))

    if require_absolute and words and not words[0].startswith("/"):
        found.append(Suspicion(
            "does not use an absolute path, so what runs depends on the PATH "
            "in force at the time",
            "medium" if system_scope else "low"))

    return found


def is_modprobe_reentry(command: str) -> bool:
    """True for the standard ``install x /sbin/modprobe --ignore-install x`` shape."""
    return bool(_MODPROBE_REENTRY.search(command))


def _safe_split(text: str) -> list[str]:
    """shlex.split, but a quoting error returns words rather than raising."""
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------


def octal(mode: int) -> str:
    """``0644`` from a stat mode."""
    return f"{mode & 0o7777:04o}"


def is_world_writable(mode: int) -> bool:
    return bool(mode & 0o002)


def is_group_writable(mode: int) -> bool:
    return bool(mode & 0o020)


def is_setuid(mode: int) -> bool:
    return bool(mode & 0o4000)


def describe_mode(mode: int) -> str:
    """Permissions in words: ``owner only``, ``world-writable``."""
    notes = []
    if is_setuid(mode):
        notes.append("setuid")
    if mode & 0o2000:
        notes.append("setgid")
    if is_world_writable(mode):
        notes.append("world-writable")
    elif is_group_writable(mode):
        notes.append("group-writable")
    if mode & 0o004:
        notes.append("world-readable")
    if not notes:
        notes.append("owner only")
    return ", ".join(notes)


def owner_name(uid: int) -> str:
    """A user name for a uid, falling back to the number."""
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError, OSError):
        return str(uid)


# ---------------------------------------------------------------------------
# systemd unit files
# ---------------------------------------------------------------------------

_EXEC_KEYS = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecReload",
              "ExecStop", "ExecStopPost", "ExecCondition")

#: Prefix characters systemd allows in front of an Exec command, all of which
#: change how failure is handled rather than what runs.
_EXEC_PREFIXES = "-@:+!"


def exec_lines(unit_text: str) -> list[tuple[str, str]]:
    """``[("ExecStart", "/usr/bin/thing --flag"), …]`` from a unit file."""
    found: list[tuple[str, str]] = []
    continued = ""
    for raw in unit_text.splitlines():
        line = (continued + raw.strip()) if continued else raw.strip()
        continued = ""
        if line.endswith("\\"):
            continued = line[:-1] + " "
            continue
        if line.startswith("#") or line.startswith(";") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in _EXEC_KEYS and value.strip():
            found.append((key, value.strip().lstrip(_EXEC_PREFIXES).strip()))
    return found


def unit_setting(unit_text: str, key: str) -> str:
    """The last value of one ``Key=value`` line, or ""."""
    value = ""
    for raw in unit_text.splitlines():
        line = raw.strip()
        if line.startswith("#") or "=" not in line:
            continue
        name, _, rest = line.partition("=")
        if name.strip() == key:
            value = rest.strip()
    return value


def desktop_entry_exec(text: str) -> str:
    """The ``Exec=`` line of a .desktop file."""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Exec="):
            return line[5:].strip()
    return ""


def desktop_entry_is_active(text: str) -> bool:
    """False for entries marked Hidden or explicitly disabled."""
    for raw in text.splitlines():
        line = raw.strip().lower().replace(" ", "")
        if line in ("hidden=true", "x-gnome-autostart-enabled=false"):
            return False
    return True


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------


def listing(items, limit: int = 8) -> str:
    """``a, b, c and 4 more`` — for putting a set of names in a sentence."""
    items = list(items)
    if not items:
        return ""
    if len(items) <= limit:
        if len(items) == 1:
            return items[0]
        return ", ".join(items[:-1]) + " and " + items[-1]
    extra = len(items) - limit
    return ", ".join(items[:limit]) + f" and {extra} more"


def plural(count: int, singular: str, many: str = "") -> str:
    """``1 file`` / ``3 files``."""
    word = singular if count == 1 else (many or singular + "s")
    return f"{count} {word}"
