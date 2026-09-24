"""Reading the systemd journal — the only module in Hunt that runs a command.

Everything else in ``core/hunt`` is forbidden from executing anything, and
``tests/test_security.py`` asserts it. This module is the single, named
exception, so it is written to be the kind of exception that stays safe:

* **One program.** ``journalctl``, resolved through ``shutil.which``, never a
  path from settings or from the database.
* **An argument allow-list.** Every element of the command line has to match
  :data:`ALLOWED_ARGUMENTS` before the process is started. A test builds the
  arguments for every combination of settings and asserts the same thing.
* **No shell, ever.** ``Popen`` with a list, and a deliberately boring
  environment.
* **Streaming.** The journal on the machine this was written for holds
  11.3 million entries; ``-o json`` is about 1.4 kB each. Nothing is buffered
  whole — entries are parsed off the pipe and the process is killed the
  moment a cap or a cancellation is hit.

Two behaviours of ``journalctl`` drove the design and are worth knowing:

**A stale cursor fails almost silently.** ``--after-cursor`` with a cursor
that no longer exists — after a ``--vacuum``, or a reinstall — prints
``Failed to seek to cursor: Invalid argument`` on *stderr*, prints nothing on
stdout, and exits non-zero. Read carelessly that is indistinguishable from
"nothing new has happened", forever. :class:`JournalRead` reports it as
:attr:`stale_cursor` and the caller falls back to the configured window.

**A valid cursor at the newest entry returns nothing and exits 0**, which is
the ordinary "up to date" case and must not be confused with the above.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable

from ..logging_setup import get_logger
from .formats import ParseContext, journal_unit, parse_journal
from .model import Event

log = get_logger(__name__)

#: The only program this module may run.
PROGRAM = "journalctl"

#: The fields asked for. Trimming them halves the bytes and quarters the time
#: — 20,000 entries go from 27.6 MB in 1.6 s to 14.0 MB in 0.375 s — and
#: journalctl returns __CURSOR and __REALTIME_TIMESTAMP regardless.
OUTPUT_FIELDS = (
    "__REALTIME_TIMESTAMP", "__CURSOR", "PRIORITY", "MESSAGE",
    "SYSLOG_IDENTIFIER", "_SYSTEMD_UNIT", "_SYSTEMD_USER_UNIT", "_COMM",
    "_PID", "_UID", "_TRANSPORT", "_HOSTNAME", "CODE_FILE", "CODE_LINE",
    "CODE_FUNC", "ERRNO", "UNIT", "JOB_TYPE",
)

#: How far back a first read goes. Not a free-text field — one of these.
WINDOWS: dict[str, tuple[str, str]] = {
    "boot": ("This boot", "Everything since the machine started."),
    "24h": ("Last 24 hours", "The last day, across reboots."),
    "7d": ("Last 7 days", "A week. On a busy machine this is a lot."),
    "30d": ("Last 30 days", "A month. Expect hundreds of thousands of entries."),
    "all": ("Everything", "The whole journal. Check the size first."),
}
DEFAULT_WINDOW = "boot"

#: The lowest priority kept. journald's numbering, lower is worse.
PRIORITIES: dict[str, tuple[str, str]] = {
    "all": ("Everything", "Including debug and info."),
    "notice": ("Notice and worse", "Drops info and debug."),
    "warning": ("Warnings and worse", "The smallest useful set."),
    "err": ("Errors and worse", "Only things that went wrong."),
}
DEFAULT_PRIORITY = "all"

#: A hard cap per read, whatever the window says. The journal is unbounded and
#: the store is not.
DEFAULT_MAX_ENTRIES = 250_000

#: journald's own cursor format. Validated before being handed back to
#: journalctl, because it round-trips through a database file the user can
#: edit — and a value beginning with "-" would otherwise be read as a flag.
CURSOR = re.compile(r"[a-z]=[0-9a-fA-F]+(;[a-z]=[0-9a-fA-F]+)*")

#: Every argument this module is allowed to pass. A test asserts that the
#: command line built for every combination of settings is a subset of this.
ALLOWED_ARGUMENTS: tuple[re.Pattern, ...] = (
    re.compile(r"--output=json"),
    re.compile(r"--output-fields=[A-Z_,]+"),
    re.compile(r"--no-pager"),
    re.compile(r"--quiet"),
    re.compile(r"--system"),
    re.compile(r"--user"),
    re.compile(r"--boot"),
    re.compile(r"--since=[0-9]+ (seconds|minutes|hours|days) ago"),
    re.compile(r"--priority=(emerg|alert|crit|err|warning|notice|info|debug)"),
    re.compile(r"--lines=[0-9]{1,9}"),
    re.compile(r"--after-cursor=" + CURSOR.pattern),
    re.compile(r"--no-tail"),
)

#: The marker journalctl prints when a cursor no longer exists.
_STALE = "failed to seek"

#: Seconds before a read is abandoned. Generous: a 30-day window on a busy
#: machine is genuinely slow.
DEFAULT_TIMEOUT = 900.0


@dataclass(frozen=True, slots=True)
class JournalOptions:
    """What to read. Every field is an enum or a number, never free text."""

    window: str = DEFAULT_WINDOW
    priority: str = DEFAULT_PRIORITY
    max_entries: int = DEFAULT_MAX_ENTRIES
    #: Include this user's own units as well as the system ones.
    include_user: bool = True
    timeout: float = DEFAULT_TIMEOUT

    def normalised(self) -> "JournalOptions":
        return JournalOptions(
            window=self.window if self.window in WINDOWS else DEFAULT_WINDOW,
            priority=(self.priority if self.priority in PRIORITIES
                      else DEFAULT_PRIORITY),
            max_entries=max(1, min(int(self.max_entries), 20_000_000)),
            include_user=bool(self.include_user),
            timeout=max(5.0, min(float(self.timeout), 7200.0)),
        )

    def describe(self) -> str:
        window = WINDOWS.get(self.window, WINDOWS[DEFAULT_WINDOW])[0]
        priority = PRIORITIES.get(self.priority, PRIORITIES[DEFAULT_PRIORITY])[0]
        return f"{window}, {priority.lower()}"


@dataclass(slots=True)
class JournalRead:
    """The outcome of one read."""

    #: (unit, event) pairs, in journal order.
    entries: list[tuple[str, Event]] = field(default_factory=list)
    #: The cursor of the last entry read, to resume from next time.
    cursor: str = ""
    #: True when the cursor we were given no longer exists.
    stale_cursor: bool = False
    #: True when `max_entries` stopped the read before the journal did.
    #: Nothing is lost when this happens — see `--no-tail` in
    #: :func:`build_arguments` — the rest arrives on the next index.
    truncated: bool = False
    #: True when the caller asked to stop.
    cancelled: bool = False
    elapsed: float = 0.0
    skipped: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def count(self) -> int:
        return len(self.entries)

    def summary(self) -> str:
        if self.error:
            return f"The journal could not be read: {self.error}"
        parts = [f"{self.count:,} entries", f"{self.elapsed:.1f}s"]
        if self.truncated:
            parts.append("stopped at the limit — the rest is read on the "
                         "next index")
        if self.stale_cursor:
            parts.append("resumed from the start: the saved position expired")
        return " · ".join(parts)


@dataclass(frozen=True, slots=True)
class Availability:
    """Whether the journal can be read here, and how much of it."""

    present: bool = False
    readable: bool = False
    system: bool = False
    user: bool = False
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.present and self.readable

    def describe(self) -> str:
        if not self.present:
            return "journalctl is not installed, so there is no journal to read."
        if not self.readable:
            return self.reason or "The journal cannot be read by this account."
        if self.system and self.user:
            return "The whole journal is readable, system units included."
        if self.user:
            return ("Only your own entries are readable. Add yourself to the "
                    "systemd-journal group to see system units too.")
        return "The journal is readable."


# ---------------------------------------------------------------------------
# Building the command
# ---------------------------------------------------------------------------


def executable() -> str:
    """The absolute path of journalctl, or "" when it is not installed.

    Resolved through PATH at call time and never taken from settings or the
    database, so there is nothing a stored value can redirect.
    """
    return shutil.which(PROGRAM) or ""


def _since(window: str) -> str | None:
    return {"24h": "--since=24 hours ago",
            "7d": "--since=7 days ago",
            "30d": "--since=30 days ago"}.get(window)


def build_arguments(options: JournalOptions, cursor: str = "") -> list[str]:
    """The argument list for one read, with nothing free-form in it."""
    options = options.normalised()
    arguments = ["--output=json", "--no-pager", "--no-tail",
                 "--output-fields=" + ",".join(OUTPUT_FIELDS)]

    resuming = bool(cursor) and CURSOR.fullmatch(cursor) is not None
    if resuming:
        arguments.append(f"--after-cursor={cursor}")
    elif options.window == "boot":
        arguments.append("--boot")
    else:
        since = _since(options.window)
        if since:
            arguments.append(since)

    if options.priority != "all":
        arguments.append(f"--priority={options.priority}")
    if not options.include_user:
        arguments.append("--system")
    # `--lines` is a cap, and `--no-tail` above is what makes it a *safe*
    # one. Measured against journalctl 258 on 11.9k entries: with `--no-tail`
    # it returns the OLDEST N of the window, so a capped read plus the cursor
    # it leaves behind resumes exactly where it stopped — 5,000 then 6,918
    # accounted for all 11,918 that existed when the first read began.
    # Without `--no-tail` the same flag returns the NEWEST N instead, and
    # everything older than the cap would be lost the moment the cursor was
    # saved past it.
    arguments.append(f"--lines={options.max_entries}")
    return arguments


def check_arguments(arguments: list[str]) -> list[str]:
    """Every argument that is not on the allow-list. Empty means safe."""
    offences = []
    for argument in arguments:
        if not any(pattern.fullmatch(argument) for pattern in ALLOWED_ARGUMENTS):
            offences.append(argument)
    return offences


def _environment() -> dict[str, str]:
    """A deliberately boring environment. The output is parsed, so the locale
    is pinned, and nothing about the caller's session is inherited that could
    change what journalctl decides to do."""
    return {
        "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", ""),
        "SYSTEMD_COLORS": "0",
        "SYSTEMD_PAGER": "",
    }


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------


def availability(runner: Callable | None = None) -> Availability:
    """Probe what this account can actually see. Cheap: reads no entries."""
    path = executable()
    if not path:
        return Availability(reason="journalctl is not installed.")

    def probe(extra: list[str]) -> bool:
        arguments = ["--no-pager", "--quiet", "--lines=1", "--output=json",
                     *extra]
        if check_arguments(arguments):
            return False
        try:
            if runner is not None:
                code, _out, _err = runner([path, *arguments])
            else:
                completed = subprocess.run(
                    [path, *arguments], capture_output=True, text=True,
                    timeout=15, env=_environment(), check=False)
                code = completed.returncode
            return code == 0
        except (OSError, subprocess.SubprocessError):
            return False

    system = probe(["--system"])
    user = probe(["--user"])
    if not system and not user:
        return Availability(
            present=True,
            reason="journalctl is installed but this account cannot read any "
                   "of the journal.")
    return Availability(present=True, readable=True, system=system, user=user)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def read(options: JournalOptions | None = None, cursor: str = "", *,
         should_stop: Callable[[], bool] | None = None,
         on_progress: Callable[[int], None] | None = None,
         opener: Callable | None = None) -> JournalRead:
    """Read the journal once, resuming from `cursor` when it is still valid.

    `opener` exists so the tests can drive this with canned output instead of
    the real journal; production leaves it None and gets ``subprocess.Popen``.
    """
    options = (options or JournalOptions()).normalised()
    result = JournalRead()
    started = time.monotonic()

    path = executable()
    if not path and opener is None:
        result.error = "journalctl is not installed."
        return result

    arguments = build_arguments(options, cursor)
    offences = check_arguments(arguments)
    if offences:
        # Cannot happen from the enums above; a loud failure beats running a
        # command line nobody checked.
        result.error = f"refusing to run journalctl with {offences!r}"
        log.error("hunt journal: %s", result.error)
        return result

    command = [path, *arguments]
    log.info("hunt journal: %s", " ".join(arguments))

    try:
        process = (opener(command) if opener is not None else subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace", bufsize=1, env=_environment()))
    except (OSError, subprocess.SubprocessError) as error:
        result.error = str(error)
        return result

    context = ParseContext(year=time.localtime().tm_year,
                           month=time.localtime().tm_mon)
    deadline = started + options.timeout
    seen = 0

    try:
        for line in process.stdout:
            seen += 1
            if seen % 2048 == 0:
                if should_stop is not None and should_stop():
                    result.cancelled = True
                    break
                if time.monotonic() > deadline:
                    result.error = (f"the journal read passed its "
                                    f"{options.timeout:.0f} second limit")
                    break
                if on_progress is not None:
                    on_progress(len(result.entries))

            entry = _entry(line, context)
            if entry is None:
                result.skipped += 1
                continue
            unit, event, entry_cursor = entry
            result.entries.append((unit, event))
            if entry_cursor:
                result.cursor = entry_cursor
            if len(result.entries) >= options.max_entries:
                result.truncated = True
                break
    finally:
        _finish(process, result, cursor)

    result.elapsed = time.monotonic() - started
    if result.skipped:
        log.debug("hunt journal: %d unparseable lines", result.skipped)
    return result


def _entry(line: str, context: ParseContext) -> tuple[str, Event, str] | None:
    """One journal line as (unit, event, cursor)."""
    body = line.strip()
    if not body or body[0] != "{":
        return None
    event = parse_journal(body, context)
    if event is None:
        return None
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        return None
    cursor = data.get("__CURSOR")
    return (journal_unit(data), event,
            cursor if isinstance(cursor, str) else "")


def _finish(process, result: JournalRead, cursor: str) -> None:
    """Close the pipe, decide whether the cursor was rejected, and reap.

    The stale-cursor case is the one that matters: journalctl says so on
    stderr and exits non-zero while printing nothing at all, which reads
    exactly like "nothing new" unless somebody looks.
    """
    errors = ""
    try:
        if result.truncated or result.cancelled or result.error:
            process.terminate()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            errors = process.stderr.read() or ""
            process.stderr.close()
        process.wait(timeout=20)
    except (OSError, subprocess.SubprocessError, ValueError):
        try:
            process.kill()
        except Exception:      # noqa: BLE001 - reaping must not raise
            pass

    code = getattr(process, "returncode", 0) or 0
    lowered = errors.lower()
    if cursor and _STALE in lowered:
        result.stale_cursor = True
        log.warning("hunt journal: the saved position no longer exists; "
                    "reading the configured window instead")
        return
    if code and not result.truncated and not result.cancelled and not result.error:
        result.error = (errors.strip().splitlines() or
                        [f"journalctl exited with status {code}"])[0][:300]


def estimate(options: JournalOptions | None = None) -> int:
    """Roughly how many entries a read would produce. -1 when unknown.

    Only answered for windows that are cheap to count. "Everything" on the
    machine this was written for is 11.3 million entries and counting them
    takes longer than most people will wait, so it is not guessed at.
    """
    options = (options or JournalOptions()).normalised()
    if options.window in ("30d", "all"):
        return -1
    path = executable()
    if not path:
        return -1
    arguments = [argument for argument in build_arguments(options)
                 if not argument.startswith("--output")]
    arguments = [argument for argument in arguments
                 if not argument.startswith("--lines")]
    arguments.append("--quiet")
    if check_arguments(arguments):
        return -1
    try:
        completed = subprocess.run(
            [path, *arguments, "--output=cat"], capture_output=True, text=True,
            timeout=60, env=_environment(), check=False)
    except (OSError, subprocess.SubprocessError):
        return -1
    if completed.returncode:
        return -1
    return completed.stdout.count("\n")
