"""Finding the log files nobody thinks about, and refusing the ones that lie.

journald and auditd are read by every tool on the machine. The interesting
half of a desktop's history is somewhere else entirely — under ``~/.config``,
``~/.local/share``, ``~/.local/state``, ``~/.cache``, inside flatpak's
``~/.var/app``, in ``~/.npm/_logs``, and in whichever files under ``/var/log``
an ordinary user is allowed to open. That is what this module walks.

The hard part is not finding files called ``*.log``. It is **not** indexing
the ones that are called that and are not logs:

* ``Session Storage/000003.log`` is a LevelDB write-ahead log. Every Electron
  application on the machine has several, they are binary, and they are the
  single most common ``.log`` file on a modern desktop.
* ``~/.local/share/gvfs-metadata/home-a45ff347.log`` is a binary metadata
  store. So is ``akonadi/db_data/tc.log``, which belongs to MariaDB.
* ``/var/log/wtmp`` and ``lastlog`` are fixed-width binary records.

So every candidate is sniffed before it is believed, directories known to hold
databases are never entered, and anything rejected is *kept with its reason*
rather than silently dropped — a log you expected and cannot find is worse
than one you were told was skipped.

The walk is bounded in wall-clock time, directories visited and depth, so a
pathological tree (a recursive bind mount, a million-entry cache) ends the
crawl with a note rather than the application.
"""

from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..logging_setup import get_logger

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Where to look
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Root:
    """One place worth walking, and how far into it."""

    id: str
    path: Path
    title: str
    description: str
    depth: int = 5
    #: Off unless the user turns it on. Used for places whose contents are
    #: sensitive (shell history) or noisy (/tmp).
    optional: bool = False

    @property
    def exists(self) -> bool:
        return self.path.is_dir() or self.path.is_file()


def default_roots(home: Path | None = None) -> tuple[Root, ...]:
    """The places ClamGuard looks by default, in the order it reports them."""
    base = home or Path.home()
    return (
        Root("config", base / ".config", "Application settings",
             "Where most desktop applications keep their logs, whatever the "
             "XDG specification says they should do.", depth=6),
        Root("state", base / ".local" / "state", "Application state",
             "The XDG directory that logs are actually supposed to live in.",
             depth=5),
        Root("data", base / ".local" / "share", "Application data",
             "Steam, Akonadi, KDE services, and anything installed per-user.",
             depth=6),
        Root("cache", base / ".cache", "Cache",
             "Short-lived logs and the crash traces that outlive them.",
             depth=5),
        Root("flatpak", base / ".var" / "app", "Flatpak applications",
             "Each flatpak gets its own private config, data and cache.",
             depth=7),
        Root("snap", base / "snap", "Snap applications",
             "The equivalent for snap packages.", depth=6),
        Root("npm", base / ".npm" / "_logs", "npm",
             "npm writes a numbered debug log every time an install fails.",
             depth=2),
        Root("home", base, "Home directory",
             "The loose files in your home directory: .xsession-errors and "
             "anything a script left behind.", depth=1),
        Root("system", Path("/var/log"), "System logs",
             "The readable half of /var/log — pacman's transaction record, "
             "the X server, and whatever else is not root-only.", depth=3),
        Root("tmp", Path("/tmp"), "Temporary files",
             "Noisy and mostly uninteresting, but a program that crashed on "
             "start-up often left its only evidence here.",
             depth=2, optional=True),
        Root("shell", base, "Shell history",
             "What was typed at a shell. Off by default: this is the most "
             "sensitive file in your home directory and it is indexed only "
             "if you ask for it.", depth=1, optional=True),
    )


#: Files the "shell" root collects. It is a fixed list rather than a pattern
#: so that turning it on cannot pull in anything unexpected.
SHELL_HISTORY_FILES = (
    ".bash_history", ".zsh_history", ".zhistory", ".history",
    ".local/share/fish/fish_history", ".python_history", ".node_repl_history",
    ".sqlite_history", ".psql_history", ".lesshst",
)


# ---------------------------------------------------------------------------
# What is and is not a log
# ---------------------------------------------------------------------------

#: Directory names never entered, at any depth. Two kinds: content-addressed
#: caches that would take minutes to walk and contain nothing readable, and
#: embedded databases whose files are named ".log" but are not.
SKIP_DIRECTORIES = frozenset({
    # Embedded databases whose write-ahead logs are called 000003.log
    "Session Storage", "Local Storage", "IndexedDB", "leveldb", "databases",
    "shared_proto_db", "Service Worker", "CacheStorage", "blob_storage",
    "WebStorage", "Local State", "db_data", "gvfs-metadata",
    # Caches: large, binary, and regenerated
    "Cache", "Cache_Data", "CachedData", "CachedExtensions", "Code Cache",
    "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache",
    "GrShaderCache", "ShaderCache", "GraphiteDawnCache", "component_crx_cache",
    "mesa_shader_cache", "mesa_shader_cache_db", "nvidia", "thumbnails",
    "fontconfig", "icon-cache", "gstreamer-1.0", "mozilla-temp-files",
    # Source trees and build output that occasionally end up under ~/.config
    "node_modules", ".git", "__pycache__", "site-packages", ".venv", "venv",
    "dist-info", "egg-info",
    # Steam ships tens of thousands of files here and none of them is a log
    "steamapps", "workshop", "depotcache", "compatdata",
})

#: Suffixes that are a log outright.
LOG_SUFFIXES = frozenset({".log", ".jsonl", ".ndjson", ".err", ".trace"})

#: Suffixes that are a log only when the name says so as well.
HINTED_SUFFIXES = frozenset({".txt", ".out", ".json", ""})

#: Words in a filename that make a .txt or an extensionless file a log —
#: matched as whole words, delimited by punctuation or the ends of the name.
#: Matching them as substrings picked up ``kwinoutputconfig.json`` on the
#: strength of the "output" inside it.
NAME_HINTS = ("log", "logs", "err", "error", "errors", "debug", "trace",
              "crash", "dump", "diagnostic", "diagnostics", "report",
              "stderr", "stdout", "output", "console")

_NAME_HINT = re.compile(
    r"(?:^|[^a-z0-9])(" + "|".join(NAME_HINTS) + r")(?:[^a-z0-9]|$)")

#: Filenames that are logs regardless of extension.
LOG_NAMES = frozenset({
    "messages", "syslog", "debug", "output", "stderr", "stdout",
    "xsession-errors", "console", "daemon",
})

#: Directory names whose ordinary files are all treated as candidate logs.
LOG_DIRECTORIES = frozenset({
    "logs", "log", "Logs", "Log", "crashlogs", "CrashReports", "crash",
    "crashes", "_logs", "diagnostics",
})

#: A LevelDB or RocksDB write-ahead log. Six digits and nothing else.
_DATABASE_LOG = re.compile(r"^\d{5,8}\.(log|ldb|sst)$")

#: Rotated logs: app.log.1, app.log.old, app.log.2026-09-21. A plain
#: ``.log`` is handled by the suffix list; this is only for what comes after
#: one. Anchored and restricted, because the earlier loose version matched
#: ``org.gnome.Logs-symbolic.svg``.
_ROTATED = re.compile(r"\.log\.(\d+|old|bak|prev|previous|[\d\-_.T]+)$",
                      re.IGNORECASE)

#: Names that are database machinery sitting next to a log.
SKIP_NAMES = frozenset({
    "LOCK", "CURRENT", "LOG", "LOG.old", "MANIFEST", "IDENTITY",
    "lastlog", "wtmp", "btmp", "utmp", "faillog", "tallylog",
})

#: Compressed logs we can read. bz2 and xz are deliberately left out: they are
#: rare for logs and decompressing them is slow enough to hurt a re-index.
GZIP_SUFFIXES = (".gz",)

#: Skip anything bigger than this by default. A single 4 GB log is almost
#: always a runaway process, and indexing it would dominate the store.
DEFAULT_MAX_BYTES = 512 * 1024 * 1024

#: Read this much of a file to decide whether it is text.
SNIFF_BYTES = 8192

#: How many unreadable directories are reported before the rest are counted
#: silently. A normal machine has a handful — /var/log/audit, /var/log/private
#: — but a misconfigured one could have thousands, and a table with thousands
#: of identical rows in it is not an explanation.
MAX_UNREADABLE_DIRECTORIES = 200

#: The control characters that appear in real text files. Everything else in
#: the C0 range means binary.
_TEXT_CONTROL = frozenset(b"\t\n\r\f\v\b\x1b")


def looks_like_a_log(name: str, parent: str) -> bool:
    """Is a file with this name, in a directory with this name, a log?"""
    if name in SKIP_NAMES or _DATABASE_LOG.match(name):
        return False
    lowered = name.lower()
    stem, _, suffix = lowered.rpartition(".")
    suffix = f".{suffix}" if stem else ""

    if lowered.endswith(GZIP_SUFFIXES):
        lowered = lowered[: -len(".gz")]
        stem, _, suffix = lowered.rpartition(".")
        suffix = f".{suffix}" if stem else ""

    if suffix in LOG_SUFFIXES:
        return True
    if _ROTATED.search(lowered):
        return True
    if lowered.lstrip(".") in LOG_NAMES or stem in LOG_NAMES:
        return True
    if parent in LOG_DIRECTORIES:
        # Inside a directory called "logs", anything that is not obviously a
        # database file is worth sniffing.
        return suffix not in (".db", ".sqlite", ".sqlite3", ".ldb", ".sst",
                              ".lock", ".pid", ".bin", ".dat", ".idx")
    if suffix in HINTED_SUFFIXES and _NAME_HINT.search(lowered):
        return True
    return False


def is_probably_text(path: Path, *, sniff: int = SNIFF_BYTES) -> tuple[bool, str]:
    """Read the first few kilobytes and decide. Returns (verdict, reason)."""
    try:
        with path.open("rb") as handle:
            chunk = handle.read(sniff)
    except OSError as error:
        return False, f"cannot be read ({error.strerror or error})"
    if not chunk:
        return True, ""
    if chunk.startswith(b"\x1f\x8b"):
        return True, ""           # gzip; the reader handles it
    if b"\x00" in chunk:
        return False, "binary (contains null bytes)"
    suspicious = sum(1 for byte in chunk
                     if byte < 32 and byte not in _TEXT_CONTROL or byte == 127)
    if suspicious > len(chunk) * 0.05:
        return False, "binary (mostly non-printable)"
    return True, ""


# ---------------------------------------------------------------------------
# What a crawl produces
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Candidate:
    """One file the crawler looked at, whether or not it will be indexed."""

    path: str
    size: int = 0
    mtime: float = 0.0
    #: Which root it was found under.
    root: str = "config"
    #: The application it appears to belong to, derived from the path.
    app: str = ""
    #: Empty when the file will be indexed; otherwise why it will not be.
    skipped: str = ""
    compressed: bool = False
    symlink: bool = False
    readable: bool = True
    #: True for a *directory* the crawl could not open. Recorded so that a
    #: whole unreadable tree is accounted for rather than vanishing: an
    #: unreadable file already says "not readable by you", and a directory
    #: going silent was the one hole in that promise.
    is_directory: bool = False

    @property
    def usable(self) -> bool:
        return not self.skipped

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def directory(self) -> str:
        return os.path.dirname(self.path)

    def display_path(self, home: str = "") -> str:
        """``~/.config/discord/logs/main.log`` rather than the full path."""
        base = home or os.path.expanduser("~")
        if base and self.path.startswith(base + os.sep):
            return "~" + self.path[len(base):]
        return self.path


@dataclass(slots=True)
class Crawl:
    """Everything one walk found, and what it cost."""

    candidates: list[Candidate] = field(default_factory=list)
    directories: int = 0
    files: int = 0
    elapsed: float = 0.0
    #: Set when the overall time limit ran out, which ends the whole crawl.
    stopped: str = ""
    #: Roots the walk gave up on early: root id -> which limit it hit. The
    #: crawl carries on with the next root rather than abandoning everything,
    #: because one cache directory with half a million shader files must not
    #: cost you /var/log.
    truncated: dict[str, str] = field(default_factory=dict)
    #: Roots that were asked for but are not on this machine.
    missing: tuple[str, ...] = ()
    #: Unreadable directories beyond MAX_UNREADABLE_DIRECTORIES, counted but
    #: not listed one by one.
    unlisted_directories: int = 0

    @property
    def usable(self) -> list[Candidate]:
        return [item for item in self.candidates if item.usable]

    @property
    def skipped(self) -> list[Candidate]:
        return [item for item in self.candidates if not item.usable]

    @property
    def total_bytes(self) -> int:
        return sum(item.size for item in self.usable)

    @property
    def complete(self) -> bool:
        return not self.stopped and not self.truncated

    @property
    def unreadable_directories(self) -> list[Candidate]:
        return [item for item in self.candidates if item.is_directory]

    def limits_hit(self) -> str:
        """A sentence for the UI when the crawl did not see everything."""
        if self.stopped:
            return f"The search stopped after {self.stopped}."
        if self.unlisted_directories:
            return (f"{self.unlisted_directories:,} more directories could not "
                    "be read and are not listed individually.")
        if self.truncated:
            names = ", ".join(sorted(self.truncated))
            return (f"Some places were only partly searched ({names}) because "
                    "they hold far more files than a log directory should. "
                    "Raise the limits in Hunt settings if you need them.")
        return ""

    def by_app(self) -> dict[str, list[Candidate]]:
        grouped: dict[str, list[Candidate]] = {}
        for item in self.usable:
            grouped.setdefault(item.app or "other", []).append(item)
        for entries in grouped.values():
            entries.sort(key=lambda entry: -entry.mtime)
        return dict(sorted(grouped.items(), key=lambda pair: pair[0].lower()))

    def summary(self) -> str:
        parts = [f"{len(self.usable)} log files",
                 f"{len(self.by_app())} applications"]
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
        return " · ".join(parts)


# ---------------------------------------------------------------------------
# The crawl
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Budget:
    """Limits that guarantee the crawl ends.

    Without these, one recursive bind mount or one cache with a million
    entries turns "find my logs" into an application that never comes back.
    Godot's shader cache on this machine holds 453,000 files, which is why
    the file limit applies *per root* rather than to the whole crawl.
    """

    seconds: float = 30.0
    directories_per_root: int = 60_000
    files_per_root: int = 600_000
    max_bytes: int = DEFAULT_MAX_BYTES


def crawl(roots: tuple[Root, ...] | None = None, *,
          budget: Budget | None = None,
          excluded: tuple[str, ...] = (),
          home: Path | None = None,
          on_progress=None) -> Crawl:
    """Walk `roots` and report every candidate log file.

    `excluded` holds glob patterns from the user's settings; anything matching
    one is recorded as skipped with that pattern as the reason, so a file that
    vanishes from the list can be traced to the rule that removed it.
    """
    roots = roots or tuple(item for item in default_roots(home) if not item.optional)
    budget = budget or Budget()
    base = home or Path.home()
    result = Crawl()
    started = time.monotonic()
    seen: set[str] = set()
    missing: list[str] = []

    for root in roots:
        if root.id == "shell":
            _collect_shell_history(base, result, seen)
            continue
        if not root.path.is_dir():
            missing.append(root.id)
            continue
        if on_progress is not None:
            on_progress(str(root.path))
        limit = _walk(root, result, budget, started, excluded, seen, base, on_progress)
        if limit:
            result.truncated[root.id] = limit
        if result.stopped:
            break

    result.missing = tuple(missing)
    result.elapsed = time.monotonic() - started
    result.candidates.sort(key=lambda item: (item.app.lower(), -item.mtime))
    log.info("hunt crawl: %d candidates (%d usable) in %d directories, %.2fs",
             len(result.candidates), len(result.usable), result.directories,
             result.elapsed)
    return result


def _walk(root: Root, result: Crawl, budget: Budget, started: float,
          excluded: tuple[str, ...], seen: set[str], home: Path,
          on_progress) -> str:
    """Breadth-first over one root. Returns the limit it hit, or "".

    Breadth-first rather than depth-first so that a root which does run out
    of budget has at least covered its shallow directories, which is where
    the logs are — ``~/.config/discord/logs`` is three levels down, while the
    half-million files that exhaust the budget are eight levels into a cache.
    """
    pending: list[tuple[str, int]] = [(str(root.path), 0)]
    home_text = str(home)
    directories = files = 0

    while pending:
        directory, depth = pending.pop(0)
        if time.monotonic() - started > budget.seconds:
            result.stopped = f"the {budget.seconds:.0f}s time limit"
            return ""
        if directories >= budget.directories_per_root:
            return f"{budget.directories_per_root:,} directories"

        directories += 1
        result.directories += 1
        if on_progress is not None and result.directories % 500 == 0:
            on_progress(directory)

        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            _note_unreadable(result, directory, root, home_text, error)
            continue

        parent_name = os.path.basename(directory)
        for entry in entries:
            try:
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue

            if is_directory:
                if depth >= root.depth or entry.name in SKIP_DIRECTORIES:
                    continue
                if entry.name.startswith(".") and root.id in ("data", "cache", "flatpak"):
                    # Hidden directories inside an already-hidden tree are
                    # nearly always machinery.
                    continue
                pending.append((entry.path, depth + 1))
                continue

            files += 1
            result.files += 1
            if files >= budget.files_per_root:
                return f"{budget.files_per_root:,} files"
            if entry.path in seen:
                continue
            if not looks_like_a_log(entry.name, parent_name):
                continue
            seen.add(entry.path)
            result.candidates.append(
                _examine(entry, root, budget, excluded, home_text))
    return ""


def _note_unreadable(result: Crawl, directory: str, root: Root, home: str,
                     error: OSError) -> None:
    """Record a directory the crawl could not open, with the reason.

    Without this, ``/var/log/audit`` — mode 0700 root:root, and holding the
    audit trail — disappears from the Sources dialog entirely. An unreadable
    *file* already lands in the Skipped tab saying so; a directory going quiet
    was the one place the tab's promise did not hold, and a log you expected
    and cannot find is worse than one you were told was skipped.
    """
    listed = sum(1 for item in result.candidates if item.is_directory)
    if listed >= MAX_UNREADABLE_DIRECTORIES:
        result.unlisted_directories += 1
        return
    candidate = Candidate(
        path=directory, root=root.id, app=app_for(directory, root, home),
        readable=False, is_directory=True,
        skipped=f"the directory cannot be read ({error.strerror or error})")
    try:
        info = os.stat(directory)
    except OSError:
        pass
    else:
        candidate.mtime = info.st_mtime
    result.candidates.append(candidate)


def _examine(entry: os.DirEntry, root: Root, budget: Budget,
             excluded: tuple[str, ...], home: str) -> Candidate:
    """Decide whether one matching file is worth indexing, and why not."""
    candidate = Candidate(path=entry.path, root=root.id,
                          app=app_for(entry.path, root, home))
    try:
        info = entry.stat(follow_symlinks=True)
    except OSError as error:
        candidate.skipped = f"cannot be read ({error.strerror or error})"
        candidate.readable = False
        return candidate

    candidate.size = info.st_size
    candidate.mtime = info.st_mtime
    candidate.symlink = entry.is_symlink()
    candidate.compressed = entry.name.lower().endswith(GZIP_SUFFIXES)

    if not stat.S_ISREG(info.st_mode):
        candidate.skipped = "not a regular file"
        return candidate
    for pattern in excluded:
        if _matches(entry.path, pattern):
            candidate.skipped = f"excluded by {pattern}"
            return candidate
    if info.st_size == 0:
        candidate.skipped = "empty"
        return candidate
    if info.st_size > budget.max_bytes:
        candidate.skipped = (f"larger than the {budget.max_bytes // (1024 * 1024)} MB "
                             "limit")
        return candidate
    if not os.access(entry.path, os.R_OK):
        candidate.skipped = "not readable by you"
        candidate.readable = False
        return candidate

    text, reason = is_probably_text(Path(entry.path))
    if not text:
        candidate.skipped = reason
    return candidate


def _collect_shell_history(home: Path, result: Crawl, seen: set[str]) -> None:
    """The opt-in root. A fixed list, never a pattern."""
    for relative in SHELL_HISTORY_FILES:
        path = home / relative
        if not path.is_file() or str(path) in seen:
            continue
        seen.add(str(path))
        try:
            info = path.stat()
        except OSError:
            continue
        candidate = Candidate(path=str(path), size=info.st_size,
                              mtime=info.st_mtime, root="shell", app="shell history")
        if info.st_size == 0:
            candidate.skipped = "empty"
        result.candidates.append(candidate)
        result.files += 1


def _matches(path: str, pattern: str) -> bool:
    """A user exclusion glob, matched against the whole path and the name."""
    from fnmatch import fnmatch

    return fnmatch(path, pattern) or fnmatch(os.path.basename(path), pattern)


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------

#: Path components that describe a location rather than an application, so
#: they are stepped over when working out which application a log belongs to.
_GENERIC_COMPONENTS = frozenset({
    "logs", "log", "Logs", "Log", "_logs", "var", "app", "share", "state",
    "cache", "config", "local", "crashlogs", "CrashReports", "diagnostics",
})


def app_for(path: str, root: Root, home: str = "") -> str:
    """Which application a log file belongs to, from where it sits.

    ``~/.config/discord/logs/discord_utils.log`` is Discord's. So is
    ``~/.var/app/com.discordapp.Discord/config/discord/logs/…`` — but that one
    is more usefully labelled by its flatpak id, because the user has both.
    """
    try:
        relative = Path(path).relative_to(root.path)
    except ValueError:
        return root.id

    parts = list(relative.parts[:-1])
    if root.id == "flatpak" and parts:
        return parts[0]
    if root.id == "system":
        return "system"
    if root.id == "npm":
        return "npm"
    if root.id == "home":
        name = Path(path).name.lstrip(".")
        return name.split(".")[0] or "home"
    if root.id == "tmp":
        return parts[0] if parts else "tmp"

    for part in parts:
        if part not in _GENERIC_COMPONENTS and not part.startswith("."):
            return part
    return parts[0] if parts else root.id


def scan_one(path: Path, *, home: Path | None = None) -> Candidate:
    """Examine a single file the user chose by hand, applying the same rules."""
    candidate = Candidate(path=str(path), root="custom", app=path.parent.name)
    try:
        info = path.stat()
    except OSError as error:
        candidate.skipped = f"cannot be read ({error.strerror or error})"
        return candidate
    candidate.size = info.st_size
    candidate.mtime = info.st_mtime
    candidate.compressed = path.name.lower().endswith(GZIP_SUFFIXES)
    if not path.is_file():
        candidate.skipped = "not a regular file"
        return candidate
    if info.st_size == 0:
        candidate.skipped = "empty"
        return candidate
    text, reason = is_probably_text(path)
    if not text:
        candidate.skipped = reason
    return candidate
