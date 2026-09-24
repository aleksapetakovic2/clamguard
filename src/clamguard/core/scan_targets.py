"""Deciding what to scan, and walking it.

ClamGuard enumerates the files itself rather than handing a directory to
clamscan. That costs a directory walk up front and buys three things:

* a real progress bar — we know the denominator before we start;
* per-file output from ``clamdscan``, which prints one line per *file* in a
  file list but only one line per *directory* when given a directory;
* control over what is skipped, including the quarantine vault, pseudo
  filesystems and anything the user excluded.

The walk is interruptible and is always run on a worker thread.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator

from . import paths
from .logging_setup import get_logger

log = get_logger(__name__)


class ScanKind(str, Enum):
    """The preset scopes offered on the scan page."""

    QUICK = "quick"
    FULL = "full"
    HOME = "home"
    REMOVABLE = "removable"
    CUSTOM = "custom"

    @property
    def title(self) -> str:
        return {
            ScanKind.QUICK: "Quick scan",
            ScanKind.FULL: "Full system scan",
            ScanKind.HOME: "Home folder scan",
            ScanKind.REMOVABLE: "Removable media scan",
            ScanKind.CUSTOM: "Custom scan",
        }[self]

    @property
    def description(self) -> str:
        return {
            ScanKind.QUICK: "The places malware actually lands: downloads, the "
                            "desktop, temporary folders and the trash.",
            ScanKind.FULL: "Every file on every local filesystem. Takes hours.",
            ScanKind.HOME: "Everything in your home folder.",
            ScanKind.REMOVABLE: "USB sticks, memory cards and external drives "
                                "that are mounted right now.",
            ScanKind.CUSTOM: "Files and folders you choose.",
        }[self]

    @property
    def icon(self) -> str:
        return {
            ScanKind.QUICK: "zap",
            ScanKind.FULL: "hard-drive",
            ScanKind.HOME: "home",
            ScanKind.REMOVABLE: "usb",
            ScanKind.CUSTOM: "folder",
        }[self]


#: Directories a quick scan looks at, relative to the user's home unless
#: absolute. Anything that does not exist is quietly skipped.
QUICK_SCAN_CANDIDATES: tuple[str, ...] = (
    "Downloads",
    "Desktop",
    "Documents",
    ".local/share/Trash/files",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
)

#: Filesystem types that are not real files on a disk. Walking them is at best
#: pointless and at worst an infinite loop.
PSEUDO_FILESYSTEMS = frozenset({
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs",
    "debugfs", "tracefs", "configfs", "fusectl", "pstore", "bpf", "hugetlbfs",
    "mqueue", "binfmt_misc", "autofs", "rpc_pipefs", "selinuxfs", "efivarfs",
    "nsfs", "ramfs",
})

#: Mount points a full scan never descends into, whatever they are mounted as.
ALWAYS_EXCLUDED_DIRECTORIES: tuple[str, ...] = (
    "/proc", "/sys", "/dev", "/run", "/lost+found",
    "/var/lib/clamav",          # the signature database scans itself otherwise
    "/var/cache/pacman/pkg",    # large, immutable, and re-downloadable
)

#: Where removable media usually appears.
REMOVABLE_ROOTS: tuple[str, ...] = ("/run/media", "/media", "/mnt")


@dataclass
class Enumeration:
    """The result of walking the targets: what will actually be scanned."""

    files: int = 0
    total_bytes: int = 0
    list_path: Path | None = None
    skipped_unreadable: int = 0
    skipped_too_large: int = 0
    skipped_special: int = 0
    errors: list[str] = field(default_factory=list)
    cancelled: bool = False

    @property
    def empty(self) -> bool:
        return self.files == 0


def quick_scan_paths(extra: list[str] | None = None) -> list[Path]:
    """Existing directories a quick scan should cover."""
    if extra:
        chosen = [Path(os.path.expanduser(item)) for item in extra]
        return [path for path in chosen if path.exists()]

    home = Path.home()
    found: list[Path] = []
    for candidate in QUICK_SCAN_CANDIDATES:
        path = Path(candidate) if candidate.startswith("/") else home / candidate
        if path.is_dir():
            found.append(path)
    return found


def full_scan_paths() -> list[Path]:
    """The root of every local filesystem worth scanning."""
    return [Path("/")]


def home_scan_paths() -> list[Path]:
    return [Path.home()]


def removable_scan_paths() -> list[Path]:
    """Mounted removable media, as directories.

    /run/media/<user>/<label> is the udisks2 convention used by most desktops;
    /media and /mnt catch the rest.
    """
    found: list[Path] = []
    for root in REMOVABLE_ROOTS:
        base = Path(root)
        if not base.is_dir():
            continue
        try:
            for child in base.iterdir():
                if not child.is_dir():
                    continue
                # /run/media/<user>/ holds one directory per mounted volume.
                if root == "/run/media" and child.name == os.environ.get("USER", ""):
                    found.extend(item for item in child.iterdir() if item.is_dir())
                elif os.path.ismount(child):
                    found.append(child)
        except OSError as error:
            log.debug("cannot list %s: %s", base, error)
    return found


def paths_for(kind: ScanKind, custom: list[str] | None = None,
              quick_override: list[str] | None = None) -> list[Path]:
    """The starting points for a scan of the given kind."""
    if kind is ScanKind.QUICK:
        return quick_scan_paths(quick_override)
    if kind is ScanKind.FULL:
        return full_scan_paths()
    if kind is ScanKind.HOME:
        return home_scan_paths()
    if kind is ScanKind.REMOVABLE:
        return removable_scan_paths()
    return [Path(os.path.expanduser(item)) for item in (custom or [])]


# ---------------------------------------------------------------------------
# Walking
# ---------------------------------------------------------------------------


def pseudo_filesystem_mountpoints() -> set[str]:
    """Mount points whose filesystem type is not a real one.

    Read from /proc/self/mounts, which is the authoritative list, so a scan
    never wanders into /proc or a FUSE gvfs mount that would hang on it.
    """
    # A mount point can appear more than once — /efi is commonly an autofs
    # trigger with the real vfat mounted over it. The last entry wins, which is
    # what the kernel itself uses, so build a map rather than a set.
    by_mountpoint: dict[str, str] = {}
    try:
        with open("/proc/self/mounts", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 3:
                    by_mountpoint[_unescape_mount(parts[1])] = parts[2]
    except OSError:
        return set()
    return {point for point, kind in by_mountpoint.items() if kind in PSEUDO_FILESYSTEMS}


def _unescape_mount(path: str) -> str:
    """/proc/self/mounts escapes spaces as \\040 and friends."""
    for escape, character in (("\\040", " "), ("\\011", "\t"),
                              ("\\012", "\n"), ("\\134", "\\")):
        path = path.replace(escape, character)
    return path


class TargetWalker:
    """Walks scan targets and writes the file list clamscan will be given.

    Call :meth:`enumerate` from a worker thread. Set :attr:`cancelled` from any
    thread to stop it.
    """

    def __init__(
        self,
        targets: list[Path],
        *,
        exclude_patterns: list[str] | None = None,
        max_file_bytes: int = 0,
        follow_symlinks: bool = False,
        cross_filesystems: bool = False,
        skip_hidden: bool = False,
    ) -> None:
        self.targets = targets
        self.max_file_bytes = max_file_bytes
        self.follow_symlinks = follow_symlinks
        self.cross_filesystems = cross_filesystems
        self.skip_hidden = skip_hidden
        self.cancelled = False

        self._excludes = _compile(exclude_patterns or [])
        self._pseudo = pseudo_filesystem_mountpoints()
        self._always_excluded = {os.path.realpath(p) for p in ALWAYS_EXCLUDED_DIRECTORIES}
        # Never scan our own vault: the payloads are neutralised, but a user
        # should not see their quarantine reported as fresh detections.
        self._always_excluded.add(os.path.realpath(paths.QUARANTINE_DIR))

    # -- the public call --------------------------------------------------

    def enumerate(self, list_path: Path,
                  on_progress: Callable[[int, int], None] | None = None) -> Enumeration:
        """Write every file to scan into `list_path`, one per line.

        `on_progress` is called with (files, bytes) every so often. It runs on
        the worker thread, so it must only marshal to the UI, not touch it.
        """
        result = Enumeration(list_path=list_path)
        list_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with list_path.open("w", encoding="utf-8", errors="surrogateescape") as handle:
                for path, size in self._walk(result):
                    if self.cancelled:
                        result.cancelled = True
                        break
                    handle.write(f"{path}\n")
                    result.files += 1
                    result.total_bytes += size
                    if on_progress and result.files % 500 == 0:
                        on_progress(result.files, result.total_bytes)
        except OSError as error:
            result.errors.append(f"Could not write the scan list: {error}")

        if on_progress:
            on_progress(result.files, result.total_bytes)
        return result

    # -- the walk ---------------------------------------------------------

    def _walk(self, result: Enumeration) -> Iterator[tuple[str, int]]:
        seen_directories: set[str] = set()
        for target in self.targets:
            if self.cancelled:
                return
            if target.is_file():
                entry = self._consider_file(str(target), result)
                if entry is not None:
                    yield entry
                continue
            if not target.is_dir():
                result.errors.append(f"{target} does not exist.")
                continue
            yield from self._walk_directory(target, result, seen_directories)

    def _walk_directory(self, root: Path, result: Enumeration,
                        seen: set[str]) -> Iterator[tuple[str, int]]:
        try:
            root_device = root.stat().st_dev
        except OSError as error:
            result.errors.append(f"Cannot read {root}: {error}")
            return

        for directory, subdirectories, filenames in os.walk(
            root, topdown=True, followlinks=self.follow_symlinks,
            onerror=lambda error: self._note_error(error, result),
        ):
            if self.cancelled:
                return

            real = os.path.realpath(directory)
            # os.walk can reach the same directory twice through bind mounts
            # or followed symlinks; visiting it twice would double-count.
            if real in seen:
                subdirectories[:] = []
                continue
            seen.add(real)

            subdirectories[:] = [
                name for name in subdirectories
                if self._should_descend(os.path.join(directory, name), root_device)
            ]

            for name in filenames:
                if self.cancelled:
                    return
                if self.skip_hidden and name.startswith("."):
                    continue
                entry = self._consider_file(os.path.join(directory, name), result)
                if entry is not None:
                    yield entry

    def _should_descend(self, path: str, root_device: int) -> bool:
        name = os.path.basename(path)
        if self.skip_hidden and name.startswith("."):
            return False

        real = os.path.realpath(path)
        if real in self._always_excluded or path in self._pseudo or real in self._pseudo:
            return False
        if self._matches_exclude(path):
            return False
        if not self.follow_symlinks and os.path.islink(path):
            return False

        try:
            info = os.stat(path, follow_symlinks=self.follow_symlinks)
        except OSError:
            return False
        if not self.cross_filesystems and info.st_dev != root_device:
            return False
        return True

    def _consider_file(self, path: str, result: Enumeration) -> tuple[str, int] | None:
        """Decide whether one file goes into the list, and why not if it does not."""
        if self._matches_exclude(path):
            return None
        if not self.follow_symlinks and os.path.islink(path):
            result.skipped_special += 1
            return None
        try:
            info = os.stat(path, follow_symlinks=self.follow_symlinks)
        except OSError:
            result.skipped_unreadable += 1
            return None

        if not stat.S_ISREG(info.st_mode):
            # Sockets, fifos and device nodes: reading one can block forever.
            result.skipped_special += 1
            return None
        if self.max_file_bytes and info.st_size > self.max_file_bytes:
            result.skipped_too_large += 1
            return None
        if not os.access(path, os.R_OK):
            result.skipped_unreadable += 1
            return None
        if "\n" in path:
            # The file list is newline-delimited, so such a name cannot be
            # expressed in it. Vanishingly rare, but silently dropping it
            # would be worse than saying so.
            result.errors.append(f"Skipped a file whose name contains a newline: {path!r}")
            return None
        return path, info.st_size

    def _matches_exclude(self, path: str) -> bool:
        return any(pattern.search(path) for pattern in self._excludes)

    @staticmethod
    def _note_error(error: OSError, result: Enumeration) -> None:
        result.skipped_unreadable += 1
        if len(result.errors) < 50:
            result.errors.append(f"{error.filename}: {error.strerror}")


def _compile(patterns: list[str]) -> list[re.Pattern]:
    """Turn user-supplied exclusions into regexes, ignoring broken ones."""
    compiled = []
    for pattern in patterns:
        if not pattern.strip():
            continue
        try:
            compiled.append(re.compile(pattern))
        except re.error as error:
            log.warning("ignoring invalid exclude pattern %r: %s", pattern, error)
    return compiled
