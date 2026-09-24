"""A snapshot of the boot chain, and what changed since.

Without a TPM measuring the boot, the practical way to answer "has anything
changed?" is to write down what is there now and compare later. That is all
this is: a JSON file of hashes, sizes, modes and modification times for the
files that decide what runs at boot.

It is honest about its limits, and those limits are worth stating plainly:

* It compares files, not what actually ran. A firmware-level implant is
  invisible to it. Measured boot is the real answer; this is the one available
  on a machine that boots with GRUB.
* ClamGuard does not run as root, so files like ``/boot/initramfs-*.img`` — mode
  0600 — cannot be hashed. Those are recorded by size, mode and timestamp
  instead, and the drift report says which ones only got the weaker check.
* The baseline lives in the user's own data directory, so anything running as
  that user could edit it. It raises the cost of a quiet change; it does not
  make one impossible.

Recording a baseline is something the user asks for explicitly. Nothing here
runs on its own.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime

from .. import paths
from ..logging_setup import get_logger

log = get_logger(__name__)

BASELINE_FILE = "boot-baseline.json"

#: What gets recorded. Everything here either runs at boot or decides what
#: does. Package-managed directories such as /etc/xdg/autostart are left out:
#: they change on every update and the noise would bury a real change.
WATCHED_ROOTS: tuple[str, ...] = (
    "/boot",
    "/etc/systemd/system",
    "/etc/modprobe.d",
    "/etc/udev/rules.d",
    "/etc/cron.d",
    "/etc/ld.so.preload",
    "~/.config/autostart",
    "~/.config/systemd/user",
)

#: Guard rails, so a machine with an unusual /boot cannot turn a snapshot into
#: a disk-bound crawl.
MAX_ENTRIES = 6000
MAX_HASH_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class Entry:
    """One recorded file."""

    path: str
    size: int
    mode: int
    mtime: float
    uid: int
    #: "" when the file could not be read; the drift report says so.
    sha256: str = ""

    @property
    def hashed(self) -> bool:
        return bool(self.sha256)

    def to_dict(self) -> dict:
        data = {"size": self.size, "mode": self.mode,
                "mtime": round(self.mtime, 3), "uid": self.uid}
        if self.sha256:
            data["sha256"] = self.sha256
        return data

    @classmethod
    def from_dict(cls, path: str, data: dict) -> "Entry":
        return cls(
            path=path,
            size=int(data.get("size", 0)),
            mode=int(data.get("mode", 0)),
            mtime=float(data.get("mtime", 0.0)),
            uid=int(data.get("uid", 0)),
            sha256=str(data.get("sha256", "")),
        )


@dataclass(frozen=True)
class Change:
    """One difference between the baseline and now."""

    path: str
    #: "added" | "removed" | "content" | "permissions" | "owner" | "timestamp"
    kind: str
    detail: str
    when: float = 0.0

    @property
    def serious(self) -> bool:
        return self.kind in ("added", "content", "permissions", "owner")


@dataclass
class Drift:
    """Everything that changed, and a guess at whether it was routine."""

    changes: list[Change] = field(default_factory=list)
    #: Files whose content could not be hashed, then or now.
    unhashed: list[str] = field(default_factory=list)
    baseline_taken_at: str = ""
    baseline_kernel: str = ""

    @property
    def empty(self) -> bool:
        return not self.changes

    def of(self, kind: str) -> list[Change]:
        return [item for item in self.changes if item.kind == kind]

    @property
    def serious(self) -> list[Change]:
        return [item for item in self.changes if item.serious]

    def looks_like_a_kernel_update(self) -> bool:
        """A heuristic, labelled as one wherever it is shown.

        A package upgrade rewrites a kernel, its initramfs and usually the
        bootloader configuration, all within a minute or two of each other. A
        single file under /boot changing on its own, or files changing hours
        apart, does not look like that.
        """
        touched = [item for item in self.changes
                   if item.path.startswith("/boot") and item.when]
        if len(touched) < 2:
            return False
        stamps = sorted(item.when for item in touched)
        if stamps[-1] - stamps[0] > 900:      # more than fifteen minutes apart
            return False
        names = " ".join(os.path.basename(item.path) for item in touched)
        has_kernel = any(word in names for word in ("vmlinuz", "vmlinux", "kernel"))
        has_initramfs = any(word in names for word in ("initramfs", "initrd", "ucode"))
        return has_kernel and has_initramfs

    def summary(self) -> str:
        if self.empty:
            return "Nothing has changed since the baseline was recorded."
        parts = []
        for kind, word in (("added", "added"), ("removed", "removed"),
                           ("content", "changed"), ("permissions", "re-permissioned"),
                           ("owner", "changed owner"), ("timestamp", "touched")):
            number = len(self.of(kind))
            if number:
                parts.append(f"{number} {word}")
        return ", ".join(parts)


@dataclass(frozen=True)
class Baseline:
    """What the boot chain looked like at one moment."""

    entries: dict[str, Entry] = field(default_factory=dict)
    taken_at: str = ""
    kernel: str = ""
    hostname: str = ""
    roots: tuple[str, ...] = ()

    @property
    def exists(self) -> bool:
        """Whether a baseline was ever recorded — not whether it found anything.

        Keyed on the timestamp rather than the entry count, because "I recorded
        a baseline of an empty ESP" and "I have never recorded a baseline" are
        different states, and treating them as one would mean a file appearing
        in that empty directory never showed up as drift.
        """
        return bool(self.taken_at)

    @property
    def hashed_count(self) -> int:
        return sum(1 for entry in self.entries.values() if entry.hashed)

    def to_dict(self) -> dict:
        return {
            "taken_at": self.taken_at,
            "kernel": self.kernel,
            "hostname": self.hostname,
            "roots": list(self.roots),
            "entries": {path: entry.to_dict()
                        for path, entry in sorted(self.entries.items())},
        }

    def save(self, path=None) -> None:
        target = path or default_path()
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(self.to_dict(), indent=1) + "\n",
                                 encoding="utf-8")
            temporary.replace(target)
        except OSError as exc:
            log.error("cannot save the boot baseline to %s: %s", target, exc)
            raise

    @classmethod
    def load(cls, path=None) -> "Baseline":
        source = path or default_path()
        if not source.is_file():
            return cls()
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("cannot read the boot baseline (%s)", exc)
            return cls()
        if not isinstance(data, dict):
            return cls()
        entries = {
            str(path): Entry.from_dict(str(path), value)
            for path, value in (data.get("entries") or {}).items()
            if isinstance(value, dict)
        }
        return cls(
            entries=entries,
            taken_at=str(data.get("taken_at", "")),
            kernel=str(data.get("kernel", "")),
            hostname=str(data.get("hostname", "")),
            roots=tuple(str(item) for item in data.get("roots", ())),
        )


def default_path():
    return paths.DATA_DIR / BASELINE_FILE


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def record(roots: tuple[str, ...] = WATCHED_ROOTS,
           on_progress=None) -> Baseline:
    """Walk the watched roots and hash what can be read.

    Runs on a worker thread — it does real I/O — and calls ``on_progress(path)``
    as it goes so the UI can say what it is doing.
    """
    entries: dict[str, Entry] = {}
    for root in roots:
        expanded = os.path.expanduser(root)
        for path in _walk(expanded):
            if len(entries) >= MAX_ENTRIES:
                log.warning("boot baseline stopped at %d entries", MAX_ENTRIES)
                break
            entry = _record_one(path)
            if entry is not None:
                entries[path] = entry
                if on_progress is not None:
                    on_progress(path)

    return Baseline(
        entries=entries,
        taken_at=datetime.now().isoformat(timespec="seconds"),
        kernel=_kernel_release(),
        hostname=_hostname(),
        roots=tuple(roots),
    )


def _walk(root: str):
    """Regular files under `root`, without following symlinks out of it."""
    if os.path.isfile(root):
        yield root
        return
    if not os.path.isdir(root):
        return
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        subdirectories.sort()
        for name in sorted(names):
            yield os.path.join(directory, name)


def _record_one(path: str) -> Entry | None:
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not (info.st_mode & 0o170000) == 0o100000:   # regular files only
        return None

    digest = ""
    if info.st_size <= MAX_HASH_BYTES:
        digest = _sha256(path)
    return Entry(path=path, size=info.st_size, mode=info.st_mode & 0o7777,
                 mtime=info.st_mtime, uid=info.st_uid, sha256=digest)


def _sha256(path: str) -> str:
    """The file's digest, or "" if it cannot be read. Never raises."""
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError:
        return ""
    return hasher.hexdigest()


def _kernel_release() -> str:
    try:
        return os.uname().release
    except OSError:
        return ""


def _hostname() -> str:
    try:
        return os.uname().nodename
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Comparing
# ---------------------------------------------------------------------------


def compare(baseline: Baseline, current: Baseline) -> Drift:
    """What changed between two snapshots."""
    drift = Drift(baseline_taken_at=baseline.taken_at,
                  baseline_kernel=baseline.kernel)
    if not baseline.exists:
        return drift

    for path, now in sorted(current.entries.items()):
        before = baseline.entries.get(path)
        if before is None:
            drift.changes.append(Change(
                path, "added",
                f"new file, {now.size} bytes, mode {now.mode:04o}", now.mtime))
            continue

        if before.hashed and now.hashed:
            if before.sha256 != now.sha256:
                drift.changes.append(Change(
                    path, "content",
                    f"contents differ ({before.sha256[:12]}… → {now.sha256[:12]}…)",
                    now.mtime))
        else:
            drift.unhashed.append(path)
            if before.size != now.size:
                drift.changes.append(Change(
                    path, "content",
                    f"size changed {before.size} → {now.size} "
                    "(contents could not be hashed)", now.mtime))
            elif abs(before.mtime - now.mtime) > 1:
                drift.changes.append(Change(
                    path, "timestamp",
                    f"modified {_stamp(now.mtime)}, same size "
                    "(contents could not be hashed)", now.mtime))

        if before.mode != now.mode:
            drift.changes.append(Change(
                path, "permissions",
                f"mode {before.mode:04o} → {now.mode:04o}", now.mtime))
        if before.uid != now.uid:
            drift.changes.append(Change(
                path, "owner",
                f"owner uid {before.uid} → {now.uid}", now.mtime))

    for path, before in sorted(baseline.entries.items()):
        if path not in current.entries:
            drift.changes.append(Change(
                path, "removed", f"was {before.size} bytes", before.mtime))

    return drift


def _stamp(when: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(when))
