"""The only way a check is allowed to look at the system.

Every check takes a :class:`Probe` and reads the machine through it. Nothing
else. That single rule buys three things:

* **Testability.** :class:`FakeProbe` takes dictionaries, so every check can be
  driven with synthetic input and no machine state at all. This is why
  ``tests/test_boot_checks.py`` can assert the exact wording of a finding about
  Secure Boot on a machine that has none.
* **Speed.** Eight checks read ``/proc/cmdline`` and four run
  ``systemd-analyze blame``. The probe caches by path and by argument vector,
  so each one happens once per run.
* **Honesty.** The probe records everything it touched, which is what the
  "what did you look at?" panel shows. A security tool that cannot be audited
  is asking for trust it has not earned.

A probe is **read-only by construction**: there is no method here that writes,
creates, deletes or executes anything with side effects. The command runner is
restricted to an allow-list of inspection tools for exactly that reason.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..logging_setup import get_logger
from ..process import CommandResult, run, which

log = get_logger(__name__)

#: Commands a check may run. Everything here only reports state; none of them
#: change anything. A check that needs something not on this list should be
#: reading a file instead — and if it genuinely cannot, the addition belongs in
#: a review, not in a check.
ALLOWED_COMMANDS: frozenset[str] = frozenset({
    "bootctl",          # bootloader, Secure Boot, TPM measurement summary
    "efibootmgr",       # EFI boot entries and order
    "findmnt",          # mounted filesystems and their options
    "journalctl",       # this boot's messages, kernel ring buffer included
    "lsblk",            # block devices, filesystems, encryption layers
    "mokutil",          # Secure Boot state and enrolled keys
    "systemctl",        # unit state
    "systemd-analyze",  # boot timing, critical chain, unit exposure scores
    "uname",            # kernel release
})

#: Nothing a check runs should take longer than this.
DEFAULT_TIMEOUT = 15.0


@dataclass(frozen=True)
class FileRead:
    """The result of reading a file, including the interesting failures.

    "Absent" and "present but not readable by you" mean completely different
    things to a boot analyzer — a missing ``/etc/ld.so.preload`` is good news,
    an unreadable ``/boot/initramfs-linux.img`` is just a permission the user
    does not have — so they are kept apart rather than both becoming ``None``.
    """

    path: str
    text: str = ""
    error: str = ""
    exists: bool = False

    @property
    def ok(self) -> bool:
        return self.exists and not self.error

    @property
    def missing(self) -> bool:
        return not self.exists

    @property
    def denied(self) -> bool:
        return self.exists and "permission" in self.error.lower()

    def lines(self) -> list[str]:
        return [line for line in self.text.splitlines() if line.strip()]

    def first_line(self) -> str:
        for line in self.text.splitlines():
            if line.strip():
                return line.strip()
        return ""


@dataclass
class ProbeRecord:
    """One thing the probe looked at, for the audit panel."""

    kind: str          # "file" | "command" | "listdir" | "stat"
    target: str
    outcome: str       # "ok", "missing", "denied", "exit 1", …
    seconds: float = 0.0

    def __str__(self) -> str:
        return f"{self.kind:8} {self.target}  → {self.outcome} ({self.seconds * 1000:.0f}ms)"


@dataclass
class Probe:
    """Cached, read-only access to the running system."""

    #: Everything the probe touched, in order.
    records: list[ProbeRecord] = field(default_factory=list)
    _files: dict[str, FileRead] = field(default_factory=dict, repr=False)
    _commands: dict[tuple[str, ...], CommandResult] = field(default_factory=dict, repr=False)
    _listings: dict[str, list[str]] = field(default_factory=dict, repr=False)
    _stats: dict[str, os.stat_result | None] = field(default_factory=dict, repr=False)

    # -- files ------------------------------------------------------------

    def file(self, path: str | Path) -> FileRead:
        """Read a text file, cached. Never raises, never blocks for long."""
        key = str(path)
        if key in self._files:
            return self._files[key]

        started = time.monotonic()
        result = self._read_now(key)
        elapsed = time.monotonic() - started
        outcome = "ok" if result.ok else ("missing" if result.missing else result.error)
        self.records.append(ProbeRecord("file", key, outcome, elapsed))
        self._files[key] = result
        return result

    @staticmethod
    def _read_now(path: str) -> FileRead:
        try:
            # Sysfs and procfs files report size 0, so reading has to be
            # unconditional rather than size-guarded. They are all tiny.
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return FileRead(path, handle.read(), exists=True)
        except FileNotFoundError:
            return FileRead(path, exists=False, error="no such file")
        except NotADirectoryError:
            return FileRead(path, exists=False, error="no such file")
        except IsADirectoryError:
            return FileRead(path, exists=True, error="is a directory")
        except PermissionError:
            return FileRead(path, exists=True, error="permission denied")
        except OSError as exc:
            return FileRead(path, exists=True, error=str(exc))

    def text(self, path: str | Path) -> str:
        """The contents of a file, or "" if it cannot be read.

        What most checks want. Use :meth:`file` when the difference between
        "missing" and "not allowed" matters.
        """
        return self.file(path).text

    def value(self, path: str | Path) -> str:
        """A one-line sysfs/procfs value, stripped. "" when unavailable."""
        return self.file(path).first_line()

    def read_bytes(self, path: str | Path, limit: int = 1 << 20) -> bytes | None:
        """Raw bytes, for the EFI variables, which are not text."""
        key = f"bytes:{path}"
        started = time.monotonic()
        try:
            with open(path, "rb") as handle:
                data = handle.read(limit)
        except OSError as exc:
            self.records.append(ProbeRecord("file", key, str(exc),
                                            time.monotonic() - started))
            return None
        self.records.append(ProbeRecord("file", key, f"{len(data)}B",
                                        time.monotonic() - started))
        return data

    def exists(self, path: str | Path) -> bool:
        return self.stat(path) is not None

    def is_dir(self, path: str | Path) -> bool:
        info = self.stat(path)
        return info is not None and os.path.isdir(str(path))

    def stat(self, path: str | Path, *, follow: bool = False) -> os.stat_result | None:
        """Stat a path, cached. By default a symlink is *not* followed.

        The default matters: a symlink's own mode is always 0777, so following
        or not following changes the answer completely. Directory walks want
        lstat so they do not descend through a link twice; permission checks on
        a named directory want the target, because /bin being a symlink to
        /usr/bin is not a world-writable /bin.
        """
        key = ("follow:" if follow else "") + str(path)
        if key in self._stats:
            return self._stats[key]
        started = time.monotonic()
        try:
            info: os.stat_result | None = os.stat(path) if follow else os.lstat(path)
            outcome = "ok"
        except OSError as exc:
            info, outcome = None, exc.strerror or "unavailable"
        self.records.append(ProbeRecord("stat", key, outcome, time.monotonic() - started))
        self._stats[key] = info
        return info

    def listdir(self, path: str | Path) -> list[str]:
        """Sorted names in a directory, or [] if it cannot be listed."""
        key = str(path)
        if key in self._listings:
            return self._listings[key]
        started = time.monotonic()
        try:
            names = sorted(os.listdir(key))
            outcome = f"{len(names)} entries"
        except OSError as exc:
            names, outcome = [], exc.strerror or "unavailable"
        self.records.append(ProbeRecord("listdir", key, outcome,
                                        time.monotonic() - started))
        self._listings[key] = names
        return names

    def files_in(self, path: str | Path, suffix: str = "") -> list[str]:
        """Full paths of the regular files directly inside a directory."""
        base = str(path)
        found = []
        for name in self.listdir(base):
            if suffix and not name.endswith(suffix):
                continue
            full = os.path.join(base, name)
            info = self.stat(full)
            if info is not None:
                found.append(full)
        return found

    # -- commands ---------------------------------------------------------

    def run(self, program: str, *args: str, timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        """Run an inspection command, cached by its full argument vector.

        Refuses anything not in :data:`ALLOWED_COMMANDS`, so a check cannot
        quietly grow the set of things this tool executes on a user's machine.
        """
        if program not in ALLOWED_COMMANDS:
            raise ValueError(
                f"{program!r} is not an allowed inspection command. "
                "The Boot Analyzer only runs read-only tools; see ALLOWED_COMMANDS."
            )
        key = (program, *args)
        if key in self._commands:
            return self._commands[key]

        started = time.monotonic()
        if which(program) is None:
            result = CommandResult(program, args, -1, "", "", error=f"{program} not installed")
        else:
            result = run(program, list(args), timeout=timeout)
        elapsed = time.monotonic() - started

        outcome = "ok" if result.ok else (result.error or f"exit {result.exit_code}")
        self.records.append(ProbeRecord("command", " ".join(key), outcome, elapsed))
        self._commands[key] = result
        return result

    def available(self, program: str) -> bool:
        """Is this tool installed? Cached through :func:`core.process.which`."""
        return which(program) is not None

    # -- things several checks want, parsed once --------------------------

    def sysctl(self, key: str) -> str:
        """A sysctl value read straight from /proc/sys. "" when absent.

        Read rather than shelled out to, because ``sysctl(8)`` is not installed
        everywhere and the file is the same answer without a subprocess.
        """
        return self.value("/proc/sys/" + key.replace(".", "/"))

    def sysctl_int(self, key: str) -> int | None:
        raw = self.sysctl(key)
        try:
            return int(raw.split()[0])
        except (ValueError, IndexError):
            return None

    def kernel_cmdline(self) -> str:
        return self.value("/proc/cmdline")

    def cmdline_parameters(self) -> dict[str, str]:
        """``/proc/cmdline`` as a mapping. A bare flag maps to "".

        Duplicated parameters keep the last value, which is what the kernel
        itself does for most options.
        """
        parameters: dict[str, str] = {}
        for token in self.kernel_cmdline().split():
            name, separator, value = token.partition("=")
            parameters[name] = value if separator else ""
        return parameters

    def os_release(self) -> dict[str, str]:
        """``/etc/os-release`` parsed into a dictionary."""
        fields: dict[str, str] = {}
        for line in self.file("/etc/os-release").lines():
            if line.startswith("#") or "=" not in line:
                continue
            name, _, value = line.partition("=")
            fields[name.strip()] = value.strip().strip('"').strip("'")
        return fields

    def kernel_release(self) -> str:
        return self.value("/proc/sys/kernel/osrelease")

    def hostname(self) -> str:
        return self.value("/proc/sys/kernel/hostname") or "this machine"

    def mounts(self) -> list[dict[str, str]]:
        """Mounted filesystems from ``/proc/self/mountinfo``.

        Parsed from the file rather than ``findmnt`` so it works without
        util-linux and costs no subprocess. Each entry has ``target``,
        ``source``, ``fstype`` and ``options`` (the combined VFS and
        superblock options, comma-separated).
        """
        entries: list[dict[str, str]] = []
        for line in self.file("/proc/self/mountinfo").lines():
            # 36 35 98:0 /mnt1 /mnt2 rw,noatime - ext3 /dev/root rw,errors=continue
            #                  ^target  ^vfs opts  ^sep ^fstype ^source ^super opts
            fields = line.split()
            try:
                separator = fields.index("-")
            except ValueError:
                continue
            if separator + 3 > len(fields) or separator < 6:
                continue
            vfs_options = fields[5]
            super_options = fields[separator + 3] if len(fields) > separator + 3 else ""
            entries.append({
                "target": _unescape_mount(fields[4]),
                "source": _unescape_mount(fields[separator + 2]),
                "fstype": fields[separator + 1],
                "options": ",".join(part for part in (vfs_options, super_options) if part),
            })
        return entries

    def mount_for(self, target: str) -> dict[str, str] | None:
        """The filesystem currently visible at `target`.

        The last matching line in mountinfo wins: a mount point can have
        several entries stacked on it, and the one on top is the one you get
        when you open a file there. /efi is commonly an autofs with the real
        vfat mounted over it, and answering "autofs" there would be wrong.
        """
        found = None
        for entry in self.mounts():
            if entry["target"] == target:
                found = entry
        return found

    def kernel_journal(self, lines: int = 4000) -> list[str]:
        """This boot's kernel messages.

        ``dmesg`` is refused on any machine with ``kernel.dmesg_restrict=1``,
        which is most of them now, so the journal is the reliable route and the
        only one used here.
        """
        result = self.run("journalctl", "-b", "-k", "--no-pager", "-o", "cat",
                          "-n", str(lines))
        return result.lines() if result.ok else []

    def journal_matching(self, pattern: str, lines: int = 200) -> list[str]:
        """Kernel messages containing `pattern` (a case-insensitive substring)."""
        needle = pattern.lower()
        return [line for line in self.kernel_journal() if needle in line.lower()][:lines]

    # -- audit ------------------------------------------------------------

    def log_lines(self) -> tuple[str, ...]:
        """Everything the probe touched, formatted for display."""
        return tuple(str(record) for record in self.records)

    def summary(self) -> str:
        files = sum(1 for record in self.records if record.kind == "file")
        commands = sum(1 for record in self.records if record.kind == "command")
        seconds = sum(record.seconds for record in self.records)
        return (f"{files} file{'' if files == 1 else 's'} read, "
                f"{commands} command{'' if commands == 1 else 's'} run, "
                f"{seconds:.2f}s total")


def _unescape_mount(field: str) -> str:
    """mountinfo escapes space, tab, newline and backslash as octal."""
    for escape, character in (("\\040", " "), ("\\011", "\t"),
                              ("\\012", "\n"), ("\\134", "\\")):
        field = field.replace(escape, character)
    return field


# ---------------------------------------------------------------------------
# The test double
# ---------------------------------------------------------------------------


class FakeProbe(Probe):
    """A Probe backed by dictionaries instead of a machine.

    ::

        probe = FakeProbe(
            files={"/proc/cmdline": "root=/dev/sda1 mitigations=off"},
            commands={("systemd-analyze", "time"): "Startup finished in 3s"},
            missing={"/etc/ld.so.preload"},
        )

    Anything not supplied behaves as absent, which is the right default: a
    check must cope with a machine that does not have the thing it looks for.
    """

    def __init__(
        self,
        files: dict[str, str] | None = None,
        commands: dict[tuple[str, ...], str] | None = None,
        directories: dict[str, list[str]] | None = None,
        modes: dict[str, int] | None = None,
        denied: set[str] | None = None,
        binaries: set[str] | None = None,
        raw: dict[str, bytes] | None = None,
    ) -> None:
        super().__init__()
        self.fake_files = dict(files or {})
        self.fake_commands = dict(commands or {})
        self.fake_directories = dict(directories or {})
        self.fake_modes = dict(modes or {})
        self.fake_denied = set(denied or ())
        # `or` would be wrong here: binaries=set() is how a test says "none of
        # these tools are installed", and an empty set is falsy.
        self.fake_binaries = set(ALLOWED_COMMANDS if binaries is None else binaries)
        self.fake_raw = dict(raw or {})

    def file(self, path: str | Path) -> FileRead:
        key = str(path)
        if key in self.fake_denied:
            result = FileRead(key, exists=True, error="permission denied")
        elif key in self.fake_files:
            result = FileRead(key, self.fake_files[key], exists=True)
        else:
            result = FileRead(key, exists=False, error="no such file")
        self.records.append(ProbeRecord("file", key,
                                        "ok" if result.ok else result.error))
        return result

    def read_bytes(self, path: str | Path, limit: int = 1 << 20) -> bytes | None:
        return self.fake_raw.get(str(path))

    def stat(self, path: str | Path, *, follow: bool = False) -> os.stat_result | None:
        key = str(path)
        if key in self.fake_modes:
            return _fake_stat(self.fake_modes[key])
        if key in self.fake_files or key in self.fake_denied:
            return _fake_stat(0o100644)
        if key in self.fake_directories:
            return _fake_stat(0o040755)
        return None

    def is_dir(self, path: str | Path) -> bool:
        return str(path) in self.fake_directories

    def listdir(self, path: str | Path) -> list[str]:
        return sorted(self.fake_directories.get(str(path), []))

    def files_in(self, path: str | Path, suffix: str = "") -> list[str]:
        base = str(path)
        return [os.path.join(base, name) for name in self.listdir(base)
                if not suffix or name.endswith(suffix)]

    def run(self, program: str, *args: str, timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        if program not in ALLOWED_COMMANDS:
            raise ValueError(f"{program!r} is not an allowed inspection command")
        key = (program, *args)
        self.records.append(ProbeRecord("command", " ".join(key), "fake"))
        if program not in self.fake_binaries:
            return CommandResult(program, args, -1, "", "",
                                 error=f"{program} not installed")
        if key in self.fake_commands:
            return CommandResult(program, args, 0, self.fake_commands[key], "")
        # Match on the program alone, so a test can stub `systemd-analyze`
        # without repeating every flag the check happens to pass.
        if (program,) in self.fake_commands:
            return CommandResult(program, args, 0, self.fake_commands[(program,)], "")
        return CommandResult(program, args, 1, "", "no fake output configured")

    def available(self, program: str) -> bool:
        return program in self.fake_binaries


def _fake_stat(mode: int) -> os.stat_result:
    """A stat_result with the mode set and everything else zeroed."""
    return os.stat_result((mode, 0, 0, 1, 0, 0, 0, 0, 0, 0))
