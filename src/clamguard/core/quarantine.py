"""The quarantine vault: where detected files go so they cannot do anything.

A quarantined file is *moved* out of its original location into
~/.local/share/clamguard/quarantine/vault/ and rewritten XOR'd against a fixed
key. That does three useful things:

* the execute bit is gone and the bytes are scrambled, so a stray double-click
  or an `exec` from some other program cannot run it;
* a later scan of the home directory does not re-detect the vault and pile up
  duplicate alerts;
* the original bytes are recoverable exactly, because XOR is its own inverse.

It is **not encryption** and the UI says so. The key is in this file. The point
is neutralisation and non-recurrence, not secrecy — a user who wants the
original bytes back is entitled to them.

Every payload has a sidecar JSON file recording where it came from, what it was
detected as, and the SHA-256 of the original bytes, which is everything
`restore()` needs and enough to prove the vault has not been tampered with.

Files the user cannot move themselves — anything owned by root — go through the
privileged helper. Everything else is done in-process with no password prompt.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QObject, Signal

from . import paths
from .logging_setup import get_logger
from .privileged import PrivilegedHelper, parse_json_output

log = get_logger(__name__)

#: Must match NEUTRALISE_KEY in packaging/clamguard-helper.
NEUTRALISE_KEY = b"ClamGuardVault01"

#: Read and write the vault in chunks so a 2 GB sample does not need 2 GB of RAM.
CHUNK = 1024 * 1024


class QuarantineError(Exception):
    """Something went wrong moving a file in or out of the vault."""


@dataclass
class QuarantineEntry:
    """One file in the vault, as recorded in its metadata sidecar."""

    id: str
    original_path: str
    payload_path: str
    threat: str
    quarantined_at: str
    size: int = 0
    mode: int = 0o600
    uid: int = 0
    gid: int = 0
    owner: str = ""
    group: str = ""
    sha256: str = ""
    engine: str = ""
    scan_id: int = 0
    #: True when the helper had to move it, so restoring needs the helper too.
    privileged: bool = False

    @property
    def filename(self) -> str:
        return Path(self.original_path).name or self.original_path

    @property
    def directory(self) -> str:
        return str(Path(self.original_path).parent)

    @property
    def when(self) -> datetime | None:
        try:
            return datetime.fromisoformat(self.quarantined_at)
        except (ValueError, TypeError):
            return None

    def payload(self) -> Path:
        return Path(self.payload_path)

    def metadata_path(self) -> Path:
        return paths.QUARANTINE_META / f"{self.id}.json"


class Quarantine(QObject):
    """The vault, and the operations on it.

    Direct operations are synchronous; ones that need root return through the
    supplied callbacks because pkexec puts a dialog on screen and we must not
    block waiting for it.
    """

    #: A file entered the vault. Carries the entry id.
    entry_added = Signal(str)
    #: A file left the vault, restored or deleted.
    entry_removed = Signal(str)
    #: Any change at all — connect this to reload a list.
    changed = Signal()

    def __init__(self, privileged: PrivilegedHelper, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.privileged = privileged
        paths.ensure_directories()

    # -- listing ----------------------------------------------------------

    def entries(self) -> list[QuarantineEntry]:
        """Everything in the vault, newest first."""
        found: list[QuarantineEntry] = []
        if not paths.QUARANTINE_META.is_dir():
            return found
        for meta_file in sorted(paths.QUARANTINE_META.glob("*.json"), reverse=True):
            entry = self._read_metadata(meta_file)
            if entry is not None:
                found.append(entry)
        return found

    def entry(self, entry_id: str) -> QuarantineEntry | None:
        return self._read_metadata(paths.QUARANTINE_META / f"{entry_id}.json")

    def count(self) -> int:
        if not paths.QUARANTINE_META.is_dir():
            return 0
        return sum(1 for _ in paths.QUARANTINE_META.glob("*.json"))

    def total_bytes(self) -> int:
        return sum(entry.size for entry in self.entries())

    def contains_path(self, path: str) -> bool:
        """Is this exact file already in the vault?"""
        return any(entry.original_path == path for entry in self.entries())

    # -- adding -----------------------------------------------------------

    def needs_privilege(self, path: Path) -> bool:
        """True when we cannot remove the original file ourselves.

        Moving a file means writing to its *directory*, so that is what gets
        tested, not the file.
        """
        try:
            return not os.access(path.parent, os.W_OK)
        except OSError:
            return True

    def quarantine(
        self,
        path: Path,
        threat: str,
        *,
        scan_id: int = 0,
        engine: str = "",
        on_success: Callable[[QuarantineEntry], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        """Move a file into the vault, asking for a password only if needed."""
        path = Path(path)
        if not path.is_file():
            self._report(on_error, f"{path} no longer exists.")
            return
        if path.is_symlink():
            self._report(on_error, f"{path} is a symlink; quarantine the target instead.")
            return

        if not self.needs_privilege(path):
            try:
                entry = self._quarantine_directly(path, threat, scan_id, engine)
            except QuarantineError as error:
                self._report(on_error, str(error))
            else:
                if on_success:
                    on_success(entry)
            return

        if not self.privileged.available:
            self._report(
                on_error,
                f"{path} is owned by another user, so moving it needs administrator "
                "rights. Install the ClamGuard helper to enable that.",
            )
            return

        self._quarantine_via_helper(path, threat, scan_id, engine, on_success, on_error)

    def _quarantine_directly(self, path: Path, threat: str, scan_id: int,
                             engine: str) -> QuarantineEntry:
        """Do the move ourselves. Used whenever the user owns the file."""
        entry_id = new_entry_id()
        payload = paths.QUARANTINE_VAULT / f"{entry_id}.quar"

        try:
            stat = path.stat()
            digest = neutralise_file(path, payload)
        except OSError as error:
            payload.unlink(missing_ok=True)
            raise QuarantineError(f"Could not read {path}: {error}") from error

        try:
            os.chmod(payload, 0o600)
        except OSError:
            pass  # a filesystem without POSIX modes

        try:
            path.unlink()
        except OSError as error:
            payload.unlink(missing_ok=True)
            raise QuarantineError(
                f"The file was copied to the vault but {path} could not be removed "
                f"({error}), so quarantine was cancelled."
            ) from error

        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(path),
            payload_path=str(payload),
            threat=threat,
            quarantined_at=datetime.now().isoformat(timespec="seconds"),
            size=stat.st_size,
            mode=stat.st_mode & 0o7777,
            uid=stat.st_uid,
            gid=stat.st_gid,
            owner=_owner_name(stat.st_uid),
            group=_group_name(stat.st_gid),
            sha256=digest,
            engine=engine,
            scan_id=scan_id,
            privileged=False,
        )
        self._write_metadata(entry)
        log.info("quarantined %s as %s (%s)", path, entry_id, threat)
        self.entry_added.emit(entry_id)
        self.changed.emit()
        return entry

    def _quarantine_via_helper(self, path: Path, threat: str, scan_id: int, engine: str,
                               on_success, on_error) -> None:
        """Ask the helper to move a file we are not allowed to touch."""
        entry_id = new_entry_id()
        payload = paths.QUARANTINE_VAULT / f"{entry_id}.quar"
        call = self.privileged.quarantine_file(path, payload)

        def succeeded(output: str) -> None:
            facts = parse_json_output(output)
            entry = QuarantineEntry(
                id=entry_id,
                original_path=facts.get("original_path", str(path)),
                payload_path=str(payload),
                threat=threat,
                quarantined_at=datetime.now().isoformat(timespec="seconds"),
                size=int(facts.get("size", 0)),
                mode=int(facts.get("mode", 0o600)),
                uid=int(facts.get("uid", 0)),
                gid=int(facts.get("gid", 0)),
                owner=facts.get("owner", ""),
                group=facts.get("group", ""),
                sha256=facts.get("sha256", ""),
                engine=engine,
                scan_id=scan_id,
                privileged=True,
            )
            self._write_metadata(entry)
            log.info("quarantined %s as %s via the helper", path, entry_id)
            self.entry_added.emit(entry_id)
            self.changed.emit()
            if on_success:
                on_success(entry)

        call.succeeded.connect(succeeded)
        if on_error:
            call.failed.connect(on_error)
            call.cancelled.connect(lambda: on_error("Quarantine was cancelled."))
        call.start()

    # -- restoring --------------------------------------------------------

    def restore(
        self,
        entry: QuarantineEntry,
        *,
        destination: Path | None = None,
        on_success: Callable[[Path], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        """Put a file back. `destination` overrides the original location.

        Restoring is how a false positive gets fixed, so it must always be
        possible — but it puts live malware back on the disk, which is why the
        UI asks twice.
        """
        target = Path(destination) if destination else Path(entry.original_path)
        payload = entry.payload()

        if not payload.is_file():
            self._report(on_error, "The quarantined file is missing from the vault.")
            return
        if target.exists():
            self._report(on_error, f"{target} already exists. Choose another location.")
            return

        if entry.privileged and destination is None:
            if not self.privileged.available:
                self._report(on_error,
                             "This file came from a location only an administrator can "
                             "write to. Install the ClamGuard helper, or restore it "
                             "somewhere else.")
                return
            call = self.privileged.restore_file(entry.id)

            def succeeded(_output: str) -> None:
                self._forget(entry)
                if on_success:
                    on_success(target)

            call.succeeded.connect(succeeded)
            if on_error:
                call.failed.connect(on_error)
                call.cancelled.connect(lambda: on_error("Restore was cancelled."))
            call.start()
            return

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = restore_file(payload, target)
        except OSError as error:
            self._report(on_error, f"Could not restore to {target}: {error}")
            return

        if entry.sha256 and digest != entry.sha256:
            target.unlink(missing_ok=True)
            self._report(on_error,
                         "The vault copy does not match its recorded checksum. "
                         "Nothing was restored.")
            return

        try:
            os.chmod(target, entry.mode or 0o600)
        except OSError:
            pass

        self._forget(entry)
        log.info("restored %s to %s", entry.id, target)
        if on_success:
            on_success(target)

    # -- deleting ---------------------------------------------------------

    def delete(self, entry: QuarantineEntry) -> None:
        """Remove a quarantined file permanently.

        The payload is overwritten once before unlinking. On a journalling or
        copy-on-write filesystem, and on any SSD, that is a courtesy rather
        than a guarantee — which is what the confirmation dialog says.
        """
        payload = entry.payload()
        try:
            if payload.is_file():
                size = payload.stat().st_size
                with payload.open("r+b") as handle:
                    remaining = size
                    while remaining > 0:
                        block = min(CHUNK, remaining)
                        handle.write(secrets.token_bytes(block))
                        remaining -= block
                    handle.flush()
                    os.fsync(handle.fileno())
                payload.unlink()
        except OSError as error:
            log.warning("could not overwrite %s before deleting: %s", payload, error)
            payload.unlink(missing_ok=True)

        self._forget(entry)
        log.info("deleted quarantined file %s", entry.id)

    def delete_all(self) -> int:
        """Empty the vault. Returns how many entries went."""
        entries = self.entries()
        for entry in entries:
            self.delete(entry)
        return len(entries)

    # -- integrity --------------------------------------------------------

    def verify(self, entry: QuarantineEntry) -> tuple[bool, str]:
        """Check the vault copy still hashes to what we recorded."""
        payload = entry.payload()
        if not payload.is_file():
            return False, "The vault payload is missing."
        if not entry.sha256:
            return True, "No checksum was recorded for this entry."

        digest = hashlib.sha256()
        offset = 0
        try:
            with payload.open("rb") as handle:
                while chunk := handle.read(CHUNK):
                    digest.update(_xor(chunk, offset))
                    offset += len(chunk)
        except OSError as error:
            return False, f"Could not read the vault payload: {error}"
        if digest.hexdigest() == entry.sha256:
            return True, "The vault copy is intact."
        return False, "The vault copy does not match its recorded checksum."

    # -- metadata ---------------------------------------------------------

    def _write_metadata(self, entry: QuarantineEntry) -> None:
        paths.QUARANTINE_META.mkdir(parents=True, exist_ok=True)
        target = entry.metadata_path()
        target.write_text(json.dumps(asdict(entry), indent=2) + "\n", encoding="utf-8")
        try:
            target.chmod(0o600)
        except OSError:
            pass

    def _read_metadata(self, meta_file: Path) -> QuarantineEntry | None:
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            log.warning("skipping unreadable quarantine metadata %s: %s", meta_file, error)
            return None
        known = {f for f in QuarantineEntry.__dataclass_fields__}
        try:
            return QuarantineEntry(**{k: v for k, v in data.items() if k in known})
        except TypeError as error:
            log.warning("skipping malformed quarantine metadata %s: %s", meta_file, error)
            return None

    def _forget(self, entry: QuarantineEntry) -> None:
        entry.payload().unlink(missing_ok=True)
        entry.metadata_path().unlink(missing_ok=True)
        self.entry_removed.emit(entry.id)
        self.changed.emit()

    @staticmethod
    def _report(callback: Callable[[str], None] | None, message: str) -> None:
        log.warning("%s", message)
        if callback:
            callback(message)


# ---------------------------------------------------------------------------
# The neutralisation primitives
# ---------------------------------------------------------------------------


def _xor(data: bytes, offset: int) -> bytes:
    """XOR `data` with the vault key, continuing from byte `offset`.

    Done as one big-integer XOR rather than a per-byte loop: Python's bignum
    arithmetic is C-level, which turns a 100 MB sample from about a minute into
    well under a second.
    """
    if not data:
        return b""
    key = NEUTRALISE_KEY
    start = offset % len(key)
    stream = (key * (len(data) // len(key) + 2))[start:start + len(data)]
    result = int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")
    return result.to_bytes(len(data), "big")


def neutralise_file(source: Path, destination: Path) -> str:
    """Copy source to destination, XOR'd. Returns the SHA-256 of the original."""
    digest = hashlib.sha256()
    offset = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as reader, destination.open("wb") as writer:
        while chunk := reader.read(CHUNK):
            digest.update(chunk)
            writer.write(_xor(chunk, offset))
            offset += len(chunk)
    return digest.hexdigest()


def restore_file(payload: Path, destination: Path) -> str:
    """Un-XOR a vault payload into destination. Returns the SHA-256 written."""
    digest = hashlib.sha256()
    offset = 0
    with payload.open("rb") as reader, destination.open("wb") as writer:
        while chunk := reader.read(CHUNK):
            plain = _xor(chunk, offset)
            digest.update(plain)
            writer.write(plain)
            offset += len(chunk)
    return digest.hexdigest()


def new_entry_id() -> str:
    """A sortable, collision-proof identifier: 20260920-031530-a3f9c2."""
    return f"{datetime.now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}"


def _owner_name(uid: int) -> str:
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        return str(uid)


def _group_name(gid: int) -> str:
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError):
        return str(gid)
