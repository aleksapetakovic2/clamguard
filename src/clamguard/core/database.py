"""What signatures are installed, how many, and how old they are.

Signature age is the single most useful number in an antivirus UI: a scanner
with three-week-old signatures is quietly useless, and nothing else on screen
will tell you. So this module exists to answer "are we current?" precisely.

CVD and CLD files begin with a 512-byte text header::

    ClamAV-VDB:19 Sep 2026 06-24 +0000:28128:355666:90:<md5>:<dsig>:<builder>:<epoch>

Reading that directly is instant, whereas `sigtool --info` has to verify a
digital signature over an 85 MB file. We parse the header ourselves and keep
sigtool for the one case that needs it — verifying integrity on demand.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from . import paths
from .logging_setup import get_logger
from .process import run, which

log = get_logger(__name__)

#: Container formats that carry a CVD header.
CONTAINER_SUFFIXES = (".cvd", ".cld", ".cud")

#: Plain-text or binary signature files a user may have added by hand.
CUSTOM_SUFFIXES = (
    ".ndb", ".ndu", ".hdb", ".hsb", ".hdu", ".hsu", ".mdb", ".msb", ".ldb", ".ldu",
    ".sdb", ".zmd", ".rmd", ".fp", ".sfp", ".pdb", ".gdb", ".wdb", ".crb", ".cbc",
    ".idb", ".cfg", ".ign", ".ign2", ".info", ".imp", ".yara", ".yar",
)

#: How the three official databases are described to a human.
OFFICIAL_DESCRIPTIONS = {
    "main": "The main signature set. Large, and updated only a few times a year.",
    "daily": "Today's signatures. This is the one that must stay fresh.",
    "bytecode": "Bytecode signatures, which can unpack and inspect tricky formats.",
}


class Freshness(str, Enum):
    """How worried to be about the age of the signatures."""

    CURRENT = "current"
    AGEING = "ageing"
    STALE = "stale"
    MISSING = "missing"
    UNKNOWN = "unknown"

    @property
    def tone(self) -> str:
        return {
            Freshness.CURRENT: "ok",
            Freshness.AGEING: "warn",
            Freshness.STALE: "danger",
            Freshness.MISSING: "danger",
            Freshness.UNKNOWN: "neutral",
        }[self]


@dataclass(frozen=True)
class DatabaseFile:
    """One signature file on disk."""

    path: Path
    size: int
    modified: datetime
    #: "main", "daily", "bytecode", or the file's stem for anything else.
    name: str = ""
    official: bool = False
    version: int = 0
    signature_count: int = 0
    built: datetime | None = None
    functionality_level: int = 0
    md5: str = ""
    builder: str = ""

    @property
    def display_name(self) -> str:
        return self.name.capitalize() if self.official else self.path.name

    @property
    def description(self) -> str:
        return OFFICIAL_DESCRIPTIONS.get(self.name, "A signature file you added yourself.")

    @property
    def age(self) -> timedelta | None:
        reference = self.built or self.modified
        if reference is None:
            return None
        now = datetime.now(reference.tzinfo) if reference.tzinfo else datetime.now()
        return now - reference

    def age_text(self) -> str:
        """"3 hours ago", "2 days ago" — the form people actually read."""
        return humanise_age(self.age)


@dataclass(frozen=True)
class DatabaseSummary:
    """Everything the dashboard needs to say about signatures in one line."""

    directory: Path
    files: tuple[DatabaseFile, ...]
    total_signatures: int
    total_bytes: int
    newest: datetime | None
    freshness: Freshness
    readable: bool = True
    note: str = ""

    @property
    def age(self) -> timedelta | None:
        if self.newest is None:
            return None
        now = datetime.now(self.newest.tzinfo) if self.newest.tzinfo else datetime.now()
        return now - self.newest

    def age_text(self) -> str:
        return humanise_age(self.age)

    def official(self) -> list[DatabaseFile]:
        return [f for f in self.files if f.official]

    def custom(self) -> list[DatabaseFile]:
        return [f for f in self.files if not f.official]

    def headline(self) -> str:
        """The sentence shown next to the signature status badge."""
        if self.freshness is Freshness.MISSING:
            return "No virus signatures are installed."
        if self.freshness is Freshness.UNKNOWN:
            return self.note or "Signature status could not be determined."
        count = f"{self.total_signatures:,} signatures"
        if self.freshness is Freshness.CURRENT:
            return f"{count}, updated {self.age_text()}."
        if self.freshness is Freshness.AGEING:
            return f"{count}, last updated {self.age_text()}."
        return f"{count}, but they were last updated {self.age_text()}."


class DatabaseInfo(QObject):
    """Reads the signature database directory and reports on it."""

    refreshed = Signal()

    def __init__(self, directory: Path | None = None, warn_after_days: int = 3,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.directory = directory or paths.CLAMAV_DB_DIR
        self.warn_after_days = warn_after_days
        self._summary: DatabaseSummary | None = None

    @property
    def summary(self) -> DatabaseSummary:
        if self._summary is None:
            self._summary = self.read()
        return self._summary

    def refresh(self) -> None:
        self._summary = self.read()
        self.refreshed.emit()

    # -- reading ----------------------------------------------------------

    def read(self) -> DatabaseSummary:
        """Scan the database directory. Safe to call from a worker thread."""
        if not self.directory.is_dir():
            return DatabaseSummary(self.directory, (), 0, 0, None, Freshness.MISSING,
                                   readable=False,
                                   note=f"{self.directory} does not exist.")
        try:
            entries = sorted(self.directory.iterdir())
        except OSError as error:
            return DatabaseSummary(self.directory, (), 0, 0, None, Freshness.UNKNOWN,
                                   readable=False,
                                   note=f"Cannot read {self.directory}: {error}")

        files: list[DatabaseFile] = []
        for entry in entries:
            parsed = self._read_file(entry)
            if parsed is not None:
                files.append(parsed)

        if not files:
            return DatabaseSummary(self.directory, (), 0, 0, None, Freshness.MISSING,
                                   note="The database directory is empty.")

        total_signatures = sum(f.signature_count for f in files)
        total_bytes = sum(f.size for f in files)
        newest = self._newest_official_timestamp(files)

        return DatabaseSummary(
            directory=self.directory,
            files=tuple(files),
            total_signatures=total_signatures,
            total_bytes=total_bytes,
            newest=newest,
            freshness=self._judge(newest, files),
        )

    def _read_file(self, path: Path) -> DatabaseFile | None:
        suffix = path.suffix.lower()
        if suffix not in CONTAINER_SUFFIXES and suffix not in CUSTOM_SUFFIXES:
            return None
        try:
            stat = path.stat()
        except OSError:
            return None

        base = DatabaseFile(
            path=path,
            size=stat.st_size,
            modified=datetime.fromtimestamp(stat.st_mtime),
            name=path.stem.lower(),
            official=path.stem.lower() in OFFICIAL_DESCRIPTIONS,
        )
        if suffix in CONTAINER_SUFFIXES:
            return self._merge_header(base, path)
        return base

    @staticmethod
    def _merge_header(base: DatabaseFile, path: Path) -> DatabaseFile:
        """Fill in version and signature count from the 512-byte CVD header."""
        header = read_cvd_header(path)
        if header is None:
            return base
        return DatabaseFile(
            path=base.path,
            size=base.size,
            modified=base.modified,
            name=base.name,
            official=base.official,
            version=header.version,
            signature_count=header.signatures,
            built=header.built,
            functionality_level=header.functionality_level,
            md5=header.md5,
            builder=header.builder,
        )

    @staticmethod
    def _newest_official_timestamp(files: list[DatabaseFile]) -> datetime | None:
        """When the signatures were last refreshed.

        The 'daily' database is what actually tracks new threats, so its build
        time is the honest answer. Fall back to the newest of anything else.
        """
        daily = next((f for f in files if f.name == "daily"), None)
        if daily is not None:
            return daily.built or _aware(daily.modified)

        candidates = [f.built or _aware(f.modified) for f in files if f.official]
        candidates = [c for c in candidates if c is not None]
        return max(candidates) if candidates else None

    def _judge(self, newest: datetime | None, files: list[DatabaseFile]) -> Freshness:
        if not any(f.official for f in files):
            return Freshness.MISSING
        if newest is None:
            return Freshness.UNKNOWN
        now = datetime.now(newest.tzinfo) if newest.tzinfo else datetime.now()
        days = (now - newest).total_seconds() / 86400
        if days <= self.warn_after_days:
            return Freshness.CURRENT
        if days <= self.warn_after_days * 3:
            return Freshness.AGEING
        return Freshness.STALE

    # -- integrity --------------------------------------------------------

    def verify(self, path: Path) -> tuple[bool, str]:
        """Ask sigtool to verify one database's digital signature.

        Slow — it reads and hashes the whole file — so call it from a worker
        thread, and only when the user asks.
        """
        sigtool = which("sigtool")
        if not sigtool:
            return False, "sigtool is not installed."
        result = run(sigtool, ["--info", str(path)], timeout=180)
        text = result.output
        if "Verification OK" in text:
            return True, "Digital signature verified."
        return False, text.splitlines()[-1] if text else "Verification failed."


# ---------------------------------------------------------------------------
# CVD header
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CvdHeader:
    """The parsed 512-byte header of a .cvd / .cld / .cud file."""

    built: datetime | None
    version: int
    signatures: int
    functionality_level: int
    md5: str
    builder: str


def read_cvd_header(path: Path) -> CvdHeader | None:
    """Parse a container's header, or return None if it is not one."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(512)
    except OSError as error:
        log.debug("cannot read %s: %s", path, error)
        return None

    text = raw.decode("ascii", errors="replace")
    if not text.startswith("ClamAV-VDB:"):
        return None

    fields = text.split(":")
    if len(fields) < 8:
        return None
    # A real header always carries a numeric version and signature count. A
    # truncated or padded file can still split into eight fields, and reporting
    # it as "version 0, 0 signatures" would look like a real but empty database
    # rather than a broken file.
    if not fields[2].strip().isdigit() or not fields[3].strip().isdigit():
        return None

    return CvdHeader(
        built=_parse_cvd_time(fields[1]),
        version=_as_int(fields[2]),
        signatures=_as_int(fields[3]),
        functionality_level=_as_int(fields[4]),
        md5=fields[5].strip(),
        builder=fields[7].strip(),
    )


def _parse_cvd_time(text: str) -> datetime | None:
    """CVD build times look like ``19 Sep 2026 06-24 +0000``."""
    try:
        return datetime.strptime(text.strip(), "%d %b %Y %H-%M %z")
    except ValueError:
        return None


def _as_int(text: str) -> int:
    try:
        return int(text.strip())
    except ValueError:
        return 0


def _aware(moment: datetime) -> datetime:
    """Give a naive local timestamp a timezone so comparisons do not explode."""
    return moment.astimezone() if moment.tzinfo is None else moment


def humanise_age(age: timedelta | None) -> str:
    """A timedelta as the phrase a person would use."""
    if age is None:
        return "at an unknown time"
    seconds = age.total_seconds()
    if seconds < 0:
        return "just now"
    if seconds < 90:
        return "moments ago"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)} minutes ago"
    hours = minutes / 60
    if hours < 24:
        count = int(hours)
        return "1 hour ago" if count == 1 else f"{count} hours ago"
    days = hours / 24
    if days < 14:
        count = int(days)
        return "1 day ago" if count == 1 else f"{count} days ago"
    if days < 60:
        return f"{int(days / 7)} weeks ago"
    return f"{int(days / 30)} months ago"


def format_bytes(count: int) -> str:
    """Bytes as the short human form: 85.2 MB."""
    size = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
