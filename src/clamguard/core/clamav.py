"""What ClamAV is installed, what version, and is the daemon listening?

Everything the rest of the app needs to know about the engine it is driving.
Nothing here writes anything; it is all discovery.

The daemon talks a small line protocol over its socket. Prefixing a command
with ``n`` means "newline-terminated", which is the documented, unambiguous
form, so that is what we send:

    nPING\\n     -> PONG
    nVERSION\\n  -> ClamAV 1.5.4/28128/Sat Sep 19 08:24:24 2026
    nSTATS\\n    -> a multi-line report about queues and threads
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from . import paths
from .logging_setup import get_logger
from .process import run, which

log = get_logger(__name__)

#: The ClamAV programs ClamGuard knows how to use, and why it wants each one.
KNOWN_TOOLS = {
    "clamscan": "scan files directly (no daemon needed)",
    "clamdscan": "scan through the daemon — much faster for repeat scans",
    "clamd": "the scanning daemon itself",
    "freshclam": "download signature updates",
    "sigtool": "inspect signature database files",
    "clamconf": "validate configuration files",
    "clamonacc": "on-access (real-time) scanning",
    "clambc": "run bytecode signatures",
}

_VERSION_RE = re.compile(
    r"ClamAV\s+(?P<engine>[0-9][^/\s]*)"
    r"(?:/(?P<sigs>\d+))?"
    r"(?:/(?P<built>.+))?"
)


@dataclass(frozen=True)
class Version:
    """A parsed ``ClamAV 1.5.4/28128/Sat Sep 19 08:24:24 2026`` string."""

    raw: str
    engine: str = ""
    signature_version: int = 0
    built: datetime | None = None

    @classmethod
    def parse(cls, text: str) -> "Version":
        text = (text or "").strip()
        match = _VERSION_RE.search(text)
        if not match:
            return cls(raw=text)
        built = None
        if match.group("built"):
            built = _parse_clamav_date(match.group("built"))
        return cls(
            raw=text,
            engine=match.group("engine") or "",
            signature_version=int(match.group("sigs") or 0),
            built=built,
        )

    def __str__(self) -> str:
        return self.engine or self.raw or "unknown"


def _parse_clamav_date(text: str) -> datetime | None:
    """ClamAV prints dates like ``Sat Sep 19 08:24:24 2026``."""
    for fmt in ("%a %b %d %H:%M:%S %Y", "%d %b %Y %H:%M %z", "%a %b %d %H:%M:%S %Y %z"):
        try:
            return datetime.strptime(text.strip(), fmt)
        except ValueError:
            continue
    return None


@dataclass(frozen=True)
class DaemonStatus:
    """A snapshot of the clamd daemon."""

    reachable: bool
    socket_path: Path | None = None
    tcp_address: str | None = None
    version: Version | None = None
    detail: str = ""

    @property
    def endpoint(self) -> str:
        if self.socket_path:
            return str(self.socket_path)
        if self.tcp_address:
            return self.tcp_address
        return "not configured"


class ClamAV(QObject):
    """Discovery of the installed ClamAV, refreshed on demand.

    Results are cached because probing runs several subprocesses. Call
    :meth:`refresh` after anything that could change them (an update, a service
    restart) and listen to :attr:`refreshed`.
    """

    refreshed = Signal()

    #: How long we wait for the daemon socket before deciding it is not there.
    SOCKET_TIMEOUT = 2.0

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._tools: dict[str, str | None] = {}
        self._version: Version | None = None
        self._daemon: DaemonStatus | None = None
        self.refresh()

    # -- tools ------------------------------------------------------------

    def refresh(self) -> None:
        """Re-probe binaries, version and daemon. Emits :attr:`refreshed`."""
        self._tools = {name: which(name) for name in KNOWN_TOOLS}
        self._version = None
        self._daemon = None
        self._version = self._read_version()
        self._daemon = self.probe_daemon()
        self.refreshed.emit()

    def tool(self, name: str) -> str | None:
        """Absolute path to a ClamAV program, or None if it is not installed."""
        if name not in self._tools:
            self._tools[name] = which(name)
        return self._tools[name]

    def has(self, name: str) -> bool:
        return self.tool(name) is not None

    @property
    def installed(self) -> bool:
        """True when we have at least one way to scan a file."""
        return self.has("clamscan") or self.has("clamdscan")

    def missing_tools(self) -> list[str]:
        """Known tools that are not present, in declaration order."""
        return [name for name in KNOWN_TOOLS if not self.has(name)]

    # -- version ----------------------------------------------------------

    @property
    def version(self) -> Version:
        if self._version is None:
            self._version = self._read_version()
        return self._version

    def _read_version(self) -> Version:
        for name in ("clamscan", "clamdscan", "freshclam", "clamconf"):
            executable = self.tool(name)
            if not executable:
                continue
            result = run(executable, ["--version"], timeout=8)
            if result.ok and result.stdout.strip():
                return Version.parse(result.stdout.splitlines()[0])
        return Version(raw="")

    # -- daemon -----------------------------------------------------------

    @property
    def daemon(self) -> DaemonStatus:
        if self._daemon is None:
            self._daemon = self.probe_daemon()
        return self._daemon

    def configured_endpoints(self) -> tuple[Path | None, str | None]:
        """Read LocalSocket / TCPSocket out of clamd.conf.

        Parsed here with a two-line loop rather than through conf_file, because
        this runs at start-up before anything else is constructed and must not
        fail if the config is malformed.
        """
        local: Path | None = None
        tcp_port: str | None = None
        tcp_addr = "127.0.0.1"
        try:
            text = paths.CLAMD_CONF.read_text(errors="replace")
        except OSError:
            return None, None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0].lower(), parts[1].strip()
            if key == "localsocket":
                local = Path(value)
            elif key == "tcpsocket":
                tcp_port = value
            elif key == "tcpaddr":
                tcp_addr = value
        return local, (f"{tcp_addr}:{tcp_port}" if tcp_port else None)

    def probe_daemon(self) -> DaemonStatus:
        """Try to reach clamd and ask it for its version."""
        local, tcp = self.configured_endpoints()

        if local is not None:
            reply = self._talk_unix(local, "nPING\n")
            if reply is not None and reply.strip() == "PONG":
                version_reply = self._talk_unix(local, "nVERSION\n") or ""
                return DaemonStatus(True, socket_path=local,
                                    version=Version.parse(version_reply))
            detail = "socket exists but is not answering" if local.exists() \
                else f"{local} does not exist"
            if tcp is None:
                return DaemonStatus(False, socket_path=local, detail=detail)

        if tcp is not None:
            host, _, port = tcp.rpartition(":")
            reply = self._talk_tcp(host, int(port), "nPING\n")
            if reply is not None and reply.strip() == "PONG":
                version_reply = self._talk_tcp(host, int(port), "nVERSION\n") or ""
                return DaemonStatus(True, tcp_address=tcp, version=Version.parse(version_reply))
            return DaemonStatus(False, socket_path=local, tcp_address=tcp,
                                detail=f"nothing answering on {tcp}")

        return DaemonStatus(False, detail="no LocalSocket or TCPSocket in clamd.conf")

    def daemon_stats(self) -> str:
        """The daemon's STATS report, or an empty string if it is unreachable."""
        status = self.daemon
        if not status.reachable:
            return ""
        if status.socket_path:
            return self._talk_unix(status.socket_path, "nSTATS\n", read_all=True) or ""
        if status.tcp_address:
            host, _, port = status.tcp_address.rpartition(":")
            return self._talk_tcp(host, int(port), "nSTATS\n", read_all=True) or ""
        return ""

    def reload_daemon_database(self) -> bool:
        """Ask clamd to re-read its signature database. No privileges needed."""
        status = self.daemon
        if not status.reachable or not status.socket_path:
            return False
        return (self._talk_unix(status.socket_path, "nRELOAD\n") or "").strip() == "RELOADING"

    # -- socket plumbing --------------------------------------------------

    def _talk_unix(self, path: Path, command: str, read_all: bool = False) -> str | None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.SOCKET_TIMEOUT)
                sock.connect(str(path))
                return self._exchange(sock, command, read_all)
        except (OSError, socket.timeout) as exc:
            log.debug("clamd unix socket %s: %s", path, exc)
            return None

    def _talk_tcp(self, host: str, port: int, command: str, read_all: bool = False) -> str | None:
        try:
            with socket.create_connection((host, port), timeout=self.SOCKET_TIMEOUT) as sock:
                sock.settimeout(self.SOCKET_TIMEOUT)
                return self._exchange(sock, command, read_all)
        except (OSError, socket.timeout) as exc:
            log.debug("clamd tcp %s:%s: %s", host, port, exc)
            return None

    @staticmethod
    def _exchange(sock: socket.socket, command: str, read_all: bool) -> str:
        sock.sendall(command.encode("ascii"))
        chunks: list[bytes] = []
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if not read_all:
                break
        return b"".join(chunks).decode("utf-8", errors="replace")


def summarise_installation(clamav: ClamAV) -> list[str]:
    """Human-readable notes about the installation, for the dashboard."""
    notes: list[str] = []
    if not clamav.installed:
        notes.append("ClamAV is not installed — no scanning is possible.")
        return notes
    if not clamav.has("freshclam"):
        notes.append("freshclam is missing, so signatures cannot be updated.")
    if not clamav.has("clamd"):
        notes.append("clamd is missing, so the fast daemon scanner is unavailable.")
    elif not clamav.daemon.reachable:
        notes.append(f"The ClamAV daemon is not responding ({clamav.daemon.detail}).")
    if not clamav.has("clamonacc"):
        notes.append("clamonacc is missing, so real-time protection is unavailable.")
    return notes
