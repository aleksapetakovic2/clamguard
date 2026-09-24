"""One ClamGuard per login: a second launch hands its request to the first.

ClamGuard lives in the tray and can start itself at login, so a second copy is
the normal case, not an accident: clicking the menu entry, "Open with
ClamGuard" on a folder, or the "Quick scan" desktop action all launch the
program again. Without this each one was a complete second instance — a second
tray icon, a second real-time log watcher and, worst, a second scheduler, so a
scheduled scan would run twice.

So the first instance listens on a local socket, and every later launch sends
it one small JSON request — show the window, open a page, scan these paths —
and exits.

The socket is a Unix-domain socket in ``$XDG_RUNTIME_DIR``, which systemd
creates per user with mode 0700, so no other account can reach it or claim
its name first; a socket under /tmp could be squatted by another user to
block ClamGuard from starting or to feed it requests. Nothing here touches the
network. Every request is still validated as though it were hostile, because
it arrives from outside the process.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from . import paths
from .logging_setup import get_logger

log = get_logger(__name__)

#: How long a second launch waits for the first to answer, in milliseconds.
CONNECT_TIMEOUT_MS = 800

#: How long the running instance waits for a connected launch to send its
#: request line. It is written immediately, so this only bounds a misbehaving
#: client — the UI thread is what waits.
READ_TIMEOUT_MS = 300

#: A request is a few hundred bytes. Anything larger is not from us.
MAX_REQUEST_BYTES = 64 * 1024

#: Paths per request, for the same reason.
MAX_PATHS = 256


#: A Unix socket's path has to fit in sockaddr_un's 108 bytes, and with
#: UserAccessOption Qt first creates the socket under a longer temporary name
#: beside the real one — so leave room. A path past this failed to listen with
#: nothing more than "Name error", and the launch quietly ran unguarded.
MAX_SOCKET_PATH = 90


def socket_path() -> str:
    """Where the running instance listens, or "" if nowhere suitable is short enough.

    ``$XDG_RUNTIME_DIR`` when there is one (every systemd login has it), and
    otherwise ClamGuard's own data directory, which is also private to the
    user — never a shared directory like /tmp.
    """
    candidates = []
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    if runtime and Path(runtime).is_dir():
        candidates.append(Path(runtime) / "clamguard.sock")
    candidates.append(paths.DATA_DIR / "clamguard.sock")
    for candidate in candidates:
        if len(os.fsencode(str(candidate))) <= MAX_SOCKET_PATH:
            return str(candidate)
    log.warning("no socket path short enough for single-instance mode; "
                "a second launch will start a second copy")
    return ""


def clean_request(raw: Any) -> dict:
    """The fields a request may carry, validated. Anything else is dropped.

    ``show``   bring the window forward
    ``quick``  start a quick scan
    ``scan``   scan these paths
    ``page``   open this page, by id
    """
    if not isinstance(raw, dict):
        return {}
    request: dict[str, Any] = {}
    if raw.get("show") is True:
        request["show"] = True
    if raw.get("quick") is True:
        request["quick"] = True
    scan = raw.get("scan")
    if isinstance(scan, list):
        request["scan"] = [item for item in scan[:MAX_PATHS]
                           if isinstance(item, str) and item and "\0" not in item]
    page = raw.get("page")
    if isinstance(page, str) and page.replace("-", "").replace("_", "").isalnum():
        request["page"] = page[:40]
    return request


class SingleInstance(QObject):
    """The listening side, and the static helper a second launch uses."""

    #: A later launch asked for something. The argument is a clean_request().
    request_received = Signal(dict)

    def __init__(self, path: str | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.path = path if path is not None else socket_path()
        self._server: QLocalServer | None = None

    # -- the second launch -------------------------------------------------

    @staticmethod
    def forward(request: dict, path: str | None = None) -> bool:
        """Hand `request` to a running instance. True if one took it."""
        path = path if path is not None else socket_path()
        if not path:
            return False
        socket = QLocalSocket()
        socket.connectToServer(path)
        if not socket.waitForConnected(CONNECT_TIMEOUT_MS):
            return False
        payload = (json.dumps(clean_request(request)) + "\n").encode("utf-8")
        socket.write(payload)
        delivered = socket.waitForBytesWritten(CONNECT_TIMEOUT_MS)
        socket.disconnectFromServer()
        if socket.state() != QLocalSocket.LocalSocketState.UnconnectedState:
            socket.waitForDisconnected(CONNECT_TIMEOUT_MS)
        return delivered

    # -- the first launch --------------------------------------------------

    @staticmethod
    def is_running(path: str | None = None) -> bool:
        """Is an instance listening at `path`? Connects and hangs up at once."""
        path = path if path is not None else socket_path()
        if not path:
            return False
        socket = QLocalSocket()
        socket.connectToServer(path)
        alive = socket.waitForConnected(CONNECT_TIMEOUT_MS)
        if alive:
            socket.disconnectFromServer()
        return alive

    def listen(self) -> bool:
        """Start listening. False if another instance got there first.

        The live check has to come *before* listen(), not after a failure:
        with UserAccessOption Qt creates the socket in a temporary directory
        and rename()s it into place, and a rename silently replaces a live
        instance's socket instead of failing. Checking afterwards let a second
        copy steal the name and orphan the first.
        """
        if not self.path or SingleInstance.is_running(self.path):
            return False
        # Nobody answered, so any socket file here is left over from a crash.
        QLocalServer.removeServer(self.path)
        server = QLocalServer(self)
        # Only this user may connect, whatever the directory's permissions.
        server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        if not server.listen(self.path):
            log.warning("single-instance socket unavailable: %s", server.errorString())
            return False
        server.newConnection.connect(self._on_connection)
        self._server = server
        log.debug("listening for other launches on %s", self.path)
        return True

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None

    def _on_connection(self) -> None:
        """Read each waiting request synchronously, then let the socket go.

        A request is one short line written the instant the other launch
        connects, so waiting for it briefly is cheaper than the alternative.
        An earlier version kept each connection alive through a Python closure
        connected to its own readyRead, with deleteLater on disconnect; which
        side owned the socket — Qt's parent or PySide's wrapper — became
        ambiguous, and a run of connections ended in a double delete inside
        ~QLocalSocket. No signal, no closure, one owner.
        """
        server = self._server
        while server is not None and server.hasPendingConnections():
            socket = server.nextPendingConnection()
            if socket is None:
                break
            data = bytearray()
            deadline = time.monotonic() + READ_TIMEOUT_MS / 1000
            while b"\n" not in data and len(data) <= MAX_REQUEST_BYTES:
                remaining = int((deadline - time.monotonic()) * 1000)
                if socket.bytesAvailable() == 0 and (
                        remaining <= 0 or not socket.waitForReadyRead(remaining)):
                    break
                data.extend(bytes(socket.readAll()))
            socket.abort()
            socket.deleteLater()
            if len(data) > MAX_REQUEST_BYTES:
                log.warning("ignoring an oversized request on the instance socket")
            elif b"\n" in data:
                self._deliver(bytes(data).split(b"\n", 1)[0])

    def _deliver(self, line: bytes) -> None:
        try:
            request = clean_request(json.loads(line.decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            log.warning("ignoring a malformed request on the instance socket")
            return
        log.info("another launch asked for %s", sorted(request) or ["nothing"])
        self.request_received.emit(request)
