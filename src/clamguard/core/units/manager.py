"""Collecting the inventory off the UI thread, and caching the result.

The whole gather is about two and a half seconds — one second of
``systemctl show`` and the rest spread over five optional helpers. That is
fast for what it produces and far too slow to do on the thread painting the
window, so it goes through :func:`core.process.run_in_background` like every
other blocking job in ClamGuard.

One refresh at a time. A second request while the first is in flight is
ignored rather than queued: the answer would be the same and the user would
wait twice for it.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from ..logging_setup import get_logger
from ..process import run_in_background
from .enrich import Enrichment, enrich
from .inventory import collect
from .model import Inventory
from .purpose import describe_all

log = get_logger(__name__)


class UnitManager(QObject):
    """Reads every unit on the machine, in the background.

    ::

        manager = UnitManager()
        manager.refreshed.connect(page.show_inventory)
        manager.refresh()
    """

    #: A refresh began.
    started = Signal()
    #: A refresh finished. The argument is an :class:`~.model.Inventory`.
    refreshed = Signal(object)
    #: The refresh could not happen at all. The argument is a sentence.
    failed = Signal(str)
    #: True while a refresh is in flight, for enabling and disabling buttons.
    busy_changed = Signal(bool)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._busy = False
        self._inventory: Inventory | None = None
        self._enrichment: Enrichment | None = None
        #: Which unit tree the cached inventory came from.
        self._user_scope = False
        #: The scope of the refresh in flight, adopted when it lands.
        self._pending_scope = False

    # -- state -------------------------------------------------------------

    @property
    def busy(self) -> bool:
        return self._busy

    @property
    def user_scope(self) -> bool:
        return self._user_scope

    def inventory(self) -> Inventory | None:
        """The last result, so reopening the page does not re-read the machine."""
        return self._inventory

    def enrichment(self) -> Enrichment | None:
        return self._enrichment

    # -- running -----------------------------------------------------------

    def refresh(self, *, user: bool = False) -> bool:
        """Re-read every unit. Returns False when one is already running."""
        if self._busy:
            log.debug("a unit refresh is already running")
            return False

        self._set_busy(True)
        self._pending_scope = user
        self._emit(self.started)

        run_in_background(
            lambda: gather(user=user),
            on_done=self._on_done,
            on_error=self._on_error,
        )
        return True

    def _on_done(self, payload: tuple[Inventory, Enrichment]) -> None:
        inventory, enrichment = payload
        self._inventory, self._enrichment = inventory, enrichment
        self._user_scope = self._pending_scope
        self._set_busy(False)
        log.info("units: %d in %.2fs", len(inventory), inventory.elapsed)
        self._emit(self.refreshed, inventory)

    def _on_error(self, message: str) -> None:
        self._set_busy(False)
        log.error("unit refresh failed: %s", message)
        self._emit(self.failed, f"The service list could not be read: {message}")

    def _set_busy(self, busy: bool) -> None:
        if busy != self._busy:
            self._busy = busy
            self._emit(self.busy_changed, busy)

    @staticmethod
    def _emit(signal, *payload) -> None:
        # The window can close while a refresh is still in flight, which takes
        # the C++ side of this object with it. Raising out of a pool thread
        # would be worse than stopping quietly.
        try:
            signal.emit(*payload)
        except RuntimeError:
            pass


def gather(*, user: bool = False) -> tuple[Inventory, Enrichment]:
    """The whole read, with no Qt in sight so a test can call it directly."""
    inventory = collect(user=user)
    enrichment = enrich(inventory, user=user)
    describe_all(inventory)
    return inventory, enrichment
