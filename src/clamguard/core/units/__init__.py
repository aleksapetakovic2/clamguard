"""Understanding systemd units: what they are, and why they are here.

`systemctl status` tells you a unit is running. It does not tell you that
nothing on the machine requires it, that it cost twenty-four seconds of your
boot, which package put it there, or that your distribution ships it disabled.
Each of those facts is a second away; none of them live in the same place.

This package gathers them. It is read-only and unprivileged throughout — every
source works as an ordinary user, and nothing here may call the privileged
helper.

::

    from clamguard.core.units import Inventory, collect

    inventory = collect()
    unit = inventory.get("clamav-clamonacc.service")
    print(unit.purpose.headline)
"""

from __future__ import annotations

from .enrich import Enrichment, enrich
from .inventory import collect, parse_show_output
from .manager import UnitManager
from .model import (
    Enablement,
    ExecCommand,
    Exposure,
    Inventory,
    Provenance,
    Purpose,
    Unit,
    UnitKind,
)
from .purpose import describe

__all__ = [
    "Enablement", "Enrichment", "ExecCommand", "Exposure", "Inventory",
    "Provenance", "Purpose", "Unit", "UnitKind", "UnitManager",
    "collect", "describe", "enrich", "parse_show_output",
]
