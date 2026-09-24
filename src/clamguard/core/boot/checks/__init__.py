"""Every check, imported here so that registering them is one import.

``from clamguard.core.boot import checks`` is what fills the catalogue in
:mod:`clamguard.core.boot.registry`. Adding a new module means adding one line
here and nothing else.

One module per category, each readable on its own:

===============  ==========================================================
firmware         What the firmware verifies before the kernel exists
bootchain        The files and disks the machine boots from
kernel           What the running kernel allows and is protected against
hardening        Switches that make a local exploit harder to land
persistence      Everything wired to run automatically
services         Units that failed, or run with more power than they need
performance      Where the time between power-on and login goes
integrity        What changed since last time, and what the journal said
===============  ==========================================================
"""

from __future__ import annotations

from . import (  # noqa: F401  - imported for the registration side effect
    bootchain,
    firmware,
    hardening,
    integrity,
    kernel,
    performance,
    persistence,
    services,
)

__all__ = ["bootchain", "firmware", "hardening", "integrity", "kernel",
           "performance", "persistence", "services"]
