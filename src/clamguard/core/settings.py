"""User preferences for ClamGuard itself.

This is *not* ClamAV's configuration — that lives in /etc/clamav and is edited
on the Configuration page. These are the app's own choices: theme, what a Quick
Scan covers, whether to start in the tray, and so on.

Stored as readable JSON so a user can edit or delete it by hand. Unknown keys
in the file are preserved on save (so downgrading the app does not lose newer
settings) and missing keys fall back to DEFAULTS.
"""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import QObject, Signal

from . import paths
from .logging_setup import get_logger

log = get_logger(__name__)


#: Every setting the app understands, with its default. Keep this flat and
#: boring — one key, one value, no nesting beyond lists of strings.
DEFAULTS: dict[str, Any] = {
    # -- appearance -------------------------------------------------------
    "theme": "auto",                 # "auto" | "light" | "dark"
    "accent": "blue",                # see ui/theme.py ACCENTS
    "window_geometry": "",           # base64 QByteArray, restored on launch
    "sidebar_collapsed": False,
    # -- behaviour --------------------------------------------------------
    "start_minimised": False,
    "close_to_tray": True,
    "show_tray_icon": True,
    "notify_on_threat": True,
    "notify_on_update": False,
    "confirm_before_delete": True,
    # -- scanning ---------------------------------------------------------
    "prefer_daemon": True,           # use clamdscan when clamd is reachable
    "default_profile": "balanced",   # see core/scan_profile.py
    "on_threat_action": "report",    # "report" | "quarantine"
    "quick_scan_paths": [],          # empty means "use the built-in list"
    "excluded_paths": [],
    "scan_hidden_files": True,
    # -- updates ----------------------------------------------------------
    "warn_db_age_days": 3,
    "check_updates_on_launch": True,
    # -- first run --------------------------------------------------------
    "setup_completed": False,
    "helper_prompt_dismissed": False,
}


class Settings(QObject):
    """A JSON-backed preference store that shouts when something changes."""

    #: Emitted with (key, new_value) after any successful set().
    changed = Signal(str, object)

    def __init__(self, path=None) -> None:
        super().__init__()
        self._path = path or paths.SETTINGS_FILE
        self._values: dict[str, Any] = {}
        self.reload()

    # -- reading ----------------------------------------------------------

    def reload(self) -> None:
        """Re-read the file from disk, discarding unsaved in-memory values."""
        self._values = {}
        if self._path.is_file():
            try:
                loaded = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._values = loaded
                else:
                    log.warning("settings file is not a JSON object, ignoring it")
            except (OSError, json.JSONDecodeError) as error:
                log.warning("cannot read settings (%s); using defaults", error)

    def get(self, key: str, default: Any = None) -> Any:
        """Value for `key`, falling back to DEFAULTS then to `default`."""
        if key in self._values:
            return self._values[key]
        if key in DEFAULTS:
            return DEFAULTS[key]
        return default

    def bool(self, key: str) -> bool:
        return bool(self.get(key))

    def int(self, key: str) -> int:
        try:
            return int(self.get(key))
        except (TypeError, ValueError):
            return int(DEFAULTS.get(key, 0))

    def str(self, key: str) -> str:
        value = self.get(key)
        return value if isinstance(value, str) else str(DEFAULTS.get(key, ""))

    def list(self, key: str) -> list:
        value = self.get(key)
        return list(value) if isinstance(value, list) else list(DEFAULTS.get(key, []))

    # -- writing ----------------------------------------------------------

    def set(self, key: str, value: Any) -> None:
        """Store `key` and persist immediately.

        Writes are cheap (a few hundred bytes) and immediate persistence means
        a crash never loses a preference the user just picked.
        """
        if self.get(key) == value:
            return
        self._values[key] = value
        self.save()
        self.changed.emit(key, value)

    def update(self, values: dict[str, Any]) -> None:
        """Set several keys, saving once and emitting once per changed key."""
        touched = [k for k, v in values.items() if self.get(k) != v]
        if not touched:
            return
        self._values.update(values)
        self.save()
        for key in touched:
            self.changed.emit(key, self._values[key])

    def reset(self, key: str) -> None:
        """Forget a stored value so the default applies again."""
        if key in self._values:
            del self._values[key]
            self.save()
            self.changed.emit(key, self.get(key))

    def save(self) -> None:
        """Write the file atomically so a crash cannot truncate it."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_suffix(".json.tmp")
            temporary.write_text(
                json.dumps(self._values, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            temporary.replace(self._path)
        except OSError as error:
            log.error("cannot save settings to %s: %s", self._path, error)

    # -- convenience ------------------------------------------------------

    def as_dict(self) -> dict[str, Any]:
        """Effective settings: defaults overlaid with stored values."""
        merged = dict(DEFAULTS)
        merged.update(self._values)
        return merged
