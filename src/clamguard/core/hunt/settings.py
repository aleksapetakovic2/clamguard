"""Everything about Hunt the user can change, in one JSON file.

Lives at ``~/.config/clamguard/hunt.json``. It is plain, commented by its own
key names, and safe to edit by hand — a broken file degrades to the defaults
with a warning rather than taking the page down, which is the same contract
the Boot Analyzer's profile has.

Two groups of settings deserve a note.

**The opt-in roots.** ``/tmp`` and shell history are searched only if asked
for. Shell history in particular is the most sensitive file in a home
directory; indexing it by default because it technically matches "a log" would
be a betrayal of the user's expectations, so it is a deliberate switch with
the reason written next to it.

**Retention.** Every limit can be set to zero, meaning no limit. That is a
supported choice and the UI says what it will cost.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import paths
from ..logging_setup import get_logger
from .discovery import Budget, DEFAULT_MAX_BYTES, Root, default_roots
from .model import DEFAULT_TIME_RANGE, TimeRange
from .store import Retention

log = get_logger(__name__)

#: Roots that are searched unless the user turns them off.
DEFAULT_ENABLED = ("config", "state", "data", "cache", "flatpak", "snap",
                   "npm", "home", "system")

#: Glob patterns excluded out of the box. Each one is here because it matched
#: something on a real machine that was not a log.
DEFAULT_EXCLUSIONS: tuple[str, ...] = (
    "*/Crashpad/*",
    "*/.git/*",
    "*.ldb",
    "*.sst",
)


@dataclass
class HuntSettings:
    """The whole configuration, loaded from and saved to one file."""

    path: Path | None = None

    #: Which discovery roots are switched on, by id.
    roots: dict[str, bool] = field(default_factory=dict)
    #: Extra directories the user added by hand.
    extra_roots: list[str] = field(default_factory=list)
    #: Individual files the user added by hand.
    extra_files: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUSIONS))

    max_file_megabytes: int = DEFAULT_MAX_BYTES // (1024 * 1024)
    crawl_seconds: float = 30.0

    max_events: int = 5_000_000
    max_age_days: int = 120
    max_store_megabytes: int = 2048

    #: The systemd journal. Off until asked for: it is a different kind of
    #: source (a command rather than a file) and on the machine this was
    #: written for it holds 11.3 million entries, which is ten times the rest
    #: of the index put together.
    journal_enabled: bool = False
    journal_window: str = "boot"
    journal_priority: str = "all"
    journal_max_entries: int = 250_000
    journal_include_user: bool = True

    use_full_text: bool = True
    row_limit: int = 100_000
    query_timeout: float = 60.0

    #: Re-read changed files whenever the page is opened.
    index_on_open: bool = False
    #: How stale the index may be before `index_on_open` bothers, in minutes.
    stale_after_minutes: int = 30

    #: The time range the picker was last left on.
    time_range: TimeRange = field(default_factory=lambda: DEFAULT_TIME_RANGE)
    #: The query in the editor when the page was last closed.
    last_query: str = ""
    #: Query ids starred in the left rail.
    favourites: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.path = self.path or (paths.CONFIG_DIR / "hunt.json")
        if not self.roots:
            self.roots = {root.id: root.id in DEFAULT_ENABLED
                          for root in default_roots()}
        self.load()

    # -- persistence ------------------------------------------------------

    def load(self) -> None:
        """Read the file. A broken one is ignored, loudly but not fatally."""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as error:
            log.warning("hunt settings unreadable (%s); using defaults", error)
            return
        if not isinstance(data, dict):
            log.warning("hunt settings is not an object; using defaults")
            return

        known = {root.id for root in default_roots()}
        roots = data.get("roots")
        if isinstance(roots, dict):
            for key, value in roots.items():
                if key in known:
                    self.roots[key] = bool(value)

        self.extra_roots = _string_list(data.get("extra_roots"))
        self.extra_files = _string_list(data.get("extra_files"))
        if "exclusions" in data:
            self.exclusions = _string_list(data.get("exclusions"))
        self.favourites = _string_list(data.get("favourites"))

        for name, lowest, highest in (
            ("max_file_megabytes", 1, 65536),
            ("crawl_seconds", 1, 600),
            ("max_events", 0, 500_000_000),
            ("max_age_days", 0, 3650),
            ("max_store_megabytes", 0, 1_000_000),
            ("row_limit", 100, 5_000_000),
            ("query_timeout", 1, 3600),
            ("stale_after_minutes", 0, 10_080),
            ("journal_max_entries", 1000, 20_000_000),
        ):
            value = data.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                current = getattr(self, name)
                setattr(self, name, type(current)(max(lowest, min(highest, value))))

        for name in ("use_full_text", "index_on_open", "journal_enabled",
                     "journal_include_user"):
            if isinstance(data.get(name), bool):
                setattr(self, name, data[name])

        # Enums, not free text: these end up on a command line.
        from .journal import PRIORITIES, WINDOWS

        if data.get("journal_window") in WINDOWS:
            self.journal_window = data["journal_window"]
        if data.get("journal_priority") in PRIORITIES:
            self.journal_priority = data["journal_priority"]

        if isinstance(data.get("time_range"), dict):
            self.time_range = TimeRange.from_dict(data["time_range"])
        if isinstance(data.get("last_query"), str):
            self.last_query = data["last_query"][:20_000]

    def save(self) -> None:
        payload = {
            "roots": self.roots,
            "extra_roots": self.extra_roots,
            "extra_files": self.extra_files,
            "exclusions": self.exclusions,
            "favourites": self.favourites,
            "max_file_megabytes": self.max_file_megabytes,
            "crawl_seconds": self.crawl_seconds,
            "max_events": self.max_events,
            "max_age_days": self.max_age_days,
            "max_store_megabytes": self.max_store_megabytes,
            "use_full_text": self.use_full_text,
            "row_limit": self.row_limit,
            "query_timeout": self.query_timeout,
            "index_on_open": self.index_on_open,
            "stale_after_minutes": self.stale_after_minutes,
            "journal_enabled": self.journal_enabled,
            "journal_window": self.journal_window,
            "journal_priority": self.journal_priority,
            "journal_max_entries": self.journal_max_entries,
            "journal_include_user": self.journal_include_user,
            "time_range": self.time_range.to_dict(),
            "last_query": self.last_query,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(payload, indent=2) + "\n",
                                 encoding="utf-8")
        except OSError as error:
            log.warning("could not save hunt settings: %s", error)

    def reset(self) -> None:
        """Back to the defaults, on disk as well as in memory."""
        fresh = HuntSettings.__new__(HuntSettings)
        fresh.path = self.path
        for name, value in _defaults().items():
            setattr(self, name, value)
        self.roots = {root.id: root.id in DEFAULT_ENABLED
                      for root in default_roots()}
        self.save()

    # -- derived ----------------------------------------------------------

    def enabled_roots(self, home: Path | None = None) -> tuple[Root, ...]:
        """The roots to crawl, including any the user added by hand."""
        chosen = [root for root in default_roots(home)
                  if self.roots.get(root.id, root.id in DEFAULT_ENABLED)]
        for index, extra in enumerate(self.extra_roots):
            directory = Path(extra).expanduser()
            if directory.is_dir():
                chosen.append(Root(f"custom{index}", directory,
                                   directory.name or str(directory),
                                   "A directory you added.", depth=6))
        return tuple(chosen)

    def budget(self) -> Budget:
        return Budget(seconds=float(self.crawl_seconds),
                      max_bytes=self.max_file_megabytes * 1024 * 1024)

    def journal_options(self):
        """The reader's options, built from these settings.

        Imported here rather than at the top of the module so that settings —
        which everything loads — does not drag in the one module in Hunt that
        can run a command.
        """
        from .journal import JournalOptions

        return JournalOptions(
            window=self.journal_window,
            priority=self.journal_priority,
            max_entries=int(self.journal_max_entries),
            include_user=bool(self.journal_include_user),
        ).normalised()

    def retention(self) -> Retention:
        return Retention(max_events=int(self.max_events),
                         max_age_days=int(self.max_age_days),
                         max_megabytes=int(self.max_store_megabytes))

    def optional_roots_on(self) -> tuple[str, ...]:
        """The opt-in roots currently enabled, for the warning strip."""
        return tuple(root.id for root in default_roots()
                     if root.optional and self.roots.get(root.id))

    def summary(self) -> str:
        enabled = sum(1 for value in self.roots.values() if value)
        parts = [f"{enabled} places searched", self.retention().describe()]
        if self.journal_enabled:
            parts.insert(1, "journal on")
        if not self.use_full_text:
            parts.append("no text index")
        return " · ".join(parts)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))][:500]


def _defaults() -> dict[str, Any]:
    return {
        "extra_roots": [], "extra_files": [],
        "exclusions": list(DEFAULT_EXCLUSIONS), "favourites": [],
        "max_file_megabytes": DEFAULT_MAX_BYTES // (1024 * 1024),
        "crawl_seconds": 30.0, "max_events": 5_000_000, "max_age_days": 120,
        "max_store_megabytes": 2048, "use_full_text": True,
        "row_limit": 100_000, "query_timeout": 60.0, "index_on_open": False,
        "stale_after_minutes": 30, "time_range": DEFAULT_TIME_RANGE,
        "last_query": "", "journal_enabled": False, "journal_window": "boot",
        "journal_priority": "all", "journal_max_entries": 250_000,
        "journal_include_user": True,
    }
