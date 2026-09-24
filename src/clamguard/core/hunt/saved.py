"""Queries the user keeps, and the ones they just ran.

Two JSON files under ``~/.config/clamguard``:

``hunt-queries.json``
    Saved queries. Each keeps the time range it was saved with, because "the
    last 24 hours" is part of what a saved hunt means. Rolling ranges are
    stored as rolling, so a query saved in March still means *the last day*
    rather than *a day in March*.

``hunt-history.json``
    The last hundred queries that were run, with how long they took and how
    many rows came back. A ring buffer, so it cannot grow.

Neither file is ever executed as code. A saved query is text that goes through
the same parser as anything typed by hand.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import paths
from ..logging_setup import get_logger
from .model import TimeRange

log = get_logger(__name__)

#: How many past runs are remembered.
HISTORY_LIMIT = 100

#: A saved query longer than this is refused; it is a query box, not a file.
MAX_QUERY = 100_000


@dataclass(slots=True)
class SavedQuery:
    """One query the user chose to keep."""

    id: str
    name: str
    text: str
    description: str = ""
    category: str = "Saved"
    time_range: TimeRange | None = None
    created: float = 0.0
    updated: float = 0.0
    #: How many times it has been run from the rail.
    uses: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "text": self.text,
            "description": self.description, "category": self.category,
            "time_range": self.time_range.to_dict() if self.time_range else None,
            "created": self.created, "updated": self.updated, "uses": self.uses,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SavedQuery | None":
        if not isinstance(data, dict):
            return None
        text = data.get("text")
        name = data.get("name")
        if not isinstance(text, str) or not isinstance(name, str) or not text.strip():
            return None
        raw_range = data.get("time_range")
        return cls(
            id=str(data.get("id") or uuid.uuid4().hex[:12]),
            name=name[:200], text=text[:MAX_QUERY],
            description=str(data.get("description") or "")[:600],
            category=str(data.get("category") or "Saved")[:80],
            time_range=TimeRange.from_dict(raw_range) if isinstance(raw_range, dict)
            else None,
            created=_number(data.get("created")),
            updated=_number(data.get("updated")),
            uses=int(_number(data.get("uses"))),
        )


@dataclass(slots=True)
class RunRecord:
    """One past execution, for the history list."""

    text: str
    when: float = 0.0
    elapsed: float = 0.0
    rows: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict:
        return {"text": self.text, "when": self.when, "elapsed": self.elapsed,
                "rows": self.rows, "error": self.error}

    @classmethod
    def from_dict(cls, data: dict) -> "RunRecord | None":
        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            return None
        return cls(text=data["text"][:MAX_QUERY], when=_number(data.get("when")),
                   elapsed=_number(data.get("elapsed")),
                   rows=int(_number(data.get("rows"))),
                   error=str(data.get("error") or "")[:400])


class QueryStore:
    """Saved queries and run history, both backed by JSON."""

    def __init__(self, directory: Path | None = None) -> None:
        base = directory or paths.CONFIG_DIR
        self.saved_path = base / "hunt-queries.json"
        self.history_path = base / "hunt-history.json"
        self.queries: dict[str, SavedQuery] = {}
        self.history: list[RunRecord] = []
        self.load()

    # -- saved queries ----------------------------------------------------

    def load(self) -> None:
        for item in _read_list(self.saved_path, "queries"):
            query = SavedQuery.from_dict(item)
            if query is not None:
                self.queries[query.id] = query
        for item in _read_list(self.history_path, "history"):
            record = RunRecord.from_dict(item)
            if record is not None:
                self.history.append(record)
        self.history = self.history[-HISTORY_LIMIT:]

    def save(self, name: str, text: str, *, description: str = "",
             time_range: TimeRange | None = None,
             query_id: str = "") -> SavedQuery:
        """Add or replace a saved query and write the file."""
        if not text.strip():
            raise ValueError("A saved query needs a query in it.")
        now = time.time()
        existing = self.queries.get(query_id) if query_id else None
        if existing is not None:
            existing.name = name[:200] or existing.name
            existing.text = text[:MAX_QUERY]
            existing.description = description[:600]
            existing.time_range = time_range
            existing.updated = now
            query = existing
        else:
            query = SavedQuery(id=uuid.uuid4().hex[:12], name=name[:200] or "Untitled",
                               text=text[:MAX_QUERY], description=description[:600],
                               time_range=time_range, created=now, updated=now)
            self.queries[query.id] = query
        self._write_saved()
        return query

    def rename(self, query_id: str, name: str) -> None:
        query = self.queries.get(query_id)
        if query is None:
            return
        query.name = name[:200] or query.name
        query.updated = time.time()
        self._write_saved()

    def delete(self, query_id: str) -> bool:
        if self.queries.pop(query_id, None) is None:
            return False
        self._write_saved()
        return True

    def record_use(self, query_id: str) -> None:
        query = self.queries.get(query_id)
        if query is None:
            return
        query.uses += 1
        self._write_saved()

    def all(self) -> list[SavedQuery]:
        return sorted(self.queries.values(),
                      key=lambda item: (-item.uses, item.name.lower()))

    def by_category(self) -> dict[str, list[SavedQuery]]:
        groups: dict[str, list[SavedQuery]] = {}
        for query in self.all():
            groups.setdefault(query.category or "Saved", []).append(query)
        return dict(sorted(groups.items()))

    # -- history ----------------------------------------------------------

    def remember(self, text: str, *, elapsed: float = 0.0, rows: int = 0,
                 error: str = "") -> None:
        """Add a run to the history, collapsing an immediate repeat."""
        body = text.strip()
        if not body:
            return
        if self.history and self.history[-1].text.strip() == body:
            self.history[-1] = RunRecord(body, time.time(), elapsed, rows, error)
        else:
            self.history.append(RunRecord(body, time.time(), elapsed, rows, error))
        self.history = self.history[-HISTORY_LIMIT:]
        self._write_history()

    def recent(self, limit: int = 30) -> list[RunRecord]:
        return list(reversed(self.history))[:limit]

    def clear_history(self) -> None:
        self.history = []
        self._write_history()

    # -- files ------------------------------------------------------------

    def _write_saved(self) -> None:
        _write(self.saved_path,
               {"queries": [query.to_dict() for query in self.queries.values()]})

    def _write_history(self) -> None:
        _write(self.history_path,
               {"history": [record.to_dict() for record in self.history]})


def _read_list(path: Path, key: str) -> list:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as error:
        log.warning("hunt: %s is unreadable (%s)", path.name, error)
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get(key), list):
        return data[key]
    return []


def _write(path: Path, payload: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as error:
        log.warning("hunt: could not write %s (%s)", path.name, error)


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return float(value)
