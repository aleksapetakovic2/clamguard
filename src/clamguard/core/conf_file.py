"""Reading and writing ClamAV configuration files without wrecking them.

A clamd.conf is 900 lines of carefully written documentation with about thirty
active settings scattered through it. If we rewrote it from a dictionary, the
user would lose every comment. So this module keeps the file as an ordered list
of lines and edits individual lines in place.

The syntax is simple:

    # a comment
    Option value            an active setting
    #Option value           a commented-out example (very common in ClamAV)
    Option                  a bare option, meaning "yes"

Some options legitimately appear more than once — ``OnAccessIncludePath``,
``ExcludePath``, ``DatabaseCustomURL`` — so both single and multi-value access
are supported.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .logging_setup import get_logger

log = get_logger(__name__)

#: Values ClamAV accepts for a boolean option.
TRUE_WORDS = {"yes", "true", "1", "on"}
FALSE_WORDS = {"no", "false", "0", "off"}

#: An active setting: ``Key`` or ``Key value``.
_OPTION_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9_]*)(?:\s+(?P<value>.*?))?\s*$")

#: A commented-out example. ClamAV's shipped configs write these with no space
#: after the hash (``#LogRotate yes``) while prose comments always have one
#: (``# Enable log rotation.``). That convention is what lets us tell a
#: disabled setting apart from a sentence, so we rely on it deliberately.
_COMMENTED_OPTION_RE = re.compile(r"^#(?P<key>[A-Za-z][A-Za-z0-9_]*)(?:\s+(?P<value>.*?))?\s*$")

#: Where set() appends options that were not already present.
APPENDED_HEADER = "# --- added by ClamGuard ---"


def to_bool(value: str | None, default: bool = False) -> bool:
    """Interpret a ClamAV boolean, tolerating every spelling it allows."""
    if value is None:
        return default
    cleaned = value.strip().lower()
    if cleaned == "":
        return True  # a bare option line means "yes"
    if cleaned in TRUE_WORDS:
        return True
    if cleaned in FALSE_WORDS:
        return False
    return default


def from_bool(value: bool) -> str:
    """The spelling ClamGuard writes. ClamAV accepts several; we pick one."""
    return "yes" if value else "no"


@dataclass
class OptionDocs:
    """Help text for one option, lifted out of the config file's comments."""

    key: str
    description: str = ""
    default: str = ""
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def from_block(cls, key: str, block: list[str]) -> "OptionDocs":
        description: list[str] = []
        default = ""
        warnings: list[str] = []
        for line in block:
            lowered = line.lower()
            if lowered.startswith("default:"):
                default = line.split(":", 1)[1].strip()
            elif lowered.startswith("warning:"):
                warnings.append(line.split(":", 1)[1].strip())
            else:
                description.append(line)
        return cls(key=key, description=" ".join(description).strip(),
                   default=default, warnings=warnings)


@dataclass
class ConfLine:
    """One physical line, remembered well enough to write it back unchanged."""

    raw: str
    key: str = ""
    value: str = ""
    active: bool = False       # an uncommented setting
    is_comment: bool = False
    is_blank: bool = False

    @property
    def looks_like_option(self) -> bool:
        """True for both ``Key value`` and ``#Key value``."""
        return bool(self.key)

    def render(self) -> str:
        return self.raw


class ConfFile:
    """An editable ClamAV configuration file.

    ::

        conf = ConfFile.load(Path("/etc/clamav/clamd.conf"))
        conf.set("LogVerbose", "yes")
        print(conf.diff())          # show the user what will change
        new_text = conf.to_text()   # hand to the privileged helper
    """

    def __init__(self, lines: list[ConfLine], path: Path | None = None, original: str = ""):
        self.lines = lines
        self.path = path
        self.original_text = original

    # -- construction -----------------------------------------------------

    @classmethod
    def parse(cls, text: str, path: Path | None = None) -> "ConfFile":
        lines: list[ConfLine] = []
        for raw in text.split("\n"):
            lines.append(cls._parse_line(raw))
        # A trailing newline produces a final empty element; keep it so that
        # to_text() round-trips exactly.
        return cls(lines, path, text)

    @staticmethod
    def _parse_line(raw: str) -> ConfLine:
        stripped = raw.strip()
        if not stripped:
            return ConfLine(raw=raw, is_blank=True)

        if stripped.startswith("#"):
            match = _COMMENTED_OPTION_RE.match(stripped)
            if not match:
                return ConfLine(raw=raw, is_comment=True)
            return ConfLine(
                raw=raw,
                key=match.group("key"),
                value=(match.group("value") or "").strip(),
                active=False,
                is_comment=True,
            )

        match = _OPTION_RE.match(stripped)
        if not match:
            return ConfLine(raw=raw)
        return ConfLine(
            raw=raw,
            key=match.group("key"),
            value=(match.group("value") or "").strip(),
            active=True,
        )

    @classmethod
    def load(cls, path: Path) -> "ConfFile":
        """Read a file from disk. Raises OSError if it cannot be read."""
        return cls.parse(path.read_text(encoding="utf-8", errors="replace"), path)

    @classmethod
    def load_or_empty(cls, path: Path) -> "ConfFile":
        """Read a file, or return an empty document if it is unreadable."""
        try:
            return cls.load(path)
        except OSError as error:
            log.warning("cannot read %s: %s", path, error)
            return cls.parse("", path)

    # -- reading ----------------------------------------------------------

    def keys(self) -> list[str]:
        """Every option name that is currently active, in file order."""
        seen: list[str] = []
        for line in self.lines:
            if line.active and line.key and line.key not in seen:
                seen.append(line.key)
        return seen

    def _find(self, key: str, *, active_only: bool) -> list[int]:
        target = key.lower()
        return [
            index
            for index, line in enumerate(self.lines)
            if line.key.lower() == target and (line.active or not active_only)
        ]

    def has(self, key: str) -> bool:
        return bool(self._find(key, active_only=True))

    def get(self, key: str, default: str | None = None) -> str | None:
        """The first active value for `key`."""
        found = self._find(key, active_only=True)
        return self.lines[found[0]].value if found else default

    def get_all(self, key: str) -> list[str]:
        """Every active value for `key`, in file order."""
        return [self.lines[i].value for i in self._find(key, active_only=True)]

    def get_bool(self, key: str, default: bool = False) -> bool:
        found = self._find(key, active_only=True)
        if not found:
            return default
        return to_bool(self.lines[found[0]].value, default)

    def get_int(self, key: str, default: int = 0) -> int:
        raw = self.get(key)
        if raw is None:
            return default
        try:
            return int(raw.strip())
        except ValueError:
            return default

    def commented_value(self, key: str) -> str | None:
        """The value from a commented-out example line, if there is one.

        Useful for showing "the shipped default was 10" next to an input.
        """
        for index in self._find(key, active_only=False):
            line = self.lines[index]
            if not line.active and line.value:
                return line.value
        return None

    # -- writing ----------------------------------------------------------

    def set(self, key: str, value: str | bool | int) -> None:
        """Give `key` exactly one active value.

        Preference order for where the line goes:
        1. an existing active line for this key — edited in place;
        2. the first commented-out example for this key — uncommented in place,
           which keeps the setting next to the documentation that explains it;
        3. appended at the end under a ClamGuard header.
        """
        text = self._format(value)

        active = self._find(key, active_only=True)
        if active:
            first = active[0]
            self.lines[first] = self._option_line(self.lines[first].key, text)
            for index in reversed(active[1:]):
                del self.lines[index]
            return

        for index in self._find(key, active_only=False):
            if not self.lines[index].active:
                self.lines[index] = self._option_line(self.lines[index].key, text)
                return

        self._append(self._option_line(key, text))

    def set_all(self, key: str, values: list[str]) -> None:
        """Replace every active occurrence of `key` with `values`.

        Used for options that may repeat. An empty list removes the option.
        """
        existing = self._find(key, active_only=True)
        canonical = self.lines[existing[0]].key if existing else key

        if not values:
            self.remove(key)
            return

        replacement = [self._option_line(canonical, value) for value in values]

        if existing:
            anchor = existing[0]
            for index in reversed(existing[1:]):
                del self.lines[index]
            self.lines[anchor:anchor + 1] = replacement
            return

        # Not present yet: place the first one (which may uncomment an example
        # line), then put the rest directly after it.
        self.set(canonical, values[0])
        anchor = self._find(canonical, active_only=True)[0]
        self.lines[anchor + 1:anchor + 1] = replacement[1:]

    def remove(self, key: str) -> None:
        """Delete every active line for `key`. Commented examples are kept."""
        for index in reversed(self._find(key, active_only=True)):
            del self.lines[index]

    def comment_out(self, key: str) -> None:
        """Disable `key` by prefixing its lines with '#', keeping them visible."""
        for index in self._find(key, active_only=True):
            line = self.lines[index]
            self.lines[index] = ConfLine(
                raw=f"#{line.raw.lstrip()}", key=line.key, value=line.value,
                active=False, is_comment=True,
            )

    def apply(self, changes: dict[str, str | bool | int | None]) -> None:
        """Set several options at once; a value of None removes the option."""
        for key, value in changes.items():
            if value is None:
                self.remove(key)
            else:
                self.set(key, value)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _format(value: str | bool | int) -> str:
        if isinstance(value, bool):
            return from_bool(value)
        return str(value).strip()

    @staticmethod
    def _option_line(key: str, value: str) -> ConfLine:
        raw = f"{key} {value}".rstrip()
        return ConfLine(raw=raw, key=key, value=value, active=True)

    def _append(self, line: ConfLine) -> None:
        """Add a line at the end, under a header we only write once."""
        while self.lines and self.lines[-1].is_blank:
            self.lines.pop()
        if not any(l.raw.strip() == APPENDED_HEADER for l in self.lines):
            self.lines.append(ConfLine(raw="", is_blank=True))
            self.lines.append(ConfLine(raw=APPENDED_HEADER, is_comment=True))
        self.lines.append(line)
        self.lines.append(ConfLine(raw="", is_blank=True))

    # -- output -----------------------------------------------------------

    def to_text(self) -> str:
        """The whole file as text, ready to be written."""
        text = "\n".join(line.render() for line in self.lines)
        if text and not text.endswith("\n"):
            text += "\n"
        return text

    def is_modified(self) -> bool:
        return self.to_text() != self.original_text

    def diff(self, label: str | None = None) -> str:
        """A unified diff of the pending changes, for the confirmation dialog."""
        name = label or (self.path.name if self.path else "configuration")
        lines = difflib.unified_diff(
            self.original_text.splitlines(keepends=True),
            self.to_text().splitlines(keepends=True),
            fromfile=f"{name} (current)",
            tofile=f"{name} (proposed)",
            n=3,
        )
        return "".join(lines)

    def changed_keys(self) -> list[str]:
        """Option names whose active value differs from the loaded file."""
        before = ConfFile.parse(self.original_text)
        names = {k.lower(): k for k in before.keys()}
        names.update({k.lower(): k for k in self.keys()})
        changed = []
        for lowered, display in sorted(names.items()):
            if before.get_all(lowered) != self.get_all(lowered):
                changed.append(display)
        return changed

    def documentation(self) -> dict[str, "OptionDocs"]:
        """Pull the help text ClamAV ships in its own config comments.

        Each option in clamd.conf and freshclam.conf is preceded by a comment
        block describing it, usually ending with a ``# Default: ...`` line.
        Reading it here means the help shown in the UI always matches the
        installed ClamAV version, with no documentation for us to maintain.
        """
        docs: dict[str, OptionDocs] = {}
        block: list[str] = []
        for line in self.lines:
            if line.is_blank:
                block = []
            elif line.looks_like_option:
                if line.key.lower() not in docs:
                    docs[line.key.lower()] = OptionDocs.from_block(line.key, block)
                block = []
            elif line.is_comment:
                block.append(line.raw.lstrip("#").strip())
            else:
                block = []
        return docs

    def mark_saved(self) -> None:
        """Call after a successful write so is_modified() resets."""
        self.original_text = self.to_text()
