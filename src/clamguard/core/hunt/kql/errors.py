"""What the engine says when a query is wrong, and where it went wrong.

A query language whose errors are "syntax error" is a query language nobody
learns. Every failure here carries a position in the source text, so the
editor can underline the exact token, and most carry a suggestion, because
the overwhelmingly common mistake is a near-miss on a name.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass


@dataclass(slots=True)
class Span:
    """A region of the query text: where an error is, in characters."""

    start: int = 0
    length: int = 1

    @property
    def end(self) -> int:
        return self.start + max(1, self.length)


class KqlError(Exception):
    """A query that could not be parsed, planned or run.

    ``position`` and ``length`` are offsets into the original query text, so
    the editor can draw a squiggle under the offending token rather than
    reporting that something, somewhere, is wrong.
    """

    def __init__(self, message: str, position: int = 0, length: int = 1,
                 hint: str = "", source: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.position = max(0, position)
        self.length = max(1, length)
        self.hint = hint
        self.source = source

    @property
    def span(self) -> Span:
        return Span(self.position, self.length)

    def line_and_column(self, text: str | None = None) -> tuple[int, int]:
        """1-based line and column of the error in `text`."""
        body = text if text is not None else self.source
        if not body:
            return 1, self.position + 1
        prefix = body[: self.position]
        line = prefix.count("\n") + 1
        column = self.position - (prefix.rfind("\n") + 1) + 1
        return line, column

    def caret(self, text: str | None = None) -> str:
        """The offending line with a caret under the token.

        ::

            Logs | wher Level == "error"
                   ^^^^
            Unknown operator 'wher'. Did you mean 'where'?
        """
        body = text if text is not None else self.source
        if not body:
            return self.full_message()
        line_number, column = self.line_and_column(body)
        lines = body.splitlines() or [""]
        line = lines[min(line_number - 1, len(lines) - 1)]
        pointer = " " * (column - 1) + "^" * min(self.length, max(1, len(line) - column + 1))
        return f"{line}\n{pointer}\n{self.full_message()}"

    def full_message(self) -> str:
        return f"{self.message} {self.hint}".strip() if self.hint else self.message

    def __str__(self) -> str:
        return self.full_message()


def did_you_mean(word: str, candidates, *, limit: int = 2) -> str:
    """``Did you mean 'where'?`` — or nothing, when nothing is close.

    Silence is better than a bad guess: offering "did you mean project" for a
    typo of "summarize" wastes more of the reader's time than saying nothing.
    """
    names = [str(name) for name in candidates]
    matches = difflib.get_close_matches(word, names, n=limit, cutoff=0.7)
    if not matches:
        # Try again ignoring case and underscores, which is where most of the
        # near-misses in a query language actually are.
        folded = {name.lower().replace("_", ""): name for name in names}
        key = word.lower().replace("_", "")
        if key in folded:
            return f"Did you mean '{folded[key]}'?"
        matches = difflib.get_close_matches(key, list(folded), n=limit, cutoff=0.78)
        matches = [folded[match] for match in matches]
    if not matches:
        return ""
    if len(matches) == 1:
        return f"Did you mean '{matches[0]}'?"
    quoted = " or ".join(f"'{match}'" for match in matches)
    return f"Did you mean {quoted}?"
