"""Query text to tokens, each remembering where it came from.

Three things here are not what a general-purpose tokeniser would do, and all
three are Kusto:

* **``5m`` is one token, not two.** Timespan literals are written as a number
  glued to a unit, so ``ago(1h)`` and ``| where Duration > 500ms`` work. The
  lexer emits a single TIMESPAN token carrying a ``timedelta``.
* **``!contains`` is one token.** Kusto negates its word operators with a
  leading bang and no space, so the lexer joins ``!`` to a following letter
  rather than leaving the parser to guess.
* **``@"C:\\logs"`` is verbatim.** No escape processing, which is what makes
  regular expressions readable inside a query.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum, auto

from .errors import KqlError


class Kind(Enum):
    IDENT = auto()
    NUMBER = auto()
    STRING = auto()
    TIMESPAN = auto()
    PUNCT = auto()
    PIPE = auto()
    END = auto()


@dataclass(frozen=True, slots=True)
class Token:
    kind: Kind
    text: str
    position: int
    #: Set for NUMBER, STRING and TIMESPAN: the value the text denotes.
    value: object = None

    @property
    def length(self) -> int:
        return len(self.text)

    def is_word(self, *words: str) -> bool:
        """True for an identifier equal to any of `words`, case-insensitively.

        Kusto keywords are case-sensitive in principle and universally written
        lowercase in practice; accepting either costs nothing and stops
        ``| Where`` from being an inscrutable failure.
        """
        return self.kind is Kind.IDENT and self.text.lower() in words

    def is_punct(self, *symbols: str) -> bool:
        return self.kind is Kind.PUNCT and self.text in symbols

    def __repr__(self) -> str:
        return f"{self.kind.name}({self.text!r})"


#: Multi-character symbols, longest first so that ``<=`` never lexes as ``<``.
_SYMBOLS = (
    "=~", "!~", "==", "!=", "<=", ">=", "..", "=>",
    "+", "-", "*", "/", "%", "<", ">", "=", "(", ")", "[", "]", "{", "}",
    ",", ".", ";", ":", "?",
    # A lone "!" only reaches here in front of a bracket — `!(a and b)`.
    # Everywhere else it has already been joined to the word after it.
    "!",
)

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER = re.compile(
    r"0[xX][0-9a-fA-F]+|"
    r"(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?")

#: Timespan units, longest first. ``m`` must be tried after ``ms`` or five
#: minutes becomes five milliseconds.
_TIMESPAN_UNITS: tuple[tuple[str, float], ...] = (
    ("microseconds", 1e-6), ("microsecond", 1e-6), ("milliseconds", 1e-3),
    ("millisecond", 1e-3), ("seconds", 1.0), ("second", 1.0),
    ("minutes", 60.0), ("minute", 60.0), ("hours", 3600.0), ("hour", 3600.0),
    ("days", 86400.0), ("day", 86400.0), ("ticks", 1e-7), ("tick", 1e-7),
    ("ms", 1e-3), ("us", 1e-6), ("µs", 1e-6),
    ("d", 86400.0), ("h", 3600.0), ("m", 60.0), ("s", 1.0),
)

#: Word operators that may be negated with a leading bang.
_NEGATABLE = frozenset({
    "in", "contains", "startswith", "endswith", "has", "hasprefix",
    "hassuffix", "between", "has_any", "has_all", "contains_cs", "has_cs",
    "hasprefix_cs", "hassuffix_cs", "startswith_cs", "endswith_cs", "in~",
})


def tokenise(text: str) -> list[Token]:
    """The whole query as a list of tokens, ending with one END token."""
    tokens: list[Token] = []
    position = 0
    length = len(text)

    while position < length:
        char = text[position]

        if char in " \t\r\n":
            position += 1
            continue

        if char == "/" and text.startswith("//", position):
            newline = text.find("\n", position)
            position = length if newline < 0 else newline + 1
            continue

        if char == "|":
            tokens.append(Token(Kind.PIPE, "|", position))
            position += 1
            continue

        if char in "\"'":
            token, position = _string(text, position, verbatim=False)
            tokens.append(token)
            continue

        if char == "@" and position + 1 < length and text[position + 1] in "\"'":
            token, position = _string(text, position + 1, verbatim=True,
                                      start=position)
            tokens.append(token)
            continue

        if char == "!" and position + 1 < length and (text[position + 1].isalpha()
                                                      or text[position + 1] == "~"):
            if text[position + 1] == "~":
                tokens.append(Token(Kind.PUNCT, "!~", position))
                position += 2
                continue
            match = _NAME.match(text, position + 1)
            if match is not None:
                word = match.group(0)
                end = match.end()
                if end < length and text[end] == "~":
                    word += "~"
                    end += 1
                if word.lower().rstrip("~") in _NEGATABLE or word.lower() in _NEGATABLE:
                    tokens.append(Token(Kind.IDENT, "!" + word, position))
                    position = end
                    continue
            tokens.append(Token(Kind.PUNCT, "!", position))
            position += 1
            continue

        if char.isdigit() or (char == "." and position + 1 < length
                              and text[position + 1].isdigit()):
            token, position = _number(text, position)
            tokens.append(token)
            continue

        if char == "$" and position + 1 < length and (text[position + 1].isalpha()
                                                      or text[position + 1] == "_"):
            # `$left` and `$right` in a join's `on` clause. Lexed as one name
            # so that `$left.App` goes through the ordinary member access.
            match = _NAME.match(text, position + 1)
            tokens.append(Token(Kind.IDENT, "$" + match.group(0), position))
            position = match.end()
            continue

        if char.isalpha() or char == "_":
            match = _NAME.match(text, position)
            word = match.group(0)
            end = match.end()
            # `in~` and `!in~` are single operators; so is the `~` suffix on
            # the set operators generally.
            if end < length and text[end] == "~" and word.lower() in ("in", "has_any",
                                                                      "has_all"):
                word += "~"
                end += 1
            tokens.append(Token(Kind.IDENT, word, position))
            position = end
            continue

        for symbol in _SYMBOLS:
            if text.startswith(symbol, position):
                tokens.append(Token(Kind.PUNCT, symbol, position))
                position += len(symbol)
                break
        else:
            raise KqlError(f"I do not know what to do with {char!r} here.",
                           position, 1, source=text)

    tokens.append(Token(Kind.END, "", length))
    return tokens


def _string(text: str, position: int, *, verbatim: bool,
            start: int | None = None) -> tuple[Token, int]:
    """A quoted string. Verbatim strings keep their backslashes."""
    quote = text[position]
    begin = position if start is None else start
    index = position + 1
    pieces: list[str] = []

    while index < len(text):
        char = text[index]
        if char == quote:
            if verbatim and index + 1 < len(text) and text[index + 1] == quote:
                pieces.append(quote)
                index += 2
                continue
            body = "".join(pieces)
            return Token(Kind.STRING, text[begin:index + 1], begin, body), index + 1
        if char == "\\" and not verbatim:
            index += 1
            if index >= len(text):
                break
            pieces.append(_ESCAPES.get(text[index], text[index]))
            index += 1
            continue
        pieces.append(char)
        index += 1

    raise KqlError("This string is never closed.", begin, 1,
                   hint=f"Add a closing {quote}.", source=text)


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\",
            "'": "'", '"': '"', "a": "\a", "b": "\b", "f": "\f", "v": "\v"}


def _number(text: str, position: int) -> tuple[Token, int]:
    """A number, or a number glued to a timespan unit."""
    match = _NUMBER.match(text, position)
    body = match.group(0)
    end = match.end()

    if not body.lower().startswith("0x"):
        for unit, seconds in _TIMESPAN_UNITS:
            if text.lower().startswith(unit, end):
                after = end + len(unit)
                # "1minutes" is a timespan; "1min" followed by more letters is
                # not, so the unit has to end the word.
                if after < len(text) and (text[after].isalnum() or text[after] == "_"):
                    continue
                span = timedelta(seconds=float(body) * seconds)
                return Token(Kind.TIMESPAN, text[position:after], position, span), after

    if body.lower().startswith("0x"):
        return Token(Kind.NUMBER, body, position, int(body, 16)), end
    if "." in body or "e" in body.lower():
        return Token(Kind.NUMBER, body, position, float(body)), end
    return Token(Kind.NUMBER, body, position, int(body)), end
