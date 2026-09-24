"""Getting a result out of Hunt and into something else.

Four formats, chosen because they are what a result is actually wanted for:
CSV for a spreadsheet, TSV for pasting into anything, JSON for a script, and
Markdown for writing up what was found.

The one that needs care is CSV. A cell beginning ``=``, ``+``, ``-`` or ``@``
is executed as a formula by Excel and by LibreOffice when the file is opened,
and every cell here holds text taken from a log file — which is to say, text
an attacker may have written. Those cells are prefixed with a tab so the
spreadsheet treats them as text. It is the one export that is not a faithful
byte-for-byte copy, and it says so in its own header comment.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .model import ResultTable, format_timespan, format_timestamp

#: (id, extension, description) for the Export menu.
FORMATS: tuple[tuple[str, str, str], ...] = (
    ("csv", "csv", "Comma-separated, for a spreadsheet"),
    ("tsv", "tsv", "Tab-separated, for pasting anywhere"),
    ("json", "json", "One JSON object per row, for a script"),
    ("markdown", "md", "A table and a note, for writing up"),
)

#: The characters a spreadsheet treats as the start of a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

#: Rows beyond this are not exported. A million-row CSV helps nobody and the
#: file dialog gives no way to say "actually, stop".
MAX_ROWS = 1_000_000


def describe_formats() -> tuple[tuple[str, str, str], ...]:
    return FORMATS


def to_csv(table: ResultTable, *, delimiter: str = ",") -> str:
    """The result as CSV, with formula injection defused."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=delimiter, lineterminator="\n",
                        quoting=csv.QUOTE_MINIMAL)
    writer.writerow(table.names)
    for row in table.rows[:MAX_ROWS]:
        writer.writerow([_spreadsheet_safe(_cell(value)) for value in row])
    return buffer.getvalue()


def to_tsv(table: ResultTable) -> str:
    """Tab separated, without the spreadsheet defusing — this is for pasting."""
    lines = ["\t".join(table.names)]
    for row in table.rows[:MAX_ROWS]:
        lines.append("\t".join(_cell(value).replace("\t", " ").replace("\n", " ⏎ ")
                               for value in row))
    return "\n".join(lines) + "\n"


def to_json(table: ResultTable, *, indent: int | None = None) -> str:
    """An object with the schema, the statistics and the rows."""
    payload = {
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "columns": [{"name": column.name, "type": column.type.value}
                    for column in table.columns],
        "rows": len(table.rows),
        "truncated": table.stats.truncated,
        "elapsed_seconds": round(table.stats.elapsed, 6),
        "data": [
            {column.name: _jsonable(value)
             for column, value in zip(table.columns, row)}
            for row in table.rows[:MAX_ROWS]
        ],
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False, default=str)


def to_markdown(table: ResultTable, *, query: str = "",
                title: str = "Hunt results") -> str:
    """A Markdown document: the query, the numbers, and the table."""
    lines = [f"# {title}", ""]
    if query:
        lines += ["```kql", query.strip(), "```", ""]
    lines.append(f"{table.stats.summary()} — "
                 f"{datetime.now().astimezone():%Y-%m-%d %H:%M}.")
    if table.stats.truncated:
        lines.append("")
        lines.append("> This result was truncated; the rows below are the "
                     "first of a larger set.")
    lines += ["", "| " + " | ".join(_escape(name) for name in table.names) + " |",
              "|" + "|".join("---" for _ in table.columns) + "|"]
    for row in table.rows[:2000]:
        lines.append("| " + " | ".join(_escape(_cell(value)) for value in row) + " |")
    if len(table.rows) > 2000:
        lines.append("")
        lines.append(f"…and {len(table.rows) - 2000:,} more rows.")
    lines += ["", "---", "",
              "Produced by ClamGuard's Hunt page. Nothing was sent anywhere; "
              "every row came from a log file on this machine."]
    return "\n".join(lines) + "\n"


def render(table: ResultTable, format_id: str, *, query: str = "") -> str:
    if format_id == "csv":
        return to_csv(table)
    if format_id == "tsv":
        return to_tsv(table)
    if format_id == "json":
        return to_json(table, indent=2)
    if format_id == "markdown":
        return to_markdown(table, query=query)
    raise ValueError(f"There is no {format_id!r} export.")


def write(table: ResultTable, directory: Path, format_id: str, *,
          query: str = "", stem: str = "hunt") -> Path:
    """Write the result into `directory` and return the path."""
    extension = next((item[1] for item in FORMATS if item[0] == format_id), None)
    if extension is None:
        raise ValueError(f"There is no {format_id!r} export.")
    directory.mkdir(parents=True, exist_ok=True)
    name = f"{stem}-{datetime.now():%Y%m%d-%H%M%S}.{extension}"
    target = directory / name
    target.write_text(render(table, format_id, query=query), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# Cells
# ---------------------------------------------------------------------------


def _cell(value: Any) -> str:
    """One value as the text a person expects to see."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return format_timestamp(value)
    if isinstance(value, timedelta):
        return format_timespan(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    return value


def _spreadsheet_safe(text: str) -> str:
    """Stop a spreadsheet executing a log line as a formula.

    ``=cmd|'/c calc'!A1`` in a cell is a real attack against whoever opens the
    export, and the text in these cells came out of files other programs
    wrote. A leading tab makes the cell text and costs nothing else.
    """
    if text and text[0] in _FORMULA_START:
        return "\t" + text
    return text


def _escape(text: str) -> str:
    """Markdown table cells cannot contain a bare pipe or a newline."""
    return text.replace("|", "\\|").replace("\n", " ⏎ ")
